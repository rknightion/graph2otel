// Package signinactivity is the Entra service-principal / app-credential
// sign-in activity collector (BETA, P1/P2-gated): stale-workload compliance
// signals from the beta /reports usage-and-insights endpoints.
//
// # Both sides of the cardinality boundary, from one fetch (#114)
//
// Each of the two per-entity halves (service principals, app credentials)
// emits TWO things per cycle, from a single paged fetch:
//
//   - a bounded GAUGE counted by threshold_days — cumulative stale counts,
//     never a per-entity series;
//   - one entra.app_signin_activity LOG record per entity carrying the
//     per-entity detail a metric label must never hold: id, appId, and (for
//     credentials) keyId/keyType/credentialOrigin/expirationDateTime, plus the
//     full signInActivity detail (not just lastSignInDateTime).
//
// This collector previously decoded only the one timestamp it needed for
// bucketing and threw the rest away, so it could answer "how many are stale"
// but never "WHICH service principal" or "WHICH credential" — the question an
// analyst actually asks when hunting dormant workload identities. That was a
// bug (#114), not a privacy control: graph2otel exports this detail by
// design, and the logs pipeline is where it belongs. The third fetch this
// collector makes, the tenant-wide D7 app sign-in summary, stays metric-only —
// it is a pre-aggregated report with no natural per-entity row to twin.
//
// Both beta resources (servicePrincipalSignInActivity,
// appCredentialSignInActivity) were checked against learn.microsoft.com
// 2026-07-16: NEITHER carries a displayName/appDisplayName property — appId
// is the only identifying field either exposes. So no "app_display_name" log
// attribute exists here; that field was never a real one to defer.
//
// This is a STATE feed, not an event stream: an entity is re-emitted every
// cycle for as long as it appears in the report, which is what makes "was
// service principal X stale at 14:00" answerable. Volume therefore scales
// with the tenant's workload/credential count x the poll interval, same as
// the metric side already did.
//
// Beta-only (collectors.Experimental, opt-in) and P1/P2-gated
// (license.CapabilityRequirer -> CapEntraP1; a P2 tenant normally also holds
// P1). The composition root skips it entirely on a tenant without the tier or
// without the explicit beta opt-in.
package signinactivity

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/rknightion/graph2otel/internal/collector"
	"github.com/rknightion/graph2otel/internal/collectors"
	"github.com/rknightion/graph2otel/internal/license"
	"github.com/rknightion/graph2otel/internal/telemetry"
)

const (
	collectorName   = "entra.signin_activity"
	spStaleMetric   = "entra.serviceprincipal.signin.stale.total"
	credStaleMetric = "entra.app.credential.signin.stale.total" //nolint:gosec // G101 false positive: a metric name, not a credential
	summaryMetric   = "entra.app.signin.summary.total"
	betaBaseURL     = "https://graph.microsoft.com/beta"
)

// eventSignInActivity is the log twin's EventName, shared by BOTH per-entity
// halves (service principals and app credentials are different entity kinds,
// but the same frozen event name per #114's "Decisions recorded" comment).
const eventSignInActivity = "entra.app_signin_activity"

// staleThresholdsDays are the bounded staleness buckets. Counts are cumulative:
// a workload older than 90d is counted in both the 90 and the 30 bucket. The
// largest value also defines the log twin's severity escalation point — see
// stalenessSeverity.
var staleThresholdsDays = []int{30, 90}

// signInActivity mirrors the Graph beta signInActivity type shared by both
// servicePrincipalSignInActivity.lastSignInActivity and
// appCredentialSignInActivity.signInActivity (verified against
// learn.microsoft.com 2026-07-16 — six fields, not just lastSignInDateTime).
// All six are decoded because "attempted vs succeeded" and
// "interactive vs non-interactive" materially change whether an entity is
// actually stale, and this is free: the JSON is already fetched, only the
// unused fields were previously discarded.
type signInActivity struct {
	LastSignInDateTime                string `json:"lastSignInDateTime"`
	LastSignInRequestID               string `json:"lastSignInRequestId"`
	LastNonInteractiveSignInDateTime  string `json:"lastNonInteractiveSignInDateTime"`
	LastNonInteractiveSignInRequestID string `json:"lastNonInteractiveSignInRequestId"`
	LastSuccessfulSignInDateTime      string `json:"lastSuccessfulSignInDateTime"`
	LastSuccessfulSignInRequestID     string `json:"lastSuccessfulSignInRequestId"`
}

// spActivity is the per-item shape of servicePrincipalSignInActivity (beta).
// Only id/appId/lastSignInActivity are decoded: the resource also carries four
// flow-specific breakdowns (applicationAuthenticationClientSignInActivity,
// applicationAuthenticationResourceSignInActivity,
// delegatedClientSignInActivity, delegatedResourceSignInActivity) that stay
// out of scope here — this collector's notion of "stale" is defined against
// lastSignInActivity (Microsoft's own "most recent... across delegated or
// app-only flows" aggregate), so the twin mirrors exactly what the gauge
// buckets on, not a four-times-wider per-flow decomposition.
//
// NOTE: this resource has NO displayName/appDisplayName property (verified
// against the beta docs, 2026-07-16) — appId is the only identifying field a
// service principal's sign-in activity record carries.
type spActivity struct {
	ID                 string         `json:"id"`
	AppID              string         `json:"appId"`
	LastSignInActivity signInActivity `json:"lastSignInActivity"`
}

// credActivity is the per-item shape of appCredentialSignInActivity (beta).
// Like spActivity, this resource has no displayName field either — appId
// (the owning application) plus keyId identify the credential.
type credActivity struct {
	ID                       string         `json:"id"`
	AppID                    string         `json:"appId"`
	AppObjectID              string         `json:"appObjectId"`
	ServicePrincipalObjectID string         `json:"servicePrincipalObjectId"`
	ResourceID               string         `json:"resourceId"`
	KeyID                    string         `json:"keyId"`
	KeyType                  string         `json:"keyType"`
	KeyUsage                 string         `json:"keyUsage"`
	CredentialOrigin         string         `json:"credentialOrigin"`
	CreatedDateTime          string         `json:"createdDateTime"`
	ExpirationDateTime       string         `json:"expirationDateTime"`
	SignInActivity           signInActivity `json:"signInActivity"`
}

type appSummary struct {
	SuccessfulSignInCount int64 `json:"successfulSignInCount"`
	FailedSignInCount     int64 `json:"failedSignInCount"`
}

// Collector polls the beta sign-in-activity reports.
type Collector struct {
	g       collectors.GraphClient
	caps    license.Capabilities
	baseURL string
	logger  *slog.Logger
	now     func() time.Time
}

// New builds the sign-in-activity collector. A nil logger falls back to slog
// default. caps is accepted for interface symmetry with other gated collectors;
// the whole-collector P1 gate is enforced via RequiredCapability, so Collect
// itself does not re-check caps.
func New(g collectors.GraphClient, caps license.Capabilities, logger *slog.Logger) *Collector {
	if logger == nil {
		logger = slog.Default()
	}
	return &Collector{g: g, caps: caps, baseURL: betaBaseURL, logger: logger, now: time.Now}
}

// Name implements collector.Collector.
func (c *Collector) Name() string { return collectorName }

// DefaultInterval implements collector.Collector. Usage insights update daily;
// a long cadence keeps well clear of the shared reporting throttle bucket.
func (c *Collector) DefaultInterval() time.Duration { return time.Hour }

// Experimental marks this as a beta, opt-in collector.
func (c *Collector) Experimental() bool { return true }

// RequiredCapability gates the whole collector on Entra P1 (P1/P2 usage
// insights). The composition root skips registration below that tier.
func (c *Collector) RequiredCapability() license.Capability { return license.CapEntraP1 }

// RequiredPermissions declares the least-privilege Graph scope.
// AuditLog.Read.All covers the two /reports/*SignInActivities fetches;
// Reports.Read.All is additionally required by the appSummary sub-fetch
// (getAzureADApplicationSignInSummary), which 403s without it (verified live).
func (c *Collector) RequiredPermissions() []string {
	return []string{"AuditLog.Read.All", "Reports.Read.All"}
}

// Collect fetches the three beta reports and emits the bounded aggregates plus
// the two per-entity log twins (#114). Each half is independent: a failure in
// one is logged and joined into the returned error, but does not stop the
// others from emitting — and a failed half short-circuits before its twin, so
// a skipped/failed fetch emits zero logs for that half, never partial ones.
func (c *Collector) Collect(ctx context.Context, e telemetry.Emitter) error {
	var errs []error

	if pts, err := c.spStaleCounts(ctx, e); err != nil {
		errs = append(errs, fmt.Errorf("service principals: %w", err))
	} else {
		e.GaugeSnapshot(spStaleMetric, "{service_principal}",
			"Service principals with no sign-in within the threshold.", pts)
	}

	if pts, err := c.credStaleCounts(ctx, e); err != nil {
		errs = append(errs, fmt.Errorf("app credentials: %w", err))
	} else {
		e.GaugeSnapshot(credStaleMetric, "{credential}",
			"App credentials with no sign-in within the threshold.", pts)
	}

	if pts, err := c.appSummary(ctx); err != nil {
		errs = append(errs, fmt.Errorf("app sign-in summary: %w", err))
	} else {
		e.GaugeSnapshot(summaryMetric, "{signin}", "App sign-ins over the last 7 days by result.", pts)
	}

	return errors.Join(errs...)
}

// ageInDays returns how many days have elapsed between now and ts (RFC3339).
// An empty or unparseable timestamp returns a large sentinel — a never-used
// workload/credential is maximally stale, not zero-age.
func ageInDays(now time.Time, ts string) float64 {
	if ts != "" {
		if t, err := time.Parse(time.RFC3339, ts); err == nil {
			return now.Sub(t).Hours() / 24
		}
	}
	return 1 << 30
}

// bucketStale increments counts[th] for every threshold age exceeds.
// Cumulative: an entity older than 90d is counted in both the 90 and the 30
// bucket.
func bucketStale(counts map[int]int, age float64) {
	for _, th := range staleThresholdsDays {
		if age > float64(th) {
			counts[th]++
		}
	}
}

// staleGaugePoints renders counts into one GaugePoint per threshold.
func staleGaugePoints(counts map[int]int) []telemetry.GaugePoint {
	pts := make([]telemetry.GaugePoint, 0, len(staleThresholdsDays))
	for _, th := range staleThresholdsDays {
		pts = append(pts, telemetry.GaugePoint{
			Value: float64(counts[th]),
			Attrs: telemetry.Attrs{"threshold_days": th},
		})
	}
	return pts
}

// stalenessSeverity escalates to Warn once an entity crosses this collector's
// widest staleness threshold (the last, largest value in staleThresholdsDays —
// 90d today) or has never signed in at all — the SAME definition of "stale"
// the gauge buckets on, so the log severity and the metric agree. Routine,
// recently active workloads/credentials stay Info.
func stalenessSeverity(age float64) telemetry.Severity {
	if age > float64(staleThresholdsDays[len(staleThresholdsDays)-1]) {
		return telemetry.SeverityWarn
	}
	return telemetry.SeverityInfo
}

// firstNonEmpty returns the first non-empty string, or "unknown".
func firstNonEmpty(vals ...string) string {
	for _, s := range vals {
		if s != "" {
			return s
		}
	}
	return "unknown"
}

// tsOrNever renders a possibly-empty timestamp for a log Body.
func tsOrNever(ts string) string {
	if ts == "" {
		return "never"
	}
	return ts
}

// setStr adds key=val only when val is non-empty, so an absent field emits no
// attribute rather than an empty one.
func setStr(attrs telemetry.Attrs, key, val string) {
	if val != "" {
		attrs[key] = val
	}
}

// setSignInActivity adds the six signInActivity sub-fields shared by both
// per-entity halves.
func setSignInActivity(attrs telemetry.Attrs, a signInActivity) {
	setStr(attrs, "last_sign_in_date_time", a.LastSignInDateTime)
	setStr(attrs, "last_sign_in_request_id", a.LastSignInRequestID)
	setStr(attrs, "last_non_interactive_sign_in_date_time", a.LastNonInteractiveSignInDateTime)
	setStr(attrs, "last_non_interactive_sign_in_request_id", a.LastNonInteractiveSignInRequestID)
	setStr(attrs, "last_successful_sign_in_date_time", a.LastSuccessfulSignInDateTime)
	setStr(attrs, "last_successful_sign_in_request_id", a.LastSuccessfulSignInRequestID)
}

// spStaleCounts pages servicePrincipalSignInActivities ONCE and emits BOTH
// sides of the cardinality boundary from that single fetch: the bounded
// stale-count gauge, and one entra.app_signin_activity log record per service
// principal — see the package doc.
func (c *Collector) spStaleCounts(ctx context.Context, e telemetry.Emitter) ([]telemetry.GaugePoint, error) {
	raw, err := collectors.GetAllValues(ctx, c.g, c.baseURL+"/reports/servicePrincipalSignInActivities", nil)
	if err != nil {
		return nil, err
	}
	now := c.now()
	counts := make(map[int]int, len(staleThresholdsDays))
	for _, r := range raw {
		var item spActivity
		if err := json.Unmarshal(r, &item); err != nil {
			return nil, fmt.Errorf("decode servicePrincipalSignInActivity: %w", err)
		}
		age := ageInDays(now, item.LastSignInActivity.LastSignInDateTime)
		bucketStale(counts, age)
		e.LogEvent(spLogTwin(item, age))
	}
	return staleGaugePoints(counts), nil
}

// credStaleCounts pages appCredentialSignInActivities ONCE and emits BOTH
// sides of the cardinality boundary from that single fetch: the bounded
// stale-count gauge, and one entra.app_signin_activity log record per app
// credential — see the package doc.
func (c *Collector) credStaleCounts(ctx context.Context, e telemetry.Emitter) ([]telemetry.GaugePoint, error) {
	raw, err := collectors.GetAllValues(ctx, c.g, c.baseURL+"/reports/appCredentialSignInActivities", nil)
	if err != nil {
		return nil, err
	}
	now := c.now()
	counts := make(map[int]int, len(staleThresholdsDays))
	for _, r := range raw {
		var item credActivity
		if err := json.Unmarshal(r, &item); err != nil {
			return nil, fmt.Errorf("decode appCredentialSignInActivity: %w", err)
		}
		age := ageInDays(now, item.SignInActivity.LastSignInDateTime)
		bucketStale(counts, age)
		e.LogEvent(credLogTwin(item, age))
	}
	return staleGaugePoints(counts), nil
}

// spLogTwin renders one service principal's sign-in activity as an OTLP log
// record. Timestamp is deliberately left zero ("now", i.e. poll time): this is
// a STATE feed, not an event stream — the same service principal is
// re-emitted every cycle for as long as it appears in the report, so stamping
// it with lastSignInDateTime would pile every cycle's repeat onto one instant
// and make "which SPs were stale at 14:00" unanswerable (same reasoning as
// entra/risk's logTwin).
func spLogTwin(item spActivity, age float64) telemetry.Event {
	attrs := telemetry.Attrs{}
	setStr(attrs, "id", item.ID)
	setStr(attrs, "app_id", item.AppID)
	setSignInActivity(attrs, item.LastSignInActivity)

	return telemetry.Event{
		Name: eventSignInActivity,
		Body: fmt.Sprintf("service principal %s: last_sign_in=%s",
			firstNonEmpty(item.AppID, item.ID), tsOrNever(item.LastSignInActivity.LastSignInDateTime)),
		Severity: stalenessSeverity(age),
		Attrs:    attrs,
	}
}

// credLogTwin renders one app credential's sign-in activity as an OTLP log
// record. Timestamp is left zero for the same STATE-feed reason as spLogTwin.
func credLogTwin(item credActivity, age float64) telemetry.Event {
	attrs := telemetry.Attrs{}
	setStr(attrs, "id", item.ID)
	setStr(attrs, "app_id", item.AppID)
	setStr(attrs, "app_object_id", item.AppObjectID)
	setStr(attrs, "service_principal_object_id", item.ServicePrincipalObjectID)
	setStr(attrs, "resource_id", item.ResourceID)
	setStr(attrs, "key_id", item.KeyID)
	setStr(attrs, "key_type", item.KeyType)
	setStr(attrs, "key_usage", item.KeyUsage)
	setStr(attrs, "credential_origin", item.CredentialOrigin)
	setStr(attrs, "created_date_time", item.CreatedDateTime)
	setStr(attrs, "expiration_date_time", item.ExpirationDateTime)
	setSignInActivity(attrs, item.SignInActivity)

	return telemetry.Event{
		Name: eventSignInActivity,
		Body: fmt.Sprintf("app credential %s (app %s): last_sign_in=%s",
			firstNonEmpty(item.KeyID, item.ID), firstNonEmpty(item.AppID, "unknown"), tsOrNever(item.SignInActivity.LastSignInDateTime)),
		Severity: stalenessSeverity(age),
		Attrs:    attrs,
	}
}

// appSummary sums the per-app D7 sign-in summary into tenant-wide success and
// failure totals (never a per-app series).
func (c *Collector) appSummary(ctx context.Context) ([]telemetry.GaugePoint, error) {
	raw, err := collectors.GetAllValues(ctx, c.g, c.baseURL+"/reports/getAzureADApplicationSignInSummary(period='D7')", nil)
	if err != nil {
		return nil, err
	}
	var success, failure int64
	for _, r := range raw {
		var s appSummary
		if err := json.Unmarshal(r, &s); err != nil {
			c.logger.Warn("signinactivity: skipping unparseable summary", "collector", collectorName, "error", err)
			continue
		}
		success += s.SuccessfulSignInCount
		failure += s.FailedSignInCount
	}
	return []telemetry.GaugePoint{
		{Value: float64(success), Attrs: telemetry.Attrs{"result": "success"}},
		{Value: float64(failure), Attrs: telemetry.Attrs{"result": "failure"}},
	}, nil
}

func init() {
	collectors.Register(func(d collectors.Deps) collector.SnapshotCollector {
		return New(d.Graph, d.Caps, d.Logger)
	})
}
