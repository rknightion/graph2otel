// Package signinactivity is the Entra service-principal / app-credential
// sign-in activity collector (BETA, P1/P2-gated): stale-workload compliance
// signals from the beta /reports usage-and-insights endpoints.
//
// It emits ONLY bounded aggregates — counts of stale service principals and
// stale app credentials by threshold, and an app sign-in success/failure
// summary. The per-SP / per-credential "days since last use" drill-down in the
// issue's original telemetry model is deliberately NOT emitted as a metric:
// app_id / app_display_name / key_id are per-entity identifiers and would make
// a metric series set grow with the tenant's workload count (even bounded by a
// staleness threshold, the number of stale workloads is unbounded), violating
// the cardinality rule. That per-item detail belongs in the logs pipeline
// (M3/M5), consistent with the credential-expiry collector's decision.
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

// staleThresholdsDays are the bounded staleness buckets. Counts are cumulative:
// a workload older than 90d is counted in both the 90 and the 30 bucket.
var staleThresholdsDays = []int{30, 90}

type signInActivity struct {
	LastSignInDateTime string `json:"lastSignInDateTime"`
}

type spActivity struct {
	LastSignInActivity signInActivity `json:"lastSignInActivity"`
}

type credActivity struct {
	SignInActivity signInActivity `json:"signInActivity"`
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
func (c *Collector) RequiredPermissions() []string { return []string{"AuditLog.Read.All"} }

// Collect fetches the three beta reports and emits the bounded aggregates. Each
// half is independent: a failure in one is logged and joined into the returned
// error, but does not stop the others from emitting.
func (c *Collector) Collect(ctx context.Context, e telemetry.Emitter) error {
	var errs []error

	if pts, err := c.staleCounts(ctx, "/reports/servicePrincipalSignInActivities", spLastSignIn); err != nil {
		errs = append(errs, fmt.Errorf("service principals: %w", err))
	} else {
		e.GaugeSnapshot(spStaleMetric, "{service_principal}",
			"Service principals with no sign-in within the threshold.", pts)
	}

	if pts, err := c.staleCounts(ctx, "/reports/appCredentialSignInActivities", credLastSignIn); err != nil {
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

// lastSignInFn extracts the last-sign-in timestamp string from one report
// element (empty string = never signed in).
type lastSignInFn func(json.RawMessage) (string, error)

func spLastSignIn(r json.RawMessage) (string, error) {
	var v spActivity
	if err := json.Unmarshal(r, &v); err != nil {
		return "", err
	}
	return v.LastSignInActivity.LastSignInDateTime, nil
}

func credLastSignIn(r json.RawMessage) (string, error) {
	var v credActivity
	if err := json.Unmarshal(r, &v); err != nil {
		return "", err
	}
	return v.SignInActivity.LastSignInDateTime, nil
}

// staleCounts pages a report and returns one cumulative stale-count point per
// threshold. An element with no (or unparseable) last-sign-in timestamp counts
// as stale for every threshold — a never-used workload is maximally stale.
func (c *Collector) staleCounts(ctx context.Context, path string, extract lastSignInFn) ([]telemetry.GaugePoint, error) {
	raw, err := collectors.GetAllValues(ctx, c.g, c.baseURL+path, nil)
	if err != nil {
		return nil, err
	}
	now := c.now()
	counts := make(map[int]int, len(staleThresholdsDays))
	for _, r := range raw {
		ts, perr := extract(r)
		var ageDays float64
		if perr != nil || ts == "" {
			ageDays = 1 << 30 // never used -> maximally stale
		} else if t, terr := time.Parse(time.RFC3339, ts); terr == nil {
			ageDays = now.Sub(t).Hours() / 24
		} else {
			ageDays = 1 << 30
		}
		for _, th := range staleThresholdsDays {
			if ageDays > float64(th) {
				counts[th]++
			}
		}
	}
	pts := make([]telemetry.GaugePoint, 0, len(staleThresholdsDays))
	for _, th := range staleThresholdsDays {
		pts = append(pts, telemetry.GaugePoint{
			Value: float64(counts[th]),
			Attrs: telemetry.Attrs{"threshold_days": th},
		})
	}
	return pts, nil
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
