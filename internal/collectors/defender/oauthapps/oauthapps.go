// Package oauthapps is the Microsoft Defender OAuth-application-inventory
// collector (#252): every OAuth app consented in the tenant, with the risk
// signals Graph does not compute.
//
// # Why this is a hunting collector
//
// OAuthAppInfo is the Defender for Cloud Apps OAuth-app inventory, exposed as an
// advanced-hunting table — reachable over the Graph runHuntingQuery API WITHOUT
// the MDCA portal token (#251). It sits on the hunting registration path
// (collectors.HuntDeps), alongside the DeviceTvm* collectors (#249), and it is
// the deferred fourth from #249.
//
// # What it adds over entra.consent / entra.service_principals
//
// Defender computes fields the directory does not: a per-app RiskScore, a
// PrivilegeLevel derived from the permission set, a VerifiedPublisher record, and
// LastUsedTime. Graph exposes the grant; Defender scores it.
//
// # Both sides of the cardinality boundary
//
//   - bounded GAUGES: an app count keyed by privilege level, status, origin and
//     admin-consent (all small closed sets), plus the worst RiskScore and the
//     summed user-consent count per privilege level. RiskScore itself is a
//     fine-grained 0-100 integer, so it is NOT a metric label — it would be ~30
//     series per app and answers nothing a max gauge plus the twin does not.
//   - one LOG twin per app carrying the per-entity detail: the app and service-
//     principal ids, the risk score, the verified-publisher record, last-used
//     time, and the granted permission values. Warn on a High-privilege app —
//     Microsoft's own classification, emitted verbatim, no invented scale.
//
// # A STATE feed
//
// A row is re-emitted every cycle for as long as the app is consented. The table
// carries a Timestamp, but twins are stamped at POLL time (Event.Timestamp left
// zero), the defender.vulnerabilities shape. Long default interval, for the
// shared advanced-hunting CPU budget (#106).
//
// # Wire, not docs
//
// Every column is read off a VERBATIM live query result (2026-07-23). The wire
// facts that drive the mapping: IsAdminConsented is an SByte number (tvm handles
// it); ConsentedUsersCount is {} (null) on admin-consented apps, so SetNum omits
// it; VerifiedPublisher is a nested dynamic object (or {} when unverified); and
// Permissions is a list of embedded-JSON strings, each an object whose
// PermissionValue is the granted scope.
package oauthapps

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"sort"
	"time"

	"github.com/rknightion/graph2otel/internal/collector"
	"github.com/rknightion/graph2otel/internal/collectors"
	"github.com/rknightion/graph2otel/internal/semconv"
	"github.com/rknightion/graph2otel/internal/telemetry"
	"github.com/rknightion/graph2otel/internal/tvm"
)

const (
	collectorName = "defender.oauth_app"
	eventName     = "defender.oauth_app"

	// interval is deliberately long — the shared advanced-hunting CPU budget
	// (#106), a state snapshot with nothing to tail. Do NOT shorten without
	// re-reading #106 and #249.
	interval = 6 * time.Hour

	defaultRowCap = 90_000

	metricApps           = "defender.oauth_app.apps"
	metricMaxRiskScore   = "defender.oauth_app.max_risk_score"
	metricConsentedUsers = "defender.oauth_app.consented_users"

	unitApp   = "{app}"
	unitScore = "{score}"
	unitUser  = "{user}"
)

// summaryQuery counts apps, sums user consents and takes the worst risk score by
// the four bounded categorical dimensions. The per-privilege max/sum gauges are
// derived collector-side (max-of-maxes, sum-of-sums), so this is one query.
const summaryQuery = `OAuthAppInfo
| summarize apps=count(), consented_users=sum(ConsentedUsersCount), max_risk=max(RiskScore) by PrivilegeLevel, AppStatus, AppOrigin, IsAdminConsented`

// twinQueryBase is the per-entity query, filtered to one privilege level and
// (when needed) one hash shard.
const twinQueryBase = `OAuthAppInfo
| where PrivilegeLevel == "%s"`

// Collector reads the OAuth-app inventory over the advanced-hunting API.
type Collector struct {
	c      collectors.HuntClient
	logger *slog.Logger
	rowCap int
}

// New builds the OAuth-app collector. A nil logger falls back to slog.Default().
func New(d collectors.HuntDeps) *Collector {
	logger := d.Logger
	if logger == nil {
		logger = slog.Default()
	}
	return &Collector{c: d.Client, logger: logger, rowCap: defaultRowCap}
}

// Name implements collector.Collector.
func (c *Collector) Name() string { return collectorName }

// DefaultInterval implements collector.Collector.
func (c *Collector) DefaultInterval() time.Duration { return interval }

// RequiredPermissions is the Graph app role the advanced-hunting query needs.
func (c *Collector) RequiredPermissions() []string {
	return []string{"ThreatHunting.Read.All"}
}

// Collect runs the summary query, emits the bounded gauges, then fetches the
// per-entity twins per privilege level in row-cap-safe partitions.
func (c *Collector) Collect(ctx context.Context, e telemetry.Emitter) error {
	summary, err := c.c.Query(ctx, "oauth_summary", summaryQuery)
	if err != nil {
		return fmt.Errorf("%s: summary query: %w", collectorName, err)
	}

	perPrivilege := c.emitGauges(e, summary)

	var errs []error
	for _, pc := range perPrivilege {
		for _, p := range tvm.PlanPartitions(pc.count, c.rowCap) {
			query := fmt.Sprintf(twinQueryBase, pc.privilege) + p.Predicate("OAuthAppId")
			rows, qerr := c.c.Query(ctx, "oauth_twin_"+pc.privilege, query)
			if qerr != nil {
				c.logger.Warn("oauth app twin partition failed",
					"collector", collectorName, "privilege", pc.privilege, "error", qerr)
				errs = append(errs, fmt.Errorf("twin %s: %w", pc.privilege, qerr))
				continue
			}
			if len(rows) >= tvm.HardRowCap {
				c.logger.Error("oauth app twin partition hit the hunting row cap; some rows were not emitted",
					"collector", collectorName, "privilege", pc.privilege, "rows", len(rows))
				errs = append(errs, fmt.Errorf("twin %s: hit row cap %d", pc.privilege, tvm.HardRowCap))
			}
			for _, r := range rows {
				e.LogEvent(appTwin(r))
			}
		}
	}
	return errors.Join(errs...)
}

// privilegeCount is the per-privilege app total, for partitioning.
type privilegeCount struct {
	privilege string
	count     int64
}

// emitGauges emits the bounded gauges and returns per-privilege app totals for
// partition planning. The apps gauge keeps all four categorical dimensions; the
// max-risk and consented-users gauges are collapsed to privilege level
// collector-side (max-of-maxes, sum-of-sums).
func (c *Collector) emitGauges(e telemetry.Emitter, summary []map[string]any) []privilegeCount {
	var appPts []telemetry.GaugePoint
	appsByPriv := map[string]int64{}
	maxRiskByPriv := map[string]float64{}
	usersByPriv := map[string]float64{}

	for _, r := range summary {
		priv, _ := r["PrivilegeLevel"].(string)
		if priv == "" {
			continue
		}
		consented, _ := tvm.SByteBool(r, "IsAdminConsented")
		attrs := telemetry.Attrs{
			semconv.AttrPrivilegeLevel: priv,
			semconv.AttrAppStatus:      tvm.Str(r, "AppStatus"),
			semconv.AttrAppOrigin:      tvm.Str(r, "AppOrigin"),
			semconv.AttrAdminConsented: tvm.FmtBool(consented),
		}
		appPts = appendNumPoint(appPts, r, "apps", attrs)

		if n, ok := r["apps"].(float64); ok {
			appsByPriv[priv] += int64(n)
		}
		if v, ok := r["max_risk"].(float64); ok && v > maxRiskByPriv[priv] {
			maxRiskByPriv[priv] = v
		}
		if v, ok := r["consented_users"].(float64); ok {
			usersByPriv[priv] += v
		}
	}

	e.GaugeSnapshot(metricApps, unitApp,
		"Consented OAuth applications, by privilege level, status, origin and admin-consent.", appPts)

	riskPts := make([]telemetry.GaugePoint, 0, len(maxRiskByPriv))
	for priv, v := range maxRiskByPriv {
		riskPts = append(riskPts, telemetry.GaugePoint{Value: v, Attrs: telemetry.Attrs{semconv.AttrPrivilegeLevel: priv}})
	}
	e.GaugeSnapshot(metricMaxRiskScore, unitScore,
		"Highest Defender OAuth-app risk score, by privilege level.", riskPts)

	userPts := make([]telemetry.GaugePoint, 0, len(usersByPriv))
	for priv, v := range usersByPriv {
		userPts = append(userPts, telemetry.GaugePoint{Value: v, Attrs: telemetry.Attrs{semconv.AttrPrivilegeLevel: priv}})
	}
	e.GaugeSnapshot(metricConsentedUsers, unitUser,
		"Summed user consents for OAuth apps, by privilege level.", userPts)

	out := make([]privilegeCount, 0, len(appsByPriv))
	for priv, n := range appsByPriv {
		out = append(out, privilegeCount{privilege: priv, count: n})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].privilege < out[j].privilege })
	return out
}

// appTwin renders one OAuth app as an OTLP log record. Timestamp is left zero
// (poll time). Severity escalates to Warn when the app is High-privilege —
// Microsoft's own classification, emitted verbatim rather than a threshold on the
// numeric risk score.
func appTwin(r map[string]any) telemetry.Event {
	attrs := telemetry.Attrs{}
	telemetry.SetStr(attrs, semconv.AttrAppName, tvm.Str(r, "AppName"))
	telemetry.SetStr(attrs, semconv.AttrOauthAppId, tvm.Str(r, "OAuthAppId"))
	telemetry.SetStr(attrs, semconv.AttrServicePrincipalId, tvm.Str(r, "ServicePrincipalId"))
	telemetry.SetStr(attrs, semconv.AttrAppStatus, tvm.Str(r, "AppStatus"))
	priv := tvm.Str(r, "PrivilegeLevel")
	telemetry.SetStr(attrs, semconv.AttrPrivilegeLevel, priv)
	telemetry.SetStr(attrs, semconv.AttrAppOrigin, tvm.Str(r, "AppOrigin"))
	telemetry.SetStr(attrs, semconv.AttrAppOwnerTenantId, tvm.Str(r, "AppOwnerTenantId"))
	telemetry.SetStr(attrs, semconv.AttrLastUsedTime, tvm.Str(r, "LastUsedTime"))
	telemetry.SetStr(attrs, semconv.AttrAddedOnTime, tvm.Str(r, "AddedOnTime"))
	telemetry.SetNum(attrs, semconv.AttrRiskScore, r, "RiskScore")
	telemetry.SetNum(attrs, semconv.AttrConsentedUsersCount, r, "ConsentedUsersCount")

	if consented, ok := tvm.SByteBool(r, "IsAdminConsented"); ok {
		telemetry.SetBool(attrs, semconv.AttrAdminConsented, consented)
	}

	name, id := verifiedPublisher(r)
	telemetry.SetStr(attrs, semconv.AttrVerifiedPublisherName, name)
	telemetry.SetStr(attrs, semconv.AttrVerifiedPublisherId, id)
	telemetry.SetBool(attrs, semconv.AttrIsVerifiedPublisher, id != "")

	perms := permissionValues(r)
	telemetry.SetStrs(attrs, semconv.AttrPermissionValues, perms)
	if len(perms) > 0 {
		attrs[semconv.AttrPermissionsCount] = float64(len(perms))
	}

	severity := telemetry.SeverityInfo
	if priv == "High" {
		severity = telemetry.SeverityWarn
	}

	return telemetry.Event{
		Name:     eventName,
		Body:     fmt.Sprintf("oauth app %q (privilege=%s, publisher=%q)", tvm.Str(r, "AppName"), priv, name),
		Severity: severity,
		Attrs:    attrs,
	}
}

// verifiedPublisher reads the nested VerifiedPublisher dynamic object, returning
// its display name and verified-publisher id, or empties when the app has no
// verified publisher (the wire sends {} in that case).
func verifiedPublisher(r map[string]any) (name, id string) {
	vp, ok := r["VerifiedPublisher"].(map[string]any)
	if !ok {
		return "", ""
	}
	name, _ = vp["displayName"].(string)
	id, _ = vp["verifiedPublisherId"].(string)
	return name, id
}

// permissionValues extracts the granted scope names from the Permissions column,
// a list of embedded-JSON strings. Each entry is a JSON object with a
// PermissionValue field; unparseable entries are skipped rather than failing the
// twin.
func permissionValues(r map[string]any) []string {
	raw, ok := r["Permissions"].([]any)
	if !ok {
		return nil
	}
	out := make([]string, 0, len(raw))
	for _, item := range raw {
		s, ok := item.(string)
		if !ok {
			continue
		}
		var perm struct {
			PermissionValue string `json:"PermissionValue"`
		}
		if err := json.Unmarshal([]byte(s), &perm); err != nil || perm.PermissionValue == "" {
			continue
		}
		out = append(out, perm.PermissionValue)
	}
	return out
}

// appendNumPoint appends a gauge point valued at the float64 column src, when
// present.
func appendNumPoint(pts []telemetry.GaugePoint, r map[string]any, src string, attrs telemetry.Attrs) []telemetry.GaugePoint {
	f, ok := r[src].(float64)
	if !ok {
		return pts
	}
	return append(pts, telemetry.GaugePoint{Value: f, Attrs: attrs})
}

func init() {
	collectors.RegisterHunt(func(d collectors.HuntDeps) collector.SnapshotCollector { return New(d) })
}
