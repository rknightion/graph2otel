// Package risk is the Entra Identity Protection current-risk collector: two
// independently license-gated halves — risky users (Entra ID P2) and risky
// service principals (Workload Identities Premium). This is the discrete "how
// much risk is live right now" state snapshot; the risk-detection *events*
// stream is a separate log-pipeline collector (M3), not this one.
//
// # Both sides of the cardinality boundary, from one fetch
//
// Each half emits TWO things per cycle, from a single paged fetch:
//
//   - a bounded GAUGE counted by risk_level x risk_state — the aggregate;
//   - one LOG record per risky entity (entra.risky_user /
//     entra.risky_service_principal) carrying the per-entity detail: id, UPN or
//     appId, display name, riskDetail, riskLastUpdatedDateTime.
//
// The log twin is not optional garnish — it is the other half of the rule.
// Per-entity identity must never become a metric label (a series per user grows
// with tenant size and bills as active series), but "not a metric label" means
// "log twin", NOT "dropped". This collector previously decoded only the two
// bounded enums and threw the rest away, so it could answer "how much risk" but
// never "WHICH user" — the question an analyst actually asks. That was a bug
// (#110), not a privacy control: graph2otel exports this detail by design, and
// the logs pipeline is where it belongs. See SECURITY.md.
//
// This is a STATE feed, not an event stream: a risky entity is re-emitted every
// cycle for as long as it stays risky, which is what makes "who was risky at
// 14:00" answerable. Volume therefore scales with the risky population (small
// on a healthy tenant) x the poll interval, not with tenant size.
//
// The two halves are gated by two DIFFERENT capabilities and degrade fully
// independently: a tenant may hold Entra ID P2 without Workload Identities
// Premium, the reverse, both, or neither. Collect emits whichever half(s) the
// tenant's detected capabilities unlock and skips-and-logs the rest, without
// treating a missing capability as an error.
package risk

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/rknightion/graph2otel/internal/collector"
	"github.com/rknightion/graph2otel/internal/collectors"
	"github.com/rknightion/graph2otel/internal/license"
	"github.com/rknightion/graph2otel/internal/telemetry"
)

// collectorName is the stable key used for config (enable/interval),
// self-observability, and the admin status page.
const collectorName = "entra.risk"

// The two gauges this collector emits. Cardinality of each is bounded by
// riskLevel x riskState (6 x 7 possible values per the Graph resource docs),
// never by tenant/entity population size — see the package doc.
const (
	metricRiskyUsers             = "entra.risky_users.total"
	metricRiskyServicePrincipals = "entra.risky_service_principals.total"
)

// The two log EventNames carrying the per-entity detail the gauges above
// cannot — one record per risky entity per cycle. See the package doc.
const (
	eventRiskyUser = "entra.risky_user"
	eventRiskySP   = "entra.risky_service_principal"
)

// defaultBaseURL is the Graph v1.0 root.
const defaultBaseURL = "https://graph.microsoft.com/v1.0"

// Collector polls the two Identity Protection current-risk endpoints.
type Collector struct {
	g       collectors.GraphClient
	caps    license.Capabilities
	baseURL string
	logger  *slog.Logger
}

// New builds the risk collector. caps is the tenant's detected license
// capabilities (see license.Detect); a nil logger falls back to
// slog.Default().
func New(g collectors.GraphClient, caps license.Capabilities, logger *slog.Logger) *Collector {
	if logger == nil {
		logger = slog.Default()
	}
	return &Collector{g: g, caps: caps, baseURL: defaultBaseURL, logger: logger}
}

// Name implements collector.Collector.
func (c *Collector) Name() string { return collectorName }

// DefaultInterval implements collector.Collector. Both endpoints share
// Identity Protection's very low throttle bucket (1 request/second per
// tenant, across every app using it, with no Retry-After — see the
// GraphClient's rate limiter), and current risk state is not a
// sub-minute-cadence signal, so a conservative interval keeps this collector
// a negligible share of that shared budget.
func (c *Collector) DefaultInterval() time.Duration { return 15 * time.Minute }

// RequiredPermissions declares the least-privilege Graph application scope
// for each half. A tenant holding only one of the two license capabilities
// only ever needs the matching scope in practice (the other half's requests
// are simply never made — see Collect), but both are declared up front so
// the full permission requirement is visible regardless of which capability
// is eventually granted.
func (c *Collector) RequiredPermissions() []string {
	return []string{"IdentityRiskyUser.Read.All", "IdentityRiskyServicePrincipal.Read.All"}
}

// riskyEntity is the UNION of the riskyUser and riskyServicePrincipal
// list-response shapes. The two resources share the risk fields and differ only
// in how they name their principal (userPrincipalName/userDisplayName vs
// appId/displayName/servicePrincipalType), so one struct decodes both: the
// half that doesn't carry a field simply leaves it zero, and emitLogTwin omits
// empty attributes.
//
// RiskLevel/RiskState bucket the gauge. Everything else is per-entity and goes
// to the log twin ONLY — never a metric label (see the package doc).
type riskyEntity struct {
	ID                      string `json:"id"`
	RiskLevel               string `json:"riskLevel"`
	RiskState               string `json:"riskState"`
	RiskDetail              string `json:"riskDetail"`
	RiskLastUpdatedDateTime string `json:"riskLastUpdatedDateTime"`

	// riskyUser only.
	UserPrincipalName string `json:"userPrincipalName"`
	UserDisplayName   string `json:"userDisplayName"`

	// riskyServicePrincipal only.
	AppID                string `json:"appId"`
	DisplayName          string `json:"displayName"`
	ServicePrincipalType string `json:"servicePrincipalType"`
}

// half describes one of the two current-risk endpoints: where to fetch it, the
// bounded gauge it aggregates into, and the log twin it emits per entity.
type half struct {
	path       string
	metricName string
	metricDesc string
	unit       string
	eventName  string
	// noun names the principal kind in the log body ("user" / "service principal").
	noun string
}

var (
	usersHalf = half{
		path:       "/identityProtection/riskyUsers",
		metricName: metricRiskyUsers,
		metricDesc: "Current count of risky Entra users, by risk level and risk state.",
		unit:       "{user}",
		eventName:  eventRiskyUser,
		noun:       "user",
	}
	spsHalf = half{
		path:       "/identityProtection/riskyServicePrincipals",
		metricName: metricRiskyServicePrincipals,
		metricDesc: "Current count of risky Entra service principals, by risk level and risk state.",
		unit:       "{service_principal}",
		eventName:  eventRiskySP,
		noun:       "service principal",
	}
)

// Collect fetches whichever half(s) the tenant's detected capabilities
// unlock. Risky users requires license.CapEntraP2; risky service principals
// requires license.CapWorkloadIdentitiesPremium. These are two INDEPENDENT
// gates: each half is checked and skipped-and-logged on its own, and a
// failure fetching one half does not prevent the other from being collected
// and emitted.
func (c *Collector) Collect(ctx context.Context, e telemetry.Emitter) error {
	var errs []error

	if c.caps.Has(license.CapEntraP2) {
		if err := c.collectHalf(ctx, e, usersHalf); err != nil {
			c.logger.Warn("risky users collection failed", "collector", collectorName, "error", err)
			errs = append(errs, fmt.Errorf("risky users: %w", err))
		}
	} else {
		c.logger.Info("skipping risky users: capability not present", "collector", collectorName, "requires", license.CapEntraP2)
	}

	if c.caps.Has(license.CapWorkloadIdentitiesPremium) {
		if err := c.collectHalf(ctx, e, spsHalf); err != nil {
			c.logger.Warn("risky service principals collection failed", "collector", collectorName, "error", err)
			errs = append(errs, fmt.Errorf("risky service principals: %w", err))
		}
	} else {
		c.logger.Info("skipping risky service principals: capability not present", "collector", collectorName, "requires", license.CapWorkloadIdentitiesPremium)
	}

	return errors.Join(errs...)
}

// collectHalf pages one of the two current-risk endpoints and emits BOTH sides
// of the cardinality boundary from that single fetch: the bounded
// (riskLevel, riskState) GaugeSnapshot, and one log record per entity carrying
// the per-entity detail the gauge cannot.
//
// GaugeSnapshot (not Gauge) is used deliberately: it is an observable
// instrument, so a level/state combination that no longer appears on a later
// tick drops out of the export instead of ghosting forever under Grafana
// Cloud's forced cumulative temporality.
//
// No advanced $filter/$search is used here (the whole collection is fetched
// and aggregated client-side), so no ConsistencyLevel header is required —
// collectors.GetAllValues is called with nil headers.
func (c *Collector) collectHalf(ctx context.Context, e telemetry.Emitter, h half) error {
	raws, err := collectors.GetAllValues(ctx, c.g, c.baseURL+h.path, nil)
	if err != nil {
		return err
	}

	counts := map[[2]string]int64{}
	for _, raw := range raws {
		var item riskyEntity
		if err := json.Unmarshal(raw, &item); err != nil {
			return fmt.Errorf("decode %s: %w", h.path, err)
		}
		counts[[2]string{item.RiskLevel, item.RiskState}]++
		e.LogEvent(logTwin(item, h))
	}

	points := make([]telemetry.GaugePoint, 0, len(counts))
	for k, v := range counts {
		points = append(points, telemetry.GaugePoint{
			Value: float64(v),
			Attrs: telemetry.Attrs{"risk_level": k[0], "risk_state": k[1]},
		})
	}
	e.GaugeSnapshot(h.metricName, h.unit, h.metricDesc, points)
	return nil
}

// logTwin renders one risky entity as an OTLP log record.
//
// Timestamp is deliberately left zero ("now", i.e. poll time) rather than set
// to riskLastUpdatedDateTime. This is a STATE feed, not an event stream: the
// same entity is re-emitted every cycle for as long as it stays risky, so
// stamping it with the last-assessment time would pile every repeat onto one
// instant and make "who was risky at 14:00" unanswerable — the whole point of
// the twin. The assessment time is preserved as the risk_last_updated
// attribute instead.
func logTwin(item riskyEntity, h half) telemetry.Event {
	attrs := telemetry.Attrs{}
	setStr(attrs, "id", item.ID)
	setStr(attrs, "risk_level", item.RiskLevel)
	setStr(attrs, "risk_state", item.RiskState)
	setStr(attrs, "risk_detail", item.RiskDetail)
	setStr(attrs, "risk_last_updated", item.RiskLastUpdatedDateTime)
	setStr(attrs, "user_principal_name", item.UserPrincipalName)
	setStr(attrs, "user_display_name", item.UserDisplayName)
	setStr(attrs, "app_id", item.AppID)
	setStr(attrs, "display_name", item.DisplayName)
	setStr(attrs, "service_principal_type", item.ServicePrincipalType)

	// Only "high" escalates: riskLevel's other values (low/medium/hidden/none)
	// are routine background state on any real tenant, and warning on them would
	// make the severity dimension useless for filtering.
	sev := telemetry.SeverityInfo
	if strings.EqualFold(item.RiskLevel, "high") {
		sev = telemetry.SeverityWarn
	}

	return telemetry.Event{
		Name:     h.eventName,
		Body:     fmt.Sprintf("risky %s %s: risk_level=%s risk_state=%s", h.noun, displayOf(item), item.RiskLevel, item.RiskState),
		Severity: sev,
		Attrs:    attrs,
	}
}

// displayOf picks the most human-readable identifier the entity carries,
// falling back through the two halves' differing name fields to the id.
func displayOf(item riskyEntity) string {
	for _, s := range []string{item.UserPrincipalName, item.DisplayName, item.UserDisplayName, item.AppID, item.ID} {
		if s != "" {
			return s
		}
	}
	return "unknown"
}

// setStr adds key=val only when val is non-empty, so an absent field (including
// every field belonging to the OTHER half's resource shape) emits no attribute
// rather than an empty one.
func setStr(attrs telemetry.Attrs, key, val string) {
	if val != "" {
		attrs[key] = val
	}
}

func init() {
	collectors.Register(func(d collectors.Deps) collector.SnapshotCollector {
		return New(d.Graph, d.Caps, d.Logger)
	})
}
