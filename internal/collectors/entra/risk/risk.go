// Package risk is the Entra Identity Protection current-risk collector: two
// independently license-gated point-in-time gauges — risky users (Entra ID
// P2) and risky service principals (Workload Identities Premium) — counted
// by the bounded risk_level x risk_state dimensions. This is the discrete
// "how much risk is live right now" snapshot; the risk-detection *events*
// stream is a separate log-pipeline collector (M3), not this one.
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

// riskyEntity is the common shape of both riskyUser and riskyServicePrincipal
// list-response elements that this collector actually uses. Every other
// field on those resources (id, userPrincipalName, appId, displayName, ...)
// is per-entity/PII and deliberately never decoded here — see the package
// doc and CLAUDE.md's cardinality rule.
type riskyEntity struct {
	RiskLevel string `json:"riskLevel"`
	RiskState string `json:"riskState"`
}

// Collect fetches whichever half(s) the tenant's detected capabilities
// unlock. Risky users requires license.CapEntraP2; risky service principals
// requires license.CapWorkloadIdentitiesPremium. These are two INDEPENDENT
// gates: each half is checked and skipped-and-logged on its own, and a
// failure fetching one half does not prevent the other from being collected
// and emitted.
func (c *Collector) Collect(ctx context.Context, e telemetry.Emitter) error {
	var errs []error

	if c.caps.Has(license.CapEntraP2) {
		if err := c.collectHalf(ctx, e, "/identityProtection/riskyUsers", metricRiskyUsers,
			"Current count of risky Entra users, by risk level and risk state.", "{user}"); err != nil {
			c.logger.Warn("risky users collection failed", "collector", collectorName, "error", err)
			errs = append(errs, fmt.Errorf("risky users: %w", err))
		}
	} else {
		c.logger.Info("skipping risky users: capability not present", "collector", collectorName, "requires", license.CapEntraP2)
	}

	if c.caps.Has(license.CapWorkloadIdentitiesPremium) {
		if err := c.collectHalf(ctx, e, "/identityProtection/riskyServicePrincipals", metricRiskyServicePrincipals,
			"Current count of risky Entra service principals, by risk level and risk state.", "{service_principal}"); err != nil {
			c.logger.Warn("risky service principals collection failed", "collector", collectorName, "error", err)
			errs = append(errs, fmt.Errorf("risky service principals: %w", err))
		}
	} else {
		c.logger.Info("skipping risky service principals: capability not present", "collector", collectorName, "requires", license.CapWorkloadIdentitiesPremium)
	}

	return errors.Join(errs...)
}

// collectHalf pages one of the two current-risk endpoints, aggregates its
// elements by (riskLevel, riskState), and emits the result as a single
// GaugeSnapshot. GaugeSnapshot (not Gauge) is used deliberately: it is an
// observable instrument, so a level/state combination that no longer appears
// on a later tick drops out of the export instead of ghosting forever under
// Grafana Cloud's forced cumulative temporality.
//
// No advanced $filter/$search is used here (the whole collection is fetched
// and aggregated client-side), so no ConsistencyLevel header is required —
// collectors.GetAllValues is called with nil headers.
func (c *Collector) collectHalf(ctx context.Context, e telemetry.Emitter, path, metricName, desc, unit string) error {
	raws, err := collectors.GetAllValues(ctx, c.g, c.baseURL+path, nil)
	if err != nil {
		return err
	}

	counts := map[[2]string]int64{}
	for _, raw := range raws {
		var item riskyEntity
		if err := json.Unmarshal(raw, &item); err != nil {
			return fmt.Errorf("decode %s: %w", path, err)
		}
		counts[[2]string{item.RiskLevel, item.RiskState}]++
	}

	points := make([]telemetry.GaugePoint, 0, len(counts))
	for k, v := range counts {
		points = append(points, telemetry.GaugePoint{
			Value: float64(v),
			Attrs: telemetry.Attrs{"risk_level": k[0], "risk_state": k[1]},
		})
	}
	e.GaugeSnapshot(metricName, unit, desc, points)
	return nil
}

func init() {
	collectors.Register(func(d collectors.Deps) collector.SnapshotCollector {
		return New(d.Graph, d.Caps, d.Logger)
	})
}
