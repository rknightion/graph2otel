package license

import (
	"github.com/rknightion/graph2otel/internal/semconv"
	"github.com/rknightion/graph2otel/internal/telemetry"
)

// MetricLicenseTier is the gauge name for the per-tenant, per-detected-
// capability license indicator.
const MetricLicenseTier = "graph2otel.tenant.license_tier"

// attrTier is the metric attribute key carrying a Capability's string form.
// Local to this package (not in internal/semconv) since license tier is the
// only signal that needs it.
const attrTier = "tier"

// EmitLicenseTier records a constant-1 gauge point per detected capability in
// caps, tagged {tenant_id, tier}. Both attributes are bounded: tenant_id by
// the configured tenant count, tier by the small fixed Capability enum — this
// never becomes a per-entity, unbounded-cardinality label.
//
// An empty caps set (Free tier) emits nothing. There is deliberately no
// "tier: free" series — the absence of every premium-tier series for a tenant
// already communicates that, and a synthetic "free" value would just be a
// fifth enum member to track for no added signal.
func EmitLicenseTier(e telemetry.Emitter, tenantID string, caps Capabilities) {
	for cap, present := range caps {
		if !present {
			continue
		}
		e.Gauge(MetricLicenseTier, semconv.UnitDimensionless,
			"Constant 1 per detected premium Microsoft Entra/Intune licensing capability for a tenant; attrs {tenant_id, tier}.",
			1, telemetry.Attrs{
				semconv.AttrTenantID: tenantID,
				attrTier:             string(cap),
			})
	}
}
