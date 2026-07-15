// Package semconv centralizes the OpenTelemetry attribute keys and UCUM units
// shared across collectors and the telemetry package, so naming stays
// consistent as new collectors land (entra.*, intune.*) alongside the
// self-observability signals defined here.
package semconv

// Self-observability attribute keys, used by the telemetry package's
// cardinality tracker (internal/telemetry.CardinalityTracker) to label its
// graph2otel.series.* gauges.
const (
	// AttrMetricName names the source metric a graph2otel.series.* gauge point
	// describes (e.g. "entra.signin.count").
	AttrMetricName = "metric.name"
)

// Collector self-observability attribute keys, used by internal/collector's
// Scheduler to label its graph2otel.scrape.* and graph2otel.checkpoint.* metrics.
const (
	// AttrCollector names the collector a scrape.* metric point describes
	// (e.g. "devices", "auditlogs").
	AttrCollector = "collector"
	// AttrTenantID identifies which tenant's Scheduler produced a scrape.*
	// metric point, added alongside AttrCollector when the Scheduler is
	// configured with WithTenant. Bounded cardinality: one value per
	// configured tenant, never a per-entity identifier.
	AttrTenantID = "tenant_id"
)

// UCUM units used by the telemetry package's self-observability metrics.
const (
	UnitSeries        = "{series}"
	UnitDimensionless = "1"
	// UnitSeconds is used by the collector self-obs duration/staleness/budget gauges.
	UnitSeconds = "s"
)
