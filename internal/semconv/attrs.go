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

// UCUM units used by the telemetry package's self-observability metrics.
const (
	UnitSeries        = "{series}"
	UnitDimensionless = "1"
)
