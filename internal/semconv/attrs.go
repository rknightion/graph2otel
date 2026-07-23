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
	// AttrField names the wire field a graph2otel.api.unexpected point describes.
	// Bounded: the value is a field name from graph2otel's own source, never data.
	AttrField = "field"
	// AttrKind names the class of a graph2otel.api.unexpected finding — see
	// internal/wirecheck for the bounded value set.
	AttrKind = "kind"
	// AttrTenantID identifies which tenant produced a record. It is on EVERY
	// signal — self-obs and domain, metrics and logs (#143).
	//
	// Two writers set it, deliberately:
	//   - collector/selfobs.go stamps it on scrape.*/checkpoint.* via selfObsAttrs.
	//   - telemetry.WithTenant stamps everything else at the emitter boundary,
	//     which is the seam that reaches all 58 collectors. First stamp wins, so
	//     the self-obs value above passes through untouched.
	//
	// Bounded cardinality: one value per operator-configured tenant. It grows with
	// tenant COUNT, never with tenant SIZE, which is what the #112 rule forbids —
	// so it is metric-label-safe, and internal/signalcapture correctly does not
	// flag it.
	//
	// It is a METRIC label, unlike AttrIngestTransport below. That asymmetry is
	// deliberate and is the whole point: there is one MeterProvider and one OTLP
	// resource per process, so without this label two tenants' domain metrics are
	// not merely unsliceable — they are the same series, interleaving samples into
	// a meaningless number.
	//
	// Empty means "no tenant configured" and stamps nothing, keeping single-tenant
	// deploys byte-identical.
	AttrTenantID = "tenant_id"
)

// Data-record attribute keys, stamped by the telemetry emitter facade rather
// than by collectors.
const (
	// AttrIngestTransport names the transport that produced a log record:
	// "graph", "blob", "o365_activity", "audit_query" or "report_export". See
	// telemetry.Transport for the values and telemetry.WithTransport for the
	// stamping seam.
	//
	// Deliberately NOT named "source" (#141): that key already carries three
	// unrelated live meanings — which Graph endpoint a certificate came from
	// (intune/certificates: "managed_device" / "user_pfx") and Microsoft's own
	// `source` field passed through verbatim (entra/riskdetections). It is also
	// distinct from the `source: graph|blob` CONFIG key (#144), which selects a
	// transport rather than reporting one.
	//
	// Bounded (five values), so it is metric-label-safe under the cardinality
	// rule (#112) — but it is stamped on LOGS ONLY, because adding a label to an
	// existing metric changes that metric's series identity and would break
	// dashboards and alerts built on the current names (#82).
	AttrIngestTransport = "ingest_transport"
)

// UCUM units used by the telemetry package's self-observability metrics.
const (
	UnitSeries        = "{series}"
	UnitDimensionless = "1"
	// UnitSeconds is used by the collector self-obs duration/staleness/budget gauges.
	UnitSeconds = "s"
)
