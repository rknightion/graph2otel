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
	// AttrClipMode says what became of the series graph2otel.series.clipped
	// counts: "folded" (summed into the `other` bucket, because the metric is
	// additive) or "dropped" (discarded, because summing it would have emitted a
	// number that was never measured). Two values, fixed (#235).
	AttrClipMode = "mode"
)

// Process-identity attribute keys, carried by graph2otel.build_info (a constant-1
// gauge) and by the graph2otel.startup marker (a log record, #310). Both signals
// read AttrVersion from internal/version.String and AttrGoVersion from
// runtime.Version — one source each, so a deploy marker and the build_info gauge
// can never disagree about which build is running.
const (
	// AttrGoVersion is the Go runtime version the binary was built with, e.g.
	// "go1.25.1". Bounded: one value per build.
	AttrGoVersion = "go.version"
	// AttrConfigFingerprint is the one-way, secret-free fingerprint of the
	// effective configuration (internal/startupevent.Fingerprint): 16 lowercase
	// hex characters. It is PROCESS-WIDE — it covers every configured tenant's
	// settings — so it says "this process's configuration changed", never "your
	// tenant's configuration changed".
	//
	// Log-only. It changes on every meaningful configuration edit, so as a metric
	// label it would mint a new series per configuration and never stop paying
	// for the old ones.
	AttrConfigFingerprint = "config.fingerprint"
	// AttrConfigTenantCount is how many tenants the process is configured with.
	// A count, never an identity: it makes a single startup record legible
	// ("one of six tenants") without a correlation query.
	AttrConfigTenantCount = "config.tenant_count"
)

// Collector self-observability attribute keys, used by internal/collector's
// Scheduler to label its graph2otel.scrape.* and graph2otel.checkpoint.* metrics.
const (
	// AttrCollector names the collector a scrape.* metric point describes
	// (e.g. "devices", "auditlogs").
	AttrCollector = "collector"
	// AttrCollectorTransport names the resolved transport for a collector
	// availability metric. It is distinct from AttrIngestTransport, which is
	// log-only provenance for an individual data record.
	AttrCollectorTransport = "collector.transport"
	// AttrReason names the bounded explanation for AttrState.
	AttrReason = "reason"
	// AttrTrafficClass distinguishes ordinary scheduled collection from bounded
	// cold-start backfill and the replay receipt reserved by #382. Values come
	// from telemetry.TrafficClass; collectors never supply arbitrary strings.
	AttrTrafficClass = "traffic_class"
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
	//     which is the seam that reaches every registered collector. First stamp wins, so
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

	// AttrAttrsTruncated marks a log record whose attribute set was clipped at
	// the emitter boundary to fit the backend's structured-metadata limit
	// (#419). "true" or absent — a record is never marked "false", so
	// `| attrs_truncated = "true"` finds every affected record with no
	// negative-match subtlety.
	//
	// The mark is not decoration. A clipped value is shorter than the source
	// field, and a reader who cannot tell that apart will read a truncated
	// command line as the whole command line. Marking degradation is what makes
	// degradation acceptable instead of a quiet lie.
	AttrAttrsTruncated = "attrs.truncated"
	// AttrAttrsTruncatedBytes is how many bytes of attribute value the clip
	// removed from this record. It is the size of the loss, per record — the
	// count of affected records lives on graph2otel.event.attrs_truncated.
	AttrAttrsTruncatedBytes = "attrs.truncated_bytes"
	// AttrAttrsTruncatedKeys names the attributes this record's clip shortened,
	// comma-joined. This is the diagnostic that finally identifies an oversized
	// record shape in production: the collector is on the metric, the offending
	// FIELD is only here.
	AttrAttrsTruncatedKeys = "attrs.truncated_keys"
	// AttrAttrsDropped is how many attributes had to be removed outright because
	// their KEYS alone exceeded the budget — a record of hundreds of attributes,
	// where no amount of value clipping fits. Nonzero means this record is
	// missing dimensions, not merely shortened ones, so it is a louder signal
	// than AttrAttrsTruncated and absent on every ordinary clip.
	AttrAttrsDropped = "attrs.dropped"
)

// UCUM units used by the telemetry package's self-observability metrics.
const (
	UnitSeries        = "{series}"
	UnitRecords       = "{record}"
	UnitRuns          = "{run}"
	UnitDimensionless = "1"
	// UnitSeconds is used by the collector self-obs duration/staleness/budget gauges.
	UnitSeconds = "s"
)
