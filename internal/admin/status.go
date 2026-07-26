package admin

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/rknightion/graph2otel/internal/availability"
	"github.com/rknightion/graph2otel/internal/collector"
	"github.com/rknightion/graph2otel/internal/graphclient"
	"github.com/rknightion/graph2otel/internal/recordoutcome"
	"github.com/rknightion/graph2otel/internal/telemetry"
)

// Health states surfaced on the admin status page.
const (
	healthHealthy  = "healthy"
	healthDegraded = "degraded"
	healthStarting = "starting"
)

// StartupFailureCode is the bounded, non-secret reason a configured tenant
// could not reach collector construction. The composition root logs the raw
// error; admin retains only one of these codes.
type StartupFailureCode string

const (
	StartupFailureCredentialInitialization  StartupFailureCode = "credential_initialization_failed" //nolint:gosec // bounded status code, not a credential
	StartupFailureGraphClientInitialization StartupFailureCode = "graph_client_initialization_failed"
)

// TenantStartupFailure is the sanitized operator-facing form of a startup
// failure. Reason is derived inside this package from Code; callers cannot
// provide arbitrary text for JSON or HTML rendering.
type TenantStartupFailure struct {
	Code   StartupFailureCode `json:"code"`
	Reason string             `json:"reason"`
}

const (
	readinessReady                  = "ready"
	readinessNoWorkingTenants       = "no_working_tenants"
	readinessWaitingForFirstSuccess = "waiting_for_first_success"
)

// ReadinessStatus distinguishes a live HTTP server from a process that cannot
// yet collect useful data. A tenant is successful for the process lifetime
// once any of its collector rows has Runs > Failures.
type ReadinessStatus struct {
	Ready             bool   `json:"ready"`
	State             string `json:"state"`
	ConfiguredTenants int    `json:"configured_tenants"`
	WorkingTenants    int    `json:"working_tenants"`
	SuccessfulTenants int    `json:"successful_tenants"`
	Reason            string `json:"reason"`
}

// DeliverySource reports the process-wide exporter callback state. The
// telemetry Provider satisfies it alongside ThroughputSource. It is optional:
// a caller that supplies only ThroughputSource retains the pre-delivery admin
// surface.
type DeliverySource interface {
	Delivery() telemetry.DeliverySnapshot
}

// DeliveryStatus is the bounded admin projection of one process-wide delivery
// snapshot. Metrics and logs are fixed fields because the underlying signal set
// is closed and their state must remain independent.
type DeliveryStatus struct {
	Metrics DeliverySignalStatus `json:"metrics"`
	Logs    DeliverySignalStatus `json:"logs"`
}

// DeliverySignalStatus contains only the frozen counters, timestamps, state,
// and failure code. Raw exporter errors never enter this package.
type DeliverySignalStatus struct {
	State telemetry.DeliveryState `json:"state"`

	ExportAttempts     uint64 `json:"export_attempts"`
	ExportSuccesses    uint64 `json:"export_successes"`
	ExportFailures     uint64 `json:"export_failures"`
	ForceFlushFailures uint64 `json:"force_flush_failures"`
	ShutdownFailures   uint64 `json:"shutdown_failures"`

	LastSuccessAt   string                        `json:"last_success_at,omitempty"`
	LastFailureAt   string                        `json:"last_failure_at,omitempty"`
	LastFailureCode telemetry.DeliveryFailureCode `json:"last_failure_code,omitempty"`
}

func deliveryStatusFrom(snapshot telemetry.DeliverySnapshot) *DeliveryStatus {
	return &DeliveryStatus{
		Metrics: deliverySignalStatusFrom(snapshot.Metrics),
		Logs:    deliverySignalStatusFrom(snapshot.Logs),
	}
}

func deliverySignalStatusFrom(signal telemetry.DeliverySignal) DeliverySignalStatus {
	return DeliverySignalStatus{
		State:              signal.State,
		ExportAttempts:     signal.ExportAttempts,
		ExportSuccesses:    signal.ExportSuccesses,
		ExportFailures:     signal.ExportFailures,
		ForceFlushFailures: signal.ForceFlushFailures,
		ShutdownFailures:   signal.ShutdownFailures,
		LastSuccessAt:      signal.LastSuccessAt,
		LastFailureAt:      signal.LastFailureAt,
		LastFailureCode:    signal.LastFailureCode,
	}
}

// CapacitySource reports cumulative logical-volume attribution and process OTLP
// transport totals. *telemetry.Provider satisfies it alongside
// ThroughputSource. Both snapshots are passive and immutable.
type CapacitySource interface {
	Volume() []telemetry.VolumeRow
	Transport() telemetry.OTLPTransportSnapshot
}

// CapacityStatus separates exact cumulative counters from an optional cost
// estimate. Cost is absent unless the operator explicitly enables pricing.
type CapacityStatus struct {
	Volume    []CapacityVolumeRow     `json:"volume"`
	Transport CapacityTransportStatus `json:"transport"`
	Cost      *CostStatus             `json:"cost,omitempty"`
}

// CapacityVolumeRow is one exact cumulative attribution row.
type CapacityVolumeRow struct {
	TenantID        string                 `json:"tenant_id"`
	Collector       string                 `json:"collector"`
	IngestTransport telemetry.Transport    `json:"ingest_transport"`
	TrafficClass    telemetry.TrafficClass `json:"traffic_class"`
	SourceRecords   uint64                 `json:"source_records"`
	MetricPoints    uint64                 `json:"metric_points"`
	LogPoints       uint64                 `json:"log_points"`
}

// CapacityTransportStatus is exact cumulative process transport activity. It
// deliberately has no tenant or collector attribution.
type CapacityTransportStatus struct {
	Metrics CapacityTransportSignalStatus `json:"metrics"`
	Logs    CapacityTransportSignalStatus `json:"logs"`
}

type CapacityTransportSignalStatus struct {
	TransmittedPayloadBytes uint64 `json:"transmitted_payload_bytes"`
	RetryAttempts           uint64 `json:"retry_attempts"`
}

const (
	costIntervalScope   = "all_observed_traffic"
	costProjectionScope = "recurring_steady_state_only"
)

// CostStatus is an observational estimate from operator-supplied rates. The
// interval includes every observed traffic class; the recurring projection and
// budget ratio include steady-state traffic only. It is display-only and has
// no scheduler, limiter, or exporter callback.
type CostStatus struct {
	Currency        string `json:"currency"`
	Version         string `json:"version"`
	Source          string `json:"source"`
	EffectiveAt     string `json:"effective_at"`
	Period          string `json:"period"`
	IntervalScope   string `json:"interval_scope"`
	ProjectionScope string `json:"projection_scope"`

	Rates CostRatesStatus `json:"rates"`

	ObservedIntervalSeconds   float64         `json:"observed_interval_seconds"`
	IntervalMicrounits        uint64          `json:"interval_microunits"`
	ProjectedPeriodMicrounits uint64          `json:"projected_period_microunits"`
	BudgetMicrounits          uint64          `json:"budget_microunits"`
	BudgetRatio               *float64        `json:"budget_ratio,omitempty"`
	BudgetPercent             float64         `json:"-"`
	Rows                      []CostRowStatus `json:"rows"`
}

type CostRatesStatus struct {
	SourceRecordMicrounits           uint64 `json:"source_record_microunits"`
	MetricPointMicrounits            uint64 `json:"metric_point_microunits"`
	LogRecordMicrounits              uint64 `json:"log_record_microunits"`
	TransmittedPayloadByteMicrounits uint64 `json:"transmitted_payload_byte_microunits"`
}

// CostRowStatus keeps exact logical cost components separate from the
// estimated payload-byte allocation. Attribution is always "estimated".
type CostRowStatus struct {
	TenantID        string `json:"tenant_id"`
	Collector       string `json:"collector"`
	IngestTransport string `json:"ingest_transport"`
	TrafficClass    string `json:"traffic_class"`
	Attribution     string `json:"attribution"`

	SourceRecordCostMicrounits  uint64 `json:"source_record_cost_microunits"`
	MetricPointCostMicrounits   uint64 `json:"metric_point_cost_microunits"`
	LogRecordCostMicrounits     uint64 `json:"log_record_cost_microunits"`
	AllocatedMetricPayloadBytes uint64 `json:"allocated_metric_payload_bytes"`
	AllocatedLogPayloadBytes    uint64 `json:"allocated_log_payload_bytes"`
	AllocatedPayloadBytes       uint64 `json:"allocated_payload_bytes"`
	PayloadCostMicrounits       uint64 `json:"payload_cost_microunits"`
	IntervalMicrounits          uint64 `json:"interval_microunits"`
	ProjectedPeriodMicrounits   uint64 `json:"projected_period_microunits"`
}

func capacityStatusFrom(
	rows []telemetry.VolumeRow,
	transport telemetry.OTLPTransportSnapshot,
	cost *CostStatus,
) *CapacityStatus {
	volume := make([]CapacityVolumeRow, 0, len(rows))
	for _, row := range rows {
		volume = append(volume, CapacityVolumeRow{
			TenantID:        row.TenantID,
			Collector:       row.Collector,
			IngestTransport: row.Transport,
			TrafficClass:    row.TrafficClass,
			SourceRecords:   row.SourceRecords,
			MetricPoints:    row.MetricPoints,
			LogPoints:       row.LogPoints,
		})
	}
	return &CapacityStatus{
		Volume: volume,
		Transport: CapacityTransportStatus{
			Metrics: capacityTransportSignalStatusFrom(transport.Metrics),
			Logs:    capacityTransportSignalStatusFrom(transport.Logs),
		},
		Cost: cost,
	}
}

func capacityTransportSignalStatusFrom(
	signal telemetry.OTLPTransportSignal,
) CapacityTransportSignalStatus {
	return CapacityTransportSignalStatus{
		TransmittedPayloadBytes: signal.PayloadBytes,
		RetryAttempts:           signal.RetryAttempts,
	}
}

// consecutiveFailureThreshold is the number of back-to-back failures at which
// a collector drags overall health to "degraded".
const consecutiveFailureThreshold = 3

// overdueIntervalFactor is how many whole intervals a collector may go without
// starting a run before the page flags it "overdue" (a wedged-ticker signal).
const overdueIntervalFactor = 2

// Skip categories classify why a collector the operator might expect to see was
// never registered. They are derived from the free-form reason string the
// composition root supplies (admin has no dependency on license/preflight), so
// the page can style license gating differently from a deliberate opt-out.
const (
	skipCatLicense      = "license"      // license/permission tier missing ("requires ...")
	skipCatDisabled     = "disabled"     // turned off in config ("disabled by config")
	skipCatExperimental = "experimental" // beta, not opted into ("beta; enable ...")
)

// skipCategory buckets a skip-reason string into one of the skipCat* constants,
// or "" when it matches none. It matches on the prefixes the composition root
// (cmd/graph2otel/tenants.go) emits: "requires <cap>", "disabled by config",
// and "beta; enable explicitly to opt in".
func skipCategory(reason string) string {
	switch {
	case strings.HasPrefix(reason, "requires "):
		return skipCatLicense
	case strings.HasPrefix(reason, "disabled"):
		return skipCatDisabled
	case strings.HasPrefix(reason, "beta"):
		return skipCatExperimental
	default:
		return ""
	}
}

// CollectorSource pairs one tenant's registered collectors with the
// StatusTracker its Scheduler records into. The admin package never keeps its
// own copy of run state — it renders a fresh Snapshot()/HistorySnapshot() of
// these on every request.
type CollectorSource struct {
	// TenantID identifies which tenant this Registry/Status pair belongs to
	// (graph2otel runs one Scheduler, Registry and StatusTracker per tenant).
	TenantID       string
	Registry       *collector.Registry
	Status         *collector.StatusTracker
	Availability   *availability.Tracker
	StartupFailure StartupFailureCode
}

// SkipKey identifies a collector that the composition root chose not to
// register for a tenant (e.g. a missing Graph permission or license tier).
type SkipKey struct {
	TenantID  string
	Collector string
}

// Status is the full admin status snapshot, serialized as JSON at
// /api/status.json and rendered as HTML at "/".
type Status struct {
	Service       ServiceInfo     `json:"service"`
	Health        string          `json:"health"`
	HealthReasons []string        `json:"health_reasons,omitempty"`
	Readiness     ReadinessStatus `json:"readiness"`
	Tenants       []TenantStatus  `json:"tenants"`
	GeneratedAt   string          `json:"generated_at"`
	// RefreshMs is the client poll interval in milliseconds (admin.refresh_interval).
	// The page falls back to 5000 when this is 0. The 1s freshness ticker is independent.
	RefreshMs int `json:"refresh_ms,omitempty"`

	// Runtime, Throughput, Fleet and Cardinality are the ~10-minute in-process
	// trends behind the Overview tab's charts (#227). They are sampled on a
	// background ticker, never per request, and are never emitted as OTLP —
	// the graph2otel.* self-obs metrics already carry what belongs on the wire.
	// Every series is empty until the sampler has enough observations, which
	// the page renders as "collecting…".
	Runtime    RuntimeInfo    `json:"runtime"`
	Throughput ThroughputInfo `json:"throughput"`
	Fleet      FleetInfo      `json:"fleet"`
	// Delivery is a fresh, process-wide exporter callback snapshot. It is
	// omitted when the existing throughput-provider argument does not also
	// implement DeliverySource.
	Delivery *DeliveryStatus `json:"delivery,omitempty"`
	// Capacity is a fresh exact cumulative volume/transport snapshot plus the
	// sampler's latest optional, explicitly estimated cost projection.
	Capacity *CapacityStatus `json:"capacity,omitempty"`
	// SeriesTrend is deliberately NOT named Cardinality: pageModel already has a
	// Cardinality field (the tab view), and an embedded Status field of the same
	// name would be silently shadowed in every template expression.
	SeriesTrend CardinalityTrend `json:"cardinality"`
}

// RuntimeInfo is a point-in-time Go runtime snapshot plus its short-term
// trends. GCRateSeries is differenced from MemStats.NumGC over elapsed wall
// time, so it is one sample shorter than the value series.
type RuntimeInfo struct {
	Goroutines       int       `json:"goroutines"`
	GOMAXPROCS       int       `json:"gomaxprocs"`
	HeapAllocBytes   uint64    `json:"heap_alloc_bytes"`
	HeapAlloc        string    `json:"heap_alloc"` // humanized, e.g. "12M"
	NumGC            uint32    `json:"num_gc"`
	GoroutinesSeries []int     `json:"goroutines_series,omitempty"`
	HeapAllocSeries  []uint64  `json:"heap_alloc_series,omitempty"`
	GCRateSeries     []float64 `json:"gc_rate_series,omitempty"`
}

// ThroughputInfo is the emit-side throughput of the telemetry pipeline: metric
// data points and log records shipped per second, differenced from lifetime
// totals. The totals count what the Emitter handed to the SDK, which is not
// the same as what the OTLP backend accepted.
type ThroughputInfo struct {
	MetricPointsPerSec float64   `json:"metric_points_per_sec"`
	LogRecordsPerSec   float64   `json:"log_records_per_sec"`
	MetricPointsTotal  uint64    `json:"metric_points_total"`
	LogRecordsTotal    uint64    `json:"log_records_total"`
	MetricPointsSeries []float64 `json:"metric_points_series,omitempty"`
	LogRecordsSeries   []float64 `json:"log_records_series,omitempty"`
}

// FleetInfo is the collector roll-up across every tenant, so a creeping
// degradation shows as a trend rather than only as a current number. A
// registered collector that has not run yet is Pending, never Failing.
type FleetInfo struct {
	Enabled            int       `json:"enabled"`
	Failing            int       `json:"failing"`
	Pending            int       `json:"pending"`
	MeanDurationMs     float64   `json:"mean_duration_ms"`
	FailingSeries      []int     `json:"failing_series,omitempty"`
	MeanDurationSeries []float64 `json:"mean_duration_series,omitempty"`
}

// CardinalityTrend is the total active-series count and its trend — the number
// Grafana Cloud bills on. Both are zero when self-observability is off, since
// no tracker is wired to count series in that case.
type CardinalityTrend struct {
	TotalSeries int   `json:"total_series"`
	Series      []int `json:"series,omitempty"`
}

// ServiceInfo is the process identity/liveness header of the page.
type ServiceInfo struct {
	Version   string `json:"version"`
	GoVersion string `json:"go_version"`
	StartedAt string `json:"started_at"`
	UptimeSec int64  `json:"uptime_seconds"`
	Uptime    string `json:"uptime"`
}

// TenantStatus is one tenant's collector table plus a small roll-up used by the
// page's per-tenant header. The counts are derived from Collectors: EnabledCount
// is registered collectors, FailingCount those whose last run failed, PendingCount
// those that have not run yet, SkippedCount the genuinely-off rows, and
// CoveredCount the off rows whose records a registered twin still ships (#178).
// Covered rows are deliberately NOT in SkippedCount — a covered signal is not a
// gap, and the header must not tally it as one.
type TenantStatus struct {
	TenantID       string                `json:"tenant_id"`
	Working        bool                  `json:"working"`
	StartupFailure *TenantStartupFailure `json:"startup_failure,omitempty"`
	Collectors     []CollectorStatus     `json:"collectors"`
	EnabledCount   int                   `json:"enabled_count"`
	FailingCount   int                   `json:"failing_count"`
	PendingCount   int                   `json:"pending_count"`
	SkippedCount   int                   `json:"skipped_count"`
	CoveredCount   int                   `json:"covered_count"`
	// RateLimits is this tenant's client-side throttle-headroom panel: one row
	// per (tenant, workload) token bucket that has actually been used since
	// process start (#85). Empty for a tenant whose buckets are all idle (lazy
	// creation means an unused pair is simply absent) or when no limiter is
	// wired at all.
	RateLimits []RateLimitStatus `json:"rate_limits,omitempty"`
}

// RateLimitStatus is one throttle bucket on a tenant's headroom panel (#85).
type RateLimitStatus struct {
	Workload    string  `json:"workload"`
	LimitPerSec float64 `json:"limit_per_sec"`
	Burst       int     `json:"burst"`
	Tokens      float64 `json:"tokens_available"`
	HeadroomPct float64 `json:"headroom_pct"` // Tokens/Burst*100, 0 when Burst==0
	// HeadroomSeries is this bucket's headroom trend over the sampler window
	// (#227), oldest first. Empty until the sampler has seen the bucket — buckets
	// are lazily created, so a workload that has never been called has no trend.
	HeadroomSeries []float64 `json:"headroom_series,omitempty"`
}

// CollectorStatus is one row of a tenant's collector table: either a
// registered collector's latest run state, or a skipped collector's reason.
type CollectorStatus struct {
	Name string `json:"name"`
	// Availability is the canonical bounded current state shared with OTLP.
	// It is present whenever the composition root supplies an availability
	// tracker. The legacy compatibility fields below are projected from this
	// typed value rather than from free-form errors or skip prose.
	Availability *CollectorAvailability `json:"availability,omitempty"`
	// LastOutcome is the immutable bounded record accounting summary for the
	// latest completed run. It is absent until a run exists.
	LastOutcome *CollectorLastOutcome `json:"last_outcome,omitempty"`
	// Enabled is false for a collector the composition root chose not to
	// register at all; SkipReason then explains why (e.g. "requires P2").
	Enabled bool `json:"enabled"`
	// SkipReason is the raw reason a skipped collector was not registered;
	// SkipCategory buckets it (see skipCategory) so the page can badge
	// license-gating separately from a deliberate opt-out or a beta opt-in.
	SkipReason   string `json:"skip_reason,omitempty"`
	SkipCategory string `json:"skip_category,omitempty"`
	IntervalSec  int64  `json:"interval_seconds,omitempty"`

	// Transport names the ingest path a REGISTERED collector runs over — the
	// same taxonomy as the ingest_transport log attribute (#141), derived from
	// collector.TransportOf. For a source-switchable collector (#135 group D)
	// this is the ACTIVE source: a directory_audits running source=blob reports
	// "blob", because the collector registered under that name is the blob one.
	// Empty on a skipped row (nothing is running to have a transport).
	Transport string `json:"transport,omitempty"`
	// CoveredBy is set on a collector that is OFF but whose records are shipped
	// by a registered twin over another transport (a beta polled form covered by
	// its GA blob twin, or m365.unified_audit covered by m365.activity). It names
	// that twin and its transport so the page states "collected via X" rather
	// than a bare "disabled" — a covered signal is not a gap (#178). Nil when the
	// collector is genuinely uncollected anywhere (the only real gap).
	CoveredBy *Coverage `json:"covered_by,omitempty"`
	// State is the collector's durable checkpoint progress, read read-only from
	// the checkpoint store at render time (#178 Part B) — the watermark (+
	// staleness) for a window poller, the byte offset/blobs/newest-hour for a blob
	// consumer, and any in-flight job id. Nil for a collector that persists no
	// cursor (an inline snapshot collector) or a skipped row (nothing running).
	State *CollectorState `json:"state,omitempty"`

	HasRun         bool   `json:"has_run"`
	Runs           int64  `json:"runs"`
	Failures       int64  `json:"failures"`
	LastStartedAt  string `json:"last_started_at,omitempty"`
	LastFinishedAt string `json:"last_finished_at,omitempty"`
	LastDurationMs int64  `json:"last_duration_ms"`
	LastSuccess    bool   `json:"last_success"`
	LastError      string `json:"last_error,omitempty"`
	// ConsecutiveFailures is the current unbroken run of failures (0 on the
	// last success). SuccessRatePct is (runs-failures)/runs over the process
	// lifetime.
	ConsecutiveFailures int64   `json:"consecutive_failures"`
	SuccessRatePct      float64 `json:"success_rate_pct"`
	// StalenessSec/Staleness are the time since the last run attempt
	// (success or failure) — not specifically the last success, since
	// CollectorRun keeps only the most recent run's outcome.
	StalenessSec int64  `json:"staleness_seconds,omitempty"`
	Staleness    string `json:"staleness,omitempty"`
	// NextRunInSec/NextRunIn estimate the time until the next scheduled tick
	// (0 / "" when due or not yet run), derived from LastStarted+interval since
	// the scheduler's ticker is anchored near run start. Overdue is set when the
	// collector has not started a run in over overdueIntervalFactor intervals — a
	// wedged-ticker signal, distinct from a run that simply failed.
	NextRunInSec int64  `json:"next_run_in_seconds,omitempty"`
	NextRunIn    string `json:"next_run_in,omitempty"`
	Overdue      bool   `json:"overdue,omitempty"`
	// DurationMsSeries/OutcomeSeries are the recent-run history (oldest
	// first, aligned), feeding a duration sparkline and outcome strip.
	DurationMsSeries []int64 `json:"duration_ms_series,omitempty"`
	OutcomeSeries    []bool  `json:"outcome_series,omitempty"`
}

// CollectorAvailability is the admin JSON projection of availability.Point.
// Bounded detail slices are always present in JSON (empty arrays when none
// apply).
type CollectorAvailability struct {
	State               availability.State               `json:"state"`
	Reason              availability.Reason              `json:"reason"`
	Transport           telemetry.Transport              `json:"transport"`
	Limitations         []availability.Limitation        `json:"limitations"`
	MissingCapabilities []availability.MissingCapability `json:"missing_capabilities"`
}

// CollectorLastOutcome is the bounded latest-run payload exposed by admin.
type CollectorLastOutcome struct {
	Result recordoutcome.Result `json:"result"`
	Cause  recordoutcome.Cause  `json:"cause"`
	Counts OutcomeCounts        `json:"counts"`
}

// OutcomeCounts mirrors recordoutcome.Counts with an explicit stable JSON
// contract. recordoutcome is an internal Go value and intentionally has no
// transport tags of its own.
type OutcomeCounts struct {
	Fetched  uint64 `json:"fetched"`
	Mapped   uint64 `json:"mapped"`
	Emitted  uint64 `json:"emitted"`
	Deduped  uint64 `json:"deduped"`
	Filtered uint64 `json:"filtered"`
	Dropped  uint64 `json:"dropped"`
	Errored  uint64 `json:"errored"`
}

// Coverage names the registered twin that ships an off collector's records, and
// the transport it uses. It is the payload of CollectorStatus.CoveredBy (#178).
type Coverage struct {
	Collector string `json:"collector"`
	Transport string `json:"transport"`
}

// CollectorState is a registered collector's durable checkpoint progress, the
// payload of CollectorStatus.State (#178 Part B). Kind ("window"/"blob") selects
// which fields are meaningful; empty fields are omitted from the JSON. It is a
// read-only render-time snapshot — this is ops visibility, not per-entity data.
type CollectorState struct {
	Kind string `json:"kind"`
	// Window fields.
	Watermark    string `json:"watermark,omitempty"` // RFC3339; empty on cold start
	StalenessSec int64  `json:"staleness_seconds,omitempty"`
	Staleness    string `json:"staleness,omitempty"`
	SeenIDs      int    `json:"seen_ids,omitempty"`
	InFlightJob  string `json:"in_flight_job,omitempty"`
	// Blob fields.
	ByteOffset   int64  `json:"byte_offset,omitempty"`
	BlobsTracked int    `json:"blobs_tracked,omitempty"`
	NewestBlob   string `json:"newest_blob,omitempty"`
}

// collectorStateFrom maps a collector.CheckpointState (read from the checkpoint
// store) into the admin JSON payload, computing watermark staleness (now -
// watermark) for a window poller. Returns nil for a nil input so a collector
// that persists nothing shows no State block.
func collectorStateFrom(st *collector.CheckpointState, now time.Time) *CollectorState {
	if st == nil {
		return nil
	}
	cs := &CollectorState{
		Kind:         st.Kind,
		SeenIDs:      st.SeenIDs,
		InFlightJob:  st.InFlightJob,
		ByteOffset:   st.ByteOffset,
		BlobsTracked: st.BlobsTracked,
		NewestBlob:   st.NewestBlob,
	}
	if !st.Watermark.IsZero() {
		cs.Watermark = st.Watermark.UTC().Format(time.RFC3339)
		staleness := now.Sub(st.Watermark)
		if staleness < 0 { // guard a backward wall-clock jump (NTP)
			staleness = 0
		}
		cs.StalenessSec = int64(staleness / time.Second)
		cs.Staleness = staleness.Round(time.Second).String()
	}
	return cs
}

// conflicter is the subset of collectors.ConflictsWith the admin page needs to
// pair an off collector with the registered twin that covers it. Declared here
// (structurally) so admin does not import internal/collectors just to read one
// method — a blob/o365 twin already names its polled peer via ConflictsWith().
type conflicter interface {
	ConflictsWith() []string
}

func startupFailure(code StartupFailureCode) *TenantStartupFailure {
	switch code {
	case StartupFailureCredentialInitialization:
		return &TenantStartupFailure{
			Code:   code,
			Reason: "credential initialization failed",
		}
	case StartupFailureGraphClientInitialization:
		return &TenantStartupFailure{
			Code:   code,
			Reason: "graph client initialization failed",
		}
	default:
		// A typed string can still be explicitly converted from arbitrary text.
		// Never retain or render an unrecognized value: raw startup errors may
		// contain credential material and belong only in the process logs.
		return nil
	}
}

// buildTenantStatuses renders sources into one TenantStatus per source: a row
// per registered collector (from Registry.Entries(), reflecting the matching
// StatusTracker snapshot) plus a row per skip reason that names a collector
// the registry has no entry for. Tenants are returned in the order given;
// within a tenant, registered collectors keep registration order and skipped
// collectors are appended sorted by name for deterministic output.
func buildTenantStatuses(sources []CollectorSource, skipReasons map[SkipKey]string, now time.Time) []TenantStatus {
	tenants := make([]TenantStatus, 0, len(sources))
	for _, src := range sources {
		if src.Availability != nil {
			tenants = append(tenants, buildAvailabilityTenantStatus(src, now))
			continue
		}

		runs := src.Status.Snapshot()
		hist := src.Status.HistorySnapshot()

		var entries []collector.Entry
		if src.Registry != nil {
			entries = src.Registry.Entries()
		}
		registered := make(map[string]bool, len(entries))
		rows := make([]CollectorStatus, 0, len(entries))
		// coveredBy pairs a polled peer name with the REGISTERED twin that ships
		// its records. Built from the live registry (not a hand list), so a new
		// twin is recognized the day it lands — the same robustness the conflict
		// check (checkRegistryConflicts) relies on.
		coveredBy := map[string]Coverage{}
		for _, e := range entries {
			name := e.Collector.Name()
			registered[name] = true
			row := collectorStatusFor(name, e.Interval, runs, hist, now)
			row.Transport = string(collector.TransportOf(e.Collector))
			// Read the collector's durable checkpoint (watermark/byte offset/job id)
			// read-only at render time, so the page shows progress, not just
			// registration (#178 Part B). Nil for a collector that persists no cursor.
			row.State = collectorStateFrom(collector.CheckpointStateOf(e.Collector), now)
			rows = append(rows, row)
			if cw, ok := e.Collector.(conflicter); ok {
				for _, peer := range cw.ConflictsWith() {
					coveredBy[peer] = Coverage{Collector: name, Transport: row.Transport}
				}
			}
		}

		var skipNames []string
		for key := range skipReasons {
			if key.TenantID != src.TenantID || registered[key.Collector] {
				continue
			}
			skipNames = append(skipNames, key.Collector)
		}
		sort.Strings(skipNames)
		for _, name := range skipNames {
			reason := skipReasons[SkipKey{TenantID: src.TenantID, Collector: name}]
			row := CollectorStatus{
				Name:         name,
				Enabled:      false,
				SkipReason:   reason,
				SkipCategory: skipCategory(reason),
			}
			// If a registered twin ships this off collector's records, it is not a
			// gap — name the twin + transport so the page says "collected via X".
			if cov, ok := coveredBy[name]; ok {
				c := cov
				row.CoveredBy = &c
			}
			rows = append(rows, row)
		}

		failure := startupFailure(src.StartupFailure)
		ten := TenantStatus{
			TenantID:       src.TenantID,
			Working:        failure == nil && src.Registry != nil && src.Status != nil && len(entries) > 0,
			StartupFailure: failure,
			Collectors:     rows,
		}
		for _, c := range rows {
			switch {
			case !c.Enabled:
				// A covered collector is not a gap — count it apart from real skips
				// so the header roll-up never tallies a collected signal as missing.
				if c.CoveredBy != nil {
					ten.CoveredCount++
				} else {
					ten.SkippedCount++
				}
			default:
				ten.EnabledCount++
				switch {
				case !c.HasRun:
					ten.PendingCount++
				case !c.LastSuccess:
					ten.FailingCount++
				}
			}
		}
		tenants = append(tenants, ten)
	}
	return tenants
}

// buildAvailabilityTenantStatus joins the canonical availability census with
// registry, durable-checkpoint, and run-history details. The tracker decides
// which rows exist and their bounded current meaning; registry ConflictsWith
// contributes only the legacy covered_by identity.
func buildAvailabilityTenantStatus(src CollectorSource, now time.Time) TenantStatus {
	runs := src.Status.Snapshot()
	hist := src.Status.HistorySnapshot()

	var entries []collector.Entry
	if src.Registry != nil {
		entries = src.Registry.Entries()
	}
	entryByName := make(map[string]collector.Entry, len(entries))
	coveredBy := make(map[string]Coverage)
	for _, entry := range entries {
		name := entry.Collector.Name()
		entryByName[name] = entry
		if cw, ok := entry.Collector.(conflicter); ok {
			for _, peer := range cw.ConflictsWith() {
				coveredBy[peer] = Coverage{
					Collector: name,
					Transport: string(collector.TransportOf(entry.Collector)),
				}
			}
		}
	}

	points := src.Availability.Snapshot()
	rows := make([]CollectorStatus, 0, len(points))
	for _, point := range points {
		var interval time.Duration
		entry, registered := entryByName[point.Collector]
		if registered {
			interval = entry.Interval
		}
		row := collectorStatusFor(point.Collector, interval, runs, hist, now)
		row.Availability = collectorAvailabilityFrom(point)
		row.LastOutcome = collectorLastOutcomeFrom(point.LastOutcome)
		row.Enabled = availabilityEnabled(point)
		row.Transport = string(point.Transport)
		if !row.Enabled {
			row.SkipReason = string(point.Reason)
			row.SkipCategory = availabilitySkipCategory(point)
		}
		if registered {
			row.State = collectorStateFrom(collector.CheckpointStateOf(entry.Collector), now)
		}
		if point.State == availability.StateCovered {
			if coverage, ok := coveredBy[point.Collector]; ok {
				c := coverage
				row.CoveredBy = &c
			}
		}
		rows = append(rows, row)
	}

	failure := startupFailure(src.StartupFailure)
	tenant := TenantStatus{
		TenantID:       src.TenantID,
		Working:        failure == nil && src.Registry != nil && src.Status != nil && len(entries) > 0,
		StartupFailure: failure,
		Collectors:     rows,
	}
	countTenantRows(&tenant)
	return tenant
}

func collectorAvailabilityFrom(point availability.Point) *CollectorAvailability {
	limitations := make([]availability.Limitation, len(point.Limitations))
	copy(limitations, point.Limitations)
	missingCapabilities := make([]availability.MissingCapability, len(point.MissingCapabilities))
	copy(missingCapabilities, point.MissingCapabilities)
	return &CollectorAvailability{
		State:               point.State,
		Reason:              point.Reason,
		Transport:           point.Transport,
		Limitations:         limitations,
		MissingCapabilities: missingCapabilities,
	}
}

func collectorLastOutcomeFrom(summary *recordoutcome.Summary) *CollectorLastOutcome {
	if summary == nil {
		return nil
	}
	return &CollectorLastOutcome{
		Result: summary.Result,
		Cause:  summary.Cause,
		Counts: OutcomeCounts{
			Fetched:  summary.Counts.Fetched,
			Mapped:   summary.Counts.Mapped,
			Emitted:  summary.Counts.Emitted,
			Deduped:  summary.Counts.Deduped,
			Filtered: summary.Counts.Filtered,
			Dropped:  summary.Counts.Dropped,
			Errored:  summary.Counts.Errored,
		},
	}
}

// availabilityEnabled projects the legacy enabled field from the typed point.
// A runtime permission block has a completed run and remains configured to
// retry; a static license block has no run and remains off.
func availabilityEnabled(point availability.Point) bool {
	switch point.State {
	case availability.StateDisabled, availability.StateCovered, availability.StateStartupFailed:
		return false
	case availability.StateBlocked:
		return point.LastOutcome != nil
	default:
		return true
	}
}

func availabilitySkipCategory(point availability.Point) string {
	switch point.Reason {
	case availability.ReasonLicenseUnavailable, availability.ReasonPermissionDenied:
		return skipCatLicense
	case availability.ReasonExperimentalNotEnabled:
		return skipCatExperimental
	case availability.ReasonTransportNotConfigured,
		availability.ReasonHighVolumeNotEnabled,
		availability.ReasonDisabledByConfig:
		return skipCatDisabled
	default:
		return ""
	}
}

func countTenantRows(tenant *TenantStatus) {
	for _, row := range tenant.Collectors {
		if row.Availability != nil {
			switch {
			case row.Availability.State == availability.StateCovered:
				tenant.CoveredCount++
			case row.Availability.State == availability.StateStartupFailed:
				tenant.FailingCount++
			case !row.Enabled:
				tenant.SkippedCount++
			default:
				tenant.EnabledCount++
				switch row.Availability.State {
				case availability.StateStarting:
					tenant.PendingCount++
				case availability.StateBlocked,
					availability.StateDegraded,
					availability.StateFailed,
					availability.StateStartupFailed:
					tenant.FailingCount++
				}
			}
			continue
		}

		switch {
		case !row.Enabled:
			if row.CoveredBy != nil {
				tenant.CoveredCount++
			} else {
				tenant.SkippedCount++
			}
		default:
			tenant.EnabledCount++
			switch {
			case !row.HasRun:
				tenant.PendingCount++
			case !row.LastSuccess:
				tenant.FailingCount++
			}
		}
	}
}

// attachHeadroomTrends fills each rendered throttle row's HeadroomSeries from
// the sampler's per-bucket ring. Rows the sampler has never seen keep an empty
// series, which the page draws as no sparkline at all.
func attachHeadroomTrends(tenants []TenantStatus, s *sampler) {
	if s == nil {
		return
	}
	for ti := range tenants {
		for ri := range tenants[ti].RateLimits {
			row := &tenants[ti].RateLimits[ri]
			row.HeadroomSeries = s.headroomTrend(tenants[ti].TenantID, row.Workload)
		}
	}
}

// attachRateLimits groups the flat headroom snapshot by tenant and attaches each
// tenant's buckets to its already-built TenantStatus (#85). A bucket whose tenant
// has no status row (e.g. a tenant whose client build failed so it has no source)
// is dropped — the panel only annotates tenants the page already shows. Buckets
// arrive pre-sorted by (tenant, workload) from WorkloadLimiter.Snapshot, so each
// tenant's rows keep that deterministic order.
func attachRateLimits(tenants []TenantStatus, headroom []graphclient.WorkloadHeadroom) {
	if len(headroom) == 0 {
		return
	}
	byTenant := make(map[string][]RateLimitStatus, len(tenants))
	for _, h := range headroom {
		var pct float64
		if h.Burst > 0 {
			pct = h.Tokens / float64(h.Burst) * 100
		}
		byTenant[h.TenantID] = append(byTenant[h.TenantID], RateLimitStatus{
			Workload:    string(h.Workload),
			LimitPerSec: h.LimitPerSec,
			Burst:       h.Burst,
			Tokens:      h.Tokens,
			HeadroomPct: pct,
		})
	}
	for i := range tenants {
		if rows, ok := byTenant[tenants[i].TenantID]; ok {
			tenants[i].RateLimits = rows
		}
	}
}

// collectorStatusFor builds one registered collector's status row from its
// StatusTracker run/history snapshots (absent when the collector has not run
// yet, e.g. immediately after startup).
func collectorStatusFor(name string, interval time.Duration, runs map[string]collector.CollectorRun, hist map[string]collector.CollectorHistory, now time.Time) CollectorStatus {
	cs := CollectorStatus{
		Name:        name,
		Enabled:     true,
		IntervalSec: int64(interval / time.Second),
	}
	if run, ok := runs[name]; ok {
		cs.HasRun = true
		cs.Runs = run.Runs
		cs.Failures = run.Failures
		cs.LastStartedAt = run.LastStarted.UTC().Format(time.RFC3339)
		cs.LastFinishedAt = run.LastFinished.UTC().Format(time.RFC3339)
		cs.LastDurationMs = run.LastDuration.Milliseconds()
		cs.LastSuccess = run.LastSuccess
		cs.LastError = run.LastError
		cs.ConsecutiveFailures = run.ConsecutiveFailures
		cs.SuccessRatePct = successRatePct(run.Runs, run.Failures)

		staleness := now.Sub(run.LastFinished)
		if staleness < 0 { // guard a backward wall-clock jump (NTP)
			staleness = 0
		}
		cs.StalenessSec = int64(staleness / time.Second)
		cs.Staleness = staleness.Round(time.Second).String()

		if interval > 0 {
			until := run.LastStarted.Add(interval).Sub(now)
			if until < 0 { // due/overdue
				until = 0
			}
			cs.NextRunInSec = int64(until / time.Second)
			cs.NextRunIn = until.Round(time.Second).String()
			if now.Sub(run.LastStarted) > overdueIntervalFactor*interval {
				cs.Overdue = true
			}
		}
	}
	if h, ok := hist[name]; ok {
		cs.DurationMsSeries = h.DurationMs
		cs.OutcomeSeries = h.Outcomes
	}
	return cs
}

// successRatePct reports the lifetime success rate as a percentage. It
// returns 0 when no run has happened yet (rate is undefined), which pairs
// with HasRun=false so a consumer can show "—" rather than a misleading 0%.
func successRatePct(runs, failures int64) float64 {
	if runs <= 0 {
		return 0
	}
	return float64(runs-failures) / float64(runs) * 100
}

// deriveHealth summarizes overall service health from the per-tenant
// collector rows. Skipped collectors (Enabled=false) never affect health —
// they are an intentional configuration choice, not a failure. Precedence:
// any collector with 3+ consecutive failures or whose last run failed makes
// the service "degraded"; otherwise a collector that has not yet run makes it
// "starting"; otherwise "healthy".
func deriveHealth(tenants []TenantStatus) (string, []string) {
	var reasons, pending []string
	for _, tenant := range tenants {
		reasons = append(reasons, deriveTenantHealthReasons(tenant)...)
		for _, c := range tenant.Collectors {
			if c.Availability != nil {
				switch c.Availability.State {
				case availability.StateBlocked:
					if c.Availability.Reason == availability.ReasonPermissionDenied {
						reasons = append(reasons, fmt.Sprintf(
							"tenant %q collector %q: %s/%s",
							tenant.TenantID,
							c.Name,
							c.Availability.State,
							c.Availability.Reason,
						))
					}
				case availability.StateDegraded,
					availability.StateFailed:
					reasons = append(reasons, fmt.Sprintf(
						"tenant %q collector %q: %s/%s",
						tenant.TenantID,
						c.Name,
						c.Availability.State,
						c.Availability.Reason,
					))
				case availability.StateStartupFailed:
					// A tenant-level startup failure already supplies one bounded
					// reason. Do not repeat it once per census row.
					if tenant.StartupFailure == nil {
						reasons = append(reasons, fmt.Sprintf(
							"tenant %q collector %q: %s/%s",
							tenant.TenantID,
							c.Name,
							c.Availability.State,
							c.Availability.Reason,
						))
					}
				case availability.StateStarting:
					pending = append(pending, tenant.TenantID+"/"+c.Name)
				}
				continue
			}
			if !c.Enabled {
				continue
			}
			if !c.HasRun {
				pending = append(pending, tenant.TenantID+"/"+c.Name)
				continue
			}
			switch {
			case c.ConsecutiveFailures >= consecutiveFailureThreshold:
				reasons = append(reasons, fmt.Sprintf("tenant %q collector %q: %d consecutive failures", tenant.TenantID, c.Name, c.ConsecutiveFailures))
			case !c.LastSuccess:
				reasons = append(reasons, fmt.Sprintf("tenant %q collector %q: last run failed", tenant.TenantID, c.Name))
			}
		}
	}
	switch {
	case len(reasons) > 0:
		return healthDegraded, reasons
	case len(pending) > 0:
		return healthStarting, []string{"waiting for first run: " + strings.Join(pending, ", ")}
	default:
		return healthHealthy, nil
	}
}

func deriveTenantHealthReasons(tenant TenantStatus) []string {
	if tenant.StartupFailure == nil {
		return nil
	}
	return []string{fmt.Sprintf("tenant %q: %s", tenant.TenantID, tenant.StartupFailure.Reason)}
}

// deriveReadiness uses only the immutable tenant snapshot assembled for this
// request. It needs no mutable latch: StatusTracker lifetime counts preserve a
// prior success even when the latest run fails (Runs > Failures).
func deriveReadiness(tenants []TenantStatus) ReadinessStatus {
	out := ReadinessStatus{ConfiguredTenants: len(tenants)}
	if len(tenants) == 0 {
		out.Ready = true
		out.State = readinessReady
		out.Reason = "ready: no tenants configured"
		return out
	}

	for _, tenant := range tenants {
		if !tenant.Working {
			continue
		}
		out.WorkingTenants++
		for _, row := range tenant.Collectors {
			if row.Enabled && row.Runs > row.Failures {
				out.SuccessfulTenants++
				break
			}
		}
	}

	switch {
	case out.SuccessfulTenants > 0:
		out.Ready = true
		out.State = readinessReady
		out.Reason = "ready: at least one tenant has completed a successful collector run"
	case out.WorkingTenants == 0:
		out.State = readinessNoWorkingTenants
		out.Reason = "no configured tenant has working collectors"
	default:
		out.State = readinessWaitingForFirstSuccess
		out.Reason = "waiting for the first successful collector run"
	}
	return out
}
