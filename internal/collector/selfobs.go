package collector

import (
	"context"
	"errors"
	"time"

	"github.com/rknightion/graph2otel/internal/availability"
	"github.com/rknightion/graph2otel/internal/recordoutcome"
	"github.com/rknightion/graph2otel/internal/semconv"
	"github.com/rknightion/graph2otel/internal/telemetry"
)

// Per-collector self-observability metric names. Each carries the
// semconv.AttrCollector attribute identifying the collector that produced it,
// plus semconv.AttrTenantID when the owning Scheduler was configured with
// WithTenant, letting operators see scrape health per data source per tenant.
const (
	// MetricCollectorAvailability is the complete tenant-scoped snapshot of
	// bounded current state for every configured logical collector.
	MetricCollectorAvailability = availability.MetricCollectorAvailability
	// MetricScrapeDuration is a gauge of the wall-clock seconds a collector run
	// took (the snapshot Collect or window CollectWindow call).
	MetricScrapeDuration = "graph2otel.scrape.duration"
	// MetricScrapeSuccess is a gauge that is 1 for an empty or successful run,
	// and 0 for a partial or failed run (including recovered panics).
	MetricScrapeSuccess = "graph2otel.scrape.success"
	// MetricScrapeErrors is a monotonic counter incremented once per failed run,
	// carrying an "error.type" attribute classifying the failure.
	MetricScrapeErrors = "graph2otel.scrape.errors"
	// MetricScrapeLastTimestamp is a gauge of the unix time, in seconds, at which
	// the most recent run finished.
	MetricScrapeLastTimestamp = "graph2otel.scrape.last_timestamp"
	// MetricScrapeStaleness is a gauge of the seconds elapsed since this
	// collector's last *successful* run. It counts up from process start until
	// the first success (so a collector that has never succeeded shows a growing,
	// alertable value rather than an absent series) and resets to ~0 on every
	// successful run. Explicit is friendlier than deriving freshness from
	// scrape.last_timestamp + scrape.success.
	MetricScrapeStaleness = "graph2otel.scrape.staleness"
	// MetricScrapeBudget is a gauge of the last run's duration as a fraction of
	// the collector's poll interval (duration ÷ interval). Values near or above
	// `1` mean a scrape is taking about as long as (or longer than) its interval
	// — little headroom, risk of overrun.
	MetricScrapeBudget = "graph2otel.scrape.budget"
	// MetricCheckpointPersistErrors is a monotonic counter incremented when a
	// window collector's high-water mark fails to persist to the checkpoint
	// store (e.g. a disk error). The window itself succeeded, and both store
	// implementations advance their in-memory cursor before attempting the disk
	// write, so the next tick still polls the *next* window regardless of this
	// failure — the failed window is only re-polled after a process restart
	// (when the in-memory advance is lost and the store falls back to its last
	// successfully persisted value).
	MetricCheckpointPersistErrors = "graph2otel.checkpoint.persist.errors"
	// MetricRecordOutcomes counts source records by their bounded processing
	// outcome for each collector run.
	MetricRecordOutcomes = "graph2otel.record.outcomes"
	// MetricScrapeOutcomes counts collector runs by their reconciled result.
	MetricScrapeOutcomes = "graph2otel.scrape.outcomes"
	// MetricPayloadTypeMismatches counts otherwise-usable records whose optional
	// field carried a different JSON type than expected. It deliberately records
	// only the field name and closed JSON type values, never the field value.
	MetricPayloadTypeMismatches = "graph2otel.payload.type_mismatches"
)

// error.type values for MetricScrapeErrors.
const (
	scrapeErrorTimeout = "timeout"
	scrapeErrorPanic   = "panic"
	scrapeErrorGeneric = "error"
)

// scrapeResult captures the outcome of a single collector run for self-obs
// emission. outcome is the authoritative health classification; err and
// panicked retain the legacy scrape.errors classification.
type scrapeResult struct {
	collector  string
	tenant     string // empty when the Scheduler has no WithTenant configured
	duration   time.Duration
	interval   time.Duration
	finishedAt time.Time
	staleness  time.Duration
	err        error
	panicked   bool
	outcome    recordoutcome.Summary
}

// selfObsAttrs builds the bounded base attribute set shared by collector
// self-observability points: the collector name, plus the tenant ID when
// non-empty. Specialized metrics add only their documented bounded dimensions.
func selfObsAttrs(collector, tenant string) telemetry.Attrs {
	attrs := telemetry.Attrs{semconv.AttrCollector: collector}
	if tenant != "" {
		attrs[semconv.AttrTenantID] = tenant
	}
	return attrs
}

// emitScrapeMetrics records the per-collector scrape metrics for one run using
// the given emitter. It always emits the gauges; the errors counter is
// incremented only when the run failed.
func emitScrapeMetrics(e telemetry.Emitter, res scrapeResult) {
	attrs := selfObsAttrs(res.collector, res.tenant)

	e.Gauge(MetricScrapeDuration, semconv.UnitSeconds,
		"Wall-clock duration of the last scrape, per collector.",
		res.duration.Seconds(), attrs)

	failed := res.outcome.Result != recordoutcome.ResultEmpty &&
		res.outcome.Result != recordoutcome.ResultSuccess
	success := 1.0
	if failed {
		success = 0
	}
	e.Gauge(MetricScrapeSuccess, semconv.UnitDimensionless,
		"1 if the last scrape result was empty or success; 0 for partial or failure.",
		success, attrs)

	e.Gauge(MetricScrapeLastTimestamp, semconv.UnitSeconds,
		"Unix time, in seconds, at which the most recent scrape finished.",
		float64(res.finishedAt.Unix()), attrs)

	e.Gauge(MetricScrapeStaleness, semconv.UnitSeconds,
		"Seconds elapsed since this collector's last successful scrape.",
		res.staleness.Seconds(), attrs)

	if res.interval > 0 { // guard: a zero/negative interval would make the ratio NaN (0/0) or Inf
		e.Gauge(MetricScrapeBudget, semconv.UnitDimensionless,
			"Last scrape's duration as a fraction of the collector's poll interval.",
			res.duration.Seconds()/res.interval.Seconds(), attrs)
	}

	if failed {
		errAttrs := selfObsAttrs(res.collector, res.tenant)
		errAttrs["error.type"] = scrapeErrorType(res.err, res.panicked)
		e.Counter(MetricScrapeErrors, semconv.UnitDimensionless,
			"Count of failed scrapes, per collector, classified by error.type.", 1, errAttrs)
	}
}

func emitOutcomeMetrics(
	e telemetry.Emitter,
	collectorName, tenant string,
	transport telemetry.Transport,
	snapshot recordoutcome.Snapshot,
	summary recordoutcome.Summary,
) {
	baseAttrs := selfObsAttrs(collectorName, tenant)
	baseAttrs[semconv.AttrIngestTransport] = string(transport)

	for _, item := range []struct {
		outcome recordoutcome.Outcome
		value   uint64
	}{
		{recordoutcome.OutcomeFetched, snapshot.Counts.Fetched},
		{recordoutcome.OutcomeMapped, snapshot.Counts.Mapped},
		{recordoutcome.OutcomeEmitted, snapshot.Counts.Emitted},
		{recordoutcome.OutcomeDeduped, snapshot.Counts.Deduped},
		{recordoutcome.OutcomeFiltered, snapshot.Counts.Filtered},
		{recordoutcome.OutcomeDropped, snapshot.Counts.Dropped},
		{recordoutcome.OutcomeErrored, snapshot.Counts.Errored},
	} {
		if item.value == 0 {
			continue
		}
		attrs := cloneAttrs(baseAttrs)
		attrs["outcome"] = string(item.outcome)
		e.Counter(MetricRecordOutcomes, semconv.UnitRecords,
			"Count of source records by processing outcome.", float64(item.value), attrs)
	}

	runAttrs := cloneAttrs(baseAttrs)
	runAttrs["result"] = string(summary.Result)
	e.Counter(MetricScrapeOutcomes, semconv.UnitRuns,
		"Count of collector runs by reconciled record outcome.", 1, runAttrs)

	for _, mismatch := range snapshot.TypeMismatches {
		attrs := cloneAttrs(baseAttrs)
		attrs["field"] = mismatch.Field
		attrs["expected_type"] = mismatch.ExpectedType
		attrs["actual_type"] = mismatch.ActualType
		e.Counter(MetricPayloadTypeMismatches, semconv.UnitRecords,
			"Count of payload fields whose JSON type differed from the expected type.",
			float64(mismatch.Count), attrs)
	}
}

func cloneAttrs(src telemetry.Attrs) telemetry.Attrs {
	dst := make(telemetry.Attrs, len(src)+1)
	for key, value := range src {
		dst[key] = value
	}
	return dst
}

// emitCheckpointPersistError records one MetricCheckpointPersistErrors increment
// for a collector whose checkpoint failed to persist, so a silently-failing
// checkpoint store (which stalls window progress on restart) is alertable.
func emitCheckpointPersistError(e telemetry.Emitter, collectorName, tenant string) {
	e.Counter(MetricCheckpointPersistErrors, semconv.UnitDimensionless,
		"Count of failed checkpoint high-water-mark persists, per collector.", 1,
		selfObsAttrs(collectorName, tenant))
}

// scrapeErrorType classifies a failed run for the "error.type" attribute:
// "panic" for a recovered panic, "timeout" for a deadline-exceeded error, and
// "error" otherwise.
func scrapeErrorType(err error, panicked bool) string {
	if panicked {
		return scrapeErrorPanic
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return scrapeErrorTimeout
	}
	return scrapeErrorGeneric
}
