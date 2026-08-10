package collector

import (
	"github.com/rknightion/graph2otel/internal/semconv"
	"github.com/rknightion/graph2otel/internal/telemetry"
)

// MetricCollectorWatermarkTimestamp is each window collector's durable
// watermark, as Unix epoch seconds (#422). It is a gauge, and deliberately
// NON-ADDITIVE — semconv.UnitSeconds already classifies "s" that way in
// internal/semconv/additive.go, so no per-metric entry is needed there, but
// TestEveryEmittedUnitIsClassifiedForAdditivity (cmd/graph2otel) still gates it.
//
// # Why an epoch timestamp rather than an age
//
// The value is the cursor itself, not a quantity derived from it. An age is
// computed against a clock, and the clock that matters for "is this collector
// stuck" is the alerting backend's, not the exporter's — publishing an age
// bakes in the exporter's clock and hides skew inside a number that then looks
// authoritative. `time() - graph2otel_collector_watermark_timestamp_seconds`
// keeps the arithmetic where it can be seen. This is the same shape as
// Prometheus's own process_start_time_seconds.
//
// # Why this, and not an expression over record_outcomes (#422)
//
// #417 livelocked eight collectors for 11 days while every health signal read
// green: the collector re-polled one frozen 15-minute window, re-fetched
// records already in SeenIDs, and deduped them. Scrapes genuinely succeeded, so
// staleness never climbed and availability stayed healthy. The proposed
// counter-based detector — `fetched > 0 unless emitted > 0` — works on that
// incident but cannot separate it from a genuinely quiet tenant re-polling its
// overlap window and deduping everything, which is a normal steady state on a
// small tenant. That ambiguity is why #422 planned to ship its rule paused.
//
// The watermark has no such ambiguity, because logpipeline.Poll advances it to
// `to - SafetyLag` even when the window drained ZERO new records: a window
// confirmed empty is still a window that has been processed. So a quiet
// collector's watermark keeps advancing at its poll interval, and a frozen
// watermark means the window itself stopped moving — which is the #417 fault
// stated directly rather than inferred from its side effects. It also covers a
// case no outcome counter can see at all: a watermark frozen in the FUTURE,
// where the collector fetches nothing because its window is unreachable, so
// there are no outcomes to count.
const MetricCollectorWatermarkTimestamp = "graph2otel.collector.watermark_timestamp"

const (
	watermarkTimestampUnit = semconv.UnitSeconds
	watermarkTimestampDesc = "Unix epoch seconds of each window collector's durable checkpoint " +
		"watermark — the last fully-processed event time, which advances every poll even " +
		"when the window drained no records. A value that stops advancing is a stalled " +
		"window, not a quiet tenant."
)

// EmitWatermarkTimestamps publishes the complete current set of window-collector
// watermarks, one series per collector, in the same shape as
// EmitExpectedIntervals and internal/availability.Tracker.Emit: the point
// attributes carry ONLY the collector identity, and tenant_id is applied at the
// emitter boundary by telemetry.WithTenant — this method never sets it itself.
// An empty tenantID omits the tenant label, WithTenant's documented
// single-tenant passthrough.
//
// It reads each collector's cursor through CheckpointStateOf, the same
// read-only seam the admin status page uses (#178), so there is no second
// source of truth for durable progress and nothing new to keep in sync.
//
// Three kinds of entry are deliberately SKIPPED, because each would publish a
// series that reads as arbitrarily stale and page on a collector that is
// behaving correctly:
//
//   - a blob-kind cursor, whose durable progress is a byte offset and whose
//     Watermark field carries no meaning (see checkpoint.BlobCursor);
//   - a zero watermark, which is a cold start — the collector has not drained a
//     window yet. A zero time.Time's Unix() is -62135596800, i.e. year 1, NOT
//     epoch 0, so the published value would claim a two-thousand-year-old
//     cursor rather than a merely old one;
//   - a collector that reports no state at all, including every inline
//     SnapshotCollector that persists no cursor.
//
// Unlike EmitExpectedIntervals this MUST be re-emitted periodically: a
// watermark changes every poll, and GaugeSnapshot's observable callback keeps
// reporting whatever set it was last given. Calling it with an empty registry
// (or one a collector has been removed from) clears the series entirely —
// GaugeSnapshot's documented way to drop a series — which matters more here
// than elsewhere: a stale frozen value left behind for a removed collector is
// indistinguishable from the livelock this metric exists to detect.
func (r *Registry) EmitWatermarkTimestamps(e telemetry.Emitter, tenantID string) {
	entries := r.Entries()
	points := make([]telemetry.GaugePoint, 0, len(entries))
	for _, entry := range entries {
		state := CheckpointStateOf(entry.Collector)
		if state == nil || state.Kind != CheckpointKindWindow || state.Watermark.IsZero() {
			continue
		}
		points = append(points, telemetry.GaugePoint{
			Value: float64(state.Watermark.Unix()),
			Attrs: telemetry.Attrs{
				semconv.AttrCollector: entry.Collector.Name(),
			},
		})
	}
	telemetry.WithTenant(e, tenantID).GaugeSnapshot(
		MetricCollectorWatermarkTimestamp,
		watermarkTimestampUnit,
		watermarkTimestampDesc,
		points,
	)
}
