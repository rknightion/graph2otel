package collector

import (
	"context"
	"testing"
	"time"

	"github.com/rknightion/graph2otel/internal/recordoutcome"
	"github.com/rknightion/graph2otel/internal/telemetry"
	"github.com/rknightion/graph2otel/internal/telemetrytest"
)

// TestEmitWatermarkTimestampsReportsOneSeriesPerWindowCursor is the primary
// #422 contract test. The #417 livelock froze eight collectors for 11 days
// while every counter-derived health signal read green, because the collector
// genuinely succeeded — it re-polled one frozen window and deduped everything
// it fetched. The watermark is the DIRECT statement of that fault: it stops
// advancing. This asserts the metric carries the raw cursor timestamp, so a
// staleness rule is `time() - metric` with nothing derived in between.
func TestEmitWatermarkTimestampsReportsOneSeriesPerWindowCursor(t *testing.T) {
	frozen := time.Date(2026, 7, 15, 9, 0, 0, 0, time.UTC)
	fresh := time.Date(2026, 7, 26, 12, 30, 0, 0, time.UTC)

	r := NewRegistry()
	r.Register(namedCheckpointStub{
		name:  "entra.signins.interactive",
		state: &CheckpointState{Kind: CheckpointKindWindow, Watermark: frozen},
	}, time.Minute)
	r.Register(namedCheckpointStub{
		name:  "entra.directory_audits",
		state: &CheckpointState{Kind: CheckpointKindWindow, Watermark: fresh},
	}, time.Minute)

	rec := telemetrytest.New()
	r.EmitWatermarkTimestamps(rec.Emitter(), "tenant-a")

	points := rec.MetricPoints(MetricCollectorWatermarkTimestamp)
	if len(points) != 2 {
		t.Fatalf("len(points) = %d, want 2: %+v", len(points), points)
	}

	want := map[string]float64{
		"entra.signins.interactive": float64(frozen.Unix()),
		"entra.directory_audits":    float64(fresh.Unix()),
	}
	for _, p := range points {
		name := p.Attrs["collector"]
		wantValue, ok := want[name]
		if !ok {
			t.Fatalf("unexpected collector %q: %+v", name, points)
		}
		if p.Value != wantValue {
			t.Errorf("collector %q value = %v, want %v (Unix epoch seconds of the watermark)",
				name, p.Value, wantValue)
		}
		if p.Attrs["tenant_id"] != "tenant-a" {
			t.Errorf("collector %q tenant_id = %q, want tenant-a", name, p.Attrs["tenant_id"])
		}
		if p.Kind != "gauge" {
			t.Errorf("collector %q kind = %q, want gauge", name, p.Kind)
		}
		if p.Unit != "s" {
			t.Errorf("collector %q unit = %q, want s", name, p.Unit)
		}
	}
}

// TestEmitWatermarkTimestampsSkipsWhatHasNoWatermark pins the three exclusions,
// each of which would publish a series that reads as "infinitely stale" and
// page on a collector that is behaving correctly — the exact failure mode #422
// calls out: an alert that fires on correct data trains the reader to ignore it.
//
//   - a BLOB cursor's durable progress is a byte offset, not a timestamp
//     (checkpoint.BlobCursor); its zero Watermark field is not meaningful.
//   - a ZERO watermark is a cold start — the collector has not drained a window
//     yet. A zero time.Time's Unix() is -62135596800 (year 1), not epoch 0, so
//     publishing it claims a two-millennia-old cursor on a collector whose only
//     fault is that it has not run yet.
//   - a collector that is not a CheckpointReporter persists no cursor at all
//     (every inline SnapshotCollector), so there is nothing to report.
func TestEmitWatermarkTimestampsSkipsWhatHasNoWatermark(t *testing.T) {
	live := time.Date(2026, 7, 26, 12, 30, 0, 0, time.UTC)

	r := NewRegistry()
	r.Register(namedCheckpointStub{
		name:  "defender.device_process",
		state: &CheckpointState{Kind: CheckpointKindBlob, ByteOffset: 4096, BlobsTracked: 7},
	}, time.Minute)
	r.Register(namedCheckpointStub{
		name:  "entra.provisioning",
		state: &CheckpointState{Kind: CheckpointKindWindow}, // cold start: zero watermark
	}, time.Minute)
	r.Register(namedCheckpointStub{
		name:  "entra.risk",
		state: nil, // a reporter may report nil (nothing persisted / read failed)
	}, time.Minute)
	r.Register(plainNoStateStub{}, time.Minute) // not a CheckpointReporter
	r.Register(namedCheckpointStub{
		name:  "entra.directory_audits",
		state: &CheckpointState{Kind: CheckpointKindWindow, Watermark: live},
	}, time.Minute)

	rec := telemetrytest.New()
	r.EmitWatermarkTimestamps(rec.Emitter(), "tenant-a")

	points := rec.MetricPoints(MetricCollectorWatermarkTimestamp)
	if len(points) != 1 {
		t.Fatalf("len(points) = %d, want 1 (only the drained window cursor): %+v",
			len(points), points)
	}
	if got := points[0].Attrs["collector"]; got != "entra.directory_audits" {
		t.Errorf("collector = %q, want entra.directory_audits", got)
	}
	if got := points[0].Value; got != float64(live.Unix()) {
		t.Errorf("value = %v, want %v", got, float64(live.Unix()))
	}
}

// TestEmitWatermarkTimestampsOmitsTenantIDWhenTenantIsEmpty matches
// telemetry.WithTenant's documented passthrough for a single-tenant deploy, the
// same shape EmitExpectedIntervals and availability.Tracker.Emit rely on.
func TestEmitWatermarkTimestampsOmitsTenantIDWhenTenantIsEmpty(t *testing.T) {
	r := NewRegistry()
	r.Register(namedCheckpointStub{
		name:  "entra.directory_audits",
		state: &CheckpointState{Kind: CheckpointKindWindow, Watermark: time.Unix(1_750_000_000, 0)},
	}, time.Minute)

	rec := telemetrytest.New()
	r.EmitWatermarkTimestamps(rec.Emitter(), "")

	points := rec.MetricPoints(MetricCollectorWatermarkTimestamp)
	if len(points) != 1 {
		t.Fatalf("len(points) = %d, want 1: %+v", len(points), points)
	}
	if _, ok := points[0].Attrs["tenant_id"]; ok {
		t.Errorf("tenant_id present for empty tenant: %+v", points[0].Attrs)
	}
}

// TestEmitWatermarkTimestampsOnEmptyRegistryClearsTheSeries pins GaugeSnapshot's
// documented way to DROP a series: an empty snapshot. A deliberately removed
// collector must stop reporting a watermark rather than freeze its last value
// forever — a frozen last value is indistinguishable from the very livelock
// this metric exists to detect, so leaving it behind would manufacture a
// permanent false page.
func TestEmitWatermarkTimestampsOnEmptyRegistryClearsTheSeries(t *testing.T) {
	rec := telemetrytest.New()
	NewRegistry().EmitWatermarkTimestamps(rec.Emitter(), "tenant-a")

	if points := rec.MetricPoints(MetricCollectorWatermarkTimestamp); len(points) != 0 {
		t.Fatalf("len(points) = %d, want 0: %+v", len(points), points)
	}
}

// namedCheckpointStub is checkpointReporterStub with a caller-chosen name, so a
// single registry can hold several distinguishable cursors.
type namedCheckpointStub struct {
	name  string
	state *CheckpointState
}

func (s namedCheckpointStub) Name() string                 { return s.name }
func (namedCheckpointStub) DefaultInterval() time.Duration { return time.Hour }
func (namedCheckpointStub) Collect(context.Context, telemetry.Emitter, *recordoutcome.Recorder) error {
	return nil
}
func (s namedCheckpointStub) CheckpointState() *CheckpointState { return s.state }
