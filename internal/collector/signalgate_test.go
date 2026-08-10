package collector_test

import (
	"context"
	"errors"
	"flag"
	"io"
	"log/slog"
	"testing"
	"time"

	"github.com/rknightion/graph2otel/internal/collector"
	"github.com/rknightion/graph2otel/internal/recordoutcome"
	"github.com/rknightion/graph2otel/internal/signalcapture"
	"github.com/rknightion/graph2otel/internal/telemetry"
	"github.com/rknightion/graph2otel/internal/telemetrytest"
)

var updateSignalGolden = flag.Bool("update", false, "rewrite testdata/signals.json")

type captureSnapshot struct {
	name         string
	err          error
	record       bool
	typeMismatch bool
}

func (c captureSnapshot) Name() string                 { return c.name }
func (captureSnapshot) DefaultInterval() time.Duration { return time.Minute }
func (c captureSnapshot) Collect(
	_ context.Context,
	_ telemetry.Emitter,
	outcomes *recordoutcome.Recorder,
) error {
	if c.record {
		outcomes.Add(recordoutcome.OutcomeFetched, 1)
		outcomes.Add(recordoutcome.OutcomeMapped, 1)
		outcomes.Add(recordoutcome.OutcomeEmitted, 1)
	}
	if c.typeMismatch {
		outcomes.TypeMismatch("capture_field", "string", "array")
	}
	return c.err
}

// captureWatermark stands in for an engine collector (logpipeline and friends)
// that persists a window cursor and reports it through CheckpointReporter, so
// the #422 watermark metric has something to publish in the signal golden.
type captureWatermark struct{ captureSnapshot }

func (captureWatermark) Name() string { return "capture.window_cursor" }
func (captureWatermark) CheckpointState() *collector.CheckpointState {
	return &collector.CheckpointState{
		Kind:      collector.CheckpointKindWindow,
		Watermark: time.Unix(1_700_000_001, 0).UTC(),
	}
}

type captureWindow struct{}

func (captureWindow) Name() string                   { return "capture.window" }
func (captureWindow) DefaultInterval() time.Duration { return time.Minute }
func (captureWindow) Lag() time.Duration             { return 0 }
func (captureWindow) CollectWindow(
	context.Context,
	time.Time,
	time.Time,
	telemetry.Emitter,
	*recordoutcome.Recorder,
) (time.Time, error) {
	return time.Unix(1_700_000_001, 0).UTC(), nil
}

type failingCheckpointStore struct{}

func (failingCheckpointStore) Get(string) (time.Time, bool) { return time.Time{}, false }
func (failingCheckpointStore) Set(string, time.Time) error  { return errors.New("disk full") }
func (failingCheckpointStore) Keys() []string               { return nil }
func (failingCheckpointStore) Delete(string) error          { return nil }

func TestSignalGolden(t *testing.T) {
	t.Parallel()

	now := time.Unix(1_700_000_000, 0).UTC()
	newScheduler := func(rec *telemetrytest.Recorder, store collector.CheckpointStore) *collector.Scheduler {
		return collector.NewScheduler(
			rec.Emitter(),
			store,
			collector.WithClock(func() time.Time { return now }),
			collector.WithLogger(slog.New(slog.NewTextHandler(io.Discard, nil))),
			collector.WithTenant("capture-tenant"),
		)
	}

	success := telemetrytest.New()
	successScheduler := newScheduler(success, collector.NewMemoryStore())
	successLast := now.Add(-time.Minute)
	successScheduler.RunTick(context.Background(), collector.Entry{
		Collector: captureSnapshot{name: "capture.success", record: true},
		Interval:  time.Minute,
	}, &successLast)

	failure := telemetrytest.New()
	failureScheduler := newScheduler(failure, collector.NewMemoryStore())
	failureLast := now.Add(-time.Minute)
	failureScheduler.RunTick(context.Background(), collector.Entry{
		Collector: captureSnapshot{name: "capture.failure", err: errors.New("graph unavailable")},
		Interval:  time.Minute,
	}, &failureLast)

	mismatch := telemetrytest.New()
	mismatchScheduler := newScheduler(mismatch, collector.NewMemoryStore())
	mismatchLast := now.Add(-time.Minute)
	mismatchScheduler.RunTick(context.Background(), collector.Entry{
		Collector: captureSnapshot{name: "capture.mismatch", record: true, typeMismatch: true},
		Interval:  time.Minute,
	}, &mismatchLast)

	checkpoint := telemetrytest.New()
	checkpointScheduler := newScheduler(checkpoint, failingCheckpointStore{})
	checkpointLast := now.Add(-time.Minute)
	checkpointScheduler.RunTick(context.Background(), collector.Entry{
		Collector:       captureWindow{},
		Interval:        time.Minute,
		InitialLookback: time.Hour,
	}, &checkpointLast)

	build := telemetrytest.New()
	collector.EmitBuildInfo(build.Emitter())

	// #299: graph2otel.collector.expected_interval — one series per registered
	// collector, the scheduler's effective (defaulted/clamped) poll interval.
	expectedInterval := telemetrytest.New()
	intervalRegistry := collector.NewRegistry()
	intervalRegistry.Register(captureSnapshot{name: "capture.success"}, time.Minute)
	intervalRegistry.RegisterWindow(captureWindow{}, 0, time.Hour, time.Hour)
	intervalRegistry.EmitExpectedIntervals(expectedInterval.Emitter(), "capture-tenant")

	// #422: graph2otel.collector.watermark_timestamp — one series per window
	// collector that has drained a window, carrying the raw cursor as Unix epoch
	// seconds. Only the CheckpointReporter contributes; captureSnapshot persists
	// no cursor and must stay absent from the golden.
	watermark := telemetrytest.New()
	watermarkRegistry := collector.NewRegistry()
	watermarkRegistry.Register(captureSnapshot{name: "capture.success"}, time.Minute)
	watermarkRegistry.Register(captureWatermark{}, time.Minute)
	watermarkRegistry.EmitWatermarkTimestamps(watermark.Emitter(), "capture-tenant")

	if err := signalcapture.GoldenAt(
		"testdata/signals.json",
		*updateSignalGolden,
		success,
		failure,
		mismatch,
		checkpoint,
		build,
		expectedInterval,
		watermark,
	); err != nil {
		t.Fatal(err)
	}
}
