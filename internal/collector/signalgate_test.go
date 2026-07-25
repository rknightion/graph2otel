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

	if err := signalcapture.GoldenAt(
		"testdata/signals.json",
		*updateSignalGolden,
		success,
		failure,
		mismatch,
		checkpoint,
		build,
	); err != nil {
		t.Fatal(err)
	}
}
