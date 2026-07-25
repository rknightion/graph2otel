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
	"github.com/rknightion/graph2otel/internal/signalcapture"
	"github.com/rknightion/graph2otel/internal/telemetry"
	"github.com/rknightion/graph2otel/internal/telemetrytest"
)

var updateSignalGolden = flag.Bool("update", false, "rewrite testdata/signals.json")

type captureSnapshot struct {
	name string
	err  error
}

func (c captureSnapshot) Name() string                 { return c.name }
func (captureSnapshot) DefaultInterval() time.Duration { return time.Minute }
func (c captureSnapshot) Collect(context.Context, telemetry.Emitter) error {
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
		Collector: captureSnapshot{name: "capture.success"},
		Interval:  time.Minute,
	}, &successLast)

	failure := telemetrytest.New()
	failureScheduler := newScheduler(failure, collector.NewMemoryStore())
	failureLast := now.Add(-time.Minute)
	failureScheduler.RunTick(context.Background(), collector.Entry{
		Collector: captureSnapshot{name: "capture.failure", err: errors.New("graph unavailable")},
		Interval:  time.Minute,
	}, &failureLast)

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
		checkpoint,
		build,
	); err != nil {
		t.Fatal(err)
	}
}
