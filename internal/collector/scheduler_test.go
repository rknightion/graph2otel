package collector_test

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/rknightion/graph2otel/internal/availability"
	"github.com/rknightion/graph2otel/internal/collector"
	"github.com/rknightion/graph2otel/internal/recordoutcome"
	"github.com/rknightion/graph2otel/internal/semconv"
	"github.com/rknightion/graph2otel/internal/telemetry"
	"github.com/rknightion/graph2otel/internal/telemetrytest"
)

// --- test doubles ---

// int32Counter is a tiny atomic tick counter for asserting a collector fired
// at least N times without racing on a plain int.
type int32Counter struct{ v atomic.Int32 }

func (c *int32Counter) inc()       { c.v.Add(1) }
func (c *int32Counter) get() int32 { return c.v.Load() }

type countingCheckpointStore struct {
	collector.CheckpointStore
	gets map[string]int
}

func (s *countingCheckpointStore) Get(name string) (time.Time, bool) {
	if s.gets == nil {
		s.gets = make(map[string]int)
	}
	s.gets[name]++
	return s.CheckpointStore.Get(name)
}

type snapFunc struct {
	name string
	def  time.Duration
	fn   func(context.Context, telemetry.Emitter, *recordoutcome.Recorder) error
}

type transportedSnap struct {
	snapFunc
	transport telemetry.Transport
}

func (s transportedSnap) IngestTransport() telemetry.Transport { return s.transport }

func (s snapFunc) Name() string                   { return s.name }
func (s snapFunc) DefaultInterval() time.Duration { return s.def }
func (s snapFunc) Collect(
	ctx context.Context,
	e telemetry.Emitter,
	outcomes *recordoutcome.Recorder,
) error {
	return s.fn(ctx, e, outcomes)
}

type winFunc struct {
	name string
	def  time.Duration
	lag  time.Duration
	fn   func(context.Context, time.Time, time.Time, telemetry.Emitter, *recordoutcome.Recorder) (time.Time, error)
}

func (w winFunc) Name() string                   { return w.name }
func (w winFunc) DefaultInterval() time.Duration { return w.def }
func (w winFunc) Lag() time.Duration             { return w.lag }
func (w winFunc) CollectWindow(
	ctx context.Context,
	from, to time.Time,
	e telemetry.Emitter,
	outcomes *recordoutcome.Recorder,
) (time.Time, error) {
	return w.fn(ctx, from, to, e, outcomes)
}

func waitFor(t *testing.T, cond func() bool, timeout time.Duration) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatal("condition not met within timeout")
}

func runScheduler(t *testing.T, e telemetry.Emitter, r *collector.Registry, store collector.CheckpointStore, opts ...collector.SchedulerOption) {
	t.Helper()
	s := collector.NewScheduler(e, store, append([]collector.SchedulerOption{collector.WithStaggerWindow(0)}, opts...)...)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { _ = s.Run(ctx, r); close(done) }()
	t.Cleanup(func() {
		cancel()
		<-done
	})
}

// --- Registry / Scheduler tick behavior ---

// TestScheduler_IndependentFailureIsolation pins the requirement that a
// collector returning an error never stops the others from ticking.
func TestScheduler_IndependentFailureIsolation(t *testing.T) {
	rec := telemetrytest.New()
	var okTicks, badTicks int32Counter
	r := collector.NewRegistry()
	r.Register(snapFunc{name: "ok", def: 5 * time.Millisecond, fn: func(context.Context, telemetry.Emitter, *recordoutcome.Recorder) error {
		okTicks.inc()
		return nil
	}}, 5*time.Millisecond)
	r.Register(snapFunc{name: "bad", def: 5 * time.Millisecond, fn: func(context.Context, telemetry.Emitter, *recordoutcome.Recorder) error {
		badTicks.inc()
		return errors.New("boom")
	}}, 5*time.Millisecond)

	runScheduler(t, rec.Emitter(), r, collector.NewMemoryStore())

	waitFor(t, func() bool { return okTicks.get() >= 3 && badTicks.get() >= 3 }, 2*time.Second)
}

// TestScheduler_PanicIsRecoveredAndCollectorKeepsTicking pins the requirement
// that a panic inside a collector tick is recovered and the collector ticks
// again next interval rather than crashing the scheduler.
func TestScheduler_PanicIsRecoveredAndCollectorKeepsTicking(t *testing.T) {
	rec := telemetrytest.New()
	var ticks int32Counter
	r := collector.NewRegistry()
	r.Register(snapFunc{name: "boom", def: 5 * time.Millisecond, fn: func(context.Context, telemetry.Emitter, *recordoutcome.Recorder) error {
		ticks.inc()
		panic("kaboom")
	}}, 5*time.Millisecond)

	runScheduler(t, rec.Emitter(), r, collector.NewMemoryStore())

	waitFor(t, func() bool { return ticks.get() >= 3 }, 2*time.Second)
}

// TestScheduler_StaggerAppliesWithinWindow pins the requirement that the
// first tick of each collector fires after a random delay bounded by
// WithStaggerWindow, rather than all collectors firing at t=0 in lock-step.
func TestScheduler_StaggerAppliesWithinWindow(t *testing.T) {
	rec := telemetrytest.New()
	started := make(chan time.Time, 1)
	r := collector.NewRegistry()
	r.Register(snapFunc{name: "staggered", def: time.Hour, fn: func(context.Context, telemetry.Emitter, *recordoutcome.Recorder) error {
		select {
		case started <- time.Now():
		default:
		}
		return nil
	}}, time.Hour)

	t0 := time.Now()
	stagger := 200 * time.Millisecond
	s := collector.NewScheduler(rec.Emitter(), collector.NewMemoryStore(), collector.WithStaggerWindow(stagger))
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { _ = s.Run(ctx, r); close(done) }()
	t.Cleanup(func() { cancel(); <-done })

	select {
	case firstTick := <-started:
		elapsed := firstTick.Sub(t0)
		if elapsed > stagger+100*time.Millisecond {
			t.Fatalf("first tick fired after %v, want within stagger window %v (+slack)", elapsed, stagger)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("collector never ticked")
	}
}

// TestScheduler_UnregisteredCollectorNeverTicks pins the requirement that a
// config-disabled collector -- resolved by the caller never calling Register
// for it -- is never ticked, since Registry only drives what was registered.
func TestScheduler_UnregisteredCollectorNeverTicks(t *testing.T) {
	rec := telemetrytest.New()
	var disabledTicks int32Counter
	disabled := snapFunc{name: "disabled", def: 5 * time.Millisecond, fn: func(context.Context, telemetry.Emitter, *recordoutcome.Recorder) error {
		disabledTicks.inc()
		return nil
	}}
	// Note: disabled is intentionally never registered.
	_ = disabled

	r := collector.NewRegistry()
	runScheduler(t, rec.Emitter(), r, collector.NewMemoryStore())

	time.Sleep(50 * time.Millisecond)
	if got := disabledTicks.get(); got != 0 {
		t.Fatalf("unregistered collector ticked %d times, want 0", got)
	}
}

// TestScheduler_SnapshotCollectorEmitsToRecorder pins that a SnapshotCollector's
// own emitted metric reaches the Recorder via the Emitter passed to Collect.
func TestScheduler_SnapshotCollectorEmitsToRecorder(t *testing.T) {
	rec := telemetrytest.New()
	r := collector.NewRegistry()
	r.Register(snapFunc{name: "devices", def: 5 * time.Millisecond, fn: func(_ context.Context, e telemetry.Emitter, _ *recordoutcome.Recorder) error {
		e.Gauge("entra.devices.count", "{device}", "device count", 42, telemetry.Attrs{})
		return nil
	}}, 5*time.Millisecond)

	runScheduler(t, rec.Emitter(), r, collector.NewMemoryStore())

	waitFor(t, func() bool { return len(rec.MetricPoints("entra.devices.count")) > 0 }, 2*time.Second)
	points := rec.MetricPoints("entra.devices.count")
	if points[0].Value != 42 {
		t.Errorf("entra.devices.count value = %v, want 42", points[0].Value)
	}
}

// TestScheduler_WindowCollectorAdvancesAndPersistsCheckpoint pins that a
// WindowCollector's returned high-water mark is persisted to the
// CheckpointStore under the collector's name.
func TestScheduler_WindowCollectorAdvancesAndPersistsCheckpoint(t *testing.T) {
	rec := telemetrytest.New()
	store := collector.NewMemoryStore()
	hwm := time.Now().Add(-time.Minute).UTC().Truncate(time.Second)
	r := collector.NewRegistry()
	r.RegisterWindow(winFunc{
		name: "auditlogs",
		def:  5 * time.Millisecond,
		lag:  0,
		fn: func(_ context.Context, from, to time.Time, e telemetry.Emitter, _ *recordoutcome.Recorder) (time.Time, error) {
			return hwm, nil
		},
	}, 5*time.Millisecond, time.Hour, 0)

	runScheduler(t, rec.Emitter(), r, store)

	waitFor(t, func() bool {
		got, ok := store.Get("auditlogs")
		return ok && got.Equal(hwm)
	}, 2*time.Second)
}

// --- self-observability (#9) ---

// TestScheduler_SuccessfulTickEmitsScrapeSuccessAndDuration pins that a
// successful tick sets graph2otel.scrape.success=1 and records
// graph2otel.scrape.duration, both carrying collector+tenant_id attrs.
func TestScheduler_SuccessfulTickEmitsScrapeSuccessAndDuration(t *testing.T) {
	rec := telemetrytest.New()
	s := collector.NewScheduler(rec.Emitter(), collector.NewMemoryStore(), collector.WithTenant("acme"))
	e := collector.Entry{
		Collector: snapFunc{name: "devices", def: time.Second, fn: func(context.Context, telemetry.Emitter, *recordoutcome.Recorder) error { return nil }},
		Interval:  time.Second,
	}
	var lastSuccess time.Time
	s.RunTick(context.Background(), e, &lastSuccess)

	assertGaugeAttrs(t, rec, collector.MetricScrapeSuccess, 1, map[string]string{
		semconv.AttrCollector: "devices",
		semconv.AttrTenantID:  "acme",
	})
	points := rec.MetricPoints(collector.MetricScrapeDuration)
	if len(points) != 1 {
		t.Fatalf("MetricScrapeDuration points = %d, want 1", len(points))
	}
	if points[0].Attrs[semconv.AttrCollector] != "devices" || points[0].Attrs[semconv.AttrTenantID] != "acme" {
		t.Errorf("MetricScrapeDuration attrs = %v, want collector=devices tenant_id=acme", points[0].Attrs)
	}
}

func TestScheduler_RecordsEventLagWithCollectorAndActualTransport(t *testing.T) {
	rec := telemetrytest.New()
	now := time.Date(2026, time.July, 25, 12, 0, 0, 0, time.UTC)
	s := collector.NewScheduler(
		telemetry.WithTenant(rec.Emitter(), "acme"),
		collector.NewMemoryStore(),
		collector.WithTenant("acme"),
		collector.WithClock(func() time.Time { return now }),
	)
	entry := collector.Entry{
		Collector: transportedSnap{
			snapFunc: snapFunc{
				name: "activity",
				def:  time.Minute,
				fn: func(_ context.Context, e telemetry.Emitter, outcomes *recordoutcome.Recorder) error {
					telemetry.WithTransport(e, telemetry.TransportBlob).LogEvent(telemetry.Event{
						Name:      "m365.activity",
						Timestamp: now.Add(-2 * time.Minute),
					})
					outcomes.Add(recordoutcome.OutcomeFetched, 1)
					outcomes.Add(recordoutcome.OutcomeMapped, 1)
					outcomes.Add(recordoutcome.OutcomeEmitted, 1)
					return nil
				},
			},
			transport: telemetry.TransportO365Activity,
		},
		Interval: time.Minute,
	}
	var lastSuccess time.Time

	s.RunTick(context.Background(), entry, &lastSuccess)

	points := rec.MetricPoints("graph2otel.event.lag")
	if len(points) != 1 {
		t.Fatalf("event lag points = %d, want 1", len(points))
	}
	if points[0].Value != 120 {
		t.Errorf("event lag = %v, want 120", points[0].Value)
	}
	wantAttrs := map[string]string{
		semconv.AttrCollector:       "activity",
		semconv.AttrTenantID:        "acme",
		semconv.AttrIngestTransport: string(telemetry.TransportBlob),
	}
	for key, want := range wantAttrs {
		if got := points[0].Attrs[key]; got != want {
			t.Errorf("event lag attribute %q = %q, want %q", key, got, want)
		}
	}
}

// TestScheduler_FailedTickSetsSuccessZeroAndStalenessGrows pins that a failing
// tick sets graph2otel.scrape.success=0 and does NOT reset last-success, so
// graph2otel.scrape.staleness keeps increasing across subsequent failures.
func TestScheduler_FailedTickSetsSuccessZeroAndStalenessGrows(t *testing.T) {
	rec := telemetrytest.New()
	now := time.Unix(1_000_000, 0).UTC()
	s := collector.NewScheduler(rec.Emitter(), collector.NewMemoryStore(), collector.WithClock(func() time.Time { return now }))
	e := collector.Entry{
		Collector: snapFunc{name: "devices", def: time.Second, fn: func(context.Context, telemetry.Emitter, *recordoutcome.Recorder) error {
			return errors.New("boom")
		}},
		Interval: time.Second,
	}
	lastSuccess := now
	s.RunTick(context.Background(), e, &lastSuccess)
	assertGaugeAttrs(t, rec, collector.MetricScrapeSuccess, 0, map[string]string{semconv.AttrCollector: "devices"})
	assertMetricSeries(t, rec, collector.MetricScrapeOutcomes, 1, map[string]string{
		semconv.AttrCollector:       "devices",
		semconv.AttrIngestTransport: "graph",
		"result":                    "failure",
	})
	staleness1 := rec.MetricPoints(collector.MetricScrapeStaleness)[0].Value
	if staleness1 != 0 {
		t.Fatalf("first-failure staleness = %v, want 0 (clock unchanged since lastSuccess)", staleness1)
	}
	if lastSuccess != now {
		t.Fatalf("lastSuccess mutated on failure: %v, want unchanged %v", lastSuccess, now)
	}

	// Advance the clock and fail again: staleness must have grown, since
	// lastSuccess was never reset by the earlier failure.
	now = now.Add(30 * time.Second)
	s.RunTick(context.Background(), e, &lastSuccess)
	assertMetricSeries(t, rec, collector.MetricScrapeOutcomes, 2, map[string]string{
		semconv.AttrCollector:       "devices",
		semconv.AttrIngestTransport: "graph",
		"result":                    "failure",
	})
	staleness2 := rec.MetricPoints(collector.MetricScrapeStaleness)[0].Value
	if staleness2 != 30 {
		t.Fatalf("second-failure staleness = %v, want 30 (seconds elapsed since last success)", staleness2)
	}

	// Errors counter must have incremented, classified as a generic error.
	errPoints := rec.MetricPoints(collector.MetricScrapeErrors)
	if len(errPoints) != 1 {
		t.Fatalf("MetricScrapeErrors points = %d, want 1 (cumulative counter, one series)", len(errPoints))
	}
	if errPoints[0].Value != 2 {
		t.Fatalf("MetricScrapeErrors value = %v, want 2 (two failed ticks)", errPoints[0].Value)
	}
}

func TestScheduler_EmptyRunIsHealthyAndEmitsExplicitOutcome(t *testing.T) {
	rec := telemetrytest.New()
	s := collector.NewScheduler(
		rec.Emitter(),
		collector.NewMemoryStore(),
		collector.WithTenant("acme"),
	)
	entry := collector.Entry{
		Collector: snapFunc{
			name: "devices",
			def:  time.Minute,
			fn: func(context.Context, telemetry.Emitter, *recordoutcome.Recorder) error {
				return nil
			},
		},
		Interval: time.Minute,
	}
	var lastSuccess time.Time

	s.RunTick(context.Background(), entry, &lastSuccess)

	assertGaugeAttrs(t, rec, collector.MetricScrapeSuccess, 1, map[string]string{
		semconv.AttrCollector: "devices",
		semconv.AttrTenantID:  "acme",
	})
	assertMetricSeries(t, rec, collector.MetricScrapeOutcomes, 1, map[string]string{
		semconv.AttrCollector:       "devices",
		semconv.AttrTenantID:        "acme",
		semconv.AttrIngestTransport: "graph",
		"result":                    "empty",
	})
}

func TestScheduler_BalancedRunEmitsRecordAndScrapeOutcomes(t *testing.T) {
	rec := telemetrytest.New()
	s := collector.NewScheduler(
		rec.Emitter(),
		collector.NewMemoryStore(),
		collector.WithTenant("acme"),
	)
	entry := collector.Entry{
		Collector: snapFunc{
			name: "devices",
			def:  time.Minute,
			fn: func(_ context.Context, _ telemetry.Emitter, outcomes *recordoutcome.Recorder) error {
				outcomes.Add(recordoutcome.OutcomeFetched, 2)
				outcomes.Add(recordoutcome.OutcomeMapped, 2)
				outcomes.Add(recordoutcome.OutcomeEmitted, 1)
				outcomes.Add(recordoutcome.OutcomeDeduped, 1)
				return nil
			},
		},
		Interval: time.Minute,
	}
	var lastSuccess time.Time

	s.RunTick(context.Background(), entry, &lastSuccess)

	for outcome, want := range map[string]float64{
		"fetched": 2,
		"mapped":  2,
		"emitted": 1,
		"deduped": 1,
	} {
		assertMetricSeries(t, rec, collector.MetricRecordOutcomes, want, map[string]string{
			semconv.AttrCollector:       "devices",
			semconv.AttrTenantID:        "acme",
			semconv.AttrIngestTransport: "graph",
			"outcome":                   outcome,
		})
	}
	assertMetricSeries(t, rec, collector.MetricScrapeOutcomes, 1, map[string]string{
		semconv.AttrCollector:       "devices",
		semconv.AttrTenantID:        "acme",
		semconv.AttrIngestTransport: "graph",
		"result":                    "success",
	})
	assertGaugeAttrs(t, rec, collector.MetricScrapeSuccess, 1, map[string]string{
		semconv.AttrCollector: "devices",
		semconv.AttrTenantID:  "acme",
	})
}

func TestScheduler_OutcomeMetricsUseCollectorsDeclaredTransport(t *testing.T) {
	rec := telemetrytest.New()
	s := collector.NewScheduler(rec.Emitter(), collector.NewMemoryStore())
	entry := collector.Entry{
		Collector: transportedSnap{
			snapFunc: snapFunc{
				name: "blob.devices",
				def:  time.Minute,
				fn: func(_ context.Context, _ telemetry.Emitter, outcomes *recordoutcome.Recorder) error {
					outcomes.Add(recordoutcome.OutcomeFetched, 1)
					outcomes.Add(recordoutcome.OutcomeMapped, 1)
					outcomes.Add(recordoutcome.OutcomeEmitted, 1)
					return nil
				},
			},
			transport: telemetry.TransportBlob,
		},
		Interval: time.Minute,
	}
	var lastSuccess time.Time

	s.RunTick(context.Background(), entry, &lastSuccess)

	assertMetricSeries(t, rec, collector.MetricRecordOutcomes, 1, map[string]string{
		semconv.AttrCollector:       "blob.devices",
		semconv.AttrIngestTransport: "blob",
		"outcome":                   "fetched",
	})
	assertMetricSeries(t, rec, collector.MetricScrapeOutcomes, 1, map[string]string{
		semconv.AttrCollector:       "blob.devices",
		semconv.AttrIngestTransport: "blob",
		"result":                    "success",
	})
}

func TestScheduler_PartialRunIsUnhealthyAndDoesNotResetStaleness(t *testing.T) {
	rec := telemetrytest.New()
	now := time.Unix(1_000_000, 0).UTC()
	s := collector.NewScheduler(
		rec.Emitter(),
		collector.NewMemoryStore(),
		collector.WithClock(func() time.Time { return now }),
	)
	entry := collector.Entry{
		Collector: snapFunc{
			name: "devices",
			def:  time.Minute,
			fn: func(_ context.Context, _ telemetry.Emitter, outcomes *recordoutcome.Recorder) error {
				outcomes.Add(recordoutcome.OutcomeFetched, 2)
				outcomes.Add(recordoutcome.OutcomeMapped, 1)
				outcomes.Add(recordoutcome.OutcomeEmitted, 1)
				outcomes.Add(recordoutcome.OutcomeErrored, 1)
				outcomes.Cause(recordoutcome.CauseSourceError)
				return errors.New("page 2 failed")
			},
		},
		Interval: time.Minute,
	}
	lastSuccess := now.Add(-30 * time.Second)

	s.RunTick(context.Background(), entry, &lastSuccess)

	assertMetricSeries(t, rec, collector.MetricScrapeOutcomes, 1, map[string]string{
		semconv.AttrCollector:       "devices",
		semconv.AttrIngestTransport: "graph",
		"result":                    "partial",
	})
	assertGaugeAttrs(t, rec, collector.MetricScrapeSuccess, 0, map[string]string{
		semconv.AttrCollector: "devices",
	})
	assertGaugeAttrs(t, rec, collector.MetricScrapeStaleness, 30, map[string]string{
		semconv.AttrCollector: "devices",
	})
	if got := lastSuccess; !got.Equal(now.Add(-30 * time.Second)) {
		t.Fatalf("lastSuccess = %v, want unchanged after partial run", got)
	}
}

func TestScheduler_PanicRetainsRecordedProgress(t *testing.T) {
	rec := telemetrytest.New()
	status := collector.NewStatusTracker()
	availabilityTracker := availability.NewTracker("tenant-a", []availability.Static{{
		Collector: "devices",
		Transport: telemetry.TransportGraph,
		State:     availability.StateStarting,
		Reason:    availability.ReasonNoCompletedRun,
	}})
	s := collector.NewScheduler(
		rec.Emitter(),
		collector.NewMemoryStore(),
		collector.WithStatusTracker(status),
		collector.WithAvailabilityTracker(availabilityTracker),
	)
	entry := collector.Entry{
		Collector: snapFunc{
			name: "devices",
			def:  time.Minute,
			fn: func(_ context.Context, _ telemetry.Emitter, outcomes *recordoutcome.Recorder) error {
				outcomes.Add(recordoutcome.OutcomeFetched, 1)
				outcomes.Add(recordoutcome.OutcomeMapped, 1)
				outcomes.Add(recordoutcome.OutcomeEmitted, 1)
				panic("mapper bug")
			},
		},
		Interval: time.Minute,
	}
	var lastSuccess time.Time

	s.RunTick(context.Background(), entry, &lastSuccess)

	assertMetricSeries(t, rec, collector.MetricRecordOutcomes, 1, map[string]string{
		semconv.AttrCollector:       "devices",
		semconv.AttrIngestTransport: "graph",
		"outcome":                   "emitted",
	})
	assertMetricSeries(t, rec, collector.MetricScrapeOutcomes, 1, map[string]string{
		semconv.AttrCollector:       "devices",
		semconv.AttrIngestTransport: "graph",
		"result":                    "partial",
	})
	run := status.Snapshot()["devices"]
	if run.LastOutcome.Result != recordoutcome.ResultPartial ||
		run.LastOutcome.Cause != recordoutcome.CausePanic {
		t.Fatalf("LastOutcome = %+v, want partial/panic", run.LastOutcome)
	}
	point := availabilityTracker.Snapshot()[0]
	if point.State != availability.StateDegraded ||
		point.Reason != availability.ReasonPanic ||
		point.LastOutcome == nil ||
		point.LastOutcome.Result != recordoutcome.ResultPartial ||
		point.LastOutcome.Cause != recordoutcome.CausePanic {
		t.Fatalf("panic availability = %+v, want degraded/panic carrying partial/panic outcome", point)
	}
}

func TestScheduler_PanicWithoutProgressRecordsFailedAvailability(t *testing.T) {
	rec := telemetrytest.New()
	status := collector.NewStatusTracker()
	availabilityTracker := availability.NewTracker("tenant-a", []availability.Static{{
		Collector: "devices",
		Transport: telemetry.TransportGraph,
		State:     availability.StateStarting,
		Reason:    availability.ReasonNoCompletedRun,
	}})
	s := collector.NewScheduler(
		rec.Emitter(),
		collector.NewMemoryStore(),
		collector.WithStatusTracker(status),
		collector.WithAvailabilityTracker(availabilityTracker),
	)
	entry := collector.Entry{
		Collector: snapFunc{
			name: "devices",
			def:  time.Minute,
			fn: func(context.Context, telemetry.Emitter, *recordoutcome.Recorder) error {
				panic("collector bug")
			},
		},
		Interval: time.Minute,
	}
	var lastSuccess time.Time

	s.RunTick(context.Background(), entry, &lastSuccess)

	run := status.Snapshot()["devices"]
	if run.Runs != 1 ||
		run.Failures != 1 ||
		run.LastSuccess ||
		run.LastOutcome.Result != recordoutcome.ResultFailure ||
		run.LastOutcome.Cause != recordoutcome.CausePanic {
		t.Fatalf("panic status = %+v, want one failed panic run", run)
	}
	point := availabilityTracker.Snapshot()[0]
	if point.State != availability.StateFailed ||
		point.Reason != availability.ReasonPanic ||
		point.LastOutcome == nil ||
		point.LastOutcome.Result != recordoutcome.ResultFailure ||
		point.LastOutcome.Cause != recordoutcome.CausePanic {
		t.Fatalf("panic availability = %+v, want failed/panic carrying failure/panic outcome", point)
	}
}

func TestScheduler_AccountingMismatchBecomesFailure(t *testing.T) {
	rec := telemetrytest.New()
	status := collector.NewStatusTracker()
	s := collector.NewScheduler(
		rec.Emitter(),
		collector.NewMemoryStore(),
		collector.WithStatusTracker(status),
	)
	entry := collector.Entry{
		Collector: snapFunc{
			name: "devices",
			def:  time.Minute,
			fn: func(_ context.Context, _ telemetry.Emitter, outcomes *recordoutcome.Recorder) error {
				outcomes.Add(recordoutcome.OutcomeFetched, 1)
				return nil
			},
		},
		Interval: time.Minute,
	}
	var lastSuccess time.Time

	s.RunTick(context.Background(), entry, &lastSuccess)

	assertMetricSeries(t, rec, collector.MetricScrapeOutcomes, 1, map[string]string{
		semconv.AttrCollector:       "devices",
		semconv.AttrIngestTransport: "graph",
		"result":                    "failure",
	})
	run := status.Snapshot()["devices"]
	if run.LastOutcome.Result != recordoutcome.ResultFailure ||
		run.LastOutcome.Cause != recordoutcome.CauseAccountingMismatch {
		t.Fatalf("LastOutcome = %+v, want failure/accounting_mismatch", run.LastOutcome)
	}
}

func TestScheduler_EmitsBoundedPayloadTypeMismatch(t *testing.T) {
	rec := telemetrytest.New()
	s := collector.NewScheduler(rec.Emitter(), collector.NewMemoryStore())
	entry := collector.Entry{
		Collector: snapFunc{
			name: "devices",
			def:  time.Minute,
			fn: func(_ context.Context, _ telemetry.Emitter, outcomes *recordoutcome.Recorder) error {
				outcomes.TypeMismatch("operatingSystem", "string", "array")
				outcomes.TypeMismatch("operatingSystem", "string", "array")
				return nil
			},
		},
		Interval: time.Minute,
	}
	var lastSuccess time.Time

	s.RunTick(context.Background(), entry, &lastSuccess)

	assertMetricSeries(t, rec, collector.MetricPayloadTypeMismatches, 2, map[string]string{
		semconv.AttrCollector:       "devices",
		semconv.AttrIngestTransport: "graph",
		"field":                     "operatingSystem",
		"expected_type":             "string",
		"actual_type":               "array",
	})
}

func TestScheduler_WithTenantStampsEventLagWithoutCallerEmitterDecorator(t *testing.T) {
	now := time.Date(2026, time.July, 25, 12, 0, 0, 0, time.UTC)
	rec := telemetrytest.New()
	s := collector.NewScheduler(
		rec.Emitter(),
		collector.NewMemoryStore(),
		collector.WithTenant("tenant-a"),
		collector.WithClock(func() time.Time { return now }),
	)
	entry := collector.Entry{
		Collector: snapFunc{
			name: "devices",
			def:  time.Minute,
			fn: func(_ context.Context, e telemetry.Emitter, _ *recordoutcome.Recorder) error {
				e.LogEvent(telemetry.Event{
					Name:      "intune.device",
					Timestamp: now.Add(-30 * time.Second),
				})
				return nil
			},
		},
		Interval: time.Minute,
	}
	var lastSuccess time.Time

	s.RunTick(context.Background(), entry, &lastSuccess)

	assertMetricSeries(t, rec, "graph2otel.event.lag", 30, map[string]string{
		semconv.AttrTenantID:        "tenant-a",
		semconv.AttrCollector:       "devices",
		semconv.AttrIngestTransport: "graph",
	})
}

func TestScheduler_LogsLegitimateLossAsDegradedOutcome(t *testing.T) {
	var logs bytes.Buffer
	s := collector.NewScheduler(
		telemetrytest.New().Emitter(),
		collector.NewMemoryStore(),
		collector.WithLogger(slog.New(slog.NewTextHandler(&logs, nil))),
	)
	entry := collector.Entry{
		Collector: snapFunc{
			name: "devices",
			def:  time.Minute,
			fn: func(_ context.Context, _ telemetry.Emitter, outcomes *recordoutcome.Recorder) error {
				outcomes.Add(recordoutcome.OutcomeFetched, 1)
				outcomes.Add(recordoutcome.OutcomeDropped, 1)
				outcomes.Cause(recordoutcome.CauseMissingEventTime)
				return nil
			},
		},
		Interval: time.Minute,
	}
	var lastSuccess time.Time

	s.RunTick(context.Background(), entry, &lastSuccess)

	got := logs.String()
	if !strings.Contains(got, "collector completed with degraded outcome") {
		t.Fatalf("logs = %q, want degraded-outcome warning", got)
	}
	if strings.Contains(got, "outcome accounting failed") {
		t.Fatalf("logs = %q, legitimate loss must not be called an accounting failure", got)
	}
}

func TestSchedulerRecordsAvailabilityWithoutChangingStatusAccounting(t *testing.T) {
	rec := telemetrytest.New()
	status := collector.NewStatusTracker()
	availabilityTracker := availability.NewTracker("tenant-a", []availability.Static{
		{
			Collector: "permission",
			Transport: telemetry.TransportGraph,
			State:     availability.StateStarting,
			Reason:    availability.ReasonNoCompletedRun,
		},
		{
			Collector:   "limited",
			Transport:   telemetry.TransportGraph,
			State:       availability.StateLimited,
			Reason:      availability.ReasonPartialLicense,
			Limitations: []availability.Limitation{"premium_signal"},
		},
	})
	s := collector.NewScheduler(
		rec.Emitter(),
		collector.NewMemoryStore(),
		collector.WithSelfObs(false),
		collector.WithStatusTracker(status),
		collector.WithAvailabilityTracker(availabilityTracker),
	)
	var lastSuccess time.Time

	s.RunTick(context.Background(), collector.Entry{
		Collector: snapFunc{
			name: "permission",
			def:  time.Minute,
			fn: func(_ context.Context, _ telemetry.Emitter, outcomes *recordoutcome.Recorder) error {
				outcomes.Cause(recordoutcome.CausePermissionDenied)
				return errors.New("forbidden")
			},
		},
		Interval: time.Minute,
	}, &lastSuccess)
	s.RunTick(context.Background(), collector.Entry{
		Collector: snapFunc{
			name: "limited",
			def:  time.Minute,
			fn: func(_ context.Context, _ telemetry.Emitter, outcomes *recordoutcome.Recorder) error {
				outcomes.Add(recordoutcome.OutcomeFetched, 1)
				outcomes.Add(recordoutcome.OutcomeMapped, 1)
				outcomes.Add(recordoutcome.OutcomeEmitted, 1)
				return nil
			},
		},
		Interval: time.Minute,
	}, &lastSuccess)

	points := availabilityTracker.Snapshot()
	if len(points) != 2 {
		t.Fatalf("availability points = %d, want 2", len(points))
	}
	gotAvailability := map[string][2]string{}
	for _, point := range points {
		gotAvailability[point.Collector] = [2]string{string(point.State), string(point.Reason)}
	}
	wantAvailability := map[string][2]string{
		"permission": {string(availability.StateBlocked), string(availability.ReasonPermissionDenied)},
		"limited":    {string(availability.StateLimited), string(availability.ReasonPartialLicense)},
	}
	if !reflect.DeepEqual(gotAvailability, wantAvailability) {
		t.Fatalf("availability = %v, want %v", gotAvailability, wantAvailability)
	}

	runs := status.Snapshot()
	if runs["permission"].Runs != 1 ||
		runs["permission"].LastSuccess ||
		runs["permission"].LastOutcome.Result != recordoutcome.ResultFailure ||
		runs["permission"].LastOutcome.Cause != recordoutcome.CausePermissionDenied {
		t.Errorf("permission status = %+v, want one permission failure", runs["permission"])
	}
	if runs["limited"].Runs != 1 ||
		!runs["limited"].LastSuccess ||
		runs["limited"].LastOutcome.Result != recordoutcome.ResultSuccess {
		t.Errorf("limited status = %+v, want one successful run independent of static limitation", runs["limited"])
	}
	if got := rec.MetricPoints(availability.MetricCollectorAvailability); len(got) != 0 {
		t.Errorf("scheduler emitted availability snapshot during run: %v", got)
	}
}

func TestSchedulerAvailabilitySkipsShutdownCancellation(t *testing.T) {
	status := collector.NewStatusTracker()
	availabilityTracker := availability.NewTracker("tenant-a", []availability.Static{{
		Collector: "devices",
		Transport: telemetry.TransportGraph,
		State:     availability.StateStarting,
		Reason:    availability.ReasonNoCompletedRun,
	}})
	s := collector.NewScheduler(
		telemetrytest.New().Emitter(),
		collector.NewMemoryStore(),
		collector.WithStatusTracker(status),
		collector.WithAvailabilityTracker(availabilityTracker),
	)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	var lastSuccess time.Time

	s.RunTick(ctx, collector.Entry{
		Collector: snapFunc{
			name: "devices",
			def:  time.Minute,
			fn: func(ctx context.Context, _ telemetry.Emitter, _ *recordoutcome.Recorder) error {
				return ctx.Err()
			},
		},
		Interval: time.Minute,
	}, &lastSuccess)

	point := availabilityTracker.Snapshot()[0]
	if point.State != availability.StateStarting ||
		point.Reason != availability.ReasonNoCompletedRun ||
		point.LastOutcome != nil {
		t.Fatalf("shutdown cancellation changed availability to %+v, want untouched starting point", point)
	}
	if got := status.Snapshot(); len(got) != 0 {
		t.Fatalf("shutdown cancellation changed status accounting: %v", got)
	}
}

func TestScheduler_SnapshotBindsSteadyStateEmitterAndReconcilesSourceRecords(t *testing.T) {
	selfObs := telemetrytest.New()
	data := telemetrytest.New()
	var got telemetry.Attribution
	var recorded telemetry.Attribution
	var recordedFetched uint64
	s := collector.NewScheduler(
		selfObs.Emitter(),
		collector.NewMemoryStore(),
		collector.WithTenant("acme"),
		collector.WithEmitterFactory(func(a telemetry.Attribution) telemetry.Emitter {
			got = a
			return data.Emitter()
		}),
		collector.WithSourceRecordRecorder(func(a telemetry.Attribution, fetched uint64) {
			recorded = a
			recordedFetched = fetched
		}),
	)
	entry := collector.Entry{
		Collector: transportedSnap{
			snapFunc: snapFunc{
				name: "devices",
				def:  time.Minute,
				fn: func(_ context.Context, e telemetry.Emitter, outcomes *recordoutcome.Recorder) error {
					e.Gauge("intune.devices.count", "{device}", "devices", 2, nil)
					outcomes.Add(recordoutcome.OutcomeFetched, 2)
					outcomes.Add(recordoutcome.OutcomeMapped, 2)
					outcomes.Add(recordoutcome.OutcomeEmitted, 2)
					return nil
				},
			},
			transport: telemetry.TransportReportExport,
		},
		Interval: time.Minute,
	}
	var lastSuccess time.Time

	s.RunTick(context.Background(), entry, &lastSuccess)

	want := telemetry.Attribution{
		TenantID:     "acme",
		Collector:    "devices",
		Transport:    telemetry.TransportReportExport,
		TrafficClass: telemetry.TrafficClassSteadyState,
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("factory attribution = %+v, want %+v", got, want)
	}
	if !reflect.DeepEqual(recorded, want) || recordedFetched != 2 {
		t.Fatalf("source-record callback = (%+v, %d), want (%+v, 2)", recorded, recordedFetched, want)
	}
	assertMetricSeries(t, data, "intune.devices.count", 2, nil)
	if got := selfObs.MetricPoints("intune.devices.count"); len(got) != 0 {
		t.Fatalf("domain metric used scheduler self-observation emitter: %v", got)
	}
	assertMetricSeries(t, selfObs, collector.MetricSourceRecords, 2, map[string]string{
		semconv.AttrTenantID:        "acme",
		semconv.AttrCollector:       "devices",
		semconv.AttrIngestTransport: "report_export",
		semconv.AttrTrafficClass:    "steady_state",
	})
	assertMetricSeries(t, selfObs, collector.MetricRecordOutcomes, 2, map[string]string{
		semconv.AttrTenantID:        "acme",
		semconv.AttrCollector:       "devices",
		semconv.AttrIngestTransport: "report_export",
		"outcome":                   "fetched",
	})
	for _, point := range selfObs.MetricPoints(collector.MetricRecordOutcomes) {
		if _, ok := point.Attrs[semconv.AttrTrafficClass]; ok {
			t.Fatalf("%s changed frozen #269 labels: %v", collector.MetricRecordOutcomes, point.Attrs)
		}
	}
}

func TestScheduler_WindowTrafficClassComesFromTheSameCheckpointRead(t *testing.T) {
	now := time.Unix(1_700_000_000, 0).UTC()
	tests := []struct {
		name       string
		checkpoint *time.Time
		want       telemetry.TrafficClass
	}{
		{name: "no checkpoint is cold-start backfill", want: telemetry.TrafficClassColdStartBackfill},
		{name: "checkpointed is steady state", checkpoint: ptrTime(now.Add(-time.Hour)), want: telemetry.TrafficClassSteadyState},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			selfObs := telemetrytest.New()
			store := &countingCheckpointStore{CheckpointStore: collector.NewMemoryStore()}
			if tc.checkpoint != nil {
				if err := store.Set("auditlogs", *tc.checkpoint); err != nil {
					t.Fatal(err)
				}
			}
			var got telemetry.Attribution
			s := collector.NewScheduler(
				selfObs.Emitter(),
				store,
				collector.WithClock(func() time.Time { return now }),
				collector.WithEmitterFactory(func(a telemetry.Attribution) telemetry.Emitter {
					got = a
					return telemetrytest.New().Emitter()
				}),
			)
			entry := collector.Entry{
				Collector: winFunc{
					name: "auditlogs",
					def:  time.Minute,
					fn: func(_ context.Context, _, to time.Time, _ telemetry.Emitter, outcomes *recordoutcome.Recorder) (time.Time, error) {
						outcomes.Add(recordoutcome.OutcomeFetched, 1)
						outcomes.Add(recordoutcome.OutcomeMapped, 1)
						outcomes.Add(recordoutcome.OutcomeEmitted, 1)
						return to, nil
					},
				},
				Interval:        time.Minute,
				InitialLookback: time.Hour,
				MaxWindow:       24 * time.Hour,
			}
			var lastSuccess time.Time

			s.RunTick(context.Background(), entry, &lastSuccess)

			if got.TrafficClass != tc.want {
				t.Fatalf("traffic class = %q, want %q", got.TrafficClass, tc.want)
			}
			if store.gets["auditlogs"] != 1 {
				t.Fatalf("main checkpoint reads = %d, want exactly 1 for class and window", store.gets["auditlogs"])
			}
			assertMetricSeries(t, selfObs, collector.MetricSourceRecords, 1, map[string]string{
				semconv.AttrCollector:    "auditlogs",
				semconv.AttrTrafficClass: string(tc.want),
			})
		})
	}
}

func TestScheduler_ZeroRowRunEmitsClassifiedSourceRecordPoint(t *testing.T) {
	rec := telemetrytest.New()
	var callbackCalls int
	var callbackFetched uint64
	s := collector.NewScheduler(
		rec.Emitter(),
		collector.NewMemoryStore(),
		collector.WithEmitterFactory(func(telemetry.Attribution) telemetry.Emitter {
			return telemetrytest.New().Emitter()
		}),
		collector.WithSourceRecordRecorder(func(_ telemetry.Attribution, fetched uint64) {
			callbackCalls++
			callbackFetched = fetched
		}),
	)
	entry := collector.Entry{
		Collector: snapFunc{
			name: "empty",
			def:  time.Minute,
			fn: func(context.Context, telemetry.Emitter, *recordoutcome.Recorder) error {
				return nil
			},
		},
		Interval: time.Minute,
	}
	var lastSuccess time.Time

	s.RunTick(context.Background(), entry, &lastSuccess)

	assertMetricSeries(t, rec, collector.MetricSourceRecords, 0, map[string]string{
		semconv.AttrCollector:    "empty",
		semconv.AttrTrafficClass: "steady_state",
	})
	if callbackCalls != 1 || callbackFetched != 0 {
		t.Fatalf("zero-row callback = (%d calls, %d fetched), want (1, 0)", callbackCalls, callbackFetched)
	}
}

func TestScheduler_SourceRecordRecorderIsIndependentOfOTLPSelfObs(t *testing.T) {
	rec := telemetrytest.New()
	var got uint64
	s := collector.NewScheduler(
		rec.Emitter(),
		collector.NewMemoryStore(),
		collector.WithSelfObs(false),
		collector.WithSourceRecordRecorder(func(_ telemetry.Attribution, fetched uint64) {
			got = fetched
		}),
	)
	entry := collector.Entry{
		Collector: snapFunc{
			name: "quiet",
			def:  time.Minute,
			fn: func(_ context.Context, _ telemetry.Emitter, outcomes *recordoutcome.Recorder) error {
				outcomes.Add(recordoutcome.OutcomeFetched, 3)
				outcomes.Add(recordoutcome.OutcomeFiltered, 3)
				return nil
			},
		},
		Interval: time.Minute,
	}
	var lastSuccess time.Time

	s.RunTick(context.Background(), entry, &lastSuccess)

	if got != 3 {
		t.Fatalf("source-record callback fetched = %d, want 3 with selfobs disabled", got)
	}
	if points := rec.MetricPoints(collector.MetricSourceRecords); len(points) != 0 {
		t.Fatalf("source-record OTLP points = %v, want none with selfobs disabled", points)
	}
}

func TestScheduler_PartialRunRetainsBoundEmitterHandoffAndSourceRecords(t *testing.T) {
	selfObs := telemetrytest.New()
	data := telemetrytest.New()
	var sourceRecordCalls int
	s := collector.NewScheduler(
		selfObs.Emitter(),
		collector.NewMemoryStore(),
		collector.WithEmitterFactory(func(telemetry.Attribution) telemetry.Emitter {
			return data.Emitter()
		}),
		collector.WithSourceRecordRecorder(func(telemetry.Attribution, uint64) {
			sourceRecordCalls++
		}),
	)
	entry := collector.Entry{
		Collector: snapFunc{
			name: "partial",
			def:  time.Minute,
			fn: func(_ context.Context, e telemetry.Emitter, outcomes *recordoutcome.Recorder) error {
				e.Counter("entra.partial.records", "{record}", "", 1, nil)
				outcomes.Add(recordoutcome.OutcomeFetched, 2)
				outcomes.Add(recordoutcome.OutcomeMapped, 1)
				outcomes.Add(recordoutcome.OutcomeEmitted, 1)
				outcomes.Add(recordoutcome.OutcomeErrored, 1)
				outcomes.Cause(recordoutcome.CauseSourceError)
				return errors.New("page failed")
			},
		},
		Interval: time.Minute,
	}
	var lastSuccess time.Time

	s.RunTick(context.Background(), entry, &lastSuccess)

	assertMetricSeries(t, data, "entra.partial.records", 1, nil)
	assertMetricSeries(t, selfObs, collector.MetricSourceRecords, 2, map[string]string{
		semconv.AttrCollector:    "partial",
		semconv.AttrTrafficClass: "steady_state",
	})
	if sourceRecordCalls != 1 {
		t.Fatalf("partial run source-record callback calls = %d, want 1", sourceRecordCalls)
	}
}

func TestScheduler_ShutdownKeepsBoundEmitterHandoffButSuppressesSourceRecords(t *testing.T) {
	selfObs := telemetrytest.New()
	data := telemetrytest.New()
	var sourceRecordCalls int
	s := collector.NewScheduler(
		selfObs.Emitter(),
		collector.NewMemoryStore(),
		collector.WithEmitterFactory(func(telemetry.Attribution) telemetry.Emitter {
			return data.Emitter()
		}),
		collector.WithSourceRecordRecorder(func(telemetry.Attribution, uint64) {
			sourceRecordCalls++
		}),
	)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	entry := collector.Entry{
		Collector: snapFunc{
			name: "shutdown",
			def:  time.Minute,
			fn: func(ctx context.Context, e telemetry.Emitter, outcomes *recordoutcome.Recorder) error {
				e.Counter("entra.shutdown.handoff", "{record}", "", 1, nil)
				outcomes.Add(recordoutcome.OutcomeFetched, 1)
				outcomes.Add(recordoutcome.OutcomeMapped, 1)
				outcomes.Add(recordoutcome.OutcomeEmitted, 1)
				return ctx.Err()
			},
		},
		Interval: time.Minute,
	}
	var lastSuccess time.Time

	s.RunTick(ctx, entry, &lastSuccess)

	assertMetricSeries(t, data, "entra.shutdown.handoff", 1, nil)
	if got := selfObs.MetricPoints(collector.MetricSourceRecords); len(got) != 0 {
		t.Fatalf("shutdown emitted source-record accounting: %v", got)
	}
	if got := selfObs.MetricPoints(collector.MetricRecordOutcomes); len(got) != 0 {
		t.Fatalf("shutdown changed frozen #269 accounting: %v", got)
	}
	if sourceRecordCalls != 0 {
		t.Fatalf("shutdown called source-record recorder %d times, want 0", sourceRecordCalls)
	}
}

func ptrTime(t time.Time) *time.Time { return &t }

// TestEmitBuildInfo pins that graph2otel.build_info is emitted once with
// value 1 and a "version" attribute.
func TestEmitBuildInfo(t *testing.T) {
	rec := telemetrytest.New()
	collector.EmitBuildInfo(rec.Emitter())

	points := rec.MetricPoints(collector.MetricBuildInfo)
	if len(points) != 1 {
		t.Fatalf("MetricBuildInfo points = %d, want 1", len(points))
	}
	if points[0].Value != 1 {
		t.Errorf("MetricBuildInfo value = %v, want 1", points[0].Value)
	}
	if _, ok := points[0].Attrs["version"]; !ok {
		t.Errorf("MetricBuildInfo attrs = %v, want a \"version\" attribute", points[0].Attrs)
	}
}

// TestSelfObsMetrics_OnlyBoundedAttrs pins the cardinality guarantee that
// every self-obs metric point carries ONLY the bounded collector/tenant_id
// attributes -- never a per-entity identifier.
func TestSelfObsMetrics_OnlyBoundedAttrs(t *testing.T) {
	rec := telemetrytest.New()
	s := collector.NewScheduler(rec.Emitter(), collector.NewMemoryStore(), collector.WithTenant("acme"))
	e := collector.Entry{
		Collector: snapFunc{name: "devices", def: time.Second, fn: func(context.Context, telemetry.Emitter, *recordoutcome.Recorder) error {
			return errors.New("boom")
		}},
		Interval: time.Second,
	}
	var lastSuccess time.Time
	s.RunTick(context.Background(), e, &lastSuccess)

	allowed := map[string]bool{semconv.AttrCollector: true, semconv.AttrTenantID: true, "error.type": true}
	for _, name := range []string{
		collector.MetricScrapeDuration, collector.MetricScrapeSuccess, collector.MetricScrapeErrors,
		collector.MetricScrapeLastTimestamp, collector.MetricScrapeStaleness, collector.MetricScrapeBudget,
	} {
		for _, p := range rec.MetricPoints(name) {
			for k := range p.Attrs {
				if !allowed[k] {
					t.Errorf("%s carries disallowed attribute key %q (attrs=%v)", name, k, p.Attrs)
				}
			}
		}
	}
}

// assertGaugeAttrs asserts that the single recorded point for name has the
// given value and attribute set.
func assertGaugeAttrs(t *testing.T, rec *telemetrytest.Recorder, name string, wantValue float64, wantAttrs map[string]string) {
	t.Helper()
	points := rec.MetricPoints(name)
	if len(points) != 1 {
		t.Fatalf("%s points = %d, want 1", name, len(points))
	}
	if points[0].Value != wantValue {
		t.Errorf("%s value = %v, want %v", name, points[0].Value, wantValue)
	}
	for k, v := range wantAttrs {
		if points[0].Attrs[k] != v {
			t.Errorf("%s attrs[%q] = %q, want %q (attrs=%v)", name, k, points[0].Attrs[k], v, points[0].Attrs)
		}
	}
}

func assertMetricSeries(
	t *testing.T,
	rec *telemetrytest.Recorder,
	name string,
	wantValue float64,
	wantAttrs map[string]string,
) {
	t.Helper()
	for _, point := range rec.MetricPoints(name) {
		matches := true
		for key, value := range wantAttrs {
			if point.Attrs[key] != value {
				matches = false
				break
			}
		}
		if matches {
			if point.Value != wantValue {
				t.Fatalf("%s matching series value = %v, want %v (attrs=%v)", name, point.Value, wantValue, point.Attrs)
			}
			return
		}
	}
	t.Fatalf("%s has no series matching attrs %v; points=%v", name, wantAttrs, rec.MetricPoints(name))
}
