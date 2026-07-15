package collector_test

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	"github.com/rknightion/graph2otel/internal/collector"
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

type snapFunc struct {
	name string
	def  time.Duration
	fn   func(context.Context, telemetry.Emitter) error
}

func (s snapFunc) Name() string                                           { return s.name }
func (s snapFunc) DefaultInterval() time.Duration                         { return s.def }
func (s snapFunc) Collect(ctx context.Context, e telemetry.Emitter) error { return s.fn(ctx, e) }

type winFunc struct {
	name string
	def  time.Duration
	lag  time.Duration
	fn   func(context.Context, time.Time, time.Time, telemetry.Emitter) (time.Time, error)
}

func (w winFunc) Name() string                   { return w.name }
func (w winFunc) DefaultInterval() time.Duration { return w.def }
func (w winFunc) Lag() time.Duration             { return w.lag }
func (w winFunc) CollectWindow(ctx context.Context, from, to time.Time, e telemetry.Emitter) (time.Time, error) {
	return w.fn(ctx, from, to, e)
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
	r.Register(snapFunc{name: "ok", def: 5 * time.Millisecond, fn: func(context.Context, telemetry.Emitter) error {
		okTicks.inc()
		return nil
	}}, 5*time.Millisecond)
	r.Register(snapFunc{name: "bad", def: 5 * time.Millisecond, fn: func(context.Context, telemetry.Emitter) error {
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
	r.Register(snapFunc{name: "boom", def: 5 * time.Millisecond, fn: func(context.Context, telemetry.Emitter) error {
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
	r.Register(snapFunc{name: "staggered", def: time.Hour, fn: func(context.Context, telemetry.Emitter) error {
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
	disabled := snapFunc{name: "disabled", def: 5 * time.Millisecond, fn: func(context.Context, telemetry.Emitter) error {
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
	r.Register(snapFunc{name: "devices", def: 5 * time.Millisecond, fn: func(_ context.Context, e telemetry.Emitter) error {
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
		fn: func(_ context.Context, from, to time.Time, e telemetry.Emitter) (time.Time, error) {
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
		Collector: snapFunc{name: "devices", def: time.Second, fn: func(context.Context, telemetry.Emitter) error { return nil }},
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

// TestScheduler_FailedTickSetsSuccessZeroAndStalenessGrows pins that a failing
// tick sets graph2otel.scrape.success=0 and does NOT reset last-success, so
// graph2otel.scrape.staleness keeps increasing across subsequent failures.
func TestScheduler_FailedTickSetsSuccessZeroAndStalenessGrows(t *testing.T) {
	rec := telemetrytest.New()
	now := time.Unix(1_000_000, 0).UTC()
	s := collector.NewScheduler(rec.Emitter(), collector.NewMemoryStore(), collector.WithClock(func() time.Time { return now }))
	e := collector.Entry{
		Collector: snapFunc{name: "devices", def: time.Second, fn: func(context.Context, telemetry.Emitter) error {
			return errors.New("boom")
		}},
		Interval: time.Second,
	}
	lastSuccess := now
	s.RunTick(context.Background(), e, &lastSuccess)
	assertGaugeAttrs(t, rec, collector.MetricScrapeSuccess, 0, map[string]string{semconv.AttrCollector: "devices"})
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
		Collector: snapFunc{name: "devices", def: time.Second, fn: func(context.Context, telemetry.Emitter) error {
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
