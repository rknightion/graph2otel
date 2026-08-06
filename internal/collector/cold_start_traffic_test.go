package collector_test

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/rknightion/graph2otel/internal/collector"
	"github.com/rknightion/graph2otel/internal/recordoutcome"
	"github.com/rknightion/graph2otel/internal/semconv"
	"github.com/rknightion/graph2otel/internal/telemetry"
	"github.com/rknightion/graph2otel/internal/telemetrytest"
)

type markerFailureStore struct {
	collector.CheckpointStore
	mainKey          string
	failMarkerSet    bool
	failMarkerClears int
	mutateOnFailure  bool
}

func (s *markerFailureStore) Set(key string, value time.Time) error {
	isMarker := key != s.mainKey
	fail := isMarker && ((!value.IsZero() && s.failMarkerSet) ||
		(value.IsZero() && s.failMarkerClears > 0))
	if value.IsZero() && isMarker && s.failMarkerClears > 0 {
		s.failMarkerClears--
	}
	if fail {
		if s.mutateOnFailure {
			_ = s.CheckpointStore.Set(key, value)
		}
		return errors.New("marker persist failed")
	}
	return s.CheckpointStore.Set(key, value)
}

func TestScheduler_ColdStartTargetSurvivesSlicesAndRestart(t *testing.T) {
	now := time.Unix(1_700_000_000, 0).UTC()
	store := collector.NewMemoryStore()
	var classes []telemetry.TrafficClass
	var windows [][2]time.Time
	newScheduler := func() *collector.Scheduler {
		return collector.NewScheduler(
			telemetrytest.New().Emitter(),
			store,
			collector.WithClock(func() time.Time { return now }),
			collector.WithEmitterFactory(func(a telemetry.Attribution) telemetry.Emitter {
				classes = append(classes, a.TrafficClass)
				return telemetrytest.New().Emitter()
			}),
		)
	}
	entry := collector.Entry{
		Collector: winFunc{
			name: "auditlogs",
			def:  time.Minute,
			fn: func(_ context.Context, from, to time.Time, _ telemetry.Emitter, outcomes *recordoutcome.Recorder) (time.Time, error) {
				windows = append(windows, [2]time.Time{from, to})
				outcomes.Add(recordoutcome.OutcomeFetched, 1)
				outcomes.Add(recordoutcome.OutcomeMapped, 1)
				outcomes.Add(recordoutcome.OutcomeEmitted, 1)
				return to, nil
			},
		},
		Interval:        time.Minute,
		InitialLookback: 3 * time.Hour,
		MaxWindow:       time.Hour,
	}
	var lastSuccess time.Time

	newScheduler().RunTick(context.Background(), entry, &lastSuccess)
	// Reconstruct the scheduler after slice one: only persisted state may carry
	// the cold-start phase across this boundary.
	newScheduler().RunTick(context.Background(), entry, &lastSuccess)
	newScheduler().RunTick(context.Background(), entry, &lastSuccess)
	newScheduler().RunTick(context.Background(), entry, &lastSuccess)

	wantClasses := []telemetry.TrafficClass{
		telemetry.TrafficClassColdStartBackfill,
		telemetry.TrafficClassColdStartBackfill,
		telemetry.TrafficClassColdStartBackfill,
		telemetry.TrafficClassSteadyState,
	}
	if len(classes) != len(wantClasses) {
		t.Fatalf("classes = %v, want %v", classes, wantClasses)
	}
	for i := range wantClasses {
		if classes[i] != wantClasses[i] {
			t.Fatalf("classes[%d] = %q, want %q (all=%v)", i, classes[i], wantClasses[i], classes)
		}
	}
	if len(windows) != 3 {
		t.Fatalf("collected windows = %d, want three cold slices and one steady no-op: %v", len(windows), windows)
	}
	target := now
	if got := windows[0][0]; !got.Equal(target.Add(-3 * time.Hour)) {
		t.Fatalf("first from = %v, want %v", got, target.Add(-3*time.Hour))
	}
	for i, window := range windows {
		if got := window[1].Sub(window[0]); got != time.Hour {
			t.Fatalf("window[%d] duration = %v, want 1h", i, got)
		}
	}

	keys := store.Keys()
	if len(keys) != 2 {
		t.Fatalf("checkpoint keys = %q, want main plus collision-safe phase marker", keys)
	}
	for _, key := range keys {
		if key == "auditlogs" {
			continue
		}
		marker, ok := store.Get(key)
		if !ok || !marker.IsZero() {
			t.Fatalf("cleared marker %q = (%v, %v), want persisted zero", key, marker, ok)
		}
		if !strings.HasPrefix(key, "\x00graph2otel/") {
			t.Fatalf("marker key %q lacks reserved collision-safe namespace", key)
		}
	}
}

func TestScheduler_ColdStartTargetIsStableAcrossFirstRunFailure(t *testing.T) {
	now := time.Unix(1_700_000_000, 0).UTC()
	current := now
	store := collector.NewMemoryStore()
	attempt := 0
	var windows [][2]time.Time
	entry := collector.Entry{
		Collector: winFunc{
			name: "auditlogs",
			def:  time.Minute,
			fn: func(_ context.Context, from, to time.Time, _ telemetry.Emitter, outcomes *recordoutcome.Recorder) (time.Time, error) {
				windows = append(windows, [2]time.Time{from, to})
				attempt++
				if attempt == 1 {
					outcomes.Cause(recordoutcome.CauseSourceError)
					return time.Time{}, errors.New("first attempt failed")
				}
				return to, nil
			},
		},
		Interval:        time.Minute,
		InitialLookback: time.Hour,
		MaxWindow:       time.Hour,
	}
	newScheduler := func() *collector.Scheduler {
		return collector.NewScheduler(
			telemetrytest.New().Emitter(),
			store,
			collector.WithClock(func() time.Time { return current }),
		)
	}
	var lastSuccess time.Time

	newScheduler().RunTick(context.Background(), entry, &lastSuccess)
	current = current.Add(2 * time.Hour)
	newScheduler().RunTick(context.Background(), entry, &lastSuccess)

	if len(windows) != 2 {
		t.Fatalf("windows = %v, want two attempts", windows)
	}
	if windows[0] != windows[1] {
		t.Fatalf("retry window moved with wall clock: first=%v retry=%v", windows[0], windows[1])
	}
	if !windows[0][1].Equal(now) {
		t.Fatalf("cold target = %v, want original %v", windows[0][1], now)
	}
}

func TestScheduler_ColdStartMarkerSetFailurePreventsCollection(t *testing.T) {
	base := collector.NewMemoryStore()
	store := &markerFailureStore{
		CheckpointStore: base,
		mainKey:         "auditlogs",
		failMarkerSet:   true,
	}
	rec := telemetrytest.New()
	collected := false
	s := collector.NewScheduler(
		rec.Emitter(),
		store,
		collector.WithClock(func() time.Time { return time.Unix(1_700_000_000, 0).UTC() }),
	)
	entry := collector.Entry{
		Collector: winFunc{
			name: "auditlogs",
			def:  time.Minute,
			fn: func(context.Context, time.Time, time.Time, telemetry.Emitter, *recordoutcome.Recorder) (time.Time, error) {
				collected = true
				return time.Time{}, nil
			},
		},
		Interval:        time.Minute,
		InitialLookback: time.Hour,
		MaxWindow:       time.Hour,
	}
	var lastSuccess time.Time

	s.RunTick(context.Background(), entry, &lastSuccess)

	if collected {
		t.Fatal("collector ran without a durable cold-start target")
	}
	if _, ok := base.Get("auditlogs"); ok {
		t.Fatal("main HWM advanced despite marker-set failure")
	}
	if got := rec.MetricPoints(collector.MetricCheckpointPersistErrors); len(got) != 1 {
		t.Fatalf("checkpoint persist errors = %v, want one marker-set failure", got)
	}
}

func TestScheduler_ColdStartMarkerClearFailureRemainsCold(t *testing.T) {
	base := collector.NewMemoryStore()
	store := &markerFailureStore{
		CheckpointStore:  base,
		mainKey:          "auditlogs",
		failMarkerClears: 2,
		mutateOnFailure:  true,
	}
	now := time.Unix(1_700_000_000, 0).UTC()
	rec := telemetrytest.New()
	var classes []telemetry.TrafficClass
	collected := 0
	newScheduler := func() *collector.Scheduler {
		return collector.NewScheduler(
			rec.Emitter(),
			store,
			collector.WithClock(func() time.Time { return now }),
			collector.WithEmitterFactory(func(a telemetry.Attribution) telemetry.Emitter {
				classes = append(classes, a.TrafficClass)
				return telemetrytest.New().Emitter()
			}),
		)
	}
	entry := collector.Entry{
		Collector: winFunc{
			name: "auditlogs",
			def:  time.Minute,
			fn: func(_ context.Context, _, to time.Time, _ telemetry.Emitter, _ *recordoutcome.Recorder) (time.Time, error) {
				collected++
				return to, nil
			},
		},
		Interval:        time.Minute,
		InitialLookback: time.Hour,
		MaxWindow:       time.Hour,
	}
	var lastSuccess time.Time

	newScheduler().RunTick(context.Background(), entry, &lastSuccess)

	keys := base.Keys()
	if len(keys) != 2 {
		t.Fatalf("keys after failed clear = %q, want main plus marker", keys)
	}
	for _, key := range keys {
		if key == "auditlogs" {
			continue
		}
		target, ok := base.Get(key)
		if !ok || target.IsZero() {
			t.Fatalf("failed clear left marker %q = (%v, %v), want restored nonzero target", key, target, ok)
		}
	}
	if got := rec.MetricPoints(collector.MetricCheckpointPersistErrors); len(got) != 1 {
		t.Fatalf("checkpoint persist errors = %v, want one clear failure", got)
	}
	if _, ok := base.Get("auditlogs"); !ok {
		t.Fatal("failed marker clear discarded the successfully persisted main HWM")
	}
	assertGaugeAttrs(t, rec, collector.MetricScrapeSuccess, 0, map[string]string{
		semconv.AttrCollector: "auditlogs",
	})
	assertMetricSeries(t, rec, collector.MetricScrapeOutcomes, 1, map[string]string{
		semconv.AttrCollector:       "auditlogs",
		semconv.AttrIngestTransport: "graph",
		"result":                    "failure",
	})

	// A reconstructed scheduler observes the restored marker. It remains cold
	// and fails closed when the retrying zero-clear also fails, even though the
	// main HWM reached the target on the prior run.
	newScheduler().RunTick(context.Background(), entry, &lastSuccess)
	if collected != 1 {
		t.Fatalf("collector calls after retry-clear failure = %d, want 1", collected)
	}
	if len(classes) != 1 || classes[0] != telemetry.TrafficClassColdStartBackfill {
		t.Fatalf("classes after retry-clear failure = %v, want only first run cold", classes)
	}
	assertMetricSeries(t, rec, collector.MetricScrapeOutcomes, 2, map[string]string{
		semconv.AttrCollector:       "auditlogs",
		semconv.AttrIngestTransport: "graph",
		"result":                    "failure",
	})

	// Once the marker clear succeeds, the reconstructed scheduler can enter
	// steady state. The retained main HWM means there is no replay.
	newScheduler().RunTick(context.Background(), entry, &lastSuccess)
	if collected != 1 {
		t.Fatalf("collector calls after successful clear = %d, want 1 (no replay)", collected)
	}
	if len(classes) != 2 ||
		classes[0] != telemetry.TrafficClassColdStartBackfill ||
		classes[1] != telemetry.TrafficClassSteadyState {
		t.Fatalf("classes after successful clear = %v, want cold/steady", classes)
	}
}

func TestScheduler_ColdStartShutdownKeepsTargetForRestart(t *testing.T) {
	now := time.Unix(1_700_000_000, 0).UTC()
	store := collector.NewMemoryStore()
	var classes []telemetry.TrafficClass
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	shutdownEntry := collector.Entry{
		Collector: winFunc{
			name: "auditlogs",
			def:  time.Minute,
			fn: func(ctx context.Context, _, _ time.Time, _ telemetry.Emitter, _ *recordoutcome.Recorder) (time.Time, error) {
				return time.Time{}, ctx.Err()
			},
		},
		Interval:        time.Minute,
		InitialLookback: 2 * time.Hour,
		MaxWindow:       time.Hour,
	}
	newScheduler := func() *collector.Scheduler {
		return collector.NewScheduler(
			telemetrytest.New().Emitter(),
			store,
			collector.WithClock(func() time.Time { return now }),
			collector.WithEmitterFactory(func(a telemetry.Attribution) telemetry.Emitter {
				classes = append(classes, a.TrafficClass)
				return telemetrytest.New().Emitter()
			}),
		)
	}
	var lastSuccess time.Time

	newScheduler().RunTick(ctx, shutdownEntry, &lastSuccess)
	restartCtx, cancelRestart := context.WithCancel(context.Background())
	cancelRestart()
	newScheduler().RunTick(restartCtx, shutdownEntry, &lastSuccess)

	if len(classes) != 2 ||
		classes[0] != telemetry.TrafficClassColdStartBackfill ||
		classes[1] != telemetry.TrafficClassColdStartBackfill {
		t.Fatalf("classes across shutdown restart = %v, want cold/cold", classes)
	}
	if _, ok := store.Get("auditlogs"); ok {
		t.Fatal("shutdown advanced main HWM")
	}
	if len(store.Keys()) != 1 {
		t.Fatalf("shutdown keys = %q, want retained cold target only", store.Keys())
	}
}

// TestScheduler_ColdStartTargetClearsWhenWatermarkTrailsBySafetyLag pins the
// #417 livelock. Every logpipeline collector returns `to - SafetyLag` as its
// high-water mark, never `to`, because the watermark deliberately trails the
// window's upper bound. The cold-start completion test used to compare that
// trailing watermark against the frozen target, so with a non-zero SafetyLag it
// could never be satisfied: the target stayed set, windowNow stayed pinned to
// it, and the collector re-polled one fixed window forever. Eight collectors on
// the live tenant sat on the same 15-minute window for 11 days, fetching and
// deduping the same records and emitting nothing while reporting healthy.
//
// The fake here returns `to - safetyLag` precisely because the pre-existing
// cold-start tests return `to` — a collector shape no real collector has, which
// is why they stayed green over the bug.
func TestScheduler_ColdStartTargetClearsWhenWatermarkTrailsBySafetyLag(t *testing.T) {
	const safetyLag = 15 * time.Minute
	now := time.Unix(1_700_000_000, 0).UTC()
	store := collector.NewMemoryStore()
	var windows [][2]time.Time
	var classes []telemetry.TrafficClass
	entry := collector.Entry{
		Collector: winFunc{
			name: "signins",
			def:  time.Minute,
			fn: func(_ context.Context, from, to time.Time, _ telemetry.Emitter, outcomes *recordoutcome.Recorder) (time.Time, error) {
				windows = append(windows, [2]time.Time{from, to})
				outcomes.Add(recordoutcome.OutcomeFetched, 1)
				outcomes.Add(recordoutcome.OutcomeMapped, 1)
				outcomes.Add(recordoutcome.OutcomeDeduped, 1)
				return to.Add(-safetyLag), nil
			},
		},
		Interval:        time.Minute,
		InitialLookback: time.Hour,
	}
	sched := collector.NewScheduler(
		telemetrytest.New().Emitter(),
		store,
		collector.WithClock(func() time.Time { return now }),
		collector.WithEmitterFactory(func(a telemetry.Attribution) telemetry.Emitter {
			classes = append(classes, a.TrafficClass)
			return telemetrytest.New().Emitter()
		}),
	)
	var lastSuccess time.Time
	for range 3 {
		sched.RunTick(context.Background(), entry, &lastSuccess)
	}

	// The backfill covers everything up to the frozen target on the first tick,
	// so tick two onwards must be steady state.
	if len(classes) < 2 || classes[1] != telemetry.TrafficClassSteadyState {
		t.Fatalf("traffic classes = %v, want steady state from the second tick", classes)
	}
	for _, key := range store.Keys() {
		if key == "signins" {
			continue
		}
		marker, ok := store.Get(key)
		if ok && !marker.IsZero() {
			t.Fatalf("cold-start target %q = %v, want cleared once the window reached it", key, marker)
		}
	}
	// The livelock's signature: the same window polled over and over.
	if len(windows) > 1 && windows[1] == windows[0] {
		t.Fatalf("window repeated: %v then %v — collector is stuck on one range", windows[0], windows[1])
	}
}
