package telemetry_test

import (
	"fmt"
	"testing"

	"github.com/rknightion/graph2otel/internal/semconv"
	"github.com/rknightion/graph2otel/internal/telemetry"
	"github.com/rknightion/graph2otel/internal/telemetrytest"
)

// seriesActivePointsByName indexes the series.active points emitted into rec
// by the value of their metric.name attribute, so a test can assert the
// per-source-metric distinct-series count.
func seriesActivePointsByName(t *testing.T, rec *telemetrytest.Recorder) map[string]float64 {
	t.Helper()
	out := map[string]float64{}
	for _, p := range rec.MetricPoints("graph2otel.series.active") {
		name := p.Attrs[semconv.AttrMetricName]
		if name == "" {
			t.Fatalf("series.active point missing %q attribute: %+v", semconv.AttrMetricName, p)
		}
		out[name] = p.Value
	}
	return out
}

// TestCardinalityTrackerExactDistinctCountPerMetric drives M source metrics
// with N distinct fingerprints each and asserts Report emits exactly M points,
// one per source metric, each carrying the exact distinct count N.
func TestCardinalityTrackerExactDistinctCountPerMetric(t *testing.T) {
	const (
		metricCount = 3
		seriesPer   = 5
	)
	rec := telemetrytest.New()
	tr := telemetry.NewCardinalityTracker()

	for m := 0; m < metricCount; m++ {
		name := fmt.Sprintf("entra.metric.%d", m)
		for s := 0; s < seriesPer; s++ {
			tr.Observe(name, telemetry.Attrs{"a": "x", "n": s})
		}
	}

	tr.Report(rec.Emitter())

	got := seriesActivePointsByName(t, rec)
	if len(got) != metricCount {
		t.Fatalf("got %d series.active points, want %d: %+v", len(got), metricCount, got)
	}
	for m := 0; m < metricCount; m++ {
		name := fmt.Sprintf("entra.metric.%d", m)
		if got[name] != float64(seriesPer) {
			t.Errorf("series.active{%s=%s} = %v, want %d", semconv.AttrMetricName, name, got[name], seriesPer)
		}
	}
}

// TestCardinalityTrackerConfigurableCap asserts a tracker built with an
// explicit cap pins each source metric's reported distinct-series count at
// that cap once exceeded (rather than the package default), so series.active
// faithfully signals when a metric is at the configured OTLP cardinality
// limit.
func TestCardinalityTrackerConfigurableCap(t *testing.T) {
	rec := telemetrytest.New()
	tr := telemetry.NewCardinalityTrackerWithCap(3)
	for s := 0; s < 5; s++ {
		tr.Observe("intune.metric", telemetry.Attrs{"n": s})
	}
	tr.Report(rec.Emitter())

	if got := seriesActivePointsByName(t, rec)["intune.metric"]; got != 3 {
		t.Fatalf("series.active = %v, want 3 (pinned at the configured cap)", got)
	}
	snap := tr.Snapshot()
	if len(snap) != 1 || snap[0].Count != 3 || !snap[0].Capped {
		t.Fatalf("Snapshot = %+v, want one entry Count=3 Capped=true", snap)
	}
}

// TestCardinalityTrackerNonPositiveCapFallsBackToDefault asserts a
// non-positive cap (the "unlimited OTLP limit" case) falls back to the
// package memory-guard default rather than tracking unboundedly, and that the
// series.limit gauge is suppressed (no positive limit configured).
func TestCardinalityTrackerNonPositiveCapFallsBackToDefault(t *testing.T) {
	tr := telemetry.NewCardinalityTrackerWithCap(0)
	rec := telemetrytest.New()
	tr.Observe("intune.metric", telemetry.Attrs{"n": 1})
	tr.Report(rec.Emitter())
	if got := seriesActivePointsByName(t, rec)["intune.metric"]; got != 1 {
		t.Fatalf("series.active = %v, want 1 (default cap still tracks normally)", got)
	}
	if pts := rec.MetricPoints("graph2otel.series.limit"); len(pts) != 0 {
		t.Errorf("series.limit = %+v, want none (unlimited)", pts)
	}
}

// TestCardinalityTrackerEmitsTheConfiguredLimit asserts Report emits a single
// graph2otel.series.limit point carrying the configured per-metric limit.
//
// graph2otel.series.overflowing is deliberately GONE (#235). It meant "this
// metric reached the SDK's per-instrument cap and the excess vanished into
// otel.metric.overflow" — a mechanism that no longer exists, since the SDK's cap
// is disabled in favor of graph2otel's own limiter. Keeping the name pointed at
// the nearest surviving condition would have made it quietly mean something
// else. graph2otel.series.clipped replaces it with strictly more: how many
// series were shed, and whether they were folded into `other` or dropped.
func TestCardinalityTrackerEmitsTheConfiguredLimit(t *testing.T) {
	rec := telemetrytest.New()
	tr := telemetry.NewCardinalityTrackerForLimit(2)
	for s := 0; s < 5; s++ {
		tr.Observe("entra.hot", telemetry.Attrs{"n": s})
	}
	tr.Report(rec.Emitter())

	limit := rec.MetricPoints("graph2otel.series.limit")
	if len(limit) != 1 || limit[0].Value != 2 {
		t.Fatalf("series.limit = %+v, want one point value=2", limit)
	}
	if pts := rec.MetricPoints("graph2otel.series.overflowing"); len(pts) != 0 {
		t.Errorf("series.overflowing = %+v, want none — it named the SDK overflow, which "+
			"no longer exists; graph2otel.series.clipped carries this now", pts)
	}
}

// TestCardinalityTrackerCountsAboveTheConfiguredLimit is the reason the memory
// guard and the reported limit had to stop being the same number.
//
// The tracker sits INSIDE the limiter, and the limiter emits up to the limit
// plus the hysteresis band plus the `other` bucket. A tracker that pinned AT the
// limit would under-report by exactly the amount that only appears once a metric
// goes over it — the one moment anybody reads the number.
func TestCardinalityTrackerCountsAboveTheConfiguredLimit(t *testing.T) {
	rec := telemetrytest.New()
	tr := telemetry.NewCardinalityTrackerForLimit(3)
	for s := 0; s < 7; s++ {
		tr.Observe("entra.hot", telemetry.Attrs{"n": s})
	}
	tr.Report(rec.Emitter())

	if got := seriesActivePointsByName(t, rec)["entra.hot"]; got != 7 {
		t.Errorf("series.active = %v, want 7 — the true count of what reached the SDK, "+
			"not a value pinned at the configured limit of 3", got)
	}
}

// TestCardinalityTrackerNilIsNoop asserts every method is safe to call on a
// nil *CardinalityTracker (the "self-observability disabled" case): Observe
// and Report must not panic, and Snapshot must return nil.
func TestCardinalityTrackerNilIsNoop(t *testing.T) {
	var tr *telemetry.CardinalityTracker
	rec := telemetrytest.New()
	tr.Observe("entra.metric", telemetry.Attrs{"n": 1})
	tr.Report(rec.Emitter())
	if snap := tr.Snapshot(); snap != nil {
		t.Errorf("Snapshot() on nil tracker = %+v, want nil", snap)
	}
	if pts := rec.MetricPoints("graph2otel.series.active"); len(pts) != 0 {
		t.Errorf("series.active = %+v, want none (nil tracker never reports)", pts)
	}
}

// TestCardinalityTrackerSelfExclusion asserts Observe ignores the
// graph2otel.series.* family itself, breaking the Report -> Gauge -> Observe
// recursion.
func TestCardinalityTrackerSelfExclusion(t *testing.T) {
	tr := telemetry.NewCardinalityTracker()
	tr.Observe("graph2otel.series.overflowing", telemetry.Attrs{semconv.AttrMetricName: "x"})
	if snap := tr.Snapshot(); snap != nil {
		t.Fatalf("Snapshot after observing a self-metric = %+v, want nil (never observed)", snap)
	}
}
