package telemetry_test

import (
	"context"
	"testing"

	"github.com/rknightion/graph2otel/internal/telemetry"
	"github.com/rknightion/graph2otel/internal/telemetrytest"
)

// TestEmitterCounter asserts a Counter call is recorded with the expected
// name, unit, description, value, and attributes.
func TestEmitterCounter(t *testing.T) {
	rec := telemetrytest.New()
	rec.Emitter().Counter("entra.signin.count", "{signin}", "sign-ins processed", 3, telemetry.Attrs{"tenant_id": "t1"})

	pts := rec.MetricPoints("entra.signin.count")
	if len(pts) != 1 {
		t.Fatalf("got %d points, want 1: %+v", len(pts), pts)
	}
	p := pts[0]
	if p.Unit != "{signin}" || p.Value != 3 || !p.Monotonic {
		t.Errorf("point = %+v, want unit={signin} value=3 monotonic=true", p)
	}
	if p.Attrs["tenant_id"] != "t1" {
		t.Errorf("attrs = %+v, want tenant_id=t1", p.Attrs)
	}
}

// TestEmitterGauge asserts a Gauge call is recorded with the expected value
// and attributes.
func TestEmitterGauge(t *testing.T) {
	rec := telemetrytest.New()
	rec.Emitter().Gauge("intune.device.count", "{device}", "enrolled devices", 42, telemetry.Attrs{"os": "windows"})

	pts := rec.MetricPoints("intune.device.count")
	if len(pts) != 1 {
		t.Fatalf("got %d points, want 1: %+v", len(pts), pts)
	}
	if pts[0].Value != 42 || pts[0].Attrs["os"] != "windows" {
		t.Errorf("point = %+v, want value=42 os=windows", pts[0])
	}
}

// TestEmitterGaugeSnapshotDropsAbsentSeries asserts GaugeSnapshot replaces the
// full set of series each call: a series present in one snapshot but absent
// from the next must disappear from the export (rather than lingering at its
// last value, as a synchronous Gauge would under cumulative temporality).
func TestEmitterGaugeSnapshotDropsAbsentSeries(t *testing.T) {
	rec := telemetrytest.New()
	e := rec.Emitter()

	e.GaugeSnapshot("intune.device.compliance", "{device}", "devices by compliance state", []telemetry.GaugePoint{
		{Value: 1, Attrs: telemetry.Attrs{"device_id": "a"}},
		{Value: 1, Attrs: telemetry.Attrs{"device_id": "b"}},
	})
	if got := rec.MetricPoints("intune.device.compliance"); len(got) != 2 {
		t.Fatalf("after first snapshot: got %d points, want 2: %+v", len(got), got)
	}

	e.GaugeSnapshot("intune.device.compliance", "{device}", "devices by compliance state", []telemetry.GaugePoint{
		{Value: 1, Attrs: telemetry.Attrs{"device_id": "a"}},
	})
	got := rec.MetricPoints("intune.device.compliance")
	if len(got) != 1 {
		t.Fatalf("after second snapshot: got %d points, want 1 (device b must drop out): %+v", len(got), got)
	}
	if got[0].Attrs["device_id"] != "a" {
		t.Errorf("remaining point = %+v, want device_id=a", got[0])
	}
}

// TestEmitterUpDownCounter asserts an UpDownCounter call is recorded as a
// non-monotonic sum with the expected value.
func TestEmitterUpDownCounter(t *testing.T) {
	rec := telemetrytest.New()
	rec.Emitter().UpDownCounter("entra.group.membership.delta", "{member}", "membership delta", -2, nil)

	pts := rec.MetricPoints("entra.group.membership.delta")
	if len(pts) != 1 {
		t.Fatalf("got %d points, want 1: %+v", len(pts), pts)
	}
	if pts[0].Value != -2 || pts[0].Monotonic {
		t.Errorf("point = %+v, want value=-2 monotonic=false", pts[0])
	}
}

// TestEmitterHistogram asserts Histogram (and its HistogramCtx equivalent
// with context.Background()) record into the given explicit bucket bounds.
func TestEmitterHistogram(t *testing.T) {
	rec := telemetrytest.New()
	bounds := []float64{0, 1, 5, 10}
	rec.Emitter().Histogram("graph2otel.collector.duration", "s", "collector run duration", 2.5, bounds, nil)
	rec.Emitter().HistogramCtx(context.Background(), "graph2otel.collector.duration", "s", "collector run duration", 7, bounds, nil)

	pts := rec.MetricPoints("graph2otel.collector.duration")
	if len(pts) != 1 {
		t.Fatalf("got %d points, want 1 (same instrument, same attrs): %+v", len(pts), pts)
	}
	p := pts[0]
	if p.Count != 2 {
		t.Errorf("Count = %d, want 2", p.Count)
	}
	if p.Value != 9.5 {
		t.Errorf("Sum = %v, want 9.5", p.Value)
	}
	if len(p.Bounds) != len(bounds) {
		t.Errorf("Bounds = %v, want %v", p.Bounds, bounds)
	}
}

// TestEmitterLogEvent asserts LogEvent is captured with the expected body,
// severity, event name, and attributes.
func TestEmitterLogEvent(t *testing.T) {
	rec := telemetrytest.New()
	rec.Emitter().LogEvent(telemetry.Event{
		Name:     "entra.signin",
		Body:     "user signed in",
		Severity: telemetry.SeverityWarn,
		Attrs:    telemetry.Attrs{"user.id": "u1"},
	})

	recs := rec.LogRecords()
	if len(recs) != 1 {
		t.Fatalf("got %d log records, want 1: %+v", len(recs), recs)
	}
	r := recs[0]
	if r.Body != "user signed in" || r.EventName != "entra.signin" || r.SeverityText != "WARN" {
		t.Errorf("record = %+v, want body/eventname/severity set", r)
	}
	if r.Attrs["user.id"] != "u1" {
		t.Errorf("attrs = %+v, want user.id=u1", r.Attrs)
	}
}
