package collector_test

import (
	"sort"
	"testing"
	"time"

	"github.com/rknightion/graph2otel/internal/collector"
	"github.com/rknightion/graph2otel/internal/telemetrytest"
)

// TestEmitExpectedIntervalsReportsTheEffectiveIntervalPerCollector is the
// primary #299 contract test: every registered collector (snapshot or window)
// gets exactly one graph2otel.collector.expected_interval series carrying the
// EFFECTIVE interval the scheduler will actually use — the defaulted value
// when the caller supplied zero, never the raw zero override itself.
func TestEmitExpectedIntervalsReportsTheEffectiveIntervalPerCollector(t *testing.T) {
	r := collector.NewRegistry()
	// Explicit override.
	r.Register(fakeCollector{name: "devices", def: time.Hour}, 30*time.Second)
	// Zero override falls back to DefaultInterval — Registry.Register already
	// resolves this at registration time (collector.go), so the reported value
	// must be the resolved 24h default, never 0.
	r.Register(fakeCollector{name: "daily_report", def: 24 * time.Hour}, 0)
	r.RegisterWindow(captureWindow{}, 5*time.Minute, time.Hour, time.Hour)

	rec := telemetrytest.New()
	r.EmitExpectedIntervals(rec.Emitter(), "tenant-a")

	points := rec.MetricPoints(collector.MetricCollectorExpectedInterval)
	if len(points) != 3 {
		t.Fatalf("len(points) = %d, want 3: %+v", len(points), points)
	}

	sort.Slice(points, func(i, j int) bool {
		return points[i].Attrs["collector"] < points[j].Attrs["collector"]
	})

	want := map[string]float64{
		"capture.window": (5 * time.Minute).Seconds(),
		"daily_report":   (24 * time.Hour).Seconds(),
		"devices":        (30 * time.Second).Seconds(),
	}
	for _, p := range points {
		name := p.Attrs["collector"]
		wantValue, ok := want[name]
		if !ok {
			t.Fatalf("unexpected collector %q in points: %+v", name, points)
		}
		if p.Value != wantValue {
			t.Errorf("collector %q value = %v, want %v (the effective interval, in seconds)",
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

// TestEmitExpectedIntervalsOmitsTenantIDWhenTenantIsEmpty matches
// telemetry.WithTenant's documented passthrough for an empty tenant ID, the
// same single-tenant-deploy behavior graph2otel.collector.availability relies
// on (internal/availability.Tracker.Emit).
func TestEmitExpectedIntervalsOmitsTenantIDWhenTenantIsEmpty(t *testing.T) {
	r := collector.NewRegistry()
	r.Register(fakeCollector{name: "devices", def: time.Hour}, 0)

	rec := telemetrytest.New()
	r.EmitExpectedIntervals(rec.Emitter(), "")

	points := rec.MetricPoints(collector.MetricCollectorExpectedInterval)
	if len(points) != 1 {
		t.Fatalf("len(points) = %d, want 1: %+v", len(points), points)
	}
	if _, stamped := points[0].Attrs["tenant_id"]; stamped {
		t.Fatalf("points[0].Attrs = %+v, want no tenant_id for an empty tenant", points[0].Attrs)
	}
}

// TestEmitExpectedIntervalsOnEmptyRegistryClearsTheSnapshot documents the
// deliberately-removed-collector outcome (#299 acceptance criterion 3): an
// empty entry set is GaugeSnapshot's documented way to clear every series for
// this tenant, so a collector no longer registered (removed in code, disabled
// by config) leaves no ghost series behind — never a stale value pretending
// to still be current.
func TestEmitExpectedIntervalsOnEmptyRegistryClearsTheSnapshot(t *testing.T) {
	r := collector.NewRegistry()
	rec := telemetrytest.New()
	r.EmitExpectedIntervals(rec.Emitter(), "tenant-a")

	points := rec.MetricPoints(collector.MetricCollectorExpectedInterval)
	if len(points) != 0 {
		t.Fatalf("len(points) = %d, want 0 for an empty registry: %+v", len(points), points)
	}
}
