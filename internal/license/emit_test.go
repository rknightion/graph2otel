package license

import (
	"testing"

	"github.com/rknightion/graph2otel/internal/telemetrytest"
)

// TestEmitLicenseTier asserts graph2otel.tenant.license_tier is emitted once
// per detected capability, each tagged {tenant_id, tier}.
func TestEmitLicenseTier(t *testing.T) {
	rec := telemetrytest.New()
	caps := Capabilities{CapEntraP1: true, CapIntune: true}

	EmitLicenseTier(rec.Emitter(), "tenant-a", caps)

	points := rec.MetricPoints(MetricLicenseTier)
	if len(points) != 2 {
		t.Fatalf("MetricPoints(%s) has %d points, want 2: %+v", MetricLicenseTier, len(points), points)
	}

	seen := map[string]bool{}
	for _, p := range points {
		if p.Value != 1 {
			t.Errorf("point value = %v, want 1", p.Value)
		}
		if p.Attrs["tenant_id"] != "tenant-a" {
			t.Errorf("tenant_id attr = %q, want tenant-a", p.Attrs["tenant_id"])
		}
		seen[p.Attrs["tier"]] = true
	}
	if !seen[string(CapEntraP1)] || !seen[string(CapIntune)] {
		t.Errorf("expected tier attrs %q and %q, got %v", CapEntraP1, CapIntune, seen)
	}
}

// TestEmitLicenseTierFreeTenantEmitsNothing: an empty capability set (Free
// tier) must not emit any license_tier series.
func TestEmitLicenseTierFreeTenantEmitsNothing(t *testing.T) {
	rec := telemetrytest.New()

	EmitLicenseTier(rec.Emitter(), "tenant-b", Capabilities{})

	if points := rec.MetricPoints(MetricLicenseTier); len(points) != 0 {
		t.Errorf("MetricPoints(%s) = %+v, want none for a Free tenant", MetricLicenseTier, points)
	}
}
