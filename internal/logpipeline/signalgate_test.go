package logpipeline

import (
	"context"
	"flag"
	"testing"
	"time"

	"github.com/rknightion/graph2otel/internal/semconv"
	"github.com/rknightion/graph2otel/internal/signalcapture"
	"github.com/rknightion/graph2otel/internal/telemetry"
	"github.com/rknightion/graph2otel/internal/telemetrytest"
)

var updateSignalGolden = flag.Bool("update", false, "rewrite testdata/signals.json")

// TestSignalGolden drives the package-owned self-exclusion signal through the
// real polling path. Removing the exclusion counter, its collector label, or
// the tenant decoration must make this fixture fail.
func TestSignalGolden(t *testing.T) {
	rec := telemetrytest.New()
	from := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	to := from.Add(selfWindow)
	cfg := selfExcludeConfig(true, "POLLER", flatAppID)
	cp := newCheckpoint("fixture-tenant", cfg.Path)
	records := []map[string]any{
		selfRecord("self-1", "POLLER", from.Add(10*time.Minute)),
		selfRecord("self-2", "POLLER", from.Add(20*time.Minute)),
	}
	emitter := telemetry.WithTenant(rec.Emitter(), "fixture-tenant")

	if _, err := Poll(context.Background(), cfg, cp, from, to, onePageFetcher(records), emitter, nil); err != nil {
		t.Fatalf("Poll: %v", err)
	}

	points := rec.MetricPoints(metricSelfExcluded)
	if len(points) != 1 {
		t.Fatalf("%s points = %d, want one series", metricSelfExcluded, len(points))
	}
	if points[0].Value != 2 {
		t.Errorf("%s value = %v, want 2", metricSelfExcluded, points[0].Value)
	}
	if got := points[0].Attrs[semconv.AttrCollector]; got != "entra.signins.service_principal" {
		t.Errorf("collector = %q, want entra.signins.service_principal", got)
	}
	if got := points[0].Attrs[semconv.AttrTenantID]; got != "fixture-tenant" {
		t.Errorf("tenant_id = %q, want fixture-tenant", got)
	}

	if err := signalcapture.GoldenAt("testdata/signals.json", *updateSignalGolden, rec); err != nil {
		t.Fatal(err)
	}
}
