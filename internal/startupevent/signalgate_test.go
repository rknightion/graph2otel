package startupevent_test

import (
	"flag"
	"testing"
	"time"

	"github.com/rknightion/graph2otel/internal/config"
	"github.com/rknightion/graph2otel/internal/signalcapture"
	"github.com/rknightion/graph2otel/internal/startupevent"
	"github.com/rknightion/graph2otel/internal/telemetrytest"
)

var updateSignalGolden = flag.Bool("update", false, "rewrite testdata/signals.json")

// TestSignalGolden is the #140 drift gate and the thing that puts
// graph2otel.startup into spec/signal-catalog.json with no human step, so the
// dashboard coverage gate and #306's typed filter contract can see it.
//
// It uses GoldenAt with DEDICATED recorders rather than signalcapture.Main's
// union of every recorder in the package, for the reason GoldenAt exists: this
// package's tests also drive collector.EmitBuildInfo, to cross-check that the
// startup marker and graph2otel.build_info report one version from one source.
// Under the union that probe would enter the golden and the catalog would name
// internal/startupevent as an emitter of build_info, which it is not.
//
// Both production shapes are captured — the tenant-stamped multi-tenant path and
// the unstamped no-tenant (stdout) path — so the golden records tenant_id, the
// attribute an annotation query filters on.
func TestSignalGolden(t *testing.T) {
	startedAt := time.Date(2026, 7, 27, 9, 15, 30, 0, time.UTC)

	tenanted := telemetrytest.New()
	tenantCfg := config.Default()
	tenantCfg.Tenants = []config.TenantConfig{
		{TenantID: "11111111-1111-1111-1111-111111111111"},
		{TenantID: "22222222-2222-2222-2222-222222222222"},
	}
	if err := startupevent.Emit(tenanted.Emitter(), tenantCfg, startedAt); err != nil {
		t.Fatalf("Emit (tenanted): %v", err)
	}

	untenanted := telemetrytest.New()
	if err := startupevent.Emit(untenanted.Emitter(), config.Default(), startedAt); err != nil {
		t.Fatalf("Emit (no tenant): %v", err)
	}

	captured := signalcapture.Union([]*telemetrytest.Recorder{tenanted, untenanted})
	if len(captured.Logs) != 1 || len(captured.Metrics) != 0 {
		t.Fatalf("captured %d logs and %d metrics, want exactly 1 log and no metric "+
			"(#310 is a log event, not a second build_info metric)",
			len(captured.Logs), len(captured.Metrics))
	}
	if v := signalcapture.PerEntityViolations(captured); len(v) > 0 {
		t.Errorf("#112 per-entity metric labels: %v", v)
	}
	if r := signalcapture.ThinReasons(captured); len(r) > 0 {
		t.Errorf("thin signal capture (#164): %v", r)
	}

	if err := signalcapture.GoldenAt(
		"testdata/signals.json", *updateSignalGolden, tenanted, untenanted,
	); err != nil {
		t.Fatal(err)
	}
}
