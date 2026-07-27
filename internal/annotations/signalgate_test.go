package annotations

import (
	"flag"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	"github.com/rknightion/graph2otel/internal/signalcapture"
	"github.com/rknightion/graph2otel/internal/telemetry"
	"github.com/rknightion/graph2otel/internal/telemetrytest"
)

var updateSignalGolden = flag.Bool("update", false, "rewrite testdata/signals.json")

// TestSignalGolden captures this package's self-observability surface (#140/#288)
// so spec/signal-catalog.json can see it with no human step.
//
// It drives the PRODUCTION paths rather than calling the recorders directly: a
// real accepted write for the published counter, a real 403 for the failure drop
// reason, a queue-full drop, and the degraded gauge in both states — so the
// golden records the attribute keys an operator actually gets, not the ones this
// test hopes for.
func TestSignalGolden(t *testing.T) {
	rec := telemetrytest.New()

	accepted := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer accepted.Close()

	cfg := testConfig()
	cfg.URL = accepted.URL
	cfg.QueueSize = 1
	a, err := Start(t.Context(), Options{
		Config:            cfg,
		Emitter:           rec.Emitter(),
		CheckpointDir:     t.TempDir(),
		Version:           "0.0.0-signalgate",
		ConfigFingerprint: "0123456789abcdef",
		TenantIDs:         []string{testTenant},
		StartedAt:         fixedNow,
		Now:               func() time.Time { return fixedNow },
	})
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer func() { _ = a.Close(t.Context()) }()

	// Every drop reason, through the production recorder.
	for _, reason := range DropReasons() {
		a.recordDropped(testTenant, reason)
	}
	// Every publish failure code, which shares the dropped counter's reason label
	// so an operator reads suppression and failure from one metric.
	for _, code := range FailureCodes() {
		a.recordDropped(testTenant, DropReason(code))
	}
	// Both degraded states.
	a.degraded.Store(true)
	a.reportDegraded()
	a.degraded.Store(false)
	a.reportDegraded()

	// A published annotation in every category, so the golden carries the label.
	for _, category := range Categories() {
		a.recordPublished(Annotation{Category: category, TenantID: testTenant})
	}

	captured := signalcapture.Union([]*telemetrytest.Recorder{rec})
	if len(captured.Logs) != 0 {
		t.Errorf("this package emits no log records; captured %d", len(captured.Logs))
	}
	if v := signalcapture.PerEntityViolations(captured); len(v) > 0 {
		t.Errorf("#112 per-entity metric labels: %v", v)
	}
	if r := signalcapture.ThinReasons(captured); len(r) > 0 {
		t.Errorf("thin signal capture (#164): %v", r)
	}
	for _, name := range []string{metricPublished, metricDropped, metricDegraded} {
		if len(rec.MetricPoints(name)) == 0 {
			t.Errorf("signal capture is missing %s", name)
		}
	}

	if err := signalcapture.GoldenAt(
		filepath.Join("testdata", "signals.json"), *updateSignalGolden, rec,
	); err != nil {
		t.Fatal(err)
	}
}

// TestDegradedIsProcessScoped documents why graph2otel.annotation.degraded
// carries no tenant_id: there is ONE Grafana endpoint and one token for the
// process, so a per-tenant series would claim a tenant-specific fault where none
// exists. It is the same scope as graph2otel.otlp.delivery.degraded.
func TestDegradedIsProcessScoped(t *testing.T) {
	rec := telemetrytest.New()
	a := &Annotator{emitter: rec.Emitter()}
	a.reportDegraded()
	points := rec.MetricPoints(metricDegraded)
	if len(points) != 1 {
		t.Fatalf("degraded points = %d, want 1", len(points))
	}
	if _, stamped := points[0].Attrs["tenant_id"]; stamped {
		t.Errorf("degraded carries tenant_id (%v); one Grafana endpoint serves every tenant", points[0].Attrs)
	}
}

// TestDroppedAndPublishedAreTenantScoped is the mirror: those counts ARE
// per-tenant facts, and #143 puts tenant_id on every signal that has one.
func TestDroppedAndPublishedAreTenantScoped(t *testing.T) {
	rec := telemetrytest.New()
	a := &Annotator{emitter: rec.Emitter()}
	a.recordPublished(Annotation{Category: CategoryConfigPosture, TenantID: testTenant})
	a.recordDropped(testTenant, DropDuplicate)
	for _, name := range []string{metricPublished, metricDropped} {
		points := rec.MetricPoints(name)
		if len(points) != 1 {
			t.Fatalf("%s points = %d, want 1", name, len(points))
		}
		if points[0].Attrs["tenant_id"] != testTenant {
			t.Errorf("%s attrs = %v, want tenant_id=%s", name, points[0].Attrs, testTenant)
		}
	}
}

// TestSelfObservabilityMetricsAreNotOfferedBackToTheRuleSet guards the wiring
// contract on Options.Emitter: publishing through a teed emitter would offer
// every self-obs counter back to the recorder on every publish.
func TestSelfObservabilityMetricsAreNotOfferedBackToTheRuleSet(t *testing.T) {
	base := newCallRecorder()
	recorder, sink := newTestRecorder(t, testConfig(), t.TempDir())
	a := &Annotator{emitter: base, recorder: recorder}
	a.recordPublished(Annotation{Category: CategoryLicense, TenantID: testTenant})
	a.reportDegraded()
	if got := sink.all(); len(got) != 0 {
		t.Fatalf("self-observability emission produced annotations: %+v", got)
	}
	// And the base emitter is a plain emitter, not a tee.
	if _, isTee := telemetry.Emitter(base).(*teeEmitter); isTee {
		t.Fatal("the test's base emitter is itself a tee")
	}
}
