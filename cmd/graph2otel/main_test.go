package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/rknightion/graph2otel/internal/admin"
	"github.com/rknightion/graph2otel/internal/availability"
	"github.com/rknightion/graph2otel/internal/config"
	"github.com/rknightion/graph2otel/internal/recordoutcome"
	"github.com/rknightion/graph2otel/internal/semconv"
	"github.com/rknightion/graph2otel/internal/telemetry"
	"github.com/rknightion/graph2otel/internal/telemetrytest"
	buildversion "github.com/rknightion/graph2otel/internal/version"
)

const validStdoutYAML = `
otlp:
  protocol: stdout
`

const invalidYAML = `
otlp:
  protocol: not-a-real-protocol
`

func TestReportAvailabilityEmitsPeriodicAndStopsWithTenantContext(t *testing.T) {
	rec := telemetrytest.New()
	emitter := &availabilityCountingEmitter{
		Emitter: rec.Emitter(),
		calls:   make(chan struct{}, 2),
	}
	tracker := availability.NewTracker("tenant-a", []availability.Static{{
		Collector: "entra.domains",
		Transport: telemetry.TransportGraph,
		State:     availability.StateStarting,
		Reason:    availability.ReasonNoCompletedRun,
	}})
	ctx, cancel := context.WithCancel(context.Background())
	ticks := make(chan time.Time)
	done := make(chan struct{})
	go func() {
		reportAvailability(ctx, tracker, emitter, ticks)
		close(done)
	}()

	ticks <- time.Now()
	<-emitter.calls
	assertAvailabilityMetricReason(t, rec, availability.ReasonNoCompletedRun)
	tracker.Record("entra.domains", recordoutcome.Summary{
		Result: recordoutcome.ResultSuccess,
	})
	ticks <- time.Now()
	<-emitter.calls
	assertAvailabilityMetricReason(t, rec, availability.ReasonSuccess)

	cancel()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("availability reporter did not stop with tenant context")
	}
}

func TestReportAvailabilityCanceledBeforeFirstTickEmitsNothing(t *testing.T) {
	rec := telemetrytest.New()
	tracker := availability.NewTracker("tenant-a", []availability.Static{{
		Collector: "entra.domains",
		Transport: telemetry.TransportGraph,
		State:     availability.StateStarting,
		Reason:    availability.ReasonNoCompletedRun,
	}})
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	reportAvailability(ctx, tracker, rec.Emitter(), nil)

	if got := rec.MetricPoints(availability.MetricCollectorAvailability); len(got) != 0 {
		t.Fatalf("periodic reporter emitted %d points before its first tick, want zero", len(got))
	}
}

func TestStartTenantWorkersEmitsInitialAvailabilityExactlyOnceBeforeScheduler(t *testing.T) {
	rec := telemetrytest.New()
	emitter := &availabilityCountingEmitter{
		Emitter: rec.Emitter(),
		calls:   make(chan struct{}, 2),
	}
	tracker := availability.NewTracker("tenant-a", []availability.Static{{
		Collector: "entra.domains",
		Transport: telemetry.TransportGraph,
		State:     availability.StateStarting,
		Reason:    availability.ReasonNoCompletedRun,
	}})
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	var wg sync.WaitGroup
	schedulerRan := false

	startTenantWorkers(
		ctx,
		tracker,
		emitter,
		&wg,
		func(context.Context, *availability.Tracker, telemetry.Emitter) {},
		func() {
			schedulerRan = true
			if got := len(emitter.calls); got != 1 {
				t.Errorf("initial availability emissions before scheduler = %d, want exactly 1", got)
			}
		},
	)
	wg.Wait()

	if !schedulerRan {
		t.Fatal("scheduler did not run")
	}
	if got := len(emitter.calls); got != 1 {
		t.Fatalf("total initial availability emissions = %d, want exactly 1", got)
	}
}

type availabilityCountingEmitter struct {
	telemetry.Emitter
	calls chan struct{}
}

func (e *availabilityCountingEmitter) GaugeSnapshot(
	name, unit, desc string,
	points []telemetry.GaugePoint,
) {
	e.Emitter.GaugeSnapshot(name, unit, desc, points)
	e.calls <- struct{}{}
}

func assertAvailabilityMetricReason(
	t *testing.T,
	rec *telemetrytest.Recorder,
	want availability.Reason,
) {
	t.Helper()
	points := rec.MetricPoints(availability.MetricCollectorAvailability)
	if got, wantCount := len(points), 1; got != wantCount {
		t.Fatalf("availability metric points = %d, want %d", got, wantCount)
	}
	if got := points[0].Attrs[semconv.AttrReason]; got != string(want) {
		t.Fatalf("availability reason = %q, want %q", got, want)
	}
	if got := points[0].Attrs[semconv.AttrTenantID]; got != "tenant-a" {
		t.Fatalf("availability tenant_id = %q, want tenant-a", got)
	}
}

// adminEnabledStdoutYAML boots the telemetry provider (stdout) and the admin
// server on an ephemeral port, exercising the M1 composition-root wiring.
const adminEnabledStdoutYAML = `
otlp:
  protocol: stdout
admin:
  enabled: true
  addr: "127.0.0.1:0"
`

func writeTempConfig(t *testing.T, content string) string {
	t.Helper()
	dir := t.TempDir()
	p := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
		t.Fatalf("write temp config: %v", err)
	}
	return p
}

func TestRun_VersionUsesCanonicalBuildVersion(t *testing.T) {
	oldVersion := buildversion.Version
	buildversion.Version = "1.2.3-test"
	t.Cleanup(func() { buildversion.Version = oldVersion })

	var stdout, stderr bytes.Buffer
	code := run(context.Background(), []string{"-version"}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("exit code = %d, want 0; stderr=%s", code, stderr.String())
	}
	if got, want := strings.TrimSpace(stdout.String()), buildversion.String(); got != want {
		t.Errorf("stdout = %q, want %q", got, want)
	}
}

func TestCanonicalBuildVersionReachesProviderResourceAndAdmin(t *testing.T) {
	const wantVersion = "1.2.3-test"
	oldVersion := buildversion.Version
	buildversion.Version = wantVersion
	t.Cleanup(func() { buildversion.Version = oldVersion })

	cfg, err := config.Load(writeTempConfig(t, validStdoutYAML))
	if err != nil {
		t.Fatalf("load config: %v", err)
	}

	var telemetryOutput bytes.Buffer
	provider, err := newTelemetryProvider(context.Background(), cfg, &telemetryOutput)
	if err != nil {
		t.Fatalf("new telemetry provider: %v", err)
	}
	provider.Emitter().LogEvent(telemetry.Event{Name: "test.version", Body: "version resource probe"})
	if err := provider.Shutdown(context.Background()); err != nil {
		t.Fatalf("shutdown telemetry provider: %v", err)
	}
	if got := telemetryOutput.String(); !strings.Contains(got, "service.version") || !strings.Contains(got, wantVersion) {
		t.Fatalf("provider log resource does not carry canonical version %q; got:\n%s", wantVersion, got)
	}

	adminServer := admin.New(config.AdminConfig{Enabled: true}, nil, nil, nil, cfg, nil, provider)
	req := httptest.NewRequest(http.MethodGet, "/api/status.json", nil)
	w := httptest.NewRecorder()
	adminServer.Handler().ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("GET /api/status.json status = %d, want %d", w.Code, http.StatusOK)
	}
	var status admin.Status
	if err := json.Unmarshal(w.Body.Bytes(), &status); err != nil {
		t.Fatalf("unmarshal admin status: %v", err)
	}
	if got := status.Service.Version; got != wantVersion {
		t.Errorf("admin version = %q, want canonical version %q", got, wantVersion)
	}
}

func TestRun_UnknownFlag(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := run(context.Background(), []string{"-bogus"}, &stdout, &stderr)
	if code != 2 {
		t.Fatalf("exit code = %d, want 2", code)
	}
}

func TestRun_InvalidConfig(t *testing.T) {
	path := writeTempConfig(t, invalidYAML)
	var stdout, stderr bytes.Buffer
	code := run(context.Background(), []string{"-config", path}, &stdout, &stderr)
	if code != 1 {
		t.Fatalf("exit code = %d, want 1; stderr=%s", code, stderr.String())
	}
	if stderr.String() == "" {
		t.Errorf("stderr should contain the validation error")
	}
}

func TestRun_MissingFile(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := run(context.Background(), []string{"-config", filepath.Join(t.TempDir(), "missing.yaml")}, &stdout, &stderr)
	if code != 1 {
		t.Fatalf("exit code = %d, want 1", code)
	}
	if stderr.String() == "" {
		t.Errorf("stderr should contain the load error")
	}
}

// TestRun_StartsAndShutsDownCleanly exercises the normal path: a valid config
// (stdout mode needs no tenants) starts the process, and canceling ctx makes
// it return cleanly instead of hanging.
func TestRun_StartsAndShutsDownCleanly(t *testing.T) {
	path := writeTempConfig(t, validStdoutYAML)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	cancel() // shut down immediately; we're only testing the clean-exit path

	var stdout, stderr bytes.Buffer
	code := run(ctx, []string{"-config", path}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("exit code = %d, want 0; stderr=%s", code, stderr.String())
	}
	if !strings.Contains(stderr.String(), "starting") {
		t.Errorf("stderr = %q, want a startup log line", stderr.String())
	}
	if !strings.Contains(stderr.String(), "stopped") {
		t.Errorf("stderr = %q, want a shutdown log line", stderr.String())
	}
}

// TestRun_AdminEnabledBootsAndShutsDown exercises the M1 composition root with
// the admin server enabled: the telemetry provider and admin HTTP server start,
// and canceling ctx returns cleanly (the admin server self-shuts-down).
func TestRun_AdminEnabledBootsAndShutsDown(t *testing.T) {
	path := writeTempConfig(t, adminEnabledStdoutYAML)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	var stdout, stderr bytes.Buffer
	// Cancel shortly after boot so the server has bound before shutdown.
	go func() {
		time.Sleep(100 * time.Millisecond)
		cancel()
	}()

	code := run(ctx, []string{"-config", path}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("exit code = %d, want 0; stderr=%s", code, stderr.String())
	}
	if !strings.Contains(stderr.String(), "stopped") {
		t.Errorf("stderr = %q, want a shutdown log line", stderr.String())
	}
}

func TestRun_AdminBindFailureIsFatalWithoutWaitingForShutdown(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("occupy admin address: %v", err)
	}
	t.Cleanup(func() { _ = listener.Close() })

	path := writeTempConfig(t, "otlp:\n  protocol: stdout\nadmin:\n  enabled: true\n  addr: \""+listener.Addr().String()+"\"\n")
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	var stdout, stderr bytes.Buffer
	started := time.Now()
	code := run(ctx, []string{"-config", path}, &stdout, &stderr)
	elapsed := time.Since(started)

	if code != 1 {
		t.Fatalf("exit code = %d, want 1 for enabled admin bind failure; stderr=%s", code, stderr.String())
	}
	if elapsed >= 2*time.Second {
		t.Fatalf("run returned after %s, want prompt fatal exit before context timeout", elapsed)
	}
	if !strings.Contains(stderr.String(), "admin server") {
		t.Errorf("stderr = %q, want admin server failure log", stderr.String())
	}
}

func TestSuperviseAdminCanceledCleanResultCancelsAndDrainsSchedulers(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	tenantCtx, cancelTenants := context.WithCancel(context.Background())
	waitStarted := make(chan struct{})
	releaseWait := make(chan struct{})
	result := make(chan error, 1)

	go func() {
		result <- superviseAdmin(
			ctx,
			func(context.Context) error { return nil },
			cancelTenants,
			func() {
				// Waiting is only valid after the scheduler context has been
				// canceled; blocking here also proves supervision cannot return
				// until the scheduler drain completes.
				<-tenantCtx.Done()
				close(waitStarted)
				<-releaseWait
			},
		)
	}()

	select {
	case <-waitStarted:
	case <-time.After(time.Second):
		t.Fatal("superviseAdmin did not cancel tenants and enter the scheduler drain")
	}
	select {
	case err := <-result:
		t.Fatalf("superviseAdmin returned before scheduler drain completed: %v", err)
	default:
	}

	close(releaseWait)
	select {
	case err := <-result:
		if err != nil {
			t.Fatalf("superviseAdmin() error = %v, want clean external cancellation", err)
		}
	case <-time.After(time.Second):
		t.Fatal("superviseAdmin did not return after scheduler drain completed")
	}
}

// TestOtelErrorHandlerLogsThroughTheAppLogger asserts SDK errors reach
// graph2otel's own structured logger at ERROR rather than Go's default log
// package. This channel carries OTLP export rejections — the backend refuses a
// log record older than its 7-day accept window with a 400 naming the limit
// (#226) — so it has to be visible to whatever an operator filters on, and a
// dropped record has to read as an error rather than a note.
func TestOtelErrorHandlerLogsThroughTheAppLogger(t *testing.T) {
	var buf bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelInfo}))

	otelErrorHandler(logger).Handle(errors.New("has timestamp too old: 2026-07-08T13:05:10Z"))

	out := buf.String()
	if !strings.Contains(out, "level=ERROR") {
		t.Errorf("output %q, want it logged at ERROR — a rejected record is data loss", out)
	}
	if !strings.Contains(out, "has timestamp too old") {
		t.Errorf("output %q, want the underlying error text preserved", out)
	}
}
