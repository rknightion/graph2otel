package main

import (
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/rknightion/graph2otel/internal/config"
	"github.com/rknightion/graph2otel/internal/startupevent"
)

// resetAnnotator restores the composition-root singleton after a test mutates
// it. The var is written exactly once in production (before any tenant exists),
// so a test must put it back rather than leave it set for the next one.
func resetAnnotator(t *testing.T) {
	t.Helper()
	previous := annotator
	t.Cleanup(func() { annotator = previous })
}

func annotationTestConfig(url string) *config.Config {
	cfg := config.Default()
	cfg.OTLP.Protocol = "stdout"
	cfg.GrafanaAnnotations.URL = url
	cfg.GrafanaAnnotations.Token = config.Secret("test-token")
	return cfg
}

// TestStartAnnotatorIsANoOpWhenUnconfigured is the default deployment: no
// client, no goroutine, no log line, and no annotator.
func TestStartAnnotatorIsANoOpWhenUnconfigured(t *testing.T) {
	resetAnnotator(t)
	annotator = nil
	cfg := config.Default()
	cfg.OTLP.Protocol = "stdout"
	if err := startAnnotator(t.Context(), cfg, nil, slog.New(slog.DiscardHandler)); err != nil {
		t.Fatalf("startAnnotator on an unconfigured block: %v", err)
	}
	if annotator != nil {
		t.Fatal("an annotator was built with no url configured")
	}
}

// TestStartAnnotatorIsFatalWhenTheTokenCannotWrite pins the maintainer's #400
// decision at the composition root, not just inside the package.
func TestStartAnnotatorIsFatalWhenTheTokenCannotWrite(t *testing.T) {
	resetAnnotator(t)
	annotator = nil
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte(`{"message":"Permissions needed: annotations:create"}`))
	}))
	defer srv.Close()

	cfg := annotationTestConfig(srv.URL)
	cfg.CheckpointDir = t.TempDir()
	err := startAnnotator(t.Context(), cfg, nil, slog.New(slog.DiscardHandler))
	if err == nil {
		t.Fatal("startAnnotator accepted a token that cannot write an annotation")
	}
	if !strings.Contains(err.Error(), "annotations:create") {
		t.Errorf("error does not name the required permission:\n%v", err)
	}
	if annotator != nil {
		t.Error("a failed writer was still installed as the singleton")
	}
}

// TestStartAnnotatorCarriesTheSharedConfigFingerprint proves the startup
// annotation reuses #310's contract rather than a second definition: an operator
// comparing the Loki startup marker with the Grafana annotation must see ONE
// fingerprint for one configuration.
func TestStartAnnotatorCarriesTheSharedConfigFingerprint(t *testing.T) {
	resetAnnotator(t)
	annotator = nil
	var body string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		body = string(raw)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	cfg := annotationTestConfig(srv.URL)
	cfg.CheckpointDir = t.TempDir()
	if err := startAnnotator(t.Context(), cfg, nil, slog.New(slog.DiscardHandler)); err != nil {
		t.Fatalf("startAnnotator: %v", err)
	}
	t.Cleanup(func() { _ = annotator.Close(t.Context()) })

	want, err := startupevent.Fingerprint(cfg)
	if err != nil {
		t.Fatalf("fingerprint: %v", err)
	}
	if !strings.Contains(body, want) {
		t.Errorf("startup annotation %q does not carry the shared fingerprint %q", body, want)
	}
	if strings.Contains(body, "test-token") {
		t.Errorf("the startup annotation leaked the Grafana token:\n%s", body)
	}
}

// TestSchedulerEmitterFactoryIsTeedThroughTheAnnotationRuleSet is the wiring
// gate. The rule set can only see a record if the scheduler's per-run emitter is
// the teed one; wiring provider.CollectorEmitter directly compiles, passes every
// annotations-package test, and publishes nothing — the exact shape of the
// #139/#100 incident CLAUDE.md records.
func TestSchedulerEmitterFactoryIsTeedThroughTheAnnotationRuleSet(t *testing.T) {
	raw, err := os.ReadFile("tenants.go")
	if err != nil {
		t.Fatalf("read tenants.go: %v", err)
	}
	source := string(raw)
	if !strings.Contains(source, "collector.WithEmitterFactory(annotatedCollectorEmitter(provider))") {
		t.Error("the scheduler's emitter factory is not teed through the annotation rule set; " +
			"annotations would be silently absent while every annotations-package test stays green")
	}
	if strings.Contains(source, "collector.WithEmitterFactory(provider.CollectorEmitter)") {
		t.Error("tenants.go still wires provider.CollectorEmitter directly, bypassing the annotation tee")
	}
}

// TestAnnotationWriterStartsAfterTheCheckpointProbeAndBeforeTenants pins the
// ordering the wiring depends on. Both directions matter: the dedupe set lives in
// the checkpoint directory, and a collector that starts first emits records the
// rule set never sees.
func TestAnnotationWriterStartsAfterTheCheckpointProbeAndBeforeTenants(t *testing.T) {
	raw, err := os.ReadFile("main.go")
	if err != nil {
		t.Fatalf("read main.go: %v", err)
	}
	source := string(raw)
	probe := strings.Index(source, "checkpoint.NewStore(cfg.CheckpointDir).Verify()")
	start := strings.Index(source, "startAnnotator(ctx, cfg, provider, logger)")
	tenants := strings.Index(source, "startTenants(tenantCtx, cfg, provider, logger)")
	if probe < 0 || start < 0 || tenants < 0 {
		t.Fatalf("could not locate the three call sites (probe=%d start=%d tenants=%d)", probe, start, tenants)
	}
	if probe >= start || start >= tenants {
		t.Errorf("startAnnotator must run after the checkpoint probe and before startTenants "+
			"(probe=%d start=%d tenants=%d)", probe, start, tenants)
	}
}
