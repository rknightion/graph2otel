package admin

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/rknightion/graph2otel/internal/config"
	"github.com/rknightion/graph2otel/internal/telemetry"
	"github.com/rknightion/graph2otel/internal/telemetrytest"
)

// The literal secret values below must NEVER appear in any rendered output. They
// are deliberately distinctive so a leak is unambiguous.
const (
	secretToken = "SUPER-SECRET-GRAFANA-TOKEN-DO-NOT-LEAK-9f3a"
	secretPass  = "SUPER-SECRET-PYROSCOPE-PASSWORD-DO-NOT-LEAK-42b1"
)

// cfgWithSecrets builds a full config carrying known secrets plus a spread of
// non-secret fields, for the config-tab tests.
func cfgWithSecrets() *config.Config {
	return &config.Config{
		LogLevel:      "debug",
		CheckpointDir: "/var/lib/g2o/ckpt",
		OTLP: config.OTLPConfig{
			Protocol: "grpc",
			Endpoint: "https://otlp.example.net/otlp",
			GrafanaCloud: config.GrafanaCloudConfig{
				InstanceID: "instance-12345",
				Token:      config.Secret(secretToken),
			},
		},
		Profiling: config.ProfilingConfig{
			Pyroscope: config.ProfilingPyroscope{
				Enabled:           true,
				ServerAddress:     "https://pyro.example.net",
				BasicAuthUser:     "grafana-user",
				BasicAuthPassword: config.Secret(secretPass),
			},
			MutexProfileFraction: 5,
			BlockProfileRate:     100000,
		},
		Cardinality: config.CardinalityConfig{MetricLimit: 2000},
		Tenants: []config.TenantConfig{
			{TenantID: "tenant-a", ClientID: "client-1"},
		},
		Admin: config.AdminConfig{Enabled: true, Addr: ":0", RefreshInterval: 5 * time.Second},
	}
}

func serve(t *testing.T, s *Server, path string) (*httptest.ResponseRecorder, string) {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, path, nil)
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, req)
	return w, w.Body.String()
}

// TestConfigTab_SecretsPresenceOnly is the guard (#211): a known secret value
// must NEVER appear in the rendered HTML page or in /api/config.json — only its
// presence ("set"). Non-secret config fields must render.
func TestConfigTab_SecretsPresenceOnly(t *testing.T) {
	cfg := cfgWithSecrets()
	s := New(cfg.Admin, nil, nil, nil, cfg, nil)
	if s == nil {
		t.Fatal("New returned nil for an enabled config")
	}

	// The HTML page must not leak either secret, must expose presence, and must
	// render the non-secret fields.
	_, html := serve(t, s, "/")
	for _, secret := range []string{secretToken, secretPass} {
		if strings.Contains(html, secret) {
			t.Fatalf("HTML page leaked a secret value %q", secret)
		}
	}
	// Presence-only markers + non-secret fields present on the Config tab.
	for _, want := range []string{
		`data-tab="config"`, "presence-only",
		">set<",             // both secrets render a "set" badge
		"debug",             // log level
		"instance-12345",    // grafana instance id (non-secret)
		"grafana-user",      // pyroscope basic-auth USER (non-secret)
		"otlp.example.net",  // endpoint
		"/var/lib/g2o/ckpt", // checkpoint dir
	} {
		if !strings.Contains(html, want) {
			t.Errorf("Config tab HTML missing %q", want)
		}
	}

	// /api/config.json must not leak either secret and must expose presence bits.
	w, body := serve(t, s, "/api/config.json")
	if w.Code != http.StatusOK {
		t.Fatalf("GET /api/config.json = %d, want 200", w.Code)
	}
	if ct := w.Header().Get("Content-Type"); ct != "application/json" {
		t.Errorf("Content-Type = %q, want application/json", ct)
	}
	for _, secret := range []string{secretToken, secretPass} {
		if strings.Contains(body, secret) {
			t.Fatalf("/api/config.json leaked a secret value %q", secret)
		}
	}
	// It must also never even emit the redaction placeholder — the view carries
	// no config.Secret at all, only presence bits.
	if strings.Contains(body, "REDACTED") {
		t.Errorf("/api/config.json contains REDACTED; the view should carry only presence bools")
	}

	var got ConfigView
	if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil {
		t.Fatalf("unmarshal config.json: %v", err)
	}
	if !got.OTLP.GrafanaTokenSet {
		t.Errorf("GrafanaTokenSet = false, want true (token is set)")
	}
	if !got.Profiling.PyroscopeBasicAuthPasswordSet {
		t.Errorf("PyroscopeBasicAuthPasswordSet = false, want true (password is set)")
	}
	if got.LogLevel != "debug" || got.OTLP.Protocol != "grpc" || got.OTLP.Endpoint != "https://otlp.example.net/otlp" {
		t.Errorf("non-secret fields wrong: %+v", got)
	}
	if got.CheckpointDir != "/var/lib/g2o/ckpt" || got.TenantCount != 1 {
		t.Errorf("checkpoint/tenants wrong: dir=%q tenants=%d", got.CheckpointDir, got.TenantCount)
	}
	if got.Cardinality.MetricLimit != 2000 {
		t.Errorf("MetricLimit = %d, want 2000", got.Cardinality.MetricLimit)
	}
}

// An UNSET secret must read "unset"/false, never leak, and never crash.
func TestConfigTab_UnsetSecretReadsUnset(t *testing.T) {
	cfg := &config.Config{
		LogLevel: "info",
		OTLP:     config.OTLPConfig{Protocol: "http", Endpoint: "https://x"},
		Admin:    config.AdminConfig{Enabled: true, Addr: ":0"},
	}
	s := New(cfg.Admin, nil, nil, nil, cfg, nil)
	w, body := serve(t, s, "/api/config.json")
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", w.Code)
	}
	var got ConfigView
	if err := json.Unmarshal([]byte(body), &got); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if got.OTLP.GrafanaTokenSet {
		t.Errorf("GrafanaTokenSet = true, want false (unset)")
	}
	if got.Profiling.PyroscopeBasicAuthPasswordSet {
		t.Errorf("PyroscopeBasicAuthPasswordSet = true, want false (unset)")
	}
}

// TestCardinalityTab_RendersFromTracker (#215): the tab and /api/cardinality.json
// render total active series, per-metric counts and the configured metric_limit,
// read from the existing CardinalityTracker's snapshot.
func TestCardinalityTab_RendersFromTracker(t *testing.T) {
	tr := telemetry.NewCardinalityTrackerWithCap(2000)
	tr.Observe("graph2otel.users.total", telemetry.Attrs{"tenant": "a"})
	tr.Observe("graph2otel.users.total", telemetry.Attrs{"tenant": "b"})
	tr.Observe("graph2otel.devices.total", telemetry.Attrs{"tenant": "a"})
	tr.Report(telemetrytest.New().Emitter()) // snapshots the interval

	cfg := cfgWithSecrets() // MetricLimit 2000
	s := New(cfg.Admin, nil, nil, nil, cfg, tr)

	w, body := serve(t, s, "/api/cardinality.json")
	if w.Code != http.StatusOK {
		t.Fatalf("GET /api/cardinality.json = %d, want 200", w.Code)
	}
	var got CardinalityView
	if err := json.Unmarshal([]byte(body), &got); err != nil {
		t.Fatalf("unmarshal cardinality.json: %v", err)
	}
	if got.TotalActiveSeries != 3 {
		t.Errorf("TotalActiveSeries = %d, want 3", got.TotalActiveSeries)
	}
	if got.MetricCount != 2 {
		t.Errorf("MetricCount = %d, want 2", got.MetricCount)
	}
	if got.MetricLimit != 2000 {
		t.Errorf("MetricLimit = %d, want 2000 (from cardinality.metric_limit)", got.MetricLimit)
	}
	byName := map[string]int{}
	for _, m := range got.Metrics {
		byName[m.Metric] = m.Count
	}
	if byName["graph2otel.users.total"] != 2 || byName["graph2otel.devices.total"] != 1 {
		t.Errorf("per-metric counts = %+v, want users=2 devices=1", byName)
	}

	// The HTML cardinality tab renders the metric names and the total.
	_, html := serve(t, s, "/")
	for _, want := range []string{
		`data-tab="cardinality"`, "graph2otel.users.total", "graph2otel.devices.total", "active series",
	} {
		if !strings.Contains(html, want) {
			t.Errorf("Cardinality tab HTML missing %q", want)
		}
	}
}

// A nil tracker (self-obs off) yields an empty, non-crashing cardinality view.
func TestCardinalityTab_NilTrackerEmpty(t *testing.T) {
	cfg := cfgWithSecrets()
	s := New(cfg.Admin, nil, nil, nil, cfg, nil)
	w, body := serve(t, s, "/api/cardinality.json")
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", w.Code)
	}
	var got CardinalityView
	if err := json.Unmarshal([]byte(body), &got); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if got.TotalActiveSeries != 0 || got.MetricCount != 0 {
		t.Errorf("empty tracker view = %+v, want zero counts", got)
	}
	if got.MetricLimit != 2000 {
		t.Errorf("MetricLimit = %d, want 2000 (still from config)", got.MetricLimit)
	}
}

// TestConfigAndCardinality_NoLiveTenantCall is the guard (b): the config and
// cardinality handlers derive their data ENTIRELY from passive injected state,
// never a live tenant call. The server is built with NO collector sources and NO
// limiter — nothing that could reach a tenant — yet both endpoints still return
// fully populated data sourced from the injected config + tracker alone.
func TestConfigAndCardinality_NoLiveTenantCall(t *testing.T) {
	tr := telemetry.NewCardinalityTrackerWithCap(2000)
	tr.Observe("graph2otel.users.total", telemetry.Attrs{"tenant": "a"})
	tr.Report(telemetrytest.New().Emitter())

	cfg := cfgWithSecrets()
	// sources = nil, skipReasons = nil, limiter = nil: no live dependency wired.
	s := New(cfg.Admin, nil, nil, nil, cfg, tr)

	cw, cbody := serve(t, s, "/api/config.json")
	if cw.Code != http.StatusOK {
		t.Fatalf("config.json = %d, want 200", cw.Code)
	}
	var cv ConfigView
	if err := json.Unmarshal([]byte(cbody), &cv); err != nil {
		t.Fatalf("unmarshal config: %v", err)
	}
	if cv.LogLevel != "debug" || cv.TenantCount != 1 {
		t.Errorf("config view not populated from injected state: %+v", cv)
	}

	kw, kbody := serve(t, s, "/api/cardinality.json")
	if kw.Code != http.StatusOK {
		t.Fatalf("cardinality.json = %d, want 200", kw.Code)
	}
	var kv CardinalityView
	if err := json.Unmarshal([]byte(kbody), &kv); err != nil {
		t.Fatalf("unmarshal cardinality: %v", err)
	}
	if kv.TotalActiveSeries != 1 {
		t.Errorf("cardinality view not populated from injected tracker: %+v", kv)
	}
}
