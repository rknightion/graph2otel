package config_test

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/rknightion/graph2otel/internal/config"
)

// writeTemp writes content to a file in a fresh temp dir and returns its path.
func writeTemp(t *testing.T, content string) string {
	t.Helper()
	dir := t.TempDir()
	p := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
		t.Fatalf("write temp config: %v", err)
	}
	return p
}

// TestConfigExampleLoadsAndValidates guards the shipped config.example.yaml
// against drift: it must always parse and validate cleanly.
func TestConfigExampleLoadsAndValidates(t *testing.T) {
	path := filepath.Join("..", "..", "config.example.yaml")
	if _, err := os.Stat(path); err != nil {
		t.Skipf("config.example.yaml not found: %v", err)
	}
	cfg, err := config.Load(path)
	if err != nil {
		t.Fatalf("config.example.yaml must load: %v", err)
	}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("config.example.yaml must validate: %v", err)
	}
}

// TestLoadDefaults verifies that Load("") (no file) returns the built-in
// defaults with no error, even though those defaults have no tenants — an
// empty-tenants Config is only rejected by Validate, not by Load itself, so a
// container can start from defaults + environment alone.
func TestLoadDefaults(t *testing.T) {
	cfg, err := config.Load("")
	if err != nil {
		t.Fatalf("Load(\"\") should succeed from defaults: %v", err)
	}
	if cfg.LogLevel != "info" {
		t.Errorf("LogLevel = %q, want default info", cfg.LogLevel)
	}
	if cfg.OTLP.Protocol != "http" {
		t.Errorf("OTLP.Protocol = %q, want default http", cfg.OTLP.Protocol)
	}
	if len(cfg.Tenants) != 0 {
		t.Errorf("Tenants = %v, want empty by default", cfg.Tenants)
	}
}

// TestLoadYAMLOverridesDefaults verifies the YAML file layer overrides the
// built-in defaults.
func TestLoadYAMLOverridesDefaults(t *testing.T) {
	const y = `
log_level: debug
otlp:
  protocol: grpc
  endpoint: "example.test:4317"
  grafana_cloud:
    instance_id: "12345"
    token: "glc_token"
tenants:
  - tenant_id: "11111111-1111-1111-1111-111111111111"
    client_id: "22222222-2222-2222-2222-222222222222"
`
	p := writeTemp(t, y)
	cfg, err := config.Load(p)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.LogLevel != "debug" {
		t.Errorf("LogLevel = %q, want debug", cfg.LogLevel)
	}
	if cfg.OTLP.Protocol != "grpc" {
		t.Errorf("OTLP.Protocol = %q, want grpc", cfg.OTLP.Protocol)
	}
	if cfg.OTLP.Endpoint != "example.test:4317" {
		t.Errorf("OTLP.Endpoint = %q, want example.test:4317", cfg.OTLP.Endpoint)
	}
	if cfg.OTLP.GrafanaCloud.InstanceID != "12345" {
		t.Errorf("GrafanaCloud.InstanceID = %q, want 12345", cfg.OTLP.GrafanaCloud.InstanceID)
	}
	if cfg.OTLP.GrafanaCloud.Token.Reveal() != "glc_token" {
		t.Errorf("GrafanaCloud.Token = %q, want glc_token", cfg.OTLP.GrafanaCloud.Token.Reveal())
	}
	if len(cfg.Tenants) != 1 {
		t.Fatalf("Tenants = %v, want 1 entry", cfg.Tenants)
	}
	if cfg.Tenants[0].TenantID != "11111111-1111-1111-1111-111111111111" {
		t.Errorf("Tenants[0].TenantID = %q, want the configured tenant ID", cfg.Tenants[0].TenantID)
	}
	if cfg.Tenants[0].ClientID != "22222222-2222-2222-2222-222222222222" {
		t.Errorf("Tenants[0].ClientID = %q, want the configured client ID", cfg.Tenants[0].ClientID)
	}
}

// TestLoadEnvOverridesYAML verifies the G2O_ environment layer overrides the
// YAML file (highest precedence).
func TestLoadEnvOverridesYAML(t *testing.T) {
	p := writeTemp(t, "log_level: debug\n")
	t.Setenv("G2O_LOG_LEVEL", "warn")

	cfg, err := config.Load(p)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.LogLevel != "warn" {
		t.Errorf("LogLevel = %q, want env override warn", cfg.LogLevel)
	}
}

// TestLoadEnvNestedDoubleUnderscore verifies the "__" nesting delimiter reaches
// a nested field (otlp.endpoint), per the frozen G2O_ env-var contract.
func TestLoadEnvNestedDoubleUnderscore(t *testing.T) {
	t.Setenv("G2O_OTLP__ENDPOINT", "https://example.test/otlp")

	cfg, err := config.Load("")
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.OTLP.Endpoint != "https://example.test/otlp" {
		t.Errorf("OTLP.Endpoint = %q, want env override", cfg.OTLP.Endpoint)
	}
}

// TestCardinalityDefaultAndEnvOverride verifies the metric_limit default and
// that G2O_CARDINALITY__METRIC_LIMIT overrides it (#105).
func TestCardinalityDefaultAndEnvOverride(t *testing.T) {
	cfg, err := config.Load("")
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.Cardinality.MetricLimit != 2000 {
		t.Errorf("default MetricLimit = %d, want 2000", cfg.Cardinality.MetricLimit)
	}

	t.Setenv("G2O_CARDINALITY__METRIC_LIMIT", "5000")
	cfg, err = config.Load("")
	if err != nil {
		t.Fatalf("Load with env: %v", err)
	}
	if cfg.Cardinality.MetricLimit != 5000 {
		t.Errorf("MetricLimit = %d, want env override 5000", cfg.Cardinality.MetricLimit)
	}
}

// TestValidateRejectsNegativeMetricLimit: a negative cap is invalid (0 = unlimited).
func TestValidateRejectsNegativeMetricLimit(t *testing.T) {
	cfg := config.Default()
	cfg.OTLP.Protocol = "stdout"
	cfg.Cardinality.MetricLimit = -1
	if err := cfg.Validate(); err == nil {
		t.Fatal("Validate accepted a negative cardinality.metric_limit")
	}
}

// TestBlobMetricRecencyWindow_DefaultAndValidation: the gate window defaults to
// 20m, honors a per-tenant override, and is validated to (0, 1h] — a larger
// window would re-admit backfilled events into counters (#128).
func TestBlobMetricRecencyWindow_DefaultAndValidation(t *testing.T) {
	c := config.Default()
	if got := c.BlobMetricRecencyWindow("t1"); got != 20*time.Minute {
		t.Fatalf("default window = %v, want 20m", got)
	}

	c.Tenants = []config.TenantConfig{{TenantID: "t1", BlobIngest: config.BlobIngestConfig{MetricRecencyWindow: 30 * time.Minute}}}
	if got := c.BlobMetricRecencyWindow("t1"); got != 30*time.Minute {
		t.Fatalf("per-tenant window = %v, want 30m", got)
	}
	if got := c.BlobMetricRecencyWindow("other"); got != 20*time.Minute {
		t.Fatalf("unknown tenant window = %v, want default 20m", got)
	}

	bad := config.Default()
	bad.OTLP.Protocol = "stdout"
	bad.Tenants = []config.TenantConfig{{TenantID: "t1", BlobIngest: config.BlobIngestConfig{MetricRecencyWindow: 2 * time.Hour}}}
	if err := bad.Validate(); err == nil {
		t.Fatal("Validate accepted a metric_recency_window > 1h")
	}

	neg := config.Default()
	neg.OTLP.Protocol = "stdout"
	neg.Tenants = []config.TenantConfig{{TenantID: "t1", BlobIngest: config.BlobIngestConfig{MetricRecencyWindow: -1}}}
	if err := neg.Validate(); err == nil {
		t.Fatal("Validate accepted a negative metric_recency_window")
	}
}

// TestLoadMissingFile: a config path that was explicitly given but cannot be
// read is a hard error.
func TestLoadMissingFile(t *testing.T) {
	if _, err := config.Load("/nonexistent/path/config.yaml"); err == nil {
		t.Fatal("expected error for missing file, got nil")
	}
}

func TestValidateRejectsEmptyTenantsWhenNotStdout(t *testing.T) {
	cfg := config.Default()
	cfg.OTLP.Protocol = "http"
	if err := cfg.Validate(); err == nil {
		t.Fatal("expected error for empty tenants with otlp.protocol=http, got nil")
	}
}

func TestValidateAllowsEmptyTenantsInStdoutMode(t *testing.T) {
	cfg := config.Default()
	cfg.OTLP.Protocol = "stdout"
	if err := cfg.Validate(); err != nil {
		t.Errorf("stdout mode with no tenants should validate cleanly: %v", err)
	}
}

func TestValidateRejectsMissingTenantID(t *testing.T) {
	cfg := config.Default()
	cfg.OTLP.Protocol = "stdout"
	cfg.Tenants = []config.TenantConfig{{TenantID: "", ClientID: "some-client-id"}}
	if err := cfg.Validate(); err == nil {
		t.Fatal("expected error for tenant with missing tenant_id, got nil")
	}
}

func TestValidateRejectsInvalidProtocol(t *testing.T) {
	cfg := config.Default()
	cfg.OTLP.Protocol = "carrier-pigeon"
	if err := cfg.Validate(); err == nil {
		t.Fatal("expected error for invalid otlp.protocol, got nil")
	}
}

func TestValidateRejectsInvalidLogLevel(t *testing.T) {
	cfg := config.Default()
	cfg.OTLP.Protocol = "stdout"
	cfg.LogLevel = "verbose"
	if err := cfg.Validate(); err == nil {
		t.Fatal("expected error for invalid log_level, got nil")
	}
}
