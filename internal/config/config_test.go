package config_test

import (
	"os"
	"path/filepath"
	"strings"
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

func TestCostDefaultsDisabledWithoutVendorRates(t *testing.T) {
	cfg, err := config.Load("")
	if err != nil {
		t.Fatalf("Load: %v", err)
	}

	if cfg.Cost.Enabled {
		t.Error("cost accounting is enabled by default")
	}
	if cfg.Cost.Period != 30*24*time.Hour {
		t.Errorf("cost period = %v, want 30 days", cfg.Cost.Period)
	}
	if cfg.Cost.Currency != "" || cfg.Cost.Version != "" ||
		cfg.Cost.Source != "" || cfg.Cost.EffectiveAt != "" {
		t.Errorf("cost metadata = %+v, want empty operator-supplied values", cfg.Cost)
	}
	if cfg.Cost.Rates.SourceRecord != nil ||
		cfg.Cost.Rates.MetricPoint != nil ||
		cfg.Cost.Rates.LogRecord != nil ||
		cfg.Cost.Rates.TransmittedPayloadByte != nil {
		t.Errorf("cost rates = %+v, want all rates omitted by default", cfg.Cost.Rates)
	}
	if cfg.Cost.BudgetMicrounits != 0 {
		t.Errorf("cost budget = %d, want 0 (no comparison)", cfg.Cost.BudgetMicrounits)
	}
}

func TestLoadCostEnvironmentOverridesAndPreservesExplicitZeroRate(t *testing.T) {
	t.Setenv("G2O_COST__ENABLED", "true")
	t.Setenv("G2O_COST__CURRENCY", "GBP")
	t.Setenv("G2O_COST__VERSION", "ops-2026-07")
	t.Setenv("G2O_COST__SOURCE", "internal-finops")
	t.Setenv("G2O_COST__EFFECTIVE_AT", "2026-07-26T00:00:00Z")
	t.Setenv("G2O_COST__PERIOD", "168h")
	t.Setenv("G2O_COST__RATES__SOURCE_RECORD_MICROUNITS", "0")
	t.Setenv("G2O_COST__RATES__METRIC_POINT_MICROUNITS", "2")
	t.Setenv("G2O_COST__RATES__LOG_RECORD_MICROUNITS", "3")
	t.Setenv("G2O_COST__RATES__TRANSMITTED_PAYLOAD_BYTE_MICROUNITS", "4")
	t.Setenv("G2O_COST__BUDGET_MICROUNITS", "500000")

	cfg, err := config.Load("")
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if !cfg.Cost.Enabled {
		t.Error("cost enabled = false, want true")
	}
	if cfg.Cost.Currency != "GBP" ||
		cfg.Cost.Version != "ops-2026-07" ||
		cfg.Cost.Source != "internal-finops" ||
		cfg.Cost.EffectiveAt != "2026-07-26T00:00:00Z" {
		t.Errorf("cost metadata = %+v, want environment values", cfg.Cost)
	}
	if cfg.Cost.Period != 7*24*time.Hour {
		t.Errorf("cost period = %v, want 168h", cfg.Cost.Period)
	}

	assertInt64Pointer := func(name string, got *int64, want int64) {
		t.Helper()
		if got == nil {
			t.Errorf("%s = nil, want explicit %d", name, want)
			return
		}
		if *got != want {
			t.Errorf("%s = %d, want %d", name, *got, want)
		}
	}
	assertInt64Pointer("source record rate", cfg.Cost.Rates.SourceRecord, 0)
	assertInt64Pointer("metric point rate", cfg.Cost.Rates.MetricPoint, 2)
	assertInt64Pointer("log record rate", cfg.Cost.Rates.LogRecord, 3)
	assertInt64Pointer(
		"transmitted payload byte rate",
		cfg.Cost.Rates.TransmittedPayloadByte,
		4,
	)
	if cfg.Cost.BudgetMicrounits != 500000 {
		t.Errorf("cost budget = %d, want 500000", cfg.Cost.BudgetMicrounits)
	}
	cfg.OTLP.Protocol = "stdout"
	if err := cfg.Validate(); err != nil {
		t.Fatalf("Validate rejected environment-loaded cost config: %v", err)
	}
}

func TestValidateCostContract(t *testing.T) {
	int64Pointer := func(value int64) *int64 { return &value }
	validCost := func() config.CostConfig {
		return config.CostConfig{
			Enabled:     true,
			Currency:    "GBP",
			Version:     "ops-2026-07",
			Source:      "internal-finops",
			EffectiveAt: "2026-07-26T00:00:00Z",
			Period:      30 * 24 * time.Hour,
			Rates: config.CostRatesConfig{
				SourceRecord:           int64Pointer(0),
				MetricPoint:            int64Pointer(0),
				LogRecord:              int64Pointer(0),
				TransmittedPayloadByte: int64Pointer(0),
			},
			BudgetMicrounits: 0,
		}
	}

	tests := []struct {
		name    string
		mutate  func(*config.CostConfig)
		wantErr string
	}{
		{
			name:    "currency required",
			mutate:  func(c *config.CostConfig) { c.Currency = "" },
			wantErr: "cost.currency",
		},
		{
			name:    "currency uppercase three letters",
			mutate:  func(c *config.CostConfig) { c.Currency = "gbp" },
			wantErr: "cost.currency",
		},
		{
			name:    "currency rejects non-ASCII letters",
			mutate:  func(c *config.CostConfig) { c.Currency = "G£P" },
			wantErr: "cost.currency",
		},
		{
			name:    "version nonblank",
			mutate:  func(c *config.CostConfig) { c.Version = " \t" },
			wantErr: "cost.version",
		},
		{
			name:    "source nonblank",
			mutate:  func(c *config.CostConfig) { c.Source = "\n" },
			wantErr: "cost.source",
		},
		{
			name:    "effective at required",
			mutate:  func(c *config.CostConfig) { c.EffectiveAt = "" },
			wantErr: "cost.effective_at",
		},
		{
			name:    "effective at RFC3339",
			mutate:  func(c *config.CostConfig) { c.EffectiveAt = "2026-07-26" },
			wantErr: "cost.effective_at",
		},
		{
			name:    "period positive",
			mutate:  func(c *config.CostConfig) { c.Period = 0 },
			wantErr: "cost.period",
		},
		{
			name: "source record rate required",
			mutate: func(c *config.CostConfig) {
				c.Rates.SourceRecord = nil
			},
			wantErr: "cost.rates.source_record_microunits",
		},
		{
			name: "metric point rate required",
			mutate: func(c *config.CostConfig) {
				c.Rates.MetricPoint = nil
			},
			wantErr: "cost.rates.metric_point_microunits",
		},
		{
			name: "log record rate required",
			mutate: func(c *config.CostConfig) {
				c.Rates.LogRecord = nil
			},
			wantErr: "cost.rates.log_record_microunits",
		},
		{
			name: "transmitted payload byte rate required",
			mutate: func(c *config.CostConfig) {
				c.Rates.TransmittedPayloadByte = nil
			},
			wantErr: "cost.rates.transmitted_payload_byte_microunits",
		},
		{
			name: "source record rate nonnegative",
			mutate: func(c *config.CostConfig) {
				c.Rates.SourceRecord = int64Pointer(-1)
			},
			wantErr: "cost.rates.source_record_microunits",
		},
		{
			name: "metric point rate nonnegative",
			mutate: func(c *config.CostConfig) {
				c.Rates.MetricPoint = int64Pointer(-1)
			},
			wantErr: "cost.rates.metric_point_microunits",
		},
		{
			name: "log record rate nonnegative",
			mutate: func(c *config.CostConfig) {
				c.Rates.LogRecord = int64Pointer(-1)
			},
			wantErr: "cost.rates.log_record_microunits",
		},
		{
			name: "transmitted payload byte rate nonnegative",
			mutate: func(c *config.CostConfig) {
				c.Rates.TransmittedPayloadByte = int64Pointer(-1)
			},
			wantErr: "cost.rates.transmitted_payload_byte_microunits",
		},
		{
			name: "budget nonnegative",
			mutate: func(c *config.CostConfig) {
				c.BudgetMicrounits = -1
			},
			wantErr: "cost.budget_microunits",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			cfg := config.Default()
			cfg.OTLP.Protocol = "stdout"
			cfg.Cost = validCost()
			test.mutate(&cfg.Cost)

			err := cfg.Validate()
			if err == nil {
				t.Fatalf("Validate accepted invalid cost config: %+v", cfg.Cost)
			}
			if !strings.Contains(err.Error(), test.wantErr) {
				t.Errorf("error %q does not identify %q", err, test.wantErr)
			}
		})
	}

	cfg := config.Default()
	cfg.OTLP.Protocol = "stdout"
	cfg.Cost = validCost()
	if err := cfg.Validate(); err != nil {
		t.Fatalf("Validate rejected valid cost config with explicit zero rates: %v", err)
	}
}

// TestCardinalityDefaultsAndEnvOverride verifies both limits' defaults and that
// their G2O_* overrides land (#235).
func TestCardinalityDefaultsAndEnvOverride(t *testing.T) {
	cfg, err := config.Load("")
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.Cardinality.PerMetricLimit != 5000 {
		t.Errorf("default PerMetricLimit = %d, want 5000", cfg.Cardinality.PerMetricLimit)
	}
	if cfg.Cardinality.GlobalLimit != 100000 {
		t.Errorf("default GlobalLimit = %d, want 100000", cfg.Cardinality.GlobalLimit)
	}

	t.Setenv("G2O_CARDINALITY__PER_METRIC_LIMIT", "250")
	t.Setenv("G2O_CARDINALITY__GLOBAL_LIMIT", "0")
	cfg, err = config.Load("")
	if err != nil {
		t.Fatalf("Load with env: %v", err)
	}
	if cfg.Cardinality.PerMetricLimit != 250 {
		t.Errorf("PerMetricLimit = %d, want env override 250", cfg.Cardinality.PerMetricLimit)
	}
	if cfg.Cardinality.GlobalLimit != 0 {
		t.Errorf("GlobalLimit = %d, want env override 0 (unlimited)", cfg.Cardinality.GlobalLimit)
	}
}

// TestValidateRejectsNegativeCardinalityLimits: a negative cap is invalid on
// either axis (0 = unlimited).
func TestValidateRejectsNegativeCardinalityLimits(t *testing.T) {
	for _, tc := range []struct {
		name  string
		apply func(*config.Config)
	}{
		{"per_metric", func(c *config.Config) { c.Cardinality.PerMetricLimit = -1 }},
		{"global", func(c *config.Config) { c.Cardinality.GlobalLimit = -1 }},
	} {
		cfg := config.Default()
		cfg.OTLP.Protocol = "stdout"
		tc.apply(cfg)
		if err := cfg.Validate(); err == nil {
			t.Errorf("Validate accepted a negative cardinality.%s limit", tc.name)
		}
	}
}

// TestRemovedMetricLimitKeyFailsFast is the migration guard.
//
// cardinality.metric_limit used to set the OTEL SDK's arrival-ordered
// per-instrument cap. #235 replaced that mechanism with a significance-ranked
// limiter and disabled the SDK's cap entirely, so the key does not merely have a
// new name — it had a different meaning. An operator who set it to 50000 to
// neuter the old behavior would silently get the new one at its default.
//
// koanf ignores keys with no matching struct field, so without this the setting
// would vanish without a word. Failing to start is the loud option, and the
// error names the replacement.
func TestRemovedMetricLimitKeyFailsFast(t *testing.T) {
	t.Setenv("G2O_CARDINALITY__METRIC_LIMIT", "2000")
	_, err := config.Load("")
	if err == nil {
		t.Fatal("Load accepted the removed cardinality.metric_limit key — it would be " +
			"silently ignored, leaving the operator with a limit they did not choose")
	}
	if !strings.Contains(err.Error(), "per_metric_limit") {
		t.Errorf("error %q does not name the replacement key", err)
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

	c.Tenants = []config.TenantConfig{{TenantID: "4b8c18bd-2f9f-4227-af55-9f1061cf9c32", BlobIngest: config.BlobIngestConfig{MetricRecencyWindow: 30 * time.Minute}}}
	if got := c.BlobMetricRecencyWindow("4b8c18bd-2f9f-4227-af55-9f1061cf9c32"); got != 30*time.Minute {
		t.Fatalf("per-tenant window = %v, want 30m", got)
	}
	if got := c.BlobMetricRecencyWindow("other"); got != 20*time.Minute {
		t.Fatalf("unknown tenant window = %v, want default 20m", got)
	}

	bad := config.Default()
	bad.OTLP.Protocol = "stdout"
	bad.Tenants = []config.TenantConfig{{TenantID: "4b8c18bd-2f9f-4227-af55-9f1061cf9c32", BlobIngest: config.BlobIngestConfig{MetricRecencyWindow: 2 * time.Hour}}}
	if err := bad.Validate(); err == nil {
		t.Fatal("Validate accepted a metric_recency_window > 1h")
	}

	neg := config.Default()
	neg.OTLP.Protocol = "stdout"
	neg.Tenants = []config.TenantConfig{{TenantID: "4b8c18bd-2f9f-4227-af55-9f1061cf9c32", BlobIngest: config.BlobIngestConfig{MetricRecencyWindow: -1}}}
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

func TestValidateTenantIDRequiresHyphenatedDirectoryGUID(t *testing.T) {
	const directoryID = "4b8c18bd-2f9f-4227-af55-9f1061cf9c32"
	tests := []struct {
		name    string
		tenant  string
		wantErr bool
	}{
		{name: "lowercase hyphenated", tenant: directoryID},
		{name: "uppercase hyphenated", tenant: strings.ToUpper(directoryID)},
		{name: "verified domain", tenant: "contoso.onmicrosoft.com", wantErr: true},
		{name: "arbitrary name", tenant: "production-tenant", wantErr: true},
		{name: "compact UUID", tenant: "4b8c18bd2f9f4227af559f1061cf9c32", wantErr: true},
		{name: "braced UUID", tenant: "{4b8c18bd-2f9f-4227-af55-9f1061cf9c32}", wantErr: true},
		{name: "surrounding whitespace", tenant: " 4b8c18bd-2f9f-4227-af55-9f1061cf9c32 ", wantErr: true},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			cfg := config.Default()
			cfg.OTLP.Protocol = "stdout"
			cfg.Tenants = []config.TenantConfig{{TenantID: tc.tenant}}

			err := cfg.Validate()
			if tc.wantErr {
				if err == nil {
					t.Fatalf("Validate accepted tenant_id %q", tc.tenant)
				}
				if !strings.Contains(err.Error(), "hyphenated Entra directory GUID") {
					t.Fatalf("Validate error = %q, want hyphenated GUID guidance", err)
				}
				return
			}
			if err != nil {
				t.Fatalf("Validate rejected tenant_id %q: %v", tc.tenant, err)
			}
		})
	}
}

func TestValidateRejectsDuplicateDirectoryGUIDIgnoringCase(t *testing.T) {
	const directoryID = "4b8c18bd-2f9f-4227-af55-9f1061cf9c32"
	cfg := config.Default()
	cfg.OTLP.Protocol = "stdout"
	cfg.Tenants = []config.TenantConfig{
		{TenantID: directoryID},
		{TenantID: strings.ToUpper(directoryID)},
	}

	err := cfg.Validate()
	if err == nil {
		t.Fatal("Validate accepted the same directory GUID in different hex case")
	}
	if !strings.Contains(err.Error(), "duplicate tenant") {
		t.Fatalf("Validate error = %q, want duplicate tenant", err)
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
