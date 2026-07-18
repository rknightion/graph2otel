package config_test

import (
	"testing"
	"time"

	"github.com/rknightion/graph2otel/internal/config"
)

// TestDefaultsResolveCollectorsEnabled: with no collectors config at all, every
// collector resolves to enabled with a zero interval meaning "use the
// collector's built-in default".
func TestDefaultsResolveCollectorsEnabled(t *testing.T) {
	cfg, err := config.Load("")
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	enabled, interval := cfg.CollectorSettings("t1", "sign_ins")
	if !enabled {
		t.Errorf("collector with no config should default to enabled")
	}
	if interval != 0 {
		t.Errorf("interval = %v, want 0 (use built-in default)", interval)
	}
}

// TestGlobalCollectorDisable: collectors.<name>.enabled=false disables exactly
// that collector and leaves others enabled.
func TestGlobalCollectorDisable(t *testing.T) {
	const y = `
otlp:
  protocol: stdout
collectors:
  sign_ins:
    enabled: false
  audit_logs:
    enabled: true
`
	cfg := mustLoad(t, y)
	if en, _ := cfg.CollectorSettings("t1", "sign_ins"); en {
		t.Errorf("sign_ins should be disabled")
	}
	if en, _ := cfg.CollectorSettings("t1", "audit_logs"); !en {
		t.Errorf("audit_logs should be enabled")
	}
	if en, _ := cfg.CollectorSettings("t1", "devices"); !en {
		t.Errorf("unconfigured collector should default to enabled")
	}
}

// TestGlobalCollectorInterval: collectors.<name>.interval decodes a duration
// string via CollectorSettings.
func TestGlobalCollectorInterval(t *testing.T) {
	const y = `
otlp:
  protocol: stdout
collectors:
  sign_ins:
    interval: "10m"
`
	cfg := mustLoad(t, y)
	_, interval := cfg.CollectorSettings("t1", "sign_ins")
	if interval != 10*time.Minute {
		t.Errorf("interval = %v, want 10m", interval)
	}
}

// TestPerTenantOverrideWins: a per-tenant collector override wins over the
// global collector config.
func TestCollectorSourceResolution(t *testing.T) {
	const y = `
otlp:
  protocol: stdout
collectors:
  entra.directory_audits:
    source: blob
  entra.provisioning:
    source: graph
tenants:
  - tenant_id: "aaaa"
    collectors:
      entra.directory_audits:
        source: graph
  - tenant_id: "bbbb"
    collectors:
      entra.provisioning:
        source: blob
`
	cfg := mustLoad(t, y)
	// Default when nothing is set: graph.
	if got := cfg.CollectorSource("aaaa", "entra.signins.interactive"); got != "graph" {
		t.Errorf("unset source = %q, want graph", got)
	}
	// Global blob, per-tenant override back to graph wins.
	if got := cfg.CollectorSource("aaaa", "entra.directory_audits"); got != "graph" {
		t.Errorf("tenant aaaa directory_audits = %q, want graph (override wins)", got)
	}
	// Global blob, no tenant override → blob.
	if got := cfg.CollectorSource("cccc", "entra.directory_audits"); got != "blob" {
		t.Errorf("tenant cccc directory_audits = %q, want blob (global)", got)
	}
	// Global graph, per-tenant override to blob wins.
	if got := cfg.CollectorSource("bbbb", "entra.provisioning"); got != "blob" {
		t.Errorf("tenant bbbb provisioning = %q, want blob (override wins)", got)
	}
	// Global graph, no override → graph.
	if got := cfg.CollectorSource("aaaa", "entra.provisioning"); got != "graph" {
		t.Errorf("tenant aaaa provisioning = %q, want graph", got)
	}
}

func TestPerTenantOverrideWins(t *testing.T) {
	const y = `
otlp:
  protocol: stdout
collectors:
  sign_ins:
    enabled: true
    interval: "5m"
tenants:
  - tenant_id: "aaaa"
    collectors:
      sign_ins:
        enabled: false
  - tenant_id: "bbbb"
    collectors:
      sign_ins:
        interval: "1m"
`
	cfg := mustLoad(t, y)
	// tenant aaaa disables the globally-enabled collector.
	if en, _ := cfg.CollectorSettings("aaaa", "sign_ins"); en {
		t.Errorf("tenant aaaa should have sign_ins disabled by override")
	}
	// tenant bbbb keeps it enabled but overrides the interval.
	en, interval := cfg.CollectorSettings("bbbb", "sign_ins")
	if !en {
		t.Errorf("tenant bbbb should keep sign_ins enabled")
	}
	if interval != 1*time.Minute {
		t.Errorf("tenant bbbb interval = %v, want 1m override", interval)
	}
	// an unknown tenant falls back to the global config.
	_, gInterval := cfg.CollectorSettings("unknown", "sign_ins")
	if gInterval != 5*time.Minute {
		t.Errorf("unknown tenant interval = %v, want global 5m", gInterval)
	}
}

// TestCollectorNestedEnvKey: a collector name containing an underscore stays
// addressable via a G2O_ env var (the "__" nesting / single "_" preserved rule).
func TestCollectorNestedEnvKey(t *testing.T) {
	t.Setenv("G2O_COLLECTORS__SIGN_INS__ENABLED", "false")
	cfg, err := config.Load("")
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if en, _ := cfg.CollectorSettings("t1", "sign_ins"); en {
		t.Errorf("G2O_COLLECTORS__SIGN_INS__ENABLED=false should disable sign_ins")
	}
}

// TestAdminConfigDefaultsAndOverride: admin block defaults and YAML override.
func TestAdminConfigDefaultsAndOverride(t *testing.T) {
	cfg, err := config.Load("")
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.Admin.Addr != ":9090" {
		t.Errorf("default admin.addr = %q, want :9090", cfg.Admin.Addr)
	}
	if cfg.Admin.Enabled {
		t.Errorf("admin should be disabled by default")
	}
	cfg2 := mustLoad(t, "otlp:\n  protocol: stdout\nadmin:\n  enabled: true\n  addr: \":8181\"\n")
	if !cfg2.Admin.Enabled || cfg2.Admin.Addr != ":8181" {
		t.Errorf("admin override failed: %+v", cfg2.Admin)
	}
}

// TestCheckpointDirDefault: checkpoint_dir has a default and is overridable.
func TestCheckpointDirDefault(t *testing.T) {
	cfg, err := config.Load("")
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.CheckpointDir == "" {
		t.Errorf("checkpoint_dir should have a non-empty default")
	}
	cfg2 := mustLoad(t, "otlp:\n  protocol: stdout\ncheckpoint_dir: /var/lib/graph2otel\n")
	if cfg2.CheckpointDir != "/var/lib/graph2otel" {
		t.Errorf("checkpoint_dir override = %q", cfg2.CheckpointDir)
	}
}

// TestValidateRejectsSubSecondInterval: Validate rejects a positive interval
// under 1s (a likely mistake) but allows a zero interval (use built-in default).
func TestValidateRejectsSubSecondInterval(t *testing.T) {
	const y = `
otlp:
  protocol: stdout
collectors:
  sign_ins:
    interval: "500ms"
`
	cfg := mustLoad(t, y)
	if err := cfg.Validate(); err == nil {
		t.Fatal("expected Validate to reject a sub-1s interval")
	}
}

func TestValidateRejectsSubSecondPerTenantInterval(t *testing.T) {
	const y = `
otlp:
  protocol: stdout
tenants:
  - tenant_id: "aaaa"
    collectors:
      sign_ins:
        interval: "10ms"
`
	cfg := mustLoad(t, y)
	if err := cfg.Validate(); err == nil {
		t.Fatal("expected Validate to reject a sub-1s per-tenant interval")
	}
}

func TestValidateAllowsZeroAndAboveSecondInterval(t *testing.T) {
	const y = `
otlp:
  protocol: stdout
collectors:
  sign_ins:
    interval: "1s"
  audit_logs:
    enabled: false
`
	cfg := mustLoad(t, y)
	if err := cfg.Validate(); err != nil {
		t.Fatalf("1s interval and unset interval should validate: %v", err)
	}
}

// mustLoad writes y to a temp file, loads it, and fails on error.
// TestCollectorExplicitlyEnabled: the default-true state is NOT "explicitly
// enabled" (so a beta collector stays off), but an explicit enabled=true at the
// global or per-tenant layer IS, and an explicit false is not.
func TestCollectorExplicitlyEnabled(t *testing.T) {
	const y = `
otlp:
  protocol: stdout
collectors:
  entra.recommendations:
    enabled: true
  entra.signin_activity:
    enabled: false
tenants:
  - tenant_id: t2
    collectors:
      entra.signin_activity:
        enabled: true
`
	cfg := mustLoad(t, y)
	// Unconfigured collector: default-enabled, but NOT explicitly enabled.
	if cfg.CollectorExplicitlyEnabled("t1", "entra.recommendations_unset") {
		t.Error("unconfigured collector must not count as explicitly enabled")
	}
	// Globally explicit true.
	if !cfg.CollectorExplicitlyEnabled("t1", "entra.recommendations") {
		t.Error("global enabled=true should be explicitly enabled")
	}
	// Globally explicit false.
	if cfg.CollectorExplicitlyEnabled("t1", "entra.signin_activity") {
		t.Error("global enabled=false is not explicitly enabled")
	}
	// Per-tenant override flips it explicitly true for t2.
	if !cfg.CollectorExplicitlyEnabled("t2", "entra.signin_activity") {
		t.Error("per-tenant enabled=true should be explicitly enabled for that tenant")
	}
}

func mustLoad(t *testing.T, y string) *config.Config {
	t.Helper()
	p := writeTemp(t, y)
	cfg, err := config.Load(p)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	return cfg
}
