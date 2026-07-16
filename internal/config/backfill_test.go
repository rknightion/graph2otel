package config_test

import (
	"strings"
	"testing"
	"time"

	"github.com/rknightion/graph2otel/internal/config"
)

func TestBackfillInitialLookbackDefaultsToZero(t *testing.T) {
	if got := config.Default().Backfill.InitialLookback; got != 0 {
		t.Errorf("Default().Backfill.InitialLookback = %v, want 0 — the default must mean "+
			"'use each collector's own built-in lookback', not impose one global value over all of them", got)
	}
}

func TestBackfillInitialLookbackFromEnv(t *testing.T) {
	t.Setenv("G2O_BACKFILL__INITIAL_LOOKBACK", "6h")
	cfg, err := config.Load("")
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if got := cfg.Backfill.InitialLookback; got != 6*time.Hour {
		t.Errorf("Backfill.InitialLookback = %v, want 6h from G2O_BACKFILL__INITIAL_LOOKBACK", got)
	}
}

func TestBackfillInitialLookbackFromYAML(t *testing.T) {
	path := writeTemp(t, `
otlp:
  protocol: stdout
backfill:
  initial_lookback: 48h
`)
	cfg, err := config.Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if got := cfg.Backfill.InitialLookback; got != 48*time.Hour {
		t.Errorf("Backfill.InitialLookback = %v, want 48h", got)
	}
	if err := cfg.Validate(); err != nil {
		t.Errorf("Validate: %v", err)
	}
}

func TestBackfillNegativeInitialLookbackRejected(t *testing.T) {
	cfg := config.Default()
	cfg.OTLP.Protocol = "stdout"
	cfg.Backfill.InitialLookback = -time.Hour

	err := cfg.Validate()
	if err == nil {
		t.Fatal("Validate: want an error for a negative initial_lookback")
	}
	if !strings.Contains(err.Error(), "backfill.initial_lookback") {
		t.Errorf("Validate error = %q, want it to name the offending key", err)
	}
}

// TestBackfillWarnsBeyondBackendAcceptWindow is the binding constraint from
// #118's comment: graph2otel ships logs over OTLP into Loki, which REJECTS
// samples older than its accept window (~13d on Grafana Cloud). A lookback beyond
// that is not a longer recovery — it is a guaranteed silent drop at the backend,
// which is a worse failure than a short lookback because it looks like it is
// working: Graph is polled, records are mapped and shipped, no error is raised,
// and nothing appears in Grafana.
func TestBackfillWarnsBeyondBackendAcceptWindow(t *testing.T) {
	tests := []struct {
		name     string
		lookback time.Duration
		wantWarn bool
	}{
		{name: "unset", lookback: 0, wantWarn: false},
		{name: "a day", lookback: 24 * time.Hour, wantWarn: false},
		{name: "just inside the ceiling", lookback: 12 * 24 * time.Hour, wantWarn: false},
		{name: "at the ceiling", lookback: 13 * 24 * time.Hour, wantWarn: false},
		{name: "beyond the ceiling", lookback: 14 * 24 * time.Hour, wantWarn: true},
		{name: "thirty days", lookback: 30 * 24 * time.Hour, wantWarn: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := config.Default()
			cfg.OTLP.Protocol = "stdout"
			cfg.Backfill.InitialLookback = tt.lookback

			warns := cfg.Warnings()
			got := false
			for _, w := range warns {
				if strings.Contains(w, "backfill.initial_lookback") {
					got = true
				}
			}
			if got != tt.wantWarn {
				t.Errorf("Warnings() = %v; warned about initial_lookback = %v, want %v", warns, got, tt.wantWarn)
			}
		})
	}
}

// TestBackfillCeilingIsAWarningNotAClamp pins the deliberate design choice from
// #118's comment: graph2otel must not pretend to know every backend's retention
// policy. A self-hosted Loki with a wider reject_old_samples_max_age (or a
// non-Loki OTLP sink) may legitimately accept more, so an over-ceiling value must
// still LOAD, still VALIDATE, and still take effect — it only warns.
func TestBackfillCeilingIsAWarningNotAClamp(t *testing.T) {
	path := writeTemp(t, `
otlp:
  protocol: stdout
backfill:
  initial_lookback: 720h
`)
	cfg, err := config.Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if err := cfg.Validate(); err != nil {
		t.Errorf("Validate: %v — an over-ceiling lookback must be valid, not rejected", err)
	}
	if got := cfg.Backfill.InitialLookback; got != 720*time.Hour {
		t.Errorf("Backfill.InitialLookback = %v, want 720h unchanged — the ceiling must NOT clamp the value", got)
	}
	if len(cfg.Warnings()) == 0 {
		t.Error("Warnings() is empty, want the operator warned about the backend accept window")
	}
}

// TestBackfillWarningIsActionable: the warning is the entire mitigation, so it
// has to tell an operator what will actually happen. A bare "value is large" note
// would not connect the setting to the symptom (logs never appearing).
func TestBackfillWarningIsActionable(t *testing.T) {
	cfg := config.Default()
	cfg.OTLP.Protocol = "stdout"
	cfg.Backfill.InitialLookback = 30 * 24 * time.Hour

	warns := cfg.Warnings()
	if len(warns) != 1 {
		t.Fatalf("Warnings() = %v, want exactly 1", warns)
	}
	for _, want := range []string{"backfill.initial_lookback", "Loki", "reject"} {
		if !strings.Contains(warns[0], want) {
			t.Errorf("warning %q does not mention %q", warns[0], want)
		}
	}
}

func TestWarningsEmptyForDefaultConfig(t *testing.T) {
	cfg := config.Default()
	cfg.OTLP.Protocol = "stdout"
	if warns := cfg.Warnings(); len(warns) != 0 {
		t.Errorf("Warnings() = %v, want none for a default config", warns)
	}
}
