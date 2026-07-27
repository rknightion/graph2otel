package main

import (
	"testing"
	"time"

	"github.com/rknightion/graph2otel/internal/collectors"
	"github.com/rknightion/graph2otel/internal/config"
	"github.com/rknightion/graph2otel/internal/telemetry"
)

// TestInitialLookback pins the precedence of the backfill.initial_lookback key
// (#118): an operator's value overrides every collector's built-in lookback, and
// the default (0) leaves each collector on its own — most 1h, m365.unified_audit
// 4h, entra.security_incidents 24h, each tuned to its endpoint.
func TestInitialLookback(t *testing.T) {
	tests := []struct {
		name       string
		configured time.Duration
		builtin    time.Duration
		want       time.Duration
	}{
		{name: "unset uses the collector's own value", configured: 0, builtin: time.Hour, want: time.Hour},
		{name: "unset preserves a collector-specific value", configured: 0, builtin: 24 * time.Hour, want: 24 * time.Hour},
		{name: "configured overrides the collector", configured: 6 * time.Hour, builtin: time.Hour, want: 6 * time.Hour},
		{name: "configured overrides a longer collector value too", configured: 2 * time.Hour, builtin: 24 * time.Hour, want: 2 * time.Hour},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := config.Default()
			cfg.Backfill.InitialLookback = tt.configured
			rw := collectors.RegisteredWindow{InitialLookback: tt.builtin}

			if got := initialLookback(cfg, rw); got != tt.want {
				t.Errorf("initialLookback(%v configured, %v builtin) = %v, want %v", tt.configured, tt.builtin, got, tt.want)
			}
		})
	}
}

// TestAnOverHorizonLookbackIsActuallyClamped is the gate on the OUTCOME rather
// than on the warning (#401). Config.Warnings() says "CLAMPED"; this proves the
// poll window really is. A message claiming a clamp that never happened is worse
// than no message, because it is believed.
func TestAnOverHorizonLookbackIsActuallyClamped(t *testing.T) {
	cfg := config.Default()
	cfg.Backfill.InitialLookback = 30 * 24 * time.Hour

	got := initialLookback(cfg, collectors.RegisteredWindow{InitialLookback: time.Hour})

	if got != telemetry.EventHorizon {
		t.Fatalf("initialLookback = %v, want the horizon %v", got, telemetry.EventHorizon)
	}
}

// TestAnInWindowLookbackIsUsedAsWritten guards the other direction: a clamp that
// also shortens correct configurations would silently reduce recovery.
func TestAnInWindowLookbackIsUsedAsWritten(t *testing.T) {
	cfg := config.Default()
	cfg.Backfill.InitialLookback = 48 * time.Hour

	if got := initialLookback(cfg, collectors.RegisteredWindow{InitialLookback: time.Hour}); got != 48*time.Hour {
		t.Fatalf("initialLookback = %v, want 48h unchanged", got)
	}
}

// TestACollectorsOwnLookbackIsAlsoClamped — the protection must not depend on
// which of the two code paths supplied the value.
func TestACollectorsOwnLookbackIsAlsoClamped(t *testing.T) {
	cfg := config.Default()

	got := initialLookback(cfg, collectors.RegisteredWindow{InitialLookback: 400 * time.Hour})

	if got != telemetry.EventHorizon {
		t.Fatalf("a factory's own over-horizon lookback was used as written: %v", got)
	}
}
