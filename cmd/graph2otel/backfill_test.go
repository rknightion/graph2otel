package main

import (
	"testing"
	"time"

	"github.com/rknightion/graph2otel/internal/collectors"
	"github.com/rknightion/graph2otel/internal/config"
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
