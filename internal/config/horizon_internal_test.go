package config

import (
	"strings"
	"testing"
	"time"

	"github.com/rknightion/graph2otel/internal/telemetry"
)

// TestTheEmitHorizonStaysInsideTheMeasuredAcceptWindow pins the relationship
// between the two numbers so they cannot drift apart (#401).
//
// backendAcceptWindow is a measured fact about the backend; telemetry.EventHorizon
// is the deliberately-smaller value graph2otel will actually emit up to. If a
// future edit raised the horizon to or past the window, the guard would stop
// preventing the rejection it exists for — and it would do so silently, because
// everything would still compile and every other test would still pass.
func TestTheEmitHorizonStaysInsideTheMeasuredAcceptWindow(t *testing.T) {
	if telemetry.EventHorizon >= backendAcceptWindow {
		t.Fatalf("emit horizon %v is not inside the measured accept window %v",
			telemetry.EventHorizon, backendAcceptWindow)
	}
	margin := backendAcceptWindow - telemetry.EventHorizon
	if margin < 2*time.Hour {
		t.Fatalf("margin %v is too thin: the production rejection observed on 2026-07-27 "+
			"was only ~1h past the limit, so the margin has to absorb clock skew and flush latency",
			margin)
	}
}

// TestAnOverHorizonLookbackIsReportedAsClamped proves the operator is TOLD.
// Applying a clamp silently would leave someone believing they had configured a
// 30-day recovery while getting 165h of it.
func TestAnOverHorizonLookbackIsReportedAsClamped(t *testing.T) {
	cfg := Default()
	cfg.Backfill.InitialLookback = 30 * 24 * time.Hour

	var found bool
	for _, w := range cfg.Warnings() {
		if strings.Contains(w, "CLAMPED") {
			found = true
			if !strings.Contains(w, telemetry.EventHorizon.String()) {
				t.Errorf("clamp warning does not name the effective value: %q", w)
			}
		}
	}
	if !found {
		t.Fatalf("an over-horizon initial_lookback produced no clamp warning: %v", cfg.Warnings())
	}
}

// TestAnInWindowLookbackIsNotReportedAsClamped guards the other direction: a
// warning on a correct configuration trains the operator to ignore warnings.
func TestAnInWindowLookbackIsNotReportedAsClamped(t *testing.T) {
	cfg := Default()
	cfg.Backfill.InitialLookback = 24 * time.Hour

	for _, w := range cfg.Warnings() {
		if strings.Contains(w, "CLAMPED") {
			t.Fatalf("a 24h lookback was reported as clamped: %q", w)
		}
	}
}
