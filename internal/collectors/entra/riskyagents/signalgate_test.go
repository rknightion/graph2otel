package riskyagents

import (
	"testing"

	"github.com/rknightion/graph2otel/internal/signalcapture"
)

// TestMain enforces #112 over everything this package's tests emit: no metric
// label may carry per-entity data (only risk_level x risk_state bucket the
// gauge). See internal/signalcapture.
func TestMain(m *testing.M) { signalcapture.Main(m) }
