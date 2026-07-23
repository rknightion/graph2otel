package exchangemailboxes

import (
	"testing"

	"github.com/rknightion/graph2otel/internal/signalcapture"
)

// TestMain enforces #112 over everything this package's tests emit: no metric
// label may carry per-entity data. A UPN label would grow one series per user —
// the exact shape the rule forbids — so identity stays on the log twin.
func TestMain(m *testing.M) { signalcapture.Main(m) }
