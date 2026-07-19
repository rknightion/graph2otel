package teams

import (
	"testing"

	"github.com/rknightion/graph2otel/internal/signalcapture"
)

// TestMain enforces #112 over everything this package's tests emit: no metric
// label may carry per-entity data (team id, displayName). The gauges are bounded
// to visibility × role; this gate keeps it that way. See internal/signalcapture.
func TestMain(m *testing.M) { signalcapture.Main(m) }
