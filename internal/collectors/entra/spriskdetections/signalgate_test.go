package spriskdetections

import (
	"testing"

	"github.com/rknightion/graph2otel/internal/signalcapture"
)

// TestMain enforces #112 (no per-entity metric label) and drift-gates the
// emitted-signal golden. This package emits only logs, so #112 holds by
// construction; the golden still pins the log attribute set.
func TestMain(m *testing.M) { signalcapture.Main(m) }
