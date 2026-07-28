package exposuregraph

import (
	"testing"

	"github.com/rknightion/graph2otel/internal/signalcapture"
)

// TestMain enforces #112 over everything this package's tests emit: no
// metric label may carry per-entity data. The only metric labels this
// package emits are node_label, edge_label and twinned — NodeId, NodeName,
// EntityIds and every mapped property are twin-only. If this fails, the fix
// is to move the attribute off the metric, never to weaken the gate. See
// internal/signalcapture.
func TestMain(m *testing.M) { signalcapture.Main(m) }
