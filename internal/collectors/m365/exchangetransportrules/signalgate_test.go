package exchangetransportrules

import (
	"testing"

	"github.com/rknightion/graph2otel/internal/signalcapture"
)

// TestMain enforces #112 over everything this package's tests emit: no metric
// label may carry per-entity data. A rule's name, its author and every recipient
// it diverts mail to are per-rule and must stay on the log twin.
func TestMain(m *testing.M) { signalcapture.Main(m) }
