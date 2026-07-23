package exchangeremotedomains

import (
	"testing"

	"github.com/rknightion/graph2otel/internal/signalcapture"
)

// TestMain enforces #112 over everything this package's tests emit: no metric
// label may carry per-entity data. The domain NAME is per-entity and must stay
// on the log twin — only the bounded auto_forward_enabled flag is a label.
func TestMain(m *testing.M) { signalcapture.Main(m) }
