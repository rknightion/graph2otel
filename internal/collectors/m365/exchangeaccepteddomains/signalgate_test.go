package exchangeaccepteddomains

import (
	"testing"

	"github.com/rknightion/graph2otel/internal/signalcapture"
)

// TestMain enforces #112 over everything this package's tests emit: no metric
// label may carry per-entity data. The domain NAME is per-entity and must stay
// on the log twin — only the bounded domain_type / is_default_domain labels
// are ever metric labels.
func TestMain(m *testing.M) { signalcapture.Main(m) }
