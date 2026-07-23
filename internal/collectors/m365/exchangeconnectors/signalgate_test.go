package exchangeconnectors

import (
	"testing"

	"github.com/rknightion/graph2otel/internal/signalcapture"
)

// TestMain enforces #112 over everything this package's tests emit: no metric
// label may carry per-entity data. A connector's name, its sender IPs, its
// trusted domains and its certificate name all identify one entity and stay on
// the log twin — only the bounded direction / enabled / require-TLS axes are
// labels.
func TestMain(m *testing.M) { signalcapture.Main(m) }
