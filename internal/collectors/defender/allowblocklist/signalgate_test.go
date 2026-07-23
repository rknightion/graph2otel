package allowblocklist

import (
	"testing"

	"github.com/rknightion/graph2otel/internal/signalcapture"
)

// TestMain enforces #112 over everything this package's tests emit: no metric
// label may carry per-entity data. The entry VALUE (a domain, address, hash or
// IP), who set it and its notes are per-entity and must stay on the log twin.
func TestMain(m *testing.M) { signalcapture.Main(m) }
