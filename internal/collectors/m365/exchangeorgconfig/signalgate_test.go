package exchangeorgconfig

import (
	"testing"

	"github.com/rknightion/graph2otel/internal/signalcapture"
)

// TestMain enforces #112 over everything this package's tests emit: no metric
// label may carry per-entity data. The only label here is `setting`, whose value
// set is the fixed booleanSettings list in this package — never tenant data.
func TestMain(m *testing.M) { signalcapture.Main(m) }
