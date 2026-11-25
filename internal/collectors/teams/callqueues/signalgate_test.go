package callqueues

import (
	"testing"

	"github.com/rknightion/graph2otel/internal/signalcapture"
)

// TestMain enforces #112 over what this package's tests emit. The only metric
// label is routing_method, whose values are the five enum names plus "unknown".
func TestMain(m *testing.M) { signalcapture.Main(m) }
