package pstngateways

import (
	"testing"

	"github.com/rknightion/graph2otel/internal/signalcapture"
)

// TestMain enforces #112 over everything this package's tests emit. The only
// label on teams.pstn_gateway.count is enabled, whose values are the fixed set
// true, false and unknown, never tenant data.
func TestMain(m *testing.M) { signalcapture.Main(m) }
