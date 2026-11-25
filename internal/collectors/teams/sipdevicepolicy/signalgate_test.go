package sipdevicepolicy

import (
	"testing"

	"github.com/rknightion/graph2otel/internal/signalcapture"
)

// TestMain enforces #112 over everything this package's tests emit. This
// collector emits no metric of its own, so no label can carry tenant data.
func TestMain(m *testing.M) { signalcapture.Main(m) }
