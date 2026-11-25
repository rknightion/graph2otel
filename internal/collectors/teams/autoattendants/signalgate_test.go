package autoattendants

import (
	"testing"

	"github.com/rknightion/graph2otel/internal/signalcapture"
)

// TestMain enforces #112 over what this package's tests emit. The collector has
// no metrics, so nothing here can carry per-entity data on a metric label.
func TestMain(m *testing.M) { signalcapture.Main(m) }
