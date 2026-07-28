package featureupdatedevices

import (
	"testing"

	"github.com/rknightion/graph2otel/internal/signalcapture"
)

// TestMain enforces #112 over everything this package's tests emit: no metric
// label may carry per-entity data (device_id, device_name, upn are all listed
// in signalcapture's perEntityKeys). See internal/signalcapture.
func TestMain(m *testing.M) { signalcapture.Main(m) }
