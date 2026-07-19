package ediscoverycases

import (
	"testing"

	"github.com/rknightion/graph2otel/internal/signalcapture"
)

// TestMain enforces #112 over everything this package's tests emit: no metric
// label may carry per-entity data (case id/display name/description must stay in
// the log twin, never on the purview.ediscovery.cases gauge). See
// internal/signalcapture.
func TestMain(m *testing.M) { signalcapture.Main(m) }
