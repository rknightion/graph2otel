package relatedtenants

import (
	"testing"

	"github.com/rknightion/graph2otel/internal/signalcapture"
)

// TestMain enforces #112 over everything this package's tests emit: no metric
// label may carry per-entity data. The only metric labels here are
// is_microsoft_infrastructure (a boolean), the metric-block kind and
// inbound/outbound direction — all closed sets — while every related tenant's
// own id and its per-relationship counters stay on the log twins. See
// internal/signalcapture.
func TestMain(m *testing.M) { signalcapture.Main(m) }
