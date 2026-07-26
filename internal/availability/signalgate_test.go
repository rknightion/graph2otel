package availability

import (
	"testing"

	"github.com/rknightion/graph2otel/internal/signalcapture"
)

// TestMain gates the availability metric from the package that owns its
// production emitter. Tracker tests exercise the real GaugeSnapshot path.
func TestMain(m *testing.M) { signalcapture.Main(m) }
