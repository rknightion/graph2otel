package discoveryparse

import (
	"testing"

	"github.com/rknightion/graph2otel/internal/signalcapture"
)

// TestMain enforces #112 over everything this package's tests emit: no metric
// label may carry per-entity data. The parse-health gauges are bounded to
// input_stream_id × template (both tenant-shaped, not tenant-sized); this gate
// keeps it that way. See internal/signalcapture.
func TestMain(m *testing.M) { signalcapture.Main(m) }
