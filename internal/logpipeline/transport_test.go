package logpipeline

import (
	"testing"

	"github.com/rknightion/graph2otel/internal/telemetry"
)

// LogCollector's declared transport must match the value it stamps at
// CollectWindow (telemetry.WithTransport(e, telemetry.TransportGraph), #141) —
// the admin page (#178) reads this accessor and it must not drift from the stamp.
func TestLogCollectorIngestTransport(t *testing.T) {
	if got := (&LogCollector{}).IngestTransport(); got != telemetry.TransportGraph {
		t.Errorf("IngestTransport() = %q, want %q", got, telemetry.TransportGraph)
	}
}
