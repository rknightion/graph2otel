package jobpipeline

import (
	"testing"

	"github.com/rknightion/graph2otel/internal/telemetry"
)

// JobCollector's declared transport must match the value it stamps at
// CollectWindow (telemetry.WithTransport(e, telemetry.TransportAuditQuery), #141) —
// the admin page (#178) reads this accessor and it must not drift from the stamp.
func TestJobCollectorIngestTransport(t *testing.T) {
	if got := (&JobCollector{}).IngestTransport(); got != telemetry.TransportAuditQuery {
		t.Errorf("IngestTransport() = %q, want %q", got, telemetry.TransportAuditQuery)
	}
}
