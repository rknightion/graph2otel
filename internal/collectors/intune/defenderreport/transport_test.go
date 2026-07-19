package defenderreport

import (
	"testing"

	"github.com/rknightion/graph2otel/internal/telemetry"
)

// The collector's declared transport must match the value Collect stamps
// (telemetry.WithTransport(e, telemetry.TransportReportExport), #141) — the admin
// page (#178) reads this accessor and it must not drift from the stamp.
func TestCollectorIngestTransport(t *testing.T) {
	if got := (&Collector{}).IngestTransport(); got != telemetry.TransportReportExport {
		t.Errorf("IngestTransport() = %q, want %q", got, telemetry.TransportReportExport)
	}
}
