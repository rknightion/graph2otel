package o365pipeline

import (
	"testing"

	"github.com/rknightion/graph2otel/internal/telemetry"
)

// ActivityCollector's declared transport must match the value the underlying
// Collector stamps (telemetry.WithTransport(e, telemetry.TransportO365Activity),
// #141) — the admin page (#178) reads this accessor and it must not drift.
func TestActivityCollectorIngestTransport(t *testing.T) {
	if got := (&ActivityCollector{}).IngestTransport(); got != telemetry.TransportO365Activity {
		t.Errorf("IngestTransport() = %q, want %q", got, telemetry.TransportO365Activity)
	}
}
