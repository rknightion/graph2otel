package blobpipeline

import (
	"testing"

	"github.com/rknightion/graph2otel/internal/telemetry"
)

// BlobCollector's declared transport must match the value it stamps at Collect
// (telemetry.WithTransport(e, telemetry.TransportBlob), #141) — the admin page
// (#178) reads this accessor and it must not drift from the stamp.
func TestBlobCollectorIngestTransport(t *testing.T) {
	if got := (&BlobCollector{}).IngestTransport(); got != telemetry.TransportBlob {
		t.Errorf("IngestTransport() = %q, want %q", got, telemetry.TransportBlob)
	}
}
