package collector

import (
	"testing"
	"time"

	"github.com/rknightion/graph2otel/internal/telemetry"
)

// a collector that declares its ingest transport.
type transportReporterStub struct{ t telemetry.Transport }

func (transportReporterStub) Name() string                   { return "stub" }
func (transportReporterStub) DefaultInterval() time.Duration { return time.Minute }
func (s transportReporterStub) IngestTransport() telemetry.Transport {
	return s.t
}

// a collector that does NOT declare a transport (inline Graph poll, e.g. entra.risk).
type plainCollectorStub struct{}

func (plainCollectorStub) Name() string                   { return "plain" }
func (plainCollectorStub) DefaultInterval() time.Duration { return time.Minute }

func TestTransportOf(t *testing.T) {
	// A reporter's declared transport is returned verbatim.
	for _, want := range []telemetry.Transport{
		telemetry.TransportGraph,
		telemetry.TransportBlob,
		telemetry.TransportO365Activity,
		telemetry.TransportAuditQuery,
		telemetry.TransportReportExport,
	} {
		if got := TransportOf(transportReporterStub{t: want}); got != want {
			t.Errorf("TransportOf(reporter %q) = %q, want %q", want, got, want)
		}
	}

	// A collector that does not implement TransportReporter defaults to graph —
	// the truthful value for an inline Graph poll (entra.risk and the other
	// SnapshotCollector twins have no engine between them and the emitter).
	if got := TransportOf(plainCollectorStub{}); got != telemetry.TransportGraph {
		t.Errorf("TransportOf(plain) = %q, want %q", got, telemetry.TransportGraph)
	}
}
