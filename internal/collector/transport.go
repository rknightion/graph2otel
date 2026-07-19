package collector

import "github.com/rknightion/graph2otel/internal/telemetry"

// TransportReporter is implemented by a collector that ingests over a specific
// transport engine (blob, o365_activity, audit_query, report_export) rather than
// a direct Graph poll. Each engine returns the SAME telemetry.Transport constant
// it stamps onto its records via telemetry.WithTransport (#141), so the value the
// admin page shows and the value on the log records cannot drift.
//
// A collector that polls Graph inline with no engine between it and the emitter
// (the SnapshotCollector twins — entra.risk is the reference shape) does NOT
// implement this; TransportOf reports graph for it, which is the truthful default
// the Scheduler also stamps as the baseline.
type TransportReporter interface {
	IngestTransport() telemetry.Transport
}

// TransportOf reports the ingest transport of a collector: its declared value if
// it is a TransportReporter, else telemetry.TransportGraph. It is how the admin
// status page states which transport a registered collector actually runs on
// (#178) without a second, drift-prone source of truth.
func TransportOf(c Collector) telemetry.Transport {
	if tr, ok := c.(TransportReporter); ok {
		return tr.IngestTransport()
	}
	return telemetry.TransportGraph
}
