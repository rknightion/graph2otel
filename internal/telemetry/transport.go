package telemetry

import (
	"maps"

	"github.com/rknightion/graph2otel/internal/semconv"
)

// Transport names the ingest path that produced a record. It is the value set of
// the semconv.AttrIngestTransport attribute (#141).
//
// The set is closed and bounded (six values), which is what makes the attribute
// safe under the cardinality rule (#112): it never grows with tenant size.
type Transport string

const (
	// TransportGraph is a direct Graph poll. It covers TWO code paths — the
	// logpipeline window engine, and the 15 SnapshotCollectors that call
	// LogEvent directly without any engine (entra/risk is the reference shape).
	// That is deliberate: this names the transport, not the engine, and both
	// paths are the same transport.
	TransportGraph Transport = "graph"
	// TransportBlob is the Azure Storage byte-offset consumer (internal/blobpipeline).
	TransportBlob Transport = "blob"
	// TransportO365Activity is the O365 Management Activity API subscription /
	// content-blob feed (internal/o365pipeline).
	TransportO365Activity Transport = "o365_activity"
	// TransportAuditQuery is the M365 async audit-query job engine (internal/jobpipeline).
	TransportAuditQuery Transport = "audit_query"
	// TransportReportExport is the Intune reports-export job engine (internal/exportjob).
	TransportReportExport Transport = "report_export"
	// TransportMDCA is the Microsoft Defender for Cloud Apps (MDCA) legacy portal
	// API — the Cloud Discovery governance log (#145). It has no ingest engine: the
	// mdca.discovery_parse WindowCollector polls the static-token portal API and
	// stamps this transport inline, the same way the 15 engineless SnapshotCollectors
	// carry TransportGraph. It is NOT a Graph transport (different host, static
	// Authorization: Token auth, no azidentity).
	TransportMDCA Transport = "mdca"
)

// transportEmitter stamps semconv.AttrIngestTransport onto every log record
// passing through it, delegating everything else to the wrapped Emitter.
type transportEmitter struct {
	Emitter
	transport Transport
}

// WithTransport returns an Emitter that stamps every log record it emits with
// the transport that produced it (semconv.AttrIngestTransport).
//
// Why this wraps the EMITTER rather than living in the four ingest engines: the
// engines are not the only things that emit. Fifteen SnapshotCollectors call
// LogEvent directly with no engine involved, so stamping "in the four engines"
// would leave a quarter of the collectors silently unstamped — and an absent
// provenance attribute reads as "not that transport" rather than "not stamped",
// which is a worse lie than having no attribute at all (#141). The Emitter is
// the only boundary with nothing behind it: there is exactly one LogEvent
// implementation and every path funnels through it, so a stamp here cannot be
// escaped by a transport added later.
//
// Metrics pass through untouched. Provenance is deliberately log-only: adding a
// label to an existing metric changes its series identity and would break the
// dashboards and alerts built on the current names (#82), whereas a log
// attribute is Loki structured metadata (#90) and is additive.
//
// The returned Emitter never mutates the caller's Attrs map. mapSignIn is
// deliberately ONE mapper shared by the Graph and blob transports, so its output
// map can be live in two decorated emitters at once; stamping in place would
// race and cross the values (see TestWithTransportIsConcurrencySafe).
func WithTransport(e Emitter, t Transport) Emitter {
	return &transportEmitter{Emitter: e, transport: t}
}

// LogEvent stamps the transport and delegates. It copies ev.Attrs rather than
// writing into it — see WithTransport for why that copy is load-bearing.
//
// PRECEDENCE: the OUTERMOST stamp wins — an already-stamped record passes
// through unchanged. This is what makes the two-layer wiring correct. The
// Scheduler hands every collector one emitter wrapped as TransportGraph, which
// is the truthful default for the 15 SnapshotCollectors that poll Graph and emit
// inline with no engine. An ingest engine (blob, o365, audit-query,
// report-export) wraps that emitter again at its own LogEvent site, and since
// the engine's wrapper is outermost it stamps first and the Scheduler's inner
// TransportGraph must not clobber it.
//
// The known limit of this shape: a FUTURE non-Graph engine that forgets to wrap
// inherits the Scheduler's "graph" rather than failing loudly. That is the one
// silent-mislabel path left, and it is why TestEveryEngineStampsItsOwnTransport
// exists — add an engine, add its case there.
func (e *transportEmitter) LogEvent(ev Event) {
	if _, stamped := ev.Attrs[semconv.AttrIngestTransport]; stamped {
		e.Emitter.LogEvent(ev)
		return
	}
	stamped := make(Attrs, len(ev.Attrs)+1)
	maps.Copy(stamped, ev.Attrs)
	stamped[semconv.AttrIngestTransport] = string(e.transport)
	ev.Attrs = stamped
	e.Emitter.LogEvent(ev)
}
