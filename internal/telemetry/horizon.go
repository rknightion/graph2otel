package telemetry

import (
	"time"

	"github.com/rknightion/graph2otel/internal/semconv"
)

const metricOverHorizon = "graph2otel.event.over_horizon"

// EventHorizon is how old a log record's event time may be and still be worth
// sending. Anything older is rejected by the backend, so emitting it is a
// guaranteed loss dressed up as a delivery.
//
// 165h (6d21h) is Grafana Cloud's measured 7-day accept window minus a
// deliberate 3-hour margin. The margin is the point, not padding: the rejection
// observed in production on 2026-07-27 was only about ONE HOUR past the limit —
//
//	entry for stream '{service_name="graph2otel"}' has timestamp too old:
//	2026-07-20T18:15:15Z, oldest acceptable timestamp is: 2026-07-20T19:21:56Z
//
// so a guard set at exactly 7 days would still lose records to clock skew, queue
// latency, and the gap between a record being read and being flushed.
//
// This is not a hypothetical edge. It fires on a DEFAULT configuration, because
// the source is blob ingest replaying historical records rather than a mis-set
// backfill window: #297 measured graph2otel's blob-ingested Intune stream at
// 3.31 days old at the newest, 5.97 median and 6.95 oldest (n=223). A stream
// whose oldest records already sit at 6.95 days crosses a 7-day window
// continuously, by ordinary aging, with nothing misconfigured anywhere.
const EventHorizon = 165 * time.Hour

// horizonEmitter drops log records whose event time is older than the horizon,
// counting each drop, and passes everything else through untouched.
//
// Why here and not in the engines: this is the only boundary every record
// crosses. Fifteen collectors emit with no engine at all, and the records that
// actually trigger this are blob-replayed ones, which no window-polling logic
// sees as late. A per-engine guard would cover the paths that do not need it and
// miss the one that does.
//
// Why drop rather than send and let the backend refuse: the backend refuses
// per-entry with an HTTP 400 while accepting in-window entries from the same
// batch, so the record is lost either way. Dropping it here makes the loss
// countable and attributable instead of leaving it as a line in an error log.
// This is the same call the emitter already makes for a record with no parseable
// event time — a record that cannot be delivered correctly is not sent.
//
// It does NOT restamp. Stamping an over-age record to "now" would make it
// deliverable and WRONG: it would claim an event happened hours or days after it
// did. Undedupeable is degraded; misdated is wrong, and only wrong justifies a
// drop.
//
// One honest caveat about accounting: the owning collector has already counted
// this record as emitted by the time it reaches here, so `record_outcomes` will
// over-report delivery by exactly the number of over-horizon drops.
// `graph2otel.event.over_horizon` is the authoritative statement that those
// records did not reach the backend. Reconciling the two would mean moving this
// guard into every engine, which is precisely the coverage gap above.
type horizonEmitter struct {
	Emitter
	horizon          time.Duration
	collector        string
	tenant           string
	defaultTransport Transport
	now              func() time.Time
}

// WithEventHorizon returns an emitter that refuses to send log records older
// than horizon. A zero or negative horizon disables the guard, which is what a
// self-hosted Loki or a non-Loki OTLP sink with a wider accept window wants.
func WithEventHorizon(
	e Emitter,
	horizon time.Duration,
	collector, tenant string,
	defaultTransport Transport,
	now func() time.Time,
) Emitter {
	if now == nil {
		now = time.Now
	}
	return &horizonEmitter{
		Emitter:          e,
		horizon:          horizon,
		collector:        collector,
		tenant:           tenant,
		defaultTransport: defaultTransport,
		now:              now,
	}
}

// gaugeSnapshotFor forwards the tenant scope carried by an outer WithTenant
// decorator. Every in-package Emitter decorator must preserve this private
// scope even when it otherwise passes metrics through unchanged.
func (e *horizonEmitter) gaugeSnapshotFor(tenant, name, unit, desc string, points []GaugePoint) {
	snapshotFor(e.Emitter, tenant, name, unit, desc, points)
}

func (e *horizonEmitter) LogEvent(ev Event) {
	if e.horizon <= 0 || ev.Timestamp.IsZero() {
		// An undated record is not this guard's business: it has no event time to
		// judge, and dropping it is already handled where the event time is parsed.
		e.Emitter.LogEvent(ev)
		return
	}
	if e.now().Sub(ev.Timestamp) <= e.horizon {
		e.Emitter.LogEvent(ev)
		return
	}

	transport := e.defaultTransport
	if stamped, ok := ev.Attrs[semconv.AttrIngestTransport].(string); ok && stamped != "" {
		transport = Transport(stamped)
	}
	attrs := Attrs{
		semconv.AttrCollector:       e.collector,
		semconv.AttrIngestTransport: string(transport),
	}
	if e.tenant != "" {
		attrs[semconv.AttrTenantID] = e.tenant
	}
	// Deliberately NOT attributed by event name: that would put a per-signal
	// dimension on a metric whose whole job is to be cheap enough to always be on,
	// and the collector already identifies which stream is affected.
	e.Counter(
		metricOverHorizon,
		semconv.UnitRecords,
		"Log records dropped because their event time was older than the backend's accept window, "+
			"so sending them would have been rejected per-entry and lost anyway.",
		1,
		attrs,
	)
}
