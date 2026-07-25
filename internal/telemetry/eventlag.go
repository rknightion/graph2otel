package telemetry

import (
	"time"

	"github.com/rknightion/graph2otel/internal/semconv"
)

const metricEventLag = "graph2otel.event.lag"

var eventLagBounds = []float64{1, 5, 15, 30, 60, 300, 900, 3600, 21600, 86400}

// eventLagEmitter measures the age of every timestamped log record immediately
// before handing it to the wrapped emitter. It does not infer a timestamp for
// undated records: zero time produces no observation.
type eventLagEmitter struct {
	Emitter
	collector        string
	tenant           string
	defaultTransport Transport
	now              func() time.Time
}

// WithEventLag returns an emitter that records source-event lag for one
// collector. A transport already stamped on the event wins over the collector's
// default, so an engine-specific stamp remains authoritative.
func WithEventLag(
	e Emitter,
	collector, tenant string,
	defaultTransport Transport,
	now func() time.Time,
) Emitter {
	if now == nil {
		now = time.Now
	}
	return &eventLagEmitter{
		Emitter:          e,
		collector:        collector,
		tenant:           tenant,
		defaultTransport: defaultTransport,
		now:              now,
	}
}

// gaugeSnapshotFor forwards the tenant scope carried by an outer WithTenant
// decorator. Every in-package Emitter decorator must preserve this private
// scope even when it otherwise passes metrics through unchanged.
func (e *eventLagEmitter) gaugeSnapshotFor(tenant, name, unit, desc string, points []GaugePoint) {
	snapshotFor(e.Emitter, tenant, name, unit, desc, points)
}

func (e *eventLagEmitter) LogEvent(ev Event) {
	if !ev.Timestamp.IsZero() {
		lag := e.now().Sub(ev.Timestamp).Seconds()
		if lag < 0 {
			lag = 0
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
		e.Histogram(
			metricEventLag,
			semconv.UnitSeconds,
			"Age of a source event when graph2otel handed its log record to the telemetry emitter.",
			lag,
			eventLagBounds,
			attrs,
		)
	}
	e.Emitter.LogEvent(ev)
}
