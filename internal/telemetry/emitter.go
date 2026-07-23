package telemetry

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"sync/atomic"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/log"
	"go.opentelemetry.io/otel/metric"
)

// otelEmitter implements Emitter on top of the OpenTelemetry Go SDK.
type otelEmitter struct {
	meter  metric.Meter
	logger log.Logger

	// card counts distinct attribute combinations per source metric for the
	// graph2otel.series.active self-metric. Nil disables tracking; Observe is
	// nil-safe so the emit path needs no guard.
	card *CardinalityTracker

	// metricPoints/logRecords are lifetime totals of everything that has passed
	// through this emitter, read by the admin status page's throughput sampler
	// (#227) and never exported as OTLP. They are plain atomics on purpose: the
	// emit path is hot, and a lock or an allocation here would be paid on every
	// data point for a number nobody outside the status page reads.
	metricPoints atomic.Uint64
	logRecords   atomic.Uint64

	mu          sync.Mutex
	counters    map[string]metric.Float64Counter
	gauges      map[string]metric.Float64Gauge
	updowns     map[string]metric.Float64UpDownCounter
	histograms  map[string]metric.Float64Histogram
	observables map[string]*observableGauge // GaugeSnapshot instruments, by name
}

// NewEmitter returns an Emitter that records to the given meter and logger,
// without cardinality self-tracking.
func NewEmitter(meter metric.Meter, logger log.Logger) Emitter {
	return newOtelEmitter(meter, logger, nil)
}

// newOtelEmitter returns an *otelEmitter wired to the given meter, logger, and
// (optional) cardinality tracker. A nil card disables series.active tracking.
func newOtelEmitter(meter metric.Meter, logger log.Logger, card *CardinalityTracker) *otelEmitter {
	return &otelEmitter{
		meter:       meter,
		logger:      logger,
		card:        card,
		counters:    map[string]metric.Float64Counter{},
		gauges:      map[string]metric.Float64Gauge{},
		updowns:     map[string]metric.Float64UpDownCounter{},
		histograms:  map[string]metric.Float64Histogram{},
		observables: map[string]*observableGauge{},
	}
}

// Throughput is a lifetime count of what an emitter has shipped: metric data
// points (one per Counter/Gauge/UpDownCounter/Histogram call, and one per
// series in a GaugeSnapshot) and log records (one per LogEvent). Both are
// cumulative and monotonic — reading them never resets them, so a caller
// differences consecutive reads to get a rate.
//
// This is in-process introspection for the admin status page (#227). It is
// deliberately never emitted as OTLP: the wire already carries the
// graph2otel.* self-observability metrics.
type Throughput struct {
	MetricPoints uint64
	LogRecords   uint64
}

// Throughput returns the emitter's cumulative emitted-record counts.
func (e *otelEmitter) Throughput() Throughput {
	return Throughput{
		MetricPoints: e.metricPoints.Load(),
		LogRecords:   e.logRecords.Load(),
	}
}

func (e *otelEmitter) Counter(name, unit, desc string, add float64, attrs Attrs) {
	e.mu.Lock()
	c, ok := e.counters[name]
	if !ok {
		var err error
		c, err = e.meter.Float64Counter(name, metric.WithUnit(unit), metric.WithDescription(desc))
		if err != nil {
			otel.Handle(err)
		}
		e.counters[name] = c
	}
	e.mu.Unlock()
	e.card.Observe(name, attrs)
	e.metricPoints.Add(1)
	if c != nil {
		c.Add(context.Background(), add, metric.WithAttributes(buildAttrs(attrs)...))
	}
}

func (e *otelEmitter) Gauge(name, unit, desc string, value float64, attrs Attrs) {
	e.mu.Lock()
	g, ok := e.gauges[name]
	if !ok {
		var err error
		g, err = e.meter.Float64Gauge(name, metric.WithUnit(unit), metric.WithDescription(desc))
		if err != nil {
			otel.Handle(err)
		}
		e.gauges[name] = g
	}
	e.mu.Unlock()
	e.card.Observe(name, attrs)
	e.metricPoints.Add(1)
	if g != nil {
		g.Record(context.Background(), value, metric.WithAttributes(buildAttrs(attrs)...))
	}
}

// observableGauge holds the mutable snapshot behind one GaugeSnapshot
// instrument. The registered observable callback ranges points under mu;
// a snapshot replaces one tenant's entry under mu.
//
// The point sets are PARTITIONED BY TENANT (#236). There is exactly one
// otelEmitter for the process and WithTenant merely decorates it, so state keyed
// by metric name alone meant the second tenant to poll replaced the first
// tenant's series for that metric — silently, and looking like flapping data
// rather than a bug. The instrument itself is still registered exactly once per
// name (registering Float64ObservableGauge twice for one name is its own
// problem), so the split lives here, inside the state, and the callback ranges
// every tenant's set.
//
// A single-tenant deploy uses the one "" key throughout — WithTenant("") is a
// passthrough — so its behavior is unchanged.
type observableGauge struct {
	mu sync.Mutex
	// points is one complete snapshot per tenant, keyed by the tenant the
	// WithTenant decorator passed through. Map iteration order in the callback is
	// unspecified and does not matter: two tenants' attribute sets differ by
	// tenant_id, so no two entries observe the same series.
	points map[string][]obsPoint
}

type obsPoint struct {
	value float64
	kvs   []attribute.KeyValue
}

// tenantSnapshotter is the tenant-scoped form of Emitter.GaugeSnapshot (#236).
//
// The tenant cannot be recovered from the points: an EMPTY snapshot is the
// documented way to clear a metric, and it carries no attributes to read a
// tenant out of. So the tenant travels as an argument from the one decorator
// that knows it, and every decorator in this package forwards it.
//
// The method is deliberately unexported: the only types that can implement it
// are the ones in this package, which is exactly the set of decorators the
// composition root wires together. Anything else — a test double, a wrapper in
// another package — falls back to plain GaugeSnapshot and gets the historical
// single-bucket behavior rather than a compile error.
// TestEveryEmitterDecoratorForwardsTheSnapshotTenant is the gate that keeps the
// in-package set complete.
type tenantSnapshotter interface {
	gaugeSnapshotFor(tenant, name, unit, desc string, points []GaugePoint)
}

// otelEmitter is the end of the chain — the only implementation that actually
// partitions state — so its conformance is asserted here rather than by the AST
// gate, which walks the decorators (the types that EMBED Emitter).
var _ tenantSnapshotter = (*otelEmitter)(nil)

// snapshotFor forwards a tenant-scoped snapshot to the next emitter in the
// chain, degrading to the unscoped call for an emitter that does not carry the
// scope.
func snapshotFor(e Emitter, tenant, name, unit, desc string, points []GaugePoint) {
	if ts, ok := e.(tenantSnapshotter); ok {
		ts.gaugeSnapshotFor(tenant, name, unit, desc, points)
		return
	}
	e.GaugeSnapshot(name, unit, desc, points)
}

// GaugeSnapshot records an unscoped snapshot: the single-tenant shape, where
// WithTenant is a passthrough and every snapshot shares the one "" partition.
func (e *otelEmitter) GaugeSnapshot(name, unit, desc string, points []GaugePoint) {
	e.gaugeSnapshotFor("", name, unit, desc, points)
}

func (e *otelEmitter) gaugeSnapshotFor(tenant, name, unit, desc string, points []GaugePoint) {
	// Resolve every point's attributes outside e.mu / the callback so
	// collection is never blocked on attribute resolution.
	resolved := make([]obsPoint, 0, len(points))
	for _, p := range points {
		e.card.Observe(name, p.Attrs)
		resolved = append(resolved, obsPoint{value: p.Value, kvs: buildAttrs(p.Attrs)})
	}
	e.metricPoints.Add(uint64(len(points)))

	e.mu.Lock()
	og, ok := e.observables[name]
	if !ok {
		og = &observableGauge{points: map[string][]obsPoint{}}
		e.observables[name] = og
		// Register the observable gauge once. Its callback reports exactly the
		// current snapshot; under cumulative temporality an observable gauge uses
		// the SDK's precomputed-last-value aggregation, which reports only the
		// sets observed this cycle — so a series dropped from a later snapshot
		// disappears from the export instead of ghosting.
		_, err := e.meter.Float64ObservableGauge(name,
			metric.WithUnit(unit), metric.WithDescription(desc),
			metric.WithFloat64Callback(func(_ context.Context, o metric.Float64Observer) error {
				og.mu.Lock()
				defer og.mu.Unlock()
				for _, pts := range og.points {
					for i := range pts {
						o.Observe(pts[i].value, metric.WithAttributes(pts[i].kvs...))
					}
				}
				return nil
			}))
		if err != nil {
			otel.Handle(err)
		}
	}
	e.mu.Unlock()

	// Replace only this tenant's partition. An empty snapshot therefore clears
	// the snapshotting tenant and leaves every other tenant's series standing,
	// which is the whole point of carrying the tenant as an argument.
	og.mu.Lock()
	og.points[tenant] = resolved
	og.mu.Unlock()
}

func (e *otelEmitter) UpDownCounter(name, unit, desc string, value float64, attrs Attrs) {
	e.mu.Lock()
	u, ok := e.updowns[name]
	if !ok {
		var err error
		u, err = e.meter.Float64UpDownCounter(name, metric.WithUnit(unit), metric.WithDescription(desc))
		if err != nil {
			otel.Handle(err)
		}
		e.updowns[name] = u
	}
	e.mu.Unlock()
	e.card.Observe(name, attrs)
	e.metricPoints.Add(1)
	if u != nil {
		u.Add(context.Background(), value, metric.WithAttributes(buildAttrs(attrs)...))
	}
}

func (e *otelEmitter) Histogram(name, unit, desc string, value float64, bounds []float64, attrs Attrs) {
	e.HistogramCtx(context.Background(), name, unit, desc, value, bounds, attrs)
}

func (e *otelEmitter) HistogramCtx(ctx context.Context, name, unit, desc string, value float64, bounds []float64, attrs Attrs) {
	e.mu.Lock()
	h, ok := e.histograms[name]
	if !ok {
		var err error
		h, err = e.meter.Float64Histogram(name,
			metric.WithUnit(unit), metric.WithDescription(desc),
			metric.WithExplicitBucketBoundaries(bounds...))
		if err != nil {
			otel.Handle(err)
		}
		e.histograms[name] = h
	}
	e.mu.Unlock()
	e.card.Observe(name, attrs)
	e.metricPoints.Add(1)
	if h != nil {
		h.Record(ctx, value, metric.WithAttributes(buildAttrs(attrs)...))
	}
}

func (e *otelEmitter) LogEvent(ev Event) {
	var r log.Record
	if !ev.Timestamp.IsZero() {
		r.SetTimestamp(ev.Timestamp)
	}
	r.SetSeverity(toLogSeverity(ev.Severity))
	r.SetSeverityText(ev.Severity.String())
	r.SetBody(log.StringValue(ev.Body))
	// The log SDK exposes a native EventName field (log v0.20.0+); use it
	// instead of carrying the event type as a separate "event.name" attribute.
	if ev.Name != "" {
		r.SetEventName(ev.Name)
	}
	r.AddAttributes(toLogKV(ev.Attrs)...)
	e.logger.Emit(context.Background(), r)
	e.logRecords.Add(1)
}

func toLogSeverity(s Severity) log.Severity {
	switch s {
	case SeverityWarn:
		return log.SeverityWarn
	case SeverityError:
		return log.SeverityError
	default:
		return log.SeverityInfo
	}
}

// toLogKV converts an Attrs map to OTEL log attributes.
func toLogKV(attrs Attrs) []log.KeyValue {
	if len(attrs) == 0 {
		return nil
	}
	kvs := make([]log.KeyValue, 0, len(attrs))
	for k, v := range attrs {
		switch val := v.(type) {
		case string:
			kvs = append(kvs, log.String(k, val))
		case bool:
			kvs = append(kvs, log.Bool(k, val))
		case int:
			kvs = append(kvs, log.Int64(k, int64(val)))
		case int64:
			kvs = append(kvs, log.Int64(k, val))
		case float64:
			kvs = append(kvs, log.Float64(k, val))
		case []string:
			kvs = append(kvs, log.String(k, strings.Join(val, ",")))
		default:
			kvs = append(kvs, log.String(k, fmt.Sprint(val)))
		}
	}
	return kvs
}

// buildAttrs converts attrs to OTEL metric attributes. graph2otel has no
// Prometheus pull endpoint (OTLP push only, see CLAUDE.md), so — unlike a
// scrape target — there is no promoted-resource-label namespace a data-point
// attribute could collide with; a plain per-key conversion is enough.
func buildAttrs(attrs Attrs) []attribute.KeyValue {
	if len(attrs) == 0 {
		return nil
	}
	kvs := make([]attribute.KeyValue, 0, len(attrs))
	for k, v := range attrs {
		kvs = append(kvs, kvFor(k, v))
	}
	return kvs
}

// kvFor converts a single Attrs value to an OTEL attribute, mirroring the
// value types documented on Attrs.
func kvFor(k string, v any) attribute.KeyValue {
	switch val := v.(type) {
	case string:
		return attribute.String(k, val)
	case bool:
		return attribute.Bool(k, val)
	case int:
		return attribute.Int(k, val)
	case int64:
		return attribute.Int64(k, val)
	case float64:
		return attribute.Float64(k, val)
	case []string:
		return attribute.StringSlice(k, val)
	default:
		return attribute.String(k, fmt.Sprint(val))
	}
}
