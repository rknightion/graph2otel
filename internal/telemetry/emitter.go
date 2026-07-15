package telemetry

import (
	"context"
	"fmt"
	"strings"
	"sync"

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
	if g != nil {
		g.Record(context.Background(), value, metric.WithAttributes(buildAttrs(attrs)...))
	}
}

// observableGauge holds the mutable snapshot behind one GaugeSnapshot
// instrument. The registered observable callback ranges points under mu;
// GaugeSnapshot replaces points under mu.
type observableGauge struct {
	mu     sync.Mutex
	points []obsPoint
}

type obsPoint struct {
	value float64
	kvs   []attribute.KeyValue
}

func (e *otelEmitter) GaugeSnapshot(name, unit, desc string, points []GaugePoint) {
	// Resolve every point's attributes outside e.mu / the callback so
	// collection is never blocked on attribute resolution.
	resolved := make([]obsPoint, 0, len(points))
	for _, p := range points {
		e.card.Observe(name, p.Attrs)
		resolved = append(resolved, obsPoint{value: p.Value, kvs: buildAttrs(p.Attrs)})
	}

	e.mu.Lock()
	og, ok := e.observables[name]
	if !ok {
		og = &observableGauge{}
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
				for i := range og.points {
					o.Observe(og.points[i].value, metric.WithAttributes(og.points[i].kvs...))
				}
				return nil
			}))
		if err != nil {
			otel.Handle(err)
		}
	}
	e.mu.Unlock()

	og.mu.Lock()
	og.points = resolved
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
