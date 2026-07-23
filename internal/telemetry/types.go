// Package telemetry is the OTEL-agnostic facade that collectors use to record
// metrics and emit log events. The concrete implementation (provider.go,
// emitter.go) wraps the OpenTelemetry Go SDK and owns all OTLP export detail;
// collectors depend only on the Emitter interface defined here, so exporter/SDK
// types never leak into collector code and every collector is unit-testable
// against the in-memory recorder in internal/telemetrytest.
//
// This file is the frozen cross-package seam for M1: the Emitter interface and
// its value types are the contract the collector framework (#6), self-obs (#9),
// and every M2-M5 collector emit through. Do not change a signature here
// without treating it as a seam change across every consumer.
package telemetry

import (
	"context"
	"time"
)

// Attrs is a set of attributes attached to a metric data point or log record.
// Supported value types: string, bool, int, int64, float64, []string.
type Attrs map[string]any

// Severity is the log severity level for an Event.
type Severity int

const (
	// SeverityInfo is the default, informational severity.
	SeverityInfo Severity = iota
	// SeverityWarn indicates a warning-level event.
	SeverityWarn
	// SeverityError indicates an error-level event.
	SeverityError
)

// String returns the canonical severity text (INFO/WARN/ERROR).
func (s Severity) String() string {
	switch s {
	case SeverityWarn:
		return "WARN"
	case SeverityError:
		return "ERROR"
	default:
		return "INFO"
	}
}

// Event is a single log record to emit.
type Event struct {
	Name      string // OTEL LogRecord EventName, e.g. "entra.signin"
	Body      string // human-readable summary
	Severity  Severity
	Timestamp time.Time // event time; zero means "now"
	Attrs     Attrs
}

// GaugePoint is one series in a GaugeSnapshot: a value and the attributes that
// identify its time series.
type GaugePoint struct {
	Value float64
	Attrs Attrs
}

// Emitter records metrics and log events. Implementations must be safe for
// concurrent use. Instruments are created lazily and cached by name.
type Emitter interface {
	// Counter adds to a monotonic Float64 counter (e.g. events processed).
	Counter(name, unit, desc string, add float64, attrs Attrs)
	// Gauge records the current value of a synchronous Float64 gauge.
	Gauge(name, unit, desc string, value float64, attrs Attrs)
	// GaugeSnapshot records the COMPLETE current set of series for an observable
	// Float64 gauge, atomically replacing any prior snapshot for name (passing an
	// empty slice clears it). Unlike Gauge — a synchronous instrument whose
	// cumulative series linger at their last value forever under Grafana Cloud's
	// forced cumulative temporality (upstream otel-go #3006) — this registers an
	// OBSERVABLE gauge: a series absent from a later snapshot drops out of the
	// export on the next collection, because the SDK's precomputed-last-value
	// aggregation reports only what the callback observes each cycle. Use it for
	// per-entity gauges whose attribute set churns (per-user, per-device,
	// per-policy) so a removed/renamed entity does not leave a ghost series (and
	// does not permanently consume a cardinality-limit slot). The caller owns
	// producing the full current set each interval; a collector that stops
	// snapshotting leaves the last set in place until it resumes.
	//
	// "Replaces the prior snapshot" is scoped PER TENANT (#236): one emitter
	// serves every configured tenant, and a snapshot through a WithTenant-wrapped
	// emitter replaces only that tenant's set, leaving the other tenants' series
	// standing. A single-tenant deploy — where WithTenant is a passthrough — has
	// one set, so the rule reads exactly as it always did.
	GaugeSnapshot(name, unit, desc string, points []GaugePoint)
	// UpDownCounter adds (or subtracts) to a non-monotonic counter.
	UpDownCounter(name, unit, desc string, value float64, attrs Attrs)
	// Histogram records value into a Float64 histogram with the given explicit
	// bucket boundaries. The bounds are honored only when the instrument is first
	// created (instruments are cached by name); pass the same bounds on every call
	// for a given metric name. Equivalent to HistogramCtx with context.Background().
	Histogram(name, unit, desc string, value float64, bounds []float64, attrs Attrs)
	// HistogramCtx records like Histogram but uses ctx as the recording context,
	// so the metric SDK can attach a trace exemplar when ctx carries a sampled
	// span. Histogram is exactly HistogramCtx with context.Background().
	HistogramCtx(ctx context.Context, name, unit, desc string, value float64, bounds []float64, attrs Attrs)
	// LogEvent emits a single OTEL log record.
	LogEvent(ev Event)
}
