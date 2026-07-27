package annotations

import (
	"context"

	"github.com/rknightion/graph2otel/internal/telemetry"
)

// teeEmitter forwards every call to the wrapped Emitter unchanged and, on the
// two methods the curated rules read, ALSO offers the record to the Recorder.
//
// # Why the emitter and not the collectors
//
// Same reason telemetry.WithTenant and telemetry.WithTransport wrap here: the
// Emitter is the only boundary with nothing behind it. Fifteen SnapshotCollectors
// emit log records with no engine involved, so hooking "the ingest engines" would
// miss a quarter of them; hooking the emitter covers every collector, including
// ones added later, and cannot be escaped. #400's hard constraint — publish from
// what collectors ALREADY emit, add no Graph polling — is satisfied structurally
// rather than by discipline: there is no Graph client in this package.
//
// # Every method is overridden explicitly
//
// An un-overridden method would be PROMOTED from the embedded Emitter and
// compile perfectly, which is exactly how tenantEmitter's tests describe the
// failure they exist to prevent. Only LogEvent and GaugeSnapshot do anything
// extra; the rest are explicit pass-throughs so a reader can see that the
// forwarding is total and TestEveryEmitterMethodIsForwarded can parse it.
//
// # It never mutates and never drops
//
// The record is forwarded FIRST, unchanged, before the Recorder sees it. Nothing
// in this package can drop a record, alter an attribute, or return an error into
// the collector — an annotation writer that could would have turned a dashboard
// nicety into a data-loss path.
type teeEmitter struct {
	telemetry.Emitter
	recorder *Recorder
	run      runID
}

// Tee returns an Emitter that forwards everything to base and derives
// annotations from the curated set of records passing through it. run identifies
// the collector run, which is what lets a state stream prime over exactly one
// tick.
func Tee(base telemetry.Emitter, recorder *Recorder, run runID) telemetry.Emitter {
	if base == nil || recorder == nil {
		return base
	}
	return &teeEmitter{Emitter: base, recorder: recorder, run: run}
}

func (e *teeEmitter) Counter(name, unit, desc string, add float64, attrs telemetry.Attrs) {
	e.Emitter.Counter(name, unit, desc, add, attrs)
}

func (e *teeEmitter) Gauge(name, unit, desc string, value float64, attrs telemetry.Attrs) {
	e.Emitter.Gauge(name, unit, desc, value, attrs)
}

func (e *teeEmitter) GaugeSnapshot(name, unit, desc string, points []telemetry.GaugePoint) {
	e.Emitter.GaugeSnapshot(name, unit, desc, points)
	e.recorder.ObserveGaugeSnapshot(e.run, name, points)
}

func (e *teeEmitter) UpDownCounter(name, unit, desc string, value float64, attrs telemetry.Attrs) {
	e.Emitter.UpDownCounter(name, unit, desc, value, attrs)
}

func (e *teeEmitter) Histogram(name, unit, desc string, value float64, bounds []float64, attrs telemetry.Attrs) {
	e.Emitter.Histogram(name, unit, desc, value, bounds, attrs)
}

func (e *teeEmitter) HistogramCtx(ctx context.Context, name, unit, desc string, value float64,
	bounds []float64, attrs telemetry.Attrs,
) {
	e.Emitter.HistogramCtx(ctx, name, unit, desc, value, bounds, attrs)
}

func (e *teeEmitter) LogEvent(ev telemetry.Event) {
	e.Emitter.LogEvent(ev)
	e.recorder.ObserveEvent(e.run, ev)
}
