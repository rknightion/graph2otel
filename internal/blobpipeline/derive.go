package blobpipeline

import (
	"time"

	"github.com/rknightion/graph2otel/internal/telemetry"
)

// MetricKind is how a derived MetricPoint is emitted.
type MetricKind int

const (
	// MetricCounter is a monotonic cumulative counter (Emitter.Counter).
	MetricCounter MetricKind = iota
	// MetricNativeHistogram is a base-2 exponential (native) histogram; the
	// aggregation is supplied by a View (fast-follow F2). Core does not derive
	// these — the routing case exists so a later lane adds it without touching
	// the gate.
	MetricNativeHistogram
)

// MetricPoint is one bounded metric increment derived from a blob record. Attrs
// must be bounded/tenant-shaped (#112); per-entity fields (ids, UPN, appId, IP,
// raw URI) stay log attributes and never appear here.
type MetricPoint struct {
	Name  string
	Kind  MetricKind
	Unit  string
	Desc  string
	Value float64
	Attrs telemetry.Attrs
}

// withinWindow reports whether an event at eventTime is recent enough (given now
// and window) to reach the metrics path. A future-dated event (negative age,
// clock skew) is treated as out of window — it cannot be trusted to a counter
// stamped now. The boundary is inclusive: age == window passes.
func withinWindow(eventTime, now time.Time, window time.Duration) (age time.Duration, ok bool) {
	age = now.Sub(eventTime)
	return age, age >= 0 && age <= window
}
