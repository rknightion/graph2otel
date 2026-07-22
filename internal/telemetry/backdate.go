package telemetry

import (
	"maps"
	"time"

	"github.com/rknightion/graph2otel/internal/semconv"
)

// MetricLogsBackdateClamped counts log records whose timestamp was relocated to
// ingestion time because their event time was older than the backend's accept
// window. Labeled by semconv.AttrEventName so an operator can see WHICH signal
// is losing its true position on the time axis, not just that something is.
//
// A non-zero rate here is not an error — it is the exporter salvaging records
// the backend would otherwise have discarded — but a sustained one means a
// collector is routinely reaching further back than the sink accepts, which is
// worth knowing.
const MetricLogsBackdateClamped = "graph2otel.logs.backdate_clamped"

// backdateClampEmitter relocates the timestamp of any log record whose event
// time is older than horizon, preserving the true time as an attribute.
//
// Only LogEvent is overridden. Metric data points carry no event timestamp —
// they are stamped by the SDK at export — so promoting the rest of the Emitter
// methods from the embedded interface is correct here, unlike tenantEmitter
// where an un-overridden method would silently emit unstamped.
type backdateClampEmitter struct {
	Emitter
	horizon time.Duration
	now     func() time.Time
}

// WithBackdateClamp returns an Emitter that rewrites the timestamp of log
// records older than horizon to the moment of emission, carrying the true event
// time on semconv.AttrEventTime and marking the record with
// semconv.AttrEventTimeClamped. A horizon <= 0 disables the behavior and
// returns e unchanged.
//
// # Why this exists (#226)
//
// Grafana Cloud's log ingestion silently discards records timestamped further
// in the past than its accept window. Measured 2026-07-22 against the live
// gateway: records backdated up to ~4h landed, everything beyond was dropped,
// and the SDK reported success for every one of them — ForceFlush returned nil,
// no OTLP error, no partial-success signal. The loss is invisible from inside
// the process, which is why it went unnoticed until a twin that happened to be
// event-stamped (intune.device_startup) never appeared in Loki while the four
// poll-stamped twins emitted in the same loop all did.
//
// The measurement also refuted the obvious explanation. It is NOT Loki's
// out-of-order rejection relative to the stream head: a virgin stream whose only
// records were old behaved identically to the production stream whose head sits
// at wall clock. The cutoff is absolute against the clock, so it cannot be
// engineered around by changing stream labels.
//
// # Why relocate rather than drop
//
// CLAUDE.md's rule is that a record with no parseable event time must be
// dropped, never stamped on arrival, because stamping on arrival silently claims
// it happened now. This is the mirror case and the rule points the other way: we
// DO have a true event time, and the choice is between a record positioned at
// arrival that still states when it happened, or no record at all. The claim is
// not silent — AttrEventTime carries the truth and AttrEventTimeClamped says the
// position is arrival — so nothing is misdated in the sense the rule forbids,
// and a SIEM feed keeps the evidence.
//
// A zero timestamp is passed through untouched: that is the no-parseable-time
// case the original rule governs, and it is the emitter's to handle.
//
// A FUTURE timestamp is also passed through untouched. It is a different defect
// — a clock or a mapper is wrong — and relocating it would erase the evidence
// while looking like a fix.
func WithBackdateClamp(e Emitter, horizon time.Duration) Emitter {
	if horizon <= 0 {
		return e
	}
	return &backdateClampEmitter{Emitter: e, horizon: horizon, now: time.Now}
}

func (e *backdateClampEmitter) LogEvent(ev Event) {
	if ev.Timestamp.IsZero() {
		e.Emitter.LogEvent(ev)
		return
	}
	now := e.now()
	if now.Sub(ev.Timestamp) <= e.horizon {
		e.Emitter.LogEvent(ev)
		return
	}

	// Copy before writing. Collectors legitimately reuse one Attrs map across
	// records in a loop, so writing into the caller's map would leak the marker
	// onto later records — including ones that were never relocated.
	attrs := make(Attrs, len(ev.Attrs)+2)
	maps.Copy(attrs, ev.Attrs)
	attrs[semconv.AttrEventTime] = ev.Timestamp.UTC().Format(time.RFC3339Nano)
	attrs[semconv.AttrEventTimeClamped] = true

	eventName := ev.Name
	ev.Attrs = attrs
	ev.Timestamp = now
	e.Emitter.LogEvent(ev)

	e.Counter(MetricLogsBackdateClamped, semconv.UnitDimensionless,
		"log records whose timestamp was relocated to ingestion time because their event time predated the backend accept window",
		1, Attrs{semconv.AttrEventName: eventName})
}
