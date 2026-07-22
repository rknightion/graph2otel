package telemetry_test

import (
	"testing"
	"time"

	"github.com/rknightion/graph2otel/internal/semconv"
	"github.com/rknightion/graph2otel/internal/telemetry"
	"github.com/rknightion/graph2otel/internal/telemetrytest"
)

// TestBackdateClampRelocatesRecordsBeyondTheHorizon asserts that a log record
// older than the horizon is re-stamped to ingestion time, and that its true
// event time survives on the record rather than being lost (#226).
func TestBackdateClampRelocatesRecordsBeyondTheHorizon(t *testing.T) {
	rec := telemetrytest.New()
	e := telemetry.WithBackdateClamp(rec.Emitter(), time.Hour)

	eventTime := time.Now().Add(-48 * time.Hour).UTC().Truncate(time.Second)
	before := time.Now()
	e.LogEvent(telemetry.Event{
		Name:      "intune.device_startup",
		Body:      "device startup: LAPHAM",
		Timestamp: eventTime,
	})
	after := time.Now()

	recs := rec.LogRecords()
	if len(recs) != 1 {
		t.Fatalf("got %d log records, want 1", len(recs))
	}
	r := recs[0]

	if r.Timestamp.Before(before) || r.Timestamp.After(after) {
		t.Errorf("Timestamp = %v, want it relocated into [%v, %v]", r.Timestamp, before, after)
	}
	if got := r.Attrs[semconv.AttrEventTime]; got != eventTime.Format(time.RFC3339Nano) {
		t.Errorf("%s = %q, want the true event time %q",
			semconv.AttrEventTime, got, eventTime.Format(time.RFC3339Nano))
	}
	if got := r.Attrs[semconv.AttrEventTimeClamped]; got != "true" {
		t.Errorf("%s = %q, want \"true\"", semconv.AttrEventTimeClamped, got)
	}
}

// TestBackdateClampLeavesFreshRecordsExactlyAsEmitted asserts the clamp is
// inert inside the horizon: the event time is preserved to the nanosecond and
// no marker attributes are added.
func TestBackdateClampLeavesFreshRecordsExactlyAsEmitted(t *testing.T) {
	rec := telemetrytest.New()
	e := telemetry.WithBackdateClamp(rec.Emitter(), time.Hour)

	eventTime := time.Now().Add(-5 * time.Minute).UTC()
	e.LogEvent(telemetry.Event{Name: "entra.signin", Timestamp: eventTime})

	r := rec.LogRecords()[0]
	if !r.Timestamp.Equal(eventTime) {
		t.Errorf("Timestamp = %v, want the untouched event time %v", r.Timestamp, eventTime)
	}
	if _, ok := r.Attrs[semconv.AttrEventTimeClamped]; ok {
		t.Errorf("%s present on a record inside the horizon: %+v", semconv.AttrEventTimeClamped, r.Attrs)
	}
	if _, ok := r.Attrs[semconv.AttrEventTime]; ok {
		t.Errorf("%s present on a record inside the horizon: %+v", semconv.AttrEventTime, r.Attrs)
	}
}

// TestBackdateClampLeavesUnstampedRecordsUnstamped asserts a zero Timestamp is
// passed through untouched. A zero timestamp means "no parseable event time",
// and CLAUDE.md's rule is that such a record is never stamped on arrival — the
// clamp must not turn that case into a false claim about when it happened.
func TestBackdateClampLeavesUnstampedRecordsUnstamped(t *testing.T) {
	rec := telemetrytest.New()
	e := telemetry.WithBackdateClamp(rec.Emitter(), time.Hour)

	e.LogEvent(telemetry.Event{Name: "intune.device_battery_health"})

	r := rec.LogRecords()[0]
	if !r.Timestamp.IsZero() {
		t.Errorf("Timestamp = %v, want zero (left for the emitter to handle)", r.Timestamp)
	}
	if _, ok := r.Attrs[semconv.AttrEventTimeClamped]; ok {
		t.Errorf("%s present on an unstamped record: %+v", semconv.AttrEventTimeClamped, r.Attrs)
	}
}

// TestBackdateClampDisabledByNonPositiveHorizon asserts a zero or negative
// horizon returns the emitter unchanged, so an operator whose sink accepts
// arbitrarily old samples can switch the behavior off entirely.
func TestBackdateClampDisabledByNonPositiveHorizon(t *testing.T) {
	for _, horizon := range []time.Duration{0, -time.Hour} {
		rec := telemetrytest.New()
		e := telemetry.WithBackdateClamp(rec.Emitter(), horizon)

		eventTime := time.Now().Add(-30 * 24 * time.Hour).UTC()
		e.LogEvent(telemetry.Event{Name: "m365.activity", Timestamp: eventTime})

		r := rec.LogRecords()[0]
		if !r.Timestamp.Equal(eventTime) {
			t.Errorf("horizon %v: Timestamp = %v, want the untouched event time %v",
				horizon, r.Timestamp, eventTime)
		}
	}
}

// TestBackdateClampDoesNotMutateCallerAttrs asserts the clamp copies before
// writing. Collectors reuse an Attrs map across records in a loop; writing into
// it would leak the marker onto every later record and, worse, onto records the
// clamp never touched.
func TestBackdateClampDoesNotMutateCallerAttrs(t *testing.T) {
	rec := telemetrytest.New()
	e := telemetry.WithBackdateClamp(rec.Emitter(), time.Hour)

	attrs := telemetry.Attrs{"device_name": "LAPHAM"}
	e.LogEvent(telemetry.Event{
		Name:      "intune.device_startup",
		Timestamp: time.Now().Add(-48 * time.Hour),
		Attrs:     attrs,
	})

	if len(attrs) != 1 {
		t.Errorf("caller Attrs mutated: %+v, want only device_name", attrs)
	}
}

// TestBackdateClampCountsWhatItRelocates asserts each clamped record increments
// a self-observability counter keyed by event name. Silent loss is what made
// #226 invisible for as long as it was; a silent REWRITE would be the same
// mistake one step to the left.
func TestBackdateClampCountsWhatItRelocates(t *testing.T) {
	rec := telemetrytest.New()
	e := telemetry.WithBackdateClamp(rec.Emitter(), time.Hour)

	e.LogEvent(telemetry.Event{Name: "intune.device_startup", Timestamp: time.Now().Add(-48 * time.Hour)})
	e.LogEvent(telemetry.Event{Name: "intune.device_startup", Timestamp: time.Now().Add(-48 * time.Hour)})
	e.LogEvent(telemetry.Event{Name: "entra.signin", Timestamp: time.Now().Add(-time.Minute)})

	// One series per event name, so the two clamped records aggregate into a
	// single point of value 2 — and the fresh record contributes nothing, which
	// is the assertion that matters: the counter tracks relocations, not traffic.
	pts := rec.MetricPoints(telemetry.MetricLogsBackdateClamped)
	if len(pts) != 1 {
		t.Fatalf("got %d points for %s, want 1 series: %+v",
			len(pts), telemetry.MetricLogsBackdateClamped, pts)
	}
	p := pts[0]
	if p.Value != 2 {
		t.Errorf("Value = %v, want 2 (the two clamped records, not the fresh one)", p.Value)
	}
	if !p.Monotonic {
		t.Errorf("point = %+v, want a monotonic counter", p)
	}
	if p.Attrs[semconv.AttrEventName] != "intune.device_startup" {
		t.Errorf("attrs = %+v, want event_name=intune.device_startup", p.Attrs)
	}
}

// TestBackdateClampDoesNotRelocateFutureTimestamps asserts a timestamp ahead of
// the clock is left alone. It is a different defect with a different fix, and
// silently moving it would destroy the evidence of it.
func TestBackdateClampDoesNotRelocateFutureTimestamps(t *testing.T) {
	rec := telemetrytest.New()
	e := telemetry.WithBackdateClamp(rec.Emitter(), time.Hour)

	future := time.Now().Add(24 * time.Hour).UTC()
	e.LogEvent(telemetry.Event{Name: "entra.signin", Timestamp: future})

	r := rec.LogRecords()[0]
	if !r.Timestamp.Equal(future) {
		t.Errorf("Timestamp = %v, want the untouched future timestamp %v", r.Timestamp, future)
	}
}
