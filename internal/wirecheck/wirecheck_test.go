package wirecheck_test

import (
	"bytes"
	"log/slog"
	"strings"
	"testing"

	"github.com/rknightion/graph2otel/internal/semconv"
	"github.com/rknightion/graph2otel/internal/telemetrytest"
	"github.com/rknightion/graph2otel/internal/wirecheck"
)

func newReporter(t *testing.T) (*wirecheck.Reporter, *bytes.Buffer) {
	t.Helper()
	var buf bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelWarn}))
	return wirecheck.New("defender.quarantine", logger), &buf
}

func TestUnmappedValueCountsAndLogs(t *testing.T) {
	r, buf := newReporter(t)
	rec := telemetrytest.New()

	r.Value(rec.Emitter(), "quarantine_type", "Sponge", wirecheck.NewEnum("Spam", "Phish"))

	pts := rec.MetricPoints(wirecheck.MetricUnexpected)
	if len(pts) != 1 {
		t.Fatalf("counter points = %d, want 1", len(pts))
	}
	if pts[0].Value != 1 {
		t.Errorf("counter = %v, want 1", pts[0].Value)
	}
	want := map[string]string{
		semconv.AttrCollector: "defender.quarantine",
		semconv.AttrField:     "quarantine_type",
		semconv.AttrKind:      wirecheck.KindUnmappedValue,
	}
	for k, v := range want {
		if got := pts[0].Attrs[k]; got != v {
			t.Errorf("attr %q = %q, want %q", k, got, v)
		}
	}

	// THE cardinality rule, applied to graph2otel's own telemetry: the offending
	// VALUE is unbounded (it is whatever Microsoft invented), so it must never
	// become a metric label — it goes in the log. The label set is bounded by
	// graph2otel's own source code.
	for _, attr := range pts[0].Attrs {
		if attr == "Sponge" {
			t.Error("the unexpected value must not appear as a metric label — it is unbounded by definition")
		}
	}
	if !strings.Contains(buf.String(), "Sponge") {
		t.Errorf("the log must carry the offending value; got %q", buf.String())
	}
}

func TestKnownValueIsSilent(t *testing.T) {
	r, buf := newReporter(t)
	rec := telemetrytest.New()

	r.Value(rec.Emitter(), "quarantine_type", "Spam", wirecheck.NewEnum("Spam", "Phish"))

	if got := len(rec.MetricPoints(wirecheck.MetricUnexpected)); got != 0 {
		t.Errorf("counter points = %d, want 0 for a known value", got)
	}
	if buf.Len() != 0 {
		t.Errorf("a known value must log nothing; got %q", buf.String())
	}
}

// TestEmptyValueIsNotUnexpected keeps the reporter from firing on every absent
// optional field. An absent field is reported through MissingField, by a caller
// that has decided the absence matters — not inferred here.
func TestEmptyValueIsNotUnexpected(t *testing.T) {
	r, buf := newReporter(t)
	rec := telemetrytest.New()

	r.Value(rec.Emitter(), "quarantine_type", "", wirecheck.NewEnum("Spam"))

	if got := len(rec.MetricPoints(wirecheck.MetricUnexpected)); got != 0 {
		t.Errorf("counter points = %d, want 0 for an absent value", got)
	}
	if buf.Len() != 0 {
		t.Errorf("an absent value must log nothing; got %q", buf.String())
	}
}

// TestRepeatLogsOnceButCountsEvery is the property that makes this usable in a
// poll loop. A persistently unmapped value would otherwise log on every tick
// forever — the log says WHAT it is once, the counter says it is still
// happening.
func TestRepeatLogsOnceButCountsEvery(t *testing.T) {
	r, buf := newReporter(t)
	rec := telemetrytest.New()
	enum := wirecheck.NewEnum("Spam")

	for range 5 {
		r.Value(rec.Emitter(), "quarantine_type", "Sponge", enum)
	}

	pts := rec.MetricPoints(wirecheck.MetricUnexpected)
	if len(pts) != 1 {
		t.Fatalf("counter points = %d, want 1 series", len(pts))
	}
	if pts[0].Value != 5 {
		t.Errorf("counter = %v, want 5 — every occurrence counts", pts[0].Value)
	}
	if got := strings.Count(buf.String(), "Sponge"); got != 1 {
		t.Errorf("logged %d times, want 1 — a repeat must not spam the log", got)
	}
}

// TestDistinctValuesEachLogOnce — deduping must not hide a SECOND new value.
func TestDistinctValuesEachLogOnce(t *testing.T) {
	r, buf := newReporter(t)
	rec := telemetrytest.New()
	enum := wirecheck.NewEnum("Spam")

	r.Value(rec.Emitter(), "quarantine_type", "Sponge", enum)
	r.Value(rec.Emitter(), "quarantine_type", "Sponge", enum)
	r.Value(rec.Emitter(), "quarantine_type", "Custard", enum)

	if !strings.Contains(buf.String(), "Sponge") || !strings.Contains(buf.String(), "Custard") {
		t.Errorf("both distinct values must be logged; got %q", buf.String())
	}
	if got := rec.MetricPoints(wirecheck.MetricUnexpected)[0].Value; got != 3 {
		t.Errorf("counter = %v, want 3", got)
	}
}

// TestSameValueOnDifferentFieldsBothLog — the dedupe key includes the field, so
// the same string arriving on two different fields is two findings.
func TestSameValueOnDifferentFieldsBothLog(t *testing.T) {
	r, buf := newReporter(t)
	rec := telemetrytest.New()
	enum := wirecheck.NewEnum("known")

	r.Value(rec.Emitter(), "quarantine_type", "Odd", enum)
	r.Value(rec.Emitter(), "entity_type", "Odd", enum)

	if got := strings.Count(buf.String(), "Odd"); got != 2 {
		t.Errorf("logged %d times, want 2 — field is part of the dedupe key", got)
	}
	if got := len(rec.MetricPoints(wirecheck.MetricUnexpected)); got != 2 {
		t.Errorf("counter series = %d, want 2 (one per field)", got)
	}
}

func TestMissingField(t *testing.T) {
	r, buf := newReporter(t)
	rec := telemetrytest.New()

	r.MissingField(rec.Emitter(), "identity")

	pts := rec.MetricPoints(wirecheck.MetricUnexpected)
	if len(pts) != 1 {
		t.Fatalf("counter points = %d, want 1", len(pts))
	}
	if got := pts[0].Attrs[semconv.AttrKind]; got != wirecheck.KindMissingField {
		t.Errorf("kind = %q, want %q", got, wirecheck.KindMissingField)
	}
	if !strings.Contains(buf.String(), "identity") {
		t.Errorf("log must name the field; got %q", buf.String())
	}
}

// TestInvariant covers the class this package exists for: an API guarantee that
// was MEASURED once and is being trusted in production. If it stops holding,
// the assumption must announce itself rather than silently corrupting a number.
func TestInvariant(t *testing.T) {
	r, buf := newReporter(t)
	rec := telemetrytest.New()

	r.Invariant(rec.Emitter(), "held_only_filter", "row 3 has released=true in a NOTRELEASED query")

	pts := rec.MetricPoints(wirecheck.MetricUnexpected)
	if len(pts) != 1 {
		t.Fatalf("counter points = %d, want 1", len(pts))
	}
	if got := pts[0].Attrs[semconv.AttrKind]; got != wirecheck.KindInvariant {
		t.Errorf("kind = %q, want %q", got, wirecheck.KindInvariant)
	}
	if got := pts[0].Attrs[semconv.AttrField]; got != "held_only_filter" {
		t.Errorf("field = %q, want the rule name", got)
	}
	if !strings.Contains(buf.String(), "released=true") {
		t.Errorf("log must carry the detail; got %q", buf.String())
	}
}

// TestNilLoggerDoesNotPanic — a zero-config Reporter must still count.
func TestNilLoggerDoesNotPanic(t *testing.T) {
	rec := telemetrytest.New()
	r := wirecheck.New("c", nil)
	r.Value(rec.Emitter(), "f", "v", wirecheck.NewEnum("other"))
	if got := len(rec.MetricPoints(wirecheck.MetricUnexpected)); got != 1 {
		t.Errorf("counter points = %d, want 1", got)
	}
}

func TestConcurrentUseIsSafe(t *testing.T) {
	r, _ := newReporter(t)
	rec := telemetrytest.New()
	enum := wirecheck.NewEnum("known")
	done := make(chan struct{})
	for i := range 8 {
		go func() {
			defer func() { done <- struct{}{} }()
			for range 20 {
				r.Value(rec.Emitter(), "f", string(rune('a'+i)), enum)
			}
		}()
	}
	for range 8 {
		<-done
	}
}
