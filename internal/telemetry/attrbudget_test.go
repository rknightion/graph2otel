package telemetry_test

import (
	"strconv"
	"strings"
	"testing"

	"github.com/rknightion/graph2otel/internal/semconv"
	"github.com/rknightion/graph2otel/internal/telemetry"
	"github.com/rknightion/graph2otel/internal/telemetrytest"
)

// budgeted builds an attribute-budget-guarded emitter over an in-memory recorder.
func budgeted(t *testing.T, budget int) (*telemetrytest.Recorder, telemetry.Emitter) {
	t.Helper()
	rec := telemetrytest.New()
	e := telemetry.WithAttributeBudget(
		rec.Emitter(), budget, "defender.device_event", "tenant-a", telemetry.Transport("blob"),
	)
	return rec, e
}

// recordedBytes measures one captured record's attribute set the way Loki
// measures structured metadata: the sum of every key's and every rendered
// value's length. The Recorder hands back already-rendered values, which is
// exactly what the OTLP exporter puts on the wire.
func recordedBytes(r telemetrytest.LogRecord) int {
	n := 0
	for k, v := range r.Attrs {
		n += len(k) + len(v)
	}
	return n
}

func TestARecordInsideTheBudgetIsPassedThroughUntouched(t *testing.T) {
	// The common case, and the one a too-eager guard would quietly damage.
	rec, e := budgeted(t, 1000)
	attrs := telemetry.Attrs{
		"process_command_line": strings.Repeat("a", 400),
		"device_name":          "laptop-1",
		"port":                 int64(443),
	}

	e.LogEvent(telemetry.Event{Name: "defender.device_event", Body: "under", Attrs: attrs})

	records := rec.LogRecords()
	if len(records) != 1 {
		t.Fatalf("got %d log records, want 1", len(records))
	}
	if got := records[0].Attrs["process_command_line"]; len(got) != 400 {
		t.Errorf("an in-budget value was clipped: len = %d, want 400", len(got))
	}
	if _, ok := records[0].Attrs[semconv.AttrAttrsTruncated]; ok {
		t.Errorf("an in-budget record was marked truncated")
	}
	if points := rec.MetricPoints("graph2otel.event.attrs_truncated"); len(points) != 0 {
		t.Fatalf("an in-budget record was counted as truncated: %+v", points)
	}
}

func TestAnOversizedRecordIsClippedToFitRatherThanRejected(t *testing.T) {
	// The #419 case. Loki refuses an entry whose structured metadata exceeds
	// 64 KiB, so a record that ships over-budget is lost outright. It must arrive
	// clipped instead — degraded is a record, rejected is not.
	rec, e := budgeted(t, 4000)
	attrs := telemetry.Attrs{
		"additional_fields": strings.Repeat("x", 200_000),
		"device_name":       "laptop-1",
	}

	e.LogEvent(telemetry.Event{Name: "defender.device_event", Body: "over", Attrs: attrs})

	records := rec.LogRecords()
	if len(records) != 1 {
		t.Fatalf("an oversized record was dropped: got %d log records, want 1", len(records))
	}
	if got := recordedBytes(records[0]); got > 4000 {
		t.Errorf("clipped record is still %d bytes, want <= 4000 — it would still be rejected", got)
	}
}

func TestClippingKeepsEveryAttributeAndTheSmallOnesWhole(t *testing.T) {
	// "Not a metric label means log twin, never dropped" (#114) applies inside a
	// record too: clipping the one huge value must not cost the twenty small ones
	// that identify the entity.
	rec, e := budgeted(t, 4000)
	attrs := telemetry.Attrs{
		"additional_fields": strings.Repeat("x", 200_000),
		"device_name":       "laptop-1",
		"account_upn":       "user@example.com",
		"remote_ip":         "10.0.0.1",
	}

	e.LogEvent(telemetry.Event{Name: "defender.device_event", Attrs: attrs})

	records := rec.LogRecords()
	if len(records) != 1 {
		t.Fatalf("got %d log records, want 1", len(records))
	}
	for key, want := range map[string]string{
		"device_name": "laptop-1",
		"account_upn": "user@example.com",
		"remote_ip":   "10.0.0.1",
	} {
		if got := records[0].Attrs[key]; got != want {
			t.Errorf("attr %s = %q, want %q — clipping the big value must not touch the small ones",
				key, got, want)
		}
	}
	if _, ok := records[0].Attrs["additional_fields"]; !ok {
		t.Error("the oversized attribute was removed entirely; it must survive clipped")
	}
}

func TestAClippedRecordSaysSoOnItself(t *testing.T) {
	// A silently shortened value is a lie about the source. The marker is what
	// stops a reader trusting a clipped command line as complete, and the key
	// list is what finally names the offending shape in production.
	rec, e := budgeted(t, 4000)
	attrs := telemetry.Attrs{"additional_fields": strings.Repeat("x", 200_000)}

	e.LogEvent(telemetry.Event{Name: "defender.device_event", Attrs: attrs})

	records := rec.LogRecords()
	if len(records) != 1 {
		t.Fatalf("got %d log records, want 1", len(records))
	}
	if got := records[0].Attrs[semconv.AttrAttrsTruncated]; got != "true" {
		t.Errorf("%s = %q, want \"true\"", semconv.AttrAttrsTruncated, got)
	}
	if got := records[0].Attrs[semconv.AttrAttrsTruncatedKeys]; !strings.Contains(got, "additional_fields") {
		t.Errorf("%s = %q, want it to name additional_fields", semconv.AttrAttrsTruncatedKeys, got)
	}
	removed, err := strconv.Atoi(records[0].Attrs[semconv.AttrAttrsTruncatedBytes])
	if err != nil {
		t.Fatalf("%s = %q, want an integer: %v",
			semconv.AttrAttrsTruncatedBytes, records[0].Attrs[semconv.AttrAttrsTruncatedBytes], err)
	}
	if removed < 190_000 {
		t.Errorf("%s = %d, want ~196000 — the marker must report the real loss",
			semconv.AttrAttrsTruncatedBytes, removed)
	}
}

func TestAClipIsCountedAndAttributed(t *testing.T) {
	// The loss #419 describes was invisible because nothing counted it. A metric
	// nobody can attribute to a collector is barely better.
	rec, e := budgeted(t, 4000)

	e.LogEvent(telemetry.Event{
		Name:  "defender.device_event",
		Attrs: telemetry.Attrs{"additional_fields": strings.Repeat("x", 200_000)},
	})

	points := rec.MetricPoints("graph2otel.event.attrs_truncated")
	if len(points) != 1 {
		t.Fatalf("a clip was not counted: got %d points, want 1", len(points))
	}
	if points[0].Value != 1 {
		t.Errorf("clip count = %v, want 1", points[0].Value)
	}
	for key, want := range map[string]string{
		semconv.AttrCollector:       "defender.device_event",
		semconv.AttrTenantID:        "tenant-a",
		semconv.AttrIngestTransport: "blob",
	} {
		if got := points[0].Attrs[key]; got != want {
			t.Errorf("attr %s = %v, want %q", key, got, want)
		}
	}
}

func TestAStampedTransportWinsOverTheCollectorDefaultWhenClipping(t *testing.T) {
	rec, e := budgeted(t, 4000)

	e.LogEvent(telemetry.Event{
		Name: "defender.device_event",
		Attrs: telemetry.Attrs{
			"additional_fields":         strings.Repeat("x", 200_000),
			semconv.AttrIngestTransport: "o365_activity",
		},
	})

	points := rec.MetricPoints("graph2otel.event.attrs_truncated")
	if len(points) != 1 {
		t.Fatalf("got %d points, want 1", len(points))
	}
	if got := points[0].Attrs[semconv.AttrIngestTransport]; got != "o365_activity" {
		t.Errorf("ingest_transport = %v, want o365_activity (the outermost stamp wins)", got)
	}
}

func TestClippingSpreadsAcrossEveryOversizedValue(t *testing.T) {
	// Two 100 KB values in one record: clipping only the larger one still leaves
	// the record over budget. The guard must hold a single ceiling across them.
	rec, e := budgeted(t, 4000)

	e.LogEvent(telemetry.Event{
		Name: "defender.device_event",
		Attrs: telemetry.Attrs{
			"additional_fields": strings.Repeat("x", 100_000),
			"raw_event_data":    strings.Repeat("y", 100_001),
		},
	})

	records := rec.LogRecords()
	if len(records) != 1 {
		t.Fatalf("got %d log records, want 1", len(records))
	}
	if got := recordedBytes(records[0]); got > 4000 {
		t.Errorf("record is %d bytes, want <= 4000", got)
	}
	for _, key := range []string{"additional_fields", "raw_event_data"} {
		if records[0].Attrs[key] == "" {
			t.Errorf("attr %s was emptied; both oversized values should survive clipped", key)
		}
	}
}

func TestAListValueIsClippedByElementNotMidElement(t *testing.T) {
	// A []string renders as a comma-joined string, so a byte cut would leave a
	// half-written last element that reads as a real value. Drop whole elements.
	rec, e := budgeted(t, 4000)
	items := make([]string, 500)
	for i := range items {
		items[i] = "urn:action:" + strconv.Itoa(i)
	}

	e.LogEvent(telemetry.Event{
		Name:  "defender.device_event",
		Attrs: telemetry.Attrs{"allowed_actions": items},
	})

	records := rec.LogRecords()
	if len(records) != 1 {
		t.Fatalf("got %d log records, want 1", len(records))
	}
	got := records[0].Attrs["allowed_actions"]
	if got == "" {
		t.Fatal("the list attribute was emptied entirely")
	}
	for _, elem := range strings.Split(got, ",") {
		if !strings.HasPrefix(elem, "urn:action:") {
			t.Fatalf("element %q is a partial value: a byte cut landed mid-element", elem)
		}
	}
}

func TestARecordOfManyTinyAttributesStillShipsSomething(t *testing.T) {
	// The pathological shape: the keys alone exceed the budget, so no amount of
	// value clipping fits. Even here the record must reach the backend — losing
	// it is exactly the failure this guard exists to prevent.
	rec, e := budgeted(t, 500)
	attrs := telemetry.Attrs{}
	for i := range 400 {
		attrs["some_reasonably_long_attribute_key_"+strconv.Itoa(i)] = "v"
	}

	e.LogEvent(telemetry.Event{Name: "defender.device_event", Attrs: attrs})

	records := rec.LogRecords()
	if len(records) != 1 {
		t.Fatalf("a pathological record was dropped: got %d log records, want 1", len(records))
	}
	if got := recordedBytes(records[0]); got > 500 {
		t.Errorf("record is %d bytes, want <= 500", got)
	}
	if got := records[0].Attrs[semconv.AttrAttrsDropped]; got == "" || got == "0" {
		t.Errorf("%s = %q, want a nonzero count — attributes that had to go must be counted",
			semconv.AttrAttrsDropped, got)
	}
}

func TestAZeroBudgetDisablesTheGuard(t *testing.T) {
	// The escape hatch for a sink with no structured-metadata limit. It must be a
	// real no-op, not a smaller number.
	rec, e := budgeted(t, 0)

	e.LogEvent(telemetry.Event{
		Name:  "defender.device_event",
		Attrs: telemetry.Attrs{"additional_fields": strings.Repeat("x", 200_000)},
	})

	records := rec.LogRecords()
	if len(records) != 1 {
		t.Fatalf("got %d log records, want 1", len(records))
	}
	if got := len(records[0].Attrs["additional_fields"]); got != 200_000 {
		t.Errorf("a zero budget still clipped: len = %d, want 200000", got)
	}
}

func TestTheGuardDoesNotMutateTheCallersAttributes(t *testing.T) {
	// Collectors reuse and inspect the maps they build; clipping in place would
	// change what a collector's own logging and tests see.
	_, e := budgeted(t, 4000)
	attrs := telemetry.Attrs{"additional_fields": strings.Repeat("x", 200_000)}

	e.LogEvent(telemetry.Event{Name: "defender.device_event", Attrs: attrs})

	if got := len(attrs["additional_fields"].(string)); got != 200_000 {
		t.Errorf("caller's attribute was mutated: len = %d, want 200000", got)
	}
}

func TestMetricsPassThroughTheAttributeBudgetUnaffected(t *testing.T) {
	rec, e := budgeted(t, 4000)

	e.Counter("graph2otel.test.counter", semconv.UnitRecords, "desc", 3, nil)
	e.Gauge("graph2otel.test.gauge", semconv.UnitRecords, "desc", 7, nil)

	if points := rec.MetricPoints("graph2otel.test.counter"); len(points) != 1 {
		t.Errorf("counter did not pass through: got %d points", len(points))
	}
	if points := rec.MetricPoints("graph2otel.test.gauge"); len(points) != 1 {
		t.Errorf("gauge did not pass through: got %d points", len(points))
	}
}

func TestTheBudgetLeavesRoomBelowTheMeasuredStructuredMetadataLimit(t *testing.T) {
	// The margin is the whole reason this is not 65536. Loki counts the RESOURCE
	// and scope attributes the SDK stamps as structured metadata too, and the
	// guard never sees them: live-measured on m7kni 2026-08-06, that fixed set
	// (host/os/process/telemetry_sdk/service_version/scope_name/severity/
	// event_name/ingest_transport/tenant_id) runs 627-653 bytes per record. Two
	// more decorators stamp attributes downstream of this guard as well.
	const lokiLimit = 65536
	const measuredOverhead = 653
	if telemetry.MaxAttributeBytes >= lokiLimit-measuredOverhead {
		t.Fatalf("budget %d leaves no room for the measured %d-byte resource overhead below %d",
			telemetry.MaxAttributeBytes, measuredOverhead, lokiLimit)
	}
	if margin := lokiLimit - measuredOverhead - telemetry.MaxAttributeBytes; margin < 2048 {
		t.Fatalf("margin %d is too thin to absorb a longer host name, a new resource attribute, "+
			"or an attribute stamped downstream of this guard", margin)
	}
}
