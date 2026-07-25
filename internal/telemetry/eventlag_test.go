package telemetry_test

import (
	"testing"
	"time"

	"github.com/rknightion/graph2otel/internal/semconv"
	"github.com/rknightion/graph2otel/internal/telemetry"
	"github.com/rknightion/graph2otel/internal/telemetrytest"
)

func TestWithEventLagRecordsEventTimeToEmissionTime(t *testing.T) {
	now := time.Date(2026, time.July, 25, 12, 0, 0, 0, time.UTC)
	rec := telemetrytest.New()
	e := telemetry.WithEventLag(
		telemetry.WithTenant(rec.Emitter(), "tenant-a"),
		"entra.signins",
		"tenant-a",
		telemetry.TransportGraph,
		func() time.Time { return now },
	)

	e.LogEvent(telemetry.Event{
		Name:      "entra.signin",
		Timestamp: now.Add(-30 * time.Second),
		Attrs: telemetry.Attrs{
			semconv.AttrIngestTransport: string(telemetry.TransportBlob),
		},
	})

	points := rec.MetricPoints("graph2otel.event.lag")
	if len(points) != 1 {
		t.Fatalf("event lag points = %d, want 1", len(points))
	}
	got := points[0]
	if got.Kind != "histogram" || got.Unit != semconv.UnitSeconds || got.Count != 1 || got.Value != 30 {
		t.Errorf("event lag point = %+v, want one 30s histogram observation", got)
	}
	wantAttrs := map[string]string{
		semconv.AttrTenantID:        "tenant-a",
		semconv.AttrCollector:       "entra.signins",
		semconv.AttrIngestTransport: string(telemetry.TransportBlob),
	}
	for key, want := range wantAttrs {
		if got.Attrs[key] != want {
			t.Errorf("event lag attribute %q = %q, want %q", key, got.Attrs[key], want)
		}
	}
	if logs := rec.LogRecords(); len(logs) != 1 || logs[0].EventName != "entra.signin" {
		t.Fatalf("forwarded logs = %+v, want entra.signin", logs)
	}
}

func TestWithEventLagUsesDefaultTransportAndClampsFutureTime(t *testing.T) {
	now := time.Date(2026, time.July, 25, 12, 0, 0, 0, time.UTC)
	rec := telemetrytest.New()
	e := telemetry.WithEventLag(
		rec.Emitter(),
		"m365.activity",
		"",
		telemetry.TransportO365Activity,
		func() time.Time { return now },
	)

	e.LogEvent(telemetry.Event{
		Name:      "m365.activity",
		Timestamp: now.Add(time.Minute),
	})

	points := rec.MetricPoints("graph2otel.event.lag")
	if len(points) != 1 {
		t.Fatalf("event lag points = %d, want 1", len(points))
	}
	if points[0].Value != 0 {
		t.Errorf("future event lag = %v, want 0", points[0].Value)
	}
	if got := points[0].Attrs[semconv.AttrIngestTransport]; got != string(telemetry.TransportO365Activity) {
		t.Errorf("ingest transport = %q, want %q", got, telemetry.TransportO365Activity)
	}
}

func TestWithEventLagSkipsZeroTimestamp(t *testing.T) {
	rec := telemetrytest.New()
	e := telemetry.WithEventLag(
		rec.Emitter(),
		"entra.signins",
		"",
		telemetry.TransportGraph,
		time.Now,
	)

	e.LogEvent(telemetry.Event{Name: "entra.signin"})

	if points := rec.MetricPoints("graph2otel.event.lag"); len(points) != 0 {
		t.Fatalf("zero-time event lag points = %+v, want none", points)
	}
	if logs := rec.LogRecords(); len(logs) != 1 {
		t.Fatalf("forwarded logs = %d, want 1", len(logs))
	}
}

func TestWithEventLagForwardsTenantScopedGaugeSnapshot(t *testing.T) {
	rec := telemetrytest.New()
	e := telemetry.WithEventLag(
		telemetry.WithTenant(rec.Emitter(), "tenant-a"),
		"entra.signins",
		"tenant-a",
		telemetry.TransportGraph,
		time.Now,
	)

	e.GaugeSnapshot("entra.test.snapshot", "{item}", "test", []telemetry.GaugePoint{{
		Value: 1,
		Attrs: telemetry.Attrs{"state": "ok"},
	}})

	points := rec.MetricPoints("entra.test.snapshot")
	if len(points) != 1 || points[0].Attrs[semconv.AttrTenantID] != "tenant-a" {
		t.Fatalf("snapshot points = %+v, want tenant-scoped point", points)
	}
}
