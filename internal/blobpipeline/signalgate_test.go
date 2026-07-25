package blobpipeline

import (
	"context"
	"flag"
	"fmt"
	"testing"
	"time"

	"github.com/rknightion/graph2otel/internal/semconv"
	"github.com/rknightion/graph2otel/internal/signalcapture"
	"github.com/rknightion/graph2otel/internal/telemetry"
	"github.com/rknightion/graph2otel/internal/telemetrytest"
	"github.com/rknightion/graph2otel/internal/wirecheck"
)

var updateBlobSignals = flag.Bool("update", false, "rewrite testdata/signals.json")

// TestSignalGate drives one dedicated fixture through Poll rather than
// cataloging the unrelated synthetic metrics emitted by the package's wider
// unit tests. The four records cover every blob-engine outcome that emits
// self-observability: fresh/metric-emitted, old/metric-gated, undated/dropped,
// and self-excluded. The caller-side decorators match production wiring so the
// golden sees tenant_id on every metric and tenant_id + blob provenance on
// every emitted log.
func TestSignalGate(t *testing.T) {
	now := time.Now().UTC()
	record := func(id, appID string, timestamp *time.Time) string {
		t.Helper()
		timeField := ""
		if timestamp != nil {
			timeField = fmt.Sprintf(`,"time":%q`, timestamp.Format(time.RFC3339Nano))
		}
		return fmt.Sprintf(`{"id":%q,"appId":%q%s}`, id, appID, timeField) + "\r\n"
	}
	fresh := now.Add(-5 * time.Minute)
	old := now.Add(-2 * time.Hour)
	name := "tenantId=tenant-capture/y=2026/m=07/d=25/h=00/PT1H.json"
	src := &fakeSource{blobs: map[string]string{
		name: record("fresh", "third-party", &fresh) +
			record("old", "third-party", &old) +
			record("undated", "third-party", nil) +
			record("self", "poller-client", &fresh),
	}}
	cfg := ContainerConfig{
		Container:     "insights-logs-capture",
		Prefix:        "tenantId=tenant-capture/",
		CollectorName: "entra.capture",
		RecencyWindow: 20 * time.Minute,
		Map: func(rec map[string]any) (telemetry.Event, bool) {
			id, _ := rec["id"].(string)
			appID, _ := rec["appId"].(string)
			ev := telemetry.Event{
				Name:  "entra.graph_activity",
				Body:  id,
				Attrs: telemetry.Attrs{semconv.AttrAppId: appID},
			}
			if raw, ok := rec["time"].(string); ok {
				ev.Timestamp, _ = time.Parse(time.RFC3339Nano, raw)
			}
			return ev, true
		},
		Derive: func(map[string]any, telemetry.Event) []MetricPoint {
			return nil
		},
		ExcludeSelf:  true,
		SelfClientID: "poller-client",
		SelfAppID: func(rec map[string]any) string {
			appID, _ := rec["appId"].(string)
			return appID
		},
	}
	recorder := telemetrytest.New()
	emitter := telemetry.WithTenant(
		telemetry.WithTransport(recorder.Emitter(), telemetry.TransportGraph),
		"tenant-capture",
	)

	if err := Poll(
		context.Background(), cfg, newCursor(), src, emitter, discardLogger(), nil,
	); err != nil {
		t.Fatalf("Poll: %v", err)
	}

	if got := len(recorder.LogRecords()); got != 2 {
		t.Fatalf("logs = %d, want 2: fresh and gated records remain on the log path", got)
	}
	for _, logRecord := range recorder.LogRecords() {
		if got := logRecord.Attrs[semconv.AttrTenantID]; got != "tenant-capture" {
			t.Errorf("log tenant_id = %q, want tenant-capture", got)
		}
		if got := logRecord.Attrs[semconv.AttrIngestTransport]; got != string(telemetry.TransportBlob) {
			t.Errorf("log ingest_transport = %q, want blob", got)
		}
	}
	for metric, want := range map[string]float64{
		metricEmitted:              1,
		metricGated:                1,
		metricRecordsDropped:       1,
		metricSelfExcluded:         1,
		wirecheck.MetricUnexpected: 1,
	} {
		points := recorder.MetricPoints(metric)
		if len(points) != 1 {
			t.Errorf("%s points = %d, want 1", metric, len(points))
			continue
		}
		if got := points[0].Value; got != want {
			t.Errorf("%s value = %v, want %v", metric, got, want)
		}
		if got := points[0].Attrs[semconv.AttrTenantID]; got != "tenant-capture" {
			t.Errorf("%s tenant_id = %q, want tenant-capture", metric, got)
		}
	}
	eventAge := recorder.MetricPoints(metricEventAge)
	if len(eventAge) != 1 {
		t.Errorf("%s points = %d, want 1", metricEventAge, len(eventAge))
	} else {
		if got := eventAge[0].Value; got <= 0 || got >= cfg.RecencyWindow.Seconds() {
			t.Errorf("%s value = %v, want positive and below %v", metricEventAge, got, cfg.RecencyWindow)
		}
		if got := eventAge[0].Attrs[semconv.AttrTenantID]; got != "tenant-capture" {
			t.Errorf("%s tenant_id = %q, want tenant-capture", metricEventAge, got)
		}
	}

	if err := signalcapture.GoldenAt(
		"testdata/signals.json", *updateBlobSignals, recorder,
	); err != nil {
		t.Fatal(err)
	}
}
