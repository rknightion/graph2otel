package graphnotifications

import (
	"bytes"
	"context"
	"encoding/json"
	"log/slog"
	"testing"
	"time"

	"github.com/rknightion/graph2otel/internal/blobpipeline"
	"github.com/rknightion/graph2otel/internal/checkpoint"
	"github.com/rknightion/graph2otel/internal/collectors"
	"github.com/rknightion/graph2otel/internal/semconv"
	"github.com/rknightion/graph2otel/internal/telemetry"
	"github.com/rknightion/graph2otel/internal/telemetrytest"
)

// liveRecord is a real GraphNotificationsActivityLogs envelope captured as
// graph2otel-poller (2026-07-17, #134): one successful notification publish, with
// properties.timeGenerated and the top-level `time` carrying the same instant,
// resultStatusCode as a native int, durationMs as an int in properties (and a
// string at the top level), and level "Informational" despite a 200.
const liveRecord = `{
 "time": "2026-07-17T09:51:04.8930910Z",
 "resourceId": "d0428537-bde0-416e-9bcf-ebb922bac393|",
 "operationName": "Graph Notifications Activity",
 "category": "GraphNotificationsActivityLogs",
 "resultSignature": "7/17/2026 9:51:04 AM +00:00",
 "durationMs": "17",
 "level": "Informational",
 "location": "North Europe",
 "properties": {
  "timeGenerated": "2026-07-17T09:51:04.893091Z",
  "location": "North Europe",
  "message": "Publishing 1 notifications to aadgroups-dq-prodweu.vault.azure.net ... 200 OK ...",
  "correlationId": "252b75ec-82bf-46db-9185-16bd448200be",
  "resourceId": "d0428537-bde0-416e-9bcf-ebb922bac393|",
  "contextId": "d0428537-bde0-416e-9bcf-ebb922bac393",
  "resultDescription": "200 OK: Successfully published notifications to the event hub.",
  "resultSignature": "7/17/2026 9:51:04 AM +00:00",
  "resultStatusCode": 200,
  "subscriptionId": "86ffb427-d53c-4f15-b609-2d8b4005eab5",
  "publicationIds": "252b75ec-82bf-46db-9185-16bd448200be,d0428537-bde0-416e-9bcf-ebb922bac393|",
  "tenantId": "4b8c18bd-2f9f-4227-af55-9f1061cf9c32",
  "durationMs": 17,
  "workloadNamespace": "Microsoft.DirectoryServices",
  "webHeaders": "",
  "accountType": "AAD",
  "applicationId": "65d91a3d-ab74-42e6-8a2f-0add61688c74",
  "operationType": "NotificationPublisherWorker",
  "loggingLevel": "Informational",
  "isReplay": false
 },
 "tenantId": "4b8c18bd-2f9f-4227-af55-9f1061cf9c32"
}`

func decode(t *testing.T, body string) map[string]any {
	t.Helper()
	var rec map[string]any
	if err := json.Unmarshal([]byte(body), &rec); err != nil {
		t.Fatalf("decode: %v", err)
	}
	return rec
}

func TestMapRecordEmitsPublishDetail(t *testing.T) {
	ev, ok := mapRecord(decode(t, liveRecord))
	if !ok {
		t.Fatal("mapRecord dropped a valid record")
	}
	if ev.Name != eventName {
		t.Errorf("event name = %q, want %q", ev.Name, eventName)
	}

	// Timestamp bound to properties.timeGenerated (RFC3339Nano) — the same instant
	// as the top-level `time`.
	wantTS, _ := time.Parse(time.RFC3339Nano, "2026-07-17T09:51:04.893091Z")
	if !ev.Timestamp.Equal(wantTS) {
		t.Errorf("timestamp = %v, want %v (bound to properties.timeGenerated)", ev.Timestamp, wantTS)
	}

	// A 200 publish is Info, not Error — despite level "Informational" being the
	// value on every record, severity comes from resultStatusCode.
	if ev.Severity != telemetry.SeverityInfo {
		t.Errorf("severity = %v, want Info for a 200", ev.Severity)
	}

	wantStr := map[string]string{
		semconv.AttrApplicationId:     "65d91a3d-ab74-42e6-8a2f-0add61688c74",
		semconv.AttrSubscriptionId:    "86ffb427-d53c-4f15-b609-2d8b4005eab5",
		semconv.AttrWorkloadNamespace: "Microsoft.DirectoryServices",
		semconv.AttrOperationType:     "NotificationPublisherWorker",
		semconv.AttrCorrelationId:     "252b75ec-82bf-46db-9185-16bd448200be",
		semconv.AttrContextId:         "d0428537-bde0-416e-9bcf-ebb922bac393",
		semconv.AttrResultDescription: "200 OK: Successfully published notifications to the event hub.",
		semconv.AttrAccountType:       "AAD",
		semconv.AttrLocation:          "North Europe",
	}
	for k, v := range wantStr {
		got, _ := ev.Attrs[k].(string)
		if got != v {
			t.Errorf("attr %q = %q, want %q", k, got, v)
		}
	}

	// resultStatusCode and durationMs are ints, read from properties (durationMs is
	// a string at the top level and must NOT be read from there).
	if got, _ := ev.Attrs[semconv.AttrResultStatusCode].(int); got != 200 {
		t.Errorf("result_status_code = %v, want 200", ev.Attrs[semconv.AttrResultStatusCode])
	}
	if got, _ := ev.Attrs[semconv.AttrDurationMs].(int); got != 17 {
		t.Errorf("duration_ms = %v, want 17 (the int in properties, not the top-level string)", ev.Attrs[semconv.AttrDurationMs])
	}

	// isReplay present → bool attribute.
	if got, ok := ev.Attrs[semconv.AttrIsReplay].(bool); !ok || got != false {
		t.Errorf("is_replay = %v, want false", ev.Attrs[semconv.AttrIsReplay])
	}

	// The verbose free-text `message` field is not emitted as its own attribute.
	if _, present := ev.Attrs["message"]; present {
		t.Error("message should not be a standalone attribute")
	}
}

func TestMapRecordSeverityFromStatus(t *testing.T) {
	cases := []struct {
		status int
		want   telemetry.Severity
	}{
		{200, telemetry.SeverityInfo},
		{404, telemetry.SeverityWarn},
		{500, telemetry.SeverityError},
	}
	for _, tc := range cases {
		rec := map[string]any{"properties": map[string]any{
			"timeGenerated":    "2026-07-17T09:51:04.893091Z",
			"resultStatusCode": float64(tc.status),
		}}
		ev, ok := mapRecord(rec)
		if !ok {
			t.Fatalf("status %d: dropped a valid record", tc.status)
		}
		if ev.Severity != tc.want {
			t.Errorf("status %d: severity = %v, want %v", tc.status, ev.Severity, tc.want)
		}
	}
}

func TestMapRecordDropsMalformed(t *testing.T) {
	// No properties → dropped.
	if _, ok := mapRecord(map[string]any{"time": "2026-07-17T09:51:04.8930910Z"}); ok {
		t.Error("record with no properties should be dropped")
	}
	// Unparseable event time (both timeGenerated and top-level time) → dropped,
	// never mis-dated.
	if _, ok := mapRecord(decode(t, `{"time":"nope","properties":{"timeGenerated":"not-a-time","resultStatusCode":200}}`)); ok {
		t.Error("record with unparseable event time should be dropped")
	}
	// No event time at all → dropped.
	if _, ok := mapRecord(decode(t, `{"properties":{"resultStatusCode":200}}`)); ok {
		t.Error("record with no event time should be dropped")
	}
}

// TestEventTimeFallsBackToTopLevelTime proves the top-level `time` is used when
// properties.timeGenerated is absent.
func TestEventTimeFallsBackToTopLevelTime(t *testing.T) {
	ev, ok := mapRecord(decode(t, `{"time":"2026-07-17T09:51:04.8930910Z","properties":{"resultStatusCode":200}}`))
	if !ok {
		t.Fatal("record with only top-level time should be kept")
	}
	wantTS, _ := time.Parse(time.RFC3339Nano, "2026-07-17T09:51:04.8930910Z")
	if !ev.Timestamp.Equal(wantTS) {
		t.Errorf("timestamp = %v, want %v (fallback to top-level time)", ev.Timestamp, wantTS)
	}
}

// staticSource is a blobpipeline.Source serving one in-memory blob, so the
// collector runs end-to-end without Azure.
type staticSource struct {
	name string
	data []byte
}

func (s *staticSource) List(_ context.Context, _, prefix string) ([]blobpipeline.BlobInfo, error) {
	if len(prefix) > len(s.name) || s.name[:len(prefix)] != prefix {
		return nil, nil
	}
	return []blobpipeline.BlobInfo{{Name: s.name, Size: int64(len(s.data))}}, nil
}

func (s *staticSource) ReadRange(_ context.Context, _, _ string, offset, count int64) ([]byte, error) {
	end := min(offset+count, int64(len(s.data)))
	if offset >= end {
		return nil, nil
	}
	return s.data[offset:end], nil
}

func compactJSON(t *testing.T, raw string) string {
	t.Helper()
	var buf bytes.Buffer
	if err := json.Compact(&buf, []byte(raw)); err != nil {
		t.Fatalf("compacting the pinned record: %v", err)
	}
	return buf.String()
}

// TestCollectorEmitsLiveRecordEndToEnd drives the whole collector over the pinned
// live record — JSON Lines with the CRLF terminators Azure writes — and asserts
// what reaches the emitter, then that the cursor persists across a second tick.
func TestCollectorEmitsLiveRecordEndToEnd(t *testing.T) {
	const tenant = "4b8c18bd-2f9f-4227-af55-9f1061cf9c32"
	src := &staticSource{
		name: "tenantId=" + tenant + "/y=2026/m=07/d=17/h=09/m=00/PT1H.json",
		data: []byte(compactJSON(t, liveRecord) + "\r\n"),
	}
	rec := telemetrytest.New()
	c := newCollector(collectors.BlobDeps{
		TenantID: tenant,
		Source:   src,
		Store:    checkpoint.NewStore(t.TempDir()),
		Logger:   slog.New(slog.DiscardHandler),
	})

	if err := c.Collect(context.Background(), rec.Emitter()); err != nil {
		t.Fatalf("Collect: %v", err)
	}
	logs := rec.LogRecords()
	if len(logs) != 1 {
		t.Fatalf("emitted %d records, want 1 — check the tenantId= listing prefix", len(logs))
	}
	if logs[0].EventName != eventName {
		t.Errorf("event name = %q, want %q", logs[0].EventName, eventName)
	}
	wantTS, _ := time.Parse(time.RFC3339Nano, "2026-07-17T09:51:04.893091Z")
	if !logs[0].Timestamp.Equal(wantTS) {
		t.Errorf("timestamp = %s, want %s", logs[0].Timestamp, wantTS)
	}
	if got := logs[0].Attrs[semconv.AttrApplicationId]; got != "65d91a3d-ab74-42e6-8a2f-0add61688c74" {
		t.Errorf("application_id attr = %q, want the subscription owner", got)
	}

	// Cursor persisted: a second tick over the unchanged blob emits nothing new.
	if err := c.Collect(context.Background(), rec.Emitter()); err != nil {
		t.Fatalf("second Collect: %v", err)
	}
	if got := len(rec.LogRecords()); got != 1 {
		t.Errorf("after a second tick over an unchanged blob: %d records, want 1", got)
	}
}
