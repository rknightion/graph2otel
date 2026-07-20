package alertinfo

import (
	"bytes"
	"context"
	"encoding/json"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/rknightion/graph2otel/internal/blobpipeline"
	"github.com/rknightion/graph2otel/internal/checkpoint"
	"github.com/rknightion/graph2otel/internal/collectors"
	"github.com/rknightion/graph2otel/internal/semconv"
	"github.com/rknightion/graph2otel/internal/telemetry"
	"github.com/rknightion/graph2otel/internal/telemetrytest"
)

// liveRecord is a real AlertInfo envelope captured off the m7kni storage
// account as graph2otel-poller (cert on camden, 2026-07-18, #106): an AAD
// Identity Protection alert. MachineGroup is JSON null and AttackTechniques
// is an empty string on this record — the "mostly absent" shape a mapper
// must handle without emitting empty attributes.
const liveRecord = `{
  "time": "2026-07-18T14:04:13.9516714Z",
  "tenantId": "4b8c18bd-2f9f-4227-af55-9f1061cf9c32",
  "operationName": "Publish",
  "category": "AdvancedHunting-AlertInfo",
  "_TimeReceivedBySvc": "2026-07-18T14:04:13.9140000Z",
  "properties": {
    "Timestamp": "2026-07-17T10:07:37.729415Z",
    "AlertId": "ad6450625369250ba3fc4b5752f34f474ec80b20ae",
    "Title": "Malicious IP address",
    "Category": "InitialAccess",
    "Severity": "High",
    "ServiceSource": "AAD Identity Protection",
    "DetectionSource": "AAD Identity Protection",
    "MachineGroup": null,
    "AttackTechniques": ""
  },
  "Tenant": "DefaultTenant"
}`

func decode(t *testing.T, body string) map[string]any {
	t.Helper()
	var rec map[string]any
	if err := json.Unmarshal([]byte(body), &rec); err != nil {
		t.Fatalf("decode: %v", err)
	}
	return rec
}

func TestMapRecordEmitsAlertInfo(t *testing.T) {
	ev, ok := mapRecord(decode(t, liveRecord))
	if !ok {
		t.Fatal("mapRecord dropped a valid record")
	}
	if ev.Name != eventName {
		t.Errorf("event name = %q, want %q", ev.Name, eventName)
	}

	// Timestamp bound to properties.Timestamp, as an instant — NOT the envelope
	// `time` or `_TimeReceivedBySvc`.
	wantTS, _ := time.Parse(time.RFC3339Nano, "2026-07-17T10:07:37.729415Z")
	if !ev.Timestamp.Equal(wantTS) {
		t.Errorf("timestamp = %v, want %v (bound to properties.Timestamp)", ev.Timestamp, wantTS)
	}

	want := map[string]string{
		semconv.AttrAlertId:         "ad6450625369250ba3fc4b5752f34f474ec80b20ae",
		semconv.AttrTitle:           "Malicious IP address",
		semconv.AttrCategory:        "InitialAccess",
		semconv.AttrSeverity:        "High",
		semconv.AttrServiceSource:   "AAD Identity Protection",
		semconv.AttrDetectionSource: "AAD Identity Protection",
	}
	for k, v := range want {
		got, _ := ev.Attrs[k].(string)
		if got != v {
			t.Errorf("attr %q = %q, want %q", k, got, v)
		}
	}

	// High severity maps to telemetry.SeverityError (alertevidence's convention).
	if ev.Severity != telemetry.SeverityError {
		t.Errorf("severity = %v, want SeverityError for High", ev.Severity)
	}

	// Null MachineGroup and empty-string AttackTechniques are omitted, never
	// emitted as empty/zero values.
	for _, k := range []string{semconv.AttrMachineGroup, semconv.AttrAttackTechniques} {
		if _, present := ev.Attrs[k]; present {
			t.Errorf("attr %q should be omitted (null/empty source), got %v", k, ev.Attrs[k])
		}
	}

	wantBody := "High [InitialAccess] Malicious IP address"
	if ev.Body != wantBody {
		t.Errorf("body = %q, want %q", ev.Body, wantBody)
	}
}

func TestMapRecordDropsMalformed(t *testing.T) {
	// No properties → dropped.
	if _, ok := mapRecord(map[string]any{"time": "2026-07-18T17:00:07Z"}); ok {
		t.Error("record with no properties should be dropped")
	}
	// Unparseable Timestamp → dropped, never mis-dated (no fallback to envelope time).
	if _, ok := mapRecord(decode(t, `{"properties":{"AlertId":"a","Timestamp":"not-a-time"}}`)); ok {
		t.Error("record with unparseable Timestamp should be dropped")
	}
	// Missing Timestamp → dropped.
	if _, ok := mapRecord(decode(t, `{"properties":{"AlertId":"a"}}`)); ok {
		t.Error("record with no Timestamp should be dropped")
	}
}

// staticSource is a blobpipeline.Source serving one in-memory blob, so the
// collector runs end-to-end without Azure.
type staticSource struct {
	name string
	data []byte
}

func (s *staticSource) List(_ context.Context, _, prefix string) ([]blobpipeline.BlobInfo, error) {
	if !strings.HasPrefix(s.name, prefix) {
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

// TestCollectorEmitsLiveRecordEndToEnd drives the whole collector over the
// pinned live record — JSON Lines with the CRLF terminators Azure writes —
// and asserts what reaches the emitter. It is also what makes the signals
// golden substantive (#164): the golden captures the attributes THIS drives
// into the Recorder.
func TestCollectorEmitsLiveRecordEndToEnd(t *testing.T) {
	const tenant = "4b8c18bd-2f9f-4227-af55-9f1061cf9c32"
	src := &staticSource{
		name: "tenantId=" + tenant + "/y=2026/m=07/d=18/h=14/m=04/PT1H.json",
		data: []byte(compactJSON(t, liveRecord) + "\r\n"),
	}
	rec := telemetrytest.New()
	c := newBlobCollector(collectors.BlobDeps{
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
	wantTS, _ := time.Parse(time.RFC3339Nano, "2026-07-17T10:07:37.729415Z")
	if !logs[0].Timestamp.Equal(wantTS) {
		t.Errorf("timestamp = %s, want %s", logs[0].Timestamp, wantTS)
	}
	if got := logs[0].Attrs[semconv.AttrAlertId]; got != "ad6450625369250ba3fc4b5752f34f474ec80b20ae" {
		t.Errorf("alert_id attr = %q, want ad6450625369250ba3fc4b5752f34f474ec80b20ae", got)
	}

	// Cursor persisted: a second tick over the unchanged blob emits nothing new.
	if err := c.Collect(context.Background(), rec.Emitter()); err != nil {
		t.Fatalf("second Collect: %v", err)
	}
	if got := len(rec.LogRecords()); got != 1 {
		t.Errorf("after a second tick over an unchanged blob: %d records, want 1", got)
	}
}
