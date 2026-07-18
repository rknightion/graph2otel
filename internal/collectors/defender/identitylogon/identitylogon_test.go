package identitylogon

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
	"github.com/rknightion/graph2otel/internal/telemetrytest"
)

// liveRecord is a real IdentityLogonEvents envelope captured off the m7kni
// storage account as graph2otel-poller (cert on camden, 2026-07-18, #106): an
// interactive LogonSuccess with AdditionalFields and LastSeenForUser present as
// native JSON objects and most destination/target columns null — the shape a
// mapper must handle.
const liveRecord = `{
  "time": "2026-07-18T14:51:05.0181894Z",
  "tenantId": "4b8c18bd-2f9f-4227-af55-9f1061cf9c32",
  "operationName": "Publish",
  "category": "AdvancedHunting-IdentityLogonEvents",
  "_TimeReceivedBySvc": "2026-07-18T14:45:58.4020000Z",
  "properties": {
    "ActionType": "LogonSuccess",
    "LogonType": "Login:reprocess",
    "Protocol": null,
    "AccountDisplayName": "Rob Knight",
    "AccountUpn": "rob@m7kni.io",
    "AccountName": "rob",
    "AccountDomain": "m7kni.io",
    "AccountSid": null,
    "AccountObjectId": "bbcfc3c5-0b93-4135-9ef9-18477a9fb504",
    "IPAddress": "2001:8b0:1f05:0:0:0:0:1077",
    "Location": "GB",
    "DeviceName": null,
    "OSPlatform": "OS X",
    "DeviceType": "Desktop",
    "ISP": "none specified",
    "DestinationDeviceName": null,
    "TargetDeviceName": null,
    "FailureReason": null,
    "Port": null,
    "DestinationPort": null,
    "DestinationIPAddress": null,
    "TargetAccountDisplayName": null,
    "AdditionalFields": {
      "ARG.CLOUD_SERVICE": "Tailscale",
      "Request ID": "8d250fcb-78c6-4ade-ac29-9b2166446900",
      "Pass-through authentication": "false",
      "ACTOR.ALIAS": "Rob Knight",
      "ACTOR.ENTITY_USER": "Rob Knight"
    },
    "UncommonForUser": [],
    "LastSeenForUser": {
      "ActionType": 0,
      "OSPlatform": 0,
      "ISP": 0,
      "UserAgent": -1,
      "CountryCode": 0,
      "IPAddress": 0,
      "Application": 0
    },
    "ReportId": "d00f01fb408282e4ef340b9421ec8723b77c2deac07e279f9f3ac8e0df3548cc",
    "Timestamp": "2026-07-18T14:43:48.137Z",
    "Application": "Microsoft 365"
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

func TestMapRecordEmitsAccountAndLogonDetail(t *testing.T) {
	ev, ok := mapRecord(decode(t, liveRecord))
	if !ok {
		t.Fatal("mapRecord dropped a valid record")
	}
	if ev.Name != eventName {
		t.Errorf("event name = %q, want %q", ev.Name, eventName)
	}

	// Timestamp bound to properties.Timestamp, as an instant — NOT the envelope
	// `time` or `_TimeReceivedBySvc`.
	wantTS, _ := time.Parse(time.RFC3339Nano, "2026-07-18T14:43:48.137Z")
	if !ev.Timestamp.Equal(wantTS) {
		t.Errorf("timestamp = %v, want %v (bound to properties.Timestamp)", ev.Timestamp, wantTS)
	}

	want := map[string]string{
		semconv.AttrActionType:  "LogonSuccess",
		semconv.AttrLogonType:   "Login:reprocess",
		semconv.AttrAccountUpn:  "rob@m7kni.io",
		semconv.AttrAccountName: "rob",
	}
	for k, v := range want {
		got, _ := ev.Attrs[k].(string)
		if got != v {
			t.Errorf("attr %q = %q, want %q", k, got, v)
		}
	}

	// AdditionalFields is a native JSON object, re-marshaled to a string
	// attribute rather than flattened or dropped.
	additional, _ := ev.Attrs[semconv.AttrAdditionalFields].(string)
	if additional == "" {
		t.Error("additional_fields should be present")
	}
	if !strings.HasPrefix(additional, "{") {
		t.Errorf("additional_fields = %q, want it to start with '{'", additional)
	}
}

func TestMapRecordDropsMalformed(t *testing.T) {
	// No properties → dropped.
	if _, ok := mapRecord(map[string]any{"time": "2026-07-18T14:51:05Z"}); ok {
		t.Error("record with no properties should be dropped")
	}
	// Unparseable Timestamp → dropped, never mis-dated (no fallback to envelope time).
	if _, ok := mapRecord(decode(t, `{"properties":{"AccountUpn":"a@b.com","Timestamp":"not-a-time"}}`)); ok {
		t.Error("record with unparseable Timestamp should be dropped")
	}
	// Missing Timestamp → dropped.
	if _, ok := mapRecord(decode(t, `{"properties":{"AccountUpn":"a@b.com"}}`)); ok {
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

// TestCollectorEmitsLiveRecordEndToEnd drives the whole collector over the pinned
// live record — JSON Lines with the CRLF terminators Azure writes — and asserts
// what reaches the emitter. It is also what makes the signals golden substantive
// (#164): the golden captures the attributes THIS drives into the Recorder.
func TestCollectorEmitsLiveRecordEndToEnd(t *testing.T) {
	const tenant = "4b8c18bd-2f9f-4227-af55-9f1061cf9c32"
	src := &staticSource{
		name: "tenantId=" + tenant + "/y=2026/m=07/d=18/h=14/m=00/PT1H.json",
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
	wantTS, _ := time.Parse(time.RFC3339Nano, "2026-07-18T14:43:48.137Z")
	if !logs[0].Timestamp.Equal(wantTS) {
		t.Errorf("timestamp = %s, want %s", logs[0].Timestamp, wantTS)
	}
	if got := logs[0].Attrs[semconv.AttrLogonType]; got != "Login:reprocess" {
		t.Errorf("logon_type attr = %q, want Login:reprocess", got)
	}

	// Cursor persisted: a second tick over the unchanged blob emits nothing new.
	if err := c.Collect(context.Background(), rec.Emitter()); err != nil {
		t.Fatalf("second Collect: %v", err)
	}
	if got := len(rec.LogRecords()); got != 1 {
		t.Errorf("after a second tick over an unchanged blob: %d records, want 1", got)
	}
}
