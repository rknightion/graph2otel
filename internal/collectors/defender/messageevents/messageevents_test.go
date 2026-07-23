package messageevents

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

// liveRecord is a real MessageEvents envelope captured off the m7kni storage
// account as graph2otel-poller (2026-07-23, #241): a delivered Teams channel
// message on an internally-owned, non-external thread.
const liveRecord = `{
 "time": "2026-07-23T09:09:09.9551737Z",
 "tenantId": "4b8c18bd-2f9f-4227-af55-9f1061cf9c32",
 "operationName": "Publish",
 "category": "AdvancedHunting-MessageEvents",
 "_TimeReceivedBySvc": "2026-07-23T09:06:30.9650000Z",
 "properties": {
  "Timestamp": "2026-07-23T09:06:30.965Z",
  "LastEditedTime": "2026-07-23T09:06:30.965Z",
  "TeamsMessageId": "/teams/5bd47737-231d-48e5-b6a0-0c5740d762c1/channels/19:hxvOjycW8oTmYflAjinfTLTJyFEbCRmEnKcKHLiew_41@thread.tacv2/messages/1784797590965",
  "SenderEmailAddress": "rob@m7kni.io",
  "SenderDisplayName": "Rob Knight",
  "SenderObjectId": "bbcfc3c5-0b93-4135-9ef9-18477a9fb504",
  "SenderType": "User",
  "RecipientDetails": [{"RecipientSmtpAddress":"teamtest@m7kni.io","RecipientDisplayName":"teamtest","RecipientObjectId":"00000000-0000-0000-0000-000000000000","RecipientType":"User"}],
  "IsOwnedThread": true,
  "MessageId": "1784797590965",
  "ParentMessageId": "1784797590965",
  "GroupId": "5bd47737-231d-48e5-b6a0-0c5740d762c1",
  "GroupName": "teamtest",
  "ThreadId": "19:hxvOjycW8oTmYflAjinfTLTJyFEbCRmEnKcKHLiew_41@thread.tacv2",
  "ThreadName": "teamtest",
  "ThreadType": "space",
  "ThreadSubType": "None",
  "IsExternalThread": false,
  "MessageType": "RichText",
  "MessageSubtype": "Html",
  "MessageVersion": "1784797590965",
  "Subject": "message with link",
  "ThreatTypes": null,
  "DetectionMethods": null,
  "ConfidenceLevel": null,
  "DeliveryAction": "Delivered",
  "DeliveryLocation": "Teams",
  "ReportId": "d9b04a46-853d-407d-ad45-08dee899c43a",
  "SafetyTip": null
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

func TestMapRecordEmitsMessageFields(t *testing.T) {
	ev, ok := mapRecord(decode(t, liveRecord))
	if !ok {
		t.Fatal("mapRecord dropped a valid record")
	}
	if ev.Name != eventName {
		t.Errorf("event name = %q, want %q", ev.Name, eventName)
	}

	wantTS, _ := time.Parse(time.RFC3339Nano, "2026-07-23T09:06:30.965Z")
	if !ev.Timestamp.Equal(wantTS) {
		t.Errorf("timestamp = %v, want %v (bound to properties.Timestamp)", ev.Timestamp, wantTS)
	}

	want := map[string]string{
		semconv.AttrTeamsMessageId:     "/teams/5bd47737-231d-48e5-b6a0-0c5740d762c1/channels/19:hxvOjycW8oTmYflAjinfTLTJyFEbCRmEnKcKHLiew_41@thread.tacv2/messages/1784797590965",
		semconv.AttrSenderEmailAddress: "rob@m7kni.io",
		semconv.AttrSenderType:         "User",
		semconv.AttrThreadType:         "space",
		semconv.AttrDeliveryAction:     "Delivered",
		semconv.AttrGroupName:          "teamtest",
	}
	for k, v := range want {
		got, _ := ev.Attrs[k].(string)
		if got != v {
			t.Errorf("attr %q = %q, want %q", k, got, v)
		}
	}

	// IsExternalThread=false is present as a bool → emitted (the external-collab
	// signal), not omitted like a null. Bools are stamped as "true"/"false"
	// strings (SetBool) to stay queryable as Loki structured metadata.
	if ext, _ := ev.Attrs[semconv.AttrIsExternalThread].(string); ext != "false" {
		t.Errorf("is_external_thread = %q, want %q", ext, "false")
	}
	if owned, _ := ev.Attrs[semconv.AttrIsOwnedThread].(string); owned != "true" {
		t.Errorf("is_owned_thread = %q, want %q", owned, "true")
	}

	// RecipientDetails emitted verbatim as a marshaled JSON string.
	rd, _ := ev.Attrs[semconv.AttrRecipientDetails].(string)
	if !strings.Contains(rd, "teamtest@m7kni.io") {
		t.Errorf("recipient_details = %q, want it to contain the recipient SMTP address", rd)
	}

	// Null columns omitted, never emitted empty.
	if _, present := ev.Attrs[semconv.AttrThreatTypes]; present {
		t.Error("threat_types should be omitted when null")
	}
	if _, present := ev.Attrs[semconv.AttrSafetyTip]; present {
		t.Error("safety_tip should be omitted when null")
	}
}

func TestMapRecordDropsMalformed(t *testing.T) {
	if _, ok := mapRecord(map[string]any{"time": "2026-07-23T09:09:09Z"}); ok {
		t.Error("record with no properties should be dropped")
	}
	if _, ok := mapRecord(decode(t, `{"properties":{"TeamsMessageId":"m","Timestamp":"not-a-time"}}`)); ok {
		t.Error("record with unparseable Timestamp should be dropped")
	}
	if _, ok := mapRecord(decode(t, `{"properties":{"TeamsMessageId":"m"}}`)); ok {
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
// live record and asserts what reaches the emitter — this is also what makes the
// signals golden substantive (#164).
func TestCollectorEmitsLiveRecordEndToEnd(t *testing.T) {
	const tenant = "4b8c18bd-2f9f-4227-af55-9f1061cf9c32"
	src := &staticSource{
		name: "tenantId=" + tenant + "/y=2026/m=07/d=23/h=09/m=00/PT1H.json",
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
	if got := logs[0].Attrs[semconv.AttrSenderEmailAddress]; got != "rob@m7kni.io" {
		t.Errorf("sender_email_address = %q, want %q", got, "rob@m7kni.io")
	}

	if err := c.Collect(context.Background(), rec.Emitter()); err != nil {
		t.Fatalf("second Collect: %v", err)
	}
	if got := len(rec.LogRecords()); got != 1 {
		t.Errorf("after a second tick over an unchanged blob: %d records, want 1", got)
	}
}
