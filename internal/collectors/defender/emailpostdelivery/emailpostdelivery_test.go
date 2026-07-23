package emailpostdelivery

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

// liveRecord is a real EmailPostDeliveryEvents envelope captured off the m7kni
// storage account as graph2otel-poller (2026-07-23, #233), container
// insights-logs-advancedhunting-emailpostdeliveryevents: a Redelivery of an
// already-delivered Microsoft notification back into the Inbox. It keeps the
// null columns (ThreatTypes, DetectionMethods, EmailDirection) so the
// omit-on-null behavior is exercised end to end.
const liveRecord = `{
  "time": "2026-07-22T10:44:33.4250955Z",
  "tenantId": "4b8c18bd-2f9f-4227-af55-9f1061cf9c32",
  "operationName": "Publish",
  "category": "AdvancedHunting-EmailPostDeliveryEvents",
  "_TimeReceivedBySvc": "2026-07-22T10:43:05.0000000",
  "properties": {
    "Timestamp": "2026-07-22T10:43:05Z",
    "NetworkMessageId": "80aa9dda-c565-45a0-6133-08dee7cf4a7a",
    "InternetMessageId": "<b853e0df-14f3-43c1-8058-a64e640d1b50@az.centralus.microsoft.com>",
    "Action": "Reprocessed",
    "ActionType": "Redelivery",
    "ActionTrigger": "SpecialAction",
    "ActionResult": "Success",
    "RecipientEmailAddress": "rob@m7kni.io",
    "DeliveryLocation": "Inbox",
    "ThreatTypes": null,
    "DetectionMethods": null,
    "ReportId": "80aa9dda-c565-45a0-6133-08dee7cf4a7a-4061291175951672650",
    "SenderFromAddress": "microsoft-noreply@microsoft.com",
    "EmailDirection": null
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

func TestMapRecordEmitsPostDeliveryFields(t *testing.T) {
	ev, ok := mapRecord(decode(t, liveRecord))
	if !ok {
		t.Fatal("mapRecord dropped a valid record")
	}
	if ev.Name != eventName {
		t.Errorf("event name = %q, want %q", ev.Name, eventName)
	}

	// Timestamp bound to properties.Timestamp, as an instant — NOT the envelope
	// `time` or `_TimeReceivedBySvc`.
	wantTS, _ := time.Parse(time.RFC3339Nano, "2026-07-22T10:43:05Z")
	if !ev.Timestamp.Equal(wantTS) {
		t.Errorf("timestamp = %v, want %v (bound to properties.Timestamp)", ev.Timestamp, wantTS)
	}
	envelopeTS, _ := time.Parse(time.RFC3339Nano, "2026-07-22T10:44:33.4250955Z")
	if ev.Timestamp.Equal(envelopeTS) {
		t.Error("timestamp is the envelope `time` (Azure's export clock), not properties.Timestamp")
	}
	// _TimeReceivedBySvc is NOT asserted against: on this live record it holds
	// the same instant as properties.Timestamp (10:43:05), so the two are
	// indistinguishable here. The envelope `time` (10:44:33, 88s later) is the
	// clock that actually differs, and it is what the check above rules out.

	want := map[string]string{
		semconv.AttrNetworkMessageId:      "80aa9dda-c565-45a0-6133-08dee7cf4a7a",
		semconv.AttrInternetMessageId:     "<b853e0df-14f3-43c1-8058-a64e640d1b50@az.centralus.microsoft.com>",
		semconv.AttrAction:                "Reprocessed",
		semconv.AttrActionType:            "Redelivery",
		semconv.AttrActionTrigger:         "SpecialAction",
		semconv.AttrActionResult:          "Success",
		semconv.AttrRecipientEmailAddress: "rob@m7kni.io",
		semconv.AttrDeliveryLocation:      "Inbox",
		semconv.AttrSenderFromAddress:     "microsoft-noreply@microsoft.com",
		// ReportId on this table is a composite STRING, not the numeric
		// per-device sequence the Device* tables carry.
		semconv.AttrReportId: "80aa9dda-c565-45a0-6133-08dee7cf4a7a-4061291175951672650",
	}
	for k, v := range want {
		got, ok := ev.Attrs[k].(string)
		if !ok {
			t.Errorf("attr %q = %#v (%T), want the string %q", k, ev.Attrs[k], ev.Attrs[k], v)
			continue
		}
		if got != v {
			t.Errorf("attr %q = %q, want %q", k, got, v)
		}
	}
}

func TestMapRecordOmitsNullColumns(t *testing.T) {
	ev, ok := mapRecord(decode(t, liveRecord))
	if !ok {
		t.Fatal("mapRecord dropped a valid record")
	}
	for _, attr := range []string{
		semconv.AttrThreatTypes,
		semconv.AttrDetectionMethods,
		semconv.AttrEmailDirection,
	} {
		if v, present := ev.Attrs[attr]; present {
			t.Errorf("attr %q = %#v, want it absent — a null column is omitted, never emitted empty", attr, v)
		}
	}
}

func TestMapRecordBody(t *testing.T) {
	ev, ok := mapRecord(decode(t, liveRecord))
	if !ok {
		t.Fatal("mapRecord dropped a valid record")
	}
	const want = "Reprocessed (Redelivery) for rob@m7kni.io: Success"
	if ev.Body != want {
		t.Errorf("body = %q, want %q", ev.Body, want)
	}
}

func TestMapRecordSeverityTracksActionResult(t *testing.T) {
	tests := []struct {
		name         string
		actionResult string
		want         telemetry.Severity
	}{
		{"success", `"Success"`, telemetry.SeverityInfo},
		{"absent", `null`, telemetry.SeverityInfo},
		{"failed", `"Failed"`, telemetry.SeverityWarn},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			body := `{"properties":{"Timestamp":"2026-07-22T10:43:05Z","ActionResult":` + tc.actionResult + `}}`
			ev, ok := mapRecord(decode(t, body))
			if !ok {
				t.Fatal("mapRecord dropped a valid record")
			}
			if ev.Severity != tc.want {
				t.Errorf("severity = %v, want %v (a remediation that did not succeed is the interesting case)", ev.Severity, tc.want)
			}
		})
	}
}

func TestMapRecordDropsMalformed(t *testing.T) {
	// No properties → dropped.
	if _, ok := mapRecord(map[string]any{"time": "2026-07-22T10:44:33Z"}); ok {
		t.Error("record with no properties should be dropped")
	}
	// Unparseable Timestamp → dropped, never mis-dated (no fallback to envelope time).
	if _, ok := mapRecord(decode(t, `{"properties":{"NetworkMessageId":"n","Timestamp":"not-a-time"}}`)); ok {
		t.Error("record with unparseable Timestamp should be dropped")
	}
	// Missing Timestamp → dropped.
	if _, ok := mapRecord(decode(t, `{"properties":{"NetworkMessageId":"n"}}`)); ok {
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
		name: "tenantId=" + tenant + "/y=2026/m=07/d=22/h=10/m=00/PT1H.json",
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
	wantTS, _ := time.Parse(time.RFC3339Nano, "2026-07-22T10:43:05Z")
	if !logs[0].Timestamp.Equal(wantTS) {
		t.Errorf("timestamp = %s, want %s", logs[0].Timestamp, wantTS)
	}
	if got := logs[0].Attrs[semconv.AttrActionType]; got != "Redelivery" {
		t.Errorf("action_type = %q, want %q", got, "Redelivery")
	}

	// Cursor persisted: a second tick over the unchanged blob emits nothing new.
	if err := c.Collect(context.Background(), rec.Emitter()); err != nil {
		t.Fatalf("second Collect: %v", err)
	}
	if got := len(rec.LogRecords()); got != 1 {
		t.Errorf("after a second tick over an unchanged blob: %d records, want 1", got)
	}
}
