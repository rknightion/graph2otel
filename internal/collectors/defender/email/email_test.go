package email

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

// liveRecord is a real EmailEvents envelope captured off the m7kni storage
// account as graph2otel-poller (cert on camden, 2026-07-18, #106): a
// "Microsoft Azure" risk-detection notification delivered to rob@m7kni.io.
// It keeps the To/Cc arrays (To has one recipient, Cc is empty) so the array
// handling is exercised end to end.
const liveRecord = `{
  "time": "2026-07-18T14:11:24.3832981Z",
  "tenantId": "4b8c18bd-2f9f-4227-af55-9f1061cf9c32",
  "operationName": "Publish",
  "category": "AdvancedHunting-EmailEvents",
  "_TimeReceivedBySvc": "2026-07-18T14:08:56.0000000",
  "properties": {
    "Timestamp": "2026-07-18T14:08:56Z",
    "NetworkMessageId": "3c7b1317-ac21-4754-5a76-08dee4d61558",
    "InternetMessageId": "<da09dfe0-fe1c-49ee-974d-3d20ad913757@az.westeurope.microsoft.com>",
    "SenderMailFromAddress": "azure-noreply@microsoft.com",
    "SenderFromAddress": "azure-noreply@microsoft.com",
    "SenderDisplayName": "Microsoft Azure",
    "SenderObjectId": null,
    "SenderMailFromDomain": "microsoft.com",
    "SenderFromDomain": "microsoft.com",
    "SenderIPv4": "20.105.209.76",
    "SenderIPv6": null,
    "RecipientEmailAddress": "rob@m7kni.io",
    "RecipientObjectId": "bbcfc3c5-0b93-4135-9ef9-18477a9fb504",
    "Subject": "User at risk detected",
    "EmailClusterId": 2898195034,
    "EmailDirection": "Inbound",
    "DeliveryAction": "Delivered",
    "DeliveryLocation": "Inbox/folder",
    "ThreatTypes": null,
    "ThreatNames": null,
    "DetectionMethods": null,
    "ConfidenceLevel": null,
    "BulkComplaintLevel": null,
    "EmailAction": null,
    "EmailActionPolicy": null,
    "EmailActionPolicyGuid": null,
    "AuthenticationDetails": "{\"SPF\":\"pass\",\"DKIM\":\"pass\",\"DMARC\":\"pass\",\"CompAuth\":\"pass\"}",
    "AttachmentCount": 0,
    "UrlCount": 16,
    "EmailLanguage": "en",
    "Connectors": null,
    "OrgLevelAction": null,
    "OrgLevelPolicy": null,
    "UserLevelAction": null,
    "UserLevelPolicy": null,
    "ReportId": "3c7b1317-ac21-4754-5a76-08dee4d61558-4061291175951672650-1",
    "AdditionalFields": null,
    "ExchangeTransportRule": null,
    "DistributionList": null,
    "ForwardingInformation": null,
    "Context": null,
    "To": [
      "rob@m7kni.io"
    ],
    "Cc": [],
    "ThreatClassification": null,
    "RecipientDomain": "m7kni.io",
    "EmailSize": 239528,
    "IsFirstContact": true
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

func TestMapRecordEmitsEmailFields(t *testing.T) {
	ev, ok := mapRecord(decode(t, liveRecord))
	if !ok {
		t.Fatal("mapRecord dropped a valid record")
	}
	if ev.Name != eventName {
		t.Errorf("event name = %q, want %q", ev.Name, eventName)
	}

	// Timestamp bound to properties.Timestamp, as an instant — NOT the envelope
	// `time` or `_TimeReceivedBySvc`.
	wantTS, _ := time.Parse(time.RFC3339Nano, "2026-07-18T14:08:56Z")
	if !ev.Timestamp.Equal(wantTS) {
		t.Errorf("timestamp = %v, want %v (bound to properties.Timestamp)", ev.Timestamp, wantTS)
	}

	want := map[string]string{
		semconv.AttrSenderFromAddress: "azure-noreply@microsoft.com",
		semconv.AttrSubject:           "User at risk detected",
		semconv.AttrDeliveryAction:    "Delivered",
		semconv.AttrRecipientDomain:   "m7kni.io",
	}
	for k, v := range want {
		got, _ := ev.Attrs[k].(string)
		if got != v {
			t.Errorf("attr %q = %q, want %q", k, got, v)
		}
	}

	if got, _ := ev.Attrs[semconv.AttrAuthenticationDetails].(string); !strings.HasPrefix(got, "{") {
		t.Errorf("authentication_details = %q, want it to start with '{' (verbatim stringified JSON)", got)
	}

	toAttr, ok := ev.Attrs[semconv.AttrTo].([]string)
	if !ok {
		t.Fatalf("to attr = %#v (%T), want []string", ev.Attrs[semconv.AttrTo], ev.Attrs[semconv.AttrTo])
	}
	if len(toAttr) != 1 || toAttr[0] != "rob@m7kni.io" {
		t.Errorf("to = %v, want [rob@m7kni.io]", toAttr)
	}

	if _, present := ev.Attrs[semconv.AttrCc]; present {
		t.Error("cc should be omitted when the array is empty, not emitted as []")
	}

	if got, _ := ev.Attrs[semconv.AttrIsFirstContact].(string); got != "true" {
		t.Errorf("is_first_contact = %q, want \"true\"", got)
	}
}

func TestMapRecordDropsMalformed(t *testing.T) {
	// No properties → dropped.
	if _, ok := mapRecord(map[string]any{"time": "2026-07-18T14:11:24Z"}); ok {
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
	wantTS, _ := time.Parse(time.RFC3339Nano, "2026-07-18T14:08:56Z")
	if !logs[0].Timestamp.Equal(wantTS) {
		t.Errorf("timestamp = %s, want %s", logs[0].Timestamp, wantTS)
	}
	if got := logs[0].Attrs[semconv.AttrSubject]; got != "User at risk detected" {
		t.Errorf("subject = %q, want %q", got, "User at risk detected")
	}

	// Cursor persisted: a second tick over the unchanged blob emits nothing new.
	if err := c.Collect(context.Background(), rec.Emitter()); err != nil {
		t.Fatalf("second Collect: %v", err)
	}
	if got := len(rec.LogRecords()); got != 1 {
		t.Errorf("after a second tick over an unchanged blob: %d records, want 1", got)
	}
}
