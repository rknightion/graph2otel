package alertevidence

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

// liveRecord is a real AlertEvidence envelope captured off the m7kni storage
// account as graph2otel-poller (cert on camden, 2026-07-18, #106) — one of
// three evidence rows Defender attached to the same alert. This one is the Ip
// EntityType: it exercises the geo sub-object inside AdditionalFields.
const liveRecord = `{
  "time": "2026-07-18T14:04:13.9530854Z",
  "tenantId": "4b8c18bd-2f9f-4227-af55-9f1061cf9c32",
  "operationName": "Publish",
  "category": "AdvancedHunting-AlertEvidence",
  "_TimeReceivedBySvc": "2026-07-18T14:04:13.9120000Z",
  "properties": {
    "Timestamp": "2026-07-17T10:07:37.729415Z",
    "AlertId": "ad6450625369250ba3fc4b5752f34f474ec80b20ae",
    "EntityType": "Ip",
    "EvidenceRole": "Related",
    "SHA1": null,
    "SHA256": null,
    "RemoteIP": "2001:67c:e60:c0c:192:42:116:55",
    "LocalIP": null,
    "RemoteUrl": null,
    "AccountName": null,
    "AccountDomain": null,
    "AccountSid": null,
    "AccountObjectId": null,
    "DeviceId": null,
    "ThreatFamily": null,
    "EvidenceDirection": null,
    "AdditionalFields": "{\"Address\":\"2001:67c:e60:c0c:192:42:116:55\",\"Location\":{\"CountryCode\":\"NL\",\"State\":\"Noord-Holland\",\"City\":\"Camperduin\",\"Longitude\":4.65,\"Latitude\":52.733,\"Asn\":215125},\"Type\":\"ip\",\"Role\":1,\"MergeByKey\":\"SZykb2B1LTSp3TruQWbiX8t3ig8=\",\"MergeByKeyHex\":\"499CA46F60752D34A9DD3AEE4166E25FCB778A0F\"}",
    "MachineGroup": null,
    "NetworkMessageId": null,
    "ServiceSource": "AAD Identity Protection",
    "FileName": null,
    "FolderPath": null,
    "ProcessCommandLine": null,
    "EmailSubject": null,
    "ApplicationId": null,
    "Application": null,
    "DeviceName": null,
    "FileSize": null,
    "RegistryKey": null,
    "RegistryValueName": null,
    "RegistryValueData": null,
    "AccountUpn": null,
    "OAuthApplicationId": null,
    "Categories": "[\"InitialAccess\"]",
    "Title": "Malicious IP address",
    "AttackTechniques": "",
    "DetectionSource": "AAD Identity Protection",
    "Severity": "High",
    "CloudResource": null,
    "CloudPlatform": "",
    "ResourceType": null,
    "ResourceID": null,
    "SubscriptionId": ""
  },
  "Tenant": "DefaultTenant"
}`

// userRecord is the second pinned evidence row from the SAME alert as
// liveRecord — the User EntityType, with no geo/AdditionalFields.Location and
// a real AccountUpn.
const userRecord = `{
  "time": "2026-07-18T14:04:13.9529565Z",
  "tenantId": "4b8c18bd-2f9f-4227-af55-9f1061cf9c32",
  "operationName": "Publish",
  "category": "AdvancedHunting-AlertEvidence",
  "_TimeReceivedBySvc": "2026-07-18T14:04:13.9120000Z",
  "properties": {
    "Timestamp": "2026-07-17T10:07:37.729415Z",
    "AlertId": "ad6450625369250ba3fc4b5752f34f474ec80b20ae",
    "EntityType": "User",
    "EvidenceRole": "Impacted",
    "SHA1": null,
    "SHA256": null,
    "RemoteIP": null,
    "LocalIP": null,
    "RemoteUrl": null,
    "AccountName": "risk-synth-delete-me",
    "AccountDomain": null,
    "AccountSid": "S-1-12-1-1384769991-1341995333-1641403279-1576319524",
    "AccountObjectId": "5289e9c7-3945-4ffd-8fd3-d56124baf45d",
    "DeviceId": null,
    "ThreatFamily": null,
    "EvidenceDirection": null,
    "AdditionalFields": "{\"InventoryIdentityId\":\"User_4b8c18bd-2f9f-4227-af55-9f1061cf9c32_d1a05b55-e320-40de-8647-12d5e150b36d\",\"Name\":\"risk-synth-delete-me\",\"UPNSuffix\":\"m7kni.io\",\"Sid\":\"S-1-12-1-1384769991-1341995333-1641403279-1576319524\",\"AadTenantId\":\"4b8c18bd-2f9f-4227-af55-9f1061cf9c32\",\"AadUserId\":\"5289e9c7-3945-4ffd-8fd3-d56124baf45d\",\"IsDomainJoined\":true,\"DisplayName\":\"RISK SYNTH - DELETE ME (graph2otel #129)\",\"Type\":\"account\",\"Role\":0,\"MergeByKey\":\"+Hq6bRPTfPjzuecvwIOXtWro0+k=\",\"MergeByKeyHex\":\"F87ABA6D13D37CF8F3B9E72FC08397B56AE8D3E9\"}",
    "MachineGroup": null,
    "NetworkMessageId": null,
    "ServiceSource": "AAD Identity Protection",
    "FileName": null,
    "FolderPath": null,
    "ProcessCommandLine": null,
    "EmailSubject": null,
    "ApplicationId": null,
    "Application": null,
    "DeviceName": null,
    "FileSize": null,
    "RegistryKey": null,
    "RegistryValueName": null,
    "RegistryValueData": null,
    "AccountUpn": "risk-synth-delete-me@m7kni.io",
    "OAuthApplicationId": null,
    "Categories": "[\"InitialAccess\"]",
    "Title": "Malicious IP address",
    "AttackTechniques": "",
    "DetectionSource": "AAD Identity Protection",
    "Severity": "High",
    "CloudResource": null,
    "CloudPlatform": "",
    "ResourceType": null,
    "ResourceID": null,
    "SubscriptionId": ""
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

func TestMapRecordIpEntityEmitsGeo(t *testing.T) {
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

	if ev.Severity != telemetry.SeverityError {
		t.Errorf("severity = %v, want SeverityError (Severity \"High\")", ev.Severity)
	}

	want := map[string]string{
		semconv.AttrEntityType:    "Ip",
		semconv.AttrRemoteIp:      "2001:67c:e60:c0c:192:42:116:55",
		semconv.AttrTitle:         "Malicious IP address",
		semconv.AttrServiceSource: "AAD Identity Protection",
		semconv.AttrGeoCountry:    "NL",
		semconv.AttrGeoCity:       "Camperduin",
	}
	for k, v := range want {
		got, _ := ev.Attrs[k].(string)
		if got != v {
			t.Errorf("attr %q = %q, want %q", k, got, v)
		}
	}

	if got, _ := ev.Attrs[semconv.AttrAdditionalFields].(string); got == "" {
		t.Error("additional_fields should be emitted verbatim, not empty")
	}
}

func TestMapRecordUserEntity(t *testing.T) {
	ev, ok := mapRecord(decode(t, userRecord))
	if !ok {
		t.Fatal("mapRecord dropped a valid record")
	}

	want := map[string]string{
		semconv.AttrAccountUpn:   "risk-synth-delete-me@m7kni.io",
		semconv.AttrEntityType:   "User",
		semconv.AttrEvidenceRole: "Impacted",
	}
	for k, v := range want {
		got, _ := ev.Attrs[k].(string)
		if got != v {
			t.Errorf("attr %q = %q, want %q", k, got, v)
		}
	}
}

func TestMapRecordDropsMalformed(t *testing.T) {
	// No properties → dropped.
	if _, ok := mapRecord(map[string]any{"time": "2026-07-18T14:04:13Z"}); ok {
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
	wantTS, _ := time.Parse(time.RFC3339Nano, "2026-07-17T10:07:37.729415Z")
	if !logs[0].Timestamp.Equal(wantTS) {
		t.Errorf("timestamp = %s, want %s", logs[0].Timestamp, wantTS)
	}
	if got := logs[0].Attrs[semconv.AttrEntityType]; got != "Ip" {
		t.Errorf("entity_type attr = %q, want Ip", got)
	}

	// Cursor persisted: a second tick over the unchanged blob emits nothing new.
	if err := c.Collect(context.Background(), rec.Emitter()); err != nil {
		t.Fatalf("second Collect: %v", err)
	}
	if got := len(rec.LogRecords()); got != 1 {
		t.Errorf("after a second tick over an unchanged blob: %d records, want 1", got)
	}
}
