package compliancealerts

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

// liveRecord is a real OperationalLogs (Intune compliance) envelope captured off
// the m7kni storage account as graph2otel-poller (2026-07-17, #94/#135): a
// "Managed Device not Compliant" fired-event for a MacMDM device, with the
// failing FileVault rule in Description and most device columns populated.
const liveRecord = `{
 "time": "2026-07-17T11:50:38.5951000Z",
 "tenantId": "4b8c18bd-2f9f-4227-af55-9f1061cf9c32",
 "category": "OperationalLogs",
 "operationName": "Compliance",
 "resultType": "None",
 "properties": {
  "IntuneAccountId": "e933bb26-3dff-49f0-a41a-bd722a92f1fb",
  "AlertDisplayName": "Managed Device THRWX5256T_14_7/17/2026_11:48 AM is not Compliant",
  "AlertType": "Managed Device Not Compliant",
  "AADTenantId": "4b8c18bd-2f9f-4227-af55-9f1061cf9c32",
  "Description": "MacOSCompliancePolicy.StorageRequireEncryption_IID_f36d2c05-9b72-7943-3303-284d29dece89||||Device_Encryption_FileVault2Encrypted||Equals True||False||SecurityInfo/FDE_Enabled",
  "DeviceDnsDomain": "",
  "DeviceHostName": "MacBook Pro",
  "IntuneDeviceId": "33dcca32-d6ea-478b-88d9-e2a891f9d83a",
  "DeviceName": "THRWX5256T_14_7/17/2026_11:48 AM",
  "DeviceNetBiosName": "MacBook Pro",
  "DeviceOperatingSystem": "MacMDM 26.5.2 (25F84)",
  "ScaleUnit": "AMSUB0601",
  "ScenarioName": "Microsoft.Management.Services.Diagnostics.SLAEvents.DeviceNotInComplianceSecurityAlert",
  "StartTimeUtc": "2026-07-17T11:50:38.5951Z",
  "UserName": "rob",
  "UPNSuffix": "m7kni.io",
  "UserDisplayName": "Rob Knight",
  "IntuneUserId": "bbcfc3c5-0b93-4135-9ef9-18477a9fb504",
  "OperationalLogCategory": "DeviceCompliance"
 }
}`

func decode(t *testing.T, body string) map[string]any {
	t.Helper()
	var rec map[string]any
	if err := json.Unmarshal([]byte(body), &rec); err != nil {
		t.Fatalf("decode: %v", err)
	}
	return rec
}

func TestMapRecordEmitsComplianceDetail(t *testing.T) {
	ev, ok := mapRecord(decode(t, liveRecord))
	if !ok {
		t.Fatal("mapRecord dropped a valid record")
	}
	if ev.Name != eventName {
		t.Errorf("event name = %q, want %q", ev.Name, eventName)
	}

	// A compliance alert is a warning, never INFO.
	if ev.Severity != telemetry.SeverityWarn {
		t.Errorf("severity = %v, want SeverityWarn", ev.Severity)
	}

	// Timestamp bound to properties.StartTimeUtc, as an instant.
	wantTS, _ := time.Parse(time.RFC3339Nano, "2026-07-17T11:50:38.5951Z")
	if !ev.Timestamp.Equal(wantTS) {
		t.Errorf("timestamp = %v, want %v (bound to properties.StartTimeUtc)", ev.Timestamp, wantTS)
	}

	want := map[string]string{
		semconv.AttrIntuneAccountId:        "e933bb26-3dff-49f0-a41a-bd722a92f1fb",
		semconv.AttrAlertType:              "Managed Device Not Compliant",
		semconv.AttrDeviceId:               "33dcca32-d6ea-478b-88d9-e2a891f9d83a",
		semconv.AttrDeviceName:             "THRWX5256T_14_7/17/2026_11:48 AM",
		semconv.AttrDeviceHostName:         "MacBook Pro",
		semconv.AttrDeviceNetBiosName:      "MacBook Pro",
		semconv.AttrOperatingSystem:        "MacMDM 26.5.2 (25F84)",
		semconv.AttrScaleUnit:              "AMSUB0601",
		semconv.AttrScenarioName:           "Microsoft.Management.Services.Diagnostics.SLAEvents.DeviceNotInComplianceSecurityAlert",
		semconv.AttrUserName:               "rob",
		semconv.AttrUpnSuffix:              "m7kni.io",
		semconv.AttrUserDisplayName:        "Rob Knight",
		semconv.AttrIntuneUserId:           "bbcfc3c5-0b93-4135-9ef9-18477a9fb504",
		semconv.AttrOperationalLogCategory: "DeviceCompliance",
	}
	for k, v := range want {
		got, _ := ev.Attrs[k].(string)
		if got != v {
			t.Errorf("attr %q = %q, want %q", k, got, v)
		}
	}

	// AlertDisplayName and the failing-rule Description are both mapped.
	if got, _ := ev.Attrs[semconv.AttrAlertDisplayName].(string); !strings.Contains(got, "is not Compliant") {
		t.Errorf("alert_display_name = %q, want it to contain the alert text", got)
	}
	if got, _ := ev.Attrs[semconv.AttrDescription].(string); !strings.Contains(got, "FileVault2Encrypted") {
		t.Errorf("description = %q, want the failing rule detail", got)
	}

	// DeviceDnsDomain is empty on the sample → SetStr no-ops, so the attribute is
	// absent rather than present-and-empty.
	if _, present := ev.Attrs[semconv.AttrDeviceDnsDomain]; present {
		t.Errorf("device_dns_domain should be absent when empty, got %v", ev.Attrs[semconv.AttrDeviceDnsDomain])
	}

	// Body is a short human summary carrying the alert type and device.
	if !strings.Contains(ev.Body, "Managed Device Not Compliant") || !strings.Contains(ev.Body, "THRWX5256T") {
		t.Errorf("body = %q, want it to summarize the alert", ev.Body)
	}
}

func TestMapRecordFallsBackToTopLevelTime(t *testing.T) {
	// StartTimeUtc missing → fall back to the top-level `time`.
	rec := decode(t, `{"time":"2026-07-17T11:50:38.5951000Z","properties":{"AlertType":"x"}}`)
	ev, ok := mapRecord(rec)
	if !ok {
		t.Fatal("record with a parseable top-level time should be kept")
	}
	wantTS, _ := time.Parse(time.RFC3339Nano, "2026-07-17T11:50:38.5951000Z")
	if !ev.Timestamp.Equal(wantTS) {
		t.Errorf("timestamp = %v, want %v (fallback to top-level time)", ev.Timestamp, wantTS)
	}
}

func TestMapRecordDropsMalformed(t *testing.T) {
	// No properties → dropped.
	if _, ok := mapRecord(map[string]any{"time": "2026-07-17T11:50:38Z"}); ok {
		t.Error("record with no properties should be dropped")
	}
	// Neither StartTimeUtc nor top-level time parses → dropped, never mis-dated.
	if _, ok := mapRecord(decode(t, `{"time":"not-a-time","properties":{"StartTimeUtc":"also-bad"}}`)); ok {
		t.Error("record with no parseable event time should be dropped")
	}
	// No event time at all → dropped.
	if _, ok := mapRecord(decode(t, `{"properties":{"AlertType":"x"}}`)); ok {
		t.Error("record with no event time should be dropped")
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
// what reaches the emitter, then that the cursor persists across a second tick.
func TestCollectorEmitsLiveRecordEndToEnd(t *testing.T) {
	const tenant = "4b8c18bd-2f9f-4227-af55-9f1061cf9c32"
	src := &staticSource{
		name: "tenantId=" + tenant + "/y=2026/m=07/d=17/h=11/m=00/PT1H.json",
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
	wantTS, _ := time.Parse(time.RFC3339Nano, "2026-07-17T11:50:38.5951Z")
	if !logs[0].Timestamp.Equal(wantTS) {
		t.Errorf("timestamp = %s, want %s", logs[0].Timestamp, wantTS)
	}
	if got := logs[0].Attrs[semconv.AttrDeviceName]; got != "THRWX5256T_14_7/17/2026_11:48 AM" {
		t.Errorf("device_name attr = %q, want the sample device", got)
	}

	// Cursor persisted: a second tick over the unchanged blob emits nothing new.
	if err := c.Collect(context.Background(), rec.Emitter()); err != nil {
		t.Fatalf("second Collect: %v", err)
	}
	if got := len(rec.LogRecords()); got != 1 {
		t.Errorf("after a second tick over an unchanged blob: %d records, want 1", got)
	}
}
