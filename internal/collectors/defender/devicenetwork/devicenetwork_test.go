package devicenetwork

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

// liveRecord is a real DeviceNetworkEvents envelope captured off the m7kni
// storage account as graph2otel-poller (cert on camden, 2026-07-18, #106). It
// is a ConnectionRequest with a full InitiatingProcess block (macOS
// Microsoft AutoUpdate opening an outbound TCP connection) — the full shape a
// mapper must handle.
const liveRecord = `{
  "time": "2026-07-18T14:00:54.7649349Z",
  "tenantId": "4b8c18bd-2f9f-4227-af55-9f1061cf9c32",
  "operationName": "Publish",
  "category": "AdvancedHunting-DeviceNetworkEvents",
  "_TimeReceivedBySvc": "2026-07-18T13:59:00.0890446Z",
  "properties": {
    "DeviceName": "mbp16",
    "DeviceId": "5844d4a3f835919fd63772082de62951d0dab09d",
    "ReportId": 26528,
    "RemoteIP": "20.42.65.85",
    "RemotePort": 443,
    "LocalIP": "10.0.0.183",
    "LocalPort": 53630,
    "Protocol": "Tcp",
    "RemoteUrl": null,
    "InitiatingProcessCreationTime": "2026-07-18T13:58:42.24998Z",
    "InitiatingProcessId": 16865,
    "InitiatingProcessCommandLine": "\"/Library/Application Support/Microsoft/MAU2.0/Microsoft AutoUpdate.app/Contents/MacOS/Microsoft Update Assistant.app/Contents/MacOS/Microsoft Update Assistant\" --launchByAgent",
    "InitiatingProcessParentCreationTime": "2026-07-18T13:58:41.811719Z",
    "InitiatingProcessParentId": 16865,
    "InitiatingProcessParentFileName": "xpcproxy",
    "InitiatingProcessSHA1": "df28e5fb02d978b99eef04163b25eefaaac32c77",
    "InitiatingProcessMD5": "f7bf030637482f078a279f92d3ee4279",
    "InitiatingProcessFolderPath": "/library/application support/microsoft/mau2.0/microsoft autoupdate.app/contents/macos/microsoft update assistant.app/contents/macos/microsoft update assistant",
    "InitiatingProcessAccountName": "rob",
    "InitiatingProcessAccountDomain": "mbp16",
    "InitiatingProcessAccountSid": "S-1-5-21-3439550418-2312797321-815996604-2006",
    "InitiatingProcessFileName": "microsoft update assistant",
    "InitiatingProcessIntegrityLevel": null,
    "InitiatingProcessTokenElevation": "None",
    "AppGuardContainerId": null,
    "LocalIPType": "Private",
    "RemoteIPType": "Public",
    "ActionType": "ConnectionRequest",
    "InitiatingProcessSHA256": "e37d25f864cea34ad200848f5fb526c2b4cb0596c59096a5ea43085d5aca601d",
    "InitiatingProcessAccountUpn": "rob@m7kni.io",
    "InitiatingProcessAccountObjectId": null,
    "AdditionalFields": "<str len=729 head='{\"InitiatingProcessPosixEffectiveUser\":{\"Sid\":\"S-1-5-21-3439550418-2312797321-815996604-2006\",\"Name\":\"rob\",\"DomainName\":'>",
    "InitiatingProcessFileSize": 3376912,
    "InitiatingProcessVersionInfoCompanyName": "UBF8T346G9",
    "InitiatingProcessVersionInfoProductName": null,
    "InitiatingProcessVersionInfoProductVersion": null,
    "InitiatingProcessVersionInfoInternalFileName": null,
    "InitiatingProcessVersionInfoOriginalFileName": null,
    "InitiatingProcessVersionInfoFileDescription": null,
    "InitiatingProcessSessionId": null,
    "IsInitiatingProcessRemoteSession": false,
    "InitiatingProcessRemoteSessionDeviceName": null,
    "InitiatingProcessRemoteSessionIP": null,
    "InitiatingProcessUniqueId": "0",
    "Timestamp": "2026-07-18T13:58:42.666487Z",
    "MachineGroup": "main"
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

func TestMapRecordEmitsNetworkAndInitiatingProcess(t *testing.T) {
	ev, ok := mapRecord(decode(t, liveRecord))
	if !ok {
		t.Fatal("mapRecord dropped a valid record")
	}
	if ev.Name != eventName {
		t.Errorf("event name = %q, want %q", ev.Name, eventName)
	}

	// Timestamp bound to properties.Timestamp, as an instant — NOT the envelope
	// `time` or `_TimeReceivedBySvc`.
	wantTS, _ := time.Parse(time.RFC3339Nano, "2026-07-18T13:58:42.666487Z")
	if !ev.Timestamp.Equal(wantTS) {
		t.Errorf("timestamp = %v, want %v (bound to properties.Timestamp)", ev.Timestamp, wantTS)
	}

	want := map[string]string{
		semconv.AttrDeviceId:                     "5844d4a3f835919fd63772082de62951d0dab09d",
		semconv.AttrDeviceName:                   "mbp16",
		semconv.AttrActionType:                   "ConnectionRequest",
		semconv.AttrMachineGroup:                 "main",
		semconv.AttrLocalIp:                      "10.0.0.183",
		semconv.AttrLocalIpType:                  "Private",
		semconv.AttrRemoteIp:                     "20.42.65.85",
		semconv.AttrRemoteIpType:                 "Public",
		semconv.AttrProtocol:                     "Tcp",
		semconv.AttrInitiatingProcessFileName:    "microsoft update assistant",
		semconv.AttrInitiatingProcessAccountName: "rob",
		semconv.AttrInitiatingProcessSha256:      "e37d25f864cea34ad200848f5fb526c2b4cb0596c59096a5ea43085d5aca601d",
	}
	for k, v := range want {
		got, _ := ev.Attrs[k].(string)
		if got != v {
			t.Errorf("attr %q = %q, want %q", k, got, v)
		}
	}

	// RemoteUrl is null on this record — must be omitted, not emitted empty.
	if _, present := ev.Attrs[semconv.AttrRemoteUrl]; present {
		t.Error("remote_url should be omitted when null")
	}

	// Numeric fields land as numbers, not strings.
	if lp, ok := ev.Attrs[semconv.AttrLocalPort].(float64); !ok || lp != 53630 {
		t.Errorf("local_port = %v, want float64(53630)", ev.Attrs[semconv.AttrLocalPort])
	}
	if rp, ok := ev.Attrs[semconv.AttrRemotePort].(float64); !ok || rp != 443 {
		t.Errorf("remote_port = %v, want float64(443)", ev.Attrs[semconv.AttrRemotePort])
	}
	if rid, ok := ev.Attrs[semconv.AttrReportId].(float64); !ok || rid != 26528 {
		t.Errorf("report_id = %v, want float64(26528)", ev.Attrs[semconv.AttrReportId])
	}
}

func TestMapRecordDropsMalformed(t *testing.T) {
	// No properties → dropped.
	if _, ok := mapRecord(map[string]any{"time": "2026-07-18T11:00:55Z"}); ok {
		t.Error("record with no properties should be dropped")
	}
	// Unparseable Timestamp → dropped, never mis-dated (no fallback to envelope time).
	if _, ok := mapRecord(decode(t, `{"properties":{"DeviceId":"d","Timestamp":"not-a-time"}}`)); ok {
		t.Error("record with unparseable Timestamp should be dropped")
	}
	// Missing Timestamp → dropped.
	if _, ok := mapRecord(decode(t, `{"properties":{"DeviceId":"d"}}`)); ok {
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
	wantTS, _ := time.Parse(time.RFC3339Nano, "2026-07-18T13:58:42.666487Z")
	if !logs[0].Timestamp.Equal(wantTS) {
		t.Errorf("timestamp = %s, want %s", logs[0].Timestamp, wantTS)
	}
	if got := logs[0].Attrs[semconv.AttrRemoteIp]; got != "20.42.65.85" {
		t.Errorf("remote_ip attr = %q, want 20.42.65.85", got)
	}
	if got := logs[0].Attrs[semconv.AttrInitiatingProcessFileName]; got != "microsoft update assistant" {
		t.Errorf("initiating_process_file_name = %q, want %q", got, "microsoft update assistant")
	}

	// Cursor persisted: a second tick over the unchanged blob emits nothing new.
	if err := c.Collect(context.Background(), rec.Emitter()); err != nil {
		t.Fatalf("second Collect: %v", err)
	}
	if got := len(rec.LogRecords()); got != 1 {
		t.Errorf("after a second tick over an unchanged blob: %d records, want 1", got)
	}
}
