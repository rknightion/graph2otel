package deviceimageload

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

// liveRecord is a real DeviceImageLoadEvents envelope captured off the m7kni
// storage account as graph2otel-poller (cert on camden, 2026-07-18, #106): an
// ImageLoaded event for samlib.dll, loaded by MsMpEng.exe — the full shape a
// mapper must handle.
const liveRecord = `{
 "time": "2026-07-18T15:10:02.6692652Z",
 "tenantId": "4b8c18bd-2f9f-4227-af55-9f1061cf9c32",
 "operationName": "Publish",
 "category": "AdvancedHunting-DeviceImageLoadEvents",
 "_TimeReceivedBySvc": "2026-07-18T15:08:04.1743316Z",
 "properties": {
  "DeviceName": "winsrv",
  "DeviceId": "56fb3abc73b440dd56cdc9873677877cd4ab0851",
  "ReportId": 9325,
  "InitiatingProcessSHA1": "dac70e816f8912fe706d6b948f33856b7166058b",
  "InitiatingProcessMD5": "9ee4afb342509c2c72aaab85b6896c09",
  "InitiatingProcessParentFileName": "services.exe",
  "InitiatingProcessFolderPath": "c:\\programdata\\microsoft\\windows defender\\platform\\4.18.26070.6-0\\msmpeng.exe",
  "InitiatingProcessFileName": "msmpeng.exe",
  "InitiatingProcessCommandLine": "\"MsMpEng.exe\"",
  "InitiatingProcessCreationTime": "2026-07-18T10:56:52.2718242Z",
  "InitiatingProcessParentCreationTime": "2026-07-18T10:56:49.6213834Z",
  "InitiatingProcessAccountName": "system",
  "InitiatingProcessAccountDomain": "nt authority",
  "InitiatingProcessAccountSid": "S-1-5-18",
  "InitiatingProcessParentId": 1028,
  "InitiatingProcessId": 3928,
  "FileName": "samlib.dll",
  "SHA1": "9d1bb22b68739d5b0dab1d121503920abfe8a62c",
  "MD5": "205d7e21e590fbbbcc10143038c593a3",
  "FolderPath": "C:\\Windows\\System32\\samlib.dll",
  "FileSize": 176128,
  "InitiatingProcessIntegrityLevel": "System",
  "InitiatingProcessTokenElevation": "TokenElevationTypeDefault",
  "AppGuardContainerId": "",
  "SHA256": "ab65136e340c027996d9271a97504762acf3d2243fd71e104bb0b3502da14cbf",
  "InitiatingProcessSHA256": "7335abd7785e82622124c1ebac8fbb130c3f2db21e28482727b134c5c2243588",
  "InitiatingProcessAccountUpn": null,
  "InitiatingProcessAccountObjectId": null,
  "InitiatingProcessFileSize": 291360,
  "InitiatingProcessVersionInfoCompanyName": "Microsoft Corporation",
  "InitiatingProcessVersionInfoProductName": "Microsoft® Windows® Operating System",
  "InitiatingProcessVersionInfoProductVersion": "4.18.26070.6",
  "InitiatingProcessVersionInfoInternalFileName": "MsMpEng.exe",
  "InitiatingProcessVersionInfoOriginalFileName": "MsMpEng.exe",
  "InitiatingProcessVersionInfoFileDescription": "Antimalware Service Executable",
  "InitiatingProcessSessionId": 0,
  "IsInitiatingProcessRemoteSession": false,
  "InitiatingProcessRemoteSessionDeviceName": null,
  "InitiatingProcessRemoteSessionIP": null,
  "InitiatingProcessUniqueId": "13510798882111570",
  "Timestamp": "2026-07-18T15:05:52.6714545Z",
  "MachineGroup": "main",
  "ActionType": "ImageLoaded"
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

func TestMapRecordEmitsDeviceAndInitiatingProcess(t *testing.T) {
	ev, ok := mapRecord(decode(t, liveRecord))
	if !ok {
		t.Fatal("mapRecord dropped a valid record")
	}
	if ev.Name != eventName {
		t.Errorf("event name = %q, want %q", ev.Name, eventName)
	}

	// Timestamp bound to properties.Timestamp, as an instant — NOT the envelope
	// `time` or `_TimeReceivedBySvc`.
	wantTS, _ := time.Parse(time.RFC3339Nano, "2026-07-18T15:05:52.6714545Z")
	if !ev.Timestamp.Equal(wantTS) {
		t.Errorf("timestamp = %v, want %v (bound to properties.Timestamp)", ev.Timestamp, wantTS)
	}

	want := map[string]string{
		semconv.AttrDeviceId:                     "56fb3abc73b440dd56cdc9873677877cd4ab0851",
		semconv.AttrDeviceName:                   "winsrv",
		semconv.AttrActionType:                   "ImageLoaded",
		semconv.AttrMachineGroup:                 "main",
		semconv.AttrFileName:                     "samlib.dll",
		semconv.AttrInitiatingProcessFileName:    "msmpeng.exe",
		semconv.AttrInitiatingProcessAccountName: "system",
		semconv.AttrInitiatingProcessSha256:      "7335abd7785e82622124c1ebac8fbb130c3f2db21e28482727b134c5c2243588",
	}
	for k, v := range want {
		got, _ := ev.Attrs[k].(string)
		if got != v {
			t.Errorf("attr %q = %q, want %q", k, got, v)
		}
	}

	// AppGuardContainerId is present but "" — must be omitted, not emitted empty.
	if _, present := ev.Attrs[semconv.AttrAppGuardContainerId]; present {
		t.Error("app_guard_container_id should be omitted when empty")
	}
}

func TestMapRecordDropsMalformed(t *testing.T) {
	// No properties → dropped.
	if _, ok := mapRecord(map[string]any{"time": "2026-07-18T15:10:02Z"}); ok {
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
		name: "tenantId=" + tenant + "/y=2026/m=07/d=18/h=15/m=10/PT1H.json",
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
	wantTS, _ := time.Parse(time.RFC3339Nano, "2026-07-18T15:05:52.6714545Z")
	if !logs[0].Timestamp.Equal(wantTS) {
		t.Errorf("timestamp = %s, want %s", logs[0].Timestamp, wantTS)
	}
	if got := logs[0].Attrs[semconv.AttrFileName]; got != "samlib.dll" {
		t.Errorf("file_name attr = %q, want samlib.dll", got)
	}
	if got := logs[0].Attrs[semconv.AttrInitiatingProcessFileName]; got != "msmpeng.exe" {
		t.Errorf("initiating_process_file_name = %q, want msmpeng.exe", got)
	}

	// Cursor persisted: a second tick over the unchanged blob emits nothing new.
	if err := c.Collect(context.Background(), rec.Emitter()); err != nil {
		t.Fatalf("second Collect: %v", err)
	}
	if got := len(rec.LogRecords()); got != 1 {
		t.Errorf("after a second tick over an unchanged blob: %d records, want 1", got)
	}
}
