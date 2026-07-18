package deviceregistry

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

// liveRecord is a real DeviceRegistryEvents envelope captured off the m7kni
// storage account as graph2otel-poller (cert on camden, 2026-07-18, #106). It is
// a RegistryValueSet with a previous value, initiated by powershell.exe — the
// full shape a mapper must handle, trimmed of the long command line only.
const liveRecord = `{
  "time": "2026-07-18T11:00:55.8621636Z",
  "tenantId": "4b8c18bd-2f9f-4227-af55-9f1061cf9c32",
  "operationName": "Publish",
  "category": "AdvancedHunting-DeviceRegistryEvents",
  "_TimeReceivedBySvc": "2026-07-18T10:59:16.2114101Z",
  "properties": {
    "DeviceName": "winsrv",
    "DeviceId": "56fb3abc73b440dd56cdc9873677877cd4ab0851",
    "ReportId": 3509,
    "RegistryKey": "HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\DataCollection",
    "RegistryValueName": "LastUpdate",
    "RegistryValueType": "String",
    "RegistryValueData": "99c53f16-e4e7-484c-83d2-6d4601bc82c1",
    "PreviousRegistryValueData": "bf4e396f-53ce-4b80-8830-092d128a5647",
    "InitiatingProcessSHA1": "eb42621654e02faf2de940442b6deb1a77864e5b",
    "InitiatingProcessFileSize": 454656,
    "InitiatingProcessMD5": "a97e6573b97b44c96122bfa543a82ea1",
    "InitiatingProcessFileName": "powershell.exe",
    "InitiatingProcessParentFileName": "SenseIR.exe",
    "InitiatingProcessAccountName": "system",
    "InitiatingProcessAccountDomain": "nt authority",
    "InitiatingProcessId": 996,
    "InitiatingProcessParentId": 5452,
    "ActionType": "RegistryValueSet",
    "InitiatingProcessSHA256": "0ff6f2c94bc7e2833a5f7e16de1622e5dba70396f31c7d5f56381870317e8c46",
    "IsInitiatingProcessRemoteSession": false,
    "PreviousRegistryValueName": "LastUpdate",
    "Timestamp": "2026-07-18T10:58:27.3137769Z",
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

func TestMapRecordEmitsRegistryAndInitiatingProcess(t *testing.T) {
	ev, ok := mapRecord(decode(t, liveRecord))
	if !ok {
		t.Fatal("mapRecord dropped a valid record")
	}
	if ev.Name != eventName {
		t.Errorf("event name = %q, want %q", ev.Name, eventName)
	}

	// Timestamp bound to properties.Timestamp, as an instant — NOT the envelope
	// `time` or `_TimeReceivedBySvc`.
	wantTS, _ := time.Parse(time.RFC3339Nano, "2026-07-18T10:58:27.3137769Z")
	if !ev.Timestamp.Equal(wantTS) {
		t.Errorf("timestamp = %v, want %v (bound to properties.Timestamp)", ev.Timestamp, wantTS)
	}

	want := map[string]string{
		semconv.AttrDeviceId:                     "56fb3abc73b440dd56cdc9873677877cd4ab0851",
		semconv.AttrDeviceName:                   "winsrv",
		semconv.AttrActionType:                   "RegistryValueSet",
		semconv.AttrMachineGroup:                 "main",
		semconv.AttrRegistryKey:                  "HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\DataCollection",
		semconv.AttrRegistryValueName:            "LastUpdate",
		semconv.AttrRegistryValueData:            "99c53f16-e4e7-484c-83d2-6d4601bc82c1",
		semconv.AttrPreviousRegistryValueData:    "bf4e396f-53ce-4b80-8830-092d128a5647",
		semconv.AttrInitiatingProcessFileName:    "powershell.exe",
		semconv.AttrInitiatingProcessAccountName: "system",
		semconv.AttrInitiatingProcessSha256:      "0ff6f2c94bc7e2833a5f7e16de1622e5dba70396f31c7d5f56381870317e8c46",
	}
	for k, v := range want {
		got, _ := ev.Attrs[k].(string)
		if got != v {
			t.Errorf("attr %q = %q, want %q", k, got, v)
		}
	}

	// Numeric InitiatingProcess fields land as numbers, not strings.
	if pid, ok := ev.Attrs[semconv.AttrInitiatingProcessId].(float64); !ok || pid != 996 {
		t.Errorf("initiating_process_id = %v, want float64(996)", ev.Attrs[semconv.AttrInitiatingProcessId])
	}
	if rid, ok := ev.Attrs[semconv.AttrReportId].(float64); !ok || rid != 3509 {
		t.Errorf("report_id = %v, want float64(3509)", ev.Attrs[semconv.AttrReportId])
	}

	// The remote-session bool is present and stamped as the string "false".
	if got, _ := ev.Attrs[semconv.AttrIsInitiatingProcessRemoteSession].(string); got != "false" {
		t.Errorf("is_initiating_process_remote_session = %q, want \"false\"", got)
	}
}

func TestMapRecordOmitsAbsentColumns(t *testing.T) {
	// A key-create with null RegistryValueName/Data must omit them, not emit "".
	body := `{"properties":{
		"DeviceName":"winsrv","DeviceId":"d1","ActionType":"RegistryKeyCreated",
		"RegistryKey":"HKLM\\SYSTEM\\X","RegistryValueName":null,"RegistryValueData":null,
		"Timestamp":"2026-07-18T10:57:47.2282625Z"}}`
	ev, ok := mapRecord(decode(t, body))
	if !ok {
		t.Fatal("mapRecord dropped a valid key-create record")
	}
	if _, present := ev.Attrs[semconv.AttrRegistryValueName]; present {
		t.Error("registry_value_name should be omitted when null, not emitted empty")
	}
	if _, present := ev.Attrs[semconv.AttrRegistryValueData]; present {
		t.Error("registry_value_data should be omitted when null")
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
		name: "tenantId=" + tenant + "/y=2026/m=07/d=18/h=11/m=00/PT1H.json",
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
	wantTS, _ := time.Parse(time.RFC3339Nano, "2026-07-18T10:58:27.3137769Z")
	if !logs[0].Timestamp.Equal(wantTS) {
		t.Errorf("timestamp = %s, want %s", logs[0].Timestamp, wantTS)
	}
	if got := logs[0].Attrs[semconv.AttrRegistryKey]; !strings.HasPrefix(got, "HKEY_LOCAL_MACHINE") {
		t.Errorf("registry_key attr = %q, want the HKLM key", got)
	}
	if got := logs[0].Attrs[semconv.AttrInitiatingProcessFileName]; got != "powershell.exe" {
		t.Errorf("initiating_process_file_name = %q, want powershell.exe", got)
	}

	// Cursor persisted: a second tick over the unchanged blob emits nothing new.
	if err := c.Collect(context.Background(), rec.Emitter()); err != nil {
		t.Fatalf("second Collect: %v", err)
	}
	if got := len(rec.LogRecords()); got != 1 {
		t.Errorf("after a second tick over an unchanged blob: %d records, want 1", got)
	}
}
