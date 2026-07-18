package deviceprocess

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

// liveRecord is a real DeviceProcessEvents envelope captured off the m7kni
// storage account as graph2otel-poller (cert on camden, 2026-07-18, #106): a
// macOS ProcessCreated event (Defender for Endpoint on Mac reports through the
// same table as Windows), ctkahp launching UserSelector, initiated by rob on
// mbp14 — the full shape a mapper must handle, no truncation.
const liveRecord = `{
 "time": "2026-07-18T15:02:23.0616003Z",
 "tenantId": "4b8c18bd-2f9f-4227-af55-9f1061cf9c32",
 "operationName": "Publish",
 "category": "AdvancedHunting-DeviceProcessEvents",
 "_TimeReceivedBySvc": "2026-07-18T15:00:43.5903183Z",
 "properties": {
  "InitiatingProcessSHA1": "a6a7b6171cf4be5e08f7f9a5523effa2f23fe517",
  "InitiatingProcessFileSize": 968384,
  "InitiatingProcessMD5": "8638f64ff5e5ac17273674db0b23a6b7",
  "InitiatingProcessFileName": "ctkahp",
  "InitiatingProcessParentFileName": "ctkahp",
  "InitiatingProcessFolderPath": "/system/library/frameworks/cryptotokenkit.framework/ctkahp.bundle/contents/macos/ctkahp",
  "InitiatingProcessCommandLine": "/System/Library/Frameworks/CryptoTokenKit.framework/ctkahp.bundle/Contents/MacOS/ctkahp",
  "SHA1": "2a6f4029044485f53d01ec273c1cc0a3802e2185",
  "FileSize": 204688,
  "MD5": "52b722931c619361d8e32d948e239590",
  "FolderPath": "/System/Library/Frameworks/CryptoTokenKit.framework/UserSelector",
  "ProcessCommandLine": "/System/Library/Frameworks/CryptoTokenKit.framework/UserSelector -o anybind",
  "FileName": "UserSelector",
  "ProcessId": 91345,
  "InitiatingProcessId": 91345,
  "ProcessCreationTime": "2026-07-18T14:55:41.322571Z",
  "DeviceName": "mbp14",
  "DeviceId": "3db402e9217f30248e26406c0a48094b00a0062e",
  "InitiatingProcessCreationTime": "2026-07-18T14:55:41.303045Z",
  "InitiatingProcessAccountName": "rob",
  "InitiatingProcessAccountDomain": "mbp14",
  "InitiatingProcessAccountSid": "S-1-5-21-2965590086-2375665732-3273071523-2006",
  "InitiatingProcessSignatureStatus": "Valid",
  "InitiatingProcessSignerType": "OsVendor",
  "InitiatingProcessParentId": 9031,
  "ReportId": 35595,
  "InitiatingProcessParentCreationTime": "2026-07-17T18:02:29.269299Z",
  "InitiatingProcessTokenElevation": "None",
  "InitiatingProcessIntegrityLevel": null,
  "AccountDomain": "mbp14",
  "AccountName": "rob",
  "ProcessTokenElevation": "None",
  "ProcessIntegrityLevel": null,
  "AccountSid": "S-1-5-21-2965590086-2375665732-3273071523-2006",
  "AppGuardContainerId": null,
  "SHA256": "283be39fc140270cfb561e503a0dcf84781c87d225f661e71a106fbcaff64c49",
  "InitiatingProcessSHA256": "8dc09e06aa29cd4448b5ff324ea405bac8423f3b80d28f9c7a791858ed3f5abf",
  "InitiatingProcessLogonId": 0,
  "LogonId": 0,
  "InitiatingProcessAccountUpn": null,
  "InitiatingProcessAccountObjectId": null,
  "AccountUpn": null,
  "AccountObjectId": null,
  "AdditionalFields": "{\"InitiatingProcessPosixEffectiveUser\":{\"Sid\":\"S-1-5-21-2965590086-2375665732-3273071523-2006\",\"Name\":\"rob\",\"DomainName\":\"mbp14\",\"LogonId\":0,\"PosixUserId\":503,\"PrimaryPosixGroup\":{\"Name\":\"staff\",\"PosixGroupId\":20}},\"InitiatingProcessPosixEffectiveGroup\":{\"Name\":\"staff\",\"PosixGroupId\":20},\"InitiatingProcessPosixProcessGroupId\":9031,\"InitiatingProcessPosixSessionId\":1,\"InitiatingProcessCurrentWorkingDirectory\":\"/\",\"InitiatingProcessPosixFilePermissions\":[\"None\"],\"InitiatingProcessPosixRealUser\":{\"Sid\":\"S-1-5-21-2965590086-2375665732-3273071523-2006\",\"Name\":\"rob\",\"DomainName\":\"mbp14\",\"LogonId\":0,\"PosixUserId\":503,\"PrimaryPosixGroup\":{\"Name\":\"staff\",\"PosixGroupId\":20}},\"ProcessPosixEffectiveUser\":{\"Sid\":\"S-1-5-21-2965590086-2375665732-3273071523-2006\",\"Name\":\"rob\",\"DomainName\":\"mbp14\",\"LogonId\":0,\"PosixUserId\":503,\"PrimaryPosixGroup\":{\"Name\":\"staff\",\"PosixGroupId\":20}},\"ProcessPosixEffectiveGroup\":{\"Name\":\"staff\",\"PosixGroupId\":20},\"ProcessPosixProcessGroupId\":91345,\"ProcessPosixSessionId\":1,\"ProcessCurrentWorkingDirectory\":\"/\",\"ProcessPosixFilePermissions\":[\"None\"]}",
  "InitiatingProcessVersionInfoCompanyName": "(APPLE)",
  "InitiatingProcessVersionInfoProductName": null,
  "InitiatingProcessVersionInfoProductVersion": null,
  "InitiatingProcessVersionInfoInternalFileName": null,
  "InitiatingProcessVersionInfoOriginalFileName": null,
  "InitiatingProcessVersionInfoFileDescription": null,
  "ProcessVersionInfoCompanyName": "(APPLE)",
  "ProcessVersionInfoProductName": null,
  "ProcessVersionInfoProductVersion": null,
  "ProcessVersionInfoInternalFileName": null,
  "ProcessVersionInfoOriginalFileName": null,
  "ProcessVersionInfoFileDescription": null,
  "InitiatingProcessSessionId": null,
  "CreatedProcessSessionId": null,
  "IsInitiatingProcessRemoteSession": false,
  "InitiatingProcessRemoteSessionDeviceName": null,
  "InitiatingProcessRemoteSessionIP": null,
  "IsProcessRemoteSession": false,
  "ProcessRemoteSessionDeviceName": null,
  "ProcessRemoteSessionIP": null,
  "ProcessUniqueId": "0",
  "InitiatingProcessUniqueId": "0",
  "ActionType": "ProcessCreated",
  "Timestamp": "2026-07-18T14:55:41.322571Z",
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

func TestMapRecordEmitsProcessAndInitiatingProcess(t *testing.T) {
	ev, ok := mapRecord(decode(t, liveRecord))
	if !ok {
		t.Fatal("mapRecord dropped a valid record")
	}
	if ev.Name != eventName {
		t.Errorf("event name = %q, want %q", ev.Name, eventName)
	}

	want := map[string]string{
		semconv.AttrDeviceName:                "mbp14",
		semconv.AttrFileName:                  "UserSelector",
		semconv.AttrActionType:                "ProcessCreated",
		semconv.AttrAccountName:               "rob",
		semconv.AttrInitiatingProcessFileName: "ctkahp",
		semconv.AttrMachineGroup:              "main",
	}
	for k, v := range want {
		got, _ := ev.Attrs[k].(string)
		if got != v {
			t.Errorf("attr %q = %q, want %q", k, got, v)
		}
	}

	if got, _ := ev.Attrs[semconv.AttrProcessCommandLine].(string); !strings.Contains(got, "UserSelector") {
		t.Errorf("process_command_line = %q, want it to contain %q", got, "UserSelector")
	}

	if pid, ok := ev.Attrs[semconv.AttrProcessId].(float64); !ok || pid != 91345 {
		t.Errorf("process_id = %v, want float64(91345)", ev.Attrs[semconv.AttrProcessId])
	}

	wantTS, err := time.Parse(time.RFC3339Nano, "2026-07-18T14:55:41.322571Z")
	if err != nil {
		t.Fatalf("parsing the expected timestamp: %v", err)
	}
	if !ev.Timestamp.Equal(wantTS) {
		t.Errorf("timestamp = %v, want %v", ev.Timestamp, wantTS)
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
		name: "tenantId=" + tenant + "/y=2026/m=07/d=18/h=15/m=00/PT1H.json",
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
	if got := logs[0].Attrs[semconv.AttrFileName]; got != "UserSelector" {
		t.Errorf("file_name = %q, want UserSelector", got)
	}

	// Cursor persisted: a second tick over the unchanged blob emits nothing new.
	if err := c.Collect(context.Background(), rec.Emitter()); err != nil {
		t.Fatalf("second Collect: %v", err)
	}
	if got := len(rec.LogRecords()); got != 1 {
		t.Errorf("after a second tick over an unchanged blob: %d records, want 1", got)
	}
}
