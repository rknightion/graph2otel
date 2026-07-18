package devicelogon

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

// liveRecord is a real DeviceLogonEvents envelope captured off the m7kni
// storage account as graph2otel-poller (cert on camden, 2026-07-18, #106): a
// macOS local console LogonSuccess for "rob" on "mbp14", initiated by
// loginwindow. AdditionalFields is a large stringified-JSON blob (POSIX
// identity details); the live probe truncated it to a head preview, so this
// pins that same truncated-but-still-JSON-shaped prefix rather than inventing
// content — it is never parsed by the mapper, only carried as an opaque string.
const liveRecord = `{
  "time": "2026-07-18T14:28:01.1633957Z",
  "tenantId": "4b8c18bd-2f9f-4227-af55-9f1061cf9c32",
  "operationName": "Publish",
  "category": "AdvancedHunting-DeviceLogonEvents",
  "_TimeReceivedBySvc": "2026-07-18T14:25:39.3807258Z",
  "properties": {
    "AccountName": "rob",
    "AccountDomain": "mbp14",
    "LogonType": "Local",
    "DeviceName": "mbp14",
    "DeviceId": "3db402e9217f30248e26406c0a48094b00a0062e",
    "ReportId": 34354,
    "AccountSid": "S-1-5-21-2965590086-2375665732-3273071523-2006",
    "AppGuardContainerId": null,
    "LogonId": null,
    "RemoteIP": "",
    "RemotePort": null,
    "RemoteDeviceName": null,
    "ActionType": "LogonSuccess",
    "InitiatingProcessId": 542,
    "InitiatingProcessCreationTime": "2026-07-17T17:52:59.034581Z",
    "InitiatingProcessFileName": "loginwindow",
    "InitiatingProcessFolderPath": "/system/library/coreservices/loginwindow.app/contents/macos/loginwindow",
    "InitiatingProcessSHA1": "f9693f6a5425cd318ef57ede11148fc790dfed96",
    "InitiatingProcessSHA256": "f63b6e8a422954d93d56f936445fd56dc7ea76eb65797d91364e3a2caf482bda",
    "InitiatingProcessMD5": "490f9955188d3a5031fcfc5d45b32570",
    "InitiatingProcessCommandLine": "/System/Library/CoreServices/loginwindow.app/Contents/MacOS/loginwindow console",
    "InitiatingProcessAccountName": "root",
    "InitiatingProcessAccountDomain": "mbp14",
    "InitiatingProcessAccountSid": "S-1-5-18",
    "InitiatingProcessTokenElevation": "None",
    "InitiatingProcessIntegrityLevel": null,
    "InitiatingProcessParentId": 1,
    "InitiatingProcessParentCreationTime": "2026-07-17T17:51:34.408701Z",
    "InitiatingProcessParentFileName": "launchd",
    "AdditionalFields": "{\"Terminal\":\"/dev/console\",\"PosixUserId\":503,\"PosixPrimaryGroupName\":\"staff\",\"PosixPrimaryGroupId\":20,\"PosixSecondaryGro",
    "RemoteIPType": null,
    "IsLocalAdmin": null,
    "InitiatingProcessAccountUpn": null,
    "InitiatingProcessAccountObjectId": null,
    "Protocol": null,
    "FailureReason": null,
    "InitiatingProcessFileSize": 1579408,
    "InitiatingProcessVersionInfoCompanyName": null,
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
    "Timestamp": "2026-07-18T14:24:35.144198Z",
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

func TestMapRecordEmitsLogonAndInitiatingProcess(t *testing.T) {
	ev, ok := mapRecord(decode(t, liveRecord))
	if !ok {
		t.Fatal("mapRecord dropped a valid record")
	}
	if ev.Name != eventName {
		t.Errorf("event name = %q, want %q", ev.Name, eventName)
	}

	// Timestamp bound to properties.Timestamp, as an instant — NOT the envelope
	// `time` or `_TimeReceivedBySvc`.
	wantTS, _ := time.Parse(time.RFC3339Nano, "2026-07-18T14:24:35.144198Z")
	if !ev.Timestamp.Equal(wantTS) {
		t.Errorf("timestamp = %v, want %v (bound to properties.Timestamp)", ev.Timestamp, wantTS)
	}

	want := map[string]string{
		semconv.AttrDeviceId:                     "3db402e9217f30248e26406c0a48094b00a0062e",
		semconv.AttrDeviceName:                   "mbp14",
		semconv.AttrActionType:                   "LogonSuccess",
		semconv.AttrMachineGroup:                 "main",
		semconv.AttrAccountName:                  "rob",
		semconv.AttrAccountDomain:                "mbp14",
		semconv.AttrLogonType:                    "Local",
		semconv.AttrInitiatingProcessFileName:    "loginwindow",
		semconv.AttrInitiatingProcessAccountName: "root",
	}
	for k, v := range want {
		got, _ := ev.Attrs[k].(string)
		if got != v {
			t.Errorf("attr %q = %q, want %q", k, got, v)
		}
	}

	// AdditionalFields is the stringified-JSON blob, carried verbatim.
	af, _ := ev.Attrs[semconv.AttrAdditionalFields].(string)
	if af == "" {
		t.Error("additional_fields should be non-empty")
	}
	if !strings.HasPrefix(af, "{") {
		t.Errorf("additional_fields = %q, want it to start with '{'", af)
	}

	// RemoteIP arrives as "" (sentinel for "no remote endpoint"), not null —
	// SetStr already omits an empty string, so it must be absent, not "".
	if _, present := ev.Attrs[semconv.AttrRemoteIp]; present {
		t.Error("remote_ip should be omitted when the wire value is the empty-string sentinel")
	}

	// Numeric fields land as numbers, not strings.
	if pid, ok := ev.Attrs[semconv.AttrInitiatingProcessId].(float64); !ok || pid != 542 {
		t.Errorf("initiating_process_id = %v, want float64(542)", ev.Attrs[semconv.AttrInitiatingProcessId])
	}
	if rid, ok := ev.Attrs[semconv.AttrReportId].(float64); !ok || rid != 34354 {
		t.Errorf("report_id = %v, want float64(34354)", ev.Attrs[semconv.AttrReportId])
	}

	// LogonId/RemotePort are null on this record — omitted, not stamped as 0.
	if _, present := ev.Attrs[semconv.AttrLogonId]; present {
		t.Error("logon_id should be omitted when null")
	}
	if _, present := ev.Attrs[semconv.AttrRemotePort]; present {
		t.Error("remote_port should be omitted when null")
	}

	// IsLocalAdmin is null on this record — omitted, not stamped false.
	if _, present := ev.Attrs[semconv.AttrIsLocalAdmin]; present {
		t.Error("is_local_admin should be omitted when null (not false)")
	}

	// The remote-session bool IS present as a JSON bool (false) and is stamped.
	if got, _ := ev.Attrs[semconv.AttrIsInitiatingProcessRemoteSession].(string); got != "false" {
		t.Errorf("is_initiating_process_remote_session = %q, want \"false\"", got)
	}
}

func TestMapRecordDropsMalformed(t *testing.T) {
	// No properties → dropped.
	if _, ok := mapRecord(map[string]any{"time": "2026-07-18T14:28:01Z"}); ok {
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
	wantTS, _ := time.Parse(time.RFC3339Nano, "2026-07-18T14:24:35.144198Z")
	if !logs[0].Timestamp.Equal(wantTS) {
		t.Errorf("timestamp = %s, want %s", logs[0].Timestamp, wantTS)
	}
	if got := logs[0].Attrs[semconv.AttrAccountName]; got != "rob" {
		t.Errorf("account_name = %q, want rob", got)
	}
	if got := logs[0].Attrs[semconv.AttrInitiatingProcessFileName]; got != "loginwindow" {
		t.Errorf("initiating_process_file_name = %q, want loginwindow", got)
	}

	// Cursor persisted: a second tick over the unchanged blob emits nothing new.
	if err := c.Collect(context.Background(), rec.Emitter()); err != nil {
		t.Fatalf("second Collect: %v", err)
	}
	if got := len(rec.LogRecords()); got != 1 {
		t.Errorf("after a second tick over an unchanged blob: %d records, want 1", got)
	}
}
