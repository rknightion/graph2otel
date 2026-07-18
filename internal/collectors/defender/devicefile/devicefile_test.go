package devicefile

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

// liveRecord is a real DeviceFileEvents envelope captured off the m7kni
// storage account as graph2otel-poller (cert on camden, 2026-07-18, #106). It
// is a local FileCreated by sdbinst.exe (a compatibility-database install), the
// baseline shape a mapper must handle — the origin/network/sensitivity columns
// (FileOriginUrl/IP/ReferrerUrl, ShareName, RequestSourceIP/Port,
// SensitivityLabel/SubLabel, IsAzureInfoProtectionApplied) are all null on this
// record, so it also exercises the omit-when-null path.
const liveRecord = `{
  "time": "2026-07-18T13:01:51.2820995Z",
  "tenantId": "4b8c18bd-2f9f-4227-af55-9f1061cf9c32",
  "operationName": "Publish",
  "category": "AdvancedHunting-DeviceFileEvents",
  "_TimeReceivedBySvc": "2026-07-18T13:00:14.4590254Z",
  "properties": {
    "SHA1": "6866429eb0f03fc50f980019774036a21063a3c1",
    "FileSize": 3466,
    "MD5": "2b98391555d04d85bd2fd7ff3c8536e7",
    "FileName": "01DA54B25CE0D000.msimain.sdb",
    "FolderPath": "C:\\Windows\\apppatch\\MergeSdbFiles\\01DA54B25CE0D000.msimain.sdb",
    "InitiatingProcessCommandLine": "sdbinst.exe -m -bg",
    "InitiatingProcessFileName": "sdbinst.exe",
    "InitiatingProcessParentFileName": "svchost.exe",
    "InitiatingProcessSHA1": "9141df287ae13c987b6177715a0b8669bcfbd430",
    "InitiatingProcessMD5": "162ee68f2d637bb7722203ca4382a921",
    "InitiatingProcessFolderPath": "c:\\windows\\system32\\sdbinst.exe",
    "InitiatingProcessParentCreationTime": "2026-07-18T10:59:30.693377Z",
    "InitiatingProcessId": 5464,
    "DeviceName": "winsrv",
    "DeviceId": "56fb3abc73b440dd56cdc9873677877cd4ab0851",
    "InitiatingProcessCreationTime": "2026-07-18T12:59:31.2576124Z",
    "InitiatingProcessAccountName": "system",
    "InitiatingProcessAccountDomain": "nt authority",
    "InitiatingProcessAccountSid": "S-1-5-18",
    "InitiatingProcessParentId": 3196,
    "ReportId": 8132,
    "SHA256": "a22e3536dcbc1e2488deca17e6c6f91e4dac7c5e3ebba453ec279b223eda6c26",
    "InitiatingProcessIntegrityLevel": "System",
    "InitiatingProcessTokenElevation": "TokenElevationTypeDefault",
    "FileOriginUrl": null,
    "FileOriginIP": null,
    "FileOriginReferrerUrl": null,
    "AppGuardContainerId": "",
    "ActionType": "FileCreated",
    "SensitivityLabel": null,
    "SensitivitySubLabel": null,
    "IsAzureInfoProtectionApplied": null,
    "RequestProtocol": "Local",
    "ShareName": null,
    "RequestSourceIP": null,
    "RequestSourcePort": null,
    "RequestAccountName": "SYSTEM",
    "RequestAccountDomain": "NT AUTHORITY",
    "RequestAccountSid": "S-1-5-18",
    "InitiatingProcessSHA256": "b10190d2bd2de337095ef3cf52178ae438cbeee5e54602b5cedd2b4c3950ec51",
    "InitiatingProcessAccountUpn": null,
    "InitiatingProcessAccountObjectId": null,
    "AdditionalFields": "{\"FileType\":\"Unknown\"}",
    "PreviousFolderPath": "",
    "PreviousFileName": "",
    "InitiatingProcessFileSize": 299008,
    "InitiatingProcessVersionInfoCompanyName": "Microsoft Corporation",
    "InitiatingProcessVersionInfoProductName": "Microsoft® Windows® Operating System",
    "InitiatingProcessVersionInfoProductVersion": "10.0.26100.32860",
    "InitiatingProcessVersionInfoInternalFileName": "sdbinst.exe",
    "InitiatingProcessVersionInfoOriginalFileName": "sdbinst.exe",
    "InitiatingProcessVersionInfoFileDescription": "Application Compatibility Database Installer",
    "InitiatingProcessSessionId": 0,
    "IsInitiatingProcessRemoteSession": false,
    "InitiatingProcessRemoteSessionDeviceName": null,
    "InitiatingProcessRemoteSessionIP": null,
    "InitiatingProcessUniqueId": "13510798882112217",
    "Timestamp": "2026-07-18T12:59:31.2914446Z",
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

func TestMapRecordEmitsFileAndInitiatingProcess(t *testing.T) {
	ev, ok := mapRecord(decode(t, liveRecord))
	if !ok {
		t.Fatal("mapRecord dropped a valid record")
	}
	if ev.Name != eventName {
		t.Errorf("event name = %q, want %q", ev.Name, eventName)
	}

	// Timestamp bound to properties.Timestamp, as an instant — NOT the envelope
	// `time` or `_TimeReceivedBySvc`.
	wantTS, _ := time.Parse(time.RFC3339Nano, "2026-07-18T12:59:31.2914446Z")
	if !ev.Timestamp.Equal(wantTS) {
		t.Errorf("timestamp = %v, want %v (bound to properties.Timestamp)", ev.Timestamp, wantTS)
	}

	want := map[string]string{
		semconv.AttrDeviceId:                     "56fb3abc73b440dd56cdc9873677877cd4ab0851",
		semconv.AttrDeviceName:                   "winsrv",
		semconv.AttrActionType:                   "FileCreated",
		semconv.AttrMachineGroup:                 "main",
		semconv.AttrFileName:                     "01DA54B25CE0D000.msimain.sdb",
		semconv.AttrFolderPath:                   "C:\\Windows\\apppatch\\MergeSdbFiles\\01DA54B25CE0D000.msimain.sdb",
		semconv.AttrSha256:                       "a22e3536dcbc1e2488deca17e6c6f91e4dac7c5e3ebba453ec279b223eda6c26",
		semconv.AttrInitiatingProcessFileName:    "sdbinst.exe",
		semconv.AttrInitiatingProcessAccountName: "system",
		semconv.AttrRequestProtocol:              "Local",
		semconv.AttrRequestAccountName:           "SYSTEM",
		semconv.AttrAdditionalFields:             `{"FileType":"Unknown"}`,
	}
	for k, v := range want {
		got, _ := ev.Attrs[k].(string)
		if got != v {
			t.Errorf("attr %q = %q, want %q", k, got, v)
		}
	}

	// Numeric fields land as numbers, not strings.
	if pid, ok := ev.Attrs[semconv.AttrInitiatingProcessId].(float64); !ok || pid != 5464 {
		t.Errorf("initiating_process_id = %v, want float64(5464)", ev.Attrs[semconv.AttrInitiatingProcessId])
	}
	if rid, ok := ev.Attrs[semconv.AttrReportId].(float64); !ok || rid != 8132 {
		t.Errorf("report_id = %v, want float64(8132)", ev.Attrs[semconv.AttrReportId])
	}

	// Origin/network/sensitivity columns are null on this record — omitted, not
	// emitted empty.
	for _, k := range []string{
		semconv.AttrFileOriginUrl,
		semconv.AttrFileOriginIp,
		semconv.AttrFileOriginReferrerUrl,
		semconv.AttrShareName,
		semconv.AttrRequestSourceIp,
		semconv.AttrRequestSourcePort,
		semconv.AttrSensitivityLabel,
		semconv.AttrSensitivitySubLabel,
		semconv.AttrIsAzureInfoProtectionApplied,
	} {
		if _, present := ev.Attrs[k]; present {
			t.Errorf("attr %q should be omitted when null, got %v", k, ev.Attrs[k])
		}
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
		name: "tenantId=" + tenant + "/y=2026/m=07/d=18/h=13/m=00/PT1H.json",
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
	wantTS, _ := time.Parse(time.RFC3339Nano, "2026-07-18T12:59:31.2914446Z")
	if !logs[0].Timestamp.Equal(wantTS) {
		t.Errorf("timestamp = %s, want %s", logs[0].Timestamp, wantTS)
	}
	if got := logs[0].Attrs[semconv.AttrFileName]; got != "01DA54B25CE0D000.msimain.sdb" {
		t.Errorf("file_name attr = %q, want 01DA54B25CE0D000.msimain.sdb", got)
	}
	if got := logs[0].Attrs[semconv.AttrInitiatingProcessFileName]; got != "sdbinst.exe" {
		t.Errorf("initiating_process_file_name = %q, want sdbinst.exe", got)
	}

	// Cursor persisted: a second tick over the unchanged blob emits nothing new.
	if err := c.Collect(context.Background(), rec.Emitter()); err != nil {
		t.Fatalf("second Collect: %v", err)
	}
	if got := len(rec.LogRecords()); got != 1 {
		t.Errorf("after a second tick over an unchanged blob: %d records, want 1", got)
	}
}
