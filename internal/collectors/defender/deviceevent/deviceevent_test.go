package deviceevent

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

// liveRecord is a real DeviceEvents envelope captured off the m7kni storage
// account as graph2otel-poller (cert on camden, 2026-07-18, #106): a
// ScriptContent event — Defender for Endpoint on macOS running its own log4j
// mitigation scanner (open_files.py) via python3.9. DeviceEvents is Defender's
// catch-all table, and ScriptContent is the specific ActionType whose
// AdditionalFields carries an entire script body; the maintainer decision on
// #106 is to ship that verbatim, so this fixture exercises exactly that path.
// The script body inside AdditionalFields is trimmed here for fixture size (the
// mapper carries the field opaquely, so the trim does not weaken the test);
// every other field is the exact wire value.
const liveRecord = `{
  "time": "2026-07-18T15:02:20.5690830Z",
  "tenantId": "4b8c18bd-2f9f-4227-af55-9f1061cf9c32",
  "operationName": "Publish",
  "category": "AdvancedHunting-DeviceEvents",
  "_TimeReceivedBySvc": "2026-07-18T15:00:43.5907012Z",
  "properties": {
    "DeviceId": "3db402e9217f30248e26406c0a48094b00a0062e",
    "DeviceName": "mbp14",
    "ReportId": 35600,
    "InitiatingProcessId": 91350,
    "InitiatingProcessCreationTime": "2026-07-18T14:55:51.572171Z",
    "InitiatingProcessCommandLine": "/Library/Developer/CommandLineTools/usr/bin/python3 \"/Applications/Microsoft Defender.app/Contents/MacOS/wdavdaemon_enterprise.app/Contents/Resources/Scripts/open_files.py\" --ScriptName open_files.py --id log4j_handlersV2",
    "InitiatingProcessParentFileName": "python3.9",
    "InitiatingProcessParentId": 91350,
    "InitiatingProcessParentCreationTime": "2026-07-18T14:55:51.497607Z",
    "InitiatingProcessSHA1": "793f255ee12b821ce0d03adb81146ff6d436f03e",
    "InitiatingProcessMD5": "c5d5a2ff9c114f9049d1c21c7e5411ef",
    "InitiatingProcessFileName": "python3.9",
    "InitiatingProcessFolderPath": "/library/developer/commandlinetools/library/frameworks/python3.framework/versions/3.9/bin/python3.9",
    "InitiatingProcessAccountName": "root",
    "InitiatingProcessAccountDomain": "mbp14",
    "AdditionalFields": "{\"ScriptContent\": \"# sudo python3 open_files.py --ScriptName open_files.py --id log4j_handlersV2 --filter-env LOG4J_FORMAT_MSG_NO_LOOKUPS=true ...[script body trimmed for fixture; carried verbatim by the mapper]\"}",
    "InitiatingProcessAccountSid": "S-1-5-18",
    "InitiatingProcessSHA256": "449911af4658415d2879b0e1dc5ce8782230cfd15dfc91f985bebd63f7098cd9",
    "SHA256": "aabadc31fe6e32576563a9c5ba19f5cf81674b6d6ca6458185adb23b6d205945",
    "ActionType": "ScriptContent",
    "InitiatingProcessLogonId": 0,
    "InitiatingProcessFileSize": 53200,
    "InitiatingProcessVersionInfoCompanyName": "(APPLE)",
    "IsInitiatingProcessRemoteSession": false,
    "IsProcessRemoteSession": false,
    "InitiatingProcessUniqueId": "0",
    "Timestamp": "2026-07-18T14:55:51.581324Z",
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

func TestMapRecordEmitsDeviceEventAndAdditionalFields(t *testing.T) {
	ev, ok := mapRecord(decode(t, liveRecord))
	if !ok {
		t.Fatal("mapRecord dropped a valid record")
	}
	if ev.Name != eventName {
		t.Errorf("event name = %q, want %q", ev.Name, eventName)
	}

	// Timestamp bound to properties.Timestamp, as an instant — NOT the envelope
	// `time` or `_TimeReceivedBySvc`.
	wantTS, _ := time.Parse(time.RFC3339Nano, "2026-07-18T14:55:51.581324Z")
	if !ev.Timestamp.Equal(wantTS) {
		t.Errorf("timestamp = %v, want %v (bound to properties.Timestamp)", ev.Timestamp, wantTS)
	}

	if got, _ := ev.Attrs[semconv.AttrActionType].(string); got != "ScriptContent" {
		t.Errorf("action_type = %q, want %q", got, "ScriptContent")
	}
	if got, _ := ev.Attrs[semconv.AttrDeviceName].(string); got != "mbp14" {
		t.Errorf("device_name = %q, want %q", got, "mbp14")
	}

	// AdditionalFields is shipped VERBATIM (#106) — never hashed, truncated, or
	// dropped, since ScriptContent lives inside it on a ScriptContent record.
	got, _ := ev.Attrs[semconv.AttrAdditionalFields].(string)
	if got == "" {
		t.Fatal("additional_fields should be present and non-empty")
	}
	if !strings.Contains(got, "ScriptContent") {
		t.Errorf("additional_fields = %q, want the raw AdditionalFields JSON verbatim (ScriptContent shipped per #106)", got)
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
	wantTS, _ := time.Parse(time.RFC3339Nano, "2026-07-18T14:55:51.581324Z")
	if !logs[0].Timestamp.Equal(wantTS) {
		t.Errorf("timestamp = %s, want %s", logs[0].Timestamp, wantTS)
	}
	if got := logs[0].Attrs[semconv.AttrActionType]; got != "ScriptContent" {
		t.Errorf("action_type = %q, want %q", got, "ScriptContent")
	}

	// Cursor persisted: a second tick over the unchanged blob emits nothing new.
	if err := c.Collect(context.Background(), rec.Emitter()); err != nil {
		t.Fatalf("second Collect: %v", err)
	}
	if got := len(rec.LogRecords()); got != 1 {
		t.Errorf("after a second tick over an unchanged blob: %d records, want 1", got)
	}
}
