package deviceinfo

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

// liveRecord is a real DeviceInfo envelope captured off the m7kni storage
// account as graph2otel-poller (cert on camden, 2026-07-18, #106) — the macOS
// "mbp14" snapshot, the first full record in that hour's blob. Its ReportId is
// an 18-digit sequence that exceeds float64's exact-integer range, so the
// collector deliberately does not emit it (see mapRecord) — the record keeps it
// only to document that trap.
const liveRecord = `{
  "time": "2026-07-18T14:08:10.0236840Z",
  "tenantId": "4b8c18bd-2f9f-4227-af55-9f1061cf9c32",
  "operationName": "Publish",
  "category": "AdvancedHunting-DeviceInfo",
  "_TimeReceivedBySvc": "2026-07-18T14:06:17.0463703Z",
  "properties": {
    "ClientVersion": "20.126052.16.0",
    "PublicIP": "81.187.237.31",
    "DeviceName": "mbp14",
    "DeviceId": "3db402e9217f30248e26406c0a48094b00a0062e",
    "ReportId": 639199803770463703,
    "OSArchitecture": "64-bit",
    "OSPlatform": "macOS",
    "OSBuild": null,
    "IsAzureADJoined": false,
    "LoggedOnUsers": "[{\"UserName\":\"rob\"}]",
    "RegistryDeviceTag": "mac",
    "OSVersion": "27.0",
    "AdditionalFields": null,
    "AadDeviceId": "8c42f011-6105-4269-a64b-6eabc71b2006",
    "MergedDeviceIds": "",
    "MergedToDeviceId": "",
    "Vendor": "Apple",
    "Model": "MacBookPro18,3",
    "OnboardingStatus": "Onboarded",
    "DeviceCategory": "Endpoint",
    "DeviceType": "Workstation",
    "DeviceSubtype": "Workstation",
    "OSVersionInfo": "",
    "OSDistribution": "macOS",
    "JoinType": "AAD Registered",
    "SensorHealthState": "Active",
    "IsInternetFacing": null,
    "IsExcluded": false,
    "ExclusionReason": null,
    "ExposureLevel": "Medium",
    "AssetValue": null,
    "DeviceDynamicTags": null,
    "MitigationStatus": null,
    "DeviceManualTags": null,
    "HardwareUuid": "d8a332db-b0c3-5046-8d99-c844c3171ba3",
    "AzureVmId": null,
    "AzureVmSubscriptionId": null,
    "CloudPlatforms": null,
    "HostDeviceId": null,
    "ConnectivityType": "Streamlined",
    "AwsResourceName": null,
    "GcpFullResourceName": null,
    "AzureResourceId": null,
    "IsTransient": false,
    "OsBuildRevision": null,
    "Timestamp": "2026-07-18T14:05:55.510513Z",
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

func TestMapRecordEmitsDeviceInfo(t *testing.T) {
	ev, ok := mapRecord(decode(t, liveRecord))
	if !ok {
		t.Fatal("mapRecord dropped a valid record")
	}
	if ev.Name != eventName {
		t.Errorf("event name = %q, want %q", ev.Name, eventName)
	}

	// Timestamp bound to properties.Timestamp, as an instant — NOT the envelope
	// `time` or `_TimeReceivedBySvc`.
	wantTS, _ := time.Parse(time.RFC3339Nano, "2026-07-18T14:05:55.510513Z")
	if !ev.Timestamp.Equal(wantTS) {
		t.Errorf("timestamp = %v, want %v (bound to properties.Timestamp)", ev.Timestamp, wantTS)
	}

	want := map[string]string{
		semconv.AttrDeviceId:          "3db402e9217f30248e26406c0a48094b00a0062e",
		semconv.AttrDeviceName:        "mbp14",
		semconv.AttrMachineGroup:      "main",
		semconv.AttrOsPlatform:        "macOS",
		semconv.AttrVendor:            "Apple",
		semconv.AttrModel:             "MacBookPro18,3",
		semconv.AttrSensorHealthState: "Active",
		semconv.AttrExposureLevel:     "Medium",
	}
	for k, v := range want {
		got, _ := ev.Attrs[k].(string)
		if got != v {
			t.Errorf("attr %q = %q, want %q", k, got, v)
		}
	}

	if got, _ := ev.Attrs[semconv.AttrLoggedOnUsers].(string); !strings.HasPrefix(got, "[") {
		t.Errorf("logged_on_users = %q, want it to start with %q (verbatim stringified JSON)", got, "[")
	}

	// Bools are stamped as strings; IsAzureADJoined is a JSON bool present as
	// `false`, so it must be present and equal "false", not omitted.
	if got, _ := ev.Attrs[semconv.AttrIsAzureAdJoined].(string); got != "false" {
		t.Errorf("is_azure_ad_joined = %q, want \"false\"", got)
	}

	// Null booleans (IsInternetFacing on this record) are omitted, not stamped
	// as a misleading "false".
	if _, present := ev.Attrs[semconv.AttrIsInternetFacing]; present {
		t.Error("is_internet_facing should be omitted when null, not stamped false")
	}

	// Empty-string columns (MergedDeviceIds/MergedToDeviceId/OSVersionInfo on
	// this record) are omitted, not emitted blank.
	for _, k := range []string{semconv.AttrMergedDeviceIds, semconv.AttrMergedToDeviceId, semconv.AttrOsVersionInfo} {
		if _, present := ev.Attrs[k]; present {
			t.Errorf("attr %q should be omitted when empty, not emitted blank", k)
		}
	}

	// OSBuild is null on this (macOS) record and must be omitted, not zeroed.
	if _, present := ev.Attrs[semconv.AttrOsBuild]; present {
		t.Error("os_build should be omitted when null")
	}
}

func TestMapRecordDropsMalformed(t *testing.T) {
	// No properties → dropped.
	if _, ok := mapRecord(map[string]any{"time": "2026-07-18T14:08:10Z"}); ok {
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

// TestCollectorEmitsLiveRecordEndToEnd drives the whole collector over the
// pinned live record — JSON Lines with the CRLF terminators Azure writes — and
// asserts what reaches the emitter. It is also what makes the signals golden
// substantive (#164): the golden captures the attributes THIS drives into the
// Recorder.
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
	wantTS, _ := time.Parse(time.RFC3339Nano, "2026-07-18T14:05:55.510513Z")
	if !logs[0].Timestamp.Equal(wantTS) {
		t.Errorf("timestamp = %s, want %s", logs[0].Timestamp, wantTS)
	}
	if got := logs[0].Attrs[semconv.AttrOsPlatform]; got != "macOS" {
		t.Errorf("os_platform attr = %q, want macOS", got)
	}

	// Cursor persisted: a second tick over the unchanged blob emits nothing new.
	if err := c.Collect(context.Background(), rec.Emitter()); err != nil {
		t.Fatalf("second Collect: %v", err)
	}
	if got := len(rec.LogRecords()); got != 1 {
		t.Errorf("after a second tick over an unchanged blob: %d records, want 1", got)
	}
}
