package manageddevices

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/rknightion/graph2otel/internal/semconv"
	"github.com/rknightion/graph2otel/internal/telemetrytest"
)

// blobDeviceRecord is a Devices diagnostic-settings record captured live off
// m7kni (2026-07-18, #135) — device mbp14. PascalCase field names and enum
// values (CompliantState "Compliant", OS "MacOS", EncryptionStatusString "True")
// that must normalize onto the Graph managedDevice shape.
const blobDeviceRecord = `{
  "time": "2026-07-18T00:44:52.4221000Z",
  "category": "Devices",
  "properties": {
    "DeviceId": "33dcca32-d6ea-478b-88d9-e2a891f9d83a",
    "DeviceName": "mbp14",
    "UPN": "rob@m7kni.io",
    "LastContact": "2026-07-17T23:55:14.00258",
    "OSVersion": "27.0 (26A5378n)",
    "OS": "MacOS",
    "CompliantState": "Compliant",
    "Ownership": "Corporate",
    "Model": "MacBook Pro",
    "SerialNumber": "THRWX5256T",
    "Manufacturer": "Apple",
    "EncryptionStatusString": "True",
    "WifiMacAddress": "bcd07417e7cd"
  }
}`

// blobStatsRecord is the trailing per-batch summary — no DeviceId, must be skipped.
const blobStatsRecord = `{
  "time": "2026-07-18T00:44:52.4221000Z",
  "category": "Devices",
  "properties": { "BatchId": "8f37f88b", "Stats": { "RecordCount": 11 } }
}`

func decodeDev(t *testing.T, body string) map[string]any {
	t.Helper()
	var rec map[string]any
	if err := json.Unmarshal([]byte(body), &rec); err != nil {
		t.Fatalf("decode: %v", err)
	}
	return rec
}

// TestMapBlobDeviceNormalizesAndReusesTwin is the load-bearing test: the blob
// values normalize onto the Graph shape (so the twin is identical across
// transports), the record renders through the SAME deviceLogTwin, and the
// timestamp binds to the snapshot's envelope time.
func TestMapBlobDeviceNormalizesAndReusesTwin(t *testing.T) {
	ev, ok := mapBlobDevice(decodeDev(t, blobDeviceRecord))
	if !ok {
		t.Fatal("mapBlobDevice dropped a valid device record")
	}
	if ev.Name != eventManagedDevice {
		t.Errorf("event name = %q, want %q", ev.Name, eventManagedDevice)
	}
	// Value normalization — the whole point: these must match the polled shape.
	if got := ev.Attrs[semconv.AttrComplianceState]; got != "compliant" {
		t.Errorf("compliance_state = %q, want compliant (from blob \"Compliant\")", got)
	}
	if got := ev.Attrs[semconv.AttrOperatingSystem]; got != "macOS" {
		t.Errorf("operating_system = %q, want macOS (from blob \"MacOS\")", got)
	}
	if got := ev.Attrs[semconv.AttrIsEncrypted]; got != "true" {
		t.Errorf("is_encrypted = %q, want true (from blob \"True\")", got)
	}
	if got := ev.Attrs[semconv.AttrDeviceName]; got != "mbp14" {
		t.Errorf("device_name = %q", got)
	}
	if got := ev.Attrs[semconv.AttrUserPrincipalName]; got != "rob@m7kni.io" {
		t.Errorf("user_principal_name = %q", got)
	}
	if got := ev.Attrs[semconv.AttrSerialNumber]; got != "THRWX5256T" {
		t.Errorf("serial_number = %q", got)
	}
	wantTS, _ := time.Parse(time.RFC3339Nano, "2026-07-18T00:44:52.4221000Z")
	if !ev.Timestamp.Equal(wantTS) {
		t.Errorf("timestamp = %v, want the envelope snapshot time", ev.Timestamp)
	}
}

func TestMapBlobDeviceSkipsStatsRecord(t *testing.T) {
	if _, ok := mapBlobDevice(decodeDev(t, blobStatsRecord)); ok {
		t.Error("the per-batch Stats summary (no DeviceId) must be skipped")
	}
}

func TestMapBlobDeviceDropsUndated(t *testing.T) {
	rec := decodeDev(t, `{"category":"Devices","properties":{"DeviceId":"x"}}`)
	if _, ok := mapBlobDevice(rec); ok {
		t.Error("record with no envelope time should be dropped")
	}
}

// TestComplianceStateParityAcrossTransports is #261's proof. The blob Devices
// category spells complianceState in PascalCase and the Graph managedDevice
// resource spells it camelCase, so the SAME device state arrives as two
// different strings depending on which transport is configured — and transport
// is exclusive per collector (#144), so nobody ever sees both to notice.
//
// The two camelCase members are the ones that broke: the blob path lowercased
// them into a spelling complianceBuckets does not contain, so they bucketed to
// "other" on blob and correctly on Graph. Both halves are asserted — the raw
// twin attribute (the value a SIEM query filters on) and the bucket (the metric
// label) — because the lowercasing corrupted both.
func TestComplianceStateParityAcrossTransports(t *testing.T) {
	for _, tc := range []struct{ blobValue, graphValue, wantAttr, wantBucket string }{
		{"Compliant", "compliant", "compliant", "compliant"},
		{"Noncompliant", "noncompliant", "noncompliant", "noncompliant"},
		{"Conflict", "conflict", "conflict", "conflict"},
		{"Error", "error", "error", "error"},
		{"Unknown", "unknown", "unknown", "unknown"},
		{"InGracePeriod", "inGracePeriod", "inGracePeriod", "in_grace_period"},
		{"ConfigManager", "configManager", "configManager", "config_manager"},
	} {
		t.Run(tc.blobValue, func(t *testing.T) {
			blobEv, ok := mapBlobDevice(decodeDev(t, `{"time":"2026-07-18T00:44:52.4221000Z","category":"Devices","properties":{"DeviceId":"d","DeviceName":"dev","OS":"Windows","CompliantState":"`+tc.blobValue+`"}}`))
			if !ok {
				t.Fatal("mapBlobDevice dropped a valid record")
			}
			graphEv := deviceLogTwin(
				managedDevice{ID: "d", DeviceName: "dev", OperatingSystem: "Windows", ComplianceState: tc.graphValue},
				complianceBucketFor(tc.graphValue), stalenessUnknown)

			blobState, _ := blobEv.Attrs[semconv.AttrComplianceState].(string)
			graphState, _ := graphEv.Attrs[semconv.AttrComplianceState].(string)
			if blobState != tc.wantAttr || graphState != tc.wantAttr {
				t.Errorf("compliance_state: blob %q, graph %q, want %q on both", blobState, graphState, tc.wantAttr)
			}
			if got := complianceBucketFor(tc.blobValue); got != tc.wantBucket {
				t.Errorf("blob %q buckets to %q, want %q", tc.blobValue, got, tc.wantBucket)
			}
			if got := complianceBucketFor(tc.graphValue); got != tc.wantBucket {
				t.Errorf("graph %q buckets to %q, want %q", tc.graphValue, got, tc.wantBucket)
			}
		})
	}
}

func TestNormalizeOSPassesThroughUnmapped(t *testing.T) {
	for blob, want := range map[string]string{"MacOS": "macOS", "IOS": "iOS", "Windows": "Windows", "Linux": "Linux"} {
		if got := normalizeOS(blob); got != want {
			t.Errorf("normalizeOS(%q) = %q, want %q", blob, got, want)
		}
	}
}

// TestDeviceTwinSuppressedKeepsGauges is the #135-F guard: with the twin
// suppressed (the blob Devices collector owns it), the polled fleet gauges still
// emit but no per-device intune.managed_device log does.
func TestDeviceTwinSuppressedKeepsGauges(t *testing.T) {
	g := &fakeGraph{bodies: fullFixtureBodies()}
	c := newTestCollector(g)
	c.suppressedTwins = map[string]bool{eventManagedDevice: true}
	rec := telemetrytest.New()
	if err := c.Collect(context.Background(), rec.Emitter()); err != nil {
		t.Fatalf("Collect: %v", err)
	}
	// Fleet count gauge is unaffected.
	if pts := rec.MetricPoints(countMetricName); len(pts) == 0 {
		t.Errorf("%s must still emit when the twin is suppressed", countMetricName)
	}
	// No per-device twin.
	for _, l := range rec.LogRecords() {
		if l.EventName == eventManagedDevice {
			t.Errorf("emitted a %s twin despite suppression — the blob owns it", eventManagedDevice)
		}
	}
}

// TestMapBlobDeviceGraceExpiryParity pins #193 blob-twin parity: the Devices
// category's `InGracePeriodUntil` (no-timezone, variable-fraction; the same two
// sentinels as the Graph field, live-measured 2026-07-19) maps onto the same
// twin attribute a real deadline emits, both sentinels omit.
func TestMapBlobDeviceGraceExpiryParity(t *testing.T) {
	rec := func(grace string) map[string]any {
		return decodeDev(t, `{"time":"2026-07-18T00:44:52.4221000Z","category":"Devices","properties":{"DeviceId":"d","DeviceName":"dev","CompliantState":"InGracePeriod","OS":"Windows","InGracePeriodUntil":"`+grace+`"}}`)
	}
	// Real deadline → emitted, normalized to RFC3339.
	ev, ok := mapBlobDevice(rec("2026-07-14T14:31:08.4122"))
	if !ok {
		t.Fatal("mapBlobDevice dropped a valid record")
	}
	want := time.Date(2026, 7, 14, 14, 31, 8, 412200000, time.UTC).Format(time.RFC3339)
	if got := ev.Attrs[semconv.AttrComplianceGracePeriodExpiration]; got != want {
		t.Errorf("grace attr = %q, want %q", got, want)
	}
	// #261: this fixture has always carried CompliantState "InGracePeriod" with
	// nothing asserting what it normalized to, which is exactly how the blob
	// path's lowercasing hid for so long. The twin must carry the canonical
	// Graph member, and the bucket must be the same one the Graph path picks.
	if got := ev.Attrs[semconv.AttrComplianceState]; got != "inGracePeriod" {
		t.Errorf("compliance_state = %q, want inGracePeriod (from blob \"InGracePeriod\")", got)
	}
	state, _ := ev.Attrs[semconv.AttrComplianceState].(string)
	if got := complianceBucketFor(state); got != "in_grace_period" {
		t.Errorf("bucket = %q, want in_grace_period", got)
	}
	// The 9999 max-date sentinel → omitted.
	ev, _ = mapBlobDevice(rec("9999-12-31T23:59:59.9999999"))
	if _, present := ev.Attrs[semconv.AttrComplianceGracePeriodExpiration]; present {
		t.Error("the 9999 max-date sentinel must be omitted from the blob twin")
	}
}
