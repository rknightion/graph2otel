package manageddevices

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/rknightion/graph2otel/internal/collectors"
	"github.com/rknightion/graph2otel/internal/semconv"
	"github.com/rknightion/graph2otel/internal/telemetry"
	"github.com/rknightion/graph2otel/internal/telemetrytest"
)

// fakeGraph maps request URLs to canned raw bodies (or errors), mirroring the
// entra/devices reference collector's test fake. GetAllValues pagination is
// supported via nextBody/nextURL chaining on the map.
type fakeGraph struct {
	bodies map[string]string
	errs   map[string]error
}

func (f *fakeGraph) RawGet(_ context.Context, url string) ([]byte, error) {
	if err, ok := f.errs[url]; ok {
		return nil, err
	}
	if body, ok := f.bodies[url]; ok {
		return []byte(body), nil
	}
	return nil, errors.New("unmapped url: " + url)
}

func (f *fakeGraph) RawGetWithHeaders(ctx context.Context, url string, _ map[string]string) ([]byte, error) {
	return f.RawGet(ctx, url)
}

var _ collectors.GraphClient = (*fakeGraph)(nil)

const base = "https://graph.microsoft.com/v1.0"

var fixedNow = time.Date(2026, 7, 15, 12, 0, 0, 0, time.UTC)

func fixedClock() time.Time { return fixedNow }

func newTestCollector(g collectors.GraphClient) *Collector {
	c := New(g, nil)
	c.now = fixedClock
	return c
}

func overviewURL() string { return base + "/deviceManagement/managedDeviceOverview" }
func fleetURL() string    { return base + "/deviceManagement/managedDevices" + managedDevicesSelect }

// devicesPage builds a canned managedDevices page body (no @odata.nextLink,
// i.e. the last/only page) from a set of raw device fixtures.
func devicesPage(devices ...map[string]any) string {
	b, err := json.Marshal(map[string]any{"value": devices})
	if err != nil {
		panic(err)
	}
	return string(b)
}

func device(compliance, os string, encrypted bool, lastSync *time.Time) map[string]any {
	d := map[string]any{
		"complianceState": compliance,
		"operatingSystem": os,
		"isEncrypted":     encrypted,
	}
	if lastSync != nil {
		d["lastSyncDateTime"] = lastSync.Format(time.RFC3339)
	} else {
		d["lastSyncDateTime"] = nil
	}
	return d
}

func daysAgo(d int) *time.Time {
	t := fixedNow.Add(-time.Duration(d) * 24 * time.Hour)
	return &t
}

// deviceWithVersion builds on device() by adding a raw osVersion field - kept
// as a separate helper (rather than widening device()'s signature) so the
// many existing device() call sites are undisturbed and continue to exercise
// the empty/missing-osVersion path.
func deviceWithVersion(compliance, os, version string, encrypted bool, lastSync *time.Time) map[string]any {
	d := device(compliance, os, encrypted, lastSync)
	d["osVersion"] = version
	return d
}

// liveManagedDevices is the VERBATIM value array of a
// GET /deviceManagement/managedDevices?$select=...,model,manufacturer,wiFiMacAddress,partnerReportedThreatState
// response from the m7kni tenant, read as graph2otel-poller on 2026-07-18
// `[live-measured 2026-07-18, #180]` (the hardware/threat fields added by #180;
// the identity/state fields and their pinned per-device values are unchanged
// from the 2026-07-17 #165 capture, so the sync/compliance bucketing stays
// deterministic). It carries exactly the collector's $select projection and
// nothing more.
//
// It replaces a hand-written docs-derived fixture (alice@example.com / dev-1 /
// SN123 / LAPTOP-A) that never existed on the wire - the same class of
// fabrication #142 ("platform": "windows", never sent) and #153 (an invented
// riskType key) are made of, where a plausible-looking fixture quietly makes a
// mapping claim untestable. Pinned real, it keeps the bounded gauges honest
// against a fleet that actually spans noncompliant/unknown/compliant and
// Windows/Linux/iOS/macOS, and - the thing a docs fixture would never invent -
// two rows with an empty serialNumber AND empty userPrincipalName AND empty
// wiFiMacAddress (oli, WINSRV), which is what exercises setStr's omit-empty
// behavior against reality rather than against a fixture where every device
// conveniently has every field. partnerReportedThreatState is "unknown" on the
// whole fleet (no active MTD connector) - the real steady state, not a gap.
const liveManagedDevices = `[
  {
    "complianceState": "noncompliant",
    "deviceName": "LAPHAM",
    "id": "d5900d67-e50c-44ef-9d5c-6a2f891099c6",
    "isEncrypted": true,
    "lastSyncDateTime": "2026-07-16T15:13:29Z",
    "manufacturer": "PCSpecialist",
    "model": "Standard",
    "operatingSystem": "Windows",
    "partnerReportedThreatState": "unknown",
    "serialNumber": "PH4TRX1S2146S0097",
    "userPrincipalName": "rob@m7kni.io",
    "wiFiMacAddress": "701AB8C7BE06"
  },
  {
    "complianceState": "unknown",
    "deviceName": "oli",
    "id": "e4639a7f-4d77-d901-1e78-57646ca78cb8",
    "isEncrypted": false,
    "lastSyncDateTime": "2026-05-23T08:55:35Z",
    "manufacturer": "Gigabyte Technology Co., Ltd.",
    "model": "Z690 UD DDR4",
    "operatingSystem": "Linux",
    "partnerReportedThreatState": "unknown",
    "serialNumber": "",
    "userPrincipalName": "",
    "wiFiMacAddress": ""
  },
  {
    "complianceState": "unknown",
    "deviceName": "WINSRV",
    "id": "f780403a-4ccd-e3ef-ac17-9f1c61c00244",
    "isEncrypted": false,
    "lastSyncDateTime": "2026-07-17T14:14:19Z",
    "manufacturer": "QEMU",
    "model": "Standard PC (Q35 + ICH9, 2009)",
    "operatingSystem": "Windows",
    "partnerReportedThreatState": "unknown",
    "serialNumber": "",
    "userPrincipalName": "",
    "wiFiMacAddress": ""
  },
  {
    "complianceState": "compliant",
    "deviceName": "TampooniPad",
    "id": "2af9ec65-db9b-455c-8b3a-7a2691958b88",
    "isEncrypted": true,
    "lastSyncDateTime": "2026-07-17T14:49:20Z",
    "manufacturer": "Apple",
    "model": "iPad Pro (12.9\")(5th generation)",
    "operatingSystem": "iOS",
    "partnerReportedThreatState": "unknown",
    "serialNumber": "NP412Q6YQ0",
    "userPrincipalName": "rob@m7kni.io",
    "wiFiMacAddress": "88665af33c71"
  },
  {
    "complianceState": "compliant",
    "deviceName": "MBP16",
    "id": "57d346d7-ddf1-489b-b70d-a30dce1e2458",
    "isEncrypted": true,
    "lastSyncDateTime": "2026-07-17T15:06:48Z",
    "manufacturer": "Apple",
    "model": "MacBook Pro",
    "operatingSystem": "macOS",
    "partnerReportedThreatState": "unknown",
    "serialNumber": "YJY0H9JDGP",
    "userPrincipalName": "rob@m7kni.io",
    "wiFiMacAddress": "f4d488683c84"
  }
]`

// liveNow is a clock just after the newest lastSyncDateTime in
// liveManagedDevices (MBP16, 15:06:48Z), chosen so the real fleet's sync
// recency buckets deterministically: MBP16/TampooniPad/WINSRV under_1d, LAPHAM
// 1d_7d (~24.8h), oli over_30d (~55d). Do not "round" it - the buckets depend
// on it.
var liveNow = time.Date(2026, 7, 17, 16, 0, 0, 0, time.UTC)

// liveFleetBody wraps the pinned live array in the {"value": ...} envelope the
// managedDevices list endpoint returns (single/last page - no @odata.nextLink).
func liveFleetBody() string { return `{"value":` + liveManagedDevices + `}` }

// decodeLiveDevices unmarshals the pinned live array into the per-record maps a
// test can index by id.
func decodeLiveDevices(t *testing.T) []map[string]any {
	t.Helper()
	var devices []map[string]any
	if err := json.Unmarshal([]byte(liveManagedDevices), &devices); err != nil {
		t.Fatalf("decode live managedDevices: %v", err)
	}
	return devices
}

// liveDevice returns the single pinned live record with the given deviceName.
func liveDevice(t *testing.T, name string) map[string]any {
	t.Helper()
	for _, d := range decodeLiveDevices(t) {
		if d["deviceName"] == name {
			return d
		}
	}
	t.Fatalf("no live device named %q", name)
	return nil
}

const overviewFixture = `{
	"enrolledDeviceCount": 42,
	"mdmEnrolledCount": 40,
	"dualEnrolledDeviceCount": 2,
	"deviceOperatingSystemSummary": {
		"androidCount": 10,
		"iosCount": 5,
		"macOSCount": 3,
		"windowsMobileCount": 0,
		"windowsCount": 20,
		"unknownCount": 4,
		"androidDedicatedCount": 1,
		"androidDeviceAdminCount": 1,
		"androidFullyManagedCount": 1,
		"androidWorkProfileCount": 1,
		"androidCorporateWorkProfileCount": 1,
		"configMgrDeviceCount": 0
	}
}`

func fullFixtureBodies() map[string]string {
	return map[string]string{
		overviewURL(): overviewFixture,
		fleetURL(): devicesPage(
			device("compliant", "Windows 10", true, daysAgo(0)),
			device("compliant", "Windows 10", true, daysAgo(2)),
			device("noncompliant", "iOS", false, daysAgo(10)),
			device("unknown", "Android", true, nil),
		),
	}
}

func TestCollectEmitsOverviewScalarGauges(t *testing.T) {
	g := &fakeGraph{bodies: fullFixtureBodies()}
	rec := telemetrytest.New()

	if err := newTestCollector(g).Collect(context.Background(), rec.Emitter()); err != nil {
		t.Fatalf("Collect: %v", err)
	}

	assertSingleValue(t, rec, overviewEnrolledMetricName, 42)
	assertSingleValue(t, rec, overviewMdmMetricName, 40)
	assertSingleValue(t, rec, overviewDualEnrolledMetric, 2)
}

func assertSingleValue(t *testing.T, rec *telemetrytest.Recorder, metric string, want float64) {
	t.Helper()
	pts := rec.MetricPoints(metric)
	if len(pts) != 1 {
		t.Fatalf("metric %s: got %d points, want 1: %+v", metric, len(pts), pts)
	}
	if pts[0].Value != want {
		t.Errorf("metric %s = %v, want %v", metric, pts[0].Value, want)
	}
}

func TestCollectEmitsOverviewOSBreakdown(t *testing.T) {
	g := &fakeGraph{bodies: fullFixtureBodies()}
	rec := telemetrytest.New()

	if err := newTestCollector(g).Collect(context.Background(), rec.Emitter()); err != nil {
		t.Fatalf("Collect: %v", err)
	}

	pts := rec.MetricPoints(overviewOSMetricName)
	got := map[string]float64{}
	for _, p := range pts {
		got[p.Attrs["os"]] = p.Value
	}
	want := map[string]float64{
		"android": 10, "ios": 5, "macos": 3, "windows_mobile": 0, "windows": 20, "unknown": 4,
		"android_dedicated": 1, "android_device_admin": 1, "android_fully_managed": 1,
		"android_work_profile": 1, "android_corporate_work_profile": 1, "config_mgr": 0,
	}
	if len(got) != len(want) {
		t.Fatalf("got %d os series, want %d: %v", len(got), len(want), got)
	}
	for k, v := range want {
		if got[k] != v {
			t.Errorf("os=%s value = %v, want %v", k, got[k], v)
		}
	}
}

func TestCollectAggregatesFleetCountByComplianceAndOS(t *testing.T) {
	g := &fakeGraph{bodies: fullFixtureBodies()}
	rec := telemetrytest.New()

	if err := newTestCollector(g).Collect(context.Background(), rec.Emitter()); err != nil {
		t.Fatalf("Collect: %v", err)
	}

	pts := rec.MetricPoints(countMetricName)
	got := map[string]float64{}
	for _, p := range pts {
		got[p.Attrs["compliance_state"]+"/"+p.Attrs["operating_system"]] = p.Value
	}
	want := map[string]float64{
		"compliant/windows": 2,
		"noncompliant/ios":  1,
		"unknown/android":   1,
	}
	if len(got) != len(want) {
		t.Fatalf("got %d count series, want %d: %v", len(got), len(want), got)
	}
	for k, v := range want {
		if got[k] != v {
			t.Errorf("%s = %v, want %v", k, got[k], v)
		}
	}
}

func TestCollectAggregatesEncryptedByOS(t *testing.T) {
	g := &fakeGraph{bodies: fullFixtureBodies()}
	rec := telemetrytest.New()

	if err := newTestCollector(g).Collect(context.Background(), rec.Emitter()); err != nil {
		t.Fatalf("Collect: %v", err)
	}

	pts := rec.MetricPoints(encryptedMetricName)
	got := map[string]float64{}
	for _, p := range pts {
		got[p.Attrs["operating_system"]] = p.Value
	}
	// 2 encrypted windows devices, 1 encrypted android device; the
	// unencrypted iOS device contributes nothing.
	want := map[string]float64{"windows": 2, "android": 1}
	if len(got) != len(want) {
		t.Fatalf("got %d encrypted series, want %d: %v", len(got), len(want), got)
	}
	for k, v := range want {
		if got[k] != v {
			t.Errorf("operating_system=%s = %v, want %v", k, got[k], v)
		}
	}
}

func TestCollectBucketsStaleness(t *testing.T) {
	g := &fakeGraph{bodies: fullFixtureBodies()}
	rec := telemetrytest.New()

	if err := newTestCollector(g).Collect(context.Background(), rec.Emitter()); err != nil {
		t.Fatalf("Collect: %v", err)
	}

	pts := rec.MetricPoints(stalenessMetricName)
	got := map[string]float64{}
	for _, p := range pts {
		got[p.Attrs["staleness_bucket"]] = p.Value
	}
	// daysAgo(0) -> under_1d, daysAgo(2) -> 1d_7d, daysAgo(10) -> 7d_30d, nil -> unknown.
	want := map[string]float64{"under_1d": 1, "1d_7d": 1, "7d_30d": 1, "unknown": 1}
	if len(got) != len(want) {
		t.Fatalf("got %d staleness buckets, want %d: %v", len(got), len(want), got)
	}
	for k, v := range want {
		if got[k] != v {
			t.Errorf("staleness_bucket=%s = %v, want %v", k, got[k], v)
		}
	}
}

// TestCollectEmitsOsVersionCounts pins #124's new standalone
// intune.devices.os_version.count gauge: one point per distinct
// (operating_system, os_version) pair, counted client-side over the same
// fleet fetch the other gauges already page. A device reporting no osVersion
// at all must bucket to os_version="unknown" rather than an empty-string
// label or being dropped.
func TestCollectEmitsOsVersionCounts(t *testing.T) {
	g := &fakeGraph{bodies: map[string]string{
		overviewURL(): overviewFixture,
		fleetURL(): devicesPage(
			deviceWithVersion("compliant", "Windows 10", "10.0.19045.1", true, daysAgo(0)),
			deviceWithVersion("compliant", "Windows 10", "10.0.19045.1", true, daysAgo(1)),
			deviceWithVersion("compliant", "Windows 10", "10.0.22631.1", true, daysAgo(0)),
			deviceWithVersion("compliant", "iOS", "17.4.1", true, daysAgo(0)),
			deviceWithVersion("unknown", "macOS", "", true, daysAgo(0)),
		),
	}}
	rec := telemetrytest.New()

	if err := newTestCollector(g).Collect(context.Background(), rec.Emitter()); err != nil {
		t.Fatalf("Collect: %v", err)
	}

	pts := rec.MetricPoints(osVersionCountMetricName)
	got := map[string]float64{}
	for _, p := range pts {
		got[p.Attrs["operating_system"]+"/"+p.Attrs["os_version"]] = p.Value
	}
	want := map[string]float64{
		"windows/10.0.19045.1": 2,
		"windows/10.0.22631.1": 1,
		"ios/17.4.1":           1,
		"macos/unknown":        1,
	}
	if len(got) != len(want) {
		t.Fatalf("got %d os_version series, want %d: %v", len(got), len(want), got)
	}
	for k, v := range want {
		if got[k] != v {
			t.Errorf("%s = %v, want %v", k, got[k], v)
		}
	}
}

// TestCollectCountMetricAttrKeysUnchanged pins that the pre-existing
// intune.devices.count gauge stays byte-identical in its attribute keys -
// the new os_version dimension must NOT be folded into it (that would
// silently multi-count a naive sum() over the metric, same rationale as the
// package doc's per-metric-name-per-dimension rule).
func TestCollectCountMetricAttrKeysUnchanged(t *testing.T) {
	g := &fakeGraph{bodies: fullFixtureBodies()}
	rec := telemetrytest.New()

	if err := newTestCollector(g).Collect(context.Background(), rec.Emitter()); err != nil {
		t.Fatalf("Collect: %v", err)
	}

	pts := rec.MetricPoints(countMetricName)
	if len(pts) == 0 {
		t.Fatal("expected count metric points, got none")
	}
	wantKeys := map[string]bool{"compliance_state": true, "operating_system": true}
	for _, p := range pts {
		if len(p.Attrs) != len(wantKeys) {
			t.Fatalf("intune.devices.count attrs = %v, want exactly %v", p.Attrs, wantKeys)
		}
		for k := range p.Attrs {
			if !wantKeys[k] {
				t.Errorf("intune.devices.count has unexpected attribute %q (want only compliance_state/operating_system)", k)
			}
		}
	}
}

// TestLogTwinCarriesOsVersion pins that every intune.managed_device log
// twin carries os_version - the raw osVersion string, or "unknown" when the
// device reported none.
func TestLogTwinCarriesOsVersion(t *testing.T) {
	g := &fakeGraph{bodies: map[string]string{
		overviewURL(): overviewFixture,
		fleetURL(): devicesPage(
			deviceWithVersion("compliant", "Windows 10", "10.0.19045.1", true, daysAgo(0)),
			deviceWithVersion("unknown", "macOS", "", true, daysAgo(0)),
		),
	}}
	rec := telemetrytest.New()

	if err := newTestCollector(g).Collect(context.Background(), rec.Emitter()); err != nil {
		t.Fatalf("Collect: %v", err)
	}

	logs := rec.LogRecords()
	if len(logs) != 2 {
		t.Fatalf("got %d log records, want 2", len(logs))
	}
	gotVersions := map[string]bool{}
	for _, l := range logs {
		v, ok := l.Attrs["os_version"]
		if !ok {
			t.Fatalf("log twin missing os_version attribute entirely: %+v", l.Attrs)
		}
		gotVersions[v] = true
	}
	want := map[string]bool{"10.0.19045.1": true, "unknown": true}
	if len(gotVersions) != len(want) {
		t.Fatalf("os_version values across twins = %v, want %v", gotVersions, want)
	}
	for k := range want {
		if !gotVersions[k] {
			t.Errorf("missing expected os_version value %q across twins: %v", k, gotVersions)
		}
	}
}

// TestNewWiresFleetFetcherWithOsVersionSelect pins the #124 acceptance
// criterion that the fleet-wide $select was widened to request osVersion -
// the new os_version.count gauge and the log twin's os_version attribute
// both ride on this same field, with no additional Graph request.
func TestNewWiresFleetFetcherWithOsVersionSelect(t *testing.T) {
	c := New(&fakeGraph{}, nil)
	df, ok := c.fleet.(*collectors.DirectFleetFetcher)
	if !ok {
		t.Fatalf("fleet fetcher = %T, want *collectors.DirectFleetFetcher", c.fleet)
	}
	if !strings.Contains(df.URL, "osVersion") {
		t.Errorf("fleet fetcher URL = %q, missing field %q required for the os_version.count gauge and log twin", df.URL, "osVersion")
	}
}

// TestCollectPagesFleetToExhaustion pins the acceptance criterion that
// pagination is followed across multiple @odata.nextLink pages.
func TestCollectPagesFleetToExhaustion(t *testing.T) {
	page2URL := base + "/deviceManagement/managedDevices?$skiptoken=abc"
	page1 := `{"value":[` +
		`{"complianceState":"compliant","operatingSystem":"Windows","isEncrypted":true,"lastSyncDateTime":"2026-07-15T12:00:00Z"}` +
		`],"@odata.nextLink":"` + page2URL + `"}`
	page2 := `{"value":[` +
		`{"complianceState":"compliant","operatingSystem":"Windows","isEncrypted":true,"lastSyncDateTime":"2026-07-15T12:00:00Z"}` +
		`]}`

	g := &fakeGraph{bodies: map[string]string{
		overviewURL(): overviewFixture,
		fleetURL():    page1,
		page2URL:      page2,
	}}
	rec := telemetrytest.New()

	if err := newTestCollector(g).Collect(context.Background(), rec.Emitter()); err != nil {
		t.Fatalf("Collect: %v", err)
	}

	pts := rec.MetricPoints(countMetricName)
	var total float64
	for _, p := range pts {
		total += p.Value
	}
	if total != 2 {
		t.Errorf("total fleet count across pages = %v, want 2 (one device from each page)", total)
	}
}

// TestCollectSkipsHardwareInformationSweepByDefault pins the acceptance
// criterion that the beta hardwareInformation per-device sweep issues zero
// per-device GETs: this collector doesn't implement it at all (deferred, see
// package doc), so a fake Graph client mapping ONLY the overview + fleet-list
// URLs must never see an unmapped per-device request.
func TestCollectSkipsHardwareInformationSweepByDefault(t *testing.T) {
	g := &fakeGraph{bodies: fullFixtureBodies()}
	rec := telemetrytest.New()

	if err := newTestCollector(g).Collect(context.Background(), rec.Emitter()); err != nil {
		t.Fatalf("Collect: %v", err)
	}
	// fullFixtureBodies maps exactly the overview singleton and the one-page
	// fleet list; any per-device GET (e.g. .../managedDevices/{id}) would hit
	// fakeGraph's "unmapped url" error path and fail Collect above.
}

func TestCollectIsResilientToOverviewFailure(t *testing.T) {
	bodies := fullFixtureBodies()
	g := &fakeGraph{
		bodies: bodies,
		errs:   map[string]error{overviewURL(): errors.New("throttled")},
	}
	rec := telemetrytest.New()

	err := newTestCollector(g).Collect(context.Background(), rec.Emitter())
	if err == nil {
		t.Fatal("expected Collect to surface the overview failure as an error")
	}
	if len(rec.MetricPoints(overviewEnrolledMetricName)) != 0 {
		t.Error("overview gauges should be absent when the overview fetch failed")
	}
	// The fleet-derived metrics must still emit despite the overview failure.
	if len(rec.MetricPoints(countMetricName)) == 0 {
		t.Error("count series should still emit despite the overview failure")
	}
}

func TestCollectIsResilientToFleetFailure(t *testing.T) {
	bodies := fullFixtureBodies()
	g := &fakeGraph{
		bodies: bodies,
		errs:   map[string]error{fleetURL(): errors.New("throttled")},
	}
	rec := telemetrytest.New()

	err := newTestCollector(g).Collect(context.Background(), rec.Emitter())
	if err == nil {
		t.Fatal("expected Collect to surface the fleet-list failure as an error")
	}
	if len(rec.MetricPoints(countMetricName)) != 0 {
		t.Error("count series should be absent when the fleet list fetch failed")
	}
	// The overview-derived metrics must still emit despite the fleet failure.
	if len(rec.MetricPoints(overviewEnrolledMetricName)) == 0 {
		t.Error("overview series should still emit despite the fleet-list failure")
	}
}

func TestNoPerDeviceAttributes(t *testing.T) {
	g := &fakeGraph{bodies: fullFixtureBodies()}
	rec := telemetrytest.New()

	if err := newTestCollector(g).Collect(context.Background(), rec.Emitter()); err != nil {
		t.Fatalf("Collect: %v", err)
	}

	for _, metric := range []string{countMetricName, encryptedMetricName, stalenessMetricName, overviewOSMetricName} {
		for _, p := range rec.MetricPoints(metric) {
			for k := range p.Attrs {
				switch k {
				case "id", "deviceId", "device_id", "serialNumber", "serial_number", "imei", "deviceName", "device_name", "userPrincipalName", "user_principal_name":
					t.Errorf("metric %s has a per-device attribute %q - cardinality violation", metric, k)
				}
			}
		}
	}
}

// TestNewWiresFleetFetcherWithWidenedSelect pins the #114 acceptance
// criterion that the fleet-wide $select actually requests the identity
// fields the log twin needs, on the real request URL New() wires up - so a
// future trim of managedDevicesSelect can't silently break the twin.
func TestNewWiresFleetFetcherWithWidenedSelect(t *testing.T) {
	c := New(&fakeGraph{}, nil)
	df, ok := c.fleet.(*collectors.DirectFleetFetcher)
	if !ok {
		t.Fatalf("fleet fetcher = %T, want *collectors.DirectFleetFetcher", c.fleet)
	}
	for _, field := range []string{"id", "deviceName", "serialNumber", "userPrincipalName", "complianceState", "operatingSystem", "isEncrypted", "lastSyncDateTime", "model", "manufacturer", "wiFiMacAddress", "partnerReportedThreatState", "complianceGracePeriodExpirationDateTime"} {
		if !strings.Contains(df.URL, field) {
			t.Errorf("fleet fetcher URL = %q, missing field %q required for the intune.managed_device log twin", df.URL, field)
		}
	}
}

// TestCollectEmitsOneLogTwinPerDevice pins the #114 maintainer decision to
// twin EVERY device row per cycle, not just non-compliant ones - the log
// pipeline is the surviving per-entity record.
func TestCollectEmitsOneLogTwinPerDevice(t *testing.T) {
	g := &fakeGraph{bodies: fullFixtureBodies()}
	rec := telemetrytest.New()

	if err := newTestCollector(g).Collect(context.Background(), rec.Emitter()); err != nil {
		t.Fatalf("Collect: %v", err)
	}

	logs := rec.LogRecords()
	if len(logs) != 4 {
		t.Fatalf("got %d log records, want 4 (one per device in the fixture)", len(logs))
	}
	for _, l := range logs {
		if l.EventName != eventManagedDevice {
			t.Errorf("EventName = %q, want %q", l.EventName, eventManagedDevice)
		}
	}
}

// TestLogTwinCarriesDeviceIdentityAndState asserts the per-device log record
// carries the identity fields the fleet-wide $select deliberately withheld
// from every metric, alongside the raw (unbucketed) state fields.
//
// It drives ONE real device (MBP16) from the pinned live capture, not an
// invented dev-1/LAPTOP-A/SN123/alice@example.com record - the real values are
// the point (#165): a compliant, encrypted, freshly-synced macOS device is a
// shape that actually exists on this fleet, and its identity fields are the
// real ones the SIEM twin must carry.
func TestLogTwinCarriesDeviceIdentityAndState(t *testing.T) {
	g := &fakeGraph{bodies: map[string]string{
		overviewURL(): overviewFixture,
		fleetURL():    devicesPage(liveDevice(t, "MBP16")),
	}}
	rec := telemetrytest.New()

	c := New(g, nil)
	c.now = func() time.Time { return liveNow }
	if err := c.Collect(context.Background(), rec.Emitter()); err != nil {
		t.Fatalf("Collect: %v", err)
	}

	logs := rec.LogRecords()
	if len(logs) != 1 {
		t.Fatalf("got %d log records, want 1", len(logs))
	}
	l := logs[0]
	want := map[string]string{
		"id":                            "57d346d7-ddf1-489b-b70d-a30dce1e2458",
		"device_name":                   "MBP16",
		"serial_number":                 "YJY0H9JDGP",
		"user_principal_name":           "rob@m7kni.io",
		"compliance_state":              "compliant",
		"operating_system":              "macOS",
		"is_encrypted":                  "true",
		"staleness_bucket":              "under_1d",
		"last_sync_date_time":           "2026-07-17T15:06:48Z",
		"model":                         "MacBook Pro",
		"manufacturer":                  "Apple",
		"wifi_mac_address":              "f4d488683c84",
		"partner_reported_threat_state": "unknown",
	}
	for k, v := range want {
		if l.Attrs[k] != v {
			t.Errorf("attr %s = %q, want %q (all attrs: %+v)", k, l.Attrs[k], v, l.Attrs)
		}
	}
	if l.SeverityText != telemetry.SeverityInfo.String() {
		t.Errorf("severity = %s, want %s for a compliant, encrypted, freshly-synced device", l.SeverityText, telemetry.SeverityInfo)
	}
}

// TestCollectEmitsLiveFleetEndToEnd drives the whole pinned live capture (5 real
// m7kni devices, #165) through Collect into a Recorder, rather than asserting on
// a single record. It is the reference "richest live fixture end-to-end" shape
// #164/#165 ask for: both the bounded gauges (counts by compliance/OS,
// encryption, sync-staleness) AND the per-device log twins are checked against
// the real fleet's values.
//
// The real fleet is what makes this worth pinning: it spans three compliance
// states and four operating systems (including a Linux device the
// managedDeviceOverview OS summary has no bucket for - that summary undercounts
// the fleet by exactly this device, which is docs/graph-api-gotchas.md's "sums
// to 9 on a fleet of 10" note), and two devices carry neither serial nor UPN.
func TestCollectEmitsLiveFleetEndToEnd(t *testing.T) {
	g := &fakeGraph{bodies: map[string]string{
		overviewURL(): overviewFixture,
		fleetURL():    liveFleetBody(),
	}}
	rec := telemetrytest.New()

	c := New(g, nil)
	c.now = func() time.Time { return liveNow }
	if err := c.Collect(context.Background(), rec.Emitter()); err != nil {
		t.Fatalf("Collect: %v", err)
	}

	// Bounded count gauge: one series per (compliance_state, operating_system)
	// pair the real fleet actually contains - Linux included.
	gotCount := map[string]float64{}
	for _, p := range rec.MetricPoints(countMetricName) {
		gotCount[p.Attrs["compliance_state"]+"/"+p.Attrs["operating_system"]] = p.Value
	}
	wantCount := map[string]float64{
		"noncompliant/windows": 1, // LAPHAM
		"unknown/linux":        1, // oli
		"unknown/windows":      1, // WINSRV
		"compliant/ios":        1, // TampooniPad
		"compliant/macos":      1, // MBP16
	}
	if len(gotCount) != len(wantCount) {
		t.Fatalf("count series = %v, want %v", gotCount, wantCount)
	}
	for k, v := range wantCount {
		if gotCount[k] != v {
			t.Errorf("count[%s] = %v, want %v", k, gotCount[k], v)
		}
	}

	// Encrypted-by-OS: only the three encrypted devices contribute; the
	// unencrypted Linux (oli) and Windows (WINSRV) devices contribute nothing.
	gotEnc := map[string]float64{}
	for _, p := range rec.MetricPoints(encryptedMetricName) {
		gotEnc[p.Attrs["operating_system"]] = p.Value
	}
	wantEnc := map[string]float64{"windows": 1, "ios": 1, "macos": 1}
	if len(gotEnc) != len(wantEnc) {
		t.Fatalf("encrypted series = %v, want %v", gotEnc, wantEnc)
	}
	for k, v := range wantEnc {
		if gotEnc[k] != v {
			t.Errorf("encrypted[%s] = %v, want %v", k, gotEnc[k], v)
		}
	}

	// Sync-staleness buckets against liveNow: 3 fresh, LAPHAM ~24.8h old, oli
	// ~55d old.
	gotStale := map[string]float64{}
	for _, p := range rec.MetricPoints(stalenessMetricName) {
		gotStale[p.Attrs["staleness_bucket"]] = p.Value
	}
	wantStale := map[string]float64{"under_1d": 3, "1d_7d": 1, "over_30d": 1}
	if len(gotStale) != len(wantStale) {
		t.Fatalf("staleness buckets = %v, want %v", gotStale, wantStale)
	}
	for k, v := range wantStale {
		if gotStale[k] != v {
			t.Errorf("staleness[%s] = %v, want %v", k, gotStale[k], v)
		}
	}

	// One log twin per real device, keyed by the real id.
	logs := rec.LogRecords()
	if len(logs) != 5 {
		t.Fatalf("got %d log records, want 5 (one per live device)", len(logs))
	}
	byID := map[string]telemetrytest.LogRecord{}
	for _, l := range logs {
		if l.EventName != eventManagedDevice {
			t.Errorf("EventName = %q, want %q", l.EventName, eventManagedDevice)
		}
		byID[l.Attrs["id"]] = l
	}

	type want struct {
		name, serial, upn, compliance, os, encrypted, stale, severity string
		model, manufacturer, wifiMac                                  string
	}
	wants := map[string]want{
		"d5900d67-e50c-44ef-9d5c-6a2f891099c6": {"LAPHAM", "PH4TRX1S2146S0097", "rob@m7kni.io", "noncompliant", "Windows", "true", "1d_7d", telemetry.SeverityWarn.String(), "Standard", "PCSpecialist", "701AB8C7BE06"},
		"e4639a7f-4d77-d901-1e78-57646ca78cb8": {"oli", "", "", "unknown", "Linux", "false", "over_30d", telemetry.SeverityWarn.String(), "Z690 UD DDR4", "Gigabyte Technology Co., Ltd.", ""},
		"f780403a-4ccd-e3ef-ac17-9f1c61c00244": {"WINSRV", "", "", "unknown", "Windows", "false", "under_1d", telemetry.SeverityWarn.String(), "Standard PC (Q35 + ICH9, 2009)", "QEMU", ""},
		"2af9ec65-db9b-455c-8b3a-7a2691958b88": {"TampooniPad", "NP412Q6YQ0", "rob@m7kni.io", "compliant", "iOS", "true", "under_1d", telemetry.SeverityInfo.String(), "iPad Pro (12.9\")(5th generation)", "Apple", "88665af33c71"},
		"57d346d7-ddf1-489b-b70d-a30dce1e2458": {"MBP16", "YJY0H9JDGP", "rob@m7kni.io", "compliant", "macOS", "true", "under_1d", telemetry.SeverityInfo.String(), "MacBook Pro", "Apple", "f4d488683c84"},
	}
	for id, w := range wants {
		l, ok := byID[id]
		if !ok {
			t.Errorf("no log twin for device id %s (%s)", id, w.name)
			continue
		}
		if l.Attrs["device_name"] != w.name {
			t.Errorf("%s device_name = %q, want %q", id, l.Attrs["device_name"], w.name)
		}
		if l.Attrs["compliance_state"] != w.compliance {
			t.Errorf("%s compliance_state = %q, want %q", id, l.Attrs["compliance_state"], w.compliance)
		}
		if l.Attrs["operating_system"] != w.os {
			t.Errorf("%s operating_system = %q, want %q", id, l.Attrs["operating_system"], w.os)
		}
		if l.Attrs["is_encrypted"] != w.encrypted {
			t.Errorf("%s is_encrypted = %q, want %q", id, l.Attrs["is_encrypted"], w.encrypted)
		}
		if l.Attrs["staleness_bucket"] != w.stale {
			t.Errorf("%s staleness_bucket = %q, want %q", id, l.Attrs["staleness_bucket"], w.stale)
		}
		if l.SeverityText != w.severity {
			t.Errorf("%s severity = %q, want %q", id, l.SeverityText, w.severity)
		}
		// setStr must OMIT an empty serial/UPN entirely, never emit "" - the
		// real property of oli/WINSRV a docs fixture would never surface.
		if w.serial == "" {
			if _, present := l.Attrs["serial_number"]; present {
				t.Errorf("%s (%s) emitted serial_number %q, want the attribute omitted (empty on the wire)", id, w.name, l.Attrs["serial_number"])
			}
		} else if l.Attrs["serial_number"] != w.serial {
			t.Errorf("%s serial_number = %q, want %q", id, l.Attrs["serial_number"], w.serial)
		}
		if w.upn == "" {
			if _, present := l.Attrs["user_principal_name"]; present {
				t.Errorf("%s (%s) emitted user_principal_name %q, want the attribute omitted (empty on the wire)", id, w.name, l.Attrs["user_principal_name"])
			}
		} else if l.Attrs["user_principal_name"] != w.upn {
			t.Errorf("%s user_principal_name = %q, want %q", id, l.Attrs["user_principal_name"], w.upn)
		}
		// #180 hardware/threat fields: model + manufacturer are populated on
		// every live device; wiFiMacAddress is empty on oli/WINSRV (no wifi) and
		// must be OMITTED, never emitted as ""; threat state is "unknown"
		// fleet-wide (no active MTD connector) and always present.
		if l.Attrs["model"] != w.model {
			t.Errorf("%s model = %q, want %q", id, l.Attrs["model"], w.model)
		}
		if l.Attrs["manufacturer"] != w.manufacturer {
			t.Errorf("%s manufacturer = %q, want %q", id, l.Attrs["manufacturer"], w.manufacturer)
		}
		if w.wifiMac == "" {
			if _, present := l.Attrs["wifi_mac_address"]; present {
				t.Errorf("%s (%s) emitted wifi_mac_address %q, want the attribute omitted (empty on the wire)", id, w.name, l.Attrs["wifi_mac_address"])
			}
		} else if l.Attrs["wifi_mac_address"] != w.wifiMac {
			t.Errorf("%s wifi_mac_address = %q, want %q", id, l.Attrs["wifi_mac_address"], w.wifiMac)
		}
		if l.Attrs["partner_reported_threat_state"] != "unknown" {
			t.Errorf("%s partner_reported_threat_state = %q, want %q", id, l.Attrs["partner_reported_threat_state"], "unknown")
		}
	}
}

// TestLogTwinSeverityEscalatesForNoncompliantUnencryptedOrStale pins the
// three independent Warn triggers: non-compliant, unencrypted, or
// sync-stale beyond 30 days.
func TestLogTwinSeverityEscalatesForNoncompliantUnencryptedOrStale(t *testing.T) {
	cases := []struct {
		name       string
		compliance string
		encrypted  bool
		lastSync   *time.Time
	}{
		{"noncompliant", "noncompliant", true, daysAgo(0)},
		{"unencrypted", "compliant", false, daysAgo(0)},
		{"stale", "compliant", true, daysAgo(45)},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			g := &fakeGraph{bodies: map[string]string{
				overviewURL(): overviewFixture,
				fleetURL():    devicesPage(device(tc.compliance, "Windows 10", tc.encrypted, tc.lastSync)),
			}}
			rec := telemetrytest.New()

			if err := newTestCollector(g).Collect(context.Background(), rec.Emitter()); err != nil {
				t.Fatalf("Collect: %v", err)
			}

			logs := rec.LogRecords()
			if len(logs) != 1 {
				t.Fatalf("got %d log records, want 1", len(logs))
			}
			if logs[0].SeverityText != telemetry.SeverityWarn.String() {
				t.Errorf("severity = %s, want %s for case %q", logs[0].SeverityText, telemetry.SeverityWarn, tc.name)
			}
		})
	}
}

// TestLogTwinSeverityIsInfoForHealthyCompliantEncryptedFreshDevice guards
// against over-eager escalation: a device satisfying none of the three Warn
// triggers must stay Info.
func TestLogTwinSeverityIsInfoForHealthyCompliantEncryptedFreshDevice(t *testing.T) {
	g := &fakeGraph{bodies: map[string]string{
		overviewURL(): overviewFixture,
		fleetURL():    devicesPage(device("compliant", "macOS", true, daysAgo(1))),
	}}
	rec := telemetrytest.New()

	if err := newTestCollector(g).Collect(context.Background(), rec.Emitter()); err != nil {
		t.Fatalf("Collect: %v", err)
	}
	logs := rec.LogRecords()
	if len(logs) != 1 {
		t.Fatalf("got %d log records, want 1", len(logs))
	}
	if logs[0].SeverityText != telemetry.SeverityInfo.String() {
		t.Errorf("severity = %s, want %s", logs[0].SeverityText, telemetry.SeverityInfo)
	}
}

func TestNameIntervalAndPermissions(t *testing.T) {
	c := New(&fakeGraph{}, nil)
	if c.Name() != "intune.devices" {
		t.Errorf("Name = %q, want intune.devices", c.Name())
	}
	if c.DefaultInterval() <= 0 {
		t.Errorf("DefaultInterval = %v, want positive", c.DefaultInterval())
	}
	perms := c.RequiredPermissions()
	if len(perms) != 1 || perms[0] != "DeviceManagementManagedDevices.Read.All" {
		t.Errorf("RequiredPermissions = %v, want [DeviceManagementManagedDevices.Read.All]", perms)
	}
}

// TestLogTwinGraceExpiryFiltersSentinels pins the #193 sentinel handling: a real
// grace deadline is emitted, but Microsoft's two "no active deadline" sentinels
// (max-date 9999-12-31 for compliant devices, zero-date 0001-01-01 for
// unknown-state ones) and a nil are omitted rather than emitted as a misleading
// far-future or zero timestamp (live-measured 2026-07-19).
func TestLogTwinGraceExpiryFiltersSentinels(t *testing.T) {
	real := time.Date(2026, 7, 19, 21, 4, 22, 0, time.UTC)
	sentinelMax := time.Date(9999, 12, 31, 23, 59, 59, 0, time.UTC)
	sentinelZero := time.Time{}
	cases := []struct {
		name string
		in   *time.Time
		want string
	}{
		{"real deadline emits", &real, real.Format(time.RFC3339)},
		{"9999 max-date sentinel omitted", &sentinelMax, ""},
		{"0001 zero-date sentinel omitted", &sentinelZero, ""},
		{"nil omitted", nil, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			d := managedDevice{ID: "x", ComplianceGracePeriodExpiration: tc.in}
			ev := deviceLogTwin(d, "compliant", "fresh")
			got, _ := ev.Attrs[semconv.AttrComplianceGracePeriodExpiration].(string)
			if got != tc.want {
				t.Errorf("grace attr = %q, want %q", got, tc.want)
			}
		})
	}
}
