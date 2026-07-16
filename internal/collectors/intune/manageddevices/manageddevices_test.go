package manageddevices

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/rknightion/graph2otel/internal/collectors"
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

// deviceWithIdentity is device() plus the log-twin-only identity fields
// (id, deviceName, serialNumber, userPrincipalName) - #114.
func deviceWithIdentity(compliance, os string, encrypted bool, lastSync *time.Time, id, name, serial, upn string) map[string]any {
	d := device(compliance, os, encrypted, lastSync)
	d["id"] = id
	d["deviceName"] = name
	d["serialNumber"] = serial
	d["userPrincipalName"] = upn
	return d
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
	for _, field := range []string{"id", "deviceName", "serialNumber", "userPrincipalName", "complianceState", "operatingSystem", "isEncrypted", "lastSyncDateTime"} {
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
func TestLogTwinCarriesDeviceIdentityAndState(t *testing.T) {
	g := &fakeGraph{bodies: map[string]string{
		overviewURL(): overviewFixture,
		fleetURL():    devicesPage(deviceWithIdentity("compliant", "Windows 10", true, daysAgo(0), "dev-1", "LAPTOP-A", "SN123", "alice@example.com")),
	}}
	rec := telemetrytest.New()

	if err := newTestCollector(g).Collect(context.Background(), rec.Emitter()); err != nil {
		t.Fatalf("Collect: %v", err)
	}

	logs := rec.LogRecords()
	if len(logs) != 1 {
		t.Fatalf("got %d log records, want 1", len(logs))
	}
	l := logs[0]
	want := map[string]string{
		"id":                  "dev-1",
		"device_name":         "LAPTOP-A",
		"serial_number":       "SN123",
		"user_principal_name": "alice@example.com",
		"compliance_state":    "compliant",
		"operating_system":    "Windows 10",
		"is_encrypted":        "true",
		"staleness_bucket":    "under_1d",
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
