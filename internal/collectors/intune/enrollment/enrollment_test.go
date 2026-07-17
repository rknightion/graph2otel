package enrollment

import (
	"context"
	"errors"
	"testing"

	"github.com/rknightion/graph2otel/internal/collectors"
	"github.com/rknightion/graph2otel/internal/telemetrytest"
)

// fakeGraph maps request URLs to canned page bodies (or errors). Every
// fixture here is a single page; GetAllValues follows @odata.nextLink but
// none of these tests exercise pagination.
type fakeGraph struct {
	bodies map[string]string
	errs   map[string]error
}

func (f *fakeGraph) RawGet(ctx context.Context, url string) ([]byte, error) {
	return f.RawGetWithHeaders(ctx, url, nil)
}

func (f *fakeGraph) RawGetWithHeaders(_ context.Context, url string, _ map[string]string) ([]byte, error) {
	if err, ok := f.errs[url]; ok {
		return nil, err
	}
	return []byte(f.bodies[url]), nil
}

var _ collectors.GraphClient = (*fakeGraph)(nil)

const (
	base           = "https://graph.microsoft.com/v1.0"
	enrollmentsURL = base + "/deviceManagement/deviceEnrollmentConfigurations"
)

func page(itemsJSON string) string {
	return `{"value":[` + itemsJSON + `]}`
}

// sampleConfigs is the VERBATIM value array of
// GET /deviceManagement/deviceEnrollmentConfigurations read as graph2otel-poller
// against the m7kni tenant `[live-measured 2026-07-17, #165]`. The full subtype
// objects are pinned as Graph returned them — including the per-subtype nested
// fields the collector deliberately ignores (androidRestriction, pin* settings,
// limit, ...) — so the wire shape stays honest rather than docs-derived.
//
// It preserves the heterogeneous @odata.type variety Collect buckets on: four
// distinct subtypes (limit, platform_restrictions, windows_hello_for_business,
// esp) plus, load-bearingly, a fifth entry (the default WindowsRestore config)
// that carries NO @odata.type at all — the live proof that configType must
// bucket a MISSING type to "other", not only an unknown non-empty one. The
// tenant exposes only the default configurations, so every entry shares the
// displayName "All users and all devices" and priority/version 0; that is the
// real tenant state, not a fixture simplification. The unknown-non-empty-type
// path someFutureConfigurationType used to cover is retained directly in
// TestConfigTypeBucketsMissingAndUnknownToOther.
const sampleConfigs = `
{
  "@odata.type": "#microsoft.graph.deviceEnrollmentLimitConfiguration",
  "createdDateTime": "0001-01-01T00:00:00Z",
  "description": "This is the default Device Limit Restriction applied with the lowest priority to all users regardless of group membership.",
  "displayName": "All users and all devices",
  "id": "e933bb26-3dff-49f0-a41a-bd722a92f1fb_DefaultLimit",
  "lastModifiedDateTime": "2026-01-17T10:42:02Z",
  "limit": 15,
  "priority": 0,
  "version": 0
},
{
  "@odata.type": "#microsoft.graph.deviceEnrollmentPlatformRestrictionsConfiguration",
  "androidRestriction": {
    "osMaximumVersion": "",
    "osMinimumVersion": "",
    "personalDeviceEnrollmentBlocked": false,
    "platformBlocked": false
  },
  "createdDateTime": "0001-01-01T00:00:00Z",
  "description": "This is the default Device Type Restriction applied with the lowest priority to all users regardless of group membership.",
  "displayName": "All users and all devices",
  "id": "e933bb26-3dff-49f0-a41a-bd722a92f1fb_DefaultPlatformRestrictions",
  "iosRestriction": {
    "osMaximumVersion": "",
    "osMinimumVersion": "",
    "personalDeviceEnrollmentBlocked": false,
    "platformBlocked": false
  },
  "lastModifiedDateTime": "2026-01-17T10:42:02Z",
  "macOSRestriction": {
    "osMaximumVersion": null,
    "osMinimumVersion": null,
    "personalDeviceEnrollmentBlocked": false,
    "platformBlocked": false
  },
  "priority": 0,
  "version": 0,
  "windowsMobileRestriction": {
    "osMaximumVersion": "",
    "osMinimumVersion": "",
    "personalDeviceEnrollmentBlocked": false,
    "platformBlocked": true
  },
  "windowsRestriction": {
    "osMaximumVersion": "",
    "osMinimumVersion": "",
    "personalDeviceEnrollmentBlocked": false,
    "platformBlocked": false
  }
},
{
  "@odata.type": "#microsoft.graph.deviceEnrollmentWindowsHelloForBusinessConfiguration",
  "createdDateTime": "0001-01-01T00:00:00Z",
  "description": "This is the default Windows Hello for Business configuration applied with the lowest priority to all users regardless of group membership.",
  "displayName": "All users and all devices",
  "enhancedBiometricsState": "enabled",
  "id": "e933bb26-3dff-49f0-a41a-bd722a92f1fb_DefaultWindowsHelloForBusiness",
  "lastModifiedDateTime": "2026-01-17T10:42:02Z",
  "pinExpirationInDays": 0,
  "pinLowercaseCharactersUsage": "allowed",
  "pinMaximumLength": 127,
  "pinMinimumLength": 6,
  "pinPreviousBlockCount": 0,
  "pinSpecialCharactersUsage": "allowed",
  "pinUppercaseCharactersUsage": "allowed",
  "priority": 0,
  "remotePassportEnabled": true,
  "securityDeviceRequired": false,
  "state": "enabled",
  "unlockWithBiometricsEnabled": true,
  "version": 0
},
{
  "@odata.type": "#microsoft.graph.windows10EnrollmentCompletionPageConfiguration",
  "allowNonBlockingAppInstallation": false,
  "createdDateTime": "0001-01-01T00:00:00Z",
  "description": "This is the default enrollment status screen configuration applied with the lowest priority to all users and all devices regardless of group membership.",
  "displayName": "All users and all devices",
  "id": "e933bb26-3dff-49f0-a41a-bd722a92f1fb_DefaultWindows10EnrollmentCompletionPageConfiguration",
  "lastModifiedDateTime": "2026-01-17T10:42:02Z",
  "priority": 0,
  "version": 0
},
{
  "createdDateTime": "0001-01-01T00:00:00Z",
  "description": "This is the default Windows Restore configuration applied with the lowest priority to all users and all devices regardless of group membership.",
  "displayName": "All users and all devices",
  "id": "e933bb26-3dff-49f0-a41a-bd722a92f1fb_WindowsRestore",
  "lastModifiedDateTime": "2026-01-17T10:42:02Z",
  "priority": 0,
  "version": 0
}
`

func fixture() map[string]string {
	return map[string]string{enrollmentsURL: page(sampleConfigs)}
}

func TestCollectEmitsCountByConfigType(t *testing.T) {
	g := &fakeGraph{bodies: fixture()}
	rec := telemetrytest.New()

	if err := New(g, nil).Collect(context.Background(), rec.Emitter()); err != nil {
		t.Fatalf("Collect: %v", err)
	}

	got := map[string]float64{}
	for _, p := range rec.MetricPoints(countMetricName) {
		got[p.Attrs["config_type"]] = p.Value
	}
	// Live tenant exposes one instance of each default subtype; the fifth
	// (WindowsRestore) carries no @odata.type and buckets to "other".
	want := map[string]float64{
		"limit":                      1,
		"platform_restrictions":      1,
		"esp":                        1,
		"windows_hello_for_business": 1,
		"other":                      1,
	}
	if len(got) != len(want) {
		t.Fatalf("got %d config_type series, want %d: %v", len(got), len(want), got)
	}
	for typ, v := range want {
		if got[typ] != v {
			t.Errorf("config_type=%s count = %v, want %v", typ, got[typ], v)
		}
	}
}

func TestCollectEmitsPriorityByTypeAndName(t *testing.T) {
	g := &fakeGraph{bodies: fixture()}
	rec := telemetrytest.New()

	if err := New(g, nil).Collect(context.Background(), rec.Emitter()); err != nil {
		t.Fatalf("Collect: %v", err)
	}

	type key struct{ typ, name string }
	got := map[key]float64{}
	for _, p := range rec.MetricPoints(priorityMetricName) {
		got[key{p.Attrs["config_type"], p.Attrs["config_name"]}] = p.Value
	}
	// Every live default config shares the displayName "All users and all
	// devices" and priority 0, so the series are distinguished only by
	// config_type; five distinct config_type values yield five series.
	want := map[key]float64{
		{"limit", "All users and all devices"}:                      0,
		{"platform_restrictions", "All users and all devices"}:      0,
		{"esp", "All users and all devices"}:                        0,
		{"windows_hello_for_business", "All users and all devices"}: 0,
		{"other", "All users and all devices"}:                      0,
	}
	if len(got) != len(want) {
		t.Fatalf("got %d priority series, want %d: %v", len(got), len(want), got)
	}
	for k, v := range want {
		if got[k] != v {
			t.Errorf("priority[%+v] = %v, want %v", k, got[k], v)
		}
	}
}

func TestCollectEmitsVersionByConfigName(t *testing.T) {
	g := &fakeGraph{bodies: fixture()}
	rec := telemetrytest.New()

	if err := New(g, nil).Collect(context.Background(), rec.Emitter()); err != nil {
		t.Fatalf("Collect: %v", err)
	}

	got := map[string]float64{}
	for _, p := range rec.MetricPoints(versionMetricName) {
		got[p.Attrs["config_name"]] = p.Value
	}
	// The version metric is keyed by config_name ALONE, and every live default
	// config is named "All users and all devices", so all five collapse into a
	// single series (a genuine live aliasing limitation on this tenant, not a
	// fixture artifact). Every default's version is 0.
	want := map[string]float64{
		"All users and all devices": 0,
	}
	if len(got) != len(want) {
		t.Fatalf("got %d version series, want %d: %v", len(got), len(want), got)
	}
	for name, v := range want {
		if got[name] != v {
			t.Errorf("version[%s] = %v, want %v", name, got[name], v)
		}
	}
}

func TestCollectIsResilientToFetchError(t *testing.T) {
	g := &fakeGraph{errs: map[string]error{enrollmentsURL: errors.New("403 Forbidden: missing scope")}}
	rec := telemetrytest.New()

	if err := New(g, nil).Collect(context.Background(), rec.Emitter()); err == nil {
		t.Error("expected Collect to surface the fetch failure as an error")
	}

	for _, name := range []string{countMetricName, priorityMetricName, versionMetricName} {
		if pts := rec.MetricPoints(name); len(pts) != 0 {
			t.Errorf("metric %s: expected no points when the fetch failed, got %d", name, len(pts))
		}
	}
}

func TestCollectSkipsUnparseableEntryButEmitsTheRest(t *testing.T) {
	bodies := map[string]string{
		enrollmentsURL: page(`
			{"@odata.type":"#microsoft.graph.deviceEnrollmentLimitConfiguration","id":"e1","displayName":"All users","priority":0,"version":1},
			{"priority": "not-a-number"}
		`),
	}
	g := &fakeGraph{bodies: bodies}
	rec := telemetrytest.New()

	err := New(g, nil).Collect(context.Background(), rec.Emitter())
	if err == nil {
		t.Error("expected Collect to surface the decode failure as an error")
	}

	pts := rec.MetricPoints(countMetricName)
	var total float64
	for _, p := range pts {
		total += p.Value
	}
	if total != 1 {
		t.Errorf("total config count = %v, want 1 (unparseable entry excluded)", total)
	}
}

func TestNameAndPermissions(t *testing.T) {
	c := New(&fakeGraph{}, nil)
	if c.Name() != "intune.enrollment" {
		t.Errorf("Name = %q, want intune.enrollment", c.Name())
	}
	perms := c.RequiredPermissions()
	if len(perms) != 1 || perms[0] != "DeviceManagementServiceConfig.Read.All" {
		t.Errorf("RequiredPermissions = %v, want [DeviceManagementServiceConfig.Read.All]", perms)
	}
}

// TestConfigTypeBucketsMissingAndUnknownToOther pins both routes into the
// "other" bucket. The live fixture only exercises the missing-@odata.type route
// (its WindowsRestore entry has no @odata.type); this retains the
// unknown-non-empty-type route that the removed someFutureConfigurationType row
// used to cover, so a future Graph subtype degrades to "other" rather than
// failing or being dropped.
func TestConfigTypeBucketsMissingAndUnknownToOther(t *testing.T) {
	cases := map[string]string{
		"missing @odata.type":             "",
		"unknown future @odata.type":      "#microsoft.graph.someFutureConfigurationType",
		"known limit subtype":             "#microsoft.graph.deviceEnrollmentLimitConfiguration",
		"known comanagement subtype":      "#microsoft.graph.deviceComanagementAuthorityConfiguration",
		"known singular platform subtype": "#microsoft.graph.deviceEnrollmentPlatformRestrictionConfiguration",
	}
	want := map[string]string{
		"missing @odata.type":             "other",
		"unknown future @odata.type":      "other",
		"known limit subtype":             "limit",
		"known comanagement subtype":      "comanagement_authority",
		"known singular platform subtype": "platform_restriction",
	}
	for name, odataType := range cases {
		if got := configType(odataType); got != want[name] {
			t.Errorf("configType(%q) = %q, want %q", odataType, got, want[name])
		}
	}
}

// TestNoPerEntitySeries guards the cardinality rule: no metric may carry a
// per-device or per-user identifier as an attribute — only the bounded
// config_type/config_name dimensions (admin-configured object count, not
// tenant device/user count).
func TestNoPerEntitySeries(t *testing.T) {
	g := &fakeGraph{bodies: fixture()}
	rec := telemetrytest.New()

	if err := New(g, nil).Collect(context.Background(), rec.Emitter()); err != nil {
		t.Fatalf("Collect: %v", err)
	}

	allowed := map[string]map[string]bool{
		countMetricName:    {"config_type": true},
		priorityMetricName: {"config_type": true, "config_name": true},
		versionMetricName:  {"config_name": true},
	}
	for name, allowedAttrs := range allowed {
		for _, p := range rec.MetricPoints(name) {
			for k := range p.Attrs {
				if !allowedAttrs[k] {
					t.Errorf("%s series has unexpected attribute %q (possible per-entity leak): %v", name, k, p.Attrs)
				}
			}
		}
	}
}
