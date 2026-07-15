package mobileapps

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/rknightion/graph2otel/internal/collectors"
	"github.com/rknightion/graph2otel/internal/telemetrytest"
)

// fakeGraph maps request URLs to canned bodies (or errors). Every fixture
// here is a single page, since GetAllValues' @odata.nextLink following is
// exercised by internal/collectors' own tests, not re-tested per collector.
type fakeGraph struct {
	bodies    map[string]string
	errs      map[string]error
	requested []string
}

func (f *fakeGraph) RawGet(ctx context.Context, url string) ([]byte, error) {
	return f.RawGetWithHeaders(ctx, url, nil)
}

func (f *fakeGraph) RawGetWithHeaders(_ context.Context, url string, _ map[string]string) ([]byte, error) {
	f.requested = append(f.requested, url)
	if err, ok := f.errs[url]; ok {
		return nil, err
	}
	return []byte(f.bodies[url]), nil
}

var _ collectors.GraphClient = (*fakeGraph)(nil)

const (
	base             = "https://graph.microsoft.com/v1.0"
	mobileAppsURL    = base + "/deviceAppManagement/mobileApps"
	mobileConfigsURL = base + "/deviceAppManagement/mobileAppConfigurations"
)

func deviceStatusSummaryURL(id string) string {
	return base + "/deviceAppManagement/mobileAppConfigurations/" + id + "/deviceStatusSummary"
}

func page(itemsJSON string) string {
	return `{"value":[` + itemsJSON + `]}`
}

const threeApps = `
{"@odata.type":"#microsoft.graph.win32LobApp","id":"app1","displayName":"7-Zip","publishingState":"published"},
{"@odata.type":"#microsoft.graph.win32LobApp","id":"app2","displayName":"VLC","publishingState":"processing"},
{"@odata.type":"#microsoft.graph.iosStoreApp","id":"app3","displayName":"Outlook"}
`

const twoConfigs = `
{"id":"cfg1","displayName":"Outlook config"},
{"id":"cfg2","displayName":"VPN config"}
`

func fullFixture() map[string]string {
	return map[string]string{
		mobileAppsURL:                  page(threeApps),
		mobileConfigsURL:               page(twoConfigs),
		deviceStatusSummaryURL("cfg1"): `{"pendingCount":1,"notApplicableCount":2,"successCount":3,"errorCount":4,"failedCount":5}`,
		deviceStatusSummaryURL("cfg2"): `{"value":{"pendingCount":10,"notApplicableCount":0,"successCount":20,"errorCount":0,"failedCount":0}}`,
	}
}

func TestCollectEmitsMobileAppsCountByTypeAndState(t *testing.T) {
	g := &fakeGraph{bodies: fullFixture()}
	rec := telemetrytest.New()

	if err := New(g, nil).Collect(context.Background(), rec.Emitter()); err != nil {
		t.Fatalf("Collect: %v", err)
	}

	pts := rec.MetricPoints(appsMetricName)
	type key struct{ appType, state string }
	got := map[key]float64{}
	for _, p := range pts {
		got[key{p.Attrs["app_type"], p.Attrs["publishing_state"]}] = p.Value
	}
	want := map[key]float64{
		{"win32LobApp", "published"}:  1,
		{"win32LobApp", "processing"}: 1,
		{"iosStoreApp", "unknown"}:    1,
	}
	if len(got) != len(want) {
		t.Fatalf("got %d series, want %d: %v", len(got), len(want), got)
	}
	for k, v := range want {
		if got[k] != v {
			t.Errorf("series app_type=%s publishing_state=%s = %v, want %v", k.appType, k.state, got[k], v)
		}
	}
}

func TestCollectEmitsConfigStatusFromDeviceStatusSummary(t *testing.T) {
	g := &fakeGraph{bodies: fullFixture()}
	rec := telemetrytest.New()

	if err := New(g, nil).Collect(context.Background(), rec.Emitter()); err != nil {
		t.Fatalf("Collect: %v", err)
	}

	pts := rec.MetricPoints(configStatusMetricName)
	type key struct{ policy, status string }
	got := map[key]float64{}
	for _, p := range pts {
		got[key{p.Attrs["policy_name"], p.Attrs["status"]}] = p.Value
	}
	want := map[key]float64{
		{"Outlook config", "pending"}:        1,
		{"Outlook config", "not_applicable"}: 2,
		{"Outlook config", "success"}:        3,
		{"Outlook config", "error"}:          4,
		{"Outlook config", "failed"}:         5,
		// cfg2's fixture uses the {"value": {...}} envelope shape — this
		// asserts the decode handles both the bare-object and enveloped
		// response shapes.
		{"VPN config", "pending"}:        10,
		{"VPN config", "not_applicable"}: 0,
		{"VPN config", "success"}:        20,
		{"VPN config", "error"}:          0,
		{"VPN config", "failed"}:         0,
	}
	if len(got) != len(want) {
		t.Fatalf("got %d series, want %d: %v", len(got), len(want), got)
	}
	for k, v := range want {
		if got[k] != v {
			t.Errorf("series policy=%s status=%s = %v, want %v", k.policy, k.status, got[k], v)
		}
	}
}

func TestCollectIsResilientToPerPolicyDeviceStatusSummaryError(t *testing.T) {
	g := &fakeGraph{
		bodies: fullFixture(),
		errs:   map[string]error{deviceStatusSummaryURL("cfg2"): errors.New("throttled")},
	}
	rec := telemetrytest.New()

	err := New(g, nil).Collect(context.Background(), rec.Emitter())
	if err == nil {
		t.Fatal("expected Collect to surface the per-policy deviceStatusSummary failure as an error")
	}

	pts := rec.MetricPoints(configStatusMetricName)
	for _, p := range pts {
		if p.Attrs["policy_name"] == "VPN config" {
			t.Errorf("VPN config series should be absent when its deviceStatusSummary fetch failed: %v", p)
		}
	}
	// cfg1 and the mobile_apps.count metric must still emit despite cfg2 failing.
	var sawCfg1 bool
	for _, p := range pts {
		if p.Attrs["policy_name"] == "Outlook config" {
			sawCfg1 = true
		}
	}
	if !sawCfg1 {
		t.Error("Outlook config series missing despite VPN config being the only failure")
	}
	if len(rec.MetricPoints(appsMetricName)) == 0 {
		t.Error("mobile_apps.count should still emit despite the config-status failure")
	}
}

func TestCollectSurfacesMobileAppsListFailure(t *testing.T) {
	g := &fakeGraph{
		bodies: fullFixture(),
		errs:   map[string]error{mobileAppsURL: errors.New("throttled")},
	}
	rec := telemetrytest.New()

	err := New(g, nil).Collect(context.Background(), rec.Emitter())
	if err == nil {
		t.Fatal("expected Collect to surface the mobileApps list failure as an error")
	}
	if pts := rec.MetricPoints(appsMetricName); len(pts) != 0 {
		t.Errorf("expected no mobile_apps.count series when the list fetch failed, got %v", pts)
	}
	// Config status is independent of the apps list and must still emit.
	if len(rec.MetricPoints(configStatusMetricName)) == 0 {
		t.Error("mobile_app_config.status should still emit despite the apps-list failure")
	}
}

func TestCollectSkipsGracefullyOn403(t *testing.T) {
	g := &fakeGraph{
		bodies: fullFixture(),
		errs: map[string]error{
			mobileAppsURL:    errors.New("graphclient: GET x: status 403: Forbidden"),
			mobileConfigsURL: errors.New("graphclient: GET x: status 403: Forbidden"),
		},
	}
	rec := telemetrytest.New()

	if err := New(g, nil).Collect(context.Background(), rec.Emitter()); err != nil {
		t.Fatalf("expected a 403 on both endpoints to be skipped, not surfaced as an error: %v", err)
	}
	if pts := rec.MetricPoints(appsMetricName); len(pts) != 0 {
		t.Errorf("expected no mobile_apps.count series on 403, got %v", pts)
	}
	if pts := rec.MetricPoints(configStatusMetricName); len(pts) != 0 {
		t.Errorf("expected no mobile_app_config.status series on 403, got %v", pts)
	}
}

func TestNoPerDeviceInstallStatusCalls(t *testing.T) {
	// Guards the M5-deferred scope: this collector must never call the
	// per-device install-status nav-props (deviceStatuses/userStatuses on
	// mobileApps/mobileAppConfigurations, or any per-app assignment install
	// detail) - those are deferred to the M5 export-job subsystem.
	g := &fakeGraph{bodies: fullFixture()}
	rec := telemetrytest.New()

	if err := New(g, nil).Collect(context.Background(), rec.Emitter()); err != nil {
		t.Fatalf("Collect: %v", err)
	}

	forbidden := []string{"deviceStatuses", "userStatuses", "installStates", "assignments"}
	for _, url := range g.requested {
		for _, f := range forbidden {
			if strings.Contains(url, f) {
				t.Errorf("collector requested %q, which touches the deferred per-device install-status surface (%s)", url, f)
			}
		}
	}
}

func TestNameIntervalAndPermissions(t *testing.T) {
	c := New(&fakeGraph{}, nil)
	if c.Name() != "intune.mobile_apps" {
		t.Errorf("Name = %q, want intune.mobile_apps", c.Name())
	}
	if c.DefaultInterval() <= 0 {
		t.Error("DefaultInterval must be positive")
	}
	perms := c.RequiredPermissions()
	if len(perms) != 1 || perms[0] != "DeviceManagementApps.Read.All" {
		t.Errorf("RequiredPermissions = %v, want [DeviceManagementApps.Read.All]", perms)
	}
}

// TestNoUnboundedLabels guards the cardinality rule: no series may carry a
// per-app or per-device identifier as an attribute — only the bounded
// app_type/publishing_state/policy_name/status dimensions.
func TestNoUnboundedLabels(t *testing.T) {
	g := &fakeGraph{bodies: fullFixture()}
	rec := telemetrytest.New()

	if err := New(g, nil).Collect(context.Background(), rec.Emitter()); err != nil {
		t.Fatalf("Collect: %v", err)
	}

	allowedAppAttrs := map[string]bool{"app_type": true, "publishing_state": true}
	for _, p := range rec.MetricPoints(appsMetricName) {
		for k := range p.Attrs {
			if !allowedAppAttrs[k] {
				t.Errorf("mobile_apps.count series has unexpected attribute %q: %v", k, p.Attrs)
			}
		}
	}

	allowedConfigAttrs := map[string]bool{"policy_name": true, "status": true}
	for _, p := range rec.MetricPoints(configStatusMetricName) {
		for k := range p.Attrs {
			if !allowedConfigAttrs[k] {
				t.Errorf("mobile_app_config.status series has unexpected attribute %q: %v", k, p.Attrs)
			}
		}
	}
}
