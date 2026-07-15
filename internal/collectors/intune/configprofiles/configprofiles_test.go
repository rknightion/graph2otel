package configprofiles

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/rknightion/graph2otel/internal/collectors"
	"github.com/rknightion/graph2otel/internal/telemetrytest"
)

// fakeGraph maps request URLs to canned response bodies (or errors) and
// records every URL requested, so tests can assert both what was emitted and
// exactly which endpoints were (or were not) called - mirrors the
// intune/compliance reference collector's test fake.
type fakeGraph struct {
	bodies       map[string]string
	errs         map[string]error
	requestedURL []string
}

func (f *fakeGraph) RawGet(ctx context.Context, url string) ([]byte, error) {
	return f.RawGetWithHeaders(ctx, url, nil)
}

func (f *fakeGraph) RawGetWithHeaders(_ context.Context, url string, _ map[string]string) ([]byte, error) {
	f.requestedURL = append(f.requestedURL, url)
	if err, ok := f.errs[url]; ok {
		return nil, err
	}
	body, ok := f.bodies[url]
	if !ok {
		return nil, errors.New("fakeGraph: no canned body for " + url)
	}
	return []byte(body), nil
}

var _ collectors.GraphClient = (*fakeGraph)(nil)

const base = "https://graph.microsoft.com/v1.0"

const profilesURL = base + "/deviceManagement/deviceConfigurations"

func statusOverviewURL(id string) string {
	return base + "/deviceManagement/deviceConfigurations/" + id + "/deviceStatusOverview"
}

// forbidden403 mimics the graphclient error format that Count/RawGet produce
// for an HTTP 403, so isForbidden's substring check is exercised the way it
// would be against the real client.
func forbidden403(url string) error {
	return errors.New("graphclient: GET " + url + ": status 403: Forbidden")
}

func emptyEndpoints() map[string]string {
	return map[string]string{profilesURL: `{"value":[]}`}
}

func merge(maps ...map[string]string) map[string]string {
	out := map[string]string{}
	for _, m := range maps {
		for k, v := range m {
			out[k] = v
		}
	}
	return out
}

func TestCollectEmitsProfileCountByODataType(t *testing.T) {
	bodies := merge(emptyEndpoints(), map[string]string{
		profilesURL: `{"value":[
			{"id":"p1","displayName":"Win10 General","version":1,"@odata.type":"#microsoft.graph.windows10GeneralConfiguration"},
			{"id":"p2","displayName":"Win10 General 2","version":1,"@odata.type":"#microsoft.graph.windows10GeneralConfiguration"},
			{"id":"p3","displayName":"iOS Wifi","version":1,"@odata.type":"#microsoft.graph.iosWiFiConfiguration"},
			{"id":"p4","displayName":"Something New","version":1,"@odata.type":"#microsoft.graph.someBrandNewConfigurationType"}
		]}`,
		statusOverviewURL("p1"): `{}`,
		statusOverviewURL("p2"): `{}`,
		statusOverviewURL("p3"): `{}`,
		statusOverviewURL("p4"): `{}`,
	})
	g := &fakeGraph{bodies: bodies}
	rec := telemetrytest.New()

	if err := New(g, nil).Collect(context.Background(), rec.Emitter()); err != nil {
		t.Fatalf("Collect: %v", err)
	}

	pts := rec.MetricPoints(countMetricName)
	got := map[string]float64{}
	for _, p := range pts {
		got[p.Attrs["odata_type"]] = p.Value
	}
	want := map[string]float64{"windows_general": 2, "ios_wifi": 1, "other": 1}
	if len(got) != len(want) {
		t.Fatalf("got %d odata_type series, want %d: %v", len(got), len(want), got)
	}
	for k, v := range want {
		if got[k] != v {
			t.Errorf("odata_type=%s = %v, want %v", k, got[k], v)
		}
	}
}

func TestCollectExcludesWindowsUpdateForBusinessConfiguration(t *testing.T) {
	bodies := merge(emptyEndpoints(), map[string]string{
		profilesURL: `{"value":[
			{"id":"p1","displayName":"Win10 General","version":1,"@odata.type":"#microsoft.graph.windows10GeneralConfiguration"},
			{"id":"ring1","displayName":"Update Ring","version":1,"@odata.type":"#microsoft.graph.windowsUpdateForBusinessConfiguration"}
		]}`,
		statusOverviewURL("p1"): `{}`,
	})
	g := &fakeGraph{bodies: bodies}
	rec := telemetrytest.New()

	if err := New(g, nil).Collect(context.Background(), rec.Emitter()); err != nil {
		t.Fatalf("Collect: %v", err)
	}

	// Not counted under any bucket.
	for _, p := range rec.MetricPoints(countMetricName) {
		if p.Value > 0 && p.Attrs["odata_type"] != "windows_general" {
			t.Errorf("unexpected odata_type bucket %q counted a Group-B-excluded profile: %+v", p.Attrs["odata_type"], p)
		}
	}
	total := 0.0
	for _, p := range rec.MetricPoints(countMetricName) {
		total += p.Value
	}
	if total != 1 {
		t.Errorf("total profile count = %v, want 1 (the windowsUpdateForBusinessConfiguration profile must be excluded, owned by #59)", total)
	}

	// Not version-tracked.
	for _, p := range rec.MetricPoints(versionMetricName) {
		if p.Attrs["profile_name"] == "Update Ring" {
			t.Error("Update Ring should have no version series - excluded Group B type")
		}
	}

	// Its status overview must never be fetched at all.
	for _, url := range g.requestedURL {
		if url == statusOverviewURL("ring1") {
			t.Errorf("requested %q - the excluded windowsUpdateForBusinessConfiguration profile's status overview must never be fetched", url)
		}
	}
}

func TestCollectEmitsVersionGauge(t *testing.T) {
	bodies := merge(emptyEndpoints(), map[string]string{
		profilesURL: `{"value":[
			{"id":"p1","displayName":"Win10 General","version":3,"@odata.type":"#microsoft.graph.windows10GeneralConfiguration"}
		]}`,
		statusOverviewURL("p1"): `{}`,
	})
	g := &fakeGraph{bodies: bodies}
	rec := telemetrytest.New()

	if err := New(g, nil).Collect(context.Background(), rec.Emitter()); err != nil {
		t.Fatalf("Collect: %v", err)
	}

	pts := rec.MetricPoints(versionMetricName)
	if len(pts) != 1 || pts[0].Value != 3 || pts[0].Attrs["profile_name"] != "Win10 General" {
		t.Fatalf("version points = %+v, want a single {profile_name=Win10 General, value=3} point", pts)
	}
}

func TestCollectSurfacesVersionBumpBetweenPolls(t *testing.T) {
	g := &fakeGraph{bodies: merge(emptyEndpoints(), map[string]string{
		profilesURL:             `{"value":[{"id":"p1","displayName":"Win10 General","version":3,"@odata.type":"#microsoft.graph.windows10GeneralConfiguration"}]}`,
		statusOverviewURL("p1"): `{}`,
	})}
	rec := telemetrytest.New()
	c := New(g, nil)

	if err := c.Collect(context.Background(), rec.Emitter()); err != nil {
		t.Fatalf("first Collect: %v", err)
	}
	first := rec.MetricPoints(versionMetricName)
	if len(first) != 1 || first[0].Value != 3 {
		t.Fatalf("first poll version = %+v, want a single point at 3", first)
	}

	g.bodies[profilesURL] = `{"value":[{"id":"p1","displayName":"Win10 General","version":4,"@odata.type":"#microsoft.graph.windows10GeneralConfiguration"}]}`
	if err := c.Collect(context.Background(), rec.Emitter()); err != nil {
		t.Fatalf("second Collect: %v", err)
	}
	second := rec.MetricPoints(versionMetricName)
	if len(second) != 1 || second[0].Value != 4 {
		t.Fatalf("second poll version = %+v, want a single point at 4 (the bump)", second)
	}
}

func TestCollectEmitsStatusOverviewByProfileAndState(t *testing.T) {
	bodies := merge(emptyEndpoints(), map[string]string{
		profilesURL: `{"value":[
			{"id":"p1","displayName":"Win10 General","version":1,"@odata.type":"#microsoft.graph.windows10GeneralConfiguration"},
			{"id":"p2","displayName":"iOS Wifi","version":1,"@odata.type":"#microsoft.graph.iosWiFiConfiguration"}
		]}`,
		statusOverviewURL("p1"): `{"pendingCount":1,"notApplicableCount":2,"successCount":10,"errorCount":0,"failedCount":3}`,
		statusOverviewURL("p2"): `{"pendingCount":2,"notApplicableCount":0,"successCount":8,"errorCount":1,"failedCount":1}`,
	})
	g := &fakeGraph{bodies: bodies}
	rec := telemetrytest.New()

	if err := New(g, nil).Collect(context.Background(), rec.Emitter()); err != nil {
		t.Fatalf("Collect: %v", err)
	}

	pts := rec.MetricPoints(statusMetricName)
	if len(pts) != 10 { // 2 profiles * 5 states
		t.Fatalf("got %d config_profile.status series, want 10: %+v", len(pts), pts)
	}
	got := map[[2]string]float64{}
	for _, p := range pts {
		got[[2]string{p.Attrs["profile_name"], p.Attrs["state"]}] = p.Value
	}
	if got[[2]string{"Win10 General", "success"}] != 10 {
		t.Errorf("Win10 General success = %v, want 10", got[[2]string{"Win10 General", "success"}])
	}
	if got[[2]string{"iOS Wifi", "failed"}] != 1 {
		t.Errorf("iOS Wifi failed = %v, want 1", got[[2]string{"iOS Wifi", "failed"}])
	}
}

func TestCollectIsResilientToOneProfileStatusOverviewFailure(t *testing.T) {
	bodies := merge(emptyEndpoints(), map[string]string{
		profilesURL: `{"value":[
			{"id":"p1","displayName":"Win10 General","version":1,"@odata.type":"#microsoft.graph.windows10GeneralConfiguration"},
			{"id":"p2","displayName":"iOS Wifi","version":1,"@odata.type":"#microsoft.graph.iosWiFiConfiguration"}
		]}`,
		statusOverviewURL("p2"): `{"successCount":9}`,
	})
	g := &fakeGraph{
		bodies: bodies,
		errs:   map[string]error{statusOverviewURL("p1"): errors.New("throttled")},
	}
	rec := telemetrytest.New()

	err := New(g, nil).Collect(context.Background(), rec.Emitter())
	if err == nil {
		t.Fatal("expected Collect to surface the per-profile status overview failure as an error")
	}

	pts := rec.MetricPoints(statusMetricName)
	got := map[[2]string]float64{}
	for _, p := range pts {
		got[[2]string{p.Attrs["profile_name"], p.Attrs["state"]}] = p.Value
	}
	if _, ok := got[[2]string{"Win10 General", "success"}]; ok {
		t.Error("Win10 General should have no status series since its overview fetch failed")
	}
	if got[[2]string{"iOS Wifi", "success"}] != 9 {
		t.Errorf("iOS Wifi success = %v, want 9 (unaffected by the other profile's failure)", got[[2]string{"iOS Wifi", "success"}])
	}
	if len(rec.MetricPoints(versionMetricName)) != 2 {
		t.Error("version series should be unaffected by the status-overview failure")
	}
}

func TestCollectGracefullySkipsForbiddenProfileList(t *testing.T) {
	g := &fakeGraph{
		bodies: emptyEndpoints(),
		errs:   map[string]error{profilesURL: forbidden403(profilesURL)},
	}
	rec := telemetrytest.New()

	if err := New(g, nil).Collect(context.Background(), rec.Emitter()); err != nil {
		t.Fatalf("Collect should gracefully skip a 403, not surface an error: %v", err)
	}
	if pts := rec.MetricPoints(countMetricName); len(pts) != 0 {
		t.Errorf("expected no count series when the profile list is forbidden, got %+v", pts)
	}
	if pts := rec.MetricPoints(versionMetricName); len(pts) != 0 {
		t.Errorf("expected no version series when the profile list is forbidden, got %+v", pts)
	}
}

func TestCollectGracefullySkipsForbiddenStatusOverview(t *testing.T) {
	bodies := merge(emptyEndpoints(), map[string]string{
		profilesURL: `{"value":[{"id":"p1","displayName":"Win10 General","version":1,"@odata.type":"#microsoft.graph.windows10GeneralConfiguration"}]}`,
	})
	g := &fakeGraph{
		bodies: bodies,
		errs:   map[string]error{statusOverviewURL("p1"): forbidden403(statusOverviewURL("p1"))},
	}
	rec := telemetrytest.New()

	if err := New(g, nil).Collect(context.Background(), rec.Emitter()); err != nil {
		t.Fatalf("Collect should gracefully skip a 403, not surface an error: %v", err)
	}
	if pts := rec.MetricPoints(statusMetricName); len(pts) != 0 {
		t.Errorf("expected no status series when the overview is forbidden, got %+v", pts)
	}
}

func TestCollectNeverFetchesPerDeviceStatusChildren(t *testing.T) {
	bodies := merge(emptyEndpoints(), map[string]string{
		profilesURL:             `{"value":[{"id":"p1","displayName":"Win10 General","version":1,"@odata.type":"#microsoft.graph.windows10GeneralConfiguration"}]}`,
		statusOverviewURL("p1"): `{}`,
	})
	g := &fakeGraph{bodies: bodies}
	rec := telemetrytest.New()

	if err := New(g, nil).Collect(context.Background(), rec.Emitter()); err != nil {
		t.Fatalf("Collect: %v", err)
	}

	forbiddenSubstrings := []string{"/deviceStatuses", "/userStatuses", "/deviceSettingStateSummaries", "$expand"}
	for _, url := range g.requestedURL {
		for _, sub := range forbiddenSubstrings {
			if strings.Contains(url, sub) {
				t.Errorf("requested %q, which touches the per-device status children this collector must never fetch", url)
			}
		}
	}
}

func TestNoPerEntityAttribute(t *testing.T) {
	bodies := merge(emptyEndpoints(), map[string]string{
		profilesURL:             `{"value":[{"id":"p1","displayName":"Win10 General","version":1,"@odata.type":"#microsoft.graph.windows10GeneralConfiguration"}]}`,
		statusOverviewURL("p1"): `{"successCount":1}`,
	})
	g := &fakeGraph{bodies: bodies}
	rec := telemetrytest.New()

	if err := New(g, nil).Collect(context.Background(), rec.Emitter()); err != nil {
		t.Fatalf("Collect: %v", err)
	}

	forbiddenAttrs := []string{"id", "deviceId", "device_id", "userId", "user_id", "upn"}
	for _, metric := range []string{countMetricName, versionMetricName, statusMetricName} {
		for _, p := range rec.MetricPoints(metric) {
			for _, bad := range forbiddenAttrs {
				if _, ok := p.Attrs[bad]; ok {
					t.Errorf("metric %s has a per-entity attribute %q - cardinality violation", metric, bad)
				}
			}
		}
	}
}

func TestNameIntervalAndPermissions(t *testing.T) {
	c := New(&fakeGraph{}, nil)
	if c.Name() != "intune.config_profiles" {
		t.Errorf("Name = %q, want intune.config_profiles", c.Name())
	}
	if c.DefaultInterval() <= 0 {
		t.Errorf("DefaultInterval = %v, want positive", c.DefaultInterval())
	}
	perms := c.RequiredPermissions()
	if len(perms) != 1 || perms[0] != "DeviceManagementConfiguration.Read.All" {
		t.Errorf("RequiredPermissions = %v, want [DeviceManagementConfiguration.Read.All]", perms)
	}
}
