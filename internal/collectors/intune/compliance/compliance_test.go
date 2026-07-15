package compliance

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/rknightion/graph2otel/internal/collectors"
	"github.com/rknightion/graph2otel/internal/telemetrytest"
)

// fakeGraph maps request URLs to canned response bodies (or errors) and
// records every URL requested, so tests can assert both what was emitted and
// exactly which endpoints were (or were not) called.
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
		return nil, fmt.Errorf("fakeGraph: no canned body for %s", url)
	}
	return []byte(body), nil
}

var _ collectors.GraphClient = (*fakeGraph)(nil)

const base = "https://graph.microsoft.com/v1.0"

const (
	stateSummaryURL     = base + "/deviceManagement/deviceCompliancePolicyDeviceStateSummary"
	policiesURL         = base + "/deviceManagement/deviceCompliancePolicies"
	settingSummariesURL = base + "/deviceManagement/deviceCompliancePolicySettingStateSummaries"
)

func deviceOverviewURL(id string) string {
	return base + "/deviceManagement/deviceCompliancePolicies/" + id + "/deviceStatusOverview"
}

func userOverviewURL(id string) string {
	return base + "/deviceManagement/deviceCompliancePolicies/" + id + "/userStatusOverview"
}

// forbidden403 mimics the graphclient error format that Count/RawGet produce
// for an HTTP 403, so isForbidden's substring check is exercised the way it
// would be against the real client.
func forbidden403(url string) error {
	return fmt.Errorf("graphclient: GET %s: status 403: Forbidden", url)
}

// emptyEndpoints returns a fixture with every endpoint answering with an
// empty/zero result, so a test can override just the endpoint(s) it cares
// about without hand-filling the rest.
func emptyEndpoints() map[string]string {
	return map[string]string{
		stateSummaryURL:     `{}`,
		policiesURL:         `{"value":[]}`,
		settingSummariesURL: `{"value":[]}`,
	}
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

func TestCollectEmitsDeviceStateSummary(t *testing.T) {
	bodies := merge(emptyEndpoints(), map[string]string{
		stateSummaryURL: `{
			"compliantDeviceCount": 100,
			"nonCompliantDeviceCount": 20,
			"inGracePeriodCount": 5,
			"configManagerCount": 3,
			"unknownDeviceCount": 2,
			"notApplicableDeviceCount": 8,
			"remediatedDeviceCount": 4,
			"errorDeviceCount": 1,
			"conflictDeviceCount": 1
		}`,
	})
	g := &fakeGraph{bodies: bodies}
	rec := telemetrytest.New()

	if err := New(g, nil).Collect(context.Background(), rec.Emitter()); err != nil {
		t.Fatalf("Collect: %v", err)
	}

	pts := rec.MetricPoints(devicesMetricName)
	got := map[string]float64{}
	for _, p := range pts {
		got[p.Attrs["state"]] = p.Value
	}
	want := map[string]float64{
		"compliant": 100, "non_compliant": 20, "in_grace_period": 5, "config_manager": 3,
		"unknown": 2, "not_applicable": 8, "remediated": 4, "error": 1, "conflict": 1,
	}
	if len(got) != len(want) {
		t.Fatalf("got %d state series, want %d: %v", len(got), len(want), got)
	}
	for k, v := range want {
		if got[k] != v {
			t.Errorf("state=%s value = %v, want %v", k, got[k], v)
		}
	}
}

func TestCollectEmitsPolicyVersionAndOverviews(t *testing.T) {
	bodies := merge(emptyEndpoints(), map[string]string{
		policiesURL: `{"value":[
			{"id":"p1","displayName":"Windows Baseline","version":3},
			{"id":"p2","displayName":"iOS Baseline","version":7}
		]}`,
		deviceOverviewURL("p1"): `{"pendingCount":1,"notApplicableCount":2,"successCount":10,"errorCount":0,"failedCount":3}`,
		userOverviewURL("p1"):   `{"pendingCount":0,"notApplicableCount":1,"successCount":5,"errorCount":1,"failedCount":0}`,
		deviceOverviewURL("p2"): `{"pendingCount":2,"notApplicableCount":0,"successCount":8,"errorCount":1,"failedCount":1}`,
		userOverviewURL("p2"):   `{"pendingCount":1,"notApplicableCount":0,"successCount":6,"errorCount":0,"failedCount":0}`,
	})
	g := &fakeGraph{bodies: bodies}
	rec := telemetrytest.New()

	if err := New(g, nil).Collect(context.Background(), rec.Emitter()); err != nil {
		t.Fatalf("Collect: %v", err)
	}

	versionPts := rec.MetricPoints(policyVersionMetricName)
	gotVersions := map[string]float64{}
	for _, p := range versionPts {
		gotVersions[p.Attrs["policy_name"]] = p.Value
	}
	wantVersions := map[string]float64{"Windows Baseline": 3, "iOS Baseline": 7}
	if len(gotVersions) != len(wantVersions) {
		t.Fatalf("got %d policy_name version series, want %d: %v", len(gotVersions), len(wantVersions), gotVersions)
	}
	for k, v := range wantVersions {
		if gotVersions[k] != v {
			t.Errorf("policy_name=%s version = %v, want %v", k, gotVersions[k], v)
		}
	}

	devicePts := rec.MetricPoints(policyDevicesMetricName)
	if len(devicePts) != 10 { // 2 policies * 5 states
		t.Fatalf("got %d policy.devices series, want 10: %+v", len(devicePts), devicePts)
	}
	got := map[[2]string]float64{}
	for _, p := range devicePts {
		got[[2]string{p.Attrs["policy_name"], p.Attrs["state"]}] = p.Value
	}
	if got[[2]string{"Windows Baseline", "success"}] != 10 {
		t.Errorf("Windows Baseline success = %v, want 10", got[[2]string{"Windows Baseline", "success"}])
	}
	if got[[2]string{"iOS Baseline", "failed"}] != 1 {
		t.Errorf("iOS Baseline failed = %v, want 1", got[[2]string{"iOS Baseline", "failed"}])
	}

	userPts := rec.MetricPoints(policyUsersMetricName)
	if len(userPts) != 10 {
		t.Fatalf("got %d policy.users series, want 10: %+v", len(userPts), userPts)
	}
	gotUsers := map[[2]string]float64{}
	for _, p := range userPts {
		gotUsers[[2]string{p.Attrs["policy_name"], p.Attrs["state"]}] = p.Value
	}
	if gotUsers[[2]string{"Windows Baseline", "success"}] != 5 {
		t.Errorf("Windows Baseline user success = %v, want 5", gotUsers[[2]string{"Windows Baseline", "success"}])
	}
}

func TestCollectSurfacesPolicyVersionBumpBetweenPolls(t *testing.T) {
	firstBodies := merge(emptyEndpoints(), map[string]string{
		policiesURL:             `{"value":[{"id":"p1","displayName":"Windows Baseline","version":3}]}`,
		deviceOverviewURL("p1"): `{}`,
		userOverviewURL("p1"):   `{}`,
	})
	g := &fakeGraph{bodies: firstBodies}
	rec := telemetrytest.New()
	c := New(g, nil)

	if err := c.Collect(context.Background(), rec.Emitter()); err != nil {
		t.Fatalf("first Collect: %v", err)
	}
	first := rec.MetricPoints(policyVersionMetricName)
	if len(first) != 1 || first[0].Value != 3 {
		t.Fatalf("first poll version = %+v, want a single point at 3", first)
	}

	// Second poll: the policy's version has bumped, simulating a
	// policy-content change between collection cycles.
	g.bodies[policiesURL] = `{"value":[{"id":"p1","displayName":"Windows Baseline","version":4}]}`
	if err := c.Collect(context.Background(), rec.Emitter()); err != nil {
		t.Fatalf("second Collect: %v", err)
	}
	second := rec.MetricPoints(policyVersionMetricName)
	if len(second) != 1 || second[0].Value != 4 {
		t.Fatalf("second poll version = %+v, want a single point at 4 (the bump)", second)
	}
}

func TestCollectEmitsBoundedSettingStateSummaries(t *testing.T) {
	bodies := merge(emptyEndpoints(), map[string]string{
		settingSummariesURL: `{"value":[
			{"settingName":"Require BitLocker","platformType":"windows10","compliantDeviceCount":40,"nonCompliantDeviceCount":10,"unknownDeviceCount":1,"notApplicableDeviceCount":2,"remediatedDeviceCount":3,"errorDeviceCount":0,"conflictDeviceCount":0},
			{"settingName":"Require Passcode","platformType":"ios","compliantDeviceCount":20,"nonCompliantDeviceCount":5,"unknownDeviceCount":0,"notApplicableDeviceCount":1,"remediatedDeviceCount":0,"errorDeviceCount":1,"conflictDeviceCount":0}
		]}`,
	})
	g := &fakeGraph{bodies: bodies}
	rec := telemetrytest.New()

	if err := New(g, nil).Collect(context.Background(), rec.Emitter()); err != nil {
		t.Fatalf("Collect: %v", err)
	}

	pts := rec.MetricPoints(settingDevicesMetricName)
	if len(pts) != 14 { // 2 unique (setting, platform) pairs * 7 states
		t.Fatalf("got %d setting.devices series, want 14 (bounded by unique setting x platform x state): %+v", len(pts), pts)
	}
	got := map[[3]string]float64{}
	for _, p := range pts {
		got[[3]string{p.Attrs["setting_name"], p.Attrs["platform"], p.Attrs["state"]}] = p.Value
	}
	if got[[3]string{"Require BitLocker", "windows10", "compliant"}] != 40 {
		t.Errorf("Require BitLocker/windows10/compliant = %v, want 40", got[[3]string{"Require BitLocker", "windows10", "compliant"}])
	}
	if got[[3]string{"Require Passcode", "ios", "non_compliant"}] != 5 {
		t.Errorf("Require Passcode/ios/non_compliant = %v, want 5", got[[3]string{"Require Passcode", "ios", "non_compliant"}])
	}
}

func TestCollectNeverFetchesPerDeviceStatusChildren(t *testing.T) {
	bodies := merge(emptyEndpoints(), map[string]string{
		policiesURL:             `{"value":[{"id":"p1","displayName":"Windows Baseline","version":1}]}`,
		deviceOverviewURL("p1"): `{}`,
		userOverviewURL("p1"):   `{}`,
	})
	g := &fakeGraph{bodies: bodies}
	rec := telemetrytest.New()

	if err := New(g, nil).Collect(context.Background(), rec.Emitter()); err != nil {
		t.Fatalf("Collect: %v", err)
	}

	forbiddenSubstrings := []string{
		"/deviceStatuses", "/userStatuses", "/deviceComplianceSettingStates", "/deviceCompliancePolicyStates",
	}
	for _, url := range g.requestedURL {
		for _, sub := range forbiddenSubstrings {
			if strings.Contains(url, sub) {
				t.Errorf("requested %q, which touches the per-device status children this collector must never fetch", url)
			}
		}
	}
}

func TestCollectGracefullySkipsForbiddenDeviceStateSummary(t *testing.T) {
	bodies := emptyEndpoints()
	g := &fakeGraph{
		bodies: bodies,
		errs:   map[string]error{stateSummaryURL: forbidden403(stateSummaryURL)},
	}
	rec := telemetrytest.New()

	if err := New(g, nil).Collect(context.Background(), rec.Emitter()); err != nil {
		t.Fatalf("Collect should gracefully skip a 403, not surface an error: %v", err)
	}
	if pts := rec.MetricPoints(devicesMetricName); len(pts) != 0 {
		t.Errorf("expected no devices series when the state summary is forbidden, got %+v", pts)
	}
}

func TestCollectGracefullySkipsForbiddenPolicyList(t *testing.T) {
	bodies := emptyEndpoints()
	g := &fakeGraph{
		bodies: bodies,
		errs:   map[string]error{policiesURL: forbidden403(policiesURL)},
	}
	rec := telemetrytest.New()

	if err := New(g, nil).Collect(context.Background(), rec.Emitter()); err != nil {
		t.Fatalf("Collect should gracefully skip a 403, not surface an error: %v", err)
	}
	if pts := rec.MetricPoints(policyVersionMetricName); len(pts) != 0 {
		t.Errorf("expected no policy.version series when the policy list is forbidden, got %+v", pts)
	}
}

func TestCollectIsResilientToOnePolicyOverviewFailure(t *testing.T) {
	bodies := merge(emptyEndpoints(), map[string]string{
		policiesURL: `{"value":[
			{"id":"p1","displayName":"Windows Baseline","version":1},
			{"id":"p2","displayName":"iOS Baseline","version":1}
		]}`,
		deviceOverviewURL("p2"): `{"successCount":9}`,
		userOverviewURL("p1"):   `{}`,
		userOverviewURL("p2"):   `{}`,
	})
	g := &fakeGraph{
		bodies: bodies,
		errs:   map[string]error{deviceOverviewURL("p1"): errors.New("throttled")},
	}
	rec := telemetrytest.New()

	err := New(g, nil).Collect(context.Background(), rec.Emitter())
	if err == nil {
		t.Fatal("expected Collect to surface the per-policy overview failure as an error")
	}

	pts := rec.MetricPoints(policyDevicesMetricName)
	got := map[[2]string]float64{}
	for _, p := range pts {
		got[[2]string{p.Attrs["policy_name"], p.Attrs["state"]}] = p.Value
	}
	if _, ok := got[[2]string{"Windows Baseline", "success"}]; ok {
		t.Error("Windows Baseline should have no policy.devices series since its overview fetch failed")
	}
	if got[[2]string{"iOS Baseline", "success"}] != 9 {
		t.Errorf("iOS Baseline success = %v, want 9 (unaffected by the other policy's failure)", got[[2]string{"iOS Baseline", "success"}])
	}
	// Every other metric must still emit despite the one failure.
	if len(rec.MetricPoints(devicesMetricName)) == 0 {
		t.Error("devices series should be unaffected by the policy-overview failure")
	}
}

func TestNoPerDeviceOrPerUserAttribute(t *testing.T) {
	bodies := merge(emptyEndpoints(), map[string]string{
		policiesURL:             `{"value":[{"id":"p1","displayName":"Windows Baseline","version":1}]}`,
		deviceOverviewURL("p1"): `{"successCount":1}`,
		userOverviewURL("p1"):   `{"successCount":1}`,
		settingSummariesURL:     `{"value":[{"settingName":"Require BitLocker","platformType":"windows10","compliantDeviceCount":1}]}`,
	})
	g := &fakeGraph{bodies: bodies}
	rec := telemetrytest.New()

	if err := New(g, nil).Collect(context.Background(), rec.Emitter()); err != nil {
		t.Fatalf("Collect: %v", err)
	}

	forbiddenAttrs := []string{"id", "deviceId", "device_id", "userId", "user_id", "upn"}
	for _, metric := range []string{devicesMetricName, policyDevicesMetricName, policyUsersMetricName, settingDevicesMetricName, policyVersionMetricName} {
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
	if c.Name() != "intune.compliance" {
		t.Errorf("Name = %q, want intune.compliance", c.Name())
	}
	if c.DefaultInterval() <= 0 {
		t.Errorf("DefaultInterval = %v, want positive", c.DefaultInterval())
	}
	perms := c.RequiredPermissions()
	if len(perms) != 1 || perms[0] != "DeviceManagementConfiguration.Read.All" {
		t.Errorf("RequiredPermissions = %v, want [DeviceManagementConfiguration.Read.All]", perms)
	}
}
