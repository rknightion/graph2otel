package scripts

import (
	"context"
	"errors"
	"testing"

	"github.com/rknightion/graph2otel/internal/collectors"
	"github.com/rknightion/graph2otel/internal/telemetrytest"
)

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
	b, ok := f.bodies[url]
	if !ok {
		return nil, errors.New("no canned body for " + url)
	}
	return []byte(b), nil
}

var _ collectors.GraphClient = (*fakeGraph)(nil)

const (
	windowsListURL    = "https://graph.microsoft.com/beta/deviceManagement/deviceManagementScripts?$select=id,displayName"
	macListURL        = "https://graph.microsoft.com/beta/deviceManagement/deviceShellScripts?$select=id,displayName"
	healthListURL     = "https://graph.microsoft.com/beta/deviceManagement/deviceHealthScripts?$select=id,displayName"
	remediationSumURL = "https://graph.microsoft.com/beta/deviceManagement/deviceHealthScripts/getRemediationSummary"
	winRunSummaryURL  = "https://graph.microsoft.com/beta/deviceManagement/deviceManagementScripts/win-1/runSummary"
	macRunSummaryURL  = "https://graph.microsoft.com/beta/deviceManagement/deviceShellScripts/mac-1/runSummary"
	healthRunSummary1 = "https://graph.microsoft.com/beta/deviceManagement/deviceHealthScripts/health-1/runSummary"
)

// fullFixture wires a fake Graph client with one script on each of the three
// surfaces plus the tenant-wide remediation overview singleton, matching the
// documented Graph response shapes (runSummary wrapped in a bare "value"
// object, list pages wrapped in "value": [...]).
func fullFixture() *fakeGraph {
	return &fakeGraph{bodies: map[string]string{
		windowsListURL: `{"value":[{"id":"win-1","displayName":"Rename Local Admin"}]}`,
		winRunSummaryURL: `{"value":{"@odata.type":"#microsoft.graph.deviceManagementScriptRunSummary",
			"id":"rs1","successDeviceCount":10,"errorDeviceCount":2,"successUserCount":0,"errorUserCount":1}}`,
		macListURL: `{"value":[{"id":"mac-1","displayName":"Install Rosetta"}]}`,
		macRunSummaryURL: `{"value":{"@odata.type":"#microsoft.graph.deviceManagementScriptRunSummary",
			"id":"rs2","successDeviceCount":5,"errorDeviceCount":0,"successUserCount":0,"errorUserCount":0}}`,
		healthListURL: `{"value":[{"id":"health-1","displayName":"Fix Disk Space"}]}`,
		healthRunSummary1: `{"value":{"@odata.type":"#microsoft.graph.deviceHealthScriptRunSummary",
			"id":"hrs1",
			"noIssueDetectedDeviceCount":100,"issueDetectedDeviceCount":8,
			"detectionScriptErrorDeviceCount":1,"detectionScriptPendingDeviceCount":2,
			"detectionScriptNotApplicableDeviceCount":3,
			"issueRemediatedDeviceCount":6,"remediationSkippedDeviceCount":1,
			"issueReoccurredDeviceCount":1,"remediationScriptErrorDeviceCount":0,
			"issueRemediatedCumulativeDeviceCount":42}}`,
		remediationSumURL: `{"value":{"@odata.type":"microsoft.graph.deviceHealthScriptRemediationSummary",
			"scriptCount":11,"remediatedDeviceCount":5}}`,
	}}
}

func pointsByKey(pts []telemetrytest.MetricPoint, keys ...string) map[string]float64 {
	out := map[string]float64{}
	for _, p := range pts {
		vals := make([]string, len(keys))
		for i, k := range keys {
			vals[i] = p.Attrs[k]
		}
		key := ""
		for _, v := range vals {
			key += v + "/"
		}
		out[key] = p.Value
	}
	return out
}

func TestCollectEmitsScriptRunSummaryAcrossOSAndTarget(t *testing.T) {
	rec := telemetrytest.New()
	if err := New(fullFixture(), nil).Collect(context.Background(), rec.Emitter()); err != nil {
		t.Fatalf("Collect: %v", err)
	}

	pts := pointsByKey(rec.MetricPoints(scriptRunSummaryMetric), "script_name", "os", "target", "run_state")

	cases := map[string]float64{
		"Rename Local Admin/windows/device/success/": 10,
		"Rename Local Admin/windows/device/error/":   2,
		"Rename Local Admin/windows/user/error/":     1,
		"Install Rosetta/macos/device/success/":      5,
	}
	for key, want := range cases {
		if got := pts[key]; got != want {
			t.Errorf("point %q = %v, want %v", key, got, want)
		}
	}
}

func TestCollectKeepsDetectionAndRemediationPhasesSeparate(t *testing.T) {
	rec := telemetrytest.New()
	if err := New(fullFixture(), nil).Collect(context.Background(), rec.Emitter()); err != nil {
		t.Fatalf("Collect: %v", err)
	}

	pts := pointsByKey(rec.MetricPoints(remediationSummaryMetric), "script_name", "phase", "state")

	detection := map[string]float64{
		"Fix Disk Space/detection/no_issue/":       100,
		"Fix Disk Space/detection/issue_detected/": 8,
		"Fix Disk Space/detection/error/":          1,
		"Fix Disk Space/detection/pending/":        2,
		"Fix Disk Space/detection/not_applicable/": 3,
	}
	remediation := map[string]float64{
		"Fix Disk Space/remediation/remediated/": 6,
		"Fix Disk Space/remediation/skipped/":    1,
		"Fix Disk Space/remediation/reoccurred/": 1,
		"Fix Disk Space/remediation/error/":      0,
	}
	for key, want := range detection {
		if got := pts[key]; got != want {
			t.Errorf("detection point %q = %v, want %v", key, got, want)
		}
	}
	for key, want := range remediation {
		if got := pts[key]; got != want {
			t.Errorf("remediation point %q = %v, want %v", key, got, want)
		}
	}

	// A phase collapse bug would merge e.g. detection/error and
	// remediation/error into one series; assert both are present and
	// independently keyed by phase.
	if pts["Fix Disk Space/detection/error/"] == pts["Fix Disk Space/remediation/error/"] &&
		len(pts) < 9 {
		t.Error("detection and remediation phases appear collapsed")
	}
}

func TestCollectEmitsCumulativeRemediatedAsSeparateMetric(t *testing.T) {
	rec := telemetrytest.New()
	if err := New(fullFixture(), nil).Collect(context.Background(), rec.Emitter()); err != nil {
		t.Fatalf("Collect: %v", err)
	}
	pts := rec.MetricPoints(remediationCumulativeMetric)
	if len(pts) != 1 {
		t.Fatalf("cumulative points = %d, want 1", len(pts))
	}
	if pts[0].Attrs["script_name"] != "Fix Disk Space" || pts[0].Value != 42 {
		t.Errorf("cumulative point = %+v, want script_name=Fix Disk Space value=42", pts[0])
	}
}

func TestCollectEmitsRemediationOverviewCrossCheck(t *testing.T) {
	rec := telemetrytest.New()
	if err := New(fullFixture(), nil).Collect(context.Background(), rec.Emitter()); err != nil {
		t.Fatalf("Collect: %v", err)
	}
	scriptCount := rec.MetricPoints(remediationOverviewScriptCountName)
	remediated := rec.MetricPoints(remediationOverviewRemediatedName)
	if len(scriptCount) != 1 || scriptCount[0].Value != 11 {
		t.Errorf("overview script_count = %+v, want 11", scriptCount)
	}
	if len(remediated) != 1 || remediated[0].Value != 5 {
		t.Errorf("overview remediated_device_count = %+v, want 5", remediated)
	}
}

func TestCollectNeverFetchesScriptContentOrDeviceRunStates(t *testing.T) {
	// The fake only has canned bodies for the list ($select=id,displayName)
	// and runSummary URLs; any request for scriptContent or the
	// deviceRunStates collection would miss the fixture and surface as an
	// error, so a clean Collect proves those are never fetched.
	rec := telemetrytest.New()
	if err := New(fullFixture(), nil).Collect(context.Background(), rec.Emitter()); err != nil {
		t.Fatalf("Collect: %v (a request outside id/displayName + runSummary would 404 against the fixture)", err)
	}
}

func TestCollectGracefulOn403PerSurface(t *testing.T) {
	g := fullFixture()
	// Windows scripts unavailable (e.g. beta surface not licensed) - the
	// other two surfaces must still emit.
	g.errs = map[string]error{
		windowsListURL: errors.New("graphclient: GET " + windowsListURL + ": status 403: {\"error\":{\"code\":\"Authorization_RequestDenied\"}}"),
	}
	rec := telemetrytest.New()
	if err := New(g, nil).Collect(context.Background(), rec.Emitter()); err != nil {
		t.Errorf("a 403 on one surface should be skipped-and-logged, not fail Collect: %v", err)
	}
	pts := pointsByKey(rec.MetricPoints(scriptRunSummaryMetric), "script_name", "os")
	if _, ok := pts["Rename Local Admin/windows/"]; ok {
		t.Error("windows script points should be absent when the list 403s")
	}
	if _, ok := pts["Install Rosetta/macos/"]; !ok {
		t.Error("macos script points should still be emitted despite the windows 403")
	}
	if len(rec.MetricPoints(remediationSummaryMetric)) == 0 {
		t.Error("remediation summary should still be emitted despite the windows 403")
	}
}

func TestCollectSurfacesNon4xxError(t *testing.T) {
	g := fullFixture()
	g.errs = map[string]error{
		windowsListURL: errors.New("graphclient: GET " + windowsListURL + ": status 500: server error"),
	}
	rec := telemetrytest.New()
	if err := New(g, nil).Collect(context.Background(), rec.Emitter()); err == nil {
		t.Error("a 500 should surface as a collector error, not be swallowed")
	}
}

func TestNameIntervalExperimentalAndPermissions(t *testing.T) {
	c := New(&fakeGraph{}, nil)
	if c.Name() != "intune.scripts" {
		t.Errorf("Name = %q", c.Name())
	}
	if !c.Experimental() {
		t.Error("scripts is a beta collector; Experimental() must be true")
	}
	if got := c.RequiredPermissions(); len(got) != 1 || got[0] != "DeviceManagementScripts.Read.All" {
		t.Errorf("RequiredPermissions = %v", got)
	}
	if c.DefaultInterval() <= 0 {
		t.Error("DefaultInterval must be positive")
	}
}
