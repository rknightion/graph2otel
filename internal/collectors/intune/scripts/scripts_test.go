package scripts

import (
	"context"
	_ "embed"
	"errors"
	"testing"

	"github.com/rknightion/graph2otel/internal/collectors"
	"github.com/rknightion/graph2otel/internal/telemetrytest"
)

type fakeGraph struct {
	bodies map[string]string
	errs   map[string]error
	seen   []string
}

func (f *fakeGraph) RawGet(ctx context.Context, url string) ([]byte, error) {
	return f.RawGetWithHeaders(ctx, url, nil)
}

func (f *fakeGraph) RawGetWithHeaders(_ context.Context, url string, _ map[string]string) ([]byte, error) {
	f.seen = append(f.seen, url)
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
// surfaces plus the tenant-wide remediation overview singleton.
//
// WARNING: the runSummary / getRemediationSummary bodies here are wrapped in a
// bare {"value":{…}} object to match the collector's scriptRunSummaryEnvelope /
// healthScriptRunSummaryEnvelope / remediationOverviewEnvelope decode structs.
// That wrapper is DOCS-DERIVED, not the live wire shape. The real endpoints
// return the runSummary/remediationSummary fields at the TOP LEVEL of the body
// (an OData $entity), with no "value" wrapper — see the verbatim captures in
// TestCollectAgainstLiveCapturesExposesRunSummaryEnvelopeDefect. These
// synthetic fixtures still earn their keep: with distinct non-zero counts they
// pin the field→attribute wiring (which count lands on which os/target/phase/
// state), which the all-zero live tenant cannot exercise. But they do NOT prove
// the envelope decode is correct — and it is not (#165 finding).
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

// Verbatim live captures, read as graph2otel-poller against the m7kni tenant on
// 2026-07-17 `[live-measured 2026-07-17, #165]`, one file per exact beta
// endpoint this collector polls:
//
//	live-deviceManagementScripts-empty.json  GET /beta/deviceManagement/deviceManagementScripts?$select=id,displayName
//	live-deviceShellScripts.json             GET /beta/deviceManagement/deviceShellScripts?$select=id,displayName
//	live-deviceHealthScripts.json            GET /beta/deviceManagement/deviceHealthScripts?$select=id,displayName
//	live-healthScript-runSummary.json        GET /beta/deviceManagement/deviceHealthScripts/{id}/runSummary
//	live-remediationSummary.json             GET /beta/deviceManagement/deviceHealthScripts/getRemediationSummary
//
// They replace the hand-written {"value":{…}}-wrapped fixtures docs said the
// runSummary singletons return. The Windows (deviceManagementScripts) surface
// is genuinely empty on this tenant — the capture is a real empty page, kept as
// the pinned empty-shape rather than deleted. Only the FIRST health script's
// runSummary was captured; the other list rows exercise the collector's
// per-item skip path.
var (
	//go:embed testdata/live-deviceManagementScripts-empty.json
	liveWindowsScriptsEmpty string
	//go:embed testdata/live-deviceShellScripts.json
	liveShellScriptsList string
	//go:embed testdata/live-deviceHealthScripts.json
	liveHealthScriptsList string
	//go:embed testdata/live-healthScript-runSummary.json
	liveHealthRunSummary string
	//go:embed testdata/live-remediationSummary.json
	liveRemediationSummary string
)

// firstHealthScriptID is the id of the one health script whose runSummary was
// captured (its displayName is "Restart stopped Office C2R svc").
const firstHealthScriptID = "02a4e7e8-195a-4824-8044-08b3a7f2d555"

// TestCollectAgainstLiveCapturesExposesRunSummaryEnvelopeDefect drives the
// VERBATIM live captures through the real Collect path and pins what the
// collector ACTUALLY emits from them.
//
// It documents a live-measured defect (#165): every runSummary /
// getRemediationSummary count decodes to ZERO, because the collector wraps the
// decode in a {"value":{…}} envelope (scripts.go scriptRunSummaryEnvelope /
// healthScriptRunSummaryEnvelope / remediationOverviewEnvelope) but the live
// singletons return their fields at the TOP LEVEL of the body — there is no
// "value" key to descend into, so json leaves the inner struct zero-valued.
//
//   - live-healthScript-runSummary.json carries noIssueDetectedDeviceCount=3 on
//     the wire; the emitted detection/no_issue point is 0.
//   - live-remediationSummary.json carries scriptCount=12 on the wire; the
//     emitted overview script_count is 0.
//
// This test asserts those ZEROS on purpose: it is the regression pin for the
// defect, not an endorsement of it. When the envelope decode is corrected, this
// test SHOULD fail and be updated to the real wire counts. The attribute-KEY
// set is still asserted in full (independent of the broken values), so the
// field→attribute wiring stays covered here too.
func TestCollectAgainstLiveCapturesExposesRunSummaryEnvelopeDefect(t *testing.T) {
	healthRunSummaryURL := "https://graph.microsoft.com/beta/deviceManagement/deviceHealthScripts/" + firstHealthScriptID + "/runSummary"
	g := &fakeGraph{bodies: map[string]string{
		windowsListURL:      liveWindowsScriptsEmpty,
		macListURL:          liveShellScriptsList,
		healthListURL:       liveHealthScriptsList,
		healthRunSummaryURL: liveHealthRunSummary,
		remediationSumURL:   liveRemediationSummary,
		// The other four health scripts' and all five shell scripts' runSummary
		// singletons were not captured; the fake answers them with "no canned
		// body", which the collector treats as a per-item skip (logged, joined
		// into nothing) — proving Collect stays green when a sub-fetch is
		// unavailable.
	}}
	rec := telemetrytest.New()

	if err := New(g, nil).Collect(context.Background(), rec.Emitter()); err != nil {
		t.Fatalf("Collect against live captures: %v", err)
	}

	// The verbatim 5-row deviceShellScripts list really was parsed: the collector
	// fanned out a runSummary GET to each mac script id.
	const firstMacRunSummaryURL = "https://graph.microsoft.com/beta/deviceManagement/deviceShellScripts/2c30f225-b8d1-4112-b689-6c41bc5affcf/runSummary"
	sawMacRunSummary := false
	for _, u := range g.seen {
		if u == firstMacRunSummaryURL {
			sawMacRunSummary = true
		}
	}
	if !sawMacRunSummary {
		t.Errorf("collector never requested %s; the verbatim deviceShellScripts list was not parsed", firstMacRunSummaryURL)
	}

	// Windows scripts are empty on this tenant, and no mac runSummary was
	// captured, so the run_summary metric emits no points.
	if pts := rec.MetricPoints(scriptRunSummaryMetric); len(pts) != 0 {
		t.Errorf("run_summary points = %d, want 0 (windows empty, mac runSummaries uncaptured), got %+v", len(pts), pts)
	}

	// The one captured health-script runSummary emits its full 9 (phase,state)
	// point set — correct KEYS — but every VALUE is 0 due to the envelope defect.
	rem := pointsByKey(rec.MetricPoints(remediationSummaryMetric), "script_name", "phase", "state")
	wantKeys := []string{
		"Restart stopped Office C2R svc/detection/no_issue/",
		"Restart stopped Office C2R svc/detection/issue_detected/",
		"Restart stopped Office C2R svc/detection/error/",
		"Restart stopped Office C2R svc/detection/pending/",
		"Restart stopped Office C2R svc/detection/not_applicable/",
		"Restart stopped Office C2R svc/remediation/remediated/",
		"Restart stopped Office C2R svc/remediation/skipped/",
		"Restart stopped Office C2R svc/remediation/reoccurred/",
		"Restart stopped Office C2R svc/remediation/error/",
	}
	for _, k := range wantKeys {
		v, ok := rem[k]
		if !ok {
			t.Errorf("remediation.summary missing point %q", k)
			continue
		}
		// DEFECT (#165): the wire body carries noIssueDetectedDeviceCount=3, but
		// the {"value":{…}} envelope decode never reaches it, so this is 0.
		if v != 0 {
			t.Errorf("remediation.summary %q = %v; live captures currently decode to 0 via the envelope defect — if this is now non-zero the decode was fixed, update this pin", k, v)
		}
	}

	// The 30-day cumulative point for the captured script — also 0 via the defect.
	cum := rec.MetricPoints(remediationCumulativeMetric)
	if len(cum) != 1 || cum[0].Attrs["script_name"] != "Restart stopped Office C2R svc" || cum[0].Value != 0 {
		t.Errorf("cumulative = %+v, want one point for the captured script, value 0 (envelope defect)", cum)
	}

	// getRemediationSummary cross-check: wire scriptCount=12, remediatedDeviceCount=0;
	// both emit 0 through the same envelope defect.
	sc := rec.MetricPoints(remediationOverviewScriptCountName)
	if len(sc) != 1 || sc[0].Value != 0 {
		t.Errorf("overview script_count = %+v; wire carried scriptCount=12 but the envelope defect emits 0 — a non-zero here means the decode was fixed, update this pin", sc)
	}
	rd := rec.MetricPoints(remediationOverviewRemediatedName)
	if len(rd) != 1 || rd[0].Value != 0 {
		t.Errorf("overview remediated_device_count = %+v, want one point value 0", rd)
	}
}
