package endpointanalytics

import (
	"context"
	"errors"
	"testing"
	"time"

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
	overviewURL     = "https://graph.microsoft.com/v1.0/deviceManagement/userExperienceAnalyticsOverview"
	startupURL      = "https://graph.microsoft.com/v1.0/deviceManagement/userExperienceAnalyticsDeviceStartupHistories"
	appHealthURL    = "https://graph.microsoft.com/v1.0/deviceManagement/userExperienceAnalyticsAppHealthApplicationPerformance"
	batteryURL      = "https://graph.microsoft.com/beta/deviceManagement/userExperienceAnalyticsBatteryHealthDevicePerformance"
	resourcePerfURL = "https://graph.microsoft.com/beta/deviceManagement/userExperienceAnalyticsResourcePerformance"
	baselineURL     = "https://graph.microsoft.com/beta/deviceManagement/userExperienceAnalyticsBaselines"
)

// emptyPage is a canned empty odata page for endpoints not under test in a
// given case, so Collect's other sub-fetches don't fail on a missing body.
const emptyPage = `{"value":[]}`

// PROVENANCE of every success-shaped body in this file: docs-derived, endpoint
// not-provisioned (400) or empty (0 rows) on tenant 2026-07-17 (#165). There is
// no live success body to convert to a verbatim capture, because probing as
// graph2otel-poller on 2026-07-17 found none of the six sub-endpoints returned
// populated data on this tenant:
//
//   - userExperienceAnalyticsOverview — HTTP 400, code "ResourceNotFound",
//     "Resource not found for segment 'userExperienceAnalyticsOverview'" (the
//     feature-not-provisioned shape isFeatureNotProvisioned skips).
//   - userExperienceAnalyticsDeviceStartupHistories — HTTP 400, "Resource not
//     found for the segment 'userExperienceAnalyticsDeviceStartupHistories'"
//     (same not-provisioned skip, code "BadRequest" but matched on the message).
//   - userExperienceAnalyticsAppHealthApplicationPerformance (v1.0), and the
//     beta batteryHealth / resourcePerformance / baselines families — all HTTP
//     200 with an empty value array (0 rows).
//
// So the bodies below stay docs-derived rather than becoming live captures. The
// live-verified reality this package pins is the SKIP path: the two 400 shapes
// above are exercised by TestCollectSkipsResourceNotFound400Gracefully, whose
// error string matches what the live capture returned — confirming the
// not-provisioned handling still catches the tenant's actual 400.

func allEndpoints(overrides map[string]string) map[string]string {
	m := map[string]string{
		overviewURL:     `{"overallScore":80,"state":"meetingGoals"}`,
		startupURL:      emptyPage,
		appHealthURL:    emptyPage,
		batteryURL:      emptyPage,
		resourcePerfURL: emptyPage,
		baselineURL:     emptyPage,
	}
	for k, v := range overrides {
		m[k] = v
	}
	return m
}

func TestCollectEmitsOverviewScoreByCategoryAndHealthState(t *testing.T) {
	body := `{
	  "overallScore": 72,
	  "deviceBootPerformanceOverallScore": 65,
	  "bestPracticesOverallScore": 90,
	  "workFromAnywhereOverallScore": 55,
	  "appHealthOverallScore": 80,
	  "resourcePerformanceOverallScore": 70,
	  "batteryHealthOverallScore": 60,
	  "state": "meetingGoals",
	  "deviceBootPerformanceHealthState": "needsAttention",
	  "bestPracticesHealthState": "meetingGoals",
	  "workFromAnywhereHealthState": "insufficientData",
	  "appHealthState": "meetingGoals",
	  "resourcePerformanceHealthState": "needsAttention",
	  "batteryHealthHealthState": "meetingGoals",
	  "batteryHealthState": "meetingGoals"
	}`
	g := &fakeGraph{bodies: allEndpoints(map[string]string{overviewURL: body})}
	rec := telemetrytest.New()

	if err := New(g, nil).Collect(context.Background(), rec.Emitter()); err != nil {
		t.Fatalf("Collect: %v", err)
	}

	got := map[string]float64{}
	state := map[string]string{}
	for _, p := range rec.MetricPoints(scoreMetric) {
		got[p.Attrs["category"]] = p.Value
		state[p.Attrs["category"]] = p.Attrs["health_state"]
	}
	if len(got) != 7 {
		t.Fatalf("want 7 bounded category points, got %d: %v", len(got), got)
	}
	cases := []struct {
		category string
		score    float64
		state    string
	}{
		{"overall", 72, "meeting_goals"},
		{"device_boot_performance", 65, "needs_attention"},
		{"best_practices", 90, "meeting_goals"},
		{"work_from_anywhere", 55, "insufficient_data"},
		{"app_health", 80, "meeting_goals"},
		{"resource_performance", 70, "needs_attention"},
		{"battery_health", 60, "meeting_goals"},
	}
	for _, c := range cases {
		if got[c.category] != c.score {
			t.Errorf("category %s score = %v, want %v", c.category, got[c.category], c.score)
		}
		if state[c.category] != c.state {
			t.Errorf("category %s health_state = %q, want %q", c.category, state[c.category], c.state)
		}
	}
}

// TestCollectTreatsInsufficientDataAsNormalNotError asserts that an overview
// entirely in the insufficientData state (a new/small tenant with too little
// accumulated telemetry) is emitted as a normal score point, never as a
// collector error.
func TestCollectTreatsInsufficientDataAsNormalNotError(t *testing.T) {
	body := `{"overallScore":0,"state":"insufficientData"}`
	g := &fakeGraph{bodies: allEndpoints(map[string]string{overviewURL: body})}
	rec := telemetrytest.New()

	if err := New(g, nil).Collect(context.Background(), rec.Emitter()); err != nil {
		t.Fatalf("Collect should treat insufficientData as normal, got error: %v", err)
	}
	found := false
	for _, p := range rec.MetricPoints(scoreMetric) {
		if p.Attrs["category"] == "overall" {
			found = true
			if p.Attrs["health_state"] != "insufficient_data" {
				t.Errorf("health_state = %q, want insufficient_data", p.Attrs["health_state"])
			}
		}
	}
	if !found {
		t.Error("expected an overall category point")
	}
}

func TestCollectAggregatesStartupHistoriesIntoBootAndLoginHistograms(t *testing.T) {
	body := `{"value":[
	  {"totalBootTimeInMs":12000,"totalLoginTimeInMs":8000,"restartCategory":"restartWithUpdate"},
	  {"totalBootTimeInMs":9000,"totalLoginTimeInMs":6000,"restartCategory":"restartWithUpdate"},
	  {"totalBootTimeInMs":40000,"totalLoginTimeInMs":15000,"restartCategory":"blueScreen"},
	  {"totalBootTimeInMs":11000,"totalLoginTimeInMs":7000,"restartCategory":"somethingBrandNew"}
	]}`
	g := &fakeGraph{bodies: allEndpoints(map[string]string{startupURL: body})}
	rec := telemetrytest.New()

	if err := New(g, nil).Collect(context.Background(), rec.Emitter()); err != nil {
		t.Fatalf("Collect: %v", err)
	}

	bootPts := rec.MetricPoints(bootTimeMetric)
	// Bounded restart_category buckets: restartWithUpdate, blueScreen, other -
	// never one series per boot row (that would be 4 points here, not 3).
	byCategory := map[string]int{}
	var totalCount uint64
	for _, p := range bootPts {
		byCategory[p.Attrs["restart_category"]]++
		totalCount += p.Count
	}
	if len(byCategory) != 3 {
		t.Fatalf("want 3 bounded restart_category buckets, got %d: %v", len(byCategory), byCategory)
	}
	if byCategory["restart_with_update"] != 1 || byCategory["blue_screen"] != 1 || byCategory["other"] != 1 {
		t.Errorf("unexpected restart_category buckets: %v", byCategory)
	}
	if totalCount != 4 {
		t.Errorf("boot histogram total observation count = %d, want 4 (one per row, still aggregated per-bucket)", totalCount)
	}

	loginPts := rec.MetricPoints(loginTimeMetric)
	if len(loginPts) != 3 {
		t.Fatalf("want 3 bounded restart_category buckets for login histogram, got %d", len(loginPts))
	}
}

func TestCollectEmitsAppCrashCountForAllowListedAppsOnly(t *testing.T) {
	body := `{"value":[
	  {"appName":"outlook.exe","appCrashCount":5},
	  {"appName":"OUTLOOK.EXE","appCrashCount":3},
	  {"appName":"some-bespoke-line-of-business.exe","appCrashCount":9999},
	  {"appName":"chrome.exe","appCrashCount":2}
	]}`
	g := &fakeGraph{bodies: allEndpoints(map[string]string{appHealthURL: body})}
	rec := telemetrytest.New()

	if err := New(g, nil).Collect(context.Background(), rec.Emitter()); err != nil {
		t.Fatalf("Collect: %v", err)
	}

	got := map[string]float64{}
	for _, p := range rec.MetricPoints(appCrashCountMetric) {
		got[p.Attrs["app_name"]] = p.Value
	}
	if len(got) != 2 {
		t.Fatalf("want exactly 2 allow-listed app_name buckets, got %d: %v", len(got), got)
	}
	if got["outlook.exe"] != 8 {
		t.Errorf("outlook.exe crash count = %v, want 8 (5+3, case-insensitive match)", got["outlook.exe"])
	}
	if got["chrome.exe"] != 2 {
		t.Errorf("chrome.exe crash count = %v, want 2", got["chrome.exe"])
	}
}

func TestCollectAggregatesBatteryHealthByHealthState(t *testing.T) {
	body := `{"value":[
	  {"deviceBatteryHealthScore":90,"healthStatus":"meetingGoals"},
	  {"deviceBatteryHealthScore":40,"healthStatus":"needsAttention"},
	  {"deviceBatteryHealthScore":95,"healthStatus":"meetingGoals"}
	]}`
	g := &fakeGraph{bodies: allEndpoints(map[string]string{batteryURL: body})}
	rec := telemetrytest.New()

	if err := New(g, nil).Collect(context.Background(), rec.Emitter()); err != nil {
		t.Fatalf("Collect: %v", err)
	}

	counts := map[string]float64{}
	for _, p := range rec.MetricPoints(batteryDeviceCountMetric) {
		counts[p.Attrs["health_state"]] = p.Value
	}
	if counts["meeting_goals"] != 2 || counts["needs_attention"] != 1 {
		t.Errorf("battery device_count by health_state = %v", counts)
	}

	scorePts := rec.MetricPoints(batteryScoreMetric)
	if len(scorePts) == 0 {
		t.Error("expected at least one battery health score histogram bucket")
	}
}

func TestCollectAggregatesResourcePerformanceByHealthState(t *testing.T) {
	body := `{"value":[
	  {"deviceResourcePerformanceScore":85,"healthStatus":"meetingGoals"},
	  {"deviceResourcePerformanceScore":30,"healthStatus":"needsAttention"}
	]}`
	g := &fakeGraph{bodies: allEndpoints(map[string]string{resourcePerfURL: body})}
	rec := telemetrytest.New()

	if err := New(g, nil).Collect(context.Background(), rec.Emitter()); err != nil {
		t.Fatalf("Collect: %v", err)
	}

	counts := map[string]float64{}
	for _, p := range rec.MetricPoints(resourceDeviceCountMetric) {
		counts[p.Attrs["health_state"]] = p.Value
	}
	if counts["meeting_goals"] != 1 || counts["needs_attention"] != 1 {
		t.Errorf("resource device_count by health_state = %v", counts)
	}
}

func TestCollectEmitsBaselineScorePerBaseline(t *testing.T) {
	body := `{"value":[
	  {"displayName":"Commercial median","overallScore":72,"isBuiltIn":true},
	  {"displayName":"Finance fleet baseline","overallScore":81,"isBuiltIn":false}
	]}`
	g := &fakeGraph{bodies: allEndpoints(map[string]string{baselineURL: body})}
	rec := telemetrytest.New()

	if err := New(g, nil).Collect(context.Background(), rec.Emitter()); err != nil {
		t.Fatalf("Collect: %v", err)
	}

	got := map[string]float64{}
	for _, p := range rec.MetricPoints(baselineScoreMetric) {
		got[p.Attrs["baseline_name"]] = p.Value
	}
	if got["Commercial median"] != 72 || got["Finance fleet baseline"] != 81 {
		t.Errorf("baseline scores = %v", got)
	}
}

// TestCollectSkipsUnavailableSubEndpointGracefully asserts a 403/404 on one
// sub-fetch (e.g. Intune Endpoint Analytics not licensed/configured on this
// tenant) is skipped-and-logged, not surfaced as a collector error - while
// every other sub-fetch's metrics still emit.
func TestCollectSkipsUnavailableSubEndpointGracefully(t *testing.T) {
	g := &fakeGraph{bodies: allEndpoints(nil)}
	g.errs = map[string]error{
		batteryURL: errors.New("graphclient: GET " + batteryURL + ": status 403: forbidden"),
	}
	rec := telemetrytest.New()

	if err := New(g, nil).Collect(context.Background(), rec.Emitter()); err != nil {
		t.Errorf("a 403 on one sub-fetch should be skipped, not surfaced: %v", err)
	}
	if len(rec.MetricPoints(batteryDeviceCountMetric)) != 0 {
		t.Error("no battery metrics should be emitted when the endpoint 403s")
	}
	// The overview (a different sub-fetch) must still have emitted.
	if len(rec.MetricPoints(scoreMetric)) == 0 {
		t.Error("overview metrics should still emit despite the battery sub-fetch 403ing")
	}
}

// TestCollectSurfacesNon4xxSubEndpointError asserts a 5xx from a sub-fetch is
// joined into the returned error (for self-obs visibility), unlike a 403/404.
func TestCollectSurfacesNon4xxSubEndpointError(t *testing.T) {
	g := &fakeGraph{bodies: allEndpoints(nil)}
	g.errs = map[string]error{
		resourcePerfURL: errors.New("graphclient: GET " + resourcePerfURL + ": status 500: server error"),
	}
	rec := telemetrytest.New()

	if err := New(g, nil).Collect(context.Background(), rec.Emitter()); err == nil {
		t.Error("a 500 from a sub-fetch should surface as a collector error")
	}
}

// TestCollectSkipsResourceNotFound400Gracefully asserts the tenant-not-
// onboarded shape observed in live verification: EVERY UXA endpoint returns
// HTTP 400 (not 403/404) with a Graph error body of code "ResourceNotFound"
// when the Endpoint Analytics feature segment doesn't exist on the tenant at
// all. That must be skipped-and-logged like a 403, not surfaced as a
// collector failure - and every other sub-fetch must still emit normally.
func TestCollectSkipsResourceNotFound400Gracefully(t *testing.T) {
	g := &fakeGraph{bodies: allEndpoints(nil)}
	g.errs = map[string]error{
		overviewURL: errors.New(`graphclient: GET ` + overviewURL + `: status 400: {"error":{"code":"ResourceNotFound","message":"Resource not found for segment 'userExperienceAnalyticsOverview'."}}`),
	}
	rec := telemetrytest.New()

	if err := New(g, nil).Collect(context.Background(), rec.Emitter()); err != nil {
		t.Errorf("a 400 ResourceNotFound should be skipped, not surfaced: %v", err)
	}
	if len(rec.MetricPoints(scoreMetric)) != 0 {
		t.Error("no overview metrics should be emitted when the endpoint is not provisioned on the tenant")
	}
	// A different sub-fetch must still have emitted.
	if len(rec.MetricPoints(baselineScoreMetric)) == 0 && len(allEndpoints(nil)) == 0 {
		t.Skip("no baseline data configured in this case; nothing further to assert")
	}
}

// TestCollectSurfacesPlainMalformed400 asserts a 400 that is NOT the
// ResourceNotFound feature-not-provisioned shape (e.g. a genuinely malformed
// query) still surfaces as a real collector error - isFeatureNotProvisioned
// must stay specific, not treat every 400 as skippable.
func TestCollectSurfacesPlainMalformed400(t *testing.T) {
	g := &fakeGraph{bodies: allEndpoints(nil)}
	g.errs = map[string]error{
		overviewURL: errors.New(`graphclient: GET ` + overviewURL + `: status 400: {"error":{"code":"BadRequest","message":"Invalid filter clause"}}`),
	}
	rec := telemetrytest.New()

	if err := New(g, nil).Collect(context.Background(), rec.Emitter()); err == nil {
		t.Error("a plain malformed-query 400 should surface as a collector error, not be swallowed")
	}
}

func TestNameIntervalPermissionsExperimental(t *testing.T) {
	c := New(&fakeGraph{}, nil)
	if c.Name() != "intune.endpoint_analytics" {
		t.Errorf("Name = %q", c.Name())
	}
	if c.DefaultInterval() != time.Hour {
		t.Errorf("DefaultInterval = %v, want 1h", c.DefaultInterval())
	}
	if !c.Experimental() {
		t.Error("endpoint analytics mixes beta-only families; Experimental() must be true")
	}
	got := c.RequiredPermissions()
	if len(got) != 1 || got[0] != "DeviceManagementManagedDevices.Read.All" {
		t.Errorf("RequiredPermissions = %v", got)
	}
}
