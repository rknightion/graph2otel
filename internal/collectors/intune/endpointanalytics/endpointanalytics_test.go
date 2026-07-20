package endpointanalytics

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/rknightion/graph2otel/internal/collectors"
	"github.com/rknightion/graph2otel/internal/semconv"
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
	deviceScoresURL = "https://graph.microsoft.com/v1.0/deviceManagement/userExperienceAnalyticsDeviceScores"
	startupURL      = "https://graph.microsoft.com/v1.0/deviceManagement/userExperienceAnalyticsDeviceStartupHistory"
	appHealthURL    = "https://graph.microsoft.com/v1.0/deviceManagement/userExperienceAnalyticsAppHealthApplicationPerformance"
	batteryURL      = "https://graph.microsoft.com/beta/deviceManagement/userExperienceAnalyticsBatteryHealthDevicePerformance"
	resourcePerfURL = "https://graph.microsoft.com/beta/deviceManagement/userExperienceAnalyticsResourcePerformance"
	baselineURL     = "https://graph.microsoft.com/beta/deviceManagement/userExperienceAnalyticsBaselines"
	anomalyURL      = "https://graph.microsoft.com/beta/deviceManagement/userExperienceAnalyticsAnomalySeverityOverview"
	wfaURL          = "https://graph.microsoft.com/beta/deviceManagement/userExperienceAnalyticsWorkFromAnywhereMetrics/allDevices/metricDevices"
	appHealthOSURL  = "https://graph.microsoft.com/v1.0/deviceManagement/userExperienceAnalyticsAppHealthOSVersionPerformance"
)

// appHealthOSLiveRow is the VERBATIM userExperienceAnalyticsAppHealthOSVersionPerformance
// row for m7kni (probed as graph2otel-poller 2026-07-20): one OS version, one active
// device, the int32-max "no failures" MTTF sentinel, a provisional "TBD" status.
const appHealthOSLiveRow = `{"id":"16863e1c-7c03-459b-85d8-88f1fe38da56","osVersion":"10.0.26120.3281","osBuildNumber":"10.0.26120","activeDeviceCount":1,"meanTimeToFailureInMinutes":2147483647,"osVersionAppHealthScore":100.0,"osVersionAppHealthStatus":"TBD"}`

// wfaLiveRow is the VERBATIM metricDevices row for LAPHAM (m7kni, probed as
// graph2otel-poller 2026-07-19): upgraded, every hardware check passed, all
// scores null (device not yet assessed). Used as the default WFA body.
const wfaLiveRow = `{"id":"d5900d67-e50c-44ef-9d5c-6a2f891099c6","deviceId":null,"deviceName":"LAPHAM","serialNumber":"PH4TRX1S2146S0097","manufacturer":"PCSpecialist","model":"Standard","ownership":"Corporate","osDescription":"Windows","osVersion":"10.0.26120.3281","upgradeEligibility":"upgraded","ramCheckFailed":false,"storageCheckFailed":false,"processorCoreCountCheckFailed":false,"processorSpeedCheckFailed":false,"tpmCheckFailed":false,"secureBootCheckFailed":false,"processorFamilyCheckFailed":false,"processor64BitCheckFailed":false,"osCheckFailed":false,"workFromAnywhereScore":null,"windowsScore":null,"cloudManagementScore":null,"cloudIdentityScore":null,"cloudProvisioningScore":null,"healthStatus":"unknown"}`

// anomalyDefaultBody is the live-verified all-zeros response of the beta
// userExperienceAnalyticsAnomalySeverityOverview SINGLETON (a flat object, not
// an odata page), used as the default so Collect's other sub-fetches don't fail
// on a missing body (live-measured 2026-07-19).
const anomalyDefaultBody = `{"lowSeverityAnomalyCount":0,"mediumSeverityAnomalyCount":0,"highSeverityAnomalyCount":0,"informationalSeverityAnomalyCount":0}`

// emptyPage is a canned empty odata page for endpoints not under test in a
// given case, so Collect's other sub-fetches don't fail on a missing body.
const emptyPage = `{"value":[]}`

// PROVENANCE (updated 2026-07-18, #179). The earlier note here claimed all six
// sub-endpoints were "not provisioned" (400) on this tenant. That was the #179
// bug seen from the test's side: two URLs were simply WRONG, so they 400'd while
// valid segments returned 200 with data. Re-probed as graph2otel-poller
// 2026-07-18 [live-measured]:
//
//   - userExperienceAnalyticsOverview — HTTP 400 "not found for segment" on BOTH
//     v1.0 and beta: a DEAD segment, removed from Graph. Replaced by
//     userExperienceAnalyticsDeviceScores (v1.0, 200 with a real device).
//   - userExperienceAnalyticsDeviceStartupHistory (SINGULAR) — HTTP 200. The
//     plural "…Histories" the collector used to call 400'd; that was a wrong
//     name, not a tenant gap.
//   - userExperienceAnalyticsDeviceScores — HTTP 200, one device with populated
//     scores incl. a -1 "not enough data" sentinel on startupPerformanceScore.
//   - appHealthApplicationPerformance (v1.0) 200 empty; batteryHealth /
//     resourcePerformance are beta-only (400 on v1.0, 200 on beta — battery had
//     a device); baselines 200 empty.
//
// The deviceScores body below is pinned to that live sample (LAPHAM). The
// live-verified reality this package now pins is the WRONG-URL path: a
// "400 not found for segment" is surfaced loudly as a graph2otel bug
// (TestCollectSurfacesWrongEndpoint400AsBug), never swallowed as a tenant gap.

func allEndpoints(overrides map[string]string) map[string]string {
	m := map[string]string{
		deviceScoresURL: `{"value":[{"endpointAnalyticsScore":80,"startupPerformanceScore":75,"appReliabilityScore":90,"workFromAnywhereScore":85,"batteryHealthScore":70,"healthStatus":"meetingGoals"}]}`,
		startupURL:      emptyPage,
		appHealthURL:    emptyPage,
		batteryURL:      emptyPage,
		resourcePerfURL: emptyPage,
		baselineURL:     emptyPage,
		anomalyURL:      anomalyDefaultBody,
		wfaURL:          `{"value":[` + wfaLiveRow + `]}`,
		appHealthOSURL:  `{"value":[` + appHealthOSLiveRow + `]}`,
	}
	for k, v := range overrides {
		m[k] = v
	}
	return m
}

// TestCollectEmitsDeviceScoresAsBoundedAggregatesExcludingSentinel pins the
// live sample (LAPHAM, m7kni, #179): per-device scores roll into a bounded
// score histogram by category and a device count by health_state - never a
// per-device series - and the -1 "not enough data" sentinel is excluded from
// the histogram so it cannot drag the distribution toward zero.
func TestCollectEmitsDeviceScoresAsBoundedAggregatesExcludingSentinel(t *testing.T) {
	body := `{"value":[
	  {"deviceName":"LAPHAM","endpointAnalyticsScore":86.62,"startupPerformanceScore":-1,"appReliabilityScore":100,"workFromAnywhereScore":96.88,"batteryHealthScore":63,"healthStatus":"meetingGoals"},
	  {"deviceName":"OTHER","endpointAnalyticsScore":40,"startupPerformanceScore":55,"appReliabilityScore":70,"workFromAnywhereScore":80,"batteryHealthScore":30,"healthStatus":"needsAttention"}
	]}`
	g := &fakeGraph{bodies: allEndpoints(map[string]string{deviceScoresURL: body})}
	rec := telemetrytest.New()

	if err := New(g, nil).Collect(context.Background(), rec.Emitter()); err != nil {
		t.Fatalf("Collect: %v", err)
	}

	// device_count is bounded by health_state, never per-device (2 devices, 2 states).
	counts := map[string]float64{}
	for _, p := range rec.MetricPoints(deviceScoreCountMetric) {
		counts[p.Attrs["health_state"]] = p.Value
	}
	if counts["meeting_goals"] != 1 || counts["needs_attention"] != 1 {
		t.Errorf("device_count by health_state = %v, want meeting_goals=1 needs_attention=1", counts)
	}

	// Score histogram is bounded by category (5), never per-device. The -1
	// sentinel is excluded: startup_performance saw one real score (55), not two.
	byCategory := map[string]uint64{}
	for _, p := range rec.MetricPoints(deviceScoreMetric) {
		byCategory[p.Attrs["category"]] += p.Count
	}
	if len(byCategory) != 5 {
		t.Fatalf("want 5 bounded score categories, got %d: %v", len(byCategory), byCategory)
	}
	if byCategory["startup_performance"] != 1 {
		t.Errorf("startup_performance observations = %d, want 1 (the -1 sentinel device excluded)", byCategory["startup_performance"])
	}
	if byCategory["endpoint_analytics"] != 2 {
		t.Errorf("endpoint_analytics observations = %d, want 2 (both devices)", byCategory["endpoint_analytics"])
	}
}

// TestDeviceScoresEmitPerDeviceLogTwinOmittingSentinel asserts the #179 twin:
// one log record per device carrying its identity + every score it actually
// reported, with the -1 "not enough data" sentinel OMITTED (never carried as
// -1). Per-entity detail belongs in a log, not a metric label (#112/#114).
func TestDeviceScoresEmitPerDeviceLogTwinOmittingSentinel(t *testing.T) {
	body := `{"value":[
	  {"id":"dev-1","deviceName":"LAPHAM","model":"Standard","manufacturer":"PCSpecialist","endpointAnalyticsScore":86.62,"startupPerformanceScore":-1,"appReliabilityScore":100,"workFromAnywhereScore":96.88,"batteryHealthScore":63,"healthStatus":"meetingGoals"},
	  {"id":"dev-2","deviceName":"OTHER","model":"XPS","manufacturer":"Dell","endpointAnalyticsScore":40,"startupPerformanceScore":55,"appReliabilityScore":70,"workFromAnywhereScore":80,"batteryHealthScore":30,"healthStatus":"needsAttention"}
	]}`
	g := &fakeGraph{bodies: allEndpoints(map[string]string{deviceScoresURL: body})}
	rec := telemetrytest.New()
	if err := New(g, nil).Collect(context.Background(), rec.Emitter()); err != nil {
		t.Fatalf("Collect: %v", err)
	}

	byDevice := map[string]telemetrytest.LogRecord{}
	for _, lr := range rec.LogRecords() {
		if lr.EventName == eventDeviceScore {
			byDevice[lr.Attrs["device_name"]] = lr
		}
	}
	if len(byDevice) != 2 {
		t.Fatalf("want 2 per-device twins, got %d", len(byDevice))
	}

	lapham, ok := byDevice["LAPHAM"]
	if !ok {
		t.Fatal("no twin for LAPHAM")
	}
	for k, want := range map[string]string{"id": "dev-1", "model": "Standard", "manufacturer": "PCSpecialist", "health_state": "meeting_goals"} {
		if lapham.Attrs[k] != want {
			t.Errorf("LAPHAM twin %s = %q, want %q", k, lapham.Attrs[k], want)
		}
	}
	if lapham.Attrs["endpoint_analytics_score"] != "86.62" {
		t.Errorf("LAPHAM twin endpoint_analytics_score = %q, want 86.62", lapham.Attrs["endpoint_analytics_score"])
	}
	if lapham.Attrs["battery_health_score"] != "63" {
		t.Errorf("LAPHAM twin battery_health_score = %q, want 63", lapham.Attrs["battery_health_score"])
	}
	if v, present := lapham.Attrs["startup_performance_score"]; present {
		t.Errorf("LAPHAM twin should OMIT the -1 startup_performance_score sentinel, got %q", v)
	}
	if other := byDevice["OTHER"]; other.Attrs["startup_performance_score"] != "55" {
		t.Errorf("OTHER twin (all scores populated) startup_performance_score = %q, want 55", other.Attrs["startup_performance_score"])
	}
}

// TestCollectTreatsInsufficientDataAsNormalNotError asserts that a device
// entirely in the insufficientData state (a new/small tenant with too little
// accumulated telemetry - all scores are the -1 sentinel) is counted as a
// normal device, never surfaced as a collector error, and contributes zero
// score-histogram observations.
func TestCollectTreatsInsufficientDataAsNormalNotError(t *testing.T) {
	body := `{"value":[{"endpointAnalyticsScore":-1,"startupPerformanceScore":-1,"appReliabilityScore":-1,"workFromAnywhereScore":-1,"batteryHealthScore":-1,"healthStatus":"insufficientData"}]}`
	g := &fakeGraph{bodies: allEndpoints(map[string]string{deviceScoresURL: body})}
	rec := telemetrytest.New()

	if err := New(g, nil).Collect(context.Background(), rec.Emitter()); err != nil {
		t.Fatalf("Collect should treat insufficientData as normal, got error: %v", err)
	}
	counts := map[string]float64{}
	for _, p := range rec.MetricPoints(deviceScoreCountMetric) {
		counts[p.Attrs["health_state"]] = p.Value
	}
	if counts["insufficient_data"] != 1 {
		t.Errorf("device_count insufficient_data = %v, want 1", counts["insufficient_data"])
	}
	if pts := rec.MetricPoints(deviceScoreMetric); len(pts) != 0 {
		t.Errorf("want no score histogram observations when every score is the -1 sentinel, got %d series", len(pts))
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

// TestCollectEmitsAppHealthOSVersionAsBoundedAggregates pins the #194 OS-version
// app-health segment: one row per OS version rolls into bounded gauges keyed by
// os_version (score, active device count, MTTF) with NO log twin (#192 — an
// OS-version aggregate, not a per-device row), the int32-max "no failures" MTTF
// sentinel is excluded, and the undocumented wire status "TBD" falls to the
// bounded "other" health_state rather than being asserted raw.
func TestCollectEmitsAppHealthOSVersionAsBoundedAggregates(t *testing.T) {
	body := `{"value":[
	  ` + appHealthOSLiveRow + `,
	  {"osVersion":"10.0.22631.1","activeDeviceCount":3,"meanTimeToFailureInMinutes":5000,"osVersionAppHealthScore":72,"osVersionAppHealthStatus":"needsAttention"}
	]}`
	g := &fakeGraph{bodies: allEndpoints(map[string]string{appHealthOSURL: body})}
	rec := telemetrytest.New()
	if err := New(g, nil).Collect(context.Background(), rec.Emitter()); err != nil {
		t.Fatalf("Collect: %v", err)
	}

	// score gauge: one point per OS version, TBD -> "other", needsAttention -> "needs_attention".
	score := map[string]telemetrytest.MetricPoint{}
	for _, p := range rec.MetricPoints(appHealthOSVersionScoreMetric) {
		score[p.Attrs["os_version"]] = p
	}
	if len(score) != 2 {
		t.Fatalf("want 2 os_version score points, got %d: %v", len(score), score)
	}
	if score["10.0.26120.3281"].Value != 100 || score["10.0.26120.3281"].Attrs["health_state"] != "other" {
		t.Errorf("live row score point = %+v, want value 100 health_state other", score["10.0.26120.3281"])
	}
	if score["10.0.22631.1"].Attrs["health_state"] != "needs_attention" {
		t.Errorf("needsAttention row health_state = %q, want needs_attention", score["10.0.22631.1"].Attrs["health_state"])
	}

	// active_device_count gauge: bounded by os_version (1 and 3).
	count := map[string]float64{}
	for _, p := range rec.MetricPoints(appHealthOSVersionCountMetric) {
		count[p.Attrs["os_version"]] = p.Value
	}
	if count["10.0.26120.3281"] != 1 || count["10.0.22631.1"] != 3 {
		t.Errorf("active_device_count by os_version = %v, want 1 and 3", count)
	}

	// MTTF gauge: ONLY the real 5000-minute row; the int32-max sentinel row is excluded.
	mttf := rec.MetricPoints(appHealthOSVersionMTTFMetric)
	if len(mttf) != 1 {
		t.Fatalf("want 1 MTTF point (sentinel row excluded), got %d: %v", len(mttf), mttf)
	}
	if mttf[0].Attrs["os_version"] != "10.0.22631.1" || mttf[0].Value != 5000 {
		t.Errorf("MTTF point = %+v, want os_version 10.0.22631.1 value 5000", mttf[0])
	}

	// No log twin from this OS-version aggregate segment.
	for _, lr := range rec.LogRecords() {
		if lr.EventName == eventDeviceScore || lr.EventName == eventWorkFromAnywhere {
			continue // twins from OTHER sub-fetches (device scores / WFA), not this one
		}
		t.Errorf("app-health-os-version segment must emit no log twin, got event %q", lr.EventName)
	}
}

// TestCollectSkipsUnavailableSubEndpointGracefully asserts a 403 on one
// sub-fetch (e.g. Intune Endpoint Analytics not licensed on this tenant) is
// skipped-and-logged, not surfaced as a collector error - while every other
// sub-fetch's metrics still emit.
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
	// The device scores (a different sub-fetch) must still have emitted.
	if len(rec.MetricPoints(deviceScoreCountMetric)) == 0 {
		t.Error("device-score metrics should still emit despite the battery sub-fetch 403ing")
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

// TestCollectSurfacesWrongEndpoint400AsBug asserts the #179 correction: a
// "400 Resource not found for segment" is a graph2otel wrong-URL BUG (the shape
// the dead overview and the plural startup-history URL used to return), not a
// tenant gap. It MUST surface as a collector error - the opposite of the old
// behavior that swallowed it as "feature not provisioned" and hid two dead
// URLs for the life of the collector.
func TestCollectSurfacesWrongEndpoint400AsBug(t *testing.T) {
	g := &fakeGraph{bodies: allEndpoints(nil)}
	g.errs = map[string]error{
		deviceScoresURL: errors.New(`graphclient: GET ` + deviceScoresURL + `: status 400: {"error":{"code":"ResourceNotFound","message":"Resource not found for segment 'userExperienceAnalyticsDeviceScores'."}}`),
	}
	rec := telemetrytest.New()

	if err := New(g, nil).Collect(context.Background(), rec.Emitter()); err == nil {
		t.Error("a 400 'not found for segment' is a wrong-URL bug and must surface, not be swallowed as a tenant gap")
	}
	if len(rec.MetricPoints(deviceScoreCountMetric)) != 0 {
		t.Error("no device-score metrics should be emitted when the device-scores fetch errors")
	}
	// A different sub-fetch (baselines, empty) still ran without error.
	if len(rec.MetricPoints(baselineScoreMetric)) != 0 {
		t.Error("baselines had no data in this case; expected no points")
	}
}

// TestCollectSurfacesPlainMalformed400 asserts a 400 that is NOT a route-segment
// error (e.g. a genuinely malformed query) also surfaces as a real collector
// error - the else branch is loud too, so only a 403 is ever a quiet skip.
func TestCollectSurfacesPlainMalformed400(t *testing.T) {
	g := &fakeGraph{bodies: allEndpoints(nil)}
	g.errs = map[string]error{
		deviceScoresURL: errors.New(`graphclient: GET ` + deviceScoresURL + `: status 400: {"error":{"code":"BadRequest","message":"Invalid filter clause"}}`),
	}
	rec := telemetrytest.New()

	if err := New(g, nil).Collect(context.Background(), rec.Emitter()); err == nil {
		t.Error("a plain malformed-query 400 should surface as a collector error, not be swallowed")
	}
}

// TestCollectEmitsAnomalyCountBySeverity pins the beta anomaly-severity
// overview SINGLETON (live-measured 2026-07-19): a single flat JSON object of
// four int counts rolls into exactly 4 gauge points, one per bounded
// anomaly_severity (low/medium/high/informational), values straight from the
// four fields. Exercised with both the all-zeros live sample and a non-zero
// variant. No log twin - this is an aggregate singleton with no per-entity rows.
func TestCollectEmitsAnomalyCountBySeverity(t *testing.T) {
	for _, tc := range []struct {
		name string
		body string
		want map[string]float64
	}{
		{
			"all-zero live sample",
			`{"lowSeverityAnomalyCount":0,"mediumSeverityAnomalyCount":0,"highSeverityAnomalyCount":0,"informationalSeverityAnomalyCount":0}`,
			map[string]float64{"low": 0, "medium": 0, "high": 0, "informational": 0},
		},
		{
			"non-zero variant",
			`{"lowSeverityAnomalyCount":2,"mediumSeverityAnomalyCount":0,"highSeverityAnomalyCount":1,"informationalSeverityAnomalyCount":0}`,
			map[string]float64{"low": 2, "medium": 0, "high": 1, "informational": 0},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			g := &fakeGraph{bodies: allEndpoints(map[string]string{anomalyURL: tc.body})}
			rec := telemetrytest.New()

			if err := New(g, nil).Collect(context.Background(), rec.Emitter()); err != nil {
				t.Fatalf("Collect: %v", err)
			}

			got := map[string]float64{}
			for _, p := range rec.MetricPoints(anomalyCountMetric) {
				got[p.Attrs["anomaly_severity"]] = p.Value
			}
			if len(got) != 4 {
				t.Fatalf("want exactly 4 bounded anomaly_severity points, got %d: %v", len(got), got)
			}
			for sev, want := range tc.want {
				if got[sev] != want {
					t.Errorf("anomaly_count[%s] = %v, want %v", sev, got[sev], want)
				}
			}
		})
	}
}

// TestCollectSkipsUnavailableAnomalyOverviewGracefully asserts the anomaly
// overview sub-fetch uses the SAME shared skip-and-log path the other beta
// sub-fetches use: a 403 (Endpoint Analytics not licensed on this tenant) is
// skipped-and-logged, not surfaced as a collector error, while every other
// sub-fetch's metrics still emit.
func TestCollectSkipsUnavailableAnomalyOverviewGracefully(t *testing.T) {
	g := &fakeGraph{bodies: allEndpoints(nil)}
	g.errs = map[string]error{
		anomalyURL: errors.New("graphclient: GET " + anomalyURL + ": status 403: forbidden"),
	}
	rec := telemetrytest.New()

	if err := New(g, nil).Collect(context.Background(), rec.Emitter()); err != nil {
		t.Errorf("a 403 on the anomaly overview should be skipped, not surfaced: %v", err)
	}
	if len(rec.MetricPoints(anomalyCountMetric)) != 0 {
		t.Error("no anomaly metrics should be emitted when the endpoint 403s")
	}
	// A different sub-fetch (device scores) must still have emitted.
	if len(rec.MetricPoints(deviceScoreCountMetric)) == 0 {
		t.Error("device-score metrics should still emit despite the anomaly sub-fetch 403ing")
	}
}

// wfaNotCapableRow is a SYNTHETIC metricDevices row (the tenant has no notCapable
// device to capture) exercising the failed-check + WARN path: the fields and
// their types are live-verified from wfaLiveRow, only the values are set to a
// failing profile (tpm + secure boot failed, notCapable).
const wfaNotCapableRow = `{"id":"9999","deviceName":"OLDBOX","serialNumber":"SN9","manufacturer":"Acme","model":"Pentium","ownership":"Personal","osDescription":"Windows","osVersion":"10.0.19045","upgradeEligibility":"notCapable","ramCheckFailed":false,"storageCheckFailed":false,"processorCoreCountCheckFailed":false,"processorSpeedCheckFailed":false,"tpmCheckFailed":true,"secureBootCheckFailed":true,"processorFamilyCheckFailed":true,"processor64BitCheckFailed":false,"osCheckFailed":false,"workFromAnywhereScore":42,"windowsScore":30,"cloudManagementScore":null,"cloudIdentityScore":null,"cloudProvisioningScore":null,"healthStatus":"needsAttention"}`

// TestCollectWorkFromAnywhereReadiness pins the #194 Win11 upgrade-readiness
// signal: a bounded device count by (upgrade_eligibility, health_state); a clean
// device's twin carries NO *_check_failed attribute and omits null scores; a
// notCapable device is WARN and lists exactly its failed checks plus its
// populated scores.
func TestCollectWorkFromAnywhereReadiness(t *testing.T) {
	g := &fakeGraph{bodies: allEndpoints(map[string]string{
		wfaURL: `{"value":[` + wfaLiveRow + `,` + wfaNotCapableRow + `]}`,
	})}
	rec := telemetrytest.New()
	if err := New(g, nil).Collect(context.Background(), rec.Emitter()); err != nil {
		t.Fatalf("Collect: %v", err)
	}

	// Gauge: two distinct (eligibility, state) buckets, one device each.
	type key struct{ elig, state string }
	got := map[key]float64{}
	for _, p := range rec.MetricPoints(wfaDeviceCountMetric) {
		got[key{p.Attrs[semconv.AttrUpgradeEligibility], p.Attrs[semconv.AttrHealthState]}] = p.Value
	}
	if got[key{"upgraded", "unknown"}] != 1 || got[key{"notCapable", "needs_attention"}] != 1 {
		t.Errorf("wfa device_count = %+v, want upgraded/unknown:1 notCapable/needs_attention:1", got)
	}

	byDevice := map[string]telemetrytest.LogRecord{}
	for _, l := range rec.LogRecords() {
		if l.EventName == eventWorkFromAnywhere {
			byDevice[l.Attrs[semconv.AttrDeviceName]] = l
		}
	}
	clean, ok := byDevice["LAPHAM"]
	if !ok {
		t.Fatalf("no WFA twin for LAPHAM")
	}
	if clean.Attrs[semconv.AttrUpgradeEligibility] != "upgraded" {
		t.Errorf("LAPHAM upgrade_eligibility = %q", clean.Attrs[semconv.AttrUpgradeEligibility])
	}
	// A clean device carries no failed-check attribute at all, and no null score.
	for _, k := range []string{
		semconv.AttrTpmCheckFailed, semconv.AttrSecureBootCheckFailed, semconv.AttrRamCheckFailed,
		semconv.AttrWorkFromAnywhereScore, semconv.AttrWindowsScore,
	} {
		if v, present := clean.Attrs[k]; present {
			t.Errorf("clean device emitted %q = %q, want omitted", k, v)
		}
	}
	if clean.SeverityText != "INFO" {
		t.Errorf("clean device severity = %q, want INFO", clean.SeverityText)
	}

	bad := byDevice["OLDBOX"]
	if bad.SeverityText != "WARN" {
		t.Errorf("notCapable device severity = %q, want WARN", bad.SeverityText)
	}
	// Exactly the failed checks are present; a passed one is absent.
	for _, k := range []string{semconv.AttrTpmCheckFailed, semconv.AttrSecureBootCheckFailed, semconv.AttrProcessorFamilyCheckFailed} {
		if bad.Attrs[k] != "true" {
			t.Errorf("notCapable device %q = %q, want \"true\"", k, bad.Attrs[k])
		}
	}
	if _, present := bad.Attrs[semconv.AttrRamCheckFailed]; present {
		t.Errorf("passed ram check should be omitted, got %q", bad.Attrs[semconv.AttrRamCheckFailed])
	}
	// Populated scores emit; null ones are omitted.
	if bad.Attrs[semconv.AttrWorkFromAnywhereScore] != "42" {
		t.Errorf("work_from_anywhere_score = %q, want 42", bad.Attrs[semconv.AttrWorkFromAnywhereScore])
	}
	if _, present := bad.Attrs[semconv.AttrCloudIdentityScore]; present {
		t.Error("null cloud_identity_score should be omitted")
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
