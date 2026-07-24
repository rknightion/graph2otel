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
	appHealthDevURL = "https://graph.microsoft.com/beta/deviceManagement/userExperienceAnalyticsAppHealthDevicePerformance"
	startupProcURL  = "https://graph.microsoft.com/beta/deviceManagement/userExperienceAnalyticsDeviceStartupProcesses"
	modelScoresURL  = "https://graph.microsoft.com/v1.0/deviceManagement/userExperienceAnalyticsModelScores"
)

// modelScoresLiveRow is the VERBATIM userExperienceAnalyticsModelScores row m7kni
// published on 2026-07-24 (probed as graph2otel-poller), the first row that
// segment has ever returned on the tenant. Note modelDeviceCount:1 — a
// SINGLE-device model bucket is published, which is what refuted #194's recorded
// "≥5 devices sharing one model string" unblock condition.
const modelScoresLiveRow = `{"id":"Virtual Machine_Microsoft Corporation","model":"Virtual Machine","manufacturer":"Microsoft Corporation","modelDeviceCount":1,"endpointAnalyticsScore":100.0,"startupPerformanceScore":-1.0,"appReliabilityScore":-1.0,"workFromAnywhereScore":-1.0,"batteryHealthScore":-1.0,"meanResourceSpikeTimeScore":100.0,"healthStatus":"meetingGoals"}`

// resourcePerfLiveRow is the VERBATIM userExperienceAnalyticsResourcePerformance
// row for wintest (m7kni, probed as graph2otel-poller 2026-07-24), the row that
// upgraded this segment's mapping from EDM-derived to live-measured. It carries
// both zero shapes the twin has to tell apart: totalRamInMB/cpuClockSpeedInMHz
// are 0 on a VM that plainly has RAM and a clock (not reported), while
// cpuSpikeTimePercentage 0 is a real measurement of zero spike time.
const resourcePerfLiveRow = `{"id":"117aea09-6b4c-48e0-8af1-26e89327160a","deviceId":"4ada2149-e9cb-4c34-827a-8df692a9065c","deviceName":"wintest","model":"Virtual Machine","deviceCount":-1,"manufacturer":"Microsoft Corporation","cpuSpikeTimePercentage":0.0,"ramSpikeTimePercentage":0.0,"cpuSpikeTimeScore":100,"cpuSpikeTimePercentageThreshold":15.0,"ramSpikeTimeScore":100,"ramSpikeTimePercentageThreshold":30.0,"deviceResourcePerformanceScore":94,"averageSpikeTimeScore":100,"machineType":"unknown","cpuDisplayName":"","totalProcessorCoreCount":0,"cpuClockSpeedInMHz":0.0,"totalRamInMB":0.0,"diskType":"unknown","healthStatus":"meetingGoals"}`

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
		appHealthDevURL: emptyPage,
		startupProcURL:  emptyPage,
		modelScoresURL:  emptyPage,
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
	  {"deviceName":"LAPHAM","endpointAnalyticsScore":86.62,"startupPerformanceScore":-1,"appReliabilityScore":100,"workFromAnywhereScore":96.88,"batteryHealthScore":63,"meanResourceSpikeTimeScore":-1,"healthStatus":"meetingGoals"},
	  {"deviceName":"OTHER","endpointAnalyticsScore":40,"startupPerformanceScore":55,"appReliabilityScore":70,"workFromAnywhereScore":80,"batteryHealthScore":30,"meanResourceSpikeTimeScore":88,"healthStatus":"needsAttention"}
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

	// Score histogram is bounded by category (6), never per-device. The -1
	// sentinel is excluded: startup_performance saw one real score (55), not two.
	byCategory := map[string]uint64{}
	for _, p := range rec.MetricPoints(deviceScoreMetric) {
		byCategory[p.Attrs["category"]] += p.Count
	}
	if len(byCategory) != 6 {
		t.Fatalf("want 6 bounded score categories, got %d: %v", len(byCategory), byCategory)
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
	body := `{"value":[{"endpointAnalyticsScore":-1,"startupPerformanceScore":-1,"appReliabilityScore":-1,"workFromAnywhereScore":-1,"batteryHealthScore":-1,"meanResourceSpikeTimeScore":-1,"healthStatus":"insufficientData"}]}`
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

// TestStartupHistoriesExcludeInsufficientDataSentinel pins #224: Endpoint
// Analytics reports -1 for "not enough data yet" on the startup-history timing
// fields, exactly as it does on the device scores, and a -1 must never reach a
// histogram as if it were a measurement.
//
// The two rows below are the VERBATIM live m7kni response (live-measured
// 2026-07-21, #224) and they are the whole point of the case: each row carries a
// real value in one field and a sentinel in the OTHER, so the sentinel cannot be
// skipped per-ROW without discarding a genuine measurement. The guard has to be
// per-FIELD. Before the fix, each histogram took one real and one -1 sample:
// _sum dragged low, _count overstated how many boots were actually measured, and
// the -1 landed in the lowest bucket claiming a sub-millisecond boot.
func TestStartupHistoriesExcludeInsufficientDataSentinel(t *testing.T) {
	body := `{"value":[
	  {"coreBootTimeInMs":2989,"groupPolicyBootTimeInMs":0,"featureUpdateBootTimeInMs":33146,
	   "totalBootTimeInMs":36135,"groupPolicyLoginTimeInMs":-1,"coreLoginTimeInMs":-1,
	   "responsiveDesktopTimeInMs":-1,"totalLoginTimeInMs":-1,"restartCategory":"update"},
	  {"coreBootTimeInMs":-1,"groupPolicyBootTimeInMs":-1,"featureUpdateBootTimeInMs":-1,
	   "totalBootTimeInMs":-1,"groupPolicyLoginTimeInMs":-1,"coreLoginTimeInMs":160762,
	   "responsiveDesktopTimeInMs":160760,"totalLoginTimeInMs":160761,"restartCategory":"unknown"}
	]}`
	g := &fakeGraph{bodies: allEndpoints(map[string]string{startupURL: body})}
	rec := telemetrytest.New()

	if err := New(g, nil).Collect(context.Background(), rec.Emitter()); err != nil {
		t.Fatalf("Collect: %v", err)
	}

	for _, tc := range []struct {
		metric  string
		wantSum float64
		field   string
	}{
		{bootTimeMetric, 36135, "totalBootTimeInMs"},
		{loginTimeMetric, 160761, "totalLoginTimeInMs"},
	} {
		var count uint64
		var sum float64
		for _, p := range rec.MetricPoints(tc.metric) {
			count += p.Count
			sum += p.Value // Value holds the Sum for histograms
		}
		if count != 1 {
			t.Errorf("%s: observation count = %d, want 1 (the -1 %s sentinel must not be recorded)",
				tc.metric, count, tc.field)
		}
		if sum != tc.wantSum {
			t.Errorf("%s: sum = %v, want %v (a recorded -1 drags the sum below the real measurement)",
				tc.metric, sum, tc.wantSum)
		}
	}

	// A row whose timing fields are ALL sentinel contributes no observation at
	// all, rather than a zero — a clamped 0ms boot is as wrong as -1, just
	// harder to spot.
	allSentinel := `{"value":[{"totalBootTimeInMs":-1,"totalLoginTimeInMs":-1,"restartCategory":"update"}]}`
	g2 := &fakeGraph{bodies: allEndpoints(map[string]string{startupURL: allSentinel})}
	rec2 := telemetrytest.New()
	if err := New(g2, nil).Collect(context.Background(), rec2.Emitter()); err != nil {
		t.Fatalf("Collect: %v", err)
	}
	if pts := rec2.MetricPoints(bootTimeMetric); len(pts) != 0 {
		t.Errorf("all-sentinel row emitted %d boot points, want 0", len(pts))
	}
	if pts := rec2.MetricPoints(loginTimeMetric); len(pts) != 0 {
		t.Errorf("all-sentinel row emitted %d login points, want 0", len(pts))
	}
}

// TestScoreSubFetchesExcludeInsufficientDataSentinel completes the #224 sweep.
// The -1 "not enough data" sentinel is an Endpoint-Analytics-wide convention, not
// a startup-history quirk: collectDeviceScores has always excluded it, and the
// battery and resource sub-fetches record the same 0-100 score shape into
// histograms. A device that is enrolled but not yet scored reports -1 rather
// than being absent (live-measured 2026-07-21, #224: the Cloud PC and the
// Parallels VM both report batteryHealthScore -1 on the sibling deviceScores
// segment while a real laptop reports 63).
//
// The device still counts in device_count under its healthStatus — only the
// score observation is suppressed, so "how many devices are in this state"
// stays correct while the distribution is not dragged toward zero.
func TestScoreSubFetchesExcludeInsufficientDataSentinel(t *testing.T) {
	for _, tc := range []struct {
		name        string
		url         string
		body        string
		scoreMetric string
		countMetric string
	}{
		{
			name:        "battery",
			url:         batteryURL,
			body:        `{"value":[{"deviceBatteryHealthScore":63,"healthStatus":"meetingGoals"},{"deviceBatteryHealthScore":-1,"healthStatus":"meetingGoals"}]}`,
			scoreMetric: batteryScoreMetric,
			countMetric: batteryDeviceCountMetric,
		},
		{
			name:        "resource",
			url:         resourcePerfURL,
			body:        `{"value":[{"deviceResourcePerformanceScore":88,"healthStatus":"meetingGoals"},{"deviceResourcePerformanceScore":-1,"healthStatus":"meetingGoals"}]}`,
			scoreMetric: resourceScoreMetric,
			countMetric: resourceDeviceCountMetric,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			g := &fakeGraph{bodies: allEndpoints(map[string]string{tc.url: tc.body})}
			rec := telemetrytest.New()
			if err := New(g, nil).Collect(context.Background(), rec.Emitter()); err != nil {
				t.Fatalf("Collect: %v", err)
			}

			var count uint64
			var sum float64
			for _, p := range rec.MetricPoints(tc.scoreMetric) {
				count += p.Count
				sum += p.Value
			}
			if count != 1 {
				t.Errorf("%s: observation count = %d, want 1 (the -1 sentinel must not be recorded)", tc.scoreMetric, count)
			}
			if sum < 0 {
				t.Errorf("%s: sum = %v, want a non-negative score sum", tc.scoreMetric, sum)
			}

			// Both devices still count — the sentinel suppresses the score, not
			// the device.
			var devices float64
			for _, p := range rec.MetricPoints(tc.countMetric) {
				devices += p.Value
			}
			if devices != 2 {
				t.Errorf("%s: device count = %v, want 2 (an unscored device is still a device)", tc.countMetric, devices)
			}
		})
	}
}

// logsNamed filters recorded log records down to those with EventName == name.
func logsNamed(rec *telemetrytest.Recorder, name string) []telemetrytest.LogRecord {
	var out []telemetrytest.LogRecord
	for _, r := range rec.LogRecords() {
		if r.EventName == name {
			out = append(out, r)
		}
	}
	return out
}

// allPoints returns every recorded metric data point across every metric, for
// the standing cardinality guards.
func allPoints(rec *telemetrytest.Recorder) []telemetrytest.MetricPoint {
	var out []telemetrytest.MetricPoint
	for _, n := range rec.MetricNames() {
		out = append(out, rec.MetricPoints(n)...)
	}
	return out
}

// liveBatteryRow is the VERBATIM userExperienceAnalyticsBatteryHealthDevicePerformance
// row for LAPHAM (m7kni, probed as graph2otel-poller 2026-07-21, #225). Note
// fullBatteryDrainCount is -1 on this real device — the "not enough data"
// sentinel — while deviceBatteriesDetails carries a real per-cell battery id.
const liveBatteryRow = `{"id":"b740c02b-b0bf-4f9a-8e4d-c4c9d3278675","deviceId":"d5900d67-e50c-44ef-9d5c-6a2f891099c6","deviceName":"LAPHAM","model":"Standard","manufacturer":"PCSpecialist","deviceModelName":"Standard","deviceManufacturerName":"PCSpecialist","maxCapacityPercentage":100,"estimatedRuntimeInMinutes":80,"batteryAgeInDays":179,"fullBatteryDrainCount":-1,"deviceBatteryCount":1,"deviceBatteryTags":[],"deviceBatteryHealthScore":63,"healthStatus":"meetingGoals","deviceBatteriesDetails":[{"batteryId":"LiON;52245;OEM;0","maxCapacityPercentage":100,"fullBatteryDrainCount":0}]}`

// TestBatteryHealthEmitsPerDeviceTwin pins the #225 decision to override the
// #114 no-twin exception for this sub-fetch. The point of the twin is that the
// bounded score histogram can say "a device scores 63" but never "LAPHAM's
// battery is 179 days old at 100% max capacity" — which is the difference
// between noticing and acting.
func TestBatteryHealthEmitsPerDeviceTwin(t *testing.T) {
	g := &fakeGraph{bodies: allEndpoints(map[string]string{batteryURL: `{"value":[` + liveBatteryRow + `]}`})}
	rec := telemetrytest.New()
	if err := New(g, nil).Collect(context.Background(), rec.Emitter()); err != nil {
		t.Fatalf("Collect: %v", err)
	}

	recs := logsNamed(rec, eventBatteryHealth)
	if len(recs) != 1 {
		t.Fatalf("want 1 %s record, got %d", eventBatteryHealth, len(recs))
	}
	got := recs[0].Attrs
	for k, want := range map[string]string{
		semconv.AttrDeviceName:              "LAPHAM",
		semconv.AttrDeviceId:                "d5900d67-e50c-44ef-9d5c-6a2f891099c6",
		semconv.AttrBatteryAgeDays:          "179",
		semconv.AttrMaxCapacityPercentage:   "100",
		semconv.AttrEstimatedRuntimeMinutes: "80",
		semconv.AttrBatteryHealthScore:      "63",
		semconv.AttrBatteryCount:            "1",
		semconv.AttrHealthState:             "meeting_goals",
	} {
		if got[k] != want {
			t.Errorf("twin attr %s = %q, want %q", k, got[k], want)
		}
	}
	// -1 is the sentinel: the attribute must be ABSENT, not "-1".
	if v, ok := got[semconv.AttrFullBatteryDrainCount]; ok {
		t.Errorf("full_battery_drain_count present as %q; the live -1 sentinel must be omitted", v)
	}
	if got[semconv.AttrBatteryIds] == "" {
		t.Errorf("battery_ids missing; the per-cell id distinguishes one bad cell from a worn pack")
	}
}

// TestStartupHistoryEmitsPerBootTwinStampedWithStartTime pins the two things
// that make the boot twin different from every other twin in this file: it
// carries the crash-bucket fields, and it is an EVENT stamped with startTime
// rather than poll time.
func TestStartupHistoryEmitsPerBootTwinStampedWithStartTime(t *testing.T) {
	body := `{"value":[
	  {"deviceId":"dev-1","startTime":"2026-07-19T21:23:25Z","coreBootTimeInMs":2989,"groupPolicyBootTimeInMs":0,
	   "featureUpdateBootTimeInMs":33146,"totalBootTimeInMs":36135,"groupPolicyLoginTimeInMs":-1,"coreLoginTimeInMs":-1,
	   "responsiveDesktopTimeInMs":-1,"totalLoginTimeInMs":-1,"isFirstLogin":false,"isFeatureUpdate":false,
	   "operatingSystemVersion":"10.0.26200.8037","restartCategory":"update","restartStopCode":"0","restartFaultBucket":""},
	  {"deviceId":"dev-2","startTime":"2026-07-20T08:00:00Z","totalBootTimeInMs":50000,"totalLoginTimeInMs":9000,
	   "restartCategory":"blueScreen","restartStopCode":"0x0000009F","restartFaultBucket":"0x9F_3_power"}
	]}`
	g := &fakeGraph{bodies: allEndpoints(map[string]string{startupURL: body})}
	rec := telemetrytest.New()
	if err := New(g, nil).Collect(context.Background(), rec.Emitter()); err != nil {
		t.Fatalf("Collect: %v", err)
	}

	recs := logsNamed(rec, eventDeviceStartup)
	if len(recs) != 2 {
		t.Fatalf("want 2 %s records, got %d", eventDeviceStartup, len(recs))
	}

	// Stamped with the boot's own startTime — NOT poll time. Stamping on arrival
	// would pile every historical restart onto one instant.
	wantTS := time.Date(2026, 7, 19, 21, 23, 25, 0, time.UTC)
	if !recs[0].Timestamp.Equal(wantTS) {
		t.Errorf("boot twin timestamp = %v, want the row's startTime %v", recs[0].Timestamp, wantTS)
	}

	// Sentinel timing fields are omitted from the twin, not rendered as "-1".
	if v, ok := recs[0].Attrs[semconv.AttrTotalLoginTimeMs]; ok {
		t.Errorf("total_login_time_ms present as %q; the -1 sentinel must be omitted", v)
	}
	if recs[0].Attrs[semconv.AttrTotalBootTimeMs] != "36135" {
		t.Errorf("total_boot_time_ms = %q, want 36135", recs[0].Attrs[semconv.AttrTotalBootTimeMs])
	}

	// The crash-bucket fields are the reason this twin exists.
	crash := recs[1].Attrs
	if crash[semconv.AttrRestartStopCode] != "0x0000009F" || crash[semconv.AttrRestartFaultBucket] != "0x9F_3_power" {
		t.Errorf("crash-bucket fields not carried: stop_code=%q fault_bucket=%q",
			crash[semconv.AttrRestartStopCode], crash[semconv.AttrRestartFaultBucket])
	}
	if recs[1].SeverityText != "WARN" {
		t.Errorf("a boot with a fault bucket should be WARN, got %q", recs[1].SeverityText)
	}
	if recs[0].SeverityText == "WARN" {
		t.Errorf("a routine restart (stop code 0, no fault bucket) must not be WARN")
	}
}

// TestStartupProcessesEmitTwinOnlyNeverAMetric pins the #199 sub-fetch and the
// cardinality call: the (device, process) pair is unbounded, so it emits a twin
// and NO metric at all.
func TestStartupProcessesEmitTwinOnlyNeverAMetric(t *testing.T) {
	// Verbatim live rows (m7kni, graph2otel-poller 2026-07-21).
	body := `{"value":[
	  {"id":"1625d698","managedDeviceId":"1625d698","processName":"MsMpEng","productName":"Windows Defender Antivirus","publisher":"Microsoft Corporation","startupImpactInMs":8038},
	  {"id":"1625d698","managedDeviceId":"1625d698","processName":"MsSense","productName":"Windows Defender Advanced Threat Protection","publisher":"Microsoft Corporation","startupImpactInMs":4822}
	]}`
	g := &fakeGraph{bodies: allEndpoints(map[string]string{startupProcURL: body})}
	rec := telemetrytest.New()
	if err := New(g, nil).Collect(context.Background(), rec.Emitter()); err != nil {
		t.Fatalf("Collect: %v", err)
	}

	recs := logsNamed(rec, eventStartupProcess)
	if len(recs) != 2 {
		t.Fatalf("want 2 %s records, got %d", eventStartupProcess, len(recs))
	}
	if recs[0].Attrs[semconv.AttrProcessName] != "MsMpEng" || recs[0].Attrs[semconv.AttrStartupImpactMs] != "8038" {
		t.Errorf("unexpected first startup-process twin: %v", recs[0].Attrs)
	}

	// Guard: no metric may carry a process name or a device id.
	for _, p := range allPoints(rec) {
		for k, v := range p.Attrs {
			if k == semconv.AttrProcessName || k == semconv.AttrDeviceId {
				t.Errorf("metric %s carries per-entity label %s=%q — (device, process) is unbounded (#112)", p.Name, k, v)
			}
		}
	}
}

// TestAppHealthDevicePerformanceEmitsCountsAndTwin pins the #225 sub-fetch that
// was not collected at all. It is the only live source of appHangCount and
// meanTimeToFailureInMinutes on a tenant under the 5-device Endpoint Analytics
// floor, which is why #194 could not build them from the application-level
// segment.
func TestAppHealthDevicePerformanceEmitsCountsAndTwin(t *testing.T) {
	// Verbatim live row (LAPHAM, m7kni, graph2otel-poller 2026-07-21).
	body := `{"value":[{"id":"6526d4c4","deviceModel":"Standard","deviceManufacturer":"PCSpecialist","appCrashCount":0,` +
		`"crashedAppCount":0,"appHangCount":0,"processedDateTime":"2026-07-20T03:05:36Z","meanTimeToFailureInMinutes":2147483647,` +
		`"deviceAppHealthScore":100.0,"deviceAppHealthStatus":"TBD","healthStatus":"meetingGoals",` +
		`"deviceId":"d5900d67-e50c-44ef-9d5c-6a2f891099c6","deviceDisplayName":"LAPHAM"}]}`
	g := &fakeGraph{bodies: allEndpoints(map[string]string{appHealthDevURL: body})}
	rec := telemetrytest.New()
	if err := New(g, nil).Collect(context.Background(), rec.Emitter()); err != nil {
		t.Fatalf("Collect: %v", err)
	}

	pts := rec.MetricPoints(appHealthDeviceCountMetric)
	if len(pts) != 1 || pts[0].Value != 1 || pts[0].Attrs["health_state"] != "meeting_goals" {
		t.Fatalf("want one device_count point of 1 under meeting_goals, got %+v", pts)
	}

	recs := logsNamed(rec, eventDeviceAppHealth)
	if len(recs) != 1 {
		t.Fatalf("want 1 %s record, got %d", eventDeviceAppHealth, len(recs))
	}
	got := recs[0].Attrs
	if got[semconv.AttrDeviceName] != "LAPHAM" || got[semconv.AttrAppHangCount] != "0" || got[semconv.AttrAppCrashCount] != "0" {
		t.Errorf("unexpected app-health twin attrs: %v", got)
	}
	// int32-max is "no failures observed", not a ~4085-year MTTF.
	if v, ok := got[semconv.AttrMeanTimeToFailureMinutes]; ok {
		t.Errorf("mean_time_to_failure_minutes present as %q; the int32-max sentinel must be omitted", v)
	}
	if recs[0].SeverityText == "WARN" {
		t.Errorf("a device with zero crashes and zero hangs must not be WARN")
	}
}

// TestEndpointAnalyticsTwinsCarryNoPerEntityMetricLabels is the standing
// cardinality guard for the whole collector (#112). Every twin added by #225
// carries device identity; none of it may reach a metric.
func TestEndpointAnalyticsTwinsCarryNoPerEntityMetricLabels(t *testing.T) {
	g := &fakeGraph{bodies: allEndpoints(map[string]string{
		batteryURL:      `{"value":[` + liveBatteryRow + `]}`,
		startupProcURL:  `{"value":[{"managedDeviceId":"d1","processName":"MsMpEng","publisher":"Microsoft Corporation","startupImpactInMs":8038}]}`,
		appHealthDevURL: `{"value":[{"deviceId":"d1","deviceDisplayName":"LAPHAM","healthStatus":"meetingGoals"}]}`,
	})}
	rec := telemetrytest.New()
	if err := New(g, nil).Collect(context.Background(), rec.Emitter()); err != nil {
		t.Fatalf("Collect: %v", err)
	}

	banned := map[string]bool{
		semconv.AttrDeviceId: true, semconv.AttrDeviceName: true, semconv.AttrProcessName: true,
		semconv.AttrBatteryIds: true, semconv.AttrBatteryAgeDays: true, semconv.AttrRestartStopCode: true,
		semconv.AttrRestartFaultBucket: true, semconv.AttrStartupImpactMs: true,
	}
	for _, p := range allPoints(rec) {
		for k := range p.Attrs {
			if banned[k] {
				t.Errorf("metric %s carries per-entity label %q — must be twin-only (#112/#114)", p.Name, k)
			}
		}
	}
}

// TestCollectEmitsAppCrashCountForEveryExecutable is the shape after #235
// retired this collector's allow-list.
//
// The list named ten Microsoft and browser executables. On m7kni it discarded
// 100% of the live data, because the one row the tenant produces is LogonUI.exe
// — and a line-of-business application crashing 9,999 times was, by
// construction, invisible. The executable set is genuinely unbounded, so the
// metric still needs a ceiling; it now gets the central limiter's, which keeps
// the top executables BY CRASH COUNT. Ranking by crashes surfaces exactly what a
// crash metric is for, which a fixed list can only do by luck.
func TestCollectEmitsAppCrashCountForEveryExecutable(t *testing.T) {
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
	if len(got) != 3 {
		t.Fatalf("want 3 app_name buckets (one per distinct executable), got %d: %v", len(got), got)
	}
	if got["outlook.exe"] != 8 {
		t.Errorf("outlook.exe crash count = %v, want 8 (5+3, folded case-insensitively — "+
			"Intune emits casing variants of one executable and they are not two apps)", got["outlook.exe"])
	}
	if got["chrome.exe"] != 2 {
		t.Errorf("chrome.exe crash count = %v, want 2", got["chrome.exe"])
	}
	// The formerly-unlisted executable is the point: 9,999 crashes, and the
	// allow-list made it invisible.
	if got["some-bespoke-line-of-business.exe"] != 9999 {
		t.Errorf("some-bespoke-line-of-business.exe = %v, want 9999 — the worst-crashing app "+
			"in the tenant, which the retired allow-list discarded outright",
			got["some-bespoke-line-of-business.exe"])
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

// TestCollectEmitsModelScoresAsBoundedAggregates pins the #194 per-model segment
// against the first row m7kni ever published (2026-07-24): a model bucket rolls
// into bounded gauges keyed by model + manufacturer — the score by category and
// the bucket's own device count — with NO log twin (#192: model/OS-level scores
// are metric-shaped, per-device rows are log-shaped), and the -1 "not enough
// data" sentinel is excluded per field rather than emitted as a negative score.
func TestCollectEmitsModelScoresAsBoundedAggregates(t *testing.T) {
	body := `{"value":[
	  ` + modelScoresLiveRow + `,
	  {"id":"Latitude 7440_Dell Inc.","model":"Latitude 7440","manufacturer":"Dell Inc.","modelDeviceCount":12,"endpointAnalyticsScore":78.5,"startupPerformanceScore":61,"appReliabilityScore":-1.0,"workFromAnywhereScore":90,"batteryHealthScore":72,"meanResourceSpikeTimeScore":-1.0,"healthStatus":"needsAttention"}
	]}`
	g := &fakeGraph{bodies: allEndpoints(map[string]string{modelScoresURL: body})}
	rec := telemetrytest.New()
	if err := New(g, nil).Collect(context.Background(), rec.Emitter()); err != nil {
		t.Fatalf("Collect: %v", err)
	}

	// Score gauge: one point per (model, category) with the sentinel fields gone.
	// The live row reports exactly two real scores of its six; the Dell row four.
	type key struct{ model, category string }
	score := map[key]telemetrytest.MetricPoint{}
	for _, p := range rec.MetricPoints(modelScoreMetric) {
		score[key{p.Attrs["model"], p.Attrs["category"]}] = p
	}
	if len(score) != 6 {
		t.Fatalf("want 6 model score points (2 live + 4 Dell, sentinels excluded), got %d: %v", len(score), score)
	}
	live := score[key{"Virtual Machine", "endpoint_analytics"}]
	if live.Value != 100 || live.Attrs["manufacturer"] != "Microsoft Corporation" || live.Attrs["health_state"] != "meeting_goals" {
		t.Errorf("live endpoint_analytics point = %+v, want value 100 / Microsoft Corporation / meeting_goals", live)
	}
	if p := score[key{"Virtual Machine", "mean_resource_spike_time"}]; p.Value != 100 {
		t.Errorf("mean_resource_spike_time is the sixth category and must be mapped, got %+v", p)
	}
	for _, c := range []string{"startup_performance", "app_reliability", "work_from_anywhere", "battery_health"} {
		if _, ok := score[key{"Virtual Machine", c}]; ok {
			t.Errorf("category %q carries the -1 sentinel on the live row and must be excluded", c)
		}
	}
	if _, ok := score[key{"Latitude 7440", "app_reliability"}]; ok {
		t.Error("Dell row's -1 app_reliability must be excluded too")
	}

	// Device-count gauge: the bucket size, which is what makes a model bucket
	// self-describing. modelDeviceCount 1 is a REAL published bucket, not a floor.
	count := map[string]telemetrytest.MetricPoint{}
	for _, p := range rec.MetricPoints(modelDeviceCountMetric) {
		count[p.Attrs["model"]] = p
	}
	if count["Virtual Machine"].Value != 1 || count["Latitude 7440"].Value != 12 {
		t.Errorf("model_device_count = %v, want 1 and 12", count)
	}
	if count["Latitude 7440"].Attrs["health_state"] != "needs_attention" {
		t.Errorf("Dell bucket health_state = %q, want needs_attention", count["Latitude 7440"].Attrs["health_state"])
	}

	// No log twin: this is a model-level aggregate, not a per-entity row.
	for _, lr := range rec.LogRecords() {
		if lr.EventName == eventDeviceScore || lr.EventName == eventWorkFromAnywhere {
			continue // twins from other sub-fetches
		}
		t.Errorf("model-scores segment must emit no log twin, got event %q", lr.EventName)
	}
}

// TestResourcePerformanceTwinDistinguishesUnreportedZeroFromRealZero pins the
// live wintest row (#194, 2026-07-24). totalRamInMB and cpuClockSpeedInMHz read 0
// on a VM that demonstrably has RAM and a clock — that is "not reported", and
// emitting it as a real reading is the same trap intune.hardware_inventory
// already handles for totalStorageSpace. cpuSpikeTimePercentage 0 is by contrast
// a legitimate measurement (0% spike time), so the guard must be per field, not
// blanket. The six fields the original mapping left on the wire are also pinned
// here, including the two tenant-policy thresholds that explain the scores.
func TestResourcePerformanceTwinDistinguishesUnreportedZeroFromRealZero(t *testing.T) {
	g := &fakeGraph{bodies: allEndpoints(map[string]string{resourcePerfURL: `{"value":[` + resourcePerfLiveRow + `]}`})}
	rec := telemetrytest.New()
	if err := New(g, nil).Collect(context.Background(), rec.Emitter()); err != nil {
		t.Fatalf("Collect: %v", err)
	}

	var attrs map[string]string
	for _, lr := range rec.LogRecords() {
		if lr.EventName == eventResourcePerformance {
			attrs = lr.Attrs
		}
	}
	if attrs == nil {
		t.Fatal("no resource-performance twin emitted")
	}

	for _, k := range []string{semconv.AttrTotalRamMb, semconv.AttrCpuClockSpeedMhz, semconv.AttrProcessorCoreCount} {
		if v, ok := attrs[k]; ok {
			t.Errorf("%s reads 0 on the wire = not reported; must be omitted, got %q", k, v)
		}
	}
	if attrs[semconv.AttrCpuSpikeTimePercentage] != "0" {
		t.Errorf("cpu_spike_time_percentage 0 is a REAL measurement and must be emitted, got %q", attrs[semconv.AttrCpuSpikeTimePercentage])
	}
	if attrs[semconv.AttrRamSpikeTimePercentage] != "0" {
		t.Errorf("ram_spike_time_percentage 0 is a REAL measurement and must be emitted, got %q", attrs[semconv.AttrRamSpikeTimePercentage])
	}
	for k, want := range map[string]string{
		semconv.AttrAverageSpikeTimeScore:           "100",
		semconv.AttrCpuSpikeTimeScore:               "100",
		semconv.AttrRamSpikeTimeScore:               "100",
		semconv.AttrCpuSpikeTimePercentageThreshold: "15",
		semconv.AttrRamSpikeTimePercentageThreshold: "30",
		semconv.AttrResourcePerformanceScore:        "94",
		semconv.AttrDeviceName:                      "wintest",
	} {
		if attrs[k] != want {
			t.Errorf("twin[%s] = %q, want %q", k, attrs[k], want)
		}
	}
	// cpuDisplayName is an empty string on the wire, not absent — SetStr must
	// omit it rather than emit "".
	if _, ok := attrs[semconv.AttrCpuDisplayName]; ok {
		t.Error("empty cpu_display_name must be omitted, not emitted as an empty attribute")
	}
}

// TestDeviceScoresMapTheSixthScoreCategory pins meanResourceSpikeTimeScore, which
// is on the userExperienceAnalyticsDeviceScores wire and was never mapped — the
// deviceScore struct predates it. Live values on m7kni 2026-07-24 range 64.33 to
// 100 across the load-generating VMs, so it is real data the collector was
// silently discarding, not a documentation artifact.
func TestDeviceScoresMapTheSixthScoreCategory(t *testing.T) {
	body := `{"value":[{"id":"4ada2149","deviceName":"wintest","model":"Virtual Machine","endpointAnalyticsScore":96.88,"startupPerformanceScore":-1.0,"appReliabilityScore":-1.0,"workFromAnywhereScore":93.75,"meanResourceSpikeTimeScore":100.0,"batteryHealthScore":-1.0,"healthStatus":"meetingGoals"}]}`
	g := &fakeGraph{bodies: allEndpoints(map[string]string{deviceScoresURL: body})}
	rec := telemetrytest.New()
	if err := New(g, nil).Collect(context.Background(), rec.Emitter()); err != nil {
		t.Fatalf("Collect: %v", err)
	}

	var seen bool
	for _, p := range rec.MetricPoints(deviceScoreMetric) {
		if p.Attrs["category"] == "mean_resource_spike_time" {
			seen = true
		}
	}
	if !seen {
		t.Error("device score histogram is missing the mean_resource_spike_time category")
	}
	for _, lr := range rec.LogRecords() {
		if lr.EventName != eventDeviceScore {
			continue
		}
		if lr.Attrs[semconv.AttrMeanResourceSpikeTimeScore] != "100" {
			t.Errorf("twin mean_resource_spike_time_score = %q, want 100", lr.Attrs[semconv.AttrMeanResourceSpikeTimeScore])
		}
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

// TestAppHealthApplicationEmitsTwinForEveryRow is the #114 guard for the
// application-level app-health segment. The allow-list is a METRIC cardinality
// boundary (app names are unbounded, so intune.uxa.app_crash_count must stay
// keyed by a fixed small set) — it is NOT a license to throw the rows away.
// Before this, a row outside the allow-list was `continue`d and vanished, so on
// a tenant whose only app-health row is LogonUI.exe the collector fetched the
// data, emitted an empty metric, and discarded 100% of it.
func TestAppHealthApplicationEmitsTwinForEveryRow(t *testing.T) {
	// First row is the verbatim live m7kni row (graph2otel-poller 2026-07-23) —
	// note appDisplayName and appPublisher are EMPTY STRINGS on the wire, and
	// meanTimeToFailureInMinutes is the int32-max no-failures sentinel.
	body := `{"value":[
	  {"id":"337c1207","appName":"LogonUI.exe","appDisplayName":"","appPublisher":"","appHealthScore":100.0,
	   "appHealthStatus":"TBD","appCrashCount":0,"appHangCount":0,"activeDeviceCount":8,
	   "appUsageDuration":200,"meanTimeToFailureInMinutes":2147483647},
	  {"appName":"outlook.exe","appDisplayName":"Microsoft Outlook","appPublisher":"Microsoft Corporation",
	   "appHealthScore":72.5,"appHealthStatus":"needsAttention","appCrashCount":4,"appHangCount":2,
	   "activeDeviceCount":3,"appUsageDuration":9001,"meanTimeToFailureInMinutes":120}
	]}`
	g := &fakeGraph{bodies: allEndpoints(map[string]string{appHealthURL: body})}
	rec := telemetrytest.New()
	if err := New(g, nil).Collect(context.Background(), rec.Emitter()); err != nil {
		t.Fatalf("Collect: %v", err)
	}

	recs := logsNamed(rec, eventAppHealth)
	if len(recs) != 2 {
		t.Fatalf("want a twin for EVERY row (2), got %d — an unlisted app must be twinned, never dropped (#114)", len(recs))
	}

	byApp := map[string]map[string]string{}
	for _, r := range recs {
		byApp[r.Attrs[semconv.AttrAppName]] = r.Attrs
	}

	// The unlisted app — the whole point. It contributes nothing to the metric
	// but must still be answerable in logs.
	logon, ok := byApp["LogonUI.exe"]
	if !ok {
		t.Fatalf("the unlisted app produced no twin; got apps %v", byApp)
	}
	if logon[semconv.AttrActiveDeviceCount] != "8" || logon[semconv.AttrAppUsageDuration] != "200" {
		t.Errorf("unlisted-app twin lost its detail: %v", logon)
	}
	// int32-max is "no failures observed", not a ~4085-year MTTF.
	if v, ok := logon[semconv.AttrMeanTimeToFailureMinutes]; ok {
		t.Errorf("mean_time_to_failure_minutes present as %q; the int32-max sentinel must be omitted", v)
	}
	// Empty on the wire, so it must be absent rather than an empty-string attr.
	if v, ok := logon[semconv.AttrAppDisplayName]; ok {
		t.Errorf("app_display_name present as %q; it is an empty string on the wire", v)
	}
	// "TBD" is an undocumented wire status and buckets like every other.
	if logon[semconv.AttrHealthState] != healthStateBucketFor("TBD") {
		t.Errorf("health_state = %q, want the bucketed form of TBD", logon[semconv.AttrHealthState])
	}

	out := byApp["outlook.exe"]
	if out[semconv.AttrAppCrashCount] != "4" || out[semconv.AttrAppHangCount] != "2" {
		t.Errorf("crash/hang counts wrong: %v", out)
	}
	if out[semconv.AttrMeanTimeToFailureMinutes] != "120" {
		t.Errorf("a real MTTF must be kept, got %q", out[semconv.AttrMeanTimeToFailureMinutes])
	}
	if out[semconv.AttrAppHealthScore] != "72.5" {
		t.Errorf("app_health_score = %q, want 72.5", out[semconv.AttrAppHealthScore])
	}
	if out[semconv.AttrPublisher] != "Microsoft Corporation" {
		t.Errorf("publisher missing: %v", out)
	}
	// A crashing app is the actionable case.
	if recsByName(recs, "outlook.exe").SeverityText != "WARN" {
		t.Errorf("an app with crashes and hangs must be WARN")
	}
	if recsByName(recs, "LogonUI.exe").SeverityText == "WARN" {
		t.Errorf("a clean app must not be WARN")
	}

	// The metric keeps its allow-list boundary: LogonUI.exe must NOT create a series.
	for _, p := range rec.MetricPoints(appCrashCountMetric) {
		if p.Attrs[semconv.AttrAppName] == "LogonUI.exe" {
			t.Errorf("unlisted app reached the metric — the allow-list is the metric cardinality boundary (#112)")
		}
	}
}

func recsByName(recs []telemetrytest.LogRecord, app string) telemetrytest.LogRecord {
	for _, r := range recs {
		if r.Attrs[semconv.AttrAppName] == app {
			return r
		}
	}
	return telemetrytest.LogRecord{}
}
