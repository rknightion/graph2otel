// Package endpointanalytics is the Intune Endpoint Analytics (User
// Experience Analytics) collector: tenant-posture scores plus bounded
// fleet-shaped aggregates over device startup performance, app crash health,
// battery health, resource performance, and baselines.
//
// MIXED v1.0/beta surface. The per-device scores collection, the device
// startup history collection, and the app health performance collection are
// all v1.0. The battery health, resource performance, and baseline families
// exist only on /beta. There is no tenant-wide overview singleton: Graph's
// userExperienceAnalyticsOverview segment was removed and 400s on both v1.0
// and beta (live-measured 2026-07-18, #179), so the score signal comes from
// the per-device userExperienceAnalyticsDeviceScores collection instead.
// Because this framework's Experimental opt-in is
// per-collector (not per-metric - see internal/collectors.Experimental), and
// a meaningful slice of this collector's value lives on those beta-only
// families, the WHOLE collector is Experimental (opt-in, default-off): when a
// tenant enables it, every signal below is emitted together, including the
// v1.0 device scores.
//
// The v1.0 per-device scores and both PER-BOOT / PER-APPLICATION-INSTANCE
// collections (device startup histories, app health performance) scale with
// fleet size and polling cadence - a 10k-device fleet can produce hundreds of
// thousands of startup-history rows a month. Per CLAUDE.md's cardinality
// rule, none of that raw shape becomes a metric label: startup history rolls
// up into bounded boot/login-time HISTOGRAMS (bucketed only by the fixed
// restartCategory enum) with NO log twin (per-boot attribution is pure ops -
// the #114-audited exception, see collectStartupHistories); per-device scores
// roll into a bounded score histogram (by the fixed category set) plus a device
// count by the bounded healthStatus enum, AND a per-device log twin carrying
// the scores (the #112/#114 shape - the twin answers "which device"); and
// app health crash counts are summed only for a small, fixed ALLOW-LIST of
// common executable names (mirroring intune/detectedapps' allow-list pattern) -
// never a series per raw exe name. The beta battery-health and
// resource-performance families are similarly per-device rows, aggregated down
// to device counts and score histograms by the bounded healthStatus enum,
// never a per-device series.
//
// insufficientData is a normal, expected healthStatus/state value on an
// immature or small tenant that hasn't accumulated enough telemetry yet - it
// is just another bounded attribute bucket here, never treated as an error.
package endpointanalytics

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"strconv"
	"strings"
	"time"

	"github.com/rknightion/graph2otel/internal/collector"
	"github.com/rknightion/graph2otel/internal/collectors"
	"github.com/rknightion/graph2otel/internal/semconv"
	"github.com/rknightion/graph2otel/internal/telemetry"
)

// collectorName is the stable key used for config (enable/interval),
// self-observability, and the admin status page.
const collectorName = "intune.endpoint_analytics"

// Metric names this collector emits.
const (
	deviceScoreMetric         = "intune.uxa.device_score"
	deviceScoreCountMetric    = "intune.uxa.device_count"
	bootTimeMetric            = "intune.uxa.boot_time_ms"
	loginTimeMetric           = "intune.uxa.login_time_ms"
	appCrashCountMetric       = "intune.uxa.app_crash_count"
	batteryDeviceCountMetric  = "intune.uxa.battery_health.device_count"
	batteryScoreMetric        = "intune.uxa.battery_health_score"
	resourceDeviceCountMetric = "intune.uxa.resource_performance.device_count"
	resourceScoreMetric       = "intune.uxa.resource_performance_score"
	baselineScoreMetric       = "intune.uxa.baseline_score"
	anomalyCountMetric        = "intune.uxa.anomaly_count"
	wfaDeviceCountMetric      = "intune.uxa.work_from_anywhere.device_count"

	appHealthOSVersionScoreMetric = "intune.uxa.app_health.os_version_score"
	appHealthOSVersionMTTFMetric  = "intune.uxa.app_health.mean_time_to_failure_minutes"
	appHealthOSVersionCountMetric = "intune.uxa.app_health.active_device_count"
)

// mttfNoFailuresSentinel is Endpoint Analytics' int32-max "no failures observed"
// value for meanTimeToFailureInMinutes (live-measured 2026-07-20, #194, on the
// one OS-version row m7kni reports). It is excluded from the MTTF gauge so it can
// never masquerade as a real ~4085-year mean time to failure.
const mttfNoFailuresSentinel = 2147483647

// eventDeviceScore is the EventName of the per-device Endpoint Analytics log
// twin (#179). It follows the intune.device_* twin convention (cf.
// intune.device_malware_state / intune.device_certificate) and sits outside the
// intune.uxa.* metric namespace so it does not collide with the device_score
// metric.
const eventDeviceScore = "intune.device_endpoint_analytics"

// eventWorkFromAnywhere is the EventName of the per-device Work-From-Anywhere
// Windows 11 upgrade-readiness twin (#194). Like eventDeviceScore it sits outside
// the intune.uxa.* metric namespace and follows the intune.device_* convention.
const eventWorkFromAnywhere = "intune.device_work_from_anywhere"

// defaultBaseURL / betaBaseURL: the per-device scores, startup histories,
// and app health performance are v1.0; battery health, resource performance,
// and baselines exist only on beta (see the package doc for why the
// collector as a whole is still Experimental).
const (
	defaultBaseURL = "https://graph.microsoft.com/v1.0"
	betaBaseURL    = "https://graph.microsoft.com/beta"
)

// bootTimeBounds are the shared explicit histogram bucket boundaries (in
// milliseconds) for both the boot-time and login-time histograms - a
// realistic spread from a healthy sub-5s boot up to a multi-minute outlier,
// fixed and small regardless of fleet size or how many boot rows are polled.
var bootTimeBounds = []float64{5000, 10000, 15000, 20000, 30000, 45000, 60000, 90000, 120000, 180000, 300000}

// scoreBounds are the shared explicit histogram bucket boundaries for the
// 0-100 battery/resource health scores.
var scoreBounds = []float64{10, 20, 30, 40, 50, 60, 70, 80, 90, 100}

// healthStateBuckets maps every documented userExperienceAnalyticsHealthState
// enum value (https://learn.microsoft.com/en-us/graph/api/resources/intune-devices-userexperienceanalyticshealthstate)
// to its bounded snake_case attribute value. Anything else (empty, or a
// future enum addition not yet in this map) falls into "other" rather than
// being passed through raw.
var healthStateBuckets = map[string]string{
	"unknown":            "unknown",
	"insufficientData":   "insufficient_data",
	"needsAttention":     "needs_attention",
	"meetingGoals":       "meeting_goals",
	"unknownFutureValue": "unknown_future_value",
}

func healthStateBucketFor(raw string) string {
	if b, ok := healthStateBuckets[raw]; ok {
		return b
	}
	return "other"
}

// restartCategoryBuckets maps every documented
// userExperienceAnalyticsOperatingSystemRestartCategory enum value
// (https://learn.microsoft.com/en-us/graph/api/resources/intune-devices-userexperienceanalyticsoperatingsystemrestartcategory)
// to its bounded snake_case attribute value. Anything unmapped falls into
// "other", keeping restart_category bounded regardless of future Graph
// schema additions.
var restartCategoryBuckets = map[string]string{
	"unknown":               "unknown",
	"restartWithUpdate":     "restart_with_update",
	"restartWithoutUpdate":  "restart_without_update",
	"blueScreen":            "blue_screen",
	"shutdownWithUpdate":    "shutdown_with_update",
	"shutdownWithoutUpdate": "shutdown_without_update",
	"longPowerButtonPress":  "long_power_button_press",
	"bootError":             "boot_error",
	"update":                "update",
	"unknownFutureValue":    "unknown_future_value",
}

func restartCategoryBucketFor(raw string) string {
	if b, ok := restartCategoryBuckets[raw]; ok {
		return b
	}
	return "other"
}

// defaultAllowedApps is the fixed, package-level cardinality boundary for
// intune.uxa.app_crash_count: only appHealthApplicationPerformance rows whose
// appName (a client executable file name, e.g. "outlook.exe") case-
// insensitively matches one of these are promoted into the series. Every
// other row is dropped from this metric (still counted only implicitly, via
// nothing - there is no catalog-size cross-check here since, unlike
// detectedApps, there is no single cheap scalar to sum it from without
// walking the whole page set again).
var defaultAllowedApps = []string{
	"outlook.exe",
	"excel.exe",
	"winword.exe",
	"powerpnt.exe",
	"onenote.exe",
	"teams.exe",
	"chrome.exe",
	"msedge.exe",
	"firefox.exe",
	"explorer.exe",
}

// deviceScore is the subset of the v1.0 userExperienceAnalyticsDeviceScores
// resource this collector reads
// (https://learn.microsoft.com/en-us/graph/api/resources/intune-devices-userexperienceanalyticsdevicescores).
// It replaces the removed userExperienceAnalyticsOverview singleton (#179): the
// tenant-wide overview segment 400s on both versions now, and per-device scores
// are the live source of the same "how is the fleet scoring" signal.
//
// Unlike the startupHistory rows - a per-BOOT firehose that keeps its
// #114-audited no-twin exception (see below) because boot-time attribution is
// pure ops and Intune's console answers it - these are per-DEVICE STATE with a
// stable identity and a small fixed score set, so each device also gets a log
// twin (eventDeviceScore). That is the #112/#114 shape: the bounded metrics
// answer "how many / what distribution", the twin answers "which device". id is
// the managed-device id (live-verified 2026-07-18 equal to the battery-health
// resource's deviceId).
//
// A score of -1 is Endpoint Analytics' "not enough data yet" sentinel, not a
// real 0-100 value (live-measured 2026-07-18, #179: a device reported
// startupPerformanceScore -1 while its other scores were populated). Sentinels
// are excluded from the score histogram so they cannot drag the distribution
// toward zero, AND omitted from the twin (absence = not reported) so nothing
// reads -1 as a real score; the device still counts in device_count under its
// healthStatus.
type deviceScore struct {
	ID                      string  `json:"id"`
	DeviceName              string  `json:"deviceName"`
	Model                   string  `json:"model"`
	Manufacturer            string  `json:"manufacturer"`
	EndpointAnalyticsScore  float64 `json:"endpointAnalyticsScore"`
	StartupPerformanceScore float64 `json:"startupPerformanceScore"`
	AppReliabilityScore     float64 `json:"appReliabilityScore"`
	WorkFromAnywhereScore   float64 `json:"workFromAnywhereScore"`
	BatteryHealthScore      float64 `json:"batteryHealthScore"`
	HealthStatus            string  `json:"healthStatus"`
}

// startupHistory is the subset of the v1.0 userExperienceAnalyticsDeviceStartupHistory
// resource this collector reads
// (https://learn.microsoft.com/en-us/graph/api/resources/intune-devices-userexperienceanalyticsdevicestartuphistory).
// deviceId is not read, and this collector deliberately has NO log twin.
//
// That is a real decision, not the #112 framing bug, so do not "fix" it by
// adding one: #114 gave a twin to every snapshot collector that was dropping
// per-entity data a metric could not carry, and audited this one as an
// exception. Startup/boot-performance attribution is an ops question, not a
// security one — Intune's own Endpoint Analytics console answers "which device
// boots slowly" better than a log stream would, and these rows roll straight
// into bounded histograms. Reconsider only if boot performance becomes a
// security signal for someone.
type startupHistory struct {
	TotalBootTimeInMs  float64 `json:"totalBootTimeInMs"`
	TotalLoginTimeInMs float64 `json:"totalLoginTimeInMs"`
	RestartCategory    string  `json:"restartCategory"`
}

// appHealthPerformance is the subset of the v1.0
// userExperienceAnalyticsAppHealthApplicationPerformance resource this
// collector reads
// (https://learn.microsoft.com/en-us/graph/api/resources/intune-devices-userexperienceanalyticsapphealthapplicationperformance).
type appHealthPerformance struct {
	AppName       string `json:"appName"`
	AppCrashCount int64  `json:"appCrashCount"`
}

// appHealthOSVersionPerformance is the subset of the v1.0
// userExperienceAnalyticsAppHealthOSVersionPerformance resource this collector
// reads (#194). It is an OS-VERSION-level app-reliability aggregate — one row per
// OS version, bounded by the number of OS versions in the fleet — so it is
// metric-shaped with NO log twin (the #192 rule: model/OS-level scores are
// metric-shaped; per-device rows are log-shaped). It survives the 5-device
// Endpoint Analytics "insufficient data" floor that empties the per-model
// segments, because it aggregates by OS build rather than by device model
// (live-measured 2026-07-20, m7kni: 1 row for 10.0.26120). osVersionAppHealthStatus
// is bucketed through healthStateBucketFor, so an undocumented wire value like the
// observed "TBD" (a provisional status not in the documented health-state enum)
// falls to "other" rather than being asserted raw.
type appHealthOSVersionPerformance struct {
	OSVersion                  string  `json:"osVersion"`
	ActiveDeviceCount          int64   `json:"activeDeviceCount"`
	MeanTimeToFailureInMinutes int64   `json:"meanTimeToFailureInMinutes"`
	OSVersionAppHealthScore    float64 `json:"osVersionAppHealthScore"`
	OSVersionAppHealthStatus   string  `json:"osVersionAppHealthStatus"`
}

// batteryHealthPerformance is the subset of the beta
// userExperienceAnalyticsBatteryHealthDevicePerformance resource this
// collector reads. deviceId/deviceName/model/manufacturer are deliberately
// never read - per-device identifiers, rolled into bounded buckets instead.
type batteryHealthPerformance struct {
	DeviceBatteryHealthScore float64 `json:"deviceBatteryHealthScore"`
	HealthStatus             string  `json:"healthStatus"`
}

// resourcePerformance is the subset of the beta
// userExperienceAnalyticsResourcePerformance resource this collector reads.
type resourcePerformance struct {
	DeviceResourcePerformanceScore float64 `json:"deviceResourcePerformanceScore"`
	HealthStatus                   string  `json:"healthStatus"`
}

// baseline is the subset of the beta userExperienceAnalyticsBaseline resource
// this collector reads. Baselines are a tiny, admin-configured collection
// (the built-in commercial-median baseline plus a handful of custom ones) -
// displayName is a bounded, admin-assigned label here, the same cardinality
// reasoning intune/appletokens applies to vppToken.organizationName.
type baseline struct {
	DisplayName  string `json:"displayName"`
	OverallScore int    `json:"overallScore"`
	IsBuiltIn    bool   `json:"isBuiltIn"`
}

// anomalySeverityOverview is the beta
// userExperienceAnalyticsAnomalySeverityOverview SINGLETON - a single flat JSON
// object (NOT an odata collection), so it is fetched as raw bytes and
// unmarshalled directly rather than through a list helper. Each field is a
// tenant-wide anomaly count for one bounded severity; they roll straight into a
// bounded gauge by anomaly_severity, with no per-entity rows and so no log twin.
// (live-measured 2026-07-19: HTTP 200 with exactly these four int fields.)
type anomalySeverityOverview struct {
	LowSeverityAnomalyCount           int64 `json:"lowSeverityAnomalyCount"`
	MediumSeverityAnomalyCount        int64 `json:"mediumSeverityAnomalyCount"`
	HighSeverityAnomalyCount          int64 `json:"highSeverityAnomalyCount"`
	InformationalSeverityAnomalyCount int64 `json:"informationalSeverityAnomalyCount"`
}

// wfaMetricDevice is the subset of the beta
// userExperienceAnalyticsWorkFromAnywhereMetrics/allDevices/metricDevices
// navigation this collector reads (#194) — the per-device Windows 11
// upgrade-readiness detail behind the tenant Work-From-Anywhere score. LIVE
// FACTS (2026-07-19, m7kni, probed as graph2otel-poller): the singleton and
// /allDevices paths 400 with "No OData route"; only the .../metricDevices leaf
// returns 200. id is the managed-device id (deviceId is null on the wire); the
// *CheckFailed fields are JSON booleans; the score fields are null on an
// insufficiently-assessed device, so they are pointers (nil = omit, never a
// misleading 0). upgradeEligibility is a small bounded enum
// (upgraded/capable/notCapable/unknown/...).
type wfaMetricDevice struct {
	ID                            string   `json:"id"`
	DeviceName                    string   `json:"deviceName"`
	SerialNumber                  string   `json:"serialNumber"`
	Manufacturer                  string   `json:"manufacturer"`
	Model                         string   `json:"model"`
	Ownership                     string   `json:"ownership"`
	OSDescription                 string   `json:"osDescription"`
	OSVersion                     string   `json:"osVersion"`
	UpgradeEligibility            string   `json:"upgradeEligibility"`
	HealthStatus                  string   `json:"healthStatus"`
	RAMCheckFailed                bool     `json:"ramCheckFailed"`
	StorageCheckFailed            bool     `json:"storageCheckFailed"`
	ProcessorCoreCountCheckFailed bool     `json:"processorCoreCountCheckFailed"`
	ProcessorSpeedCheckFailed     bool     `json:"processorSpeedCheckFailed"`
	TPMCheckFailed                bool     `json:"tpmCheckFailed"`
	SecureBootCheckFailed         bool     `json:"secureBootCheckFailed"`
	ProcessorFamilyCheckFailed    bool     `json:"processorFamilyCheckFailed"`
	Processor64BitCheckFailed     bool     `json:"processor64BitCheckFailed"`
	OSCheckFailed                 bool     `json:"osCheckFailed"`
	WorkFromAnywhereScore         *float64 `json:"workFromAnywhereScore"`
	WindowsScore                  *float64 `json:"windowsScore"`
	CloudManagementScore          *float64 `json:"cloudManagementScore"`
	CloudIdentityScore            *float64 `json:"cloudIdentityScore"`
	CloudProvisioningScore        *float64 `json:"cloudProvisioningScore"`
}

// Collector polls Intune Endpoint Analytics (User Experience Analytics).
type Collector struct {
	g       collectors.GraphClient
	baseURL string
	beta    string
	logger  *slog.Logger
}

// New builds the endpoint-analytics collector. A nil logger falls back to
// the slog default.
func New(g collectors.GraphClient, logger *slog.Logger) *Collector {
	if logger == nil {
		logger = slog.Default()
	}
	return &Collector{g: g, baseURL: defaultBaseURL, beta: betaBaseURL, logger: logger}
}

// Name implements collector.Collector.
func (c *Collector) Name() string { return collectorName }

// DefaultInterval implements collector.Collector. This is the heaviest M4
// poll cycle after intune.devices - up to six Graph fetches, three of them
// paged over fleet-scale collections - and endpoint-analytics scores drift
// slowly, so it defaults to a long cadence.
func (c *Collector) DefaultInterval() time.Duration { return time.Hour }

// Experimental marks the whole collector as beta/opt-in - see the package
// doc for why this covers the v1.0 signals too.
func (c *Collector) Experimental() bool { return true }

// RequiredPermissions declares the least-privilege Graph application scope.
func (c *Collector) RequiredPermissions() []string {
	return []string{"DeviceManagementManagedDevices.Read.All"}
}

// Collect fetches all six Endpoint Analytics signals and emits the bounded
// gauges/histograms described in the package doc. Each sub-fetch is
// independently resilient: a 403/404 (Endpoint Analytics not licensed/
// configured on this tenant) is skipped-and-logged, any other error is joined
// into the returned error, and every other sub-fetch's metrics still emit
// regardless of one failing.
func (c *Collector) Collect(ctx context.Context, e telemetry.Emitter) error {
	fetchers := []struct {
		name string
		fn   func(context.Context, telemetry.Emitter) error
	}{
		{"device scores", c.collectDeviceScores},
		{"startup histories", c.collectStartupHistories},
		{"app health", c.collectAppHealth},
		{"battery health", c.collectBatteryHealth},
		{"resource performance", c.collectResourcePerformance},
		{"baselines", c.collectBaselines},
		{"anomaly severity overview", c.collectAnomalySeverityOverview},
		{"work from anywhere readiness", c.collectWorkFromAnywhere},
		{"app health os version", c.collectAppHealthOSVersion},
	}

	var errs []error
	for _, f := range fetchers {
		if err := f.fn(ctx, e); err != nil {
			if isNotLicensed(err) {
				c.logger.Info("endpoint analytics sub-endpoint not licensed on this tenant; skipping",
					"collector", collectorName, "endpoint", f.name, "error", err)
				continue
			}
			// A wrong/dead route segment is graph2otel asking for a URL that does
			// not exist - our bug, never a tenant condition (#179). It is joined
			// into the error like any other failure, but logged distinctly so it
			// cannot masquerade as a quiet "not available on this tenant" skip for
			// the life of the collector, which is exactly how the removed overview
			// and the plural startup-history URL hid until #179.
			if isWrongEndpoint(err) {
				c.logger.Error("endpoint analytics sub-endpoint URL is wrong/dead - this is a graph2otel bug, not a tenant gap",
					"collector", collectorName, "endpoint", f.name, "error", err)
			} else {
				c.logger.Warn("endpoint analytics sub-fetch failed", "collector", collectorName, "endpoint", f.name, "error", err)
			}
			errs = append(errs, fmt.Errorf("%s: %w", f.name, err))
		}
	}
	return errors.Join(errs...)
}

// collectDeviceScores fetches the per-device Endpoint Analytics scores and
// rolls them into a bounded score histogram (by category, sentinels excluded)
// plus a device count by health state - see the deviceScore doc for why there
// is no log twin.
func (c *Collector) collectDeviceScores(ctx context.Context, e telemetry.Emitter) error {
	raw, err := collectors.GetAllValues(ctx, c.g, c.baseURL+"/deviceManagement/userExperienceAnalyticsDeviceScores", nil)
	if err != nil {
		return err
	}
	counts := map[string]int64{}
	for _, r := range raw {
		var d deviceScore
		if err := json.Unmarshal(r, &d); err != nil {
			c.logger.Warn("endpoint_analytics: skipping malformed device score row", "collector", collectorName, "error", err)
			continue
		}
		state := healthStateBucketFor(d.HealthStatus)
		counts[state]++

		// The per-device log twin: identity + every score the device actually
		// reported. -1 sentinels are omitted (absence = not reported).
		attrs := telemetry.Attrs{semconv.AttrHealthState: state}
		telemetry.SetStr(attrs, semconv.AttrId, d.ID)
		telemetry.SetStr(attrs, semconv.AttrDeviceName, d.DeviceName)
		telemetry.SetStr(attrs, semconv.AttrModel, d.Model)
		telemetry.SetStr(attrs, semconv.AttrManufacturer, d.Manufacturer)
		for _, cs := range []struct {
			category string
			attr     string
			score    float64
		}{
			{"endpoint_analytics", semconv.AttrEndpointAnalyticsScore, d.EndpointAnalyticsScore},
			{"startup_performance", semconv.AttrStartupPerformanceScore, d.StartupPerformanceScore},
			{"app_reliability", semconv.AttrAppReliabilityScore, d.AppReliabilityScore},
			{"work_from_anywhere", semconv.AttrWorkFromAnywhereScore, d.WorkFromAnywhereScore},
			{"battery_health", semconv.AttrBatteryHealthScore, d.BatteryHealthScore},
		} {
			if cs.score < 0 {
				continue // -1 = "not enough data" sentinel: excluded from the histogram AND omitted from the twin
			}
			e.Histogram(deviceScoreMetric, "{score}", "Intune Endpoint Analytics per-device score distribution (0-100), by score category.",
				cs.score, scoreBounds, telemetry.Attrs{semconv.AttrCategory: cs.category})
			// String-valued so it lands as clean Loki structured metadata (a
			// double would be stringified downstream anyway); FormatFloat(-1)
			// gives the minimal form ("86.62", "63", not "63.000000").
			attrs[cs.attr] = strconv.FormatFloat(cs.score, 'f', -1, 64)
		}
		// Timestamp left zero (poll time): this is a STATE feed re-emitted every
		// cycle, like entra/risk's twin - stamping the assessment time would pile
		// repeats onto one instant and make "which device was failing at 14:00"
		// unanswerable.
		e.LogEvent(telemetry.Event{
			Name:     eventDeviceScore,
			Body:     fmt.Sprintf("endpoint analytics for %s: health=%s", deviceScoreDisplay(d), orUnknown(d.HealthStatus)),
			Severity: telemetry.SeverityInfo,
			Attrs:    attrs,
		})
	}
	points := make([]telemetry.GaugePoint, 0, len(counts))
	for state, n := range counts {
		points = append(points, telemetry.GaugePoint{Value: float64(n), Attrs: telemetry.Attrs{semconv.AttrHealthState: state}})
	}
	e.GaugeSnapshot(deviceScoreCountMetric, "{device}", "Intune Endpoint Analytics device count, by overall Endpoint Analytics health state.", points)
	return nil
}

func (c *Collector) collectStartupHistories(ctx context.Context, e telemetry.Emitter) error {
	raw, err := collectors.GetAllValues(ctx, c.g, c.baseURL+"/deviceManagement/userExperienceAnalyticsDeviceStartupHistory", nil)
	if err != nil {
		return err
	}
	for _, r := range raw {
		var h startupHistory
		if err := json.Unmarshal(r, &h); err != nil {
			c.logger.Warn("endpoint_analytics: skipping malformed startup history row", "collector", collectorName, "error", err)
			continue
		}
		bucket := restartCategoryBucketFor(h.RestartCategory)
		attrs := telemetry.Attrs{semconv.AttrRestartCategory: bucket}
		e.Histogram(bootTimeMetric, "ms", "Intune Endpoint Analytics device boot time, by restart category.", h.TotalBootTimeInMs, bootTimeBounds, attrs)
		e.Histogram(loginTimeMetric, "ms", "Intune Endpoint Analytics device login time, by restart category.", h.TotalLoginTimeInMs, bootTimeBounds, attrs)
	}
	return nil
}

func (c *Collector) collectAppHealth(ctx context.Context, e telemetry.Emitter) error {
	raw, err := collectors.GetAllValues(ctx, c.g, c.baseURL+"/deviceManagement/userExperienceAnalyticsAppHealthApplicationPerformance", nil)
	if err != nil {
		return err
	}
	crashes := map[string]int64{}
	for _, r := range raw {
		var a appHealthPerformance
		if err := json.Unmarshal(r, &a); err != nil {
			c.logger.Warn("endpoint_analytics: skipping malformed app health row", "collector", collectorName, "error", err)
			continue
		}
		canonical, ok := allowedApp(a.AppName)
		if !ok {
			continue
		}
		crashes[canonical] += a.AppCrashCount
	}
	points := make([]telemetry.GaugePoint, 0, len(crashes))
	for app, count := range crashes {
		points = append(points, telemetry.GaugePoint{Value: float64(count), Attrs: telemetry.Attrs{semconv.AttrAppName: app}})
	}
	e.GaugeSnapshot(appCrashCountMetric, "{crash}", "Intune Endpoint Analytics app crash count, for an allow-listed set of common executables.", points)
	return nil
}

func (c *Collector) collectBatteryHealth(ctx context.Context, e telemetry.Emitter) error {
	raw, err := collectors.GetAllValues(ctx, c.g, c.beta+"/deviceManagement/userExperienceAnalyticsBatteryHealthDevicePerformance", nil)
	if err != nil {
		return err
	}
	counts := map[string]int64{}
	for _, r := range raw {
		var b batteryHealthPerformance
		if err := json.Unmarshal(r, &b); err != nil {
			c.logger.Warn("endpoint_analytics: skipping malformed battery health row", "collector", collectorName, "error", err)
			continue
		}
		state := healthStateBucketFor(b.HealthStatus)
		counts[state]++
		e.Histogram(batteryScoreMetric, "{score}", "Intune Endpoint Analytics device battery health score (0-100), by health state.",
			b.DeviceBatteryHealthScore, scoreBounds, telemetry.Attrs{semconv.AttrHealthState: state})
	}
	points := make([]telemetry.GaugePoint, 0, len(counts))
	for state, n := range counts {
		points = append(points, telemetry.GaugePoint{Value: float64(n), Attrs: telemetry.Attrs{semconv.AttrHealthState: state}})
	}
	e.GaugeSnapshot(batteryDeviceCountMetric, "{device}", "Intune Endpoint Analytics device count, by battery health state.", points)
	return nil
}

func (c *Collector) collectResourcePerformance(ctx context.Context, e telemetry.Emitter) error {
	raw, err := collectors.GetAllValues(ctx, c.g, c.beta+"/deviceManagement/userExperienceAnalyticsResourcePerformance", nil)
	if err != nil {
		return err
	}
	counts := map[string]int64{}
	for _, r := range raw {
		var rp resourcePerformance
		if err := json.Unmarshal(r, &rp); err != nil {
			c.logger.Warn("endpoint_analytics: skipping malformed resource performance row", "collector", collectorName, "error", err)
			continue
		}
		state := healthStateBucketFor(rp.HealthStatus)
		counts[state]++
		e.Histogram(resourceScoreMetric, "{score}", "Intune Endpoint Analytics device resource performance score (0-100), by health state.",
			rp.DeviceResourcePerformanceScore, scoreBounds, telemetry.Attrs{semconv.AttrHealthState: state})
	}
	points := make([]telemetry.GaugePoint, 0, len(counts))
	for state, n := range counts {
		points = append(points, telemetry.GaugePoint{Value: float64(n), Attrs: telemetry.Attrs{semconv.AttrHealthState: state}})
	}
	e.GaugeSnapshot(resourceDeviceCountMetric, "{device}", "Intune Endpoint Analytics device count, by resource performance health state.", points)
	return nil
}

func (c *Collector) collectBaselines(ctx context.Context, e telemetry.Emitter) error {
	raw, err := collectors.GetAllValues(ctx, c.g, c.beta+"/deviceManagement/userExperienceAnalyticsBaselines", nil)
	if err != nil {
		return err
	}
	points := make([]telemetry.GaugePoint, 0, len(raw))
	for _, r := range raw {
		var b baseline
		if err := json.Unmarshal(r, &b); err != nil {
			c.logger.Warn("endpoint_analytics: skipping malformed baseline row", "collector", collectorName, "error", err)
			continue
		}
		points = append(points, telemetry.GaugePoint{
			Value: float64(b.OverallScore),
			Attrs: telemetry.Attrs{semconv.AttrBaselineName: orUnknown(b.DisplayName), semconv.AttrIsBuiltIn: fmt.Sprintf("%t", b.IsBuiltIn)},
		})
	}
	e.GaugeSnapshot(baselineScoreMetric, "{score}", "Intune Endpoint Analytics baseline overall score, by baseline.", points)
	return nil
}

// collectAnomalySeverityOverview fetches the beta anomaly-severity overview
// singleton and emits one bounded gauge point per severity. Unlike the other
// sub-fetches this is a single flat object, not an odata collection, so it is
// fetched as raw bytes and unmarshalled directly (no GetAllValues). No log twin
// - it is a tenant-wide aggregate with no per-entity rows. Errors are returned
// unwrapped so Collect's shared skip-and-log path handles them exactly like the
// other beta sub-fetches (a 403 on an unlicensed tenant is a quiet skip).
func (c *Collector) collectAnomalySeverityOverview(ctx context.Context, e telemetry.Emitter) error {
	body, err := c.g.RawGet(ctx, c.beta+"/deviceManagement/userExperienceAnalyticsAnomalySeverityOverview")
	if err != nil {
		return err
	}
	var o anomalySeverityOverview
	if err := json.Unmarshal(body, &o); err != nil {
		return fmt.Errorf("unmarshal anomaly severity overview: %w", err)
	}
	points := []telemetry.GaugePoint{
		{Value: float64(o.LowSeverityAnomalyCount), Attrs: telemetry.Attrs{semconv.AttrAnomalySeverity: "low"}},
		{Value: float64(o.MediumSeverityAnomalyCount), Attrs: telemetry.Attrs{semconv.AttrAnomalySeverity: "medium"}},
		{Value: float64(o.HighSeverityAnomalyCount), Attrs: telemetry.Attrs{semconv.AttrAnomalySeverity: "high"}},
		{Value: float64(o.InformationalSeverityAnomalyCount), Attrs: telemetry.Attrs{semconv.AttrAnomalySeverity: "informational"}},
	}
	e.GaugeSnapshot(anomalyCountMetric, "{anomaly}", "Intune Endpoint Analytics anomaly count by severity.", points)
	return nil
}

// collectWorkFromAnywhere fetches the per-device Windows 11 upgrade-readiness
// rows (the metricDevices navigation) and rolls them into a bounded device count
// by (upgrade_eligibility, health_state), plus a per-device twin carrying the
// readiness detail. The twin lists a hardware readiness check ONLY when it FAILED
// (a device that meets every requirement carries no *_check_failed attribute) —
// the failures are the actionable signal, and this keeps a clean device's twin
// lean; the score fields are omitted when the device has not been assessed
// (null on the wire). Severity escalates to WARN for a notCapable device.
func (c *Collector) collectWorkFromAnywhere(ctx context.Context, e telemetry.Emitter) error {
	raw, err := collectors.GetAllValues(ctx, c.g, c.beta+"/deviceManagement/userExperienceAnalyticsWorkFromAnywhereMetrics/allDevices/metricDevices", nil)
	if err != nil {
		return err
	}
	type wfaKey struct {
		eligibility string
		state       string
	}
	counts := map[wfaKey]int64{}
	for _, r := range raw {
		var d wfaMetricDevice
		if err := json.Unmarshal(r, &d); err != nil {
			c.logger.Warn("endpoint_analytics: skipping malformed work-from-anywhere row", "collector", collectorName, "error", err)
			continue
		}
		eligibility := orUnknown(d.UpgradeEligibility)
		state := healthStateBucketFor(d.HealthStatus)
		counts[wfaKey{eligibility: eligibility, state: state}]++

		attrs := telemetry.Attrs{semconv.AttrUpgradeEligibility: eligibility, semconv.AttrHealthState: state}
		telemetry.SetStr(attrs, semconv.AttrId, d.ID)
		telemetry.SetStr(attrs, semconv.AttrDeviceName, d.DeviceName)
		telemetry.SetStr(attrs, semconv.AttrSerialNumber, d.SerialNumber)
		telemetry.SetStr(attrs, semconv.AttrManufacturer, d.Manufacturer)
		telemetry.SetStr(attrs, semconv.AttrModel, d.Model)
		telemetry.SetStr(attrs, semconv.AttrOwnership, d.Ownership)
		telemetry.SetStr(attrs, semconv.AttrOs, d.OSDescription)
		telemetry.SetStr(attrs, semconv.AttrOsVersion, d.OSVersion)
		// A readiness check rides the twin only when it FAILED (the actionable case).
		for _, cf := range []struct {
			failed bool
			attr   string
		}{
			{d.RAMCheckFailed, semconv.AttrRamCheckFailed},
			{d.StorageCheckFailed, semconv.AttrStorageCheckFailed},
			{d.ProcessorCoreCountCheckFailed, semconv.AttrProcessorCoreCountCheckFailed},
			{d.ProcessorSpeedCheckFailed, semconv.AttrProcessorSpeedCheckFailed},
			{d.TPMCheckFailed, semconv.AttrTpmCheckFailed},
			{d.SecureBootCheckFailed, semconv.AttrSecureBootCheckFailed},
			{d.ProcessorFamilyCheckFailed, semconv.AttrProcessorFamilyCheckFailed},
			{d.Processor64BitCheckFailed, semconv.AttrProcessor64BitCheckFailed},
			{d.OSCheckFailed, semconv.AttrOsCheckFailed},
		} {
			if cf.failed {
				attrs[cf.attr] = "true"
			}
		}
		// Scores are omitted when unassessed (null on the wire) so nothing reads a
		// missing score as 0.
		for _, s := range []struct {
			score *float64
			attr  string
		}{
			{d.WorkFromAnywhereScore, semconv.AttrWorkFromAnywhereScore},
			{d.WindowsScore, semconv.AttrWindowsScore},
			{d.CloudManagementScore, semconv.AttrCloudManagementScore},
			{d.CloudIdentityScore, semconv.AttrCloudIdentityScore},
			{d.CloudProvisioningScore, semconv.AttrCloudProvisioningScore},
		} {
			if s.score != nil {
				attrs[s.attr] = strconv.FormatFloat(*s.score, 'f', -1, 64)
			}
		}

		severity := telemetry.SeverityInfo
		if d.UpgradeEligibility == "notCapable" {
			severity = telemetry.SeverityWarn
		}
		// Timestamp left zero (poll time): a re-emitted STATE feed, like the
		// device-score twin.
		e.LogEvent(telemetry.Event{
			Name:     eventWorkFromAnywhere,
			Body:     fmt.Sprintf("windows 11 upgrade readiness for %s: %s", orUnknown(d.DeviceName), eligibility),
			Severity: severity,
			Attrs:    attrs,
		})
	}
	points := make([]telemetry.GaugePoint, 0, len(counts))
	for k, n := range counts {
		points = append(points, telemetry.GaugePoint{
			Value: float64(n),
			Attrs: telemetry.Attrs{semconv.AttrUpgradeEligibility: k.eligibility, semconv.AttrHealthState: k.state},
		})
	}
	e.GaugeSnapshot(wfaDeviceCountMetric, "{device}", "Intune Endpoint Analytics device count by Windows 11 upgrade eligibility and health state; per-device readiness detail on the intune.device_work_from_anywhere log twin.", points)
	return nil
}

// collectAppHealthOSVersion fetches the OS-version-level application health
// aggregate and emits three bounded gauges keyed by os_version (bounded by the
// number of OS versions in the fleet): the app-health score, the count of
// devices actively reporting app health, and the mean time to failure in
// minutes. No log twin — this is an OS-version aggregate, not a per-device row
// (#192). The int32-max "no failures" MTTF sentinel is excluded so it never
// reads as a real ~4085-year mean time to failure.
func (c *Collector) collectAppHealthOSVersion(ctx context.Context, e telemetry.Emitter) error {
	raw, err := collectors.GetAllValues(ctx, c.g, c.baseURL+"/deviceManagement/userExperienceAnalyticsAppHealthOSVersionPerformance", nil)
	if err != nil {
		return err
	}
	scorePoints := make([]telemetry.GaugePoint, 0, len(raw))
	countPoints := make([]telemetry.GaugePoint, 0, len(raw))
	mttfPoints := make([]telemetry.GaugePoint, 0, len(raw))
	for _, r := range raw {
		var a appHealthOSVersionPerformance
		if err := json.Unmarshal(r, &a); err != nil {
			c.logger.Warn("endpoint_analytics: skipping malformed app health os-version row", "collector", collectorName, "error", err)
			continue
		}
		osv := orUnknown(a.OSVersion)
		scorePoints = append(scorePoints, telemetry.GaugePoint{
			Value: a.OSVersionAppHealthScore,
			Attrs: telemetry.Attrs{semconv.AttrOsVersion: osv, semconv.AttrHealthState: healthStateBucketFor(a.OSVersionAppHealthStatus)},
		})
		countPoints = append(countPoints, telemetry.GaugePoint{
			Value: float64(a.ActiveDeviceCount),
			Attrs: telemetry.Attrs{semconv.AttrOsVersion: osv},
		})
		// The int32-max "no failures observed" sentinel is excluded so it never
		// lands as a real mean-time-to-failure value.
		if a.MeanTimeToFailureInMinutes != mttfNoFailuresSentinel {
			mttfPoints = append(mttfPoints, telemetry.GaugePoint{
				Value: float64(a.MeanTimeToFailureInMinutes),
				Attrs: telemetry.Attrs{semconv.AttrOsVersion: osv},
			})
		}
	}
	e.GaugeSnapshot(appHealthOSVersionScoreMetric, "{score}", "Intune Endpoint Analytics application health score (0-100) per OS version, by app-health state.", scorePoints)
	e.GaugeSnapshot(appHealthOSVersionCountMetric, "{device}", "Intune Endpoint Analytics count of devices actively reporting application health, by OS version.", countPoints)
	e.GaugeSnapshot(appHealthOSVersionMTTFMetric, "min", "Intune Endpoint Analytics application mean time to failure (minutes) per OS version; the int32-max 'no failures' sentinel is excluded.", mttfPoints)
	return nil
}

// allowedApp reports whether name (a client executable file name, e.g.
// "outlook.exe") case-insensitively matches the fixed app-name allow-list,
// returning the allow-list's own canonical casing.
func allowedApp(name string) (string, bool) {
	name = strings.ToLower(strings.TrimSpace(name))
	for _, allowed := range defaultAllowedApps {
		if strings.ToLower(allowed) == name {
			return allowed, true
		}
	}
	return "", false
}

func orUnknown(s string) string {
	if s == "" {
		return "unknown"
	}
	return s
}

// deviceScoreDisplay picks the most human-readable identifier a device-score
// row carries for the twin's body line, falling back device name -> id.
func deviceScoreDisplay(d deviceScore) string {
	if d.DeviceName != "" {
		return d.DeviceName
	}
	return orUnknown(d.ID)
}

// isNotLicensed reports whether err is a 403 from a sub-endpoint the tenant is
// not licensed/permitted for - the one genuinely quiet "no data here" skip.
//
// Deliberately 403-only. The previous version also swallowed a "400/404 Resource
// not found for segment" as a "feature not provisioned" gap, but #179 showed
// that was a misdiagnosis: userExperienceAnalyticsOverview (dead segment) and
// the plural userExperienceAnalyticsDeviceStartupHistories (wrong name) BOTH
// returned that exact 400 shape while valid segments on the SAME tenant returned
// 200 with data. A route-segment error means graph2otel asked for a URL that
// does not exist (isWrongEndpoint), not that the tenant lacks the feature - a
// valid UXA segment returns 200 with insufficientData even on an immature
// tenant, never a segment 400. So a segment error must be loud, and only a 403
// stays a quiet skip. [live-measured 2026-07-18, #179]
func isNotLicensed(err error) bool {
	return strings.Contains(err.Error(), "status 403")
}

// isWrongEndpoint reports whether err is Graph's "no such route segment" shape
// (HTTP 400/404, code "ResourceNotFound"/"BadRequest", message "Resource not
// found for [the ]segment '...'"). That is a graph2otel bug - a URL that does
// not exist - so the caller surfaces it loudly rather than skipping it (#179).
func isWrongEndpoint(err error) bool {
	s := err.Error()
	if !strings.Contains(s, "status 400") && !strings.Contains(s, "status 404") {
		return false
	}
	return strings.Contains(s, "ResourceNotFound") ||
		strings.Contains(s, "not found for segment") ||
		strings.Contains(s, "not found for the segment")
}

var (
	_ collector.SnapshotCollector = (*Collector)(nil)
	_ collectors.Experimental     = (*Collector)(nil)
)

func init() {
	collectors.Register(func(d collectors.Deps) collector.SnapshotCollector {
		return New(d.Graph, d.Logger)
	})
}
