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

	// appHealthDeviceCountMetric (#225) is the DEVICE-level app-health rollup,
	// its own metric name rather than a dimension on the OS-version gauge so a
	// naive sum() over either yields a true device count.
	appHealthDeviceCountMetric = "intune.uxa.app_health.device_count"
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

// The remaining per-entity twins, added in #225 when the maintainer overrode the
// #114 no-twin exception this collector had carried since the original audit.
//
// The exception's rationale was that boot/startup performance is an ops question
// the Intune console answers better, and that one record per boot per device is a
// volume a twin does not earn. That reasoning was accepted for two years and is
// deliberately reversed here: the console shows current state, not history, so it
// cannot answer "how has this device's battery decayed over six months" or "which
// devices share this crash bucket" — and those are the questions the aggregate
// metrics provably cannot answer either. #179 and #194 had already overridden the
// exception for two sub-fetches without recording why; this completes it and
// docs/pii-cardinality-audit.md now records the whole decision rather than a
// stale "no twin" claim.
//
// All four follow the intune.device_* convention and sit outside the
// intune.uxa.* metric namespace so a twin can never collide with a metric name.
const (
	eventBatteryHealth       = "intune.device_battery_health"
	eventDeviceStartup       = "intune.device_startup"
	eventStartupProcess      = "intune.device_startup_process"
	eventDeviceAppHealth     = "intune.device_app_health"
	eventResourcePerformance = "intune.device_resource_performance"

	// eventAppHealth is the APPLICATION-level twin, so it deliberately breaks the
	// intune.device_* convention above — its entity is an application, not a
	// device. It still sits outside intune.uxa.*, so it cannot collide with a
	// metric name.
	eventAppHealth = "intune.app_health"
)

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

// healthStateMeetingGoals is the bucketed value for a healthy device — the one
// state that does NOT raise a twin to WARN.
const healthStateMeetingGoals = "meeting_goals"

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
// startupHistory is one BOOT EVENT, not a device state: each row is a single
// restart with its own startTime. That distinction drives two decisions below —
// the twin is stamped with startTime rather than poll time (a state twin like
// deviceScore deliberately is not), and the timing fields carry the -1
// "not enough data" sentinel per field (#224).
//
// restartStopCode / restartFaultBucket are the Windows crash-bucket identifiers.
// They are the reason the per-boot twin was worth building: a histogram bucketed
// by restart_category can say "three blue screens" but never "three blue screens
// all in fault bucket X", which is the difference between noticing a problem and
// diagnosing it.
type startupHistory struct {
	DeviceID                  string  `json:"deviceId"`
	StartTime                 string  `json:"startTime"`
	CoreBootTimeInMs          float64 `json:"coreBootTimeInMs"`
	GroupPolicyBootTimeInMs   float64 `json:"groupPolicyBootTimeInMs"`
	FeatureUpdateBootTimeInMs float64 `json:"featureUpdateBootTimeInMs"`
	TotalBootTimeInMs         float64 `json:"totalBootTimeInMs"`
	CoreLoginTimeInMs         float64 `json:"coreLoginTimeInMs"`
	GroupPolicyLoginTimeInMs  float64 `json:"groupPolicyLoginTimeInMs"`
	ResponsiveDesktopTimeInMs float64 `json:"responsiveDesktopTimeInMs"`
	TotalLoginTimeInMs        float64 `json:"totalLoginTimeInMs"`
	IsFirstLogin              bool    `json:"isFirstLogin"`
	IsFeatureUpdate           bool    `json:"isFeatureUpdate"`
	OperatingSystemVersion    string  `json:"operatingSystemVersion"`
	RestartCategory           string  `json:"restartCategory"`
	RestartStopCode           string  `json:"restartStopCode"`
	RestartFaultBucket        string  `json:"restartFaultBucket"`
}

// startupProcess is one (device, startup process) pair from the beta
// userExperienceAnalyticsDeviceStartupProcesses segment (#199).
//
// TRAP (live-measured 2026-07-21): this segment REJECTS $top at any value with a
// 400, and $count with it, while $orderby is accepted and the bare list works.
// That is the inverse of the usual per-endpoint $top ceiling documented in
// docs/graph-api-gotchas.md — there is no ceiling to stay under, the parameter is
// simply unsupported. The sibling DeviceStartupHistory segment has the same
// trigger but answers 500 instead of 400, so a 5xx here is not a transient fault.
// collectors.GetAllValues paginates with the Prefer: odata.maxpagesize header and
// never emits $top, which is why both fetches work.
//
// The (device, process) pair is unbounded, so nothing here may be a metric label —
// this sub-fetch is twin-only, with no metric at all.
type startupProcess struct {
	ManagedDeviceID   string  `json:"managedDeviceId"`
	ProcessName       string  `json:"processName"`
	ProductName       string  `json:"productName"`
	Publisher         string  `json:"publisher"`
	StartupImpactInMs float64 `json:"startupImpactInMs"`
}

// appHealthDevicePerformance is the DEVICE-level sibling of the application-level
// app-health segment (#225). It matters because the application-level segment is
// empty on tenants under the 5-device Endpoint Analytics floor while this one
// returns rows, so it is the only live source of appHangCount and
// meanTimeToFailureInMinutes on a small tenant — the fields #194 parked.
//
// meanTimeToFailureInMinutes carries the same int32-max "no failures observed"
// sentinel as the OS-version segment, excluded via mttfNoFailuresSentinel.
type appHealthDevicePerformance struct {
	DeviceID                   string  `json:"deviceId"`
	DeviceDisplayName          string  `json:"deviceDisplayName"`
	DeviceModel                string  `json:"deviceModel"`
	DeviceManufacturer         string  `json:"deviceManufacturer"`
	AppCrashCount              int64   `json:"appCrashCount"`
	CrashedAppCount            int64   `json:"crashedAppCount"`
	AppHangCount               int64   `json:"appHangCount"`
	MeanTimeToFailureInMinutes int64   `json:"meanTimeToFailureInMinutes"`
	DeviceAppHealthScore       float64 `json:"deviceAppHealthScore"`
	HealthStatus               string  `json:"healthStatus"`
}

// appHealthPerformance is the subset of the v1.0
// userExperienceAnalyticsAppHealthApplicationPerformance resource this
// collector reads
// (https://learn.microsoft.com/en-us/graph/api/resources/intune-devices-userexperienceanalyticsapphealthapplicationperformance).
type appHealthPerformance struct {
	AppName        string  `json:"appName"`
	AppDisplayName string  `json:"appDisplayName"`
	AppPublisher   string  `json:"appPublisher"`
	AppCrashCount  int64   `json:"appCrashCount"`
	AppHangCount   int64   `json:"appHangCount"`
	AppHealthScore float64 `json:"appHealthScore"`
	// AppHealthStatus is "TBD" on every observed row — an undocumented wire
	// value, bucketed like any other rather than "corrected" (#142).
	AppHealthStatus string `json:"appHealthStatus"`
	// ActiveDeviceCount disagreed with the per-device sibling on m7kni (8 here
	// vs 1 row from AppHealthDevicePerformance, live 2026-07-23). Recorded, not
	// reconciled — they are not two views of one set.
	ActiveDeviceCount          int64 `json:"activeDeviceCount"`
	AppUsageDuration           int64 `json:"appUsageDuration"`
	MeanTimeToFailureInMinutes int64 `json:"meanTimeToFailureInMinutes"`
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

// batteryHealthPerformance is the beta
// userExperienceAnalyticsBatteryHealthDevicePerformance resource.
//
// The fields beyond the score are the ones that make it ACTIONABLE. A bare
// "63" is not: it cannot distinguish a two-year-old battery at end of life from
// a new one with a firmware fault. "63, 179 days old, 100% max capacity, 80
// minutes estimated runtime" can. All of it rides the twin; the metric keeps
// only the bounded health_state bucket (#112).
//
// fullBatteryDrainCount is live-observed as -1 on a real device (2026-07-21) —
// the same "not enough data" sentinel as the score, omitted rather than emitted
// as a real drain count of minus one.
type batteryHealthPerformance struct {
	DeviceID                  string  `json:"deviceId"`
	DeviceName                string  `json:"deviceName"`
	Model                     string  `json:"model"`
	Manufacturer              string  `json:"manufacturer"`
	MaxCapacityPercentage     float64 `json:"maxCapacityPercentage"`
	EstimatedRuntimeInMinutes float64 `json:"estimatedRuntimeInMinutes"`
	BatteryAgeInDays          float64 `json:"batteryAgeInDays"`
	FullBatteryDrainCount     float64 `json:"fullBatteryDrainCount"`
	DeviceBatteryCount        int64   `json:"deviceBatteryCount"`
	DeviceBatteriesDetails    []struct {
		BatteryID string `json:"batteryId"`
	} `json:"deviceBatteriesDetails"`
	DeviceBatteryHealthScore float64 `json:"deviceBatteryHealthScore"`
	HealthStatus             string  `json:"healthStatus"`
}

// resourcePerformance is the subset of the beta
// userExperienceAnalyticsResourcePerformance resource this collector reads.
// NOTE ON EVIDENCE: this segment returns 0 rows on m7kni — it sits under the same
// 5-device Endpoint Analytics floor as the per-model segments (#194) — so unlike
// every other struct in this file the field names below are taken from the beta
// $metadata EDM (2026-07-21), NOT from an observed row. That is a weaker evidence
// class and is recorded as such rather than dressed up as live-measured.
//
// The exposure is bounded by construction: every field is emitted only when
// present, so a name that turns out to be wrong yields an ABSENT twin attribute
// rather than a wrong value. Nothing here is asserted into a metric label.
type resourcePerformance struct {
	DeviceID                       string  `json:"deviceId"`
	DeviceName                     string  `json:"deviceName"`
	Model                          string  `json:"model"`
	Manufacturer                   string  `json:"manufacturer"`
	CPUDisplayName                 string  `json:"cpuDisplayName"`
	CPUSpikeTimePercentage         float64 `json:"cpuSpikeTimePercentage"`
	RAMSpikeTimePercentage         float64 `json:"ramSpikeTimePercentage"`
	TotalRAMInMB                   float64 `json:"totalRamInMB"`
	TotalProcessorCoreCount        int64   `json:"totalProcessorCoreCount"`
	DiskType                       string  `json:"diskType"`
	MachineType                    string  `json:"machineType"`
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
		{"app health device performance", c.collectAppHealthDevicePerformance},
		{"startup processes", c.collectStartupProcesses},
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
		// Per-FIELD sentinel guard, not per-row (#224): a live row routinely
		// carries a real measurement in one timing field and -1 in the other,
		// so dropping the whole row would discard genuine data. Omit rather
		// than clamp — a 0ms boot is as wrong as -1 and harder to notice.
		if h.TotalBootTimeInMs >= 0 {
			e.Histogram(bootTimeMetric, "ms", "Intune Endpoint Analytics device boot time, by restart category; the -1 'not enough data' sentinel is excluded.", h.TotalBootTimeInMs, bootTimeBounds, attrs)
		}
		if h.TotalLoginTimeInMs >= 0 {
			e.Histogram(loginTimeMetric, "ms", "Intune Endpoint Analytics device login time, by restart category; the -1 'not enough data' sentinel is excluded.", h.TotalLoginTimeInMs, bootTimeBounds, attrs)
		}

		// The per-boot twin (#225). Every timing field gets the same per-field
		// sentinel guard as the two histogram fields above, so the twin never
		// reports a -1 millisecond phase.
		twin := telemetry.Attrs{semconv.AttrRestartCategory: bucket}
		telemetry.SetStr(twin, semconv.AttrDeviceId, h.DeviceID)
		telemetry.SetStr(twin, semconv.AttrOsVersion, h.OperatingSystemVersion)
		telemetry.SetStr(twin, semconv.AttrRestartStopCode, h.RestartStopCode)
		telemetry.SetStr(twin, semconv.AttrRestartFaultBucket, h.RestartFaultBucket)
		telemetry.SetBool(twin, semconv.AttrIsFirstLogin, h.IsFirstLogin)
		telemetry.SetBool(twin, semconv.AttrIsFeatureUpdate, h.IsFeatureUpdate)
		for _, f := range []struct {
			attr  string
			value float64
		}{
			{semconv.AttrCoreBootTimeMs, h.CoreBootTimeInMs},
			{semconv.AttrGroupPolicyBootTimeMs, h.GroupPolicyBootTimeInMs},
			{semconv.AttrFeatureUpdateBootTimeMs, h.FeatureUpdateBootTimeInMs},
			{semconv.AttrTotalBootTimeMs, h.TotalBootTimeInMs},
			{semconv.AttrCoreLoginTimeMs, h.CoreLoginTimeInMs},
			{semconv.AttrGroupPolicyLoginTimeMs, h.GroupPolicyLoginTimeInMs},
			{semconv.AttrResponsiveDesktopTimeMs, h.ResponsiveDesktopTimeInMs},
			{semconv.AttrTotalLoginTimeMs, h.TotalLoginTimeInMs},
		} {
			if f.value >= 0 {
				twin[f.attr] = strconv.FormatFloat(f.value, 'f', -1, 64)
			}
		}
		// Unlike the state twins in this file, a boot is an EVENT: it happened at
		// startTime and stamping it with poll time would pile every historical
		// restart onto one instant. An unparseable startTime leaves the timestamp
		// zero, which the emitter treats as "no event time" — per CLAUDE.md a
		// record must never be stamped on arrival, because that would silently
		// claim the boot happened now.
		ev := telemetry.Event{
			Name:     eventDeviceStartup,
			Body:     fmt.Sprintf("device startup: category=%s total_boot=%s", orUnknown(h.RestartCategory), msOrUnknown(h.TotalBootTimeInMs)),
			Severity: startupSeverity(h),
			Attrs:    twin,
		}
		if ts, err := time.Parse(time.RFC3339, h.StartTime); err == nil {
			ev.Timestamp = ts
		}
		e.LogEvent(ev)
	}
	return nil
}

// startupSeverity raises a boot record that carries crash evidence. A stop code
// or fault bucket means the restart was a failure, not a routine reboot, and that
// is the whole reason these fields are worth carrying.
func startupSeverity(h startupHistory) telemetry.Severity {
	if h.RestartFaultBucket != "" || h.RestartStopCode != "" && h.RestartStopCode != "0" {
		return telemetry.SeverityWarn
	}
	return telemetry.SeverityInfo
}

// msOrUnknown renders a timing field for a log body, collapsing the -1
// "not enough data" sentinel to "unknown" rather than printing "-1".
func msOrUnknown(v float64) string {
	if v < 0 {
		return "unknown"
	}
	return strconv.FormatFloat(v, 'f', -1, 64) + "ms"
}

// collectStartupProcesses fetches the per-(device, process) startup impact
// (#199). It is TWIN-ONLY and emits no metric: the pair is unbounded, so every
// aggregation shape would either grow with the fleet or need an arbitrary
// allow-list. A LogQL topk over startup_impact_ms answers the same question.
func (c *Collector) collectStartupProcesses(ctx context.Context, e telemetry.Emitter) error {
	raw, err := collectors.GetAllValues(ctx, c.g, c.beta+"/deviceManagement/userExperienceAnalyticsDeviceStartupProcesses", nil)
	if err != nil {
		return err
	}
	for _, r := range raw {
		var p startupProcess
		if err := json.Unmarshal(r, &p); err != nil {
			c.logger.Warn("endpoint_analytics: skipping malformed startup process row", "collector", collectorName, "error", err)
			continue
		}
		attrs := telemetry.Attrs{}
		telemetry.SetStr(attrs, semconv.AttrDeviceId, p.ManagedDeviceID)
		telemetry.SetStr(attrs, semconv.AttrProcessName, p.ProcessName)
		telemetry.SetStr(attrs, semconv.AttrProductName, p.ProductName)
		telemetry.SetStr(attrs, semconv.AttrPublisher, p.Publisher)
		if p.StartupImpactInMs >= 0 {
			attrs[semconv.AttrStartupImpactMs] = strconv.FormatFloat(p.StartupImpactInMs, 'f', -1, 64)
		}
		e.LogEvent(telemetry.Event{
			Name:     eventStartupProcess,
			Body:     fmt.Sprintf("startup process %s: impact=%s", orUnknown(p.ProcessName), msOrUnknown(p.StartupImpactInMs)),
			Severity: telemetry.SeverityInfo,
			Attrs:    attrs,
		})
	}
	return nil
}

// collectAppHealthDevicePerformance fetches the DEVICE-level app-health rows
// (#225). On a tenant under the 5-device Endpoint Analytics floor this is the
// only live source of appHangCount and meanTimeToFailureInMinutes, which #194
// parked because the application-level segment is empty there.
func (c *Collector) collectAppHealthDevicePerformance(ctx context.Context, e telemetry.Emitter) error {
	raw, err := collectors.GetAllValues(ctx, c.g, c.beta+"/deviceManagement/userExperienceAnalyticsAppHealthDevicePerformance", nil)
	if err != nil {
		return err
	}
	counts := map[string]int64{}
	for _, r := range raw {
		var a appHealthDevicePerformance
		if err := json.Unmarshal(r, &a); err != nil {
			c.logger.Warn("endpoint_analytics: skipping malformed app health device row", "collector", collectorName, "error", err)
			continue
		}
		state := healthStateBucketFor(a.HealthStatus)
		counts[state]++

		attrs := telemetry.Attrs{semconv.AttrHealthState: state}
		telemetry.SetStr(attrs, semconv.AttrDeviceId, a.DeviceID)
		telemetry.SetStr(attrs, semconv.AttrDeviceName, a.DeviceDisplayName)
		telemetry.SetStr(attrs, semconv.AttrModel, a.DeviceModel)
		telemetry.SetStr(attrs, semconv.AttrManufacturer, a.DeviceManufacturer)
		attrs[semconv.AttrAppCrashCount] = strconv.FormatInt(a.AppCrashCount, 10)
		attrs[semconv.AttrCrashedAppCount] = strconv.FormatInt(a.CrashedAppCount, 10)
		attrs[semconv.AttrAppHangCount] = strconv.FormatInt(a.AppHangCount, 10)
		if a.DeviceAppHealthScore >= 0 {
			attrs[semconv.AttrDeviceAppHealthScore] = strconv.FormatFloat(a.DeviceAppHealthScore, 'f', -1, 64)
		}
		// int32-max is "no failures observed", not a ~4085-year MTTF (#194).
		if a.MeanTimeToFailureInMinutes != mttfNoFailuresSentinel {
			attrs[semconv.AttrMeanTimeToFailureMinutes] = strconv.FormatInt(a.MeanTimeToFailureInMinutes, 10)
		}
		e.LogEvent(telemetry.Event{
			Name:     eventDeviceAppHealth,
			Body:     fmt.Sprintf("app health for %s: crashes=%d hangs=%d", orUnknown(a.DeviceDisplayName), a.AppCrashCount, a.AppHangCount),
			Severity: severityIf(a.AppCrashCount > 0 || a.AppHangCount > 0),
			Attrs:    attrs,
		})
	}
	points := make([]telemetry.GaugePoint, 0, len(counts))
	for state, n := range counts {
		points = append(points, telemetry.GaugePoint{Value: float64(n), Attrs: telemetry.Attrs{semconv.AttrHealthState: state}})
	}
	e.GaugeSnapshot(appHealthDeviceCountMetric, "{device}", "Intune Endpoint Analytics device count, by application health state.", points)
	return nil
}

// batteryIDs pulls the per-battery identifiers out of deviceBatteriesDetails.
// A multi-battery laptop reports one entry per cell, so this is what lets a
// reader tell "one bad cell" from "a worn pack" — the aggregate score cannot.
func batteryIDs(b batteryHealthPerformance) []string {
	ids := make([]string, 0, len(b.DeviceBatteriesDetails))
	for _, d := range b.DeviceBatteriesDetails {
		if d.BatteryID != "" {
			ids = append(ids, d.BatteryID)
		}
	}
	return ids
}

// severityIf raises to WARN when the actionable condition holds.
func severityIf(warn bool) telemetry.Severity {
	if warn {
		return telemetry.SeverityWarn
	}
	return telemetry.SeverityInfo
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
		// The twin is emitted for EVERY row, before any allow-list gating. The
		// allow-list below bounds the METRIC (application names are unbounded, so
		// a series per app would scale with the tenant, #112) — it is not a
		// judgement that unlisted apps are uninteresting. Dropping them was a
		// #114 violation: the collector paid for the fetch and could then answer
		// "how many crashes" for eight executables and nothing at all for the
		// rest. On m7kni that meant discarding 100% of the data, the only live
		// row being LogonUI.exe.
		state := healthStateBucketFor(a.AppHealthStatus)
		attrs := telemetry.Attrs{semconv.AttrHealthState: state}
		telemetry.SetStr(attrs, semconv.AttrAppName, a.AppName)
		telemetry.SetStr(attrs, semconv.AttrAppDisplayName, a.AppDisplayName)
		telemetry.SetStr(attrs, semconv.AttrPublisher, a.AppPublisher)
		attrs[semconv.AttrAppCrashCount] = strconv.FormatInt(a.AppCrashCount, 10)
		attrs[semconv.AttrAppHangCount] = strconv.FormatInt(a.AppHangCount, 10)
		attrs[semconv.AttrActiveDeviceCount] = strconv.FormatInt(a.ActiveDeviceCount, 10)
		attrs[semconv.AttrAppUsageDuration] = strconv.FormatInt(a.AppUsageDuration, 10)
		if a.AppHealthScore >= 0 {
			attrs[semconv.AttrAppHealthScore] = strconv.FormatFloat(a.AppHealthScore, 'f', -1, 64)
		}
		// int32-max is "no failures observed", not a ~4085-year MTTF (#194).
		if a.MeanTimeToFailureInMinutes != mttfNoFailuresSentinel {
			attrs[semconv.AttrMeanTimeToFailureMinutes] = strconv.FormatInt(a.MeanTimeToFailureInMinutes, 10)
		}
		e.LogEvent(telemetry.Event{
			Name:     eventAppHealth,
			Body:     fmt.Sprintf("app health for %s: crashes=%d hangs=%d devices=%d", orUnknown(a.AppName), a.AppCrashCount, a.AppHangCount, a.ActiveDeviceCount),
			Severity: severityIf(a.AppCrashCount > 0 || a.AppHangCount > 0),
			Attrs:    attrs,
		})

		name := strings.ToLower(strings.TrimSpace(a.AppName))
		if name == "" {
			continue
		}
		crashes[name] += a.AppCrashCount
	}
	points := make([]telemetry.GaugePoint, 0, len(crashes))
	for app, count := range crashes {
		points = append(points, telemetry.GaugePoint{Value: float64(count), Attrs: telemetry.Attrs{semconv.AttrAppName: app}})
	}
	e.GaugeSnapshot(appCrashCountMetric, "{crash}",
		"Intune Endpoint Analytics app crash count by client executable. Bounded by the central "+
			"cardinality limiter: past cardinality.per_metric_limit the top executables by crash count "+
			"are kept and the tail folds into app_name=\"other\".", points)
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
		// -1 = "not enough data yet" (#224). The device still counts under its
		// health state; only the score observation is suppressed.
		if b.DeviceBatteryHealthScore >= 0 {
			e.Histogram(batteryScoreMetric, "{score}", "Intune Endpoint Analytics device battery health score (0-100), by health state; the -1 'not enough data' sentinel is excluded.",
				b.DeviceBatteryHealthScore, scoreBounds, telemetry.Attrs{semconv.AttrHealthState: state})
		}

		// The per-device twin (#225) — the fields that explain the score.
		attrs := telemetry.Attrs{semconv.AttrHealthState: state}
		telemetry.SetStr(attrs, semconv.AttrDeviceId, b.DeviceID)
		telemetry.SetStr(attrs, semconv.AttrDeviceName, b.DeviceName)
		telemetry.SetStr(attrs, semconv.AttrModel, b.Model)
		telemetry.SetStr(attrs, semconv.AttrManufacturer, b.Manufacturer)
		if b.DeviceBatteryCount > 0 { // 0 = not reported, unlike a crash count where 0 is real
			attrs[semconv.AttrBatteryCount] = strconv.FormatInt(b.DeviceBatteryCount, 10)
		}
		for _, f := range []struct {
			attr  string
			value float64
		}{
			{semconv.AttrBatteryHealthScore, b.DeviceBatteryHealthScore},
			{semconv.AttrMaxCapacityPercentage, b.MaxCapacityPercentage},
			{semconv.AttrEstimatedRuntimeMinutes, b.EstimatedRuntimeInMinutes},
			{semconv.AttrBatteryAgeDays, b.BatteryAgeInDays},
			// Live-observed as -1 on a real device (2026-07-21): the same
			// "not enough data" sentinel, omitted rather than emitted as a
			// drain count of minus one.
			{semconv.AttrFullBatteryDrainCount, b.FullBatteryDrainCount},
		} {
			if f.value >= 0 {
				attrs[f.attr] = strconv.FormatFloat(f.value, 'f', -1, 64)
			}
		}
		if ids := batteryIDs(b); len(ids) > 0 {
			telemetry.SetStrs(attrs, semconv.AttrBatteryIds, ids)
		}
		// State feed, re-emitted every cycle — timestamp left zero (poll time),
		// same reasoning as the device-scores twin above.
		e.LogEvent(telemetry.Event{
			Name:     eventBatteryHealth,
			Body:     fmt.Sprintf("battery health for %s: health=%s", orUnknown(b.DeviceName), orUnknown(b.HealthStatus)),
			Severity: severityIf(state != healthStateMeetingGoals),
			Attrs:    attrs,
		})
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
		// -1 = "not enough data yet" (#224); see collectBatteryHealth.
		if rp.DeviceResourcePerformanceScore >= 0 {
			e.Histogram(resourceScoreMetric, "{score}", "Intune Endpoint Analytics device resource performance score (0-100), by health state; the -1 'not enough data' sentinel is excluded.",
				rp.DeviceResourcePerformanceScore, scoreBounds, telemetry.Attrs{semconv.AttrHealthState: state})
		}

		// The per-device twin (#225). NOTE: this segment is empty on the only
		// tenant available, so these mappings are EDM-derived, not live-verified
		// — see the resourcePerformance struct doc. Everything is emitted only
		// when present, so a wrong field name yields an absent attribute.
		attrs := telemetry.Attrs{semconv.AttrHealthState: state}
		telemetry.SetStr(attrs, semconv.AttrDeviceId, rp.DeviceID)
		telemetry.SetStr(attrs, semconv.AttrDeviceName, rp.DeviceName)
		telemetry.SetStr(attrs, semconv.AttrModel, rp.Model)
		telemetry.SetStr(attrs, semconv.AttrManufacturer, rp.Manufacturer)
		telemetry.SetStr(attrs, semconv.AttrCpuDisplayName, rp.CPUDisplayName)
		telemetry.SetStr(attrs, semconv.AttrDiskType, rp.DiskType)
		telemetry.SetStr(attrs, semconv.AttrMachineType, rp.MachineType)
		if rp.TotalProcessorCoreCount > 0 { // 0 = not reported
			attrs[semconv.AttrProcessorCoreCount] = strconv.FormatInt(rp.TotalProcessorCoreCount, 10)
		}
		for _, f := range []struct {
			attr  string
			value float64
		}{
			{semconv.AttrResourcePerformanceScore, rp.DeviceResourcePerformanceScore},
			{semconv.AttrCpuSpikeTimePercentage, rp.CPUSpikeTimePercentage},
			{semconv.AttrRamSpikeTimePercentage, rp.RAMSpikeTimePercentage},
			{semconv.AttrTotalRamMb, rp.TotalRAMInMB},
		} {
			if f.value >= 0 {
				attrs[f.attr] = strconv.FormatFloat(f.value, 'f', -1, 64)
			}
		}
		e.LogEvent(telemetry.Event{
			Name:     eventResourcePerformance,
			Body:     fmt.Sprintf("resource performance for %s: health=%s", orUnknown(rp.DeviceName), orUnknown(rp.HealthStatus)),
			Severity: severityIf(state != healthStateMeetingGoals),
			Attrs:    attrs,
		})
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
