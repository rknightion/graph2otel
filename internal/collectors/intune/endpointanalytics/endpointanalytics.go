// Package endpointanalytics is the Intune Endpoint Analytics (User
// Experience Analytics) collector: tenant-posture scores plus bounded
// fleet-shaped aggregates over device startup performance, app crash health,
// battery health, resource performance, and baselines.
//
// MIXED v1.0/beta surface. The tenant-wide overview singleton, the device
// startup history collection, and the app health performance collection are
// all v1.0. The battery health, resource performance, and baseline families
// exist only on /beta. Because this framework's Experimental opt-in is
// per-collector (not per-metric - see internal/collectors.Experimental), and
// a meaningful slice of this collector's value lives on those beta-only
// families, the WHOLE collector is Experimental (opt-in, default-off): when a
// tenant enables it, every signal below is emitted together, including the
// v1.0 overview.
//
// Two of the v1.0 collections (device startup histories, app health
// performance) are PER-BOOT / PER-APPLICATION-INSTANCE rows that scale with
// fleet size and polling cadence - a 10k-device fleet can produce hundreds of
// thousands of startup-history rows a month. Per CLAUDE.md's cardinality
// rule, none of that raw shape becomes a metric label: startup history rolls
// up into bounded boot/login-time HISTOGRAMS (bucketed only by the fixed
// restartCategory enum), and app health crash counts are summed only for a
// small, fixed ALLOW-LIST of common executable names (mirroring
// intune/detectedapps' allow-list pattern) - never a series per raw exe name.
// The beta battery-health and resource-performance families are similarly
// per-device rows, aggregated down to device counts and score histograms by
// the bounded healthStatus enum, never a per-device series.
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
	scoreMetric               = "intune.uxa.score"
	bootTimeMetric            = "intune.uxa.boot_time_ms"
	loginTimeMetric           = "intune.uxa.login_time_ms"
	appCrashCountMetric       = "intune.uxa.app_crash_count"
	batteryDeviceCountMetric  = "intune.uxa.battery_health.device_count"
	batteryScoreMetric        = "intune.uxa.battery_health_score"
	resourceDeviceCountMetric = "intune.uxa.resource_performance.device_count"
	resourceScoreMetric       = "intune.uxa.resource_performance_score"
	baselineScoreMetric       = "intune.uxa.baseline_score"
)

// defaultBaseURL / betaBaseURL: the overview singleton, startup histories,
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

// overview is the subset of the v1.0 userExperienceAnalyticsOverview
// singleton this collector reads
// (https://learn.microsoft.com/en-us/graph/api/resources/intune-devices-userexperienceanalyticsoverview).
type overview struct {
	OverallScore                      int    `json:"overallScore"`
	DeviceBootPerformanceOverallScore int    `json:"deviceBootPerformanceOverallScore"`
	BestPracticesOverallScore         int    `json:"bestPracticesOverallScore"`
	WorkFromAnywhereOverallScore      int    `json:"workFromAnywhereOverallScore"`
	AppHealthOverallScore             int    `json:"appHealthOverallScore"`
	ResourcePerformanceOverallScore   int    `json:"resourcePerformanceOverallScore"`
	BatteryHealthOverallScore         int    `json:"batteryHealthOverallScore"`
	State                             string `json:"state"`
	DeviceBootPerformanceHealthState  string `json:"deviceBootPerformanceHealthState"`
	BestPracticesHealthState          string `json:"bestPracticesHealthState"`
	WorkFromAnywhereHealthState       string `json:"workFromAnywhereHealthState"`
	AppHealthState                    string `json:"appHealthState"`
	ResourcePerformanceHealthState    string `json:"resourcePerformanceHealthState"`
	BatteryHealthState                string `json:"batteryHealthState"`
}

// points returns the overview's 7 fixed category scores as bounded gauge
// points, one per Microsoft-documented schema field - the category set can
// never grow with tenant size, only with a future Graph schema change.
func (o overview) points() []telemetry.GaugePoint {
	cat := func(score int, category, state string) telemetry.GaugePoint {
		return telemetry.GaugePoint{
			Value: float64(score),
			Attrs: telemetry.Attrs{semconv.AttrCategory: category, semconv.AttrHealthState: healthStateBucketFor(state)},
		}
	}
	return []telemetry.GaugePoint{
		cat(o.OverallScore, "overall", o.State),
		cat(o.DeviceBootPerformanceOverallScore, "device_boot_performance", o.DeviceBootPerformanceHealthState),
		cat(o.BestPracticesOverallScore, "best_practices", o.BestPracticesHealthState),
		cat(o.WorkFromAnywhereOverallScore, "work_from_anywhere", o.WorkFromAnywhereHealthState),
		cat(o.AppHealthOverallScore, "app_health", o.AppHealthState),
		cat(o.ResourcePerformanceOverallScore, "resource_performance", o.ResourcePerformanceHealthState),
		cat(o.BatteryHealthOverallScore, "battery_health", o.BatteryHealthState),
	}
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
		{"overview", c.collectOverview},
		{"startup histories", c.collectStartupHistories},
		{"app health", c.collectAppHealth},
		{"battery health", c.collectBatteryHealth},
		{"resource performance", c.collectResourcePerformance},
		{"baselines", c.collectBaselines},
	}

	var errs []error
	for _, f := range fetchers {
		if err := f.fn(ctx, e); err != nil {
			if isUnavailable(err) || isFeatureNotProvisioned(err) {
				c.logger.Info("endpoint analytics sub-endpoint not available on this tenant; skipping",
					"collector", collectorName, "endpoint", f.name, "error", err)
				continue
			}
			c.logger.Warn("endpoint analytics sub-fetch failed", "collector", collectorName, "endpoint", f.name, "error", err)
			errs = append(errs, fmt.Errorf("%s: %w", f.name, err))
		}
	}
	return errors.Join(errs...)
}

func (c *Collector) collectOverview(ctx context.Context, e telemetry.Emitter) error {
	body, err := c.g.RawGet(ctx, c.baseURL+"/deviceManagement/userExperienceAnalyticsOverview")
	if err != nil {
		return err
	}
	var ov overview
	if err := json.Unmarshal(body, &ov); err != nil {
		return fmt.Errorf("decode userExperienceAnalyticsOverview: %w", err)
	}
	e.GaugeSnapshot(scoreMetric, "{score}", "Intune Endpoint Analytics overall and per-category scores (0-100).", ov.points())
	return nil
}

func (c *Collector) collectStartupHistories(ctx context.Context, e telemetry.Emitter) error {
	raw, err := collectors.GetAllValues(ctx, c.g, c.baseURL+"/deviceManagement/userExperienceAnalyticsDeviceStartupHistories", nil)
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

// isUnavailable reports whether err is a 4xx from a sub-endpoint being
// unavailable/unlicensed on the tenant (403 forbidden, 404 not found) - an
// expected "no data here" condition, not a failure.
func isUnavailable(err error) bool {
	s := err.Error()
	return strings.Contains(s, "status 403") || strings.Contains(s, "status 404")
}

// isFeatureNotProvisioned reports whether err is Graph's "the Endpoint
// Analytics feature segment doesn't exist on this tenant at all" shape -
// observed live (M4 verification) as HTTP 400 (sometimes 404), Graph error
// code "ResourceNotFound", message "Resource not found for segment '...'".
// This is NOT the same as insufficientData (a 200 response body state value
// for an enabled-but-immature tenant) - it means the tenant never onboarded
// Endpoint Analytics, so every UXA endpoint 400s this way every cycle.
// Deliberately specific: a plain malformed-query 400 (wrong code/message)
// must still surface as a real collector error, not be silently swallowed.
func isFeatureNotProvisioned(err error) bool {
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
