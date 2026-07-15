// Package compliance is the Intune device-compliance collector: the
// tenant-wide compliance state rollup, the per-policy device/user status
// overviews, the per-setting compliance summary, and a policy-version gauge
// for change detection.
//
// This deliberately polls only the cheap aggregate/overview endpoints — the
// tenant singleton, the bounded (tens) policy list, one overview singleton
// per policy, and the setting-state summary list (bounded by the tenant's
// unique-setting catalog). It never walks the per-device×policy(×setting)
// status children (deviceStatuses, userStatuses,
// deviceComplianceSettingStates, per-device deviceCompliancePolicyStates):
// those are device×policy cross-products that would put a per-device
// identifier on a metric label, the primary cardinality bomb this collector
// exists to avoid. On-demand/fleet-wide per-device compliance detail is a
// logs-pipeline concern for a later milestone, not this collector.
package compliance

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
const collectorName = "intune.compliance"

// Metric names this collector emits. Each is its own metric name (rather than
// stuffing independent dimensions under one name) so that summing a single
// metric always yields the true total for that breakdown — mixing
// independent dimensions under one metric name would mean a naive `sum()`
// over it silently multi-counts.
const (
	devicesMetricName        = "intune.compliance.devices"
	policyVersionMetricName  = "intune.compliance.policy.version"
	policyDevicesMetricName  = "intune.compliance.policy.devices"
	policyUsersMetricName    = "intune.compliance.policy.users"
	settingDevicesMetricName = "intune.compliance.setting.devices"
)

// defaultBaseURL is the Graph v1.0 root. Every endpoint this collector polls
// (deviceCompliancePolicyDeviceStateSummary, deviceCompliancePolicies, their
// deviceStatusOverview/userStatusOverview children, and
// deviceCompliancePolicySettingStateSummaries) is v1.0 today.
const defaultBaseURL = "https://graph.microsoft.com/v1.0"

// Collector polls the Intune device-compliance summary/overview endpoints.
type Collector struct {
	g       collectors.GraphClient
	baseURL string
	logger  *slog.Logger
}

// New builds the compliance collector. A nil logger falls back to the slog
// default.
func New(g collectors.GraphClient, logger *slog.Logger) *Collector {
	if logger == nil {
		logger = slog.Default()
	}
	return &Collector{g: g, baseURL: defaultBaseURL, logger: logger}
}

// Name implements collector.Collector.
func (c *Collector) Name() string { return collectorName }

// DefaultInterval implements collector.Collector. The tenant-wide state
// summary alone is cheap enough to poll every few minutes, but this
// collector also fans out two overview requests per compliance policy plus
// the setting-summary list on every cycle, so the whole collector gets a
// slower cadence sized to that heavier combined cost rather than the
// cheapest single endpoint. Compliance state also lags real device check-in
// by minutes to hours (see Collect), so polling faster than that buys
// nothing.
func (c *Collector) DefaultInterval() time.Duration { return 15 * time.Minute }

// RequiredPermissions declares the least-privilege Graph application scope.
// Every endpoint this collector reads is documented under
// DeviceManagementConfiguration.Read.All.
func (c *Collector) RequiredPermissions() []string {
	return []string{"DeviceManagementConfiguration.Read.All"}
}

// Collect fetches the tenant state summary, the policy inventory (plus its
// per-policy status-overview fan-out), and the setting-state summaries.
// Each of the three phases is independently resilient: a failure in one is
// logged and joined into the returned error, but does not prevent the
// others from emitting. A 403 (missing scope, or Intune not licensed on this
// tenant) is treated as an expected "no data here" condition — skipped and
// logged at Info, not surfaced as an error — since every one of these
// endpoints requires an active Intune license on the tenant in addition to
// the Graph scope.
//
// Overview counts lag real client check-in by minutes to hours; a transient
// mismatch against a device's actual last-known state is expected, not a
// bug.
func (c *Collector) Collect(ctx context.Context, e telemetry.Emitter) error {
	var errs []error

	if err := c.collectDeviceStateSummary(ctx, e); err != nil {
		if isForbidden(err) {
			c.logger.Info("compliance: device state summary unavailable on this tenant; skipping",
				"collector", collectorName, "error", err)
		} else {
			c.logger.Warn("compliance: device state summary fetch failed", "collector", collectorName, "error", err)
			errs = append(errs, fmt.Errorf("device state summary: %w", err))
		}
	}

	policies, err := c.collectPolicies(ctx, e)
	if err != nil {
		if isForbidden(err) {
			c.logger.Info("compliance: policy list unavailable on this tenant; skipping",
				"collector", collectorName, "error", err)
		} else {
			c.logger.Warn("compliance: policy list fetch failed", "collector", collectorName, "error", err)
			errs = append(errs, fmt.Errorf("policy list: %w", err))
		}
	}
	if len(policies) > 0 {
		if err := c.collectPolicyOverviews(ctx, e, policies); err != nil {
			errs = append(errs, err)
		}
	}

	if err := c.collectSettingStateSummaries(ctx, e); err != nil {
		if isForbidden(err) {
			c.logger.Info("compliance: setting state summaries unavailable on this tenant; skipping",
				"collector", collectorName, "error", err)
		} else {
			c.logger.Warn("compliance: setting state summaries fetch failed", "collector", collectorName, "error", err)
			errs = append(errs, fmt.Errorf("setting state summaries: %w", err))
		}
	}

	return errors.Join(errs...)
}

// deviceStateSummary is the tenant-wide singleton
// GET /deviceManagement/deviceCompliancePolicyDeviceStateSummary. Field
// names mirror the documented resource exactly (some carry a "Device" infix,
// some don't — that's Graph's own naming, not a typo here).
type deviceStateSummary struct {
	UnknownDeviceCount       int64 `json:"unknownDeviceCount"`
	NotApplicableDeviceCount int64 `json:"notApplicableDeviceCount"`
	CompliantDeviceCount     int64 `json:"compliantDeviceCount"`
	RemediatedDeviceCount    int64 `json:"remediatedDeviceCount"`
	NonCompliantDeviceCount  int64 `json:"nonCompliantDeviceCount"`
	ErrorDeviceCount         int64 `json:"errorDeviceCount"`
	ConflictDeviceCount      int64 `json:"conflictDeviceCount"`
	InGracePeriodCount       int64 `json:"inGracePeriodCount"`
	ConfigManagerCount       int64 `json:"configManagerCount"`
}

// collectDeviceStateSummary fetches the tenant-wide singleton and emits it as
// the headline intune.compliance.devices{state} gauge set. This is the
// cheapest call this collector makes (no pagination, no per-entity fan-out).
func (c *Collector) collectDeviceStateSummary(ctx context.Context, e telemetry.Emitter) error {
	body, err := c.g.RawGet(ctx, c.baseURL+"/deviceManagement/deviceCompliancePolicyDeviceStateSummary")
	if err != nil {
		return err
	}
	var s deviceStateSummary
	if err := json.Unmarshal(body, &s); err != nil {
		return fmt.Errorf("decode deviceCompliancePolicyDeviceStateSummary: %w", err)
	}

	points := []telemetry.GaugePoint{
		{Value: float64(s.CompliantDeviceCount), Attrs: telemetry.Attrs{"state": "compliant"}},
		{Value: float64(s.NonCompliantDeviceCount), Attrs: telemetry.Attrs{"state": "non_compliant"}},
		{Value: float64(s.InGracePeriodCount), Attrs: telemetry.Attrs{"state": "in_grace_period"}},
		{Value: float64(s.ConfigManagerCount), Attrs: telemetry.Attrs{"state": "config_manager"}},
		{Value: float64(s.UnknownDeviceCount), Attrs: telemetry.Attrs{"state": "unknown"}},
		{Value: float64(s.NotApplicableDeviceCount), Attrs: telemetry.Attrs{"state": "not_applicable"}},
		{Value: float64(s.RemediatedDeviceCount), Attrs: telemetry.Attrs{"state": "remediated"}},
		{Value: float64(s.ErrorDeviceCount), Attrs: telemetry.Attrs{"state": "error"}},
		{Value: float64(s.ConflictDeviceCount), Attrs: telemetry.Attrs{"state": "conflict"}},
	}
	e.GaugeSnapshot(devicesMetricName, "{device}", "Tenant-wide Intune device compliance state summary.", points)
	return nil
}

// policySummary is the base deviceCompliancePolicy shape. Per Microsoft's own
// docs the base type returns only 6 shared properties (id, displayName,
// description, createdDateTime, lastModifiedDateTime, version) — the
// concrete platform subtype is required to read actual rule content, but
// this collector only needs id/displayName/version, all base props, so no
// subtype request is needed here.
type policySummary struct {
	ID          string `json:"id"`
	DisplayName string `json:"displayName"`
	Version     int64  `json:"version"`
}

// policyRef is the bounded (id, name) pair this collector carries from the
// policy inventory into the per-policy overview fan-out.
type policyRef struct {
	id   string
	name string
}

// collectPolicies pages the (tenant-config-bounded, tens of policies)
// compliance-policy inventory, emits the policy-version gauge for
// change-detection, and returns the (id, name) pairs the per-policy overview
// fan-out needs.
func (c *Collector) collectPolicies(ctx context.Context, e telemetry.Emitter) ([]policyRef, error) {
	raw, err := collectors.GetAllValues(ctx, c.g, c.baseURL+"/deviceManagement/deviceCompliancePolicies", nil)
	if err != nil {
		return nil, err
	}

	refs := make([]policyRef, 0, len(raw))
	points := make([]telemetry.GaugePoint, 0, len(raw))
	for _, r := range raw {
		var p policySummary
		if err := json.Unmarshal(r, &p); err != nil {
			c.logger.Warn("compliance: skipping unparseable deviceCompliancePolicy", "collector", collectorName, "error", err)
			continue
		}
		if p.ID == "" {
			c.logger.Warn("compliance: skipping deviceCompliancePolicy with empty id", "collector", collectorName)
			continue
		}
		name := orUnknown(p.DisplayName)
		refs = append(refs, policyRef{id: p.ID, name: name})
		points = append(points, telemetry.GaugePoint{
			Value: float64(p.Version),
			Attrs: telemetry.Attrs{"policy_name": name},
		})
	}
	e.GaugeSnapshot(policyVersionMetricName, semconv.UnitDimensionless,
		"Configured version of each Intune device compliance policy; a bump signals a policy-content change.", points)
	return refs, nil
}

// statusOverview is the shared shape of both deviceComplianceDeviceOverview
// (deviceStatusOverview) and deviceComplianceUserOverview
// (userStatusOverview) — the two documented resources are field-for-field
// identical besides their id.
type statusOverview struct {
	PendingCount       int64 `json:"pendingCount"`
	NotApplicableCount int64 `json:"notApplicableCount"`
	SuccessCount       int64 `json:"successCount"`
	ErrorCount         int64 `json:"errorCount"`
	FailedCount        int64 `json:"failedCount"`
}

// points renders one overview into its five bounded (policy_name, state)
// gauge points.
func (o statusOverview) points(policyName string) []telemetry.GaugePoint {
	return []telemetry.GaugePoint{
		{Value: float64(o.SuccessCount), Attrs: telemetry.Attrs{"policy_name": policyName, "state": "success"}},
		{Value: float64(o.PendingCount), Attrs: telemetry.Attrs{"policy_name": policyName, "state": "pending"}},
		{Value: float64(o.FailedCount), Attrs: telemetry.Attrs{"policy_name": policyName, "state": "failed"}},
		{Value: float64(o.ErrorCount), Attrs: telemetry.Attrs{"policy_name": policyName, "state": "error"}},
		{Value: float64(o.NotApplicableCount), Attrs: telemetry.Attrs{"policy_name": policyName, "state": "not_applicable"}},
	}
}

// fetchStatusOverview GETs and decodes a single deviceStatusOverview or
// userStatusOverview singleton.
func (c *Collector) fetchStatusOverview(ctx context.Context, url string) (statusOverview, error) {
	body, err := c.g.RawGet(ctx, url)
	if err != nil {
		return statusOverview{}, err
	}
	var o statusOverview
	if err := json.Unmarshal(body, &o); err != nil {
		return statusOverview{}, fmt.Errorf("decode status overview from %q: %w", url, err)
	}
	return o, nil
}

// collectPolicyOverviews fans out to each policy's deviceStatusOverview and
// userStatusOverview singleton and emits the two per-policy gauge sets. A
// failure fetching one policy's overview (of either kind) is logged and
// joined into the returned error, but every other policy and both metrics
// still emit whatever succeeded — one throttled or newly-deleted policy
// never blanks the whole snapshot.
func (c *Collector) collectPolicyOverviews(ctx context.Context, e telemetry.Emitter, policies []policyRef) error {
	var errs []error
	devicePoints := make([]telemetry.GaugePoint, 0, len(policies)*5)
	userPoints := make([]telemetry.GaugePoint, 0, len(policies)*5)

	for _, p := range policies {
		devOverview, err := c.fetchStatusOverview(ctx, c.baseURL+"/deviceManagement/deviceCompliancePolicies/"+p.id+"/deviceStatusOverview")
		switch {
		case err == nil:
			devicePoints = append(devicePoints, devOverview.points(p.name)...)
		case isForbidden(err):
			c.logger.Info("compliance: deviceStatusOverview unavailable; skipping policy",
				"collector", collectorName, "policy_name", p.name, "error", err)
		default:
			c.logger.Warn("compliance: deviceStatusOverview fetch failed",
				"collector", collectorName, "policy_name", p.name, "error", err)
			errs = append(errs, fmt.Errorf("deviceStatusOverview policy=%s: %w", p.name, err))
		}

		userOverview, err := c.fetchStatusOverview(ctx, c.baseURL+"/deviceManagement/deviceCompliancePolicies/"+p.id+"/userStatusOverview")
		switch {
		case err == nil:
			userPoints = append(userPoints, userOverview.points(p.name)...)
		case isForbidden(err):
			c.logger.Info("compliance: userStatusOverview unavailable; skipping policy",
				"collector", collectorName, "policy_name", p.name, "error", err)
		default:
			c.logger.Warn("compliance: userStatusOverview fetch failed",
				"collector", collectorName, "policy_name", p.name, "error", err)
			errs = append(errs, fmt.Errorf("userStatusOverview policy=%s: %w", p.name, err))
		}
	}

	e.GaugeSnapshot(policyDevicesMetricName, "{device}",
		"Per-policy Intune device compliance status overview, by policy and state.", devicePoints)
	e.GaugeSnapshot(policyUsersMetricName, "{user}",
		"Per-policy Intune user compliance status overview, by policy and state.", userPoints)
	return errors.Join(errs...)
}

// settingStateSummary is the shape of one
// deviceCompliancePolicySettingStateSummaries element. settingName is the
// human-readable label Graph documents (distinct from the shorter, raw
// "setting" key); this collector uses settingName since it's what the
// telemetry model's setting_name attribute names.
type settingStateSummary struct {
	SettingName              string `json:"settingName"`
	PlatformType             string `json:"platformType"`
	UnknownDeviceCount       int64  `json:"unknownDeviceCount"`
	NotApplicableDeviceCount int64  `json:"notApplicableDeviceCount"`
	CompliantDeviceCount     int64  `json:"compliantDeviceCount"`
	RemediatedDeviceCount    int64  `json:"remediatedDeviceCount"`
	NonCompliantDeviceCount  int64  `json:"nonCompliantDeviceCount"`
	ErrorDeviceCount         int64  `json:"errorDeviceCount"`
	ConflictDeviceCount      int64  `json:"conflictDeviceCount"`
}

// settingStateKey identifies one (setting_name, platform, state) series.
type settingStateKey struct {
	settingName string
	platform    string
	state       string
}

// collectSettingStateSummaries pages the setting-state summary list —
// bounded by the tenant's unique compliance-setting catalog, not by device
// or policy count — and emits it as the setting_name/platform/state gauge
// set. These summaries aggregate across every policy checking a given
// setting; Graph does not expose which policy contributed which count, so
// this deliberately never implies a per-policy attribution for this metric.
func (c *Collector) collectSettingStateSummaries(ctx context.Context, e telemetry.Emitter) error {
	raw, err := collectors.GetAllValues(ctx, c.g, c.baseURL+"/deviceManagement/deviceCompliancePolicySettingStateSummaries", nil)
	if err != nil {
		return err
	}

	// Aggregated by key rather than appended per-row, so a tenant/paging
	// oddity that repeats a (setting, platform) pair across rows sums
	// correctly instead of one row silently shadowing another.
	agg := map[settingStateKey]int64{}
	add := func(settingName, platform, state string, n int64) {
		agg[settingStateKey{orUnknown(settingName), orUnknown(platform), state}] += n
	}

	for _, r := range raw {
		var s settingStateSummary
		if err := json.Unmarshal(r, &s); err != nil {
			c.logger.Warn("compliance: skipping unparseable setting state summary", "collector", collectorName, "error", err)
			continue
		}
		add(s.SettingName, s.PlatformType, "compliant", s.CompliantDeviceCount)
		add(s.SettingName, s.PlatformType, "non_compliant", s.NonCompliantDeviceCount)
		add(s.SettingName, s.PlatformType, "remediated", s.RemediatedDeviceCount)
		add(s.SettingName, s.PlatformType, "error", s.ErrorDeviceCount)
		add(s.SettingName, s.PlatformType, "conflict", s.ConflictDeviceCount)
		add(s.SettingName, s.PlatformType, "unknown", s.UnknownDeviceCount)
		add(s.SettingName, s.PlatformType, "not_applicable", s.NotApplicableDeviceCount)
	}

	points := make([]telemetry.GaugePoint, 0, len(agg))
	for k, v := range agg {
		points = append(points, telemetry.GaugePoint{
			Value: float64(v),
			Attrs: telemetry.Attrs{"setting_name": k.settingName, "platform": k.platform, "state": k.state},
		})
	}
	e.GaugeSnapshot(settingDevicesMetricName, "{device}",
		"Intune compliance setting-state summary, aggregated across every policy checking that setting, by setting, platform, and state.", points)
	return nil
}

// isForbidden reports whether err is a 403 from the Graph client — this
// collector's endpoints all require an active Intune license on the tenant
// in addition to the Graph scope, so "forbidden" is treated as an expected
// "no data here" condition, not a failure.
func isForbidden(err error) bool {
	return strings.Contains(err.Error(), "status 403")
}

// orUnknown substitutes "unknown" for an empty label value, so a gauge point
// never carries an empty attribute value.
func orUnknown(s string) string {
	if s == "" {
		return "unknown"
	}
	return s
}

var _ collector.SnapshotCollector = (*Collector)(nil)

func init() {
	collectors.Register(func(d collectors.Deps) collector.SnapshotCollector {
		return New(d.Graph, d.Logger)
	})
}
