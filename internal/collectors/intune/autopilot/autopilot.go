// Package autopilot is the Windows Autopilot collector: bounded aggregate
// gauges over registered device identities
// (`/deviceManagement/windowsAutopilotDeviceIdentities`, v1.0) and deployment
// profile configuration
// (`/deviceManagement/windowsAutopilotDeploymentProfiles` + per-profile
// `/assignments`, both BETA-only - v1.0 404s on these paths).
//
// Beta-only: the deployment-profile side of this collector lives on /beta, so
// the whole collector implements collectors.Experimental (opt-in, off by
// default) and degrades cleanly - a 403/404 (endpoint unavailable or
// unlicensed on the tenant) is skipped-and-logged rather than treated as a
// failure, same as entra/recommendations.
//
// Per-device enrollment *events* (`autopilotEvents`, beta) are an event
// stream and belong in the M5 logs pipeline, not here - this collector covers
// only the device-identity and profile entity snapshots (issue #57).
package autopilot

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"sort"
	"strings"
	"time"

	"github.com/rknightion/graph2otel/internal/collector"
	"github.com/rknightion/graph2otel/internal/collectors"
	"github.com/rknightion/graph2otel/internal/semconv"
	"github.com/rknightion/graph2otel/internal/telemetry"
)

// collectorName is the stable key used for config (enable/interval),
// self-observability, and the admin status page.
const collectorName = "intune.autopilot"

// Metric names this collector emits. Each is its own metric name so that
// summing a single metric always yields the true count for that breakdown -
// mixing independent dimensions under one metric name would mean a naive
// `sum()` over it silently multi-counts.
const (
	devicesMetricName            = "intune.autopilot.devices"
	staleContactMetricName       = "intune.autopilot.stale_contact.count"
	profileCountMetricName       = "intune.autopilot.profile.count"
	profileSettingMetricName     = "intune.autopilot.profile.setting"
	profileEspTimeoutMetricName  = "intune.autopilot.profile.esp_timeout_minutes"
	profileAssignmentsMetricName = "intune.autopilot.profile.assignments"
)

// defaultBaseURL is the Graph v1.0 root, used for windowsAutopilotDeviceIdentities.
const defaultBaseURL = "https://graph.microsoft.com/v1.0"

// betaBaseURL is the Graph beta root, required for
// windowsAutopilotDeploymentProfiles and its /assignments sub-resource - both
// 404 on v1.0 (verified against Microsoft's own docs, updated 2024-08-01).
const betaBaseURL = "https://graph.microsoft.com/beta"

// staleContactThreshold is how long since lastContactedDateTime an Autopilot
// device identity must go before it counts toward stale_contact.count.
const staleContactThreshold = 30 * 24 * time.Hour

// maxGroupTags bounds the group_tag dimension. groupTag is admin-set free
// text (site codes, department names, ...) with no Graph-side enum, so
// without a cap a tenant with many ad-hoc tags would produce an unbounded
// metric series. Only the top maxGroupTags tags by device count keep their
// own series; every other tag (however many tenants define) rolls into
// "other". 20 is a generous bound for the typical dozens-of-sites use of this
// field while remaining a hard, documented cap.
const maxGroupTags = 20

// enrollmentStateBuckets maps every documented windowsAutopilotDeviceIdentity
// enrollmentState value (https://learn.microsoft.com/en-us/graph/api/resources/intune-enrollment-enrollmentstate)
// to its bounded attribute value. An unrecognized value falls into "other"
// rather than being passed through raw, so the dimension can never grow
// unbounded from a future enum addition.
var enrollmentStateBuckets = map[string]string{
	"unknown":      "unknown",
	"enrolled":     "enrolled",
	"pendingReset": "pending_reset",
	"failed":       "failed",
	"notContacted": "not_contacted",
}

func enrollmentStateBucketFor(raw string) string {
	if b, ok := enrollmentStateBuckets[raw]; ok {
		return b
	}
	return "other"
}

// deviceTypeBuckets maps every documented windowsAutopilotDeviceType value
// (https://learn.microsoft.com/en-us/graph/api/resources/intune-enrollment-windowsautopilotdevicetype)
// to its bounded attribute value. "unknownFutureValue" and anything
// unrecognized fall into "other".
var deviceTypeBuckets = map[string]string{
	"windowsPc":      "windows_pc",
	"holoLens":       "hololens",
	"surfaceHub2":    "surface_hub2",
	"surfaceHub2S":   "surface_hub2s",
	"virtualMachine": "virtual_machine",
}

func deviceTypeBucketFor(raw string) string {
	if raw == "" {
		return "unknown"
	}
	if b, ok := deviceTypeBuckets[raw]; ok {
		return b
	}
	return "other"
}

func boolAttr(b bool) string {
	if b {
		return "true"
	}
	return "false"
}

func boolValue(b bool) float64 {
	if b {
		return 1
	}
	return 0
}

// normGroupTag maps an empty groupTag to the bounded "unassigned" bucket
// rather than an empty-string label.
func normGroupTag(raw string) string {
	if raw == "" {
		return "unassigned"
	}
	return raw
}

// topGroupTags returns the up-to-maxGroupTags tags with the highest device
// counts (ties broken alphabetically for determinism). Every tag not in the
// returned set must be bucketed to "other" by the caller.
func topGroupTags(counts map[string]int64) map[string]struct{} {
	type kv struct {
		tag   string
		count int64
	}
	list := make([]kv, 0, len(counts))
	for tag, n := range counts {
		list = append(list, kv{tag, n})
	}
	sort.Slice(list, func(i, j int) bool {
		if list[i].count != list[j].count {
			return list[i].count > list[j].count
		}
		return list[i].tag < list[j].tag
	})
	if len(list) > maxGroupTags {
		list = list[:maxGroupTags]
	}
	keep := make(map[string]struct{}, len(list))
	for _, e := range list {
		keep[e.tag] = struct{}{}
	}
	return keep
}

func groupTagBucketFor(raw string, keep map[string]struct{}) string {
	norm := normGroupTag(raw)
	if _, ok := keep[norm]; ok {
		return norm
	}
	return "other"
}

// deviceIdentity is the subset of the windowsAutopilotDeviceIdentity resource
// this collector reads. It is intentionally narrow - no id, serialNumber,
// managedDeviceId, azureActiveDirectoryDeviceId, userPrincipalName, or
// displayName is ever read, since those are unbounded per-entity identifiers
// that must never become metric labels.
type deviceIdentity struct {
	EnrollmentState       string     `json:"enrollmentState"`
	GroupTag              string     `json:"groupTag"`
	LastContactedDateTime *time.Time `json:"lastContactedDateTime"`
}

// espSettings is the subset of windowsEnrollmentStatusScreenSettings
// (https://learn.microsoft.com/en-us/graph/api/resources/intune-enrollment-windowsenrollmentstatusscreensettings)
// this collector reads for config-drift alerting.
type espSettings struct {
	HideInstallationProgress                         bool `json:"hideInstallationProgress"`
	AllowDeviceUseBeforeProfileAndAppInstallComplete bool `json:"allowDeviceUseBeforeProfileAndAppInstallComplete"`
	BlockDeviceSetupRetryByUser                      bool `json:"blockDeviceSetupRetryByUser"`
	AllowLogCollectionOnInstallFailure               bool `json:"allowLogCollectionOnInstallFailure"`
	InstallProgressTimeoutInMinutes                  int  `json:"installProgressTimeoutInMinutes"`
	AllowDeviceUseOnInstallFailure                   bool `json:"allowDeviceUseOnInstallFailure"`
}

// deploymentProfile is the subset of the windowsAutopilotDeploymentProfile
// resource this collector reads. Uses the post-May-2024 field names
// (locale/preprovisioningAllowed/hardwareHashExtractionEnabled) - the
// deprecated language/enableWhiteGlove/extractHardwareHash predecessors are
// deliberately not read. displayName is read here (unlike deviceIdentity):
// deployment profiles are a small, admin-configured collection, bounded by
// profile count rather than tenant/device-fleet size - the same precedent as
// intune/mobileapps' policy_name label on deviceStatusSummary.
type deploymentProfile struct {
	ID                             string       `json:"id"`
	DisplayName                    string       `json:"displayName"`
	DeviceType                     string       `json:"deviceType"`
	PreprovisioningAllowed         bool         `json:"preprovisioningAllowed"`
	HardwareHashExtractionEnabled  bool         `json:"hardwareHashExtractionEnabled"`
	EnrollmentStatusScreenSettings *espSettings `json:"enrollmentStatusScreenSettings"`
}

// profileName returns the profile's display name, or its id if the display
// name is empty.
func (p deploymentProfile) profileName() string {
	if p.DisplayName != "" {
		return p.DisplayName
	}
	return p.ID
}

// settingBuckets pairs each bounded config-drift setting attribute value with
// the boolean it reads off a decoded deploymentProfile. A profile lacking
// enrollmentStatusScreenSettings simply yields false for the esp_* settings,
// not an error.
var settingBuckets = []struct {
	attr string
	get  func(deploymentProfile) bool
}{
	{"preprovisioning_allowed", func(p deploymentProfile) bool { return p.PreprovisioningAllowed }},
	{"hardware_hash_extraction_enabled", func(p deploymentProfile) bool { return p.HardwareHashExtractionEnabled }},
	{"esp_hide_installation_progress", func(p deploymentProfile) bool {
		return p.EnrollmentStatusScreenSettings != nil && p.EnrollmentStatusScreenSettings.HideInstallationProgress
	}},
	{"esp_allow_device_use_before_install_complete", func(p deploymentProfile) bool {
		return p.EnrollmentStatusScreenSettings != nil && p.EnrollmentStatusScreenSettings.AllowDeviceUseBeforeProfileAndAppInstallComplete
	}},
	{"esp_block_device_setup_retry_by_user", func(p deploymentProfile) bool {
		return p.EnrollmentStatusScreenSettings != nil && p.EnrollmentStatusScreenSettings.BlockDeviceSetupRetryByUser
	}},
	{"esp_allow_log_collection_on_install_failure", func(p deploymentProfile) bool {
		return p.EnrollmentStatusScreenSettings != nil && p.EnrollmentStatusScreenSettings.AllowLogCollectionOnInstallFailure
	}},
	{"esp_allow_device_use_on_install_failure", func(p deploymentProfile) bool {
		return p.EnrollmentStatusScreenSettings != nil && p.EnrollmentStatusScreenSettings.AllowDeviceUseOnInstallFailure
	}},
}

// Collector polls Windows Autopilot device identities (v1.0) and deployment
// profiles + assignments (beta).
type Collector struct {
	g       collectors.GraphClient
	baseURL string
	betaURL string
	logger  *slog.Logger
	// now returns the current time; overridable in tests so stale-contact
	// bucketing is deterministic and assertable.
	now func() time.Time
}

// New builds the autopilot collector. A nil logger falls back to the slog
// default.
func New(g collectors.GraphClient, logger *slog.Logger) *Collector {
	if logger == nil {
		logger = slog.Default()
	}
	return &Collector{g: g, baseURL: defaultBaseURL, betaURL: betaBaseURL, logger: logger, now: time.Now}
}

// Name implements collector.Collector.
func (c *Collector) Name() string { return collectorName }

// DefaultInterval implements collector.Collector. Autopilot device
// registration and deployment-profile configuration both drift slowly.
func (c *Collector) DefaultInterval() time.Duration { return 30 * time.Minute }

// Experimental marks this collector as beta/opt-in: the deployment-profile
// half of it has no v1.0 equivalent.
func (c *Collector) Experimental() bool { return true }

// RequiredPermissions declares the least-privilege Graph application scope.
// Both windowsAutopilotDeviceIdentities and windowsAutopilotDeploymentProfiles
// (+ its assignments) document DeviceManagementServiceConfig.Read.All.
func (c *Collector) RequiredPermissions() []string {
	return []string{"DeviceManagementServiceConfig.Read.All"}
}

// Collect fetches the device-identity list and the deployment-profile
// (+ assignments) list, and emits the bounded gauges described in the package
// doc. The two fetches are independently resilient: a failure in one is
// logged and joined into the returned error, but the other's metrics still
// emit.
func (c *Collector) Collect(ctx context.Context, e telemetry.Emitter) error {
	var errs []error

	if err := c.collectDevices(ctx, e); err != nil {
		c.logger.Warn("autopilot: device identities failed", "collector", collectorName, "error", err)
		errs = append(errs, fmt.Errorf("device identities: %w", err))
	}

	if err := c.collectProfiles(ctx, e); err != nil {
		c.logger.Warn("autopilot: deployment profiles failed", "collector", collectorName, "error", err)
		errs = append(errs, fmt.Errorf("deployment profiles: %w", err))
	}

	return errors.Join(errs...)
}

// collectDevices pages the full windowsAutopilotDeviceIdentities collection.
// Full-collection paging is the deliberate exception here, same as
// intune/manageddevices: there is no managedDeviceOverview-style aggregate
// for Autopilot identities, and $filter support on this collection is
// undocumented, so there is no bounded $count slice to lean on instead. The
// result is rolled up into bounded buckets (enrollment_state, capped
// group_tag) - never a per-device series - which is exactly what this method
// does. This collection also includes historically-registered (retired)
// hardware unless explicitly deleted, so it can exceed the live device
// fleet - that's expected, not a bug.
func (c *Collector) collectDevices(ctx context.Context, e telemetry.Emitter) error {
	raw, err := collectors.GetAllValues(ctx, c.g, c.baseURL+"/deviceManagement/windowsAutopilotDeviceIdentities", nil)
	if err != nil {
		if isUnavailable(err) {
			c.logger.Info("autopilot: device identities endpoint unavailable; skipping",
				"collector", collectorName, "error", err)
			return nil
		}
		return err
	}

	type parsed struct {
		state    string
		groupTag string
		stale    bool
	}
	items := make([]parsed, 0, len(raw))
	tagTotals := map[string]int64{}
	now := c.now()

	for _, r := range raw {
		var d deviceIdentity
		if err := json.Unmarshal(r, &d); err != nil {
			c.logger.Warn("autopilot: skipping unparseable device identity", "collector", collectorName, "error", err)
			continue
		}
		norm := normGroupTag(d.GroupTag)
		tagTotals[norm]++
		stale := d.LastContactedDateTime != nil && now.Sub(*d.LastContactedDateTime) > staleContactThreshold
		items = append(items, parsed{state: enrollmentStateBucketFor(d.EnrollmentState), groupTag: norm, stale: stale})
	}

	keep := topGroupTags(tagTotals)

	counts := map[[2]string]int64{}
	stale := map[string]int64{}
	for _, it := range items {
		tag := groupTagBucketFor(it.groupTag, keep)
		counts[[2]string{it.state, tag}]++
		if it.stale {
			stale[tag]++
		}
	}

	devicePoints := make([]telemetry.GaugePoint, 0, len(counts))
	for k, v := range counts {
		devicePoints = append(devicePoints, telemetry.GaugePoint{
			Value: float64(v),
			Attrs: telemetry.Attrs{semconv.AttrEnrollmentState: k[0], semconv.AttrGroupTag: k[1]},
		})
	}
	e.GaugeSnapshot(devicesMetricName, "{device}", "Windows Autopilot device identities, by enrollment state and group tag (capped to top tags by device count, see maxGroupTags).", devicePoints)

	stalePoints := make([]telemetry.GaugePoint, 0, len(stale))
	for tag, v := range stale {
		stalePoints = append(stalePoints, telemetry.GaugePoint{
			Value: float64(v),
			Attrs: telemetry.Attrs{semconv.AttrGroupTag: tag},
		})
	}
	e.GaugeSnapshot(staleContactMetricName, "{device}", "Windows Autopilot device identities whose lastContactedDateTime is older than the stale-contact threshold, by group tag.", stalePoints)

	return nil
}

// collectProfiles lists the (small, admin-configured) deployment profiles,
// emits the aggregate profile.count snapshot, then for each profile fetches
// its assignments and emits the per-profile config-drift gauges. A 403/404 on
// the list is skipped-and-logged (beta endpoint unavailable/unlicensed); a
// per-profile assignments failure is logged and that profile's assignment
// count is dropped, but every other profile's gauges still emit.
func (c *Collector) collectProfiles(ctx context.Context, e telemetry.Emitter) error {
	raw, err := collectors.GetAllValues(ctx, c.g, c.betaURL+"/deviceManagement/windowsAutopilotDeploymentProfiles", nil)
	if err != nil {
		if isUnavailable(err) {
			c.logger.Info("autopilot: deployment profiles endpoint unavailable; skipping",
				"collector", collectorName, "error", err)
			return nil
		}
		return err
	}

	countBuckets := map[[2]string]int64{}
	var settingPoints []telemetry.GaugePoint
	var espTimeoutPoints []telemetry.GaugePoint
	var assignmentPoints []telemetry.GaugePoint
	var errs []error

	for _, r := range raw {
		var p deploymentProfile
		if err := json.Unmarshal(r, &p); err != nil {
			c.logger.Warn("autopilot: skipping unparseable deployment profile", "collector", collectorName, "error", err)
			continue
		}

		countBuckets[[2]string{deviceTypeBucketFor(p.DeviceType), boolAttr(p.PreprovisioningAllowed)}]++

		name := p.profileName()
		for _, sb := range settingBuckets {
			settingPoints = append(settingPoints, telemetry.GaugePoint{
				Value: boolValue(sb.get(p)),
				Attrs: telemetry.Attrs{semconv.AttrProfileName: name, semconv.AttrSetting: sb.attr},
			})
		}
		if p.EnrollmentStatusScreenSettings != nil {
			espTimeoutPoints = append(espTimeoutPoints, telemetry.GaugePoint{
				Value: float64(p.EnrollmentStatusScreenSettings.InstallProgressTimeoutInMinutes),
				Attrs: telemetry.Attrs{semconv.AttrProfileName: name},
			})
		}

		if p.ID == "" {
			c.logger.Warn("autopilot: skipping assignments fetch for profile with empty id", "collector", collectorName, "profile", name)
			continue
		}
		n, err := c.assignmentCount(ctx, p.ID)
		if err != nil {
			c.logger.Warn("autopilot: assignments fetch failed", "collector", collectorName, "profile", p.ID, "error", err)
			errs = append(errs, fmt.Errorf("profile %s assignments: %w", p.ID, err))
			continue
		}
		assignmentPoints = append(assignmentPoints, telemetry.GaugePoint{
			Value: float64(n),
			Attrs: telemetry.Attrs{semconv.AttrProfileName: name},
		})
	}

	countPoints := make([]telemetry.GaugePoint, 0, len(countBuckets))
	for k, v := range countBuckets {
		countPoints = append(countPoints, telemetry.GaugePoint{
			Value: float64(v),
			Attrs: telemetry.Attrs{semconv.AttrDeviceType: k[0], semconv.AttrPreprovisioningAllowed: k[1]},
		})
	}
	e.GaugeSnapshot(profileCountMetricName, "{profile}", "Windows Autopilot deployment profiles, by device type and whether pre-provisioning (white glove) is allowed.", countPoints)
	e.GaugeSnapshot(profileSettingMetricName, "1", "Windows Autopilot deployment profile config-drift-relevant boolean settings (1=enabled, 0=disabled), by profile and setting.", settingPoints)
	e.GaugeSnapshot(profileEspTimeoutMetricName, "min", "Windows Autopilot deployment profile Enrollment Status Page install-progress timeout, by profile.", espTimeoutPoints)
	e.GaugeSnapshot(profileAssignmentsMetricName, "{assignment}", "Windows Autopilot deployment profile group assignment count, by profile.", assignmentPoints)

	return errors.Join(errs...)
}

// assignmentCount fetches a single profile's assignments collection and
// returns its length. The collection is small and bounded (group
// assignments), so no per-item decoding is needed - only the count.
func (c *Collector) assignmentCount(ctx context.Context, profileID string) (int, error) {
	raw, err := collectors.GetAllValues(ctx, c.g, c.betaURL+"/deviceManagement/windowsAutopilotDeploymentProfiles/"+profileID+"/assignments", nil)
	if err != nil {
		return 0, err
	}
	return len(raw), nil
}

// isUnavailable reports whether err is a 4xx from the beta endpoint being
// unavailable/unlicensed on the tenant (403 forbidden, 404 not found) - an
// expected "no data here" condition, not a failure.
func isUnavailable(err error) bool {
	s := err.Error()
	return strings.Contains(s, "status 403") || strings.Contains(s, "status 404")
}

// Compile-time interface assertions.
var _ collector.SnapshotCollector = (*Collector)(nil)
var _ collectors.Experimental = (*Collector)(nil)

func init() {
	collectors.Register(func(d collectors.Deps) collector.SnapshotCollector {
		return New(d.Graph, d.Logger)
	})
}
