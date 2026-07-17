// Package configprofiles is the Intune device-configuration-profiles
// collector: inventory of the classic `deviceConfigurations` collection
// (VPN/Wi-Fi/general-config/etc.), bucketed by `@odata.type`, plus a
// version-change gauge and the per-profile `deviceStatusOverview` deployment
// status - without ever walking per-device status rows.
//
// The `deviceConfigurations` collection is heterogeneous: Windows Update ring
// profiles (`@odata.type` `#microsoft.graph.windowsUpdateForBusinessConfiguration`)
// live in the same collection but are owned by the update-rings collector
// (tracker #79, Group B partition, issue #59) - this collector deliberately
// excludes that one type from every metric (count, version, and the
// deviceStatusOverview fan-out) so the two collectors never double-count the
// same objects.
//
// This never walks the per-device x profile status children
// (deviceStatuses, userStatuses, deviceSettingStateSummaries): those put a
// per-device identifier on what would have to be a metric label, the primary
// cardinality bomb this collector exists to avoid. Fleet-wide per-device
// detail is a logs-pipeline concern for the M5 milestone, not this collector.
package configprofiles

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
const collectorName = "intune.config_profiles"

// Metric names this collector emits. Each is its own metric name (rather than
// stuffing independent dimensions under one name) so that summing a single
// metric always yields the true total for that breakdown - mixing
// independent dimensions under one metric name would mean a naive `sum()`
// over it silently multi-counts.
const (
	countMetricName   = "intune.config_profile.count"
	statusMetricName  = "intune.config_profile.status"
	versionMetricName = "intune.config_profile.version"
)

// defaultBaseURL is the Graph v1.0 root. Both endpoints this collector polls
// (deviceConfigurations and its deviceStatusOverview child) are v1.0 - this
// collector is NOT Experimental.
const defaultBaseURL = "https://graph.microsoft.com/v1.0"

// windowsUpdateForBusinessODataType is the Group-B deviceConfigurations
// subtype owned by the update-rings collector (#59), decided on tracker #79.
// A profile of this type is skipped entirely here - never counted,
// version-tracked, or fanned out to for a status overview - so the two
// collectors' data never overlaps.
const windowsUpdateForBusinessODataType = "#microsoft.graph.windowsUpdateForBusinessConfiguration"

// odataTypeBuckets maps every deviceConfigurations subtype this collector is
// responsible for
// (https://learn.microsoft.com/en-us/graph/api/resources/intune-deviceconfig-deviceconfiguration)
// to a short, bounded odata_type attribute value. A type not in this map -
// including a brand-new subtype Microsoft adds later, or the
// windowsUpdateForBusinessConfiguration type this collector excludes outright
// (see above, it never reaches bucketing) - falls into "other" rather than
// being passed through raw, so the odata_type dimension can never grow
// unbounded.
var odataTypeBuckets = map[string]string{
	"#microsoft.graph.windows10GeneralConfiguration":                        "windows_general",
	"#microsoft.graph.windows10TeamGeneralConfiguration":                    "windows_general",
	"#microsoft.graph.windowsHealthMonitoringConfiguration":                 "windows_general",
	"#microsoft.graph.windowsIdentityProtectionConfiguration":               "windows_general",
	"#microsoft.graph.windowsKioskConfiguration":                            "windows_general",
	"#microsoft.graph.windowsDeliveryOptimizationConfiguration":             "windows_general",
	"#microsoft.graph.sharedPCConfiguration":                                "windows_general",
	"#microsoft.graph.editionUpgradeConfiguration":                          "windows_general",
	"#microsoft.graph.windows10EndpointProtectionConfiguration":             "windows_endpoint_protection",
	"#microsoft.graph.windowsDefenderAdvancedThreatProtectionConfiguration": "windows_endpoint_protection",
	"#microsoft.graph.windows10CustomConfiguration":                         "windows_custom",
	"#microsoft.graph.windowsWifiConfiguration":                             "windows_wifi",
	"#microsoft.graph.windowsVpnConfiguration":                              "windows_vpn",
	"#microsoft.graph.iosGeneralDeviceConfiguration":                        "ios_general",
	"#microsoft.graph.iosCustomConfiguration":                               "ios_custom",
	"#microsoft.graph.iosWiFiConfiguration":                                 "ios_wifi",
	"#microsoft.graph.iosVpnConfiguration":                                  "ios_vpn",
	"#microsoft.graph.androidGeneralDeviceConfiguration":                    "android_general",
	"#microsoft.graph.androidWorkProfileGeneralDeviceConfiguration":         "android_general",
	"#microsoft.graph.androidCustomConfiguration":                           "android_custom",
	"#microsoft.graph.androidWiFiConfiguration":                             "android_wifi",
	"#microsoft.graph.androidVpnConfiguration":                              "android_vpn",
	"#microsoft.graph.macOSGeneralDeviceConfiguration":                      "macos_general",
	"#microsoft.graph.macOSCustomConfiguration":                             "macos_custom",
	"#microsoft.graph.macOSWiFiConfiguration":                               "macos_wifi",
	"#microsoft.graph.macOSVpnConfiguration":                                "macos_vpn",
}

// odataTypeBucketFor buckets a raw @odata.type value into its bounded
// odata_type attribute value, falling back to "other" for anything not in
// odataTypeBuckets.
func odataTypeBucketFor(raw string) string {
	if b, ok := odataTypeBuckets[raw]; ok {
		return b
	}
	return "other"
}

// Collector polls the Intune deviceConfigurations inventory and its
// per-profile deviceStatusOverview singletons.
type Collector struct {
	g       collectors.GraphClient
	baseURL string
	logger  *slog.Logger
}

// New builds the configuration-profiles collector. A nil logger falls back
// to the slog default.
func New(g collectors.GraphClient, logger *slog.Logger) *Collector {
	if logger == nil {
		logger = slog.Default()
	}
	return &Collector{g: g, baseURL: defaultBaseURL, logger: logger}
}

// Name implements collector.Collector.
func (c *Collector) Name() string { return collectorName }

// DefaultInterval implements collector.Collector. This collector fans out one
// deviceStatusOverview request per profile on every cycle (bounded by the
// tenant's admin-configured profile count, not device count), and deployment
// status lags real client check-in by minutes to hours (see Collect), so
// polling faster than that buys nothing.
func (c *Collector) DefaultInterval() time.Duration { return 30 * time.Minute }

// RequiredPermissions declares the least-privilege Graph application scope.
// Per https://learn.microsoft.com/en-us/graph/api/resources/intune-deviceconfig-deviceconfiguration,
// DeviceManagementConfiguration.Read.All is the permission both
// deviceConfigurations and its deviceStatusOverview child document.
func (c *Collector) RequiredPermissions() []string {
	return []string{"DeviceManagementConfiguration.Read.All"}
}

// Collect fetches the profile inventory (emitting the count and version
// gauges) and fans out to each profile's deviceStatusOverview singleton
// (emitting the status gauge). Each phase is independently resilient: a
// failure in one is logged and joined into the returned error, but does not
// prevent the other from emitting. A 403 (missing scope, or Intune not
// licensed on this tenant) is treated as an expected "no data here" condition
// - skipped and logged at Info, not surfaced as an error - since every
// endpoint here requires an active Intune license on the tenant in addition
// to the Graph scope.
//
// Overview counts lag real client check-in by minutes to hours; a transient
// mismatch against a device's actual last-known state is expected, not a bug.
func (c *Collector) Collect(ctx context.Context, e telemetry.Emitter) error {
	var errs []error

	profiles, err := c.collectProfiles(ctx, e)
	if err != nil {
		if isForbidden(err) {
			c.logger.Info("configprofiles: profile list unavailable on this tenant; skipping",
				"collector", collectorName, "error", err)
		} else {
			c.logger.Warn("configprofiles: profile list fetch failed", "collector", collectorName, "error", err)
			errs = append(errs, fmt.Errorf("profile list: %w", err))
		}
	}
	if len(profiles) > 0 {
		if err := c.collectStatusOverviews(ctx, e, profiles); err != nil {
			errs = append(errs, err)
		}
	}

	return errors.Join(errs...)
}

// configProfile is the subset of the heterogeneous deviceConfigurations base
// resource this collector reads. Only id/displayName/version/@odata.type are
// needed - the concrete platform subtype's settings are never read, since
// this collector aggregates inventory and status, not policy content.
type configProfile struct {
	ID          string `json:"id"`
	DisplayName string `json:"displayName"`
	Version     int64  `json:"version"`
	ODataType   string `json:"@odata.type"`
}

// profileRef is the bounded (id, name) pair this collector carries from the
// profile inventory into the per-profile status-overview fan-out.
type profileRef struct {
	id   string
	name string
}

// collectProfiles pages the (tenant-config-bounded, typically tens to low
// hundreds) deviceConfigurations inventory, emits the count-by-odata_type and
// version gauges, and returns the (id, name) pairs the per-profile overview
// fan-out needs. Every windowsUpdateForBusinessConfiguration profile is
// skipped outright (see the package doc and the windowsUpdateForBusinessODataType
// constant) - it is never counted, version-tracked, or returned for the
// status-overview fan-out.
func (c *Collector) collectProfiles(ctx context.Context, e telemetry.Emitter) ([]profileRef, error) {
	raw, err := collectors.GetAllValues(ctx, c.g, c.baseURL+"/deviceManagement/deviceConfigurations", nil)
	if err != nil {
		return nil, err
	}

	refs := make([]profileRef, 0, len(raw))
	counts := map[string]int64{}
	versionPoints := make([]telemetry.GaugePoint, 0, len(raw))

	for _, r := range raw {
		var p configProfile
		if err := json.Unmarshal(r, &p); err != nil {
			c.logger.Warn("configprofiles: skipping unparseable deviceConfiguration", "collector", collectorName, "error", err)
			continue
		}
		if p.ODataType == windowsUpdateForBusinessODataType {
			// Group B: owned by the update-rings collector (#59) - never
			// counted, version-tracked, or fanned out to here.
			continue
		}
		if p.ID == "" {
			c.logger.Warn("configprofiles: skipping deviceConfiguration with empty id", "collector", collectorName)
			continue
		}
		name := orUnknown(p.DisplayName)
		bucket := odataTypeBucketFor(p.ODataType)
		counts[bucket]++
		refs = append(refs, profileRef{id: p.ID, name: name})
		versionPoints = append(versionPoints, telemetry.GaugePoint{
			Value: float64(p.Version),
			Attrs: telemetry.Attrs{semconv.AttrProfileName: name},
		})
	}

	countPoints := make([]telemetry.GaugePoint, 0, len(counts))
	for bucket, n := range counts {
		countPoints = append(countPoints, telemetry.GaugePoint{
			Value: float64(n),
			Attrs: telemetry.Attrs{semconv.AttrOdataType: bucket},
		})
	}
	e.GaugeSnapshot(countMetricName, "{profile}",
		"Intune device configuration profile inventory, by configuration type (excludes Windows Update ring profiles, owned by the update-rings collector).", countPoints)
	e.GaugeSnapshot(versionMetricName, semconv.UnitDimensionless,
		"Configured version of each Intune device configuration profile; a bump signals a profile-content change.", versionPoints)

	return refs, nil
}

// statusOverview is the deviceConfigurationDeviceOverview
// (deviceStatusOverview) resource shape.
type statusOverview struct {
	PendingCount       int64 `json:"pendingCount"`
	NotApplicableCount int64 `json:"notApplicableCount"`
	SuccessCount       int64 `json:"successCount"`
	ErrorCount         int64 `json:"errorCount"`
	FailedCount        int64 `json:"failedCount"`
}

// points renders one overview into its five bounded (profile_name, state)
// gauge points.
func (o statusOverview) points(profileName string) []telemetry.GaugePoint {
	return []telemetry.GaugePoint{
		{Value: float64(o.SuccessCount), Attrs: telemetry.Attrs{semconv.AttrProfileName: profileName, semconv.AttrState: "success"}},
		{Value: float64(o.PendingCount), Attrs: telemetry.Attrs{semconv.AttrProfileName: profileName, semconv.AttrState: "pending"}},
		{Value: float64(o.FailedCount), Attrs: telemetry.Attrs{semconv.AttrProfileName: profileName, semconv.AttrState: "failed"}},
		{Value: float64(o.ErrorCount), Attrs: telemetry.Attrs{semconv.AttrProfileName: profileName, semconv.AttrState: "error"}},
		{Value: float64(o.NotApplicableCount), Attrs: telemetry.Attrs{semconv.AttrProfileName: profileName, semconv.AttrState: "not_applicable"}},
	}
}

// fetchStatusOverview GETs and decodes a single deviceStatusOverview
// singleton. This hits the sub-path directly rather than $expand, since
// $expand on a deviceConfigurations status collection can return HTTP 400
// (verified against the reference intune/compliance collector's identical
// deviceStatusOverview shape).
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

// collectStatusOverviews fans out to each profile's deviceStatusOverview
// singleton and emits the per-profile status gauge. A failure fetching one
// profile's overview is logged and joined into the returned error, but every
// other profile still emits whatever succeeded - one throttled or
// newly-deleted profile never blanks the whole snapshot.
func (c *Collector) collectStatusOverviews(ctx context.Context, e telemetry.Emitter, profiles []profileRef) error {
	var errs []error
	points := make([]telemetry.GaugePoint, 0, len(profiles)*5)

	for _, p := range profiles {
		ov, err := c.fetchStatusOverview(ctx, c.baseURL+"/deviceManagement/deviceConfigurations/"+p.id+"/deviceStatusOverview")
		switch {
		case err == nil:
			points = append(points, ov.points(p.name)...)
		case isForbidden(err):
			c.logger.Info("configprofiles: deviceStatusOverview unavailable; skipping profile",
				"collector", collectorName, "profile_name", p.name, "error", err)
		default:
			c.logger.Warn("configprofiles: deviceStatusOverview fetch failed",
				"collector", collectorName, "profile_name", p.name, "error", err)
			errs = append(errs, fmt.Errorf("deviceStatusOverview profile=%s: %w", p.name, err))
		}
	}

	e.GaugeSnapshot(statusMetricName, "{profile}",
		"Per-profile Intune device configuration deployment status, by profile and state.", points)
	return errors.Join(errs...)
}

// isForbidden reports whether err is a 403 from the Graph client - this
// collector's endpoints all require an active Intune license on the tenant in
// addition to the Graph scope, so "forbidden" is treated as an expected
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
