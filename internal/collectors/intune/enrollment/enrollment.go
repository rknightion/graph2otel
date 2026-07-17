// Package enrollment is the Intune device enrollment configuration
// collector: inventory and change-detection gauges over the bounded
// `/deviceManagement/deviceEnrollmentConfigurations` collection (enrollment
// limits, platform restrictions, Windows Autopilot Enrollment Status Page
// profiles, Windows Hello for Business enrollment settings, co-management
// authority, ...).
//
// This is a heterogeneous OData collection - every entry derives from the
// same deviceEnrollmentConfiguration base type but each carries a different
// @odata.type subtype - so Collect branches on that field into a bounded set
// of config_type buckets, with an "other" leftover bucket for any subtype
// this collector doesn't yet recognize (a future Graph addition degrades to
// "other" rather than being silently dropped or failing the whole collect).
//
// The live enrollment-failure event stream (enrollmentTroubleshootingEvent)
// and the EnrollmentFailures report export are separate log-shaped surfaces
// deferred to the M5 logs milestone; this collector covers only the
// enrollment-config entities themselves.
package enrollment

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/rknightion/graph2otel/internal/collector"
	"github.com/rknightion/graph2otel/internal/collectors"
	"github.com/rknightion/graph2otel/internal/semconv"
	"github.com/rknightion/graph2otel/internal/telemetry"
)

// collectorName is the stable key used for config (enable/interval),
// self-observability, and the admin status page.
const collectorName = "intune.enrollment"

// Metric names this collector emits.
const (
	countMetricName    = "intune.enrollment_config.count"
	priorityMetricName = "intune.enrollment_config.priority"
	versionMetricName  = "intune.enrollment_config.version"
)

// defaultBaseURL is the Graph v1.0 root.
const defaultBaseURL = "https://graph.microsoft.com/v1.0"

// enrollmentConfigurationsPath is the single v1.0 endpoint this collector
// polls. It returns every deviceEnrollmentConfiguration subtype in one
// heterogeneous, admin-configured (not per-device) collection - small and
// bounded, so a full paged read every tick is the correct, cheap approach.
const enrollmentConfigurationsPath = "/deviceManagement/deviceEnrollmentConfigurations"

// configTypeBuckets maps a deviceEnrollmentConfiguration @odata.type value to
// its bounded config_type attribute value. This is the known-subtype set
// documented at
// https://learn.microsoft.com/en-us/graph/api/resources/intune-onboarding-deviceenrollmentconfiguration -
// an @odata.type not in this map (a future Graph addition) is bucketed as
// "other" by configType below, rather than failing or being dropped, so the
// count metric's total is always correct even as Microsoft adds subtypes.
var configTypeBuckets = map[string]string{
	"#microsoft.graph.deviceEnrollmentLimitConfiguration":                   "limit",
	"#microsoft.graph.deviceEnrollmentPlatformRestrictionsConfiguration":    "platform_restrictions",
	"#microsoft.graph.deviceEnrollmentPlatformRestrictionConfiguration":     "platform_restriction",
	"#microsoft.graph.windows10EnrollmentCompletionPageConfiguration":       "esp",
	"#microsoft.graph.deviceEnrollmentWindowsHelloForBusinessConfiguration": "windows_hello_for_business",
	"#microsoft.graph.deviceComanagementAuthorityConfiguration":             "comanagement_authority",
}

// configType returns the bounded config_type bucket for a raw @odata.type
// value, falling back to "other" for any subtype not in configTypeBuckets.
func configType(odataType string) string {
	if t, ok := configTypeBuckets[odataType]; ok {
		return t
	}
	return "other"
}

// enrollmentConfiguration mirrors only the base deviceEnrollmentConfiguration
// fields this collector reads (id, description, and per-subtype settings are
// per-entity/config detail that belongs in the M5 logs pipeline or Graph
// itself, never a metric label here). Per
// https://learn.microsoft.com/en-us/graph/api/resources/intune-onboarding-deviceenrollmentconfiguration,
// priority and version are both non-nullable Int32 properties on every
// subtype.
type enrollmentConfiguration struct {
	ODataType   string `json:"@odata.type"`
	DisplayName string `json:"displayName"`
	Priority    int    `json:"priority"`
	Version     int    `json:"version"`
}

// Collector polls the bounded deviceEnrollmentConfigurations collection.
type Collector struct {
	g       collectors.GraphClient
	baseURL string
	logger  *slog.Logger
}

// New builds the enrollment configuration collector. A nil logger falls back
// to the slog default.
func New(g collectors.GraphClient, logger *slog.Logger) *Collector {
	if logger == nil {
		logger = slog.Default()
	}
	return &Collector{g: g, baseURL: defaultBaseURL, logger: logger}
}

// Name implements collector.Collector.
func (c *Collector) Name() string { return collectorName }

// DefaultInterval implements collector.Collector. Enrollment configuration is
// an admin-set object with no delta query and no per-device throttle
// pressure; it drifts rarely, so fifteen minutes matches this exporter's
// other slow-drifting admin-config collectors.
func (c *Collector) DefaultInterval() time.Duration { return 15 * time.Minute }

// RequiredPermissions declares the least-privilege Graph application scope.
// Per the deviceEnrollmentConfigurations list operation docs,
// DeviceManagementServiceConfig.Read.All is the least-privileged application
// permission for GET /deviceManagement/deviceEnrollmentConfigurations.
func (c *Collector) RequiredPermissions() []string {
	return []string{"DeviceManagementServiceConfig.Read.All"}
}

// Collect fetches the full deviceEnrollmentConfigurations collection and
// emits three gauges: inventory counts by config_type, per-config priority,
// and per-config version. A failure to list the collection at all (including
// a 403 from a missing scope) aborts before emitting anything, since there is
// no partial data to report in that case - the wrapped error still lets
// self-observability (graph2otel.scrape.success) reflect the failure rather
// than reporting an optimistic success. An entry that fails to decode is
// logged and skipped (aggregated into the returned error) without discarding
// the rest of the snapshot.
func (c *Collector) Collect(ctx context.Context, e telemetry.Emitter) error {
	raw, err := collectors.GetAllValues(ctx, c.g, c.baseURL+enrollmentConfigurationsPath, nil)
	if err != nil {
		return fmt.Errorf("intune.enrollment: list device enrollment configurations: %w", err)
	}

	countByType := map[string]int64{}
	var priorityPoints []telemetry.GaugePoint
	var versionPoints []telemetry.GaugePoint
	var errs []error

	for _, r := range raw {
		var cfg enrollmentConfiguration
		if err := json.Unmarshal(r, &cfg); err != nil {
			c.logger.Warn("intune.enrollment: skipping unparseable configuration", "collector", collectorName, "error", err)
			errs = append(errs, fmt.Errorf("decode enrollment configuration: %w", err))
			continue
		}

		typ := configType(cfg.ODataType)
		name := orUnknown(cfg.DisplayName)
		countByType[typ]++
		priorityPoints = append(priorityPoints, telemetry.GaugePoint{
			Value: float64(cfg.Priority),
			Attrs: telemetry.Attrs{semconv.AttrConfigType: typ, semconv.AttrConfigName: name},
		})
		versionPoints = append(versionPoints, telemetry.GaugePoint{
			Value: float64(cfg.Version),
			Attrs: telemetry.Attrs{semconv.AttrConfigName: name},
		})
	}

	countPoints := make([]telemetry.GaugePoint, 0, len(countByType))
	for typ, n := range countByType {
		countPoints = append(countPoints, telemetry.GaugePoint{Value: float64(n), Attrs: telemetry.Attrs{semconv.AttrConfigType: typ}})
	}

	e.GaugeSnapshot(countMetricName, "{config}",
		"Intune device enrollment configurations, by config type.", countPoints)
	e.GaugeSnapshot(priorityMetricName, semconv.UnitDimensionless,
		"Evaluation priority of each Intune device enrollment configuration. Lower values win: "+
			"a user in scope for multiple configurations of the same type is subject only to the "+
			"one with the lowest priority value - a higher number is NOT higher precedence.",
		priorityPoints)
	e.GaugeSnapshot(versionMetricName, semconv.UnitDimensionless,
		"Version counter of each Intune device enrollment configuration, for change detection.",
		versionPoints)

	return errors.Join(errs...)
}

// orUnknown substitutes "unknown" for an empty displayName, keeping the
// config_name attribute value always non-empty without inventing a
// per-entity identifier (id is never used as the label).
func orUnknown(s string) string {
	if s == "" {
		return "unknown"
	}
	return s
}

// Compile-time assertion that Collector satisfies collector.SnapshotCollector.
var _ collector.SnapshotCollector = (*Collector)(nil)

func init() {
	collectors.Register(func(d collectors.Deps) collector.SnapshotCollector {
		return New(d.Graph, d.Logger)
	})
}
