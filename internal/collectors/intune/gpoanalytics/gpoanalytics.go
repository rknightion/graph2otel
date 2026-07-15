// Package gpoanalytics is the Intune Group Policy analytics collector
// (BETA): migration-readiness scoring for imported Group Policy Objects
// (how much of a GPO can move to Intune), plus a bounded inventory count of
// groupPolicyConfigurations by ingestion type.
//
// Beta-only: both polled resources (groupPolicyMigrationReport,
// groupPolicyConfiguration) live only on /beta, so this collector implements
// collectors.Experimental (opt-in, off by default) and degrades cleanly — a
// 403/404 (endpoint unavailable or unlicensed on the tenant) is
// skipped-and-logged rather than treated as a failure, mirroring
// entra/recommendations.
//
// groupPolicyObjectFiles is deliberately never polled: its only interesting
// field is the raw GPO XML (groupPolicyObjectFile.content), which must never
// become telemetry, and no metric here needs it — the migration report
// already carries migrationReadiness/totalSettingsCount/
// supportedSettingsCount directly. Not fetching the endpoint is the simplest
// way to guarantee that raw XML can never leak into a metric attribute.
package gpoanalytics

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
	"github.com/rknightion/graph2otel/internal/telemetry"
)

// collectorName is the stable key used for config (enable/interval),
// self-observability, and the admin status page.
const collectorName = "intune.gpo_analytics"

// Metric names this collector emits. Each is its own metric name so summing
// one metric always yields the true count for that breakdown.
const (
	migrationReadinessMetric       = "intune.gpo.migration_readiness"
	supportedSettingsPercentMetric = "intune.gpo.supported_settings_percent"
	configCountMetric              = "intune.gpo.config.count"
)

// betaBaseURL is the Graph beta root. Both groupPolicyMigrationReports and
// groupPolicyConfigurations are beta-only resources.
const betaBaseURL = "https://graph.microsoft.com/beta"

// readinessBuckets maps every documented groupPolicyMigrationReadiness enum
// value (https://learn.microsoft.com/en-us/graph/api/resources/intune-gpanalyticsservice-grouppolicymigrationreport)
// to its bounded attribute value. Anything not in this map (a future beta
// enum addition, or an empty/unexpected value) falls into "other" rather
// than being passed through raw, so the readiness dimension can never grow
// unbounded.
var readinessBuckets = map[string]string{
	"none":          "none",
	"partial":       "partial",
	"complete":      "complete",
	"error":         "error",
	"notApplicable": "notApplicable",
}

func readinessBucketFor(raw string) string {
	if b, ok := readinessBuckets[raw]; ok {
		return b
	}
	return "other"
}

// ingestionTypeBuckets maps every documented groupPolicyConfigurationIngestionType
// enum value to its bounded attribute value. Anything not in this map falls
// into "other".
var ingestionTypeBuckets = map[string]string{
	"unknown":            "unknown",
	"custom":             "custom",
	"builtIn":            "builtIn",
	"mixed":              "mixed",
	"unknownFutureValue": "unknownFutureValue",
}

func ingestionTypeBucketFor(raw string) string {
	if b, ok := ingestionTypeBuckets[raw]; ok {
		return b
	}
	return "other"
}

// groupPolicyMigrationReport is the subset of the beta groupPolicyMigrationReport
// resource this collector reads. displayName is the GPO's own name — bounded
// by the number of imported GPOs (an admin-configured count, dozens to low
// hundreds), not by tenant/device size. No id, groupPolicyObjectId, or
// ouDistinguishedName is ever read, since those are per-entity identifiers
// that must never become metric labels, and content (raw GPO XML) lives only
// on the separate groupPolicyObjectFiles resource, which this collector does
// not poll at all.
type groupPolicyMigrationReport struct {
	DisplayName            string `json:"displayName"`
	MigrationReadiness     string `json:"migrationReadiness"`
	TotalSettingsCount     int64  `json:"totalSettingsCount"`
	SupportedSettingsCount int64  `json:"supportedSettingsCount"`
}

// groupPolicyConfiguration is the subset of the beta groupPolicyConfiguration
// resource this collector reads for the config-count-by-ingestion-type
// gauge. No id or displayName is read into telemetry.
type groupPolicyConfiguration struct {
	PolicyConfigurationIngestionType string `json:"policyConfigurationIngestionType"`
}

// Collector polls the beta groupPolicyMigrationReports and
// groupPolicyConfigurations endpoints.
type Collector struct {
	g       collectors.GraphClient
	baseURL string
	logger  *slog.Logger
}

// New builds the gpoanalytics collector. A nil logger falls back to the slog
// default.
func New(g collectors.GraphClient, logger *slog.Logger) *Collector {
	if logger == nil {
		logger = slog.Default()
	}
	return &Collector{g: g, baseURL: betaBaseURL, logger: logger}
}

// Name implements collector.SnapshotCollector.
func (c *Collector) Name() string { return collectorName }

// DefaultInterval implements collector.SnapshotCollector. GPO migration
// readiness and configuration inventory are admin-driven and change rarely —
// a daily cadence is plenty (see the tracking issue).
func (c *Collector) DefaultInterval() time.Duration { return 24 * time.Hour }

// Experimental marks this as a beta, opt-in collector.
func (c *Collector) Experimental() bool { return true }

// RequiredPermissions declares the least-privilege Graph scope both polled
// resources document.
func (c *Collector) RequiredPermissions() []string {
	return []string{"DeviceManagementConfiguration.Read.All"}
}

// Collect fetches groupPolicyMigrationReports and groupPolicyConfigurations
// independently and emits the bounded gauges described in the package doc.
// Each fetch is independently resilient: a 403/404 (endpoint unavailable or
// unlicensed on the tenant) is skipped-and-logged, any other error is logged
// and joined into the returned error, but the other fetch's metrics still
// emit.
func (c *Collector) Collect(ctx context.Context, e telemetry.Emitter) error {
	var errs []error

	if err := c.collectMigrationReports(ctx, e); err != nil {
		if isUnavailable(err) {
			c.logger.Info("gpoanalytics: groupPolicyMigrationReports unavailable on this tenant; skipping",
				"collector", collectorName, "error", err)
		} else {
			c.logger.Warn("gpoanalytics: groupPolicyMigrationReports fetch failed", "collector", collectorName, "error", err)
			errs = append(errs, fmt.Errorf("migration reports: %w", err))
		}
	}

	if err := c.collectConfigurations(ctx, e); err != nil {
		if isUnavailable(err) {
			c.logger.Info("gpoanalytics: groupPolicyConfigurations unavailable on this tenant; skipping",
				"collector", collectorName, "error", err)
		} else {
			c.logger.Warn("gpoanalytics: groupPolicyConfigurations fetch failed", "collector", collectorName, "error", err)
			errs = append(errs, fmt.Errorf("configurations: %w", err))
		}
	}

	return errors.Join(errs...)
}

// collectMigrationReports pages groupPolicyMigrationReports (bounded by
// imported-GPO count, not device count) and emits one migration_readiness
// point plus one supported_settings_percent point per report.
func (c *Collector) collectMigrationReports(ctx context.Context, e telemetry.Emitter) error {
	raw, err := collectors.GetAllValues(ctx, c.g, c.baseURL+"/deviceManagement/groupPolicyMigrationReports", nil)
	if err != nil {
		return err
	}

	readiness := make([]telemetry.GaugePoint, 0, len(raw))
	percent := make([]telemetry.GaugePoint, 0, len(raw))
	for _, r := range raw {
		var rep groupPolicyMigrationReport
		if err := json.Unmarshal(r, &rep); err != nil {
			c.logger.Warn("gpoanalytics: skipping unparseable migration report", "collector", collectorName, "error", err)
			continue
		}
		name := orUnknown(rep.DisplayName)
		readiness = append(readiness, telemetry.GaugePoint{
			Value: 1,
			Attrs: telemetry.Attrs{"report_name": name, "readiness": readinessBucketFor(rep.MigrationReadiness)},
		})
		percent = append(percent, telemetry.GaugePoint{
			Value: percentOf(rep.SupportedSettingsCount, rep.TotalSettingsCount),
			Attrs: telemetry.Attrs{"report_name": name},
		})
	}

	e.GaugeSnapshot(migrationReadinessMetric, "{report}", "Intune Group Policy migration reports by readiness state.", readiness)
	e.GaugeSnapshot(supportedSettingsPercentMetric, "%", "Percentage of a Group Policy Object's settings supported by Intune, computed from supportedSettingsCount/totalSettingsCount.", percent)
	return nil
}

// collectConfigurations pages groupPolicyConfigurations (bounded by
// admin-configured config count, not device count) and emits the count by
// ingestion type.
func (c *Collector) collectConfigurations(ctx context.Context, e telemetry.Emitter) error {
	raw, err := collectors.GetAllValues(ctx, c.g, c.baseURL+"/deviceManagement/groupPolicyConfigurations", nil)
	if err != nil {
		return err
	}

	counts := map[string]int64{}
	for _, r := range raw {
		var cfg groupPolicyConfiguration
		if err := json.Unmarshal(r, &cfg); err != nil {
			c.logger.Warn("gpoanalytics: skipping unparseable configuration", "collector", collectorName, "error", err)
			continue
		}
		counts[ingestionTypeBucketFor(cfg.PolicyConfigurationIngestionType)]++
	}

	points := make([]telemetry.GaugePoint, 0, len(counts))
	for typ, n := range counts {
		points = append(points, telemetry.GaugePoint{Value: float64(n), Attrs: telemetry.Attrs{"ingestion_type": typ}})
	}
	e.GaugeSnapshot(configCountMetric, "{config}", "Intune Group Policy configurations by policy configuration ingestion type.", points)
	return nil
}

// percentOf computes the supported-settings percentage from raw counts,
// guarding the 0/0 case (a GPO with no settings at all) rather than dividing
// by zero.
func percentOf(supported, total int64) float64 {
	if total == 0 {
		return 0
	}
	return float64(supported) / float64(total) * 100
}

// isUnavailable reports whether err is a 4xx from a beta endpoint being
// unavailable/unlicensed on the tenant (403 forbidden, 404 not found) — an
// expected "no data here" condition, not a failure.
func isUnavailable(err error) bool {
	s := err.Error()
	return strings.Contains(s, "status 403") || strings.Contains(s, "status 404")
}

func orUnknown(s string) string {
	if s == "" {
		return "unknown"
	}
	return s
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
