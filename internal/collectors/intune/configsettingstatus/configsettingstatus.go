// Package configsettingstatus is the Intune per-setting configuration-policy
// device-summary collector (BETA): for every (policy, setting) pair, the
// PerSettingDeviceSummaryByConfigurationPolicy export report returns how many
// assigned devices are compliant, errored, or in CONFLICT on that setting. This
// is the "which settings are in conflict across the fleet" view — the pre-aggregated
// answer to profile-assignment conflicts.
//
// Built on the shared reports export-job subsystem (internal/exportjob, #17). The
// report carries a localized SettingId_loc column, so an explicit `select` 400s
// (#203); the export omits select and takes the report's default columns.
//
// Shape: the report is ALREADY aggregated (one row per policy-setting, carrying
// three device counts), so there is no per-device entity here. The metric is the
// tenant-wide rollup — total compliant / error / conflict device-settings, three
// bounded series — and every (policy, setting) row's own counts ride the
// intune.config_setting_status log twin, so a LogQL `sum by (setting_name)` over
// conflict_device_count answers "which setting conflicts on how many devices" off
// data already shipped.
//
// Cardinality (#112): the gauge is keyed only by setting_device_status (a fixed
// three-value enum), so its series count never grows with the fleet or the config
// surface; policy/setting identity lives on the twin. Counts are Microsoft's own
// values, emitted verbatim. A row with any error or conflict device escalates its
// twin to WARN.
package configsettingstatus

import (
	"context"
	"errors"
	"log/slog"
	"strconv"
	"strings"
	"time"

	"github.com/rknightion/graph2otel/internal/collector"
	"github.com/rknightion/graph2otel/internal/collectors"
	"github.com/rknightion/graph2otel/internal/exportjob"
	"github.com/rknightion/graph2otel/internal/preflight"
	"github.com/rknightion/graph2otel/internal/semconv"
	"github.com/rknightion/graph2otel/internal/telemetry"
)

const (
	collectorName = "intune.config_setting_status"
	metricName    = "intune.config_setting_status.devices"
	eventName     = "intune.config_setting_status"
	reportName    = "PerSettingDeviceSummaryByConfigurationPolicy"

	statusCompliant = "compliant"
	statusError     = "error"
	statusConflict  = "conflict"
)

// Collector polls the PerSettingDeviceSummaryByConfigurationPolicy export report
// through the shared export-job subsystem (internal/exportjob, #17).
type Collector struct {
	export exportjob.Runner
	logger *slog.Logger
}

// New builds the collector. A nil export or logger is handled gracefully.
func New(export exportjob.Runner, logger *slog.Logger) *Collector {
	if logger == nil {
		logger = slog.Default()
	}
	return &Collector{export: export, logger: logger}
}

func (c *Collector) Name() string { return collectorName }

func (c *Collector) IngestTransport() telemetry.Transport {
	return telemetry.TransportReportExport
}

func (c *Collector) DefaultInterval() time.Duration { return 6 * time.Hour }

func (c *Collector) Experimental() bool { return true }

// RequiredPermissions declares the least-privilege Graph application scope — the
// write scope creates the export job and nothing else (see the export gotcha).
func (c *Collector) RequiredPermissions() []string {
	return []string{"DeviceManagementManagedDevices.ReadWrite.All"}
}

// Collect runs the export job, sums the three device-count columns across all
// policy-setting rows into a bounded three-point gauge, and emits one twin per row
// carrying that row's own counts. Export failures are logged and swallowed.
func (c *Collector) Collect(ctx context.Context, e telemetry.Emitter) error {
	// This collector names its own transport (#141): exportjob never calls LogEvent.
	e = telemetry.WithTransport(e, telemetry.TransportReportExport)

	if c.export == nil {
		c.logger.Info("configsettingstatus: no export runner configured; skipping", "collector", collectorName)
		return nil
	}

	rows, err := c.export.Export(ctx, exportjob.Request{
		ReportName: reportName,
		// Select omitted on purpose — the report's SettingId_loc column 400s when
		// named in select (#203), so we take the report's default columns.
		Format: exportjob.FormatCSV,
	}, e)
	if err != nil {
		logExportFailure(c.logger, err)
		return nil
	}

	if len(rows) == 0 {
		return nil
	}

	var compliant, errored, conflicted float64
	for _, row := range rows {
		compliant += parseCount(row["NumberOfCompliantDevices"])
		errored += parseCount(row["NumberOfErrorDevices"])
		conflicted += parseCount(row["NumberOfConflictDevices"])
		e.LogEvent(settingLogEvent(row))
	}

	points := []telemetry.GaugePoint{
		{Value: compliant, Attrs: telemetry.Attrs{semconv.AttrSettingDeviceStatus: statusCompliant}},
		{Value: errored, Attrs: telemetry.Attrs{semconv.AttrSettingDeviceStatus: statusError}},
		{Value: conflicted, Attrs: telemetry.Attrs{semconv.AttrSettingDeviceStatus: statusConflict}},
	}
	e.GaugeSnapshot(metricName, "{device}", "Intune configuration-policy per-setting device counts summed across all settings, bucketed by status (compliant/error/conflict); per-setting detail on the intune.config_setting_status log twin.", points)

	return nil
}

// parseCount parses a Microsoft count column to a float64, treating an empty or
// unparseable value as zero (a missing count is not a failure).
func parseCount(s string) float64 {
	if s == "" {
		return 0
	}
	v, err := strconv.ParseFloat(s, 64)
	if err != nil {
		return 0
	}
	return v
}

// settingLogEvent builds the per-(policy, setting) twin carrying that row's three
// device counts. The event timestamp is left unset (a re-emitted state snapshot).
// Severity escalates to WARN when the setting has any errored or conflicting
// device — the actionable rows an operator alerts on.
func settingLogEvent(row exportjob.Row) telemetry.Event {
	attrs := telemetry.Attrs{}
	telemetry.SetStr(attrs, semconv.AttrPolicyId, row["PolicyId"])
	telemetry.SetStr(attrs, semconv.AttrSettingId, row["SettingId"])
	telemetry.SetStr(attrs, semconv.AttrSettingName, row["SettingName"])
	telemetry.SetStr(attrs, semconv.AttrCompliantDeviceCount, row["NumberOfCompliantDevices"])
	telemetry.SetStr(attrs, semconv.AttrErrorDeviceCount, row["NumberOfErrorDevices"])
	telemetry.SetStr(attrs, semconv.AttrConflictDeviceCount, row["NumberOfConflictDevices"])

	severity := telemetry.SeverityInfo
	if parseCount(row["NumberOfErrorDevices"]) > 0 || parseCount(row["NumberOfConflictDevices"]) > 0 {
		severity = telemetry.SeverityWarn
	}

	return telemetry.Event{
		Name:     eventName,
		Body:     "Intune configuration-policy per-setting device summary",
		Severity: severity,
		Attrs:    attrs,
	}
}

func logExportFailure(logger *slog.Logger, err error) {
	switch {
	case errors.Is(err, exportjob.ErrJobFailed):
		logger.Warn("configsettingstatus: export job failed", "collector", collectorName, "report_name", reportName, "error", err)
	case errors.Is(err, exportjob.ErrSASExpired):
		logger.Warn("configsettingstatus: export SAS url expired before download", "collector", collectorName, "report_name", reportName, "error", err)
	case strings.Contains(err.Error(), "status 403"):
		logger.Info("configsettingstatus: export job creation forbidden (missing write scope?); skipping", "collector", collectorName, "report_name", reportName, "error", err)
	default:
		logger.Warn("configsettingstatus: export failed", "collector", collectorName, "report_name", reportName, "error", err)
	}
}

var (
	_ collector.SnapshotCollector  = (*Collector)(nil)
	_ collectors.Experimental      = (*Collector)(nil)
	_ preflight.PermissionRequirer = (*Collector)(nil)
)

func init() {
	collectors.Register(func(d collectors.Deps) collector.SnapshotCollector {
		return New(d.Export, d.Logger)
	})
}
