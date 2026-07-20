// Package autopilotdeploymentscripts is the Intune Autopilot device-preparation (V2)
// per-script deployment-status collector (BETA): the "Scripts" tab of the
// device-deployment-details pane — for every PowerShell script run during a Windows
// Autopilot device-preparation deployment, its per-device execution status —
// bucketed into a bounded status gauge and mirrored per (device, script) row on a
// log twin.
//
// Sibling of intune.autopilot_deployment (device-level) and
// intune.autopilot_deployment_apps (per-app). Same Reports Export subsystem, same
// shape; the report is AutopilotV2DeploymentStatusDetailedScriptInfo.
//
// Evidence class: the report and its columns (DeviceId, PolicyId, DisplayName,
// PolicyInstallStatus) are live-confirmed from the export header (probed as
// graph2otel-poller 2026-07-20 on m7kni), but the report returned ZERO rows — m7kni
// configures no device-prep scripts, so no live row was observed (n=0). Empty is a
// valid steady state (a green run with no data), like several risk collectors.
//
// PolicyInstallStatus is Microsoft's own RAW numeric code, emitted verbatim and NOT
// decoded (undocumented enum — the #142 trap) and NOT translated into severity;
// every row is INFO. A failed execution surfaces as a distinct raw status bucket in
// both the gauge and the twin (count by policy_install_status).
//
// Cardinality (#83/#112): per-entity identity — device id, script name — never
// becomes a metric label. The gauge is keyed only by policy_install_status; every
// (device, script) execution detail rides the log twin. Guard test.
package autopilotdeploymentscripts

import (
	"context"
	"errors"
	"log/slog"
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
	collectorName = "intune.autopilot_deployment_scripts"
	metricName    = "intune.autopilot_deployment_scripts.executions"
	eventName     = "intune.autopilot_deployment_scripts"
	reportName    = "AutopilotV2DeploymentStatusDetailedScriptInfo"
)

// selectColumns pins the export columns (Microsoft's default set can change).
var selectColumns = []string{
	"DeviceId", "PolicyId", "DisplayName", "PolicyInstallStatus",
}

// Collector polls the AutopilotV2DeploymentStatusDetailedScriptInfo export report
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

// Collect runs the export job, counts script-execution rows by raw
// PolicyInstallStatus into the bounded gauge, and emits one twin per (device,
// script) row. Export failures are logged and swallowed, never surfaced to the
// scheduler. Zero rows emit nothing and is a valid steady state.
func (c *Collector) Collect(ctx context.Context, e telemetry.Emitter) error {
	// This collector names its own transport (#141): exportjob never calls LogEvent.
	e = telemetry.WithTransport(e, telemetry.TransportReportExport)

	if c.export == nil {
		c.logger.Info("autopilotdeploymentscripts: no export runner configured; skipping", "collector", collectorName)
		return nil
	}

	rows, err := c.export.Export(ctx, exportjob.Request{
		ReportName: reportName,
		Select:     selectColumns,
		Format:     exportjob.FormatCSV,
	}, e)
	if err != nil {
		logExportFailure(c.logger, err)
		return nil
	}

	counts := map[string]float64{}
	for _, row := range rows {
		counts[row["PolicyInstallStatus"]]++
		e.LogEvent(scriptLogEvent(row))
	}

	points := make([]telemetry.GaugePoint, 0, len(counts))
	for status, v := range counts {
		points = append(points, telemetry.GaugePoint{
			Value: v,
			Attrs: telemetry.Attrs{semconv.AttrPolicyInstallStatus: status},
		})
	}
	e.GaugeSnapshot(metricName, "{script}", "Intune Autopilot device-preparation (V2) per-script execution count by raw PolicyInstallStatus code; per-script detail on the intune.autopilot_deployment_scripts log twin.", points)

	return nil
}

// scriptLogEvent builds the per-(device, script) twin. The event timestamp is left
// unset: this is a state snapshot re-emitted each poll, and the report carries no
// per-row timestamp. Severity is INFO for every row — the raw PolicyInstallStatus
// enum is undocumented, so a failed run shows as a distinct raw status bucket rather
// than an invented severity.
func scriptLogEvent(row exportjob.Row) telemetry.Event {
	attrs := telemetry.Attrs{}
	telemetry.SetStr(attrs, semconv.AttrDeviceId, row["DeviceId"])
	telemetry.SetStr(attrs, semconv.AttrPolicyId, row["PolicyId"])
	telemetry.SetStr(attrs, semconv.AttrDisplayName, row["DisplayName"])
	telemetry.SetStr(attrs, semconv.AttrPolicyInstallStatus, row["PolicyInstallStatus"])

	return telemetry.Event{
		Name:     eventName,
		Body:     "Intune Autopilot device-preparation script execution status",
		Severity: telemetry.SeverityInfo,
		Attrs:    attrs,
	}
}

func logExportFailure(logger *slog.Logger, err error) {
	switch {
	case errors.Is(err, exportjob.ErrJobFailed):
		logger.Warn("autopilotdeploymentscripts: export job failed", "collector", collectorName, "report_name", reportName, "error", err)
	case errors.Is(err, exportjob.ErrSASExpired):
		logger.Warn("autopilotdeploymentscripts: export SAS url expired before download", "collector", collectorName, "report_name", reportName, "error", err)
	case strings.Contains(err.Error(), "status 403"):
		logger.Info("autopilotdeploymentscripts: export job creation forbidden (missing write scope?); skipping", "collector", collectorName, "report_name", reportName, "error", err)
	default:
		logger.Warn("autopilotdeploymentscripts: export failed", "collector", collectorName, "report_name", reportName, "error", err)
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
