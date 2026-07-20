// Package autopilotdeploymentapps is the Intune Autopilot device-preparation (V2)
// per-application deployment-status collector (BETA): the "Apps" tab of the
// device-deployment-details pane — for every application targeted during a Windows
// Autopilot device-preparation deployment, its per-device install status — bucketed
// into a bounded status gauge and mirrored per (device, app) row on a log twin.
//
// Sibling of intune.autopilot_deployment (the device-level "Device" tab). Same
// Reports Export subsystem, same shape; the report is
// AutopilotV2DeploymentStatusDetailedAppInfo (live-verified 2026-07-20 as
// graph2otel-poller: real rows on m7kni).
//
// PolicyInstallStatus is Microsoft's own RAW numeric code, emitted verbatim and
// NOT decoded (the enum→text mapping is undocumented — the #142 trap). It is also
// NOT translated into a severity: app-level status is independent of the device's
// overall deployment outcome (live-measured — a device whose deployment FAILED at a
// later phase still shows PolicyInstallStatus=2 for its apps), and the failed code
// was not observed, so inventing a success/failure split would be a guess. Every
// row is INFO; a failed install surfaces as a distinct raw status bucket in both the
// gauge and the twin, which operators alert on (count by policy_install_status).
//
// Cardinality (#83/#112): per-entity identity — device id, application id/name —
// never becomes a metric label. The gauge is keyed only by policy_install_status (a
// bounded code), so series count is fixed regardless of fleet or app-catalog size;
// every (device, app) install detail rides the log twin. Guard test.
package autopilotdeploymentapps

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
	collectorName = "intune.autopilot_deployment_apps"
	metricName    = "intune.autopilot_deployment_apps.installs"
	eventName     = "intune.autopilot_deployment_apps"
	reportName    = "AutopilotV2DeploymentStatusDetailedAppInfo"
)

// selectColumns pins the export columns (Microsoft's default set can change).
var selectColumns = []string{
	"DeviceId", "ApplicationId", "ApplicationName", "AppType",
	"IsAdminSelected", "PolicyInstallStatus",
}

// Collector polls the AutopilotV2DeploymentStatusDetailedAppInfo export report
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

// Collect runs the export job, counts app-install rows by raw PolicyInstallStatus
// into the bounded gauge, and emits one twin per (device, app) row. Export failures
// are logged and swallowed, never surfaced to the scheduler.
func (c *Collector) Collect(ctx context.Context, e telemetry.Emitter) error {
	// This collector names its own transport (#141): exportjob never calls LogEvent.
	e = telemetry.WithTransport(e, telemetry.TransportReportExport)

	if c.export == nil {
		c.logger.Info("autopilotdeploymentapps: no export runner configured; skipping", "collector", collectorName)
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
		e.LogEvent(appLogEvent(row))
	}

	points := make([]telemetry.GaugePoint, 0, len(counts))
	for status, v := range counts {
		points = append(points, telemetry.GaugePoint{
			Value: v,
			Attrs: telemetry.Attrs{semconv.AttrPolicyInstallStatus: status},
		})
	}
	e.GaugeSnapshot(metricName, "{app}", "Intune Autopilot device-preparation (V2) per-application install count by raw PolicyInstallStatus code; per-app detail on the intune.autopilot_deployment_apps log twin.", points)

	return nil
}

// appLogEvent builds the per-(device, app) twin. The event timestamp is left unset:
// this is a state snapshot re-emitted each poll (like the sibling export collectors),
// and the report carries no per-row timestamp. Severity is INFO for every row — the
// raw PolicyInstallStatus enum is undocumented and app status is independent of the
// device's deployment outcome, so a failed install shows as a distinct raw status
// bucket rather than an invented severity.
func appLogEvent(row exportjob.Row) telemetry.Event {
	attrs := telemetry.Attrs{}
	telemetry.SetStr(attrs, semconv.AttrDeviceId, row["DeviceId"])
	telemetry.SetStr(attrs, semconv.AttrApplicationId, row["ApplicationId"])
	telemetry.SetStr(attrs, semconv.AttrAppName, row["ApplicationName"])
	telemetry.SetStr(attrs, semconv.AttrAppType, row["AppType"])
	telemetry.SetStr(attrs, semconv.AttrIsAdminSelected, row["IsAdminSelected"])
	telemetry.SetStr(attrs, semconv.AttrPolicyInstallStatus, row["PolicyInstallStatus"])

	return telemetry.Event{
		Name:     eventName,
		Body:     "Intune Autopilot device-preparation app install status",
		Severity: telemetry.SeverityInfo,
		Attrs:    attrs,
	}
}

func logExportFailure(logger *slog.Logger, err error) {
	switch {
	case errors.Is(err, exportjob.ErrJobFailed):
		logger.Warn("autopilotdeploymentapps: export job failed", "collector", collectorName, "report_name", reportName, "error", err)
	case errors.Is(err, exportjob.ErrSASExpired):
		logger.Warn("autopilotdeploymentapps: export SAS url expired before download", "collector", collectorName, "report_name", reportName, "error", err)
	case strings.Contains(err.Error(), "status 403"):
		logger.Info("autopilotdeploymentapps: export job creation forbidden (missing write scope?); skipping", "collector", collectorName, "report_name", reportName, "error", err)
	default:
		logger.Warn("autopilotdeploymentapps: export failed", "collector", collectorName, "report_name", reportName, "error", err)
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
