// Package autopilotdeployment is the Intune Autopilot device-preparation (V2)
// deployment-status collector (BETA): the per-device outcome of every Windows
// Autopilot device-prep deployment — the provisioning phase reached, the final
// deployment status, its duration, and the Windows result code — bucketed into a
// bounded status gauge and mirrored per device on a log twin.
//
// V2, not V1: on m7kni (live-verified 2026-07-19, probed as graph2otel-poller)
// the AutopilotV1DeploymentStatus export returns zero rows — the tenant uses
// Autopilot device preparation (V2). The V2 report returns real per-device rows,
// so this collector targets V2. A V1 collector is not built until a tenant with
// V1 (legacy Autopilot) data exists to map against (wire over docs).
//
// Codes are emitted RAW: DeploymentStatus, CurrentProvisioningPhase, Phase, and
// ResultCode are Microsoft's own numeric codes. They are not decoded into
// human-readable labels here — the enum→text mapping is undocumented and varies,
// and inventing it is the #142 trap. The raw code is bounded (a small fixed set)
// and honest; operators map it downstream. ResultCode 0 means success; anything
// else escalates the twin to WARN.
//
// Cardinality (#83/#112): per-device identity — device name, serial, UPN — never
// becomes a metric label. The gauge is keyed only by deployment_status (a bounded
// code), so the series count is fixed regardless of fleet size; every device's own
// deployment detail rides the intune.autopilot_deployment log twin. Guard test.
package autopilotdeployment

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
	collectorName = "intune.autopilot_deployment"
	metricName    = "intune.autopilot_deployment.deployments"
	eventName     = "intune.autopilot_deployment"
	reportName    = "AutopilotV2DeploymentStatus"
	// successResultCode is the ResultCode value meaning the deployment succeeded.
	successResultCode = "0"
)

// selectColumns pins the export columns (Microsoft's default set can change).
var selectColumns = []string{
	"DeviceId", "DeviceName", "SerialNumber", "UPN",
	"EnrollmentTimeInUtc", "CurrentProvisioningPhase", "DeploymentStatus",
	"DeploymentDurationTimeInSeconds", "Phase", "ResultCode",
}

// Collector polls the AutopilotV2DeploymentStatus export report through the shared
// export-job subsystem (internal/exportjob, #17).
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

// Collect runs the export job, counts devices by deployment status into the
// bounded gauge, and emits one twin per device row. Export failures are logged and
// swallowed, never surfaced to the scheduler.
func (c *Collector) Collect(ctx context.Context, e telemetry.Emitter) error {
	// This collector names its own transport (#141): exportjob never calls LogEvent.
	e = telemetry.WithTransport(e, telemetry.TransportReportExport)

	if c.export == nil {
		c.logger.Info("autopilotdeployment: no export runner configured; skipping", "collector", collectorName)
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
		counts[row["DeploymentStatus"]]++
		e.LogEvent(deviceLogEvent(row))
	}

	points := make([]telemetry.GaugePoint, 0, len(counts))
	for status, v := range counts {
		points = append(points, telemetry.GaugePoint{
			Value: v,
			Attrs: telemetry.Attrs{semconv.AttrDeploymentStatus: status},
		})
	}
	e.GaugeSnapshot(metricName, "{device}", "Intune Autopilot device-preparation (V2) deployment count by raw DeploymentStatus code; per-device detail on the intune.autopilot_deployment log twin.", points)

	return nil
}

// deviceLogEvent builds the per-device twin. The event timestamp is left unset:
// this is a state snapshot re-emitted each poll (like the sibling export
// collectors), so EnrollmentTimeInUtc is carried as an attribute, not the event
// time. Severity escalates to WARN when ResultCode is non-zero (a failed or
// timed-out deployment).
func deviceLogEvent(row exportjob.Row) telemetry.Event {
	attrs := telemetry.Attrs{}
	telemetry.SetStr(attrs, semconv.AttrDeviceName, row["DeviceName"])
	telemetry.SetStr(attrs, semconv.AttrDeviceId, row["DeviceId"])
	telemetry.SetStr(attrs, semconv.AttrSerialNumber, row["SerialNumber"])
	telemetry.SetStr(attrs, semconv.AttrUpn, row["UPN"])
	telemetry.SetStr(attrs, semconv.AttrDeploymentStatus, row["DeploymentStatus"])
	telemetry.SetStr(attrs, semconv.AttrCurrentProvisioningPhase, row["CurrentProvisioningPhase"])
	telemetry.SetStr(attrs, semconv.AttrPhase, row["Phase"])
	telemetry.SetStr(attrs, semconv.AttrResultCode, row["ResultCode"])
	telemetry.SetStr(attrs, semconv.AttrDeploymentDurationSeconds, row["DeploymentDurationTimeInSeconds"])
	telemetry.SetStr(attrs, semconv.AttrEnrollmentTime, row["EnrollmentTimeInUtc"])

	severity := telemetry.SeverityInfo
	if row["ResultCode"] != successResultCode {
		severity = telemetry.SeverityWarn
	}

	return telemetry.Event{
		Name:     eventName,
		Body:     "Intune Autopilot device-preparation deployment status",
		Severity: severity,
		Attrs:    attrs,
	}
}

func logExportFailure(logger *slog.Logger, err error) {
	switch {
	case errors.Is(err, exportjob.ErrJobFailed):
		logger.Warn("autopilotdeployment: export job failed", "collector", collectorName, "report_name", reportName, "error", err)
	case errors.Is(err, exportjob.ErrSASExpired):
		logger.Warn("autopilotdeployment: export SAS url expired before download", "collector", collectorName, "report_name", reportName, "error", err)
	case strings.Contains(err.Error(), "status 403"):
		logger.Info("autopilotdeployment: export job creation forbidden (missing write scope?); skipping", "collector", collectorName, "report_name", reportName, "error", err)
	default:
		logger.Warn("autopilotdeployment: export failed", "collector", collectorName, "report_name", reportName, "error", err)
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
