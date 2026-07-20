// Package epmdenied is the Intune Endpoint Privilege Management (EPM) denied-elevation
// collector: for every elevation request a user's EPM policy DENIED (an "Unmanaged
// elevation" attempt outside any elevation rule, or an explicit deny), the target
// file, its publisher/hash, and the requesting user and device — bucketed into a
// bounded gauge by elevation type and mirrored per-denial on a log twin.
//
// Sibling of intune.epm_elevations (the granted-elevation collector); this report
// covers the denied side, which is the security-relevant one (#83/#112 rationale for
// the twin — a denied elevation is a thing an analyst wants to find by device/user/
// hash, never a metric label).
//
// Evidence class: EpmDeniedReport returned ZERO rows when probed as
// graph2otel-poller on m7kni on 2026-07-20 — a healthy tenant has no denied
// elevations, so no live row was observed (n=0). The report has no "_loc" localized
// column variant (unlike most Intune export reports), so the export column set is
// pinned explicitly below rather than left to Microsoft's changeable default. Column
// NAMES are live-confirmed from the export default header; fixture VALUES in the
// tests are illustrative only, never asserted as observed on the wire (#142
// discipline). Full live header: UserName, DeviceId, DeviceName, FileName,
// FileProductName, FileDescription, FileInternalName, FileVersion, HashValue,
// Publisher, ElevationType, MonthElevationCount.
package epmdenied

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
	collectorName = "intune.epm_denied"
	metricName    = "intune.epm_denied.denials"
	eventName     = "intune.epm_denied"
	reportName    = "EpmDeniedReport"
)

// selectColumns pins the export columns. EpmDeniedReport has no "_loc" column
// variant to fall back to, so this list is not merely Microsoft's default set — it
// is the only known-working select for this report.
var selectColumns = []string{
	"UserName", "DeviceId", "DeviceName", "FileName", "FileProductName",
	"FileDescription", "FileInternalName", "FileVersion", "HashValue",
	"Publisher", "ElevationType", "MonthElevationCount",
}

// Collector polls the EpmDeniedReport export report through the shared export-job
// subsystem (internal/exportjob, #17).
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

// Collect runs the export job, counts denied-elevation rows by ElevationType into
// the bounded gauge, and emits one twin per denial row at WARN severity. Export
// failures are logged and swallowed, never surfaced to the scheduler. Zero rows
// emit nothing and is a valid steady state.
func (c *Collector) Collect(ctx context.Context, e telemetry.Emitter) error {
	// This collector names its own transport (#141): exportjob never calls LogEvent.
	e = telemetry.WithTransport(e, telemetry.TransportReportExport)

	if c.export == nil {
		c.logger.Info("epmdenied: no export runner configured; skipping", "collector", collectorName)
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
		counts[row["ElevationType"]]++
		e.LogEvent(denialLogEvent(row))
	}

	points := make([]telemetry.GaugePoint, 0, len(counts))
	for elevationType, v := range counts {
		points = append(points, telemetry.GaugePoint{
			Value: v,
			Attrs: telemetry.Attrs{semconv.AttrElevationType: elevationType},
		})
	}
	e.GaugeSnapshot(metricName, "{denial}", "Intune Endpoint Privilege Management denied elevation count by elevation type; per-denial detail on the intune.epm_denied log twin.", points)

	return nil
}

// denialLogEvent builds the per-denial twin. The event timestamp is left unset:
// this is a state snapshot re-emitted each poll, and the report carries no per-row
// timestamp. Severity is always WARN: a denied privilege elevation is a security
// signal, not routine informational activity.
func denialLogEvent(row exportjob.Row) telemetry.Event {
	attrs := telemetry.Attrs{}
	telemetry.SetStr(attrs, semconv.AttrDeviceId, row["DeviceId"])
	telemetry.SetStr(attrs, semconv.AttrDeviceName, row["DeviceName"])
	telemetry.SetStr(attrs, semconv.AttrUserName, row["UserName"])
	telemetry.SetStr(attrs, semconv.AttrFileName, row["FileName"])
	telemetry.SetStr(attrs, semconv.AttrFileDescription, row["FileDescription"])
	telemetry.SetStr(attrs, semconv.AttrPublisher, row["Publisher"])
	telemetry.SetStr(attrs, semconv.AttrHash, row["HashValue"])
	telemetry.SetStr(attrs, semconv.AttrElevationType, row["ElevationType"])
	telemetry.SetStr(attrs, semconv.AttrMonthElevationCount, row["MonthElevationCount"])

	return telemetry.Event{
		Name:     eventName,
		Body:     "Intune EPM denied elevation",
		Severity: telemetry.SeverityWarn,
		Attrs:    attrs,
	}
}

func logExportFailure(logger *slog.Logger, err error) {
	switch {
	case errors.Is(err, exportjob.ErrJobFailed):
		logger.Warn("epmdenied: export job failed", "collector", collectorName, "report_name", reportName, "error", err)
	case errors.Is(err, exportjob.ErrSASExpired):
		logger.Warn("epmdenied: export SAS url expired before download", "collector", collectorName, "report_name", reportName, "error", err)
	case strings.Contains(err.Error(), "status 403"):
		logger.Info("epmdenied: export job creation forbidden (missing write scope?); skipping", "collector", collectorName, "report_name", reportName, "error", err)
	default:
		logger.Warn("epmdenied: export failed", "collector", collectorName, "report_name", reportName, "error", err)
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
