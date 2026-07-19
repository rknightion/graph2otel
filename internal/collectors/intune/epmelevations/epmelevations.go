// Package epmelevations is the Intune Endpoint Privilege Management (EPM)
// elevation collector (BETA): which applications were run with elevated privilege
// on managed devices, how often, and whether the elevation was governed by an EPM
// policy — a security-relevant SIEM signal (unmanaged elevations are users
// self-elevating outside policy). Emitted as a bounded elevation-count gauge by
// elevation type, mirrored per application on a log twin.
//
// The source is the EpmAggregationReportByApplication export report (live-verified
// 2026-07-19 on m7kni, probed as graph2otel-poller: 7 rows). It is already an
// aggregate — one row per (application, elevation type) with an ElevationCount —
// so there is no per-device row here; the aggregation is Microsoft's, and the
// per-application detail (file name, hash, version, publisher) rides the twin.
//
// Cardinality (#83/#112): the application identity — file name, hash, internal
// name — is unbounded (any binary a user elevates) and never becomes a metric
// label. The gauge is keyed only by elevation_type (a bounded EPM enum), value =
// the summed ElevationCount, so the series count is fixed regardless of how many
// distinct applications elevate; each application's own row rides the
// intune.epm_elevations log twin. Guard test.
package epmelevations

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
	collectorName = "intune.epm_elevations"
	metricName    = "intune.epm_elevations.count"
	eventName     = "intune.epm_elevations"
	reportName    = "EpmAggregationReportByApplication"
	// unmanagedElevation is the ElevationType meaning the elevation was NOT
	// governed by an EPM policy — the security-relevant case, escalated to WARN.
	unmanagedElevation = "UnmanagedElevation"
)

// selectColumns pins the export columns (Microsoft's default set can change).
var selectColumns = []string{
	"CompanyName", "ElevationType", "FileVersion", "Hash",
	"InternalName", "ElevationCount", "FileName", "IsBackgroundProcess",
}

// Collector polls the EpmAggregationReportByApplication export report through the
// shared export-job subsystem (internal/exportjob, #17).
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

// Collect runs the export job, sums ElevationCount by elevation_type into the
// bounded gauge, and emits one twin per application row. Export failures are
// logged and swallowed, never surfaced to the scheduler.
func (c *Collector) Collect(ctx context.Context, e telemetry.Emitter) error {
	// This collector names its own transport (#141): exportjob never calls LogEvent.
	e = telemetry.WithTransport(e, telemetry.TransportReportExport)

	if c.export == nil {
		c.logger.Info("epmelevations: no export runner configured; skipping", "collector", collectorName)
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

	// Sum the per-application ElevationCount into a bounded gauge by elevation
	// type. A type that appears with zero parseable counts still emits a 0 point,
	// so the series is visible even in a quiet window.
	sums := map[string]float64{}
	for _, row := range rows {
		et := row["ElevationType"]
		if _, seen := sums[et]; !seen {
			sums[et] = 0
		}
		if n, perr := strconv.ParseFloat(row["ElevationCount"], 64); perr == nil {
			sums[et] += n
		}
		e.LogEvent(appLogEvent(row))
	}

	points := make([]telemetry.GaugePoint, 0, len(sums))
	for et, v := range sums {
		points = append(points, telemetry.GaugePoint{
			Value: v,
			Attrs: telemetry.Attrs{semconv.AttrElevationType: et},
		})
	}
	e.GaugeSnapshot(metricName, "{elevation}", "Intune Endpoint Privilege Management elevation count by elevation type (managed vs unmanaged); per-application detail on the intune.epm_elevations log twin.", points)

	return nil
}

// appLogEvent builds the per-application twin. The event timestamp is left unset:
// this is an aggregate snapshot re-emitted each poll, so there is no per-row event
// time. Severity escalates to WARN for an unmanaged elevation (a user elevating
// outside any EPM policy — the security signal).
func appLogEvent(row exportjob.Row) telemetry.Event {
	attrs := telemetry.Attrs{}
	telemetry.SetStr(attrs, semconv.AttrFileName, row["FileName"])
	telemetry.SetStr(attrs, semconv.AttrInternalName, row["InternalName"])
	telemetry.SetStr(attrs, semconv.AttrCompanyName, row["CompanyName"])
	telemetry.SetStr(attrs, semconv.AttrFileVersion, row["FileVersion"])
	telemetry.SetStr(attrs, semconv.AttrFileHash, row["Hash"])
	telemetry.SetStr(attrs, semconv.AttrElevationType, row["ElevationType"])
	telemetry.SetStr(attrs, semconv.AttrElevationCount, row["ElevationCount"])
	telemetry.SetStr(attrs, semconv.AttrIsBackgroundProcess, row["IsBackgroundProcess"])

	severity := telemetry.SeverityInfo
	if row["ElevationType"] == unmanagedElevation {
		severity = telemetry.SeverityWarn
	}

	return telemetry.Event{
		Name:     eventName,
		Body:     "Intune EPM application elevation",
		Severity: severity,
		Attrs:    attrs,
	}
}

func logExportFailure(logger *slog.Logger, err error) {
	switch {
	case errors.Is(err, exportjob.ErrJobFailed):
		logger.Warn("epmelevations: export job failed", "collector", collectorName, "report_name", reportName, "error", err)
	case errors.Is(err, exportjob.ErrSASExpired):
		logger.Warn("epmelevations: export SAS url expired before download", "collector", collectorName, "report_name", reportName, "error", err)
	case strings.Contains(err.Error(), "status 403"):
		logger.Info("epmelevations: export job creation forbidden (missing write scope?); skipping", "collector", collectorName, "report_name", reportName, "error", err)
	default:
		logger.Warn("epmelevations: export failed", "collector", collectorName, "report_name", reportName, "error", err)
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
