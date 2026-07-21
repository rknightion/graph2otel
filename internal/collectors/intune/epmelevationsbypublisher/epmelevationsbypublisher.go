// Package epmelevationsbypublisher is the per-PUBLISHER attribution cut of Intune
// Endpoint Privilege Management elevations (BETA): whose software is being run
// elevated on managed devices, how often, and whether the elevation was governed
// by an EPM policy. It is a sibling of intune.epm_elevations (the per-application
// cut, EpmAggregationReportByApplication) reading the same EPM data through the
// same reports-export engine, rolled up to the signing company rather than the
// binary — the cut that shows a long tail of third-party publishers elevating
// outside policy without needing per-binary detail.
//
// The source is the EpmAggregationReportByPublisher export report (live-verified
// 2026-07-21 on m7kni, probed as graph2otel-poller). It is already an aggregate:
// one row per (publisher, elevation type) with an ElevationCount. The report
// accepts an explicit `select` naming exactly the three columns below
// (live-confirmed), and none of them is a localized `_loc` column, so the #203
// "explicit select 400s" trap does not apply and the columns are pinned.
//
// ElevationType is the same wire enum as intune.epm_elevations —
// "UnmanagedElevation" means an elevation NOT governed by an EPM policy, the
// security-relevant case. Its values are passed through VERBATIM (not lowercased,
// not re-mapped), so the metric label matches what an analyst sees in the Intune
// portal and in the sibling collectors.
//
// Cardinality (#83/#112): the publisher (CompanyName) is unbounded in principle —
// any company whose signed binary a user elevates — and never becomes a metric
// label. The gauge is keyed only by elevation_type (a bounded EPM enum), value =
// the summed ElevationCount, so the series count is fixed regardless of how many
// distinct publishers appear; each publisher's own row rides the
// intune.epm_elevations_by_publisher log twin. Guard test.
package epmelevationsbypublisher

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
	collectorName = "intune.epm_elevations_by_publisher"
	metricName    = "intune.epm_elevations_by_publisher.count"
	eventName     = "intune.epm_elevations_by_publisher"
	reportName    = "EpmAggregationReportByPublisher"
	// unmanagedElevation is the ElevationType meaning the elevation was NOT
	// governed by an EPM policy — the security-relevant case, escalated to WARN.
	unmanagedElevation = "UnmanagedElevation"
)

// selectColumns pins the export columns (Microsoft's default set can change).
// Live-confirmed accepted as an explicit select 2026-07-21.
var selectColumns = []string{"CompanyName", "ElevationType", "ElevationCount"}

// Collector polls the EpmAggregationReportByPublisher export report through the
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
// bounded gauge, and emits one twin per publisher row. Export failures are logged
// and swallowed, never surfaced to the scheduler.
func (c *Collector) Collect(ctx context.Context, e telemetry.Emitter) error {
	// This collector names its own transport (#141): exportjob never calls LogEvent.
	e = telemetry.WithTransport(e, telemetry.TransportReportExport)

	if c.export == nil {
		c.logger.Info("epmelevationsbypublisher: no export runner configured; skipping", "collector", collectorName)
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

	// Sum the per-publisher ElevationCount into a bounded gauge by elevation type.
	// A type that appears with zero parseable counts still emits a 0 point, so the
	// series is visible even in a quiet window.
	sums := map[string]float64{}
	for _, row := range rows {
		et := row["ElevationType"]
		if _, seen := sums[et]; !seen {
			sums[et] = 0
		}
		if n, perr := strconv.ParseFloat(row["ElevationCount"], 64); perr == nil {
			sums[et] += n
		}
		e.LogEvent(publisherLogEvent(row))
	}

	points := make([]telemetry.GaugePoint, 0, len(sums))
	for et, v := range sums {
		points = append(points, telemetry.GaugePoint{
			Value: v,
			Attrs: telemetry.Attrs{semconv.AttrElevationType: et},
		})
	}
	e.GaugeSnapshot(metricName, "{elevation}", "Intune Endpoint Privilege Management elevation count by elevation type (managed vs unmanaged), summed across publishers; per-publisher detail on the intune.epm_elevations_by_publisher log twin.", points)

	return nil
}

// publisherLogEvent builds the per-publisher twin. The event timestamp is left
// unset: this is an aggregate snapshot re-emitted each poll, so there is no
// per-row event time. Severity escalates to WARN for an unmanaged elevation (a
// user elevating outside any EPM policy — the security signal).
func publisherLogEvent(row exportjob.Row) telemetry.Event {
	attrs := telemetry.Attrs{}
	telemetry.SetStr(attrs, semconv.AttrCompanyName, row["CompanyName"])
	telemetry.SetStr(attrs, semconv.AttrElevationType, row["ElevationType"])
	telemetry.SetStr(attrs, semconv.AttrElevationCount, row["ElevationCount"])

	severity := telemetry.SeverityInfo
	if row["ElevationType"] == unmanagedElevation {
		severity = telemetry.SeverityWarn
	}

	return telemetry.Event{
		Name:     eventName,
		Body:     "Intune EPM elevations by publisher",
		Severity: severity,
		Attrs:    attrs,
	}
}

func logExportFailure(logger *slog.Logger, err error) {
	switch {
	case errors.Is(err, exportjob.ErrJobFailed):
		logger.Warn("epmelevationsbypublisher: export job failed", "collector", collectorName, "report_name", reportName, "error", err)
	case errors.Is(err, exportjob.ErrSASExpired):
		logger.Warn("epmelevationsbypublisher: export SAS url expired before download", "collector", collectorName, "report_name", reportName, "error", err)
	case strings.Contains(err.Error(), "status 403"):
		logger.Info("epmelevationsbypublisher: export job creation forbidden (missing write scope?); skipping", "collector", collectorName, "report_name", reportName, "error", err)
	default:
		logger.Warn("epmelevationsbypublisher: export failed", "collector", collectorName, "report_name", reportName, "error", err)
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
