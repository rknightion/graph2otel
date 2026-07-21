// Package epmelevationsbyuser is the per-USER attribution cut of Intune Endpoint
// Privilege Management elevations (BETA): which users elevated, how often, and how
// much of that was governed by an EPM policy. It is a sibling of
// intune.epm_elevations (the per-application cut,
// EpmAggregationReportByApplication) reading the same EPM data through the same
// reports-export engine, and answers the question that one cannot — WHO is
// self-elevating outside policy.
//
// The source is the EpmAggregationReportByUser export report (live-verified
// 2026-07-21 on m7kni, probed as graph2otel-poller). It is already an aggregate:
// one row per user with ManagedCount / UnmanagedCount / TotalCount, so there is no
// per-elevation row here — the per-event stream is intune.epm_elevation_events.
// The report accepts an explicit `select` naming exactly the four columns below
// (live-confirmed), and none of them is a localized `_loc` column, so the #203
// "explicit select 400s" trap does not apply and the columns are pinned.
//
// The Upn column is NOT always a real UPN: one live row carried the down-level
// logon name `AzureAD\RobKnight`. It is emitted VERBATIM — nothing here parses,
// normalises or validates it, because a value the wire disagrees with the name of
// is still the value the analyst has to search for.
//
// Cardinality (#83/#112): the user identity is unbounded (it grows with tenant
// user count) and never becomes a metric label. The gauge is keyed only by
// elevation_governance — exactly two series, managed and unmanaged, ALWAYS
// both, even at zero, so an alert on them has something to evaluate in a quiet
// window — with each user's own row on the intune.epm_elevations_by_user log twin.
// Guard test.
package epmelevationsbyuser

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
	collectorName = "intune.epm_elevations_by_user"
	metricName    = "intune.epm_elevations_by_user.count"
	eventName     = "intune.epm_elevations_by_user"
	reportName    = "EpmAggregationReportByUser"
)

// selectColumns pins the export columns (Microsoft's default set can change).
// Live-confirmed accepted as an explicit select 2026-07-21.
var selectColumns = []string{"ManagedCount", "UnmanagedCount", "TotalCount", "Upn"}

// Collector polls the EpmAggregationReportByUser export report through the shared
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

// Collect runs the export job, sums the per-user managed/unmanaged counts into the
// two-series bounded gauge, and emits one twin per user row. Export failures are
// logged and swallowed, never surfaced to the scheduler.
func (c *Collector) Collect(ctx context.Context, e telemetry.Emitter) error {
	// This collector names its own transport (#141): exportjob never calls LogEvent.
	e = telemetry.WithTransport(e, telemetry.TransportReportExport)

	if c.export == nil {
		c.logger.Info("epmelevationsbyuser: no export runner configured; skipping", "collector", collectorName)
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

	// Both series are seeded at zero before the walk, so a tenant with no
	// elevations this window still reports 0 rather than dropping the series.
	var managed, unmanaged float64
	for _, row := range rows {
		managed += count(row["ManagedCount"])
		unmanaged += count(row["UnmanagedCount"])
		e.LogEvent(userLogEvent(row))
	}

	e.GaugeSnapshot(metricName, "{elevation}", "Intune Endpoint Privilege Management elevation count by governance (policy-managed vs unmanaged), summed across users; per-user detail on the intune.epm_elevations_by_user log twin.", []telemetry.GaugePoint{
		{Value: managed, Attrs: telemetry.Attrs{semconv.AttrElevationGovernance: semconv.ElevationGovernanceManaged}},
		{Value: unmanaged, Attrs: telemetry.Attrs{semconv.AttrElevationGovernance: semconv.ElevationGovernanceUnmanaged}},
	})

	return nil
}

// count parses one export count column, treating anything unparseable as zero —
// a malformed cell must not drop the rest of the tenant's total.
func count(s string) float64 {
	n, err := strconv.ParseFloat(s, 64)
	if err != nil {
		return 0
	}
	return n
}

// userLogEvent builds the per-user twin. The event timestamp is left unset: this
// is an aggregate snapshot re-emitted each poll, so there is no per-row event
// time. Severity escalates to WARN when the user has ANY unmanaged elevation —
// self-elevation outside every EPM policy is the security signal.
func userLogEvent(row exportjob.Row) telemetry.Event {
	attrs := telemetry.Attrs{}
	// Verbatim: the column is not always a real UPN (a live row carried
	// `AzureAD\RobKnight`), and rewriting it would hide what is actually on the wire.
	telemetry.SetStr(attrs, semconv.AttrUpn, row["Upn"])
	telemetry.SetStr(attrs, semconv.AttrManagedCount, row["ManagedCount"])
	telemetry.SetStr(attrs, semconv.AttrUnmanagedCount, row["UnmanagedCount"])
	telemetry.SetStr(attrs, semconv.AttrTotalCount, row["TotalCount"])

	severity := telemetry.SeverityInfo
	if count(row["UnmanagedCount"]) > 0 {
		severity = telemetry.SeverityWarn
	}

	return telemetry.Event{
		Name:     eventName,
		Body:     "Intune EPM elevations by user",
		Severity: severity,
		Attrs:    attrs,
	}
}

func logExportFailure(logger *slog.Logger, err error) {
	switch {
	case errors.Is(err, exportjob.ErrJobFailed):
		logger.Warn("epmelevationsbyuser: export job failed", "collector", collectorName, "report_name", reportName, "error", err)
	case errors.Is(err, exportjob.ErrSASExpired):
		logger.Warn("epmelevationsbyuser: export SAS url expired before download", "collector", collectorName, "report_name", reportName, "error", err)
	case strings.Contains(err.Error(), "status 403"):
		logger.Info("epmelevationsbyuser: export job creation forbidden (missing write scope?); skipping", "collector", collectorName, "report_name", reportName, "error", err)
	default:
		logger.Warn("epmelevationsbyuser: export failed", "collector", collectorName, "report_name", reportName, "error", err)
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
