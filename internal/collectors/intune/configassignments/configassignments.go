// Package configassignments is the Intune configuration-policy assignment-status
// collector (BETA): for every device x configuration-policy assignment, what
// state did the assignment land in (Succeeded / Pending / Error / Conflict /
// Noncompliant / NotApplicable), across the whole fleet at once.
//
// Like the other fleet-wide Intune report collectors it is built entirely on the
// reports export-job subsystem (internal/exportjob, #17): the per-device
// assignment detail is only available fleet-wide through an async export, not a
// synchronous entity walk. The report requested is
// DeviceAssignmentStatusByConfigurationPolicy, which returns one row per
// (device, policy) assignment.
//
// Cardinality (mirrors appinstallreport's #83 guard): device, policy, and UPN
// are NEVER metric labels — each row is one device x policy pair, so a series
// keyed by any of them grows with fleet x policy count. The metric therefore
// counts rows into the bounded (report_status x policy_platform) enum space
// (both fixed by Microsoft's schema), and every row's per-entity identity is
// emitted as an intune.config_assignment_status log twin instead. A LogQL
// `count by` over the twin answers "which device/policy" off data already
// shipped, for free — the label would buy nothing and cost active series.
//
// The gauge dimensions are taken VERBATIM from the non-localized enum columns
// ReportStatus and UnifiedPolicyPlatformType — never their _loc siblings. The
// _loc columns are localized (a request-header artifact), so feeding one into a
// metric label would split a single bucket into two series as a function of
// Accept-Language; the canonical columns are stable across locale. This is the
// same lesson #142 established for appinstallreport's platform code.
package configassignments

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

// collectorName is the stable key used for config (enable/interval),
// self-observability, and the admin status page.
const collectorName = "intune.config_assignment_status"

// metricName is the bounded report_status x policy_platform gauge this collector
// emits. It counts device x policy assignment ROWS bucketed into Microsoft's
// enum space — see the package doc's cardinality note for why per-entity detail
// lives on the log twin instead.
const metricName = "intune.config_assignment_status.assignments"

// eventName is the OTLP LogRecord EventName every per-row twin carries.
const eventName = "intune.config_assignment_status"

// reportName is the export report catalog name this collector requests: one row
// per (device, configuration-policy) assignment.
const reportName = "DeviceAssignmentStatusByConfigurationPolicy"

// The columns this collector consumes are PolicyId, PolicyName, IntuneDeviceId,
// DeviceName, AadDeviceId, UPN, AssignmentStatus, PspdpuLastModifiedTimeUtc,
// UnifiedPolicyPlatformType(+_loc), UnifiedPolicyType(+_loc), ReportStatus(+_loc):
// the non-localized enums feed the bounded metric labels, the _loc friendlies feed
// the log twin. They are NOT pinned via an explicit `select`: this report 400s when
// a localized `_loc` column is named in select (wire-verified 2026-07-20, #203), and
// those columns exist only in the report's default output. So the export omits
// `select` and takes the default columns (a superset); each column is read by name
// and a missing one degrades to empty rather than failing.

// warnStatuses are the ReportStatus values that escalate a row's log twin to
// WARN: an assignment that errored, conflicts, or left the device noncompliant
// is worth an operator's attention; a clean assignment is not. Keyed on the
// canonical non-localized ReportStatus (live-measured 2026-07-19), never the
// localized _loc sibling.
var warnStatuses = map[string]bool{
	"Error":        true,
	"Conflict":     true,
	"Noncompliant": true,
}

// Collector polls the DeviceAssignmentStatusByConfigurationPolicy export report
// through the shared export-job subsystem (internal/exportjob, #17).
type Collector struct {
	export exportjob.Runner
	logger *slog.Logger
}

// New builds the config-assignment-status collector. export is typically the
// per-tenant *exportjob.Client the composition root builds
// (collectors.Deps.Export); a nil export is handled gracefully by Collect
// (skip-and-log), so a tenant that hasn't wired the export subsystem yet doesn't
// crash the scheduler. A nil logger falls back to the slog default.
func New(export exportjob.Runner, logger *slog.Logger) *Collector {
	if logger == nil {
		logger = slog.Default()
	}
	return &Collector{export: export, logger: logger}
}

// Name implements collector.SnapshotCollector.
func (c *Collector) Name() string { return collectorName }

// IngestTransport reports the transport this collector ingests over — the same
// telemetry.Transport Collect stamps onto every record via
// telemetry.WithTransport (#141), so the admin status page and the log records
// agree by construction.
func (c *Collector) IngestTransport() telemetry.Transport { return telemetry.TransportReportExport }

// DefaultInterval implements collector.SnapshotCollector. Export jobs are
// expensive (create + poll + download, sharing the 48-req/min-per-app export
// budget with every other export-based collector on this tenant), so this
// defaults to a much longer cadence than a plain paged fetch.
func (c *Collector) DefaultInterval() time.Duration { return 6 * time.Hour }

// Experimental marks this as a beta, opt-in collector: it depends on the
// export-job subsystem creating a job under a write-level Graph scope (see
// RequiredPermissions).
func (c *Collector) Experimental() bool { return true }

// RequiredPermissions declares the least-privilege Graph application scope.
// Creating an export job requires DeviceManagementManagedDevices.ReadWrite.All
// even though this collector only ever reads the result back — Microsoft
// requires a write-level scope just to POST the export-job creation request
// (the project's export-scope gotcha); this is the one exception to read-only
// scoping the export subsystem forces on every consumer, not a request for more.
func (c *Collector) RequiredPermissions() []string {
	return []string{"DeviceManagementManagedDevices.ReadWrite.All"}
}

// seriesKey is the aggregation key for the assignment-count gauge: the complete
// set of dimensions. Both are bounded by Microsoft's report schema (the
// ReportStatus enum x the policy-platform enum), never by fleet or policy count,
// which is the whole point of aggregating here rather than emitting per row.
type seriesKey struct {
	reportStatus string
	platform     string
}

// Collect runs the DeviceAssignmentStatusByConfigurationPolicy export job,
// counts its per-assignment rows into the bounded report_status x policy_platform
// gauge, and emits one log twin per row carrying the per-entity detail. Any
// export failure is logged and swallowed rather than treated as a
// scheduler-visible error — see logExportFailure and the exportjob sentinels.
func (c *Collector) Collect(ctx context.Context, e telemetry.Emitter) error {
	// This collector names its own transport because no engine can (#141):
	// internal/exportjob creates/polls/downloads the job and hands rows back
	// without ever calling LogEvent, so there is no engine seam to stamp from.
	// Left unstamped, the Scheduler's "graph" baseline would be the only stamp
	// these rows got — a confident lie about a transport that is not Graph polling.
	e = telemetry.WithTransport(e, telemetry.TransportReportExport)

	if c.export == nil {
		c.logger.Info("configassignments: no export runner configured; skipping", "collector", collectorName)
		return nil
	}

	rows, err := c.export.Export(ctx, exportjob.Request{
		ReportName: reportName,
		// Select omitted on purpose — see the selectColumns note above (#203).
		Format: exportjob.FormatCSV,
	}, e)
	if err != nil {
		logExportFailure(c.logger, err)
		return nil
	}

	counts := map[seriesKey]float64{}
	for _, row := range rows {
		counts[seriesKey{
			reportStatus: row["ReportStatus"],
			platform:     row["UnifiedPolicyPlatformType"],
		}]++

		e.LogEvent(rowLogEvent(row))
	}

	points := make([]telemetry.GaugePoint, 0, len(counts))
	for k, v := range counts {
		points = append(points, telemetry.GaugePoint{
			Value: v,
			Attrs: telemetry.Attrs{
				semconv.AttrReportStatus:   k.reportStatus,
				semconv.AttrPolicyPlatform: k.platform,
			},
		})
	}
	e.GaugeSnapshot(metricName, "{assignment}",
		"Intune configuration-policy assignments counted by report status and policy platform. Each device x policy assignment row is bucketed into Microsoft's ReportStatus x UnifiedPolicyPlatformType enum space (both bounded); the per-row detail — which device, which policy, which user — is on the intune.config_assignment_status log twin, never a metric label.",
		points)

	return nil
}

// rowLogEvent builds the per-assignment intune.config_assignment_status log
// event for one export row. The device/policy/user identity dropped from the
// metric lives here as structured attributes (#83/#112). policy_type carries the
// friendly localized UnifiedPolicyType_loc, while report_status and
// policy_platform carry the same canonical non-localized values the metric uses.
//
// Severity escalates to WARN for an Error/Conflict/Noncompliant assignment; a
// clean assignment stays INFO.
func rowLogEvent(row exportjob.Row) telemetry.Event {
	attrs := telemetry.Attrs{}
	telemetry.SetStr(attrs, semconv.AttrDeviceName, row["DeviceName"])
	telemetry.SetStr(attrs, semconv.AttrDeviceId, row["IntuneDeviceId"])
	telemetry.SetStr(attrs, semconv.AttrUpn, row["UPN"])
	telemetry.SetStr(attrs, semconv.AttrPolicyName, row["PolicyName"])
	telemetry.SetStr(attrs, semconv.AttrPolicyId, row["PolicyId"])
	telemetry.SetStr(attrs, semconv.AttrReportStatus, row["ReportStatus"])
	telemetry.SetStr(attrs, semconv.AttrAssignmentStatusCode, row["AssignmentStatus"])
	telemetry.SetStr(attrs, semconv.AttrPolicyType, row["UnifiedPolicyType_loc"])
	telemetry.SetStr(attrs, semconv.AttrPolicyPlatform, row["UnifiedPolicyPlatformType"])

	severity := telemetry.SeverityInfo
	if warnStatuses[row["ReportStatus"]] {
		severity = telemetry.SeverityWarn
	}

	return telemetry.Event{
		Name:     eventName,
		Body:     "Intune config policy assignment status",
		Severity: severity,
		Attrs:    attrs,
	}
}

// logExportFailure logs an Export failure at a level matching its cause: a
// missing write scope or a failed/expired job are expected tenant-side
// conditions (Warn/Info); anything else is also just logged, never escalated to
// a returned error — see the package doc.
func logExportFailure(logger *slog.Logger, err error) {
	switch {
	case errors.Is(err, exportjob.ErrJobFailed):
		logger.Warn("configassignments: export job failed", "collector", collectorName, "report_name", reportName, "error", err)
	case errors.Is(err, exportjob.ErrSASExpired):
		logger.Warn("configassignments: export SAS url expired before download", "collector", collectorName, "report_name", reportName, "error", err)
	case strings.Contains(err.Error(), "status 403"):
		logger.Info("configassignments: export job creation forbidden (missing write scope?); skipping", "collector", collectorName, "report_name", reportName, "error", err)
	default:
		logger.Warn("configassignments: export failed", "collector", collectorName, "report_name", reportName, "error", err)
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
