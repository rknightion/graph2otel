// Package configprofiledevicestatus is the Intune configuration-profile
// per-device deployment-status collector (BETA): for every device x
// configuration-profile assignment, what deployment state did it land in
// (Succeeded / Error / Conflict / Noncompliant / …), across the whole fleet
// at once.
//
// Like the other fleet-wide Intune report collectors it is built entirely on
// the reports export-job subsystem (internal/exportjob, #17): the per-device
// detail is only available fleet-wide through an async export, not a
// synchronous entity walk. The report requested is
// DeviceStatusesByConfigurationProfile, which returns one row per
// (device, configuration-profile) pair.
//
// Cardinality (mirrors configassignments' #83/#112 guard): device, policy,
// and UPN are NEVER metric labels — each row is one device x profile pair,
// so a series keyed by any of them grows with fleet x profile count. The
// metric therefore counts rows into the bounded ReportStatus enum space
// (fixed by Microsoft's schema), and every row's per-entity identity is
// emitted as an intune.config_profile_device_status log twin instead.
package configprofiledevicestatus

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
const collectorName = "intune.config_profile_device_status"

// metricName is the bounded ReportStatus gauge this collector emits. It
// counts device x configuration-profile assignment ROWS bucketed into
// Microsoft's ReportStatus enum space — see the package doc's cardinality
// note for why per-entity detail lives on the log twin instead.
const metricName = "intune.config_profile_device_status.devices"

// eventName is the OTLP LogRecord EventName every per-row twin carries.
const eventName = "intune.config_profile_device_status"

// reportName is the export report catalog name this collector requests: one
// row per (device, configuration-profile) assignment.
const reportName = "DeviceStatusesByConfigurationProfile"

// Select is deliberately OMITTED from the export request below. This report
// 400s when a localized _loc column is named in select (live-verified
// 2026-07-20, #203, same trap documented on configassignments) — so this
// collector takes the report's default columns rather than pinning a select
// list.

// warnStatuses are the ReportStatus values that escalate a row's log twin to
// WARN: a device whose profile deployment errored, conflicts, or left it
// noncompliant is worth an operator's attention; a clean deployment is not.
// Keyed on the canonical ReportStatus column, mirroring configassignments.
var warnStatuses = map[string]bool{
	"Error":        true,
	"Conflict":     true,
	"Noncompliant": true,
}

// Collector polls the DeviceStatusesByConfigurationProfile export report
// through the shared export-job subsystem (internal/exportjob, #17).
type Collector struct {
	export exportjob.Runner
	logger *slog.Logger
}

// New builds the config-profile-device-status collector. A nil export or
// logger is handled gracefully.
func New(export exportjob.Runner, logger *slog.Logger) *Collector {
	if logger == nil {
		logger = slog.Default()
	}
	return &Collector{export: export, logger: logger}
}

// Name implements collector.SnapshotCollector.
func (c *Collector) Name() string { return collectorName }

// IngestTransport reports the transport this collector ingests over — the
// same telemetry.Transport Collect stamps onto every record via
// telemetry.WithTransport (#141).
func (c *Collector) IngestTransport() telemetry.Transport { return telemetry.TransportReportExport }

// DefaultInterval implements collector.SnapshotCollector. Export jobs are
// expensive (create + poll + download, sharing the export budget with every
// other export-based collector on this tenant), so this defaults to a much
// longer cadence than a plain paged fetch.
func (c *Collector) DefaultInterval() time.Duration { return 6 * time.Hour }

// Experimental marks this as a beta, opt-in collector: it depends on the
// export-job subsystem creating a job under a write-level Graph scope (see
// RequiredPermissions).
func (c *Collector) Experimental() bool { return true }

// RequiredPermissions declares the least-privilege Graph application scope.
// Creating an export job requires DeviceManagementManagedDevices.ReadWrite.All
// even though this collector only ever reads the result back — the
// project's export-scope gotcha.
func (c *Collector) RequiredPermissions() []string {
	return []string{"DeviceManagementManagedDevices.ReadWrite.All"}
}

// Collect runs the DeviceStatusesByConfigurationProfile export job, counts
// its per-device rows into the bounded report_status gauge, and emits one
// log twin per row carrying the per-entity detail. Any export failure is
// logged and swallowed rather than treated as a scheduler-visible error —
// see logExportFailure and the exportjob sentinels.
func (c *Collector) Collect(ctx context.Context, e telemetry.Emitter) error {
	// This collector names its own transport because no engine can (#141):
	// internal/exportjob creates/polls/downloads the job and hands rows back
	// without ever calling LogEvent, so there is no engine seam to stamp from.
	e = telemetry.WithTransport(e, telemetry.TransportReportExport)

	if c.export == nil {
		c.logger.Info("configprofiledevicestatus: no export runner configured; skipping", "collector", collectorName)
		return nil
	}

	rows, err := c.export.Export(ctx, exportjob.Request{
		ReportName: reportName,
		// Select omitted on purpose — see the package doc note above (#203).
		Format: exportjob.FormatCSV,
	}, e)
	if err != nil {
		logExportFailure(c.logger, err)
		return nil
	}

	counts := map[string]float64{}
	for _, row := range rows {
		counts[row["ReportStatus"]]++
		e.LogEvent(deviceLogEvent(row))
	}

	points := make([]telemetry.GaugePoint, 0, len(counts))
	for status, v := range counts {
		points = append(points, telemetry.GaugePoint{
			Value: v,
			Attrs: telemetry.Attrs{semconv.AttrReportStatus: status},
		})
	}
	e.GaugeSnapshot(metricName, "{device}",
		"Intune configuration-profile device deployment status counted by report status. Each device x profile assignment row is bucketed into Microsoft's ReportStatus enum space (bounded); the per-row detail — which device, which policy, which user — is on the intune.config_profile_device_status log twin, never a metric label.",
		points)

	return nil
}

// deviceLogEvent builds the per-(device, profile) intune.config_profile_device_status
// twin. The event timestamp is left unset: this is a state snapshot
// re-emitted each poll, like the sibling export collectors, and the report
// carries no per-row timestamp. Severity escalates to WARN for an
// Error/Conflict/Noncompliant row; a clean row stays INFO. policy_status
// carries Microsoft's raw numeric code verbatim, undecoded.
func deviceLogEvent(row exportjob.Row) telemetry.Event {
	attrs := telemetry.Attrs{}
	telemetry.SetStr(attrs, semconv.AttrPolicyId, row["PolicyId"])
	telemetry.SetStr(attrs, semconv.AttrPolicyName, row["PolicyName"])
	telemetry.SetStr(attrs, semconv.AttrDeviceId, row["IntuneDeviceId"])
	telemetry.SetStr(attrs, semconv.AttrDeviceName, row["DeviceName"])
	telemetry.SetStr(attrs, semconv.AttrUpn, row["UPN"])
	telemetry.SetStr(attrs, semconv.AttrReportStatus, row["ReportStatus"])
	telemetry.SetStr(attrs, semconv.AttrPolicyStatus, row["PolicyStatus"])
	telemetry.SetStr(attrs, semconv.AttrUnifiedPolicyType, row["UnifiedPolicyType"])

	severity := telemetry.SeverityInfo
	if warnStatuses[row["ReportStatus"]] {
		severity = telemetry.SeverityWarn
	}

	return telemetry.Event{
		Name:     eventName,
		Body:     "Intune configuration profile device status",
		Severity: severity,
		Attrs:    attrs,
	}
}

// logExportFailure logs an Export failure at a level matching its cause: a
// missing write scope or a failed/expired job are expected tenant-side
// conditions (Warn/Info); anything else is also just logged, never
// escalated to a returned error — see the package doc.
func logExportFailure(logger *slog.Logger, err error) {
	switch {
	case errors.Is(err, exportjob.ErrJobFailed):
		logger.Warn("configprofiledevicestatus: export job failed", "collector", collectorName, "report_name", reportName, "error", err)
	case errors.Is(err, exportjob.ErrSASExpired):
		logger.Warn("configprofiledevicestatus: export SAS url expired before download", "collector", collectorName, "report_name", reportName, "error", err)
	case strings.Contains(err.Error(), "status 403"):
		logger.Info("configprofiledevicestatus: export job creation forbidden (missing write scope?); skipping", "collector", collectorName, "report_name", reportName, "error", err)
	default:
		logger.Warn("configprofiledevicestatus: export failed", "collector", collectorName, "report_name", reportName, "error", err)
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
