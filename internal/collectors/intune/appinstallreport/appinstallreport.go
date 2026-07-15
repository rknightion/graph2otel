// Package appinstallreport is the Intune per-app device install status
// collector (BETA, M5 #37): how many devices installed a given managed app,
// broken down by install state, at fleet scale.
//
// The synchronous navigation properties Microsoft once exposed for this
// (`mobileApps/{id}/deviceStatuses` / `userStatuses` / `installSummary`) are
// beta, were deprecated in May 2023, and are reportedly broken
// ("BadRequest, Resource not found") on live tenants — the reports export API
// (internal/exportjob, #17) is the only working path, so this collector is
// built entirely on top of it rather than treating export as a fallback.
//
// Report choice (LIVE-VERIFIED 2026-07-15): the per-device report
// DeviceInstallStatusByApp cannot be used fleet-wide — Graph returns
// HTTP 400 "required filters are not set, restriction filter needed" without
// a per-app ApplicationId filter, so pulling it across every app would mean a
// per-app export-job fan-out (against a 48-req/min-per-app export budget).
// This collector instead requests AppInstallStatusAggregate, which has no
// required filter and returns one pre-aggregated row per app with the five
// device-count columns this collector's metric is built from directly. The
// per-device detail (install-state-detail, error code, device identity) that
// only DeviceInstallStatusByApp carries is therefore NOT available from this
// collector in v1 — deliberately deferred rather than built as a per-app
// fan-out; see the tracking issue for a possible follow-up.
package appinstallreport

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
	"github.com/rknightion/graph2otel/internal/telemetry"
)

// collectorName is the stable key used for config (enable/interval),
// self-observability, and the admin status page.
const collectorName = "intune.app_install_status"

// deviceInstallStatusMetricName is the bounded per-app/install-state device
// count gauge this collector emits.
const deviceInstallStatusMetricName = "intune.app_install_status.devices"

// reportName is the export report catalog name this collector requests.
// LIVE-VERIFIED 2026-07-15: DeviceInstallStatusByApp 400s fleet-wide (needs a
// per-app ApplicationId filter); AppInstallStatusAggregate has no required
// filter — see the package doc.
const reportName = "AppInstallStatusAggregate"

// selectColumns are the export columns this collector requests, per
// Microsoft's available-reports reference for AppInstallStatusAggregate.
// Select is required and non-empty: Microsoft warns the default column set
// can change without notice, so every export caller must pin its own columns
// explicitly (see internal/exportjob).
var selectColumns = []string{
	"DisplayName",
	"ApplicationId",
	"Platform",
	"Publisher",
	"InstalledDeviceCount",
	"FailedDeviceCount",
	"NotApplicableDeviceCount",
	"NotInstalledDeviceCount",
	"PendingInstallDeviceCount",
}

// installStateColumns maps each of AppInstallStatusAggregate's five
// device-count columns to the bounded install_state label value the
// corresponding gauge point carries. Fixed by Microsoft's report schema, not
// tenant-driven, so this can never grow with fleet or app-catalog size.
var installStateColumns = []struct {
	column string
	state  string
}{
	{"InstalledDeviceCount", "installed"},
	{"FailedDeviceCount", "failed"},
	{"NotApplicableDeviceCount", "not_applicable"},
	{"NotInstalledDeviceCount", "not_installed"},
	{"PendingInstallDeviceCount", "pending"},
}

// Collector polls the AppInstallStatusAggregate export report through the
// shared export-job subsystem (internal/exportjob, #17).
type Collector struct {
	export exportjob.Runner
	logger *slog.Logger
}

// New builds the app-install-status collector. export is typically the
// per-tenant *exportjob.Client the composition root builds
// (collectors.Deps.Export); a nil export is handled gracefully by Collect
// (skip-and-log), so a tenant that hasn't wired the export subsystem yet
// doesn't crash the scheduler. A nil logger falls back to the slog default.
func New(export exportjob.Runner, logger *slog.Logger) *Collector {
	if logger == nil {
		logger = slog.Default()
	}
	return &Collector{export: export, logger: logger}
}

// Name implements collector.SnapshotCollector.
func (c *Collector) Name() string { return collectorName }

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
// (see the project's export-scope gotcha); this is the one exception to
// least-privileged read-only scoping the export subsystem forces on every
// consumer, not a request for more than that.
func (c *Collector) RequiredPermissions() []string {
	return []string{"DeviceManagementManagedDevices.ReadWrite.All"}
}

// Collect runs the AppInstallStatusAggregate export job and emits one bounded
// gauge point per (app, install state, platform) from its pre-aggregated
// device-count columns. Any export failure (missing write scope, a job that
// reports failed, or a SAS url that expired before download) is logged and
// swallowed rather than treated as a scheduler-visible error — see the
// package doc and the exportjob seam's sentinel errors.
func (c *Collector) Collect(ctx context.Context, e telemetry.Emitter) error {
	if c.export == nil {
		c.logger.Info("appinstallreport: no export runner configured; skipping", "collector", collectorName)
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

	points := make([]telemetry.GaugePoint, 0, len(rows)*len(installStateColumns))
	for _, row := range rows {
		appName := row["DisplayName"]
		if appName == "" {
			appName = "unknown"
		}
		platform := row["Platform"]
		if platform == "" {
			platform = "unknown"
		}

		for _, isc := range installStateColumns {
			points = append(points, telemetry.GaugePoint{
				Value: c.parseCount(row[isc.column], appName, isc.column),
				Attrs: telemetry.Attrs{"app_name": appName, "install_state": isc.state, "platform": platform},
			})
		}
	}
	e.GaugeSnapshot(deviceInstallStatusMetricName, "{device}", "Intune managed devices by per-app install state, from the AppInstallStatusAggregate export report.", points)

	return nil
}

// parseCount parses one device-count column's string value. An empty value
// (column absent from this row) is silently 0; a non-empty but unparsable
// value is logged and treated as 0 rather than dropping the whole app's
// gauge points.
func (c *Collector) parseCount(raw, appName, column string) float64 {
	if raw == "" {
		return 0
	}
	v, err := strconv.ParseFloat(raw, 64)
	if err != nil {
		c.logger.Warn("appinstallreport: unparsable device count; treating as 0", "collector", collectorName, "app_name", appName, "column", column, "value", raw, "error", err)
		return 0
	}
	return v
}

// logExportFailure logs an Export failure at a level matching its cause:
// a missing write scope or a failed/expired job are expected, tenant-side
// conditions worth an operator's attention (Warn); anything else (transport
// failure, malformed response) is also just logged, never escalated to a
// returned error - see the package doc.
func logExportFailure(logger *slog.Logger, err error) {
	switch {
	case errors.Is(err, exportjob.ErrJobFailed):
		logger.Warn("appinstallreport: export job failed", "collector", collectorName, "report_name", reportName, "error", err)
	case errors.Is(err, exportjob.ErrSASExpired):
		logger.Warn("appinstallreport: export SAS url expired before download", "collector", collectorName, "report_name", reportName, "error", err)
	case strings.Contains(err.Error(), "status 403"):
		logger.Info("appinstallreport: export job creation forbidden (missing write scope?); skipping", "collector", collectorName, "report_name", reportName, "error", err)
	default:
		logger.Warn("appinstallreport: export failed", "collector", collectorName, "report_name", reportName, "error", err)
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
