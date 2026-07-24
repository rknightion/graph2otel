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
// device-count columns this collector's metric is built from directly.
//
// Cardinality (#83, live-verified): app_name is NOT a metric label, and must
// never become one again — there is a guard test. AppInstallStatusAggregate
// returns a row for every app in the tenant's Intune CATALOG, not just the
// admin-deployed ones, so app_name is unbounded in the sense that matters: it
// scales with the catalog, not with the fleet. On the 6-device m7kni lab
// tenant it took 341 distinct values, and 341 apps x 5 install states x 4
// platforms produced 1,870 active series from this one collector — a real
// enterprise catalog would produce tens of thousands. The metric therefore
// sums the per-app counts into install_state x platform (both fixed by
// Microsoft's schema: five columns x the platform enum, ~20 series regardless
// of tenant size), and every app's own row is emitted as an
// intune.app_install_status log event instead. Capping app_name to a top-N
// allow-list was considered and rejected: the log twin is obligatory either
// way (see below), and once the per-app detail is in the logs a LogQL
// `count by (app_name)` answers the same question off data already shipped,
// so the label buys nothing.
//
// The summed gauge counts app INSTALLATIONS, not distinct devices — a device
// running ten apps contributes to ten rows — which is why the metric is named
// intune.app_install_status.installations with unit {installation} rather than
// the ".devices"/{device} it carried before #83. That name was inherited from
// the pre-#83 shape, where each point WAS one app's device count and the name
// was accurate; summing across apps made it a lie. Distinct devices are not
// obtainable here at any name: the report has no device rows to deduplicate
// (see below). Do not "restore" the old name. The per-app numbers on the log
// twin are the exact export values.
//
// The log twin is per-APP, not per-device: AppInstallStatusAggregate carries
// no device rows at all. The per-device detail (install-state-detail, error
// code, device identity) that only DeviceInstallStatusByApp carries is
// therefore NOT available from this collector — an absent data shape in the
// only report that works fleet-wide, not a deferred log twin. Building it
// would mean a per-app export-job fan-out against the 48-req/min-per-app
// export budget; see the tracking issue for a possible follow-up.
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
	"github.com/rknightion/graph2otel/internal/semconv"
	"github.com/rknightion/graph2otel/internal/telemetry"
	"github.com/rknightion/graph2otel/internal/wirecheck"
)

// collectorName is the stable key used for config (enable/interval),
// self-observability, and the admin status page.
const collectorName = "intune.app_install_status"

// installationsMetricName is the bounded install-state/platform gauge this
// collector emits. It counts app INSTALLATIONS, not distinct devices — see the
// package doc's cardinality note for why distinct devices are not obtainable
// from this report, and why the name must not drift back to ".devices".
const installationsMetricName = "intune.app_install_status.installations"

// eventName is the OTLP LogRecord EventName every per-app row carries. The
// per-app detail lives here rather than on the metric — see the package doc's
// cardinality note (#83).
const eventName = "intune.app_install_status"

// platformUnknown is the bounded label value a Platform code outside
// platformNames buckets to.
const platformUnknown = "unknown"

// platformNames decodes the AppInstallStatusAggregate Platform column's raw
// numeric code to this project's stable label value.
//
// LIVE-MEASURED 2026-07-17 (#142, probed as graph2otel-poller): across 371
// rows the column returned exactly '1','2','3','5', paired by Microsoft's own
// Platform_loc sibling with Android, iOS, MacOS, Windows respectively. Note 2
// is iOS and 5 is Windows — the codes are not in any order worth guessing, and
// 4 is not emitted by this tenant at all.
//
// Keyed on the CODE rather than the Platform_loc string on purpose, and this
// is the load-bearing decision on #142: _loc is LOCALIZED. Replaying the same
// export job under four Accept-Language values (live 2026-07-17) returned
// "MacOS" for code 3 under en/fr-FR but "macOS" under de-DE/ja-JP. A label fed
// from _loc would therefore split one platform into two series as a function
// of a request header. The numeric code is stable across every locale probed,
// so it is the only safe key for a metric label. Do not "simplify" this map
// away by reading the _loc sibling — there is a guard test.
var platformNames = map[string]string{
	"1": "android",
	"2": "ios",
	"3": "macos",
	"5": "windows",
}

// platformFor decodes a raw Platform code to its bounded label value,
// reporting whether the code was known. An unknown code buckets to
// platformUnknown rather than passing the raw code through to a label: the
// raw value stays on the log twin (see appLogEvent's platform_code), which is
// where a value the decode could not resolve belongs.
func platformFor(raw string) (string, bool) {
	if name, ok := platformNames[raw]; ok {
		return name, true
	}
	return platformUnknown, false
}

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
	watch  *wirecheck.Reporter
}

// knownPlatformCodes is the wire assumption this collector watches at runtime
// (#233/#234). platform is a METRIC LABEL fed from platformNames, which is a
// LIVE-MEASURED code table (2026-07-17, #142) and therefore a fact about one
// tenant at one moment: '4' was already known to exist and simply not be
// emitted there. The announce log below makes a decode miss diagnosable but not
// ALERTABLE — nothing counts it — so a code Microsoft starts sending moves
// installs into "unknown" and only a log reader would ever know.
//
// Derived from platformNames' own keys rather than restated, so the watched set
// is exactly the set this collector decodes.
var knownPlatformCodes = func() wirecheck.Enum {
	keys := make([]string, 0, len(platformNames))
	for k := range platformNames {
		keys = append(keys, k)
	}
	return wirecheck.NewEnum(keys...)
}()

// New builds the app-install-status collector. export is typically the
// per-tenant *exportjob.Client the composition root builds
// (collectors.Deps.Export); a nil export is handled gracefully by Collect
// (skip-and-log), so a tenant that hasn't wired the export subsystem yet
// doesn't crash the scheduler. A nil logger falls back to the slog default.
func New(export exportjob.Runner, logger *slog.Logger) *Collector {
	if logger == nil {
		logger = slog.Default()
	}
	return &Collector{export: export, logger: logger, watch: wirecheck.New(collectorName, logger)}
}

// Name implements collector.SnapshotCollector.
func (c *Collector) Name() string { return collectorName }

// IngestTransport reports the transport this collector ingests over — the same
// telemetry.Transport Collect stamps onto every record via telemetry.WithTransport
// (#141), so the admin status page (#178) and the log records agree by construction.
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
// (see the project's export-scope gotcha); this is the one exception to
// least-privileged read-only scoping the export subsystem forces on every
// consumer, not a request for more than that.
func (c *Collector) RequiredPermissions() []string {
	return []string{"DeviceManagementManagedDevices.ReadWrite.All"}
}

// seriesKey is the aggregation key for the device-count gauge: the complete
// set of dimensions that survive the #83 fix. Both are bounded by Microsoft's
// report schema (five fixed columns x the app-platform enum), never by tenant
// size — which is the whole point of aggregating here rather than emitting a
// point per app.
type seriesKey struct {
	state    string
	platform string
}

// Collect runs the AppInstallStatusAggregate export job, sums its
// pre-aggregated device-count columns across every app into the bounded
// install_state x platform gauge, and emits one log event per app row carrying
// the per-app detail. Any export failure (missing write scope, a job that
// reports failed, or a SAS url that expired before download) is logged and
// swallowed rather than treated as a scheduler-visible error — see the
// package doc and the exportjob seam's sentinel errors.
func (c *Collector) Collect(ctx context.Context, e telemetry.Emitter) error {
	// This collector names its own transport because no engine can (#141):
	// internal/exportjob creates/polls/downloads the job and hands rows back
	// without ever calling LogEvent, so there is no engine seam to stamp from.
	// Left unstamped, the Scheduler's "graph" baseline would be the only stamp
	// these rows got — a confident lie, which is the exact failure #141 exists
	// to remove. exportjob's own graph2otel.export.* self-obs metrics pass
	// through untouched: the decorator is log-only.
	e = telemetry.WithTransport(e, telemetry.TransportReportExport)

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

	counts := map[seriesKey]float64{}
	for _, row := range rows {
		platform, known := platformFor(row["Platform"])
		// Count it too (#234): the log below is diagnosable but not alertable,
		// and platform is a METRIC LABEL, so a new code moves installs into
		// "unknown" where only a log reader would see it.
		c.watch.Value(e, semconv.AttrPlatformCode, row["Platform"], knownPlatformCodes)
		// An unmapped code is a Microsoft-side enum addition, and it is
		// invisible on the metric (it buckets to "unknown" like an empty
		// column). Log it once per row so a new platform is discoverable
		// without a live probe — the _loc sibling names it on the wire, which
		// is the cheapest way to learn what the new code means. This is the
		// lesson of #142's Defender half: an "other"/"unknown" bucket that
		// nothing ever complains about hides a total decode failure.
		if !known && row["Platform"] != "" {
			c.logger.Warn("appinstallreport: unmapped Platform code; bucketing as unknown",
				"collector", collectorName, "platform_code", row["Platform"],
				"platform_loc", row["Platform_loc"], "app_name", row["DisplayName"])
		}

		for _, isc := range installStateColumns {
			counts[seriesKey{state: isc.state, platform: platform}] += c.parseCount(row[isc.column], row["DisplayName"], isc.column)
		}

		e.LogEvent(appLogEvent(row))
	}

	points := make([]telemetry.GaugePoint, 0, len(counts))
	for k, v := range counts {
		points = append(points, telemetry.GaugePoint{
			Value: v,
			Attrs: telemetry.Attrs{semconv.AttrInstallState: k.state, semconv.AttrPlatform: k.platform},
		})
	}
	e.GaugeSnapshot(installationsMetricName, "{installation}", "Intune app installations by install state and platform, summed across every app in the AppInstallStatusAggregate export report. A device counts once per app it has, so this counts installations, not distinct devices; see the intune.app_install_status log event for per-app detail.", points)

	return nil
}

// appLogEvent builds the per-app intune.app_install_status log event for one
// AppInstallStatusAggregate row. The app's identity (name, id, publisher) and
// its five raw per-state device counts live here as structured attributes
// instead of metric labels — see the package doc's cardinality note (#83).
// Counts are carried as the export's raw column values, so a value the metric
// path could not parse (and therefore counted as 0) stays visible here rather
// than being silently normalized away.
//
// Severity escalates to WARN when any install failed: a failing app deployment
// is worth an operator's attention, a clean row is not.
func appLogEvent(row exportjob.Row) telemetry.Event {
	platform, _ := platformFor(row["Platform"])

	attrs := telemetry.Attrs{}
	telemetry.SetStr(attrs, semconv.AttrAppName, row["DisplayName"])
	telemetry.SetStr(attrs, semconv.AttrAppId, row["ApplicationId"])
	telemetry.SetStr(attrs, semconv.AttrPlatform, platform)
	// The raw code is emitted unconditionally alongside the decoded name, per
	// the house pattern (m365/activity's record_type_id, recordtypes.go): on
	// this project Microsoft's published tables have repeatedly failed to
	// cover every value the wire actually sends, so the lossless code must
	// survive a decode miss. platform above is then free to be a clean bounded
	// label without that costing the reader the ability to see what arrived.
	telemetry.SetStr(attrs, semconv.AttrPlatformCode, row["Platform"])
	telemetry.SetStr(attrs, semconv.AttrPublisher, row["Publisher"])
	telemetry.SetStr(attrs, semconv.AttrInstalledDeviceCount, row["InstalledDeviceCount"])
	telemetry.SetStr(attrs, semconv.AttrFailedDeviceCount, row["FailedDeviceCount"])
	telemetry.SetStr(attrs, semconv.AttrNotApplicableDeviceCount, row["NotApplicableDeviceCount"])
	telemetry.SetStr(attrs, semconv.AttrNotInstalledDeviceCount, row["NotInstalledDeviceCount"])
	telemetry.SetStr(attrs, semconv.AttrPendingInstallDeviceCount, row["PendingInstallDeviceCount"])

	severity := telemetry.SeverityInfo
	if v, err := strconv.ParseFloat(row["FailedDeviceCount"], 64); err == nil && v > 0 {
		severity = telemetry.SeverityWarn
	}

	return telemetry.Event{
		Name:     eventName,
		Body:     "Intune app install status",
		Severity: severity,
		Attrs:    attrs,
	}
}

// parseCount parses one device-count column's string value, contributing it to
// the aggregate. An empty value (column absent from this row) is silently 0; a
// non-empty but unparsable value is logged and treated as 0 rather than
// failing the whole aggregate. The raw value stays visible on the row's log
// twin either way (see appLogEvent).
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
