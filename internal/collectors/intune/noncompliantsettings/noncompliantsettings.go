// Package noncompliantsettings is the Intune noncompliant-devices-and-settings
// collector (BETA): for every managed device that fails a compliance policy, the
// NoncompliantDevicesAndSettings export report returns one row per failing
// setting — device identity, the setting that failed, the owning policy, and a
// status code. This report only ever returns noncompliant/error settings, so
// every row is a warning by construction.
//
// Built on the shared reports export-job subsystem (internal/exportjob, #17),
// the only fleet-wide-viable path for Intune report data — a per-device entity
// walk blows the throttling budget on a large fleet.
//
// Cardinality (#112): device / setting / user identity is per-entity and must
// never become a metric label — it grows with the fleet, not with Microsoft's
// schema. The metric therefore counts rows into a bounded os × setting_status
// gauge, and every row's own per-entity detail is emitted as an
// intune.noncompliant_setting log event. A LogQL `count by` over the twin answers
// "which device / which setting" off data already shipped.
//
// SettingStatus is a raw numeric code decoded to a bounded label via statusNames,
// which is seeded with the ONLY live-verified value (LIVE-MEASURED 2026-07-19,
// m7kni, probed as graph2otel-poller): code "4" → "not_compliant", paired by
// Microsoft's own SettingStatus_loc sibling "Not compliant". The map grows ONLY
// on live evidence — an unmapped code buckets to "unknown" and logs a Warn
// naming the raw code and its _loc sibling, so a new code is discoverable without
// a live probe (the #142 lesson: an "unknown" bucket nothing complains about
// hides a total decode failure). Do not guess other codes into the map.
package noncompliantsettings

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
const collectorName = "intune.noncompliant_settings"

// countMetricName is the bounded os × setting_status gauge this collector emits;
// each point's value is the COUNT of noncompliant device×setting rows in that
// bucket. Per-entity detail lives on the log twin, never here (#112).
const countMetricName = "intune.noncompliant_settings.count"

// eventName is the OTLP LogRecord EventName every per-row log twin carries.
const eventName = "intune.noncompliant_setting"

// reportName is the export report catalog name this collector requests.
const reportName = "NoncompliantDevicesAndSettings"

// statusUnknown is the bounded label value a SettingStatus code outside
// statusNames buckets to.
const statusUnknown = "unknown"

// statusNames decodes the NoncompliantDevicesAndSettings SettingStatus column's
// raw numeric code to this project's stable label value.
//
// LIVE-MEASURED 2026-07-19 (m7kni, probed as graph2otel-poller): every observed
// row carried SettingStatus="4", paired by Microsoft's SettingStatus_loc sibling
// "Not compliant". That is the ONLY value seen on the wire, so it is the only
// seed. Keyed on the CODE rather than the localized _loc string on purpose (the
// #142 lesson): _loc is localized and would split one status into two series as a
// function of a request header, whereas the numeric code is locale-stable. The
// map grows only on live evidence of a new code — never a guess.
var statusNames = map[string]string{
	"4": "not_compliant",
}

// decodeStatus decodes a raw SettingStatus code to its bounded label value,
// reporting whether the code was known. An unknown (or empty) code buckets to
// statusUnknown rather than passing the raw code through to a label: the raw
// value stays on the log twin (see logEvent's setting_status_code), which is
// where a value the decode could not resolve belongs.
func decodeStatus(raw string) (string, bool) {
	if name, ok := statusNames[raw]; ok {
		return name, true
	}
	return statusUnknown, false
}

// The columns this collector consumes are DeviceId, DeviceName, UPN, OS,
// OSVersion, SettingName, SettingNm, SettingNm_loc, PolicyName, SettingStatus,
// SettingStatus_loc, ErrorCode. They are NOT pinned via an explicit `select`:
// this report 400s when the localized SettingNm_loc / SettingStatus_loc columns
// are named in select (wire-verified 2026-07-20, #203), and those _loc friendlies
// exist only in the report's default output. So the export omits `select`
// entirely and takes the default columns (a superset of the above); each column
// is read by name and a missing one degrades to empty rather than failing.

// Collector polls the NoncompliantDevicesAndSettings export report through the
// shared export-job subsystem (internal/exportjob, #17).
type Collector struct {
	export exportjob.Runner
	logger *slog.Logger
}

// New builds the noncompliant-settings collector. export is typically the
// per-tenant *exportjob.Client the composition root builds
// (collectors.Deps.Export); a nil export is handled gracefully by Collect
// (skip-and-log). A nil logger falls back to the slog default.
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
func (c *Collector) IngestTransport() telemetry.Transport {
	return telemetry.TransportReportExport
}

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
// requires a write-level scope just to POST the export-job creation request (see
// the project's export-scope gotcha); this is the one exception to
// least-privileged read-only scoping the export subsystem forces on every
// consumer, not a request for more than that.
func (c *Collector) RequiredPermissions() []string {
	return []string{"DeviceManagementManagedDevices.ReadWrite.All"}
}

// seriesKey is the aggregation key for the count gauge: the complete set of
// bounded dimensions. os is the row's OS verbatim (a small closed enum);
// setting_status is the decoded status label. Neither grows with fleet size —
// which is the whole point of counting here rather than emitting a point per row.
type seriesKey struct {
	os     string
	status string
}

// Collect runs the NoncompliantDevicesAndSettings export job, counts its rows
// into the bounded os × setting_status gauge, and emits one log event per row
// carrying the per-entity detail. Any export failure is logged and swallowed
// rather than treated as a scheduler-visible error — see logExportFailure and
// the exportjob seam's sentinel errors.
func (c *Collector) Collect(ctx context.Context, e telemetry.Emitter) error {
	// This collector names its own transport because no engine can (#141):
	// internal/exportjob hands rows back without ever calling LogEvent, so there
	// is no engine seam to stamp report_export from. Left unstamped, the
	// Scheduler's "graph" baseline would be the only stamp these rows got — a
	// confident lie about a transport that is not Graph polling.
	e = telemetry.WithTransport(e, telemetry.TransportReportExport)

	if c.export == nil {
		c.logger.Info("noncompliantsettings: no export runner configured; skipping", "collector", collectorName)
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
		status, known := decodeStatus(row["SettingStatus"])
		// An unmapped, non-empty code is a Microsoft-side enum value this map
		// has not learned yet; it is invisible on the metric (buckets to
		// "unknown"). Log it once per row so a new status is discoverable
		// without a live probe — the _loc sibling names it on the wire.
		if !known && row["SettingStatus"] != "" {
			c.logger.Warn("noncompliantsettings: unmapped SettingStatus code; bucketing as unknown",
				"collector", collectorName, "setting_status_code", row["SettingStatus"],
				"setting_status_loc", row["SettingStatus_loc"], "device_name", row["DeviceName"])
		}

		counts[seriesKey{os: row["OS"], status: status}]++
		e.LogEvent(logEvent(row, status))
	}

	points := make([]telemetry.GaugePoint, 0, len(counts))
	for k, v := range counts {
		points = append(points, telemetry.GaugePoint{
			Value: v,
			Attrs: telemetry.Attrs{semconv.AttrOs: k.os, semconv.AttrSettingStatus: k.status},
		})
	}
	e.GaugeSnapshot(countMetricName, "{setting}", "Counts of noncompliant device×setting rows from the Intune NoncompliantDevicesAndSettings export report, bucketed by OS and decoded setting status; per-setting detail is on the intune.noncompliant_setting log twin.", points)

	return nil
}

// logEvent builds the per-row intune.noncompliant_setting log event. The device,
// setting, policy, and user identity live here as structured attributes instead
// of metric labels (#112). The decoded setting_status and the raw
// setting_status_code both ride along, per the house pattern: Microsoft's
// published tables have repeatedly failed to cover every live value on this
// project, so the lossless code must survive a decode miss.
//
// Severity is always WARN: this report only returns noncompliant/error settings.
func logEvent(row exportjob.Row, status string) telemetry.Event {
	attrs := telemetry.Attrs{}
	telemetry.SetStr(attrs, semconv.AttrDeviceName, row["DeviceName"])
	telemetry.SetStr(attrs, semconv.AttrDeviceId, row["DeviceId"])
	telemetry.SetStr(attrs, semconv.AttrUpn, row["UPN"])
	telemetry.SetStr(attrs, semconv.AttrOs, row["OS"])
	telemetry.SetStr(attrs, semconv.AttrOsVersion, row["OSVersion"])
	telemetry.SetStr(attrs, semconv.AttrSettingName, row["SettingName"])
	telemetry.SetStr(attrs, semconv.AttrSettingDisplayName, row["SettingNm_loc"])
	telemetry.SetStr(attrs, semconv.AttrPolicyName, row["PolicyName"])
	telemetry.SetStr(attrs, semconv.AttrSettingStatus, status)
	telemetry.SetStr(attrs, semconv.AttrSettingStatusCode, row["SettingStatus"])
	telemetry.SetStr(attrs, semconv.AttrErrorCode, row["ErrorCode"])

	return telemetry.Event{
		Name:     eventName,
		Body:     "Intune noncompliant setting",
		Severity: telemetry.SeverityWarn,
		Attrs:    attrs,
	}
}

// logExportFailure logs an Export failure at a level matching its cause: a
// missing write scope or a failed/expired job are expected, tenant-side
// conditions (Warn/Info); anything else is also just logged, never escalated to
// a returned error — see the package doc.
func logExportFailure(logger *slog.Logger, err error) {
	switch {
	case errors.Is(err, exportjob.ErrJobFailed):
		logger.Warn("noncompliantsettings: export job failed", "collector", collectorName, "report_name", reportName, "error", err)
	case errors.Is(err, exportjob.ErrSASExpired):
		logger.Warn("noncompliantsettings: export SAS url expired before download", "collector", collectorName, "report_name", reportName, "error", err)
	case strings.Contains(err.Error(), "status 403"):
		logger.Info("noncompliantsettings: export job creation forbidden (missing write scope?); skipping", "collector", collectorName, "report_name", reportName, "error", err)
	default:
		logger.Warn("noncompliantsettings: export failed", "collector", collectorName, "report_name", reportName, "error", err)
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
