// Package deviceattestation is the Intune device TPM-attestation collector
// (BETA): the per-device TPM/health-attestation state of every managed device,
// bucketed into a bounded gauge and mirrored per device on a log twin.
//
// Why the export report, not the Graph property (LIVE-VERIFIED 2026-07-19,
// m7kni, probed as graph2otel-poller): the deviceHealthAttestationState
// property on managedDevices is NULL tenant-wide — reading it back returns
// nothing for any device. The TpmAttestationStatus export report, by contrast,
// returns real per-device rows (attestation status, TPM manufacturer/version,
// os, ownership). So this collector is built on the reports export subsystem
// (internal/exportjob, #17), which is the working path — the same lesson
// appinstallreport learned choosing the aggregate report over the broken
// per-device navigation properties.
//
// Cardinality (#83/#112): per-device identity — device name, model, UPN, TPM
// details — never becomes a metric label. The gauge is keyed only by
// (attestation_status, os), both bounded by Microsoft's enum, so the series
// count is fixed regardless of fleet size; every device's own row is emitted as
// an intune.device_attestation log event instead (the obligatory log twin — a
// per-device count that discarded the rows would answer "how many" but never
// "which one"). There is a guard test.
package deviceattestation

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
const collectorName = "intune.device_attestation"

// devicesMetricName is the bounded attestation-status/os device-count gauge this
// collector emits. It counts devices — one row is one device — bucketed into
// (attestation_status, os); see the package doc's cardinality note for why no
// per-device dimension may ever join it.
const devicesMetricName = "intune.device_attestation.devices"

// eventName is the OTLP LogRecord EventName every per-device row carries. The
// per-device detail lives here rather than on the metric (#83/#112).
const eventName = "intune.device_attestation"

// completedStatus is the AttestationStatus value that means the device passed
// attestation. Any other value escalates the log twin's severity to WARN.
const completedStatus = "Completed"

// reportName is the export report catalog name this collector requests.
// LIVE-VERIFIED 2026-07-19: the deviceHealthAttestationState managedDevice
// property is NULL tenant-wide, but this report returns real per-device rows —
// see the package doc.
const reportName = "TpmAttestationStatus"

// selectColumns are the export columns this collector requests. Select is
// required and non-empty: Microsoft warns the default column set can change
// without notice, so every export caller must pin its own columns explicitly
// (see internal/exportjob). Pinned exactly per the frozen contract; a few
// columns (EnrolledByUser, EnrollmentDate) are requested for completeness but
// not emitted.
var selectColumns = []string{
	"DeviceId",
	"DeviceName",
	"AttestationStatus",
	"AttestationStatusDetail",
	"TpmManufacturer",
	"TpmVersion",
	"EnrolledByUser",
	"OS",
	"OSVersion",
	"Model",
	"Ownership",
	"EnrollmentDate",
	"LastCheckin",
	"UPN",
}

// Collector polls the TpmAttestationStatus export report through the shared
// export-job subsystem (internal/exportjob, #17).
type Collector struct {
	export exportjob.Runner
	logger *slog.Logger
}

// New builds the device-attestation collector. export is typically the
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
// (see the project's export-scope gotcha); this is the one documented exception
// to least-privileged read-only scoping that the export subsystem forces on
// every consumer, not a request for more than that.
func (c *Collector) RequiredPermissions() []string {
	return []string{"DeviceManagementManagedDevices.ReadWrite.All"}
}

// seriesKey is the aggregation key for the device-count gauge: both dimensions
// are bounded by Microsoft's enum (attestation status x os), never by fleet
// size — which is the whole point of aggregating here rather than emitting a
// point per device.
type seriesKey struct {
	status string
	os     string
}

// Collect runs the TpmAttestationStatus export job, counts devices into the
// bounded (attestation_status, os) gauge, and emits one log event per device row
// carrying the per-device detail. Any export failure (missing write scope, a job
// that reports failed, or a SAS url that expired before download) is logged and
// swallowed rather than treated as a scheduler-visible error — see the package
// doc and the exportjob seam's sentinel errors.
func (c *Collector) Collect(ctx context.Context, e telemetry.Emitter) error {
	// This collector names its own transport because no engine can (#141):
	// internal/exportjob creates/polls/downloads the job and hands rows back
	// without ever calling LogEvent, so there is no engine seam to stamp from.
	// Left unstamped, the Scheduler's "graph" baseline would be the only stamp
	// these rows got — a confident lie. exportjob's own graph2otel.export.*
	// self-obs metrics pass through untouched: the decorator is log-only.
	e = telemetry.WithTransport(e, telemetry.TransportReportExport)

	if c.export == nil {
		c.logger.Info("deviceattestation: no export runner configured; skipping", "collector", collectorName)
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
		// Both dimensions are emitted VERBATIM: AttestationStatus is Microsoft's
		// canonical enum (Completed/Failed/...) — do not decode it — and OS is
		// the raw os string. Both are bounded, so an empty value is a bounded
		// bucket, not a cardinality risk.
		counts[seriesKey{status: row["AttestationStatus"], os: row["OS"]}]++
		e.LogEvent(deviceLogEvent(row))
	}

	points := make([]telemetry.GaugePoint, 0, len(counts))
	for k, v := range counts {
		points = append(points, telemetry.GaugePoint{
			Value: v,
			Attrs: telemetry.Attrs{semconv.AttrAttestationStatus: k.status, semconv.AttrOs: k.os},
		})
	}
	e.GaugeSnapshot(devicesMetricName, "{device}", "Intune managed-device count by TPM attestation status and OS; per-device detail on the intune.device_attestation log twin.", points)

	return nil
}

// deviceLogEvent builds the per-device intune.device_attestation log event for
// one TpmAttestationStatus row. The device identity and its TPM/os detail live
// here as structured attributes instead of metric labels (#83/#112). setStr
// omits any absent column entirely rather than emitting an empty string (#114).
//
// The event timestamp is left unset on purpose: this is a state feed re-emitted
// each poll (like endpoint analytics), so LastCheckin is carried as an attribute
// but NOT parsed into the event time — stamping arrival time is correct here.
//
// Severity escalates to WARN when attestation is not Completed: a device that
// failed TPM attestation is worth an operator's attention, a clean one is not.
func deviceLogEvent(row exportjob.Row) telemetry.Event {
	attrs := telemetry.Attrs{}
	telemetry.SetStr(attrs, semconv.AttrDeviceName, row["DeviceName"])
	telemetry.SetStr(attrs, semconv.AttrDeviceId, row["DeviceId"])
	telemetry.SetStr(attrs, semconv.AttrUpn, row["UPN"])
	telemetry.SetStr(attrs, semconv.AttrOs, row["OS"])
	telemetry.SetStr(attrs, semconv.AttrOsVersion, row["OSVersion"])
	telemetry.SetStr(attrs, semconv.AttrModel, row["Model"])
	telemetry.SetStr(attrs, semconv.AttrAttestationStatus, row["AttestationStatus"])
	telemetry.SetStr(attrs, semconv.AttrAttestationStatusDetail, row["AttestationStatusDetail"])
	telemetry.SetStr(attrs, semconv.AttrTpmManufacturer, row["TpmManufacturer"])
	telemetry.SetStr(attrs, semconv.AttrTpmVersion, row["TpmVersion"])
	telemetry.SetStr(attrs, semconv.AttrOwnership, row["Ownership"])
	telemetry.SetStr(attrs, semconv.AttrLastCheckin, row["LastCheckin"])

	severity := telemetry.SeverityInfo
	if row["AttestationStatus"] != completedStatus {
		severity = telemetry.SeverityWarn
	}

	return telemetry.Event{
		Name:     eventName,
		Body:     "Intune device TPM attestation status",
		Severity: severity,
		Attrs:    attrs,
	}
}

// logExportFailure logs an Export failure at a level matching its cause: a
// missing write scope or a failed/expired job are expected tenant-side
// conditions worth an operator's attention (Warn/Info); anything else is also
// just logged, never escalated to a returned error — see the package doc.
func logExportFailure(logger *slog.Logger, err error) {
	switch {
	case errors.Is(err, exportjob.ErrJobFailed):
		logger.Warn("deviceattestation: export job failed", "collector", collectorName, "report_name", reportName, "error", err)
	case errors.Is(err, exportjob.ErrSASExpired):
		logger.Warn("deviceattestation: export SAS url expired before download", "collector", collectorName, "report_name", reportName, "error", err)
	case strings.Contains(err.Error(), "status 403"):
		logger.Info("deviceattestation: export job creation forbidden (missing write scope?); skipping", "collector", collectorName, "report_name", reportName, "error", err)
	default:
		logger.Warn("deviceattestation: export failed", "collector", collectorName, "report_name", reportName, "error", err)
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
