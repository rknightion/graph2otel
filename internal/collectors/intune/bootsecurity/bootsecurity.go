// Package bootsecurity is the Intune device boot-security posture collector
// (BETA): the per-device Windows boot-integrity / health-attestation posture of
// every attesting managed device — BitLocker, Secure Boot, Code Integrity, VBS,
// firmware protection, memory integrity, Secured-Core, System Management Mode,
// TPM version — bucketed into a bounded posture gauge and mirrored per device on
// a log twin.
//
// Why the export report, not the Graph property (LIVE-VERIFIED 2026-07-19,
// m7kni, probed as graph2otel-poller): the deviceHealthAttestationState property
// on managedDevices is NULL tenant-wide (the same finding that put
// intune.device_attestation on the export path). The
// WindowsDeviceHealthAttestationReport export, by contrast, returns real
// per-device rows with the full boot-security field set. So this collector is
// built on the reports export subsystem (internal/exportjob, #17).
//
// Relationship to intune.device_attestation (#195): that collector reports the
// TpmAttestationStatus summary (did the device attest, TPM manufacturer/version).
// This one reports the boot-security POSTURE behind an attestation — the detail
// TpmAttestationStatus does not carry. Two reports, two collectors.
//
// Cardinality (#83/#112): per-device identity — device name, UPN, TPM version —
// never becomes a metric label. The single gauge is keyed only by
// (posture, status, os), all three bounded by Microsoft's enums, so the series
// count is fixed regardless of fleet size; every device's own posture row is
// emitted as an intune.device_boot_security log event instead. There is a guard
// test. A device that fails to report a posture (empty column, loc "Unknown")
// contributes no gauge point for that posture rather than a meaningless "" bucket.
package bootsecurity

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

// collectorName is the stable key used for config, self-observability, and the
// admin status page.
const collectorName = "intune.device_boot_security"

// devicesMetricName is the bounded (posture, status, os) device-count gauge. One
// device contributes one point per reported posture; see the package doc's
// cardinality note for why no per-device dimension may join it.
const devicesMetricName = "intune.device_boot_security.devices"

// eventName is the OTLP LogRecord EventName every per-device posture row carries.
const eventName = "intune.device_boot_security"

// reportName is the export report catalog name this collector requests.
const reportName = "WindowsDeviceHealthAttestationReport"

// successAttestation is the AttestationError value that means the device attested
// cleanly. Any other value escalates the twin's severity to WARN.
const successAttestation = "Success"

// selectColumns pins the raw (non-localized) export columns. Microsoft warns the
// default column set can change without notice, so every export caller pins its
// own. The `_loc` localized siblings are deliberately not requested — this
// collector emits the canonical enum values, not the display strings.
var selectColumns = []string{
	"DeviceId", "DeviceName", "PrimaryUser", "UPN", "DeviceOS",
	"BitlockerStatus", "CodeIntegrityStatus", "BootDebuggingStatus", "AIKKey",
	"SecureBootStatus", "DEPPolicy", "HealthCertIssuedDate",
	"OSKernelDebuggingStatus", "SafeModeStatus", "VSMStatus", "WinPEStatus",
	"ELAMDriverLoadedStatus", "FirmwareProtectionStatus",
	"MemoryIntegrityProtectionStatus", "MemoryAccessProtectionStatus",
	"SecuredCorePCStatus", "SystemManagementMode", "TpmVersion", "AttestationError",
}

// postureFacet maps a bounded gauge posture label to its raw export column. The
// facets are the security-relevant boot-integrity toggles worth a fleet KPI; the
// remaining columns ride the twin only. All facet values are Microsoft enums
// (Enabled/Disabled/Enforce/NotApplicable/...), bounded regardless of fleet size.
type postureFacet struct {
	posture string
	column  string
}

var gaugeFacets = []postureFacet{
	{"bitlocker", "BitlockerStatus"},
	{"secure_boot", "SecureBootStatus"},
	{"code_integrity", "CodeIntegrityStatus"},
	{"vsm", "VSMStatus"},
	{"firmware_protection", "FirmwareProtectionStatus"},
	{"memory_integrity", "MemoryIntegrityProtectionStatus"},
	{"secured_core_pc", "SecuredCorePCStatus"},
}

// Collector polls the WindowsDeviceHealthAttestationReport export report through
// the shared export-job subsystem (internal/exportjob, #17).
type Collector struct {
	export exportjob.Runner
	logger *slog.Logger
}

// New builds the boot-security collector. export is typically the per-tenant
// *exportjob.Client the composition root builds (collectors.Deps.Export); a nil
// export is handled gracefully by Collect (skip-and-log). A nil logger falls back
// to the slog default.
func New(export exportjob.Runner, logger *slog.Logger) *Collector {
	if logger == nil {
		logger = slog.Default()
	}
	return &Collector{export: export, logger: logger}
}

// Name implements collector.SnapshotCollector.
func (c *Collector) Name() string { return collectorName }

// IngestTransport reports the transport this collector ingests over (#141): the
// same telemetry.Transport Collect stamps onto every record.
func (c *Collector) IngestTransport() telemetry.Transport { return telemetry.TransportReportExport }

// DefaultInterval mirrors the sibling export collectors: export jobs are
// expensive and share the 48-req/min-per-app export budget, so this defaults to a
// long cadence.
func (c *Collector) DefaultInterval() time.Duration { return 6 * time.Hour }

// Experimental marks this as an opt-in collector: it depends on the export-job
// subsystem creating a job under a write-level Graph scope (see RequiredPermissions).
func (c *Collector) Experimental() bool { return true }

// RequiredPermissions declares the least-privilege Graph application scope.
// Creating an export job requires DeviceManagementManagedDevices.ReadWrite.All
// even though this collector only reads the result back — the one documented
// exception to read-only scoping the export subsystem forces on every consumer.
func (c *Collector) RequiredPermissions() []string {
	return []string{"DeviceManagementManagedDevices.ReadWrite.All"}
}

// seriesKey is the aggregation key for the device-count gauge: all three
// dimensions are bounded by Microsoft's enums, never by fleet size.
type seriesKey struct {
	posture string
	status  string
	os      string
}

// Collect runs the WindowsDeviceHealthAttestationReport export job, counts devices
// into the bounded (posture, status, os) gauge, and emits one posture twin per
// device row. Any export failure is logged and swallowed rather than surfaced to
// the scheduler — see logExportFailure and the package doc.
func (c *Collector) Collect(ctx context.Context, e telemetry.Emitter) error {
	// This collector names its own transport because no engine can (#141):
	// internal/exportjob hands rows back without ever calling LogEvent.
	e = telemetry.WithTransport(e, telemetry.TransportReportExport)

	if c.export == nil {
		c.logger.Info("bootsecurity: no export runner configured; skipping", "collector", collectorName)
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
		os := row["DeviceOS"]
		for _, f := range gaugeFacets {
			// An empty posture value means the device did not report it (loc
			// "Unknown") — no bucket, rather than a meaningless "" series.
			if v := row[f.column]; v != "" {
				counts[seriesKey{posture: f.posture, status: v, os: os}]++
			}
		}
		e.LogEvent(deviceLogEvent(row))
	}

	points := make([]telemetry.GaugePoint, 0, len(counts))
	for k, v := range counts {
		points = append(points, telemetry.GaugePoint{
			Value: v,
			Attrs: telemetry.Attrs{semconv.AttrPosture: k.posture, semconv.AttrStatus: k.status, semconv.AttrOs: k.os},
		})
	}
	e.GaugeSnapshot(devicesMetricName, "{device}", "Intune managed-device count by boot-security posture (bitlocker/secure_boot/code_integrity/vsm/firmware_protection/memory_integrity/secured_core_pc), status, and OS; per-device detail on the intune.device_boot_security log twin.", points)

	return nil
}

// deviceLogEvent builds the per-device intune.device_boot_security twin for one
// WindowsDeviceHealthAttestationReport row. The device identity and its full
// boot-security posture live here as structured attributes instead of metric
// labels (#83/#112). SetStr omits any absent column entirely rather than emitting
// an empty string (#114).
//
// The event timestamp is left unset on purpose: this is a state feed re-emitted
// each poll (like intune.device_attestation), so HealthCertIssuedDate is carried
// as an attribute but NOT parsed into the event time.
//
// Severity escalates to WARN when the device did not attest cleanly
// (AttestationError != Success). Individual posture concerns (BitLocker off,
// Secure Boot off, ...) are queried per device via LogQL over the twin.
func deviceLogEvent(row exportjob.Row) telemetry.Event {
	attrs := telemetry.Attrs{}
	telemetry.SetStr(attrs, semconv.AttrDeviceName, row["DeviceName"])
	telemetry.SetStr(attrs, semconv.AttrDeviceId, row["DeviceId"])
	telemetry.SetStr(attrs, semconv.AttrIntuneUserId, row["PrimaryUser"])
	telemetry.SetStr(attrs, semconv.AttrUpn, row["UPN"])
	telemetry.SetStr(attrs, semconv.AttrOs, row["DeviceOS"])
	telemetry.SetStr(attrs, semconv.AttrTpmVersion, row["TpmVersion"])
	telemetry.SetStr(attrs, semconv.AttrHealthCertIssuedDate, row["HealthCertIssuedDate"])
	telemetry.SetStr(attrs, semconv.AttrAttestationError, row["AttestationError"])
	telemetry.SetStr(attrs, semconv.AttrBitlockerStatus, row["BitlockerStatus"])
	telemetry.SetStr(attrs, semconv.AttrSecureBootStatus, row["SecureBootStatus"])
	telemetry.SetStr(attrs, semconv.AttrCodeIntegrityStatus, row["CodeIntegrityStatus"])
	telemetry.SetStr(attrs, semconv.AttrBootDebuggingStatus, row["BootDebuggingStatus"])
	telemetry.SetStr(attrs, semconv.AttrOsKernelDebuggingStatus, row["OSKernelDebuggingStatus"])
	telemetry.SetStr(attrs, semconv.AttrSafeModeStatus, row["SafeModeStatus"])
	telemetry.SetStr(attrs, semconv.AttrVsmStatus, row["VSMStatus"])
	telemetry.SetStr(attrs, semconv.AttrWinpeStatus, row["WinPEStatus"])
	telemetry.SetStr(attrs, semconv.AttrElamDriverLoadedStatus, row["ELAMDriverLoadedStatus"])
	telemetry.SetStr(attrs, semconv.AttrFirmwareProtectionStatus, row["FirmwareProtectionStatus"])
	telemetry.SetStr(attrs, semconv.AttrMemoryIntegrityProtection, row["MemoryIntegrityProtectionStatus"])
	telemetry.SetStr(attrs, semconv.AttrMemoryAccessProtectionStatus, row["MemoryAccessProtectionStatus"])
	telemetry.SetStr(attrs, semconv.AttrSecuredCorePcStatus, row["SecuredCorePCStatus"])
	telemetry.SetStr(attrs, semconv.AttrSystemManagementMode, row["SystemManagementMode"])
	telemetry.SetStr(attrs, semconv.AttrDepPolicy, row["DEPPolicy"])
	telemetry.SetStr(attrs, semconv.AttrAikKey, row["AIKKey"])

	severity := telemetry.SeverityInfo
	if row["AttestationError"] != successAttestation {
		severity = telemetry.SeverityWarn
	}

	return telemetry.Event{
		Name:     eventName,
		Body:     "Intune device boot-security posture",
		Severity: severity,
		Attrs:    attrs,
	}
}

// logExportFailure logs an Export failure at a level matching its cause, never
// escalating to a returned error — see the package doc.
func logExportFailure(logger *slog.Logger, err error) {
	switch {
	case errors.Is(err, exportjob.ErrJobFailed):
		logger.Warn("bootsecurity: export job failed", "collector", collectorName, "report_name", reportName, "error", err)
	case errors.Is(err, exportjob.ErrSASExpired):
		logger.Warn("bootsecurity: export SAS url expired before download", "collector", collectorName, "report_name", reportName, "error", err)
	case strings.Contains(err.Error(), "status 403"):
		logger.Info("bootsecurity: export job creation forbidden (missing write scope?); skipping", "collector", collectorName, "report_name", reportName, "error", err)
	default:
		logger.Warn("bootsecurity: export failed", "collector", collectorName, "report_name", reportName, "error", err)
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
