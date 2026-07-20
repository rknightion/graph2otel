// Package deviceswithoutcompliancepolicy is the Intune "Devices without compliance
// policy" export-report collector (BETA): every managed device with no compliance
// policy assigned — bucketed into a bounded OS gauge and mirrored per-device on a
// log twin at WARN, since a managed device with no compliance policy assigned is a
// posture gap.
//
// Same Reports Export subsystem as its siblings (#17); the report is
// DevicesWithoutCompliancePolicy.
//
// Evidence class: this report returned ZERO rows on m7kni when probed as
// graph2otel-poller 2026-07-20 — every managed device on the tenant HAS a compliance
// policy assigned, the healthy state. The column NAMES below are live-confirmed from
// the export default header; the fixture VALUES in the test file are illustrative
// and never assert a value exists on the wire (the #142 discipline). Full live
// header (default columns): DeviceId, DeviceName, DeviceModel, DeviceType,
// OSDescription, OSVersion, OwnerType, OwnerType_loc, ManagementAgents,
// ManagementAgents_loc, UserId, LastContactedUserId, PrimaryUser, UPN, UserEmail,
// UserName, LastContact, AadDeviceId, ComplianceState, ComplianceState_loc, OS,
// OS_loc. The `_loc` columns are localized-label duplicates of their base column and
// selecting them 400s (#203) — so the export request OMITS Select entirely and
// takes Microsoft's default column set.
//
// Cardinality (#83/#112): per-entity identity — device id, device name, UPN — never
// becomes a metric label. The gauge is keyed only by semconv.AttrOs; every per-device
// detail rides the log twin. Guard test.
package deviceswithoutcompliancepolicy

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

const (
	collectorName = "intune.devices_without_compliance_policy"
	metricName    = "intune.devices_without_compliance_policy.devices"
	eventName     = "intune.devices_without_compliance_policy"
	reportName    = "DevicesWithoutCompliancePolicy"
)

// Collector polls the DevicesWithoutCompliancePolicy export report through the
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

// Collect runs the export job, counts devices-without-compliance-policy rows by OS
// into the bounded gauge, and emits one WARN twin per device row. Export failures
// are logged and swallowed, never surfaced to the scheduler. Zero rows emit nothing
// and is a valid steady state (the observed m7kni state — every device has a
// compliance policy).
func (c *Collector) Collect(ctx context.Context, e telemetry.Emitter) error {
	// This collector names its own transport (#141): exportjob never calls LogEvent.
	e = telemetry.WithTransport(e, telemetry.TransportReportExport)

	if c.export == nil {
		c.logger.Info("deviceswithoutcompliancepolicy: no export runner configured; skipping", "collector", collectorName)
		return nil
	}

	// Select is deliberately omitted: the report carries _loc columns that 400 when
	// selected (#203), so this request takes Microsoft's default column set.
	rows, err := c.export.Export(ctx, exportjob.Request{
		ReportName: reportName,
		Format:     exportjob.FormatCSV,
	}, e)
	if err != nil {
		logExportFailure(c.logger, err)
		return nil
	}

	counts := map[string]float64{}
	for _, row := range rows {
		counts[row["OS"]]++
		e.LogEvent(deviceLogEvent(row))
	}

	points := make([]telemetry.GaugePoint, 0, len(counts))
	for os, v := range counts {
		points = append(points, telemetry.GaugePoint{
			Value: v,
			Attrs: telemetry.Attrs{semconv.AttrOs: os},
		})
	}
	e.GaugeSnapshot(metricName, "{device}", "Intune managed device count without a compliance policy assigned, by OS; per-device detail on the intune.devices_without_compliance_policy log twin.", points)

	return nil
}

// deviceLogEvent builds the per-device twin. Severity is always WARN: a managed
// device with no compliance policy assigned is a posture gap, unlike the raw-status
// twins on sibling export collectors. The event timestamp is left unset: this is a
// state snapshot re-emitted each poll, and the report carries no per-row timestamp.
func deviceLogEvent(row exportjob.Row) telemetry.Event {
	attrs := telemetry.Attrs{}
	telemetry.SetStr(attrs, semconv.AttrDeviceId, row["DeviceId"])
	telemetry.SetStr(attrs, semconv.AttrDeviceName, row["DeviceName"])
	telemetry.SetStr(attrs, semconv.AttrOs, row["OS"])
	telemetry.SetStr(attrs, semconv.AttrOsVersion, row["OSVersion"])
	telemetry.SetStr(attrs, semconv.AttrOwnerType, row["OwnerType"])
	telemetry.SetStr(attrs, semconv.AttrUpn, row["UPN"])
	telemetry.SetStr(attrs, semconv.AttrComplianceState, row["ComplianceState"])

	return telemetry.Event{
		Name:     eventName,
		Body:     "Intune device without a compliance policy",
		Severity: telemetry.SeverityWarn,
		Attrs:    attrs,
	}
}

func logExportFailure(logger *slog.Logger, err error) {
	switch {
	case errors.Is(err, exportjob.ErrJobFailed):
		logger.Warn("deviceswithoutcompliancepolicy: export job failed", "collector", collectorName, "report_name", reportName, "error", err)
	case errors.Is(err, exportjob.ErrSASExpired):
		logger.Warn("deviceswithoutcompliancepolicy: export SAS url expired before download", "collector", collectorName, "report_name", reportName, "error", err)
	case strings.Contains(err.Error(), "status 403"):
		logger.Info("deviceswithoutcompliancepolicy: export job creation forbidden (missing write scope?); skipping", "collector", collectorName, "report_name", reportName, "error", err)
	default:
		logger.Warn("deviceswithoutcompliancepolicy: export failed", "collector", collectorName, "report_name", reportName, "error", err)
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
