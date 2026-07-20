// Package firewallstatus is the Intune Windows firewall-status collector: for
// every managed device that has reported in, the raw Windows Firewall status
// code — bucketed into a bounded status gauge and mirrored per device on a log
// twin.
//
// Report: FirewallStatus (export-job subsystem, internal/exportjob, #17).
//
// The export Select is deliberately OMITTED entirely, not pinned to a column
// list like the sibling export collectors: this report carries `_loc` (localized
// display-string) columns that the export API 400s on when explicitly selected
// (live-measured 2026-07-20, m7kni, #203). Requesting no Select falls back to
// Microsoft's default column set, which does include the raw (non-localized)
// FirewallStatus code this collector needs.
//
// FirewallStatus is Microsoft's own RAW numeric code, emitted verbatim and NOT
// decoded beyond the one documented meaning: 0 means the firewall is Enabled
// (healthy). Every other value is undocumented beyond that single data point, so
// this collector maps 0 to INFO and anything else to WARN without attempting to
// interpret which specific non-zero state it represents.
//
// Cardinality (#83/#112): per-device identity — device id, device name, UPN —
// never becomes a metric label. The gauge is keyed only by firewall_status (a
// bounded code), so series count is fixed regardless of fleet size; every
// device's own row rides the intune.firewall_status log twin. Guard test.
package firewallstatus

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
	collectorName = "intune.firewall_status"
	metricName    = "intune.firewall_status.devices"
	eventName     = "intune.firewall_status"
	reportName    = "FirewallStatus"
)

// firewallEnabled is the raw FirewallStatus code meaning the firewall is
// Enabled (healthy). Any other value escalates the twin's severity to WARN.
const firewallEnabled = "0"

// Collector polls the FirewallStatus export report through the shared
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

// Collect runs the export job, counts device rows by raw FirewallStatus code
// into the bounded gauge, and emits one twin per device row. Export failures are
// logged and swallowed, never surfaced to the scheduler.
func (c *Collector) Collect(ctx context.Context, e telemetry.Emitter) error {
	// This collector names its own transport (#141): exportjob never calls LogEvent.
	e = telemetry.WithTransport(e, telemetry.TransportReportExport)

	if c.export == nil {
		c.logger.Info("firewallstatus: no export runner configured; skipping", "collector", collectorName)
		return nil
	}

	rows, err := c.export.Export(ctx, exportjob.Request{
		ReportName: reportName,
		// Select is deliberately omitted: this report's `_loc` columns 400 the
		// export job when explicitly selected (#203). The default column set
		// includes the raw FirewallStatus code this collector needs.
		Format: exportjob.FormatCSV,
	}, e)
	if err != nil {
		logExportFailure(c.logger, err)
		return nil
	}

	counts := map[string]float64{}
	for _, row := range rows {
		counts[row["FirewallStatus"]]++
		e.LogEvent(deviceLogEvent(row))
	}

	points := make([]telemetry.GaugePoint, 0, len(counts))
	for status, v := range counts {
		points = append(points, telemetry.GaugePoint{
			Value: v,
			Attrs: telemetry.Attrs{semconv.AttrFirewallStatus: status},
		})
	}
	e.GaugeSnapshot(metricName, "{device}", "Intune managed-device count by raw Windows firewall status code; per-device detail on the intune.firewall_status log twin.", points)

	return nil
}

// deviceLogEvent builds the per-device twin. The event timestamp is left unset:
// this is a state snapshot re-emitted each poll, and LastReportedDateTime is
// carried as an attribute but not parsed into the event time.
//
// Severity is WARN when FirewallStatus != "0" (0 = Enabled = healthy) and INFO
// otherwise. The code is raw/undocumented beyond that single meaning, so it is
// never decoded further.
func deviceLogEvent(row exportjob.Row) telemetry.Event {
	attrs := telemetry.Attrs{}
	telemetry.SetStr(attrs, semconv.AttrDeviceId, row["DeviceId"])
	telemetry.SetStr(attrs, semconv.AttrDeviceName, row["DeviceName"])
	telemetry.SetStr(attrs, semconv.AttrUpn, row["UPN"])
	telemetry.SetStr(attrs, semconv.AttrFirewallStatus, row["FirewallStatus"])
	telemetry.SetStr(attrs, semconv.AttrLastReportedDateTime, row["LastReportedDateTime"])

	severity := telemetry.SeverityInfo
	if row["FirewallStatus"] != firewallEnabled {
		severity = telemetry.SeverityWarn
	}

	return telemetry.Event{
		Name:     eventName,
		Body:     "Intune device firewall status",
		Severity: severity,
		Attrs:    attrs,
	}
}

func logExportFailure(logger *slog.Logger, err error) {
	switch {
	case errors.Is(err, exportjob.ErrJobFailed):
		logger.Warn("firewallstatus: export job failed", "collector", collectorName, "report_name", reportName, "error", err)
	case errors.Is(err, exportjob.ErrSASExpired):
		logger.Warn("firewallstatus: export SAS url expired before download", "collector", collectorName, "report_name", reportName, "error", err)
	case strings.Contains(err.Error(), "status 403"):
		logger.Info("firewallstatus: export job creation forbidden (missing write scope?); skipping", "collector", collectorName, "report_name", reportName, "error", err)
	default:
		logger.Warn("firewallstatus: export failed", "collector", collectorName, "report_name", reportName, "error", err)
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
