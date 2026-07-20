// Package qualityupdatesummary is the Intune Windows quality/expedite-update
// policy status-summary collector (BETA): a thin adapter over the
// QualityUpdatePolicyStatusSummary export report.
//
// This report is PRE-AGGREGATED by Microsoft — one row per policy, already
// carrying device counts bucketed by deployment state — so there is no
// per-device data to shed onto a log twin. The gauge alone is the whole
// signal: policy count x release-date x 3 states is tenant-shaped and bounded
// by the tenant's own policy count (#112), so nothing is dropped and #114
// does not apply (there is no per-entity row to lose).
package qualityupdatesummary

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
	collectorName = "intune.quality_update_summary"
	metricName    = "intune.quality_update_summary.devices"
	reportName    = "QualityUpdatePolicyStatusSummary"

	stateInProgress = "in_progress"
	stateError      = "error"
	stateSuccess    = "success"
)

// selectColumns pins the export columns (Microsoft's default set can change).
var selectColumns = []string{
	"PolicyId", "PolicyName", "ExpediteQUReleaseDate",
	"CountDevicesInProgressStatus", "CountDevicesErrorStatus", "CountDevicesSuccessStatus",
}

// Collector polls the QualityUpdatePolicyStatusSummary export report through
// the shared export-job subsystem (internal/exportjob, #17).
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

// Collect runs the export job and emits three bounded gauge points per policy
// row (in_progress/error/success device counts). Export failures are logged
// and swallowed, never surfaced to the scheduler. There is no per-device data
// in this report, so no log twin is emitted.
func (c *Collector) Collect(ctx context.Context, e telemetry.Emitter) error {
	// This collector names its own transport (#141): exportjob never calls LogEvent.
	e = telemetry.WithTransport(e, telemetry.TransportReportExport)

	if c.export == nil {
		c.logger.Info("qualityupdatesummary: no export runner configured; skipping", "collector", collectorName)
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

	points := make([]telemetry.GaugePoint, 0, len(rows)*3)
	for _, row := range rows {
		attrs := telemetry.Attrs{
			semconv.AttrPolicyId:            row["PolicyId"],
			semconv.AttrPolicyName:          row["PolicyName"],
			semconv.AttrExpediteReleaseDate: row["ExpediteQUReleaseDate"],
		}
		points = append(points,
			gaugePoint(attrs, stateInProgress, row["CountDevicesInProgressStatus"]),
			gaugePoint(attrs, stateError, row["CountDevicesErrorStatus"]),
			gaugePoint(attrs, stateSuccess, row["CountDevicesSuccessStatus"]),
		)
	}
	e.GaugeSnapshot(metricName, "{device}", "Windows quality/expedite-update policy device counts by deployment state, from the pre-aggregated QualityUpdatePolicyStatusSummary report.", points)

	return nil
}

// gaugePoint builds one state's point, cloning attrs so each of the three
// points per policy gets its own map plus the state label.
func gaugePoint(base telemetry.Attrs, state, rawCount string) telemetry.GaugePoint {
	attrs := make(telemetry.Attrs, len(base)+1)
	for k, v := range base {
		attrs[k] = v
	}
	attrs[semconv.AttrUpdateDeploymentState] = state

	value, err := strconv.ParseFloat(rawCount, 64)
	if err != nil {
		value = 0
	}
	return telemetry.GaugePoint{Value: value, Attrs: attrs}
}

func logExportFailure(logger *slog.Logger, err error) {
	switch {
	case errors.Is(err, exportjob.ErrJobFailed):
		logger.Warn("qualityupdatesummary: export job failed", "collector", collectorName, "report_name", reportName, "error", err)
	case errors.Is(err, exportjob.ErrSASExpired):
		logger.Warn("qualityupdatesummary: export SAS url expired before download", "collector", collectorName, "report_name", reportName, "error", err)
	case strings.Contains(err.Error(), "status 403"):
		logger.Info("qualityupdatesummary: export job creation forbidden (missing write scope?); skipping", "collector", collectorName, "report_name", reportName, "error", err)
	default:
		logger.Warn("qualityupdatesummary: export failed", "collector", collectorName, "report_name", reportName, "error", err)
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
