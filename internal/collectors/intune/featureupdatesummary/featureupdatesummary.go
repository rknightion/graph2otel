// Package featureupdatesummary is the Intune Windows feature-update policy status
// summary collector (BETA): a thin adapter over the shared report-export subsystem
// (internal/exportjob) for the FeatureUpdatePolicyStatusSummary report.
//
// The report is PRE-AGGREGATED by Microsoft: one row per feature-update policy,
// already carrying device counts bucketed by deployment state (in-progress, error,
// success). There is no per-device row anywhere in this report, so this collector
// emits a bounded gauge only — no log twin. Per #114, a log twin exists to answer
// "which one" when a collector fetches per-entity rows and discards them; there is
// no entity here to discard, so #114 does not apply and dropping nothing is correct.
//
// Cardinality (#112): the gauge is keyed by policy_id, policy_name,
// feature_update_version, and update_deployment_state — a policy is a bounded
// config object (small, tenant-shaped), not a per-user/per-device entity, so this
// stays within the metric-label rule.
package featureupdatesummary

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
	collectorName = "intune.feature_update_summary"
	metricName    = "intune.feature_update_summary.devices"
	reportName    = "FeatureUpdatePolicyStatusSummary"

	stateInProgress = "in_progress"
	stateError      = "error"
	stateSuccess    = "success"
)

// selectColumns pins the export columns (Microsoft's default set can change).
var selectColumns = []string{
	"PolicyId", "PolicyName", "FeatureUpdateVersion",
	"CountDevicesInProgressStatus", "CountDevicesErrorStatus", "CountDevicesSuccessStatus",
}

// Collector polls the FeatureUpdatePolicyStatusSummary export report through the
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

// Collect runs the export job and re-emits each policy's pre-aggregated device
// counts as three gauge points (one per deployment state). Export failures are
// logged and swallowed, never surfaced to the scheduler.
func (c *Collector) Collect(ctx context.Context, e telemetry.Emitter) error {
	// This collector names its own transport (#141): exportjob never calls LogEvent.
	e = telemetry.WithTransport(e, telemetry.TransportReportExport)

	if c.export == nil {
		c.logger.Info("featureupdatesummary: no export runner configured; skipping", "collector", collectorName)
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
		points = append(points, policyPoints(row)...)
	}
	e.GaugeSnapshot(metricName, "{device}", "Intune Windows feature-update policy device counts by deployment state, from the pre-aggregated FeatureUpdatePolicyStatusSummary report.", points)

	return nil
}

// policyPoints builds the three per-state gauge points for one policy row. All
// three states are always emitted, even when a count is 0, so series shape stays
// stable across polls.
func policyPoints(row exportjob.Row) []telemetry.GaugePoint {
	base := telemetry.Attrs{
		semconv.AttrPolicyId:             row["PolicyId"],
		semconv.AttrPolicyName:           row["PolicyName"],
		semconv.AttrFeatureUpdateVersion: row["FeatureUpdateVersion"],
	}

	states := []struct {
		state  string
		column string
	}{
		{stateInProgress, "CountDevicesInProgressStatus"},
		{stateError, "CountDevicesErrorStatus"},
		{stateSuccess, "CountDevicesSuccessStatus"},
	}

	points := make([]telemetry.GaugePoint, 0, len(states))
	for _, s := range states {
		attrs := telemetry.Attrs{
			semconv.AttrPolicyId:              base[semconv.AttrPolicyId],
			semconv.AttrPolicyName:            base[semconv.AttrPolicyName],
			semconv.AttrFeatureUpdateVersion:  base[semconv.AttrFeatureUpdateVersion],
			semconv.AttrUpdateDeploymentState: s.state,
		}
		points = append(points, telemetry.GaugePoint{
			Value: parseCount(row[s.column]),
			Attrs: attrs,
		})
	}
	return points
}

// parseCount parses a device-count column; an unparseable value is treated as 0
// rather than dropping the point, keeping the fixed 3-states-per-policy shape.
func parseCount(v string) float64 {
	n, err := strconv.ParseFloat(v, 64)
	if err != nil {
		return 0
	}
	return n
}

func logExportFailure(logger *slog.Logger, err error) {
	switch {
	case errors.Is(err, exportjob.ErrJobFailed):
		logger.Warn("featureupdatesummary: export job failed", "collector", collectorName, "report_name", reportName, "error", err)
	case errors.Is(err, exportjob.ErrSASExpired):
		logger.Warn("featureupdatesummary: export SAS url expired before download", "collector", collectorName, "report_name", reportName, "error", err)
	case strings.Contains(err.Error(), "status 403"):
		logger.Info("featureupdatesummary: export job creation forbidden (missing write scope?); skipping", "collector", collectorName, "report_name", reportName, "error", err)
	default:
		logger.Warn("featureupdatesummary: export failed", "collector", collectorName, "report_name", reportName, "error", err)
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
