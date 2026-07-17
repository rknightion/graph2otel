// Package scripts is the Intune management-scripts and proactive-remediation
// collector (BETA): fleet-wide run-state rollups for Windows PowerShell
// scripts (deviceManagementScripts), macOS shell scripts (deviceShellScripts),
// and health scripts / proactive remediations (deviceHealthScripts).
//
// All three surfaces live only on /beta, so this collector implements
// collectors.Experimental (opt-in, off by default) and degrades cleanly - a
// 403/404 (endpoint unavailable or unlicensed on the tenant) is
// skipped-and-logged rather than treated as a failure, per source.
//
// Script objects themselves are a bounded, admin-configured inventory
// (dozens, not thousands): this collector pages that small collection and
// then reads each script's runSummary singleton, never scriptContent /
// detectionScriptContent / remediationScriptContent (config, not telemetry)
// and never the per-device deviceRunStates collection (unbounded -
// scripts x devices - and event-shaped, deferred to the M5 log pipeline; see
// the package doc on Collect for detail).
package scripts

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/rknightion/graph2otel/internal/collector"
	"github.com/rknightion/graph2otel/internal/collectors"
	"github.com/rknightion/graph2otel/internal/semconv"
	"github.com/rknightion/graph2otel/internal/telemetry"
)

// collectorName is the stable key used for config (enable/interval),
// self-observability, and the admin status page.
const collectorName = "intune.scripts"

// Metric names this collector emits. Each is its own metric name so that
// summing a single metric always yields the true count for that breakdown -
// mixing independent dimensions (or a snapshot count and a rolling-window
// count) under one metric name would mean a naive `sum()` over it silently
// double-counts.
const (
	scriptRunSummaryMetric             = "intune.script.run_summary"
	remediationSummaryMetric           = "intune.remediation.summary"
	remediationCumulativeMetric        = "intune.remediation.remediated_cumulative_devices"
	remediationOverviewScriptCountName = "intune.remediation.overview.script_count"
	remediationOverviewRemediatedName  = "intune.remediation.overview.remediated_device_count"
)

// betaBaseURL is the Graph beta root. All three script surfaces
// (deviceManagementScripts, deviceShellScripts, deviceHealthScripts) and
// their runSummary / getRemediationSummary() functions are beta-only - see
// the tracking issue and the M4 authoring guide.
const betaBaseURL = "https://graph.microsoft.com/beta"

const (
	windowsScriptsPath     = "/deviceManagement/deviceManagementScripts"
	macScriptsPath         = "/deviceManagement/deviceShellScripts"
	healthScriptsPath      = "/deviceManagement/deviceHealthScripts"
	remediationSummaryPath = "/deviceManagement/deviceHealthScripts/getRemediationSummary"
)

// scriptListSelect limits the bounded script inventory fetch to id and
// displayName - scriptContent (Windows/macOS) and
// detectionScriptContent/remediationScriptContent (health scripts) are
// base64 script bodies, config rather than telemetry, and are never
// $selected here.
const scriptListSelect = "?$select=id,displayName"

// Bounded "os" attribute values for the run-summary metric. Fixed by which
// endpoint a script came from, not free text, so this can never grow beyond
// two values.
const (
	osWindows = "windows"
	osMacOS   = "macos"
)

// Bounded "target" attribute values: deviceManagementScriptRunSummary reports
// success/error counts separately for the devices and the (optional)
// per-user run context, and both are real, distinct signal - collapsing them
// would hide e.g. a script whose device-context runs succeed but whose
// user-context runs are failing.
const (
	targetDevice = "device"
	targetUser   = "user"
)

// Bounded "run_state" attribute values available from the runSummary
// aggregate. Note this is deliberately narrower than the full
// deviceManagementScriptDeviceState.runState enum
// (unknown/success/fail/scriptError/pending/notApplicable): that finer enum
// is only reported per-device (the deviceRunStates collection this collector
// does not fetch, per the package doc). The runSummary singleton this
// collector reads only ever aggregates into two buckets, success and error.
const (
	runStateSuccess = "success"
	runStateError   = "error"
)

// Bounded "phase" attribute values for the remediation-summary metric. Health
// scripts run in two independent phases - do NOT collapse them into one
// enum, per the tracking issue.
const (
	phaseDetection   = "detection"
	phaseRemediation = "remediation"
)

// Bounded "state" attribute values per phase, from deviceHealthScriptRunSummary.
const (
	detectionStateNoIssue       = "no_issue"
	detectionStateIssueDetected = "issue_detected"
	detectionStateError         = "error"
	detectionStatePending       = "pending"
	detectionStateNotApplicable = "not_applicable"

	remediationStateRemediated = "remediated"
	remediationStateSkipped    = "skipped"
	remediationStateReoccurred = "reoccurred"
	remediationStateError      = "error"
)

// scriptListItem is the subset of deviceManagementScript / deviceShellScript
// / deviceHealthScript this collector reads from the bounded list fetch -
// just enough to key the runSummary follow-up call and label the metric.
type scriptListItem struct {
	ID          string `json:"id"`
	DisplayName string `json:"displayName"`
}

// scriptRunSummary is the deviceManagementScriptRunSummary resource -
// shared by both deviceManagementScripts (Windows PowerShell) and
// deviceShellScripts (macOS shell), per Microsoft's own schema. The runSummary
// GET returns these fields at the TOP LEVEL of the body (an OData $entity) -
// no "value" envelope, contra the docs' worked example
// (live-measured 2026-07-17, #165/#174) - so this decodes directly against
// the response, the same as settingscatalog's singletons.
type scriptRunSummary struct {
	SuccessDeviceCount int64 `json:"successDeviceCount"`
	ErrorDeviceCount   int64 `json:"errorDeviceCount"`
	SuccessUserCount   int64 `json:"successUserCount"`
	ErrorUserCount     int64 `json:"errorUserCount"`
}

// healthScriptRunSummary is the deviceHealthScriptRunSummary resource: a
// two-phase rollup (detection fields, then remediation fields), plus a
// 30-day cumulative remediated-device count that is a distinct rolling
// window rather than a point-in-time state - emitted as its own metric
// below rather than folded into the phase/state breakdown.
type healthScriptRunSummary struct {
	NoIssueDetectedDeviceCount              int64 `json:"noIssueDetectedDeviceCount"`
	IssueDetectedDeviceCount                int64 `json:"issueDetectedDeviceCount"`
	DetectionScriptErrorDeviceCount         int64 `json:"detectionScriptErrorDeviceCount"`
	DetectionScriptPendingDeviceCount       int64 `json:"detectionScriptPendingDeviceCount"`
	DetectionScriptNotApplicableDeviceCount int64 `json:"detectionScriptNotApplicableDeviceCount"`
	IssueRemediatedDeviceCount              int64 `json:"issueRemediatedDeviceCount"`
	RemediationSkippedDeviceCount           int64 `json:"remediationSkippedDeviceCount"`
	IssueReoccurredDeviceCount              int64 `json:"issueReoccurredDeviceCount"`
	RemediationScriptErrorDeviceCount       int64 `json:"remediationScriptErrorDeviceCount"`
	IssueRemediatedCumulativeDeviceCount    int64 `json:"issueRemediatedCumulativeDeviceCount"`
}

// remediationOverview is the tenant-wide deviceHealthScriptRemediationSummary
// singleton returned by getRemediationSummary() on the deviceHealthScripts
// collection itself (not per-script) - a cheap, Microsoft-aggregated
// cross-check, the same role managedDeviceOverview plays in
// internal/collectors/intune/manageddevices. Also a top-level, envelope-free
// body - same wire shape as scriptRunSummary above.
type remediationOverview struct {
	ScriptCount           int64 `json:"scriptCount"`
	RemediatedDeviceCount int64 `json:"remediatedDeviceCount"`
}

// Collector polls the beta Intune scripts and proactive-remediation
// surfaces.
type Collector struct {
	g       collectors.GraphClient
	baseURL string
	logger  *slog.Logger
}

// New builds the scripts collector. A nil logger falls back to the slog
// default.
func New(g collectors.GraphClient, logger *slog.Logger) *Collector {
	if logger == nil {
		logger = slog.Default()
	}
	return &Collector{g: g, baseURL: betaBaseURL, logger: logger}
}

// Name implements collector.SnapshotCollector.
func (c *Collector) Name() string { return collectorName }

// DefaultInterval implements collector.SnapshotCollector. Script inventory
// and run-state rollups drift on the device check-in cadence, not
// real-time, so a mid-range Intune polling interval is appropriate.
func (c *Collector) DefaultInterval() time.Duration { return 30 * time.Minute }

// Experimental marks this as a beta, opt-in collector.
func (c *Collector) Experimental() bool { return true }

// RequiredPermissions declares the least-privilege Graph application scope.
// Every endpoint this collector reads (deviceManagementScripts,
// deviceShellScripts, deviceHealthScripts, and their runSummary /
// getRemediationSummary() functions) documents
// DeviceManagementScripts.Read.All as its least-privileged application
// permission.
func (c *Collector) RequiredPermissions() []string {
	return []string{"DeviceManagementScripts.Read.All"}
}

// Collect fetches the three bounded script inventories plus each one's
// runSummary, and the tenant-wide remediation overview singleton, emitting
// the gauges described in the package doc. Each sub-fetch is independently
// resilient: a 403/404 (beta surface unavailable/unlicensed on this tenant)
// is skipped-and-logged, any other error is logged and joined into the
// returned error, but every other metric still emits.
func (c *Collector) Collect(ctx context.Context, e telemetry.Emitter) error {
	var errs []error
	var runPoints []telemetry.GaugePoint

	for _, src := range []struct {
		path string
		os   string
	}{
		{windowsScriptsPath, osWindows},
		{macScriptsPath, osMacOS},
	} {
		pts, err := c.collectScriptRunSummaries(ctx, src.path, src.os)
		if err != nil {
			if isUnavailable(err) {
				c.logger.Info("scripts: endpoint unavailable on this tenant; skipping",
					"collector", collectorName, "os", src.os, "error", err)
			} else {
				c.logger.Warn("scripts: run summary collection failed",
					"collector", collectorName, "os", src.os, "error", err)
				errs = append(errs, fmt.Errorf("%s scripts: %w", src.os, err))
			}
		}
		runPoints = append(runPoints, pts...)
	}
	e.GaugeSnapshot(scriptRunSummaryMetric, "{run}",
		"Windows PowerShell / macOS shell script run outcomes, by script, OS, target (device or user context) and run state.",
		runPoints)

	remPoints, cumPoints, err := c.collectHealthScriptRunSummaries(ctx)
	if err != nil {
		if isUnavailable(err) {
			c.logger.Info("scripts: health scripts endpoint unavailable on this tenant; skipping",
				"collector", collectorName, "error", err)
		} else {
			c.logger.Warn("scripts: health script run summary collection failed", "collector", collectorName, "error", err)
			errs = append(errs, fmt.Errorf("health scripts: %w", err))
		}
	}
	e.GaugeSnapshot(remediationSummaryMetric, "{device}",
		"Proactive remediation (health script) run outcomes, by script, phase (detection or remediation) and state.",
		remPoints)
	e.GaugeSnapshot(remediationCumulativeMetric, "{device}",
		"Distinct devices remediated by each health script over the trailing 30 days (issueRemediatedCumulativeDeviceCount).",
		cumPoints)

	if err := c.collectRemediationOverview(ctx, e); err != nil {
		if isUnavailable(err) {
			c.logger.Info("scripts: remediation overview unavailable on this tenant; skipping",
				"collector", collectorName, "error", err)
		} else {
			c.logger.Warn("scripts: remediation overview fetch failed", "collector", collectorName, "error", err)
			errs = append(errs, fmt.Errorf("remediation overview: %w", err))
		}
	}

	return errors.Join(errs...)
}

// collectScriptRunSummaries pages the bounded script inventory at listPath
// and reads each script's runSummary singleton, returning the resulting
// device/user x success/error points labeled with the given os.
func (c *Collector) collectScriptRunSummaries(ctx context.Context, listPath, os string) ([]telemetry.GaugePoint, error) {
	raw, err := collectors.GetAllValues(ctx, c.g, c.baseURL+listPath+scriptListSelect, nil)
	if err != nil {
		return nil, err
	}

	var pts []telemetry.GaugePoint
	for _, r := range raw {
		var item scriptListItem
		if err := json.Unmarshal(r, &item); err != nil {
			c.logger.Warn("scripts: skipping unparseable script list entry", "collector", collectorName, "os", os, "error", err)
			continue
		}
		if item.ID == "" {
			continue
		}

		body, err := c.g.RawGet(ctx, c.baseURL+listPath+"/"+item.ID+"/runSummary")
		if err != nil {
			if isUnavailable(err) {
				continue
			}
			c.logger.Warn("scripts: runSummary fetch failed for script", "collector", collectorName, "os", os, "error", err)
			continue
		}
		var rs scriptRunSummary
		if err := json.Unmarshal(body, &rs); err != nil {
			c.logger.Warn("scripts: skipping unparseable runSummary", "collector", collectorName, "os", os, "error", err)
			continue
		}

		name := orUnknown(item.DisplayName)
		pts = append(pts,
			telemetry.GaugePoint{Value: float64(rs.SuccessDeviceCount), Attrs: telemetry.Attrs{semconv.AttrScriptName: name, semconv.AttrOs: os, semconv.AttrTarget: targetDevice, semconv.AttrRunState: runStateSuccess}},
			telemetry.GaugePoint{Value: float64(rs.ErrorDeviceCount), Attrs: telemetry.Attrs{semconv.AttrScriptName: name, semconv.AttrOs: os, semconv.AttrTarget: targetDevice, semconv.AttrRunState: runStateError}},
			telemetry.GaugePoint{Value: float64(rs.SuccessUserCount), Attrs: telemetry.Attrs{semconv.AttrScriptName: name, semconv.AttrOs: os, semconv.AttrTarget: targetUser, semconv.AttrRunState: runStateSuccess}},
			telemetry.GaugePoint{Value: float64(rs.ErrorUserCount), Attrs: telemetry.Attrs{semconv.AttrScriptName: name, semconv.AttrOs: os, semconv.AttrTarget: targetUser, semconv.AttrRunState: runStateError}},
		)
	}
	return pts, nil
}

// collectHealthScriptRunSummaries pages the bounded deviceHealthScripts
// inventory and reads each script's two-phase runSummary singleton,
// returning the phase/state points plus the separate 30-day cumulative
// remediated-device points.
func (c *Collector) collectHealthScriptRunSummaries(ctx context.Context) ([]telemetry.GaugePoint, []telemetry.GaugePoint, error) {
	raw, err := collectors.GetAllValues(ctx, c.g, c.baseURL+healthScriptsPath+scriptListSelect, nil)
	if err != nil {
		return nil, nil, err
	}

	var pts, cumPts []telemetry.GaugePoint
	for _, r := range raw {
		var item scriptListItem
		if err := json.Unmarshal(r, &item); err != nil {
			c.logger.Warn("scripts: skipping unparseable health script list entry", "collector", collectorName, "error", err)
			continue
		}
		if item.ID == "" {
			continue
		}

		body, err := c.g.RawGet(ctx, c.baseURL+healthScriptsPath+"/"+item.ID+"/runSummary")
		if err != nil {
			if isUnavailable(err) {
				continue
			}
			c.logger.Warn("scripts: health script runSummary fetch failed", "collector", collectorName, "error", err)
			continue
		}
		var rs healthScriptRunSummary
		if err := json.Unmarshal(body, &rs); err != nil {
			c.logger.Warn("scripts: skipping unparseable health script runSummary", "collector", collectorName, "error", err)
			continue
		}

		name := orUnknown(item.DisplayName)
		pts = append(pts,
			telemetry.GaugePoint{Value: float64(rs.NoIssueDetectedDeviceCount), Attrs: telemetry.Attrs{semconv.AttrScriptName: name, semconv.AttrPhase: phaseDetection, semconv.AttrState: detectionStateNoIssue}},
			telemetry.GaugePoint{Value: float64(rs.IssueDetectedDeviceCount), Attrs: telemetry.Attrs{semconv.AttrScriptName: name, semconv.AttrPhase: phaseDetection, semconv.AttrState: detectionStateIssueDetected}},
			telemetry.GaugePoint{Value: float64(rs.DetectionScriptErrorDeviceCount), Attrs: telemetry.Attrs{semconv.AttrScriptName: name, semconv.AttrPhase: phaseDetection, semconv.AttrState: detectionStateError}},
			telemetry.GaugePoint{Value: float64(rs.DetectionScriptPendingDeviceCount), Attrs: telemetry.Attrs{semconv.AttrScriptName: name, semconv.AttrPhase: phaseDetection, semconv.AttrState: detectionStatePending}},
			telemetry.GaugePoint{Value: float64(rs.DetectionScriptNotApplicableDeviceCount), Attrs: telemetry.Attrs{semconv.AttrScriptName: name, semconv.AttrPhase: phaseDetection, semconv.AttrState: detectionStateNotApplicable}},
			telemetry.GaugePoint{Value: float64(rs.IssueRemediatedDeviceCount), Attrs: telemetry.Attrs{semconv.AttrScriptName: name, semconv.AttrPhase: phaseRemediation, semconv.AttrState: remediationStateRemediated}},
			telemetry.GaugePoint{Value: float64(rs.RemediationSkippedDeviceCount), Attrs: telemetry.Attrs{semconv.AttrScriptName: name, semconv.AttrPhase: phaseRemediation, semconv.AttrState: remediationStateSkipped}},
			telemetry.GaugePoint{Value: float64(rs.IssueReoccurredDeviceCount), Attrs: telemetry.Attrs{semconv.AttrScriptName: name, semconv.AttrPhase: phaseRemediation, semconv.AttrState: remediationStateReoccurred}},
			telemetry.GaugePoint{Value: float64(rs.RemediationScriptErrorDeviceCount), Attrs: telemetry.Attrs{semconv.AttrScriptName: name, semconv.AttrPhase: phaseRemediation, semconv.AttrState: remediationStateError}},
		)
		cumPts = append(cumPts, telemetry.GaugePoint{
			Value: float64(rs.IssueRemediatedCumulativeDeviceCount),
			Attrs: telemetry.Attrs{semconv.AttrScriptName: name},
		})
	}
	return pts, cumPts, nil
}

// collectRemediationOverview reads the tenant-wide getRemediationSummary()
// singleton and emits the two cross-check scalar gauges.
func (c *Collector) collectRemediationOverview(ctx context.Context, e telemetry.Emitter) error {
	body, err := c.g.RawGet(ctx, c.baseURL+remediationSummaryPath)
	if err != nil {
		return err
	}
	var ov remediationOverview
	if err := json.Unmarshal(body, &ov); err != nil {
		return fmt.Errorf("decode getRemediationSummary: %w", err)
	}
	e.Gauge(remediationOverviewScriptCountName, "{script}",
		"Tenant-wide count of health scripts deployed (getRemediationSummary() cross-check).",
		float64(ov.ScriptCount), nil)
	e.Gauge(remediationOverviewRemediatedName, "{device}",
		"Tenant-wide count of devices remediated by health scripts (getRemediationSummary() cross-check).",
		float64(ov.RemediatedDeviceCount), nil)
	return nil
}

// isUnavailable reports whether err is a 4xx from a beta endpoint being
// unavailable/unlicensed on the tenant (403 forbidden, 404 not found) - an
// expected "no data here" condition, not a failure.
func isUnavailable(err error) bool {
	s := err.Error()
	return strings.Contains(s, "status 403") || strings.Contains(s, "status 404")
}

func orUnknown(s string) string {
	if s == "" {
		return "unknown"
	}
	return s
}

var _ collector.SnapshotCollector = (*Collector)(nil)
var _ collectors.Experimental = (*Collector)(nil)

func init() {
	collectors.Register(func(d collectors.Deps) collector.SnapshotCollector {
		return New(d.Graph, d.Logger)
	})
}
