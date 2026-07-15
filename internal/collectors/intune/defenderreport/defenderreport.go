// Package defenderreport is the Intune fleet-wide Windows Defender agent
// health collector (BETA, M5 #42): device counts by Defender health signal,
// from the DefenderAgents export report.
//
// Per-device Defender/antimalware agent health does not batch through a
// regular Graph GET at fleet scale (the live windowsProtectionState entity
// is one call per device - 10k+ devices would blow the throttling budget),
// so this collector is built entirely on the reports export API
// (internal/exportjob, #17) rather than treating export as a fallback.
//
// Report shape: DefenderAgents returns one row per device, already carrying
// the per-device health flags this collector needs - no separate
// aggregate-count report to cross-check against. This collector aggregates
// those rows itself into a bounded, fixed set of health-signal counts for
// the metric, and emits only the unhealthy rows (any signal tripped) as
// logs, so per-device detail (device id/name, UPN, raw flag values) never
// becomes a metric label - see the project's cardinality/PII guidance.
//
// reportName and selectColumns are live-smoke-tested (2026-07-15): the
// initial selectColumns guess 400'd against a real tenant even though
// reportName was already correct, and got corrected to the exact column set
// below (see Microsoft's export-reports reference,
// https://learn.microsoft.com/en-us/mem/intune/fundamentals/reports-export-graph-available-reports).
// If this collector ever 400s again, re-verify this list first - per the
// project's export-report gotcha, an unrecognized column/report name gets
// no fuzzy match.
//
// UnhealthyDefenderAgents (mentioned as an optional companion report in the
// tracking issue) is deliberately NOT consumed: per Microsoft's documented
// schema it exposes the exact same columns as DefenderAgents, so it would
// just be the same per-device rows pre-filtered server-side - this
// collector already derives that filter client-side (see unhealthy below),
// making a second export job redundant. Likewise the optional
// windowsMalwareOverview singleton cross-check is skipped here: the M4
// intune/malware collector already emits that overview, so consuming it
// again from this collector would duplicate a signal rather than add one.
// Also note windowsMalwareInformation (a different resource entirely) is
// the malware DEFINITIONS catalog, not device health - this collector never
// touches it.
package defenderreport

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
const collectorName = "intune.defender_agents"

// signalCountMetricName is the bounded device-count-by-health-signal gauge
// this collector emits. Signals are not mutually exclusive - one device can
// trip several in the same row - so this is a set of independent counts,
// not a partition of the fleet.
const signalCountMetricName = "intune.defender_agents.count"

// eventName is the OTLP LogRecord EventName every unhealthy per-device row
// carries.
const eventName = "intune.defender_agent"

// reportName is the export report catalog name this collector requests.
// Live-smoke-tested (2026-07-15) against a real tenant; per the project's
// export-report gotcha a typo in this name 400s with no fuzzy match.
const reportName = "DefenderAgents"

// Export column names, live-smoke-tested (2026-07-15) against the
// DefenderAgents report - see the package doc's smoke-test note. Kept as
// individual consts (rather than inlined into selectColumns) so any future
// correction touches one place instead of every reference to it in this
// file.
const (
	colDeviceID                  = "DeviceId"
	colDeviceName                = "DeviceName"
	colUPN                       = "UPN"
	colDeviceState               = "DeviceState"
	colProductStatus             = "ProductStatus"
	colRealTimeProtectionEnabled = "RealTimeProtectionEnabled"
	colNetworkInspectionSystemOn = "NetworkInspectionSystemEnabled"
	colSignatureUpdateOverdue    = "SignatureUpdateOverdue"
	colTamperProtectionEnabled   = "TamperProtectionEnabled"
	colMalwareProtectionEnabled  = "MalwareProtectionEnabled"
)

// selectColumns are the export columns this collector requests. Cannot be a
// const (Go slices aren't constant-expressible); this var is the frozen,
// live-verified equivalent - every entry is one of the colXxx consts above,
// so a correction there is the one place to change it.
var selectColumns = []string{
	colDeviceID,
	colDeviceName,
	colUPN,
	colDeviceState,
	colProductStatus,
	colRealTimeProtectionEnabled,
	colNetworkInspectionSystemOn,
	colSignatureUpdateOverdue,
	colTamperProtectionEnabled,
	colMalwareProtectionEnabled,
}

// The fixed, bounded set of Defender health signals this collector counts.
// Each is a documented DefenderAgents boolean column read in its unhealthy
// direction (protection/inspection "off", signature "overdue"). Signals are
// independent, not a partition - one device can trip several.
const (
	signalRealTimeProtectionOff  = "real_time_protection_off"
	signalSignatureUpdateOverdue = "signature_update_overdue"
	signalTamperProtectionOff    = "tamper_protection_off"
	signalMalwareProtectionOff   = "malware_protection_off"
	signalNetworkInspectionOff   = "network_inspection_off"
)

// rowSignals is one row's evaluated health signals.
type rowSignals struct {
	realTimeProtectionOff  bool
	signatureUpdateOverdue bool
	tamperProtectionOff    bool
	malwareProtectionOff   bool
	networkInspectionOff   bool
}

// any reports whether at least one signal tripped - the row is "unhealthy"
// and should be logged.
func (s rowSignals) any() bool {
	return s.realTimeProtectionOff || s.signatureUpdateOverdue || s.tamperProtectionOff ||
		s.malwareProtectionOff || s.networkInspectionOff
}

// tripped returns the names of every signal that tripped, for the count
// gauge.
func (s rowSignals) tripped() []string {
	var names []string
	if s.realTimeProtectionOff {
		names = append(names, signalRealTimeProtectionOff)
	}
	if s.signatureUpdateOverdue {
		names = append(names, signalSignatureUpdateOverdue)
	}
	if s.tamperProtectionOff {
		names = append(names, signalTamperProtectionOff)
	}
	if s.malwareProtectionOff {
		names = append(names, signalMalwareProtectionOff)
	}
	if s.networkInspectionOff {
		names = append(names, signalNetworkInspectionOff)
	}
	return names
}

// evaluateSignals reads a DefenderAgents row's flag columns and derives its
// rowSignals. A missing/malformed "enabled" column defaults to enabled
// (true) and a missing/malformed "overdue" column defaults to not-overdue
// (false) - malformed data should never manufacture a false alert.
func evaluateSignals(row exportjob.Row) rowSignals {
	return rowSignals{
		realTimeProtectionOff:  !rowBoolDefault(row, colRealTimeProtectionEnabled, true),
		signatureUpdateOverdue: rowBoolDefault(row, colSignatureUpdateOverdue, false),
		tamperProtectionOff:    !rowBoolDefault(row, colTamperProtectionEnabled, true),
		malwareProtectionOff:   !rowBoolDefault(row, colMalwareProtectionEnabled, true),
		networkInspectionOff:   !rowBoolDefault(row, colNetworkInspectionSystemOn, true),
	}
}

// productStatusMetricName is the bounded device-count-by-ProductStatus
// gauge, a top-line breakdown over every returned row (not just the
// unhealthy ones the signal gauge and per-device logs cover).
const productStatusMetricName = "intune.defender_agents.product_status"

// productStatusBuckets maps every documented windowsDefenderProductStatus
// enum value (https://learn.microsoft.com/en-us/graph/api/resources/intune-devices-windowsdefenderproductstatus)
// to its snake_case bounded attribute value, case-insensitively. Anything
// not in this map (a future enum addition, or an unexpected/empty value)
// falls into "other" rather than growing the label's cardinality.
var productStatusBuckets = map[string]string{
	"nostatus":                                        "no_status",
	"servicenotrunning":                               "service_not_running",
	"servicestartedwithoutmalwareprotection":          "service_started_without_malware_protection",
	"pendingfullscanduetothreataction":                "pending_full_scan_due_to_threat_action",
	"pendingrebootduetothreataction":                  "pending_reboot_due_to_threat_action",
	"pendingmanualstepsduetothreataction":             "pending_manual_steps_due_to_threat_action",
	"avsignaturesoutofdate":                           "av_signatures_out_of_date",
	"assignaturesoutofdate":                           "as_signatures_out_of_date",
	"noquickscanhappenedforspecifiedperiod":           "no_quick_scan_happened_for_specified_period",
	"nofullscanhappenedforspecifiedperiod":            "no_full_scan_happened_for_specified_period",
	"systeminitiatedscaninprogress":                   "system_initiated_scan_in_progress",
	"systeminitiatedcleaninprogress":                  "system_initiated_clean_in_progress",
	"samplespendingsubmission":                        "samples_pending_submission",
	"productrunninginevaluationmode":                  "product_running_in_evaluation_mode",
	"productrunninginnongenuinemode":                  "product_running_in_non_genuine_mode",
	"productexpired":                                  "product_expired",
	"offlinescanrequired":                             "offline_scan_required",
	"serviceshutdownaspartofsystemshutdown":           "service_shutdown_as_part_of_system_shutdown",
	"threatremediationfailedcritically":               "threat_remediation_failed_critically",
	"threatremediationfailednoncritically":            "threat_remediation_failed_non_critically",
	"nostatusflagsset":                                "no_status_flags_set",
	"platformoutofdate":                               "platform_out_of_date",
	"platformupdateinprogress":                        "platform_update_in_progress",
	"platformabouttobeoutdated":                       "platform_about_to_be_outdated",
	"signatureorplatformendoflifeispastorisimpending": "signature_or_platform_end_of_life_is_past_or_is_impending",
	"windowssmodesignaturesinuseonnonwin10sinstall":   "windows_s_mode_signatures_in_use_on_non_win10_s_install",
}

// productStatusBucketFor buckets a row's raw ProductStatus value, case
// insensitively. See productStatusBuckets.
func productStatusBucketFor(raw string) string {
	if b, ok := productStatusBuckets[strings.ToLower(raw)]; ok {
		return b
	}
	return "other"
}

// rowBoolDefault parses row[key] as a bool ("true"/"false" per the export
// API's documented flag encoding), falling back to def when the column is
// missing or unparseable.
func rowBoolDefault(row exportjob.Row, key string, def bool) bool {
	v, ok := row[key]
	if !ok {
		return def
	}
	b, err := strconv.ParseBool(v)
	if err != nil {
		return def
	}
	return b
}

// Collector polls the DefenderAgents export report through the shared
// export-job subsystem (internal/exportjob, #17).
type Collector struct {
	export exportjob.Runner
	logger *slog.Logger
}

// New builds the Defender-agents collector. export is typically the
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
// expensive (create + poll + download, sharing the 48-req/min-per-app
// export budget with every other export-based collector on this tenant),
// so this defaults to a much longer cadence than a plain paged fetch.
func (c *Collector) DefaultInterval() time.Duration { return 6 * time.Hour }

// Experimental marks this as a beta, opt-in collector: it depends on the
// export-job subsystem creating a job under a write-level Graph scope (see
// RequiredPermissions), and its Select columns are not yet live-verified
// against a real tenant.
func (c *Collector) Experimental() bool { return true }

// RequiredPermissions declares the least-privilege Graph application scope.
// Creating an export job requires DeviceManagementManagedDevices.ReadWrite.All
// even though this collector only ever reads the result back - Microsoft
// requires a write-level scope just to POST the export-job creation request
// (see the project's export-scope gotcha); this is the one exception to
// least-privileged read-only scoping the export subsystem forces on every
// consumer, not a request for more than that.
func (c *Collector) RequiredPermissions() []string {
	return []string{"DeviceManagementManagedDevices.ReadWrite.All"}
}

// Collect runs the DefenderAgents export job, aggregates its rows into the
// bounded health-signal count gauge, and emits every unhealthy row (any
// signal tripped) as a log event carrying the per-device detail. A fully
// healthy row produces no log. Any export failure (missing write scope, a
// job that reports failed, or a SAS url that expired before download) is
// logged and swallowed rather than treated as a scheduler-visible error -
// see the package doc and the exportjob seam's sentinel errors.
func (c *Collector) Collect(ctx context.Context, e telemetry.Emitter) error {
	if c.export == nil {
		c.logger.Info("defenderreport: no export runner configured; skipping", "collector", collectorName)
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

	counts := map[string]int64{}
	statusCounts := map[string]int64{}
	for _, row := range rows {
		statusCounts[productStatusBucketFor(row[colProductStatus])]++

		signals := evaluateSignals(row)
		if !signals.any() {
			continue
		}
		for _, name := range signals.tripped() {
			counts[name]++
		}

		e.LogEvent(telemetry.Event{
			Name:     eventName,
			Body:     "Intune Defender agent health row",
			Severity: telemetry.SeverityWarn,
			Attrs: telemetry.Attrs{
				"device_id":                         row[colDeviceID],
				"device_name":                       row[colDeviceName],
				"upn":                               row[colUPN],
				"device_state":                      row[colDeviceState],
				"product_status":                    row[colProductStatus],
				"real_time_protection_enabled":      row[colRealTimeProtectionEnabled],
				"network_inspection_system_enabled": row[colNetworkInspectionSystemOn],
				"signature_update_overdue":          row[colSignatureUpdateOverdue],
				"tamper_protection_enabled":         row[colTamperProtectionEnabled],
				"malware_protection_enabled":        row[colMalwareProtectionEnabled],
			},
		})
	}

	points := make([]telemetry.GaugePoint, 0, len(counts))
	for signal, v := range counts {
		points = append(points, telemetry.GaugePoint{
			Value: float64(v),
			Attrs: telemetry.Attrs{"signal": signal},
		})
	}
	e.GaugeSnapshot(signalCountMetricName, "{device}", "Intune managed devices by Defender agent health signal, from the DefenderAgents export report.", points)

	statusPoints := make([]telemetry.GaugePoint, 0, len(statusCounts))
	for status, v := range statusCounts {
		statusPoints = append(statusPoints, telemetry.GaugePoint{
			Value: float64(v),
			Attrs: telemetry.Attrs{"status": status},
		})
	}
	e.GaugeSnapshot(productStatusMetricName, "{device}", "Intune managed devices by Windows Defender ProductStatus, from the DefenderAgents export report.", statusPoints)

	return nil
}

// logExportFailure logs an Export failure at a level matching its cause: a
// missing write scope or a failed/expired job are expected, tenant-side
// conditions worth an operator's attention (Warn); anything else (transport
// failure, malformed response) is also just logged, never escalated to a
// returned error - see the package doc.
func logExportFailure(logger *slog.Logger, err error) {
	switch {
	case errors.Is(err, exportjob.ErrJobFailed):
		logger.Warn("defenderreport: export job failed", "collector", collectorName, "report_name", reportName, "error", err)
	case errors.Is(err, exportjob.ErrSASExpired):
		logger.Warn("defenderreport: export SAS url expired before download", "collector", collectorName, "report_name", reportName, "error", err)
	case strings.Contains(err.Error(), "status 403"):
		logger.Info("defenderreport: export job creation forbidden (missing write scope?); skipping", "collector", collectorName, "report_name", reportName, "error", err)
	default:
		logger.Warn("defenderreport: export failed", "collector", collectorName, "report_name", reportName, "error", err)
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
