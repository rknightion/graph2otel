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
	"github.com/rknightion/graph2otel/internal/defender/productstatus"
	"github.com/rknightion/graph2otel/internal/exportjob"
	"github.com/rknightion/graph2otel/internal/preflight"
	"github.com/rknightion/graph2otel/internal/semconv"
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
	colDeviceID      = "DeviceId"
	colDeviceName    = "DeviceName"
	colUPN           = "UPN"
	colDeviceState   = "DeviceState"
	colProductStatus = "ProductStatus"
	// colDeviceStateLoc is the localized sibling Microsoft returns alongside
	// DeviceState. LIVE-MEASURED 2026-07-17 (#142): it arrives whether or not
	// it is selected (selecting only DeviceState still yields DeviceState_loc),
	// so it is NOT added to selectColumns - sending it would be requesting a
	// column the report does not accept in a select list.
	colDeviceStateLoc            = "DeviceState_loc"
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

// productStatusMetricName is the bounded device-count-by-ProductStatus-flag
// gauge, a top-line breakdown over every returned row (not just the unhealthy
// ones the signal gauge and per-device logs cover).
//
// Like the sibling count{signal} gauge this is a set of INDEPENDENT counts,
// not a partition: ProductStatus is a bitmask, so a device setting several
// flags is counted under each, and the points can sum to more than the fleet
// size. See productStatusFlags (#142).
const productStatusMetricName = "intune.defender_agents.product_status"

// ProductStatus label values for the two shapes that are not a flag bit. Both
// are shared with the entity transport (#156): they are states BOTH transports
// reach, by different routes, so they must carry one label each.
const (
	// productStatusNoStatus is windowsDefenderProductStatus's `noStatus`
	// member, whose value is 0 — the absence of every flag. It is NOT the same
	// thing as noStatusFlagsSet (2^19), which is an actual set bit meaning
	// "Defender reported, and reported nothing wrong". A bit-walk over 0 emits
	// nothing at all, so 0 is special-cased here rather than letting those
	// devices silently vanish from the gauge. (The entity transport reaches the
	// same value from the literal name "noStatus" — hence one shared constant.)
	productStatusNoStatus = productstatus.NoStatus
	// productStatusUnknown is the label for an absent or unparseable
	// ProductStatus column. Distinct from no_status (a real reported value).
	productStatusUnknown = productstatus.Unknown
)

// productStatusFlags decodes the DefenderAgents ProductStatus column, which is
// a BITMASK of windowsDefenderProductStatus flags, keyed by bit VALUE.
//
// LIVE-MEASURED 2026-07-17 (#142, probed as graph2otel-poller): the column
// returns a raw integer — '524288' and '524416' on the live fleet — and gets
// NO ProductStatus_loc sibling at ANY localizationType, including an explicit
// LocalizedValuesAsAdditionalColumn. DeviceState on the same report DOES get
// one. So Microsoft itself does not treat this column as a localizable enum,
// and there is no server-side decode to lean on: the decode has to happen
// here.
//
// Evidence classes differ within this table, and that matters:
//   - That the column is a bitmask, and the decomposition of the two live
//     values, is arithmetic over LIVE-MEASURED data: 524288 = 2^19, and
//     524416 = 2^19 + 2^7. A single value carrying two flags is why the
//     predecessor of this table — a scalar, name-keyed lookup — could not have
//     worked even if it had been keyed correctly.
//   - Bits 19 and 7 are LIVE-CONFIRMED, and by two independent transports
//     rather than one. The same three devices were read back through the
//     entity form (GET managedDevices/{id}/windowsProtectionState), which
//     serializes this enum as NAMES instead of an integer, and the two agree
//     device-for-device: HAMRIG and LAPHAM export 524288 and report
//     "noStatusFlagsSet"; DESKTOP-CB3D9AB exports 524416 and reports
//     "noQuickScanHappenedForSpecifiedPeriod,noStatusFlagsSet". So 2^19 is
//     noStatusFlagsSet and 2^7 is noQuickScanHappenedForSpecifiedPeriod on the
//     wire, not merely in the docs.
//   - Every OTHER bit position below is DOCS-ONLY, from Microsoft's
//     windowsDefenderProductStatus reference
//     (https://learn.microsoft.com/en-us/graph/api/resources/intune-devices-windowsdefenderproductstatus),
//     and Microsoft's published tables have been wrong or incomplete on
//     essentially every load-bearing detail on this project (#100, #142). Treat
//     an unobserved bit as a hypothesis; productStatusesFor names any bit
//     absent from this table rather than discarding it, so a wrong or missing
//     entry surfaces as unknown_bit_<n> instead of silently vanishing.
//
// This map is THIS TRANSPORT'S WIRE KNOWLEDGE ONLY - the bit positions. It
// spells no value itself: every value is a constant from
// internal/defender/productstatus, the one canonical vocabulary, which the entity
// transport's name-keyed table (malware.productStatusValues) reads the same
// constants from (#156). Each transport keeps its own decoder because the wire
// formats genuinely differ; neither keeps its own vocabulary, because a device's
// state must not produce a different label value depending on which transport
// observed it.
//
// CORRECTION (#156, verified against git history 2026-07-17): this comment
// previously claimed "the snake_case values are carried over verbatim from the
// name-keyed map this replaced, so the label vocabulary ... is unchanged". That
// was FALSE. #142 introduced a transcription slip at bit 24 - it wrote
// "..._non_win10_s_install" where the name-keyed map read
// "..._non_win10s_install" - so one enum member had two label values across the
// two transports until #150 converged them by hand and #156 removed the second
// source of truth entirely. The claim is the reason the drift went unexamined:
// "carried over verbatim" reads as a reason not to check. Verbatim-carry is now
// enforced by the compiler rather than asserted in a comment.
var productStatusFlags = map[int64]string{
	1 << 0:  productstatus.ServiceNotRunning,
	1 << 1:  productstatus.ServiceStartedWithoutMalwareProtection,
	1 << 2:  productstatus.PendingFullScanDueToThreatAction,
	1 << 3:  productstatus.PendingRebootDueToThreatAction,
	1 << 4:  productstatus.PendingManualStepsDueToThreatAction,
	1 << 5:  productstatus.AVSignaturesOutOfDate,
	1 << 6:  productstatus.ASSignaturesOutOfDate,
	1 << 7:  productstatus.NoQuickScanHappenedForSpecifiedPeriod, // live-observed (524416)
	1 << 8:  productstatus.NoFullScanHappenedForSpecifiedPeriod,
	1 << 9:  productstatus.SystemInitiatedScanInProgress,
	1 << 10: productstatus.SystemInitiatedCleanInProgress,
	1 << 11: productstatus.SamplesPendingSubmission,
	1 << 12: productstatus.ProductRunningInEvaluationMode,
	1 << 13: productstatus.ProductRunningInNonGenuineMode,
	1 << 14: productstatus.ProductExpired,
	1 << 15: productstatus.OfflineScanRequired,
	1 << 16: productstatus.ServiceShutdownAsPartOfSystemShutdown,
	1 << 17: productstatus.ThreatRemediationFailedCritically,
	1 << 18: productstatus.ThreatRemediationFailedNonCritically,
	1 << 19: productstatus.NoStatusFlagsSet, // live-observed (524288, 524416)
	1 << 20: productstatus.PlatformOutOfDate,
	1 << 21: productstatus.PlatformUpdateInProgress,
	1 << 22: productstatus.PlatformAboutToBeOutdated,
	1 << 23: productstatus.SignatureOrPlatformEndOfLifeIsPastOrIsImpending,
	// The #156 flag: the bit whose value this transport and the entity transport
	// rendered two different ways. Both now read the same constant.
	1 << 24: productstatus.WindowsSModeSignaturesInUseOnNonWin10SInstall,
}

// productStatusesFor decodes a raw ProductStatus bitmask into every flag it
// sets. It returns a SLICE, not a single value, because the field is a flags
// field: the live value 524416 carries two flags at once, so no single-valued
// `status` label could ever represent it faithfully.
//
// The returned set is bounded — at most 64 entries, one per bit — so it is
// safe as a metric label despite being per-row derived.
//
// An unrecognized bit becomes unknown_bit_<n> rather than "other" or nothing:
// #142 shipped precisely because a catch-all bucket made a total decode
// failure look like a healthy steady state, so an unmapped bit here names
// itself and stays diagnosable.
func productStatusesFor(raw string) []string {
	v, err := strconv.ParseInt(strings.TrimSpace(raw), 10, 64)
	if err != nil {
		return []string{productStatusUnknown}
	}
	if v == 0 {
		return []string{productStatusNoStatus}
	}

	var out []string
	for bit := 0; bit < 63; bit++ {
		mask := int64(1) << bit
		if v&mask == 0 {
			continue
		}
		if name, ok := productStatusFlags[mask]; ok {
			out = append(out, name)
			continue
		}
		out = append(out, "unknown_bit_"+strconv.Itoa(bit))
	}
	if len(out) == 0 {
		// Only reachable for a negative value (sign bit only), which the API
		// has never sent; kept so the function is total.
		return []string{productStatusUnknown}
	}
	return out
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
	// Stamped here because no engine can: internal/exportjob never calls
	// LogEvent, so report_export has no engine seam (#141). See
	// appinstallreport.Collect for the full reasoning.
	e = telemetry.WithTransport(e, telemetry.TransportReportExport)

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
		// One increment per SET FLAG, not per row: ProductStatus is a bitmask,
		// so a device reporting 524416 legitimately counts under both of its
		// flags. This mirrors the sibling count{signal} gauge, which is already
		// documented as a set of independent counts rather than a partition of
		// the fleet - the same thing is true here for the same reason.
		for _, status := range productStatusesFor(row[colProductStatus]) {
			statusCounts[status]++
		}

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
				semconv.AttrDeviceId:   row[colDeviceID],
				semconv.AttrDeviceName: row[colDeviceName],
				semconv.AttrUpn:        row[colUPN],
				// device_state carries Microsoft's own localized rendering of
				// the DeviceState code, taken from the _loc sibling that
				// arrives unrequested. Read from the wire rather than decoded
				// against a table because only code 0 ("Clean") has ever been
				// observed live (#142) - a table for the rest would be a
				// guess. _loc is safe HERE, unlike on a metric label: a log
				// attribute creates no series, so its locale-dependence (live
				// 2026-07-17: casing shifts under Accept-Language) costs
				// nothing, and device_state_code below is the stable value.
				semconv.AttrDeviceState:     row[colDeviceStateLoc],
				semconv.AttrDeviceStateCode: row[colDeviceState],
				// product_status is the decoded flag set, comma-joined; a
				// bitmask can hold several flags at once (live: 524416 = two),
				// so this is deliberately not a single value.
				semconv.AttrProductStatus: strings.Join(productStatusesFor(row[colProductStatus]), ","),
				// The raw bitmask is emitted unconditionally alongside it, per
				// the house pattern (m365/activity's record_type_id): the
				// lossless value must survive a decode miss, since most bits
				// in productStatusFlags are docs-only and Microsoft's tables
				// have been wrong before on this project.
				semconv.AttrProductStatusCode:              row[colProductStatus],
				semconv.AttrRealTimeProtectionEnabled:      row[colRealTimeProtectionEnabled],
				semconv.AttrNetworkInspectionSystemEnabled: row[colNetworkInspectionSystemOn],
				semconv.AttrSignatureUpdateOverdue:         row[colSignatureUpdateOverdue],
				semconv.AttrTamperProtectionEnabled:        row[colTamperProtectionEnabled],
				semconv.AttrMalwareProtectionEnabled:       row[colMalwareProtectionEnabled],
			},
		})
	}

	points := make([]telemetry.GaugePoint, 0, len(counts))
	for signal, v := range counts {
		points = append(points, telemetry.GaugePoint{
			Value: float64(v),
			Attrs: telemetry.Attrs{semconv.AttrSignal: signal},
		})
	}
	e.GaugeSnapshot(signalCountMetricName, "{device}", "Intune managed devices by Defender agent health signal, from the DefenderAgents export report.", points)

	statusPoints := make([]telemetry.GaugePoint, 0, len(statusCounts))
	for status, v := range statusCounts {
		statusPoints = append(statusPoints, telemetry.GaugePoint{
			Value: float64(v),
			Attrs: telemetry.Attrs{semconv.AttrStatus: status},
		})
	}
	e.GaugeSnapshot(productStatusMetricName, "{device}", "Intune managed devices by Windows Defender ProductStatus flag, from the DefenderAgents export report. ProductStatus is a bitmask: a device setting several flags is counted under each, so these points are independent counts and can sum to more than the fleet size.", statusPoints)

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
