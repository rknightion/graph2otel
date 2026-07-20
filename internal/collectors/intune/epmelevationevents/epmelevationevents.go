// Package epmelevationevents is the Intune Endpoint Privilege Management (EPM)
// per-elevation event collector (BETA): one log record per privilege elevation
// on a managed device — which binary was run elevated, by whom, on which device,
// under what (if any) EPM policy, and whether it was governed. It is the
// per-event SIEM stream behind the intune.epm_elevations aggregate (this
// package's sibling, EpmAggregationReportByApplication, which counts elevations
// by application): the aggregate answers "how many", this answers "which one,
// when, on which device, by which user".
//
// Source: the EpmElevationReportElevationEvent export report (live-verified
// 2026-07-20 on m7kni, probed as graph2otel-poller: 43 rows). Two wire traps make
// it NOT a clean snapshot clone (#205):
//
//   - It is an EVENT stream — each row has an immutable Id and a real EventDateTime
//     — so re-exporting the whole report every 6h would re-emit every elevation as
//     a duplicate log line, and old events would be rejected at the backend's ingest
//     (stale event time). It therefore checkpoints a watermark + a SeenIDs set over
//     the export transport (the same checkpoint.Store the window collectors use)
//     and emits each event exactly once, stamped with its own EventDateTime.
//   - EventDateTime is NOT RFC3339: the export CSV renders it as
//     "2026-07-19 19:10:54.0000000" (space separator, 7 fractional digits, no zone,
//     UTC). Parsing it as RFC3339 would fail for every row, and a row with no
//     parseable event time is DROPPED (never stamped "now", which would misdate it).
//     "<Null>" and "" are sentinels for absent columns and are treated as absent.
//
// Cardinality (#112/#114): every per-event field — the event Id, UPN, device,
// file path, hash, parent process — rides the intune.epm_elevation_events log twin
// and NEVER a metric label. The metric is a bounded monotonic counter keyed only
// by (elevation_type, result), both small EPM enums, incremented once per newly
// observed event. Guard test.
package epmelevationevents

import (
	"context"
	"errors"
	"log/slog"
	"strings"
	"time"

	"github.com/rknightion/graph2otel/internal/checkpoint"
	"github.com/rknightion/graph2otel/internal/collector"
	"github.com/rknightion/graph2otel/internal/collectors"
	"github.com/rknightion/graph2otel/internal/exportjob"
	"github.com/rknightion/graph2otel/internal/preflight"
	"github.com/rknightion/graph2otel/internal/semconv"
	"github.com/rknightion/graph2otel/internal/telemetry"
)

const (
	collectorName = "intune.epm_elevation_events"
	metricName    = "intune.epm_elevation_events.count"
	eventName     = "intune.epm_elevation_events"
	reportName    = "EpmElevationReportElevationEvent"
	// endpoint is this collector's checkpoint namespace (the endpoint component
	// of the (tenant, endpoint) key). It never collides with exportjob's
	// in-flight JobRecord for the same report: checkpoint.jobFileKey prefixes
	// those with "jobrecord\x00", a separate file (#118).
	endpoint = "export/EpmElevationReportElevationEvent"
	// unmanagedElevation is the ElevationType meaning the elevation was NOT
	// governed by an EPM policy — the security-relevant case, escalated to WARN
	// (same as the intune.epm_elevations aggregate sibling).
	unmanagedElevation = "UnmanagedElevation"
	// nullSentinel is the literal the export CSV writes for an absent column
	// (e.g. RuleId/PolicyId on an unmanaged elevation); treated as absent.
	nullSentinel = "<Null>"
	// overlapWindow is how far behind the watermark a poll still considers events
	// for dedupe. Set well beyond the report's retained window so SeenIDs alone
	// dedupes every row the report returns (it is tiny — tens of rows) and the
	// "older than overlap → already emitted" skip is only a backstop; this makes
	// dedupe exact even against out-of-order/late-arriving rows within retention.
	overlapWindow = 30 * 24 * time.Hour
)

// eventTimeLayouts are tried in order to parse EventDateTime. The first is the
// live-observed Intune export CSV format; RFC3339 variants are cheap fallbacks so
// a format change does not silently drop the whole stream.
var eventTimeLayouts = []string{
	"2006-01-02 15:04:05.0000000",
	time.RFC3339Nano,
	time.RFC3339,
}

// selectColumns pins the export columns (Microsoft's default set can change).
// All are live-confirmed on the report's default output, so an explicit select
// does not 400 (no localized _loc column is named — the #203 trap).
var selectColumns = []string{
	"Id", "DeviceId", "DeviceName", "EventDateTime", "ElevationType",
	"FilePath", "Upn", "UserType", "ProductName", "CompanyName",
	"FileVersion", "Justification", "Hash", "InternalName",
	"FileDescription", "Result", "ProcessType", "RuleId",
	"ParentProcessName", "PolicyId", "PolicyName", "IsSystemInitiated",
}

// Collector polls EpmElevationReportElevationEvent through the shared export-job
// subsystem and checkpoints a watermark + SeenIDs so each elevation emits once.
type Collector struct {
	export   exportjob.Runner
	store    *checkpoint.Store
	tenantID string
	logger   *slog.Logger
}

// New builds the collector. A nil export or store makes Collect a no-op (it would
// otherwise re-emit every elevation every poll); a nil logger defaults.
func New(export exportjob.Runner, store *checkpoint.Store, tenantID string, logger *slog.Logger) *Collector {
	if logger == nil {
		logger = slog.Default()
	}
	return &Collector{export: export, store: store, tenantID: tenantID, logger: logger}
}

func (c *Collector) Name() string { return collectorName }

func (c *Collector) IngestTransport() telemetry.Transport {
	return telemetry.TransportReportExport
}

func (c *Collector) DefaultInterval() time.Duration { return 6 * time.Hour }

func (c *Collector) Experimental() bool { return true }

// RequiredPermissions declares the least-privilege Graph application scope — the
// write scope creates the export job and nothing else (the export gotcha).
func (c *Collector) RequiredPermissions() []string {
	return []string{"DeviceManagementManagedDevices.ReadWrite.All"}
}

// Collect runs the export job, then emits each elevation event NOT already seen
// (deduped by immutable Id against the persisted overlap-window SeenIDs), stamped
// with its own EventDateTime, and increments a bounded counter by
// (elevation_type, result). Export failures are logged and swallowed, never
// surfaced to the scheduler.
func (c *Collector) Collect(ctx context.Context, e telemetry.Emitter) error {
	// This collector names its own transport (#141): exportjob never calls LogEvent.
	e = telemetry.WithTransport(e, telemetry.TransportReportExport)

	if c.export == nil || c.store == nil {
		c.logger.Info("epmelevationevents: no export runner or checkpoint store configured; skipping", "collector", collectorName)
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

	cp, err := c.store.Load(c.tenantID, endpoint)
	if err != nil {
		// Corrupt/unreadable checkpoint: degrade to an empty one (a single cold
		// start's worth of possible re-emit) rather than fail the collector — the
		// same call the window engine makes on ErrCorruptCheckpoint.
		c.logger.Warn("epmelevationevents: checkpoint load failed; starting from empty", "collector", collectorName, "error", err)
		cp = &checkpoint.Checkpoint{TenantID: c.tenantID, Endpoint: endpoint, SeenIDs: checkpoint.NewSeenIDs()}
	}
	// Ensure the key fields are set for Save even on a freshly-loaded cold start.
	cp.TenantID, cp.Endpoint = c.tenantID, endpoint
	if cp.SeenIDs == nil {
		cp.SeenIDs = checkpoint.NewSeenIDs()
	}

	cutoff := cp.Watermark.Add(-overlapWindow)
	counts := map[[2]string]float64{}
	newest := cp.Watermark
	sawAny := false

	for _, row := range rows {
		id := row["Id"]
		if id == "" {
			// No immutable id ⇒ undedupeable ⇒ would re-emit every poll. Drop it
			// (loudly), rather than dup-storm the backend.
			c.logger.Warn("epmelevationevents: elevation row has no Id; dropping (undedupeable)", "collector", collectorName)
			continue
		}
		t, ok := parseEventTime(row["EventDateTime"])
		if !ok {
			// No parseable event time ⇒ emitting would stamp "now" and misdate it.
			c.logger.Warn("epmelevationevents: unparseable EventDateTime; dropping row", "collector", collectorName, "id", id, "value", row["EventDateTime"])
			continue
		}
		if t.Before(cutoff) {
			continue // older than the overlap window: emitted on a prior poll and evicted.
		}
		if cp.SeenIDs.Has(id) {
			continue // already emitted within the current overlap window.
		}

		e.LogEvent(elevationEvent(row, t))
		cp.SeenIDs.Add(id, t)
		counts[[2]string{row["ElevationType"], clean(row["Result"])}]++
		if !sawAny || t.After(newest) {
			newest = t
		}
		sawAny = true
	}

	for k, v := range counts {
		e.Counter(metricName, "{event}",
			"Intune EPM privilege elevations newly observed, counted by elevation type and result; per-event detail (device, user, file, hash) on the intune.epm_elevation_events log twin.",
			v, telemetry.Attrs{semconv.AttrElevationType: k[0], semconv.AttrResult: k[1]})
	}

	if sawAny && newest.After(cp.Watermark) {
		cp.Watermark = newest
	}
	cp.OverlapWindow = overlapWindow
	cp.EvictStale()
	if err := c.store.Save(cp); err != nil {
		// A save failure means the next poll re-dedupes from the last good
		// checkpoint (at worst re-emitting this poll's new events once). Degrade,
		// don't fail — the events already emitted are not lost.
		c.logger.Warn("epmelevationevents: checkpoint save failed", "collector", collectorName, "error", err)
	}
	return nil
}

// elevationEvent builds the per-event twin, stamped with the event's own time.
// Severity escalates to WARN for an unmanaged elevation (a user elevating outside
// any EPM policy — the security signal), matching the aggregate sibling.
func elevationEvent(row exportjob.Row, t time.Time) telemetry.Event {
	attrs := telemetry.Attrs{}
	telemetry.SetStr(attrs, semconv.AttrElevationId, clean(row["Id"]))
	telemetry.SetStr(attrs, semconv.AttrDeviceId, clean(row["DeviceId"]))
	telemetry.SetStr(attrs, semconv.AttrDeviceName, clean(row["DeviceName"]))
	telemetry.SetStr(attrs, semconv.AttrElevationType, clean(row["ElevationType"]))
	telemetry.SetStr(attrs, semconv.AttrFilePath, clean(row["FilePath"]))
	telemetry.SetStr(attrs, semconv.AttrUpn, clean(row["Upn"]))
	telemetry.SetStr(attrs, semconv.AttrUserType, clean(row["UserType"]))
	telemetry.SetStr(attrs, semconv.AttrProductName, clean(row["ProductName"]))
	telemetry.SetStr(attrs, semconv.AttrCompanyName, clean(row["CompanyName"]))
	telemetry.SetStr(attrs, semconv.AttrFileVersion, clean(row["FileVersion"]))
	telemetry.SetStr(attrs, semconv.AttrJustification, clean(row["Justification"]))
	telemetry.SetStr(attrs, semconv.AttrFileHash, clean(row["Hash"]))
	telemetry.SetStr(attrs, semconv.AttrInternalName, clean(row["InternalName"]))
	telemetry.SetStr(attrs, semconv.AttrFileDescription, clean(row["FileDescription"]))
	telemetry.SetStr(attrs, semconv.AttrResult, clean(row["Result"]))
	telemetry.SetStr(attrs, semconv.AttrProcessType, clean(row["ProcessType"]))
	telemetry.SetStr(attrs, semconv.AttrRuleId, clean(row["RuleId"]))
	telemetry.SetStr(attrs, semconv.AttrParentProcessName, clean(row["ParentProcessName"]))
	telemetry.SetStr(attrs, semconv.AttrPolicyId, clean(row["PolicyId"]))
	telemetry.SetStr(attrs, semconv.AttrPolicyName, clean(row["PolicyName"]))
	telemetry.SetStr(attrs, semconv.AttrIsSystemInitiated, clean(row["IsSystemInitiated"]))

	severity := telemetry.SeverityInfo
	if row["ElevationType"] == unmanagedElevation {
		severity = telemetry.SeverityWarn
	}

	return telemetry.Event{
		Name:      eventName,
		Body:      "Intune EPM privilege elevation event",
		Severity:  severity,
		Timestamp: t,
		Attrs:     attrs,
	}
}

// parseEventTime parses the export CSV's EventDateTime, trying the live-observed
// space-separated 7-fractional-digit UTC format first, then RFC3339 fallbacks.
// ok is false when the value is empty or matches no layout — the caller drops the
// row rather than emit it stamped "now".
func parseEventTime(s string) (time.Time, bool) {
	s = strings.TrimSpace(s)
	if s == "" || s == nullSentinel {
		return time.Time{}, false
	}
	for _, layout := range eventTimeLayouts {
		if t, err := time.Parse(layout, s); err == nil {
			return t.UTC(), true
		}
	}
	return time.Time{}, false
}

// clean maps the export's absent-value sentinels ("<Null>" and "") to "", so
// telemetry.SetStr omits the attribute rather than emitting the sentinel verbatim.
func clean(s string) string {
	if s == nullSentinel {
		return ""
	}
	return s
}

func logExportFailure(logger *slog.Logger, err error) {
	switch {
	case errors.Is(err, exportjob.ErrJobFailed):
		logger.Warn("epmelevationevents: export job failed", "collector", collectorName, "report_name", reportName, "error", err)
	case errors.Is(err, exportjob.ErrSASExpired):
		logger.Warn("epmelevationevents: export SAS url expired before download", "collector", collectorName, "report_name", reportName, "error", err)
	case strings.Contains(err.Error(), "status 403"):
		logger.Info("epmelevationevents: export job creation forbidden (missing write scope?); skipping", "collector", collectorName, "report_name", reportName, "error", err)
	default:
		logger.Warn("epmelevationevents: export failed", "collector", collectorName, "report_name", reportName, "error", err)
	}
}

var (
	_ collector.SnapshotCollector  = (*Collector)(nil)
	_ collectors.Experimental      = (*Collector)(nil)
	_ preflight.PermissionRequirer = (*Collector)(nil)
)

func init() {
	collectors.Register(func(d collectors.Deps) collector.SnapshotCollector {
		return New(d.Export, d.Store, d.TenantID, d.Logger)
	})
}
