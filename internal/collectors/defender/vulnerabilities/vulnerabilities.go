// Package vulnerabilities is the Microsoft Defender threat-and-vulnerability-
// management device-vulnerability collector (#249): which CVEs are present on
// which devices, enriched server-side with CVSS, EPSS and exploit availability.
//
// # Why this is a hunting collector, not blob or Graph REST
//
// The DeviceTvmSoftwareVulnerabilities table has no dedicated Graph REST endpoint
// and is not written to any Defender streaming-export blob container (verified
// against the live container list, #249). The only route to it is the Graph
// advanced-hunting query API (internal/huntclient), so this package sits on the
// hunting registration path (collectors.HuntDeps).
//
// # Both sides of the cardinality boundary, from a fixed number of queries
//
//   - bounded GAUGES from ONE summarize query: instance count, affected-device
//     count, distinct-CVE count, and the worst CVSS/EPSS, each keyed by the
//     severity level and whether an exploit is available. Both dimensions are a
//     small closed set, so the series count never grows with tenant size.
//   - one LOG twin per (device, CVE, software) row carrying the per-entity detail
//     the gauges collapse — which device, which CVE, which software version, and
//     the CVSS/EPSS/exploit/mitigation attributes that turn a count into a ranked
//     worklist. "Not a metric label" means "log twin", never "dropped" (#114): a
//     UPN, device or CVE keyed metric would grow with the tenant and answer no
//     question the log twin does not answer for free.
//
// # A STATE feed with no wire timestamp
//
// DeviceTvmSoftwareVulnerabilities has NO Timestamp column — it is a current-state
// snapshot, re-emitted in full every cycle. Twins are therefore stamped at POLL
// time (Event.Timestamp left zero), the same shape as defender.quarantine and
// entra/risk. There is nothing to tail, which is exactly why polling it does not
// contradict #106's choice of the streaming blob export for the EDR event tables:
// see the package doc on internal/huntclient and the long default interval below.
//
// # The row cap is the real constraint (#249)
//
// Advanced hunting returns at most 100,000 rows per query, hard. m7kni returns
// ~24,912 vulnerability rows today; a large tenant will exceed the cap on a
// single unpartitioned twin fetch and the API would silently truncate. The twin
// fetch therefore partitions: first by severity, then — for any severity whose
// instance count (known from the summary) approaches the cap — by hash(DeviceId)
// into enough shards that each stays under it. planPartitions owns that math and
// is unit-tested to prove it never drops a shard.
//
// # Wire, not docs
//
// Every column mapped here was read off a VERBATIM live query result captured as
// graph2otel-poller on 2026-07-23. Two wire facts drive the mapping and are not
// obvious from documentation: every boolean column (IsExploitAvailable) arrives
// as an SByte NUMBER (0/1), never a JSON bool; and CveMitigationStatus is an
// empty string, not null, on essentially every row (#249).
package vulnerabilities

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"sort"
	"time"

	"github.com/rknightion/graph2otel/internal/collector"
	"github.com/rknightion/graph2otel/internal/collectors"
	"github.com/rknightion/graph2otel/internal/semconv"
	"github.com/rknightion/graph2otel/internal/telemetry"
	"github.com/rknightion/graph2otel/internal/tvm"
)

const (
	collectorName = "defender.vulnerabilities"
	eventName     = "defender.vulnerability"

	// interval is deliberately long. Every query draws on the per-tenant
	// advanced-hunting CPU budget shared with humans in the Defender portal
	// (#106); a current-state snapshot with no Timestamp to tail needs polling
	// only a few times a day, and polling it at a collector-default cadence is
	// precisely the failure mode #106 warns about. Do NOT shorten this without
	// re-reading #106 and #249.
	interval = 6 * time.Hour

	// hardRowCap is the advanced-hunting API's per-query row ceiling: 100,000
	// rows, hard (#249). A query returning more is truncated with no error.
	hardRowCap = 100_000
	// defaultRowCap is the per-partition target this collector aims for, held
	// under hardRowCap so a partition that grew slightly between the summarize
	// and the twin fetch still fits. Overridable in tests to force partitioning
	// on small fixtures.
	defaultRowCap = 90_000

	metricInstances = "defender.vulnerability.instances"
	metricDevices   = "defender.vulnerability.affected_devices"
	metricCVEs      = "defender.vulnerability.cves"
	metricMaxCVSS   = "defender.vulnerability.max_cvss"
	metricMaxEPSS   = "defender.vulnerability.max_epss"

	unitVuln  = "{vulnerability}"
	unitDev   = "{device}"
	unitCVE   = "{cve}"
	unitScore = "{score}"
)

// summaryQuery is the single bounded-metric query: instances, affected devices,
// distinct CVEs and worst CVSS/EPSS, grouped by severity and exploit
// availability. The KB join is server-side and projects only the four columns
// the summary needs — the KB table is 321,736 rows and must never be shipped
// whole (#249).
const summaryQuery = `DeviceTvmSoftwareVulnerabilities
| join kind=leftouter (DeviceTvmSoftwareVulnerabilitiesKB | project CveId, IsExploitAvailable, CvssScore, EpssScore) on CveId
| summarize instances=count(), devices=dcount(DeviceId), cves=dcount(CveId), max_cvss=max(CvssScore), max_epss=max(EpssScore) by VulnerabilitySeverityLevel, IsExploitAvailable`

// twinQueryBase is the per-entity query, filtered to one severity and (when a
// partition is needed) one hash shard. The KB join adds the CVSS/EPSS/exploit/
// vector/published columns the twin carries.
const twinQueryBase = `DeviceTvmSoftwareVulnerabilities
| join kind=leftouter (DeviceTvmSoftwareVulnerabilitiesKB | project CveId, CvssScore, EpssScore, IsExploitAvailable, CvssVector, PublishedDate) on CveId
| where VulnerabilitySeverityLevel == "%s"`

// Collector reads device-vulnerability posture over the advanced-hunting API.
type Collector struct {
	c      collectors.HuntClient
	logger *slog.Logger
	rowCap int
}

// New builds the vulnerabilities collector. A nil logger falls back to
// slog.Default().
func New(d collectors.HuntDeps) *Collector {
	logger := d.Logger
	if logger == nil {
		logger = slog.Default()
	}
	return &Collector{c: d.Client, logger: logger, rowCap: defaultRowCap}
}

// Name implements collector.Collector.
func (c *Collector) Name() string { return collectorName }

// DefaultInterval implements collector.Collector.
func (c *Collector) DefaultInterval() time.Duration { return interval }

// RequiredPermissions is the Graph app role the advanced-hunting query needs.
// Unlike the Exchange Online collectors (which need a directory role outside the
// scope vocabulary), this is a genuine Graph scope, so it is declared and shows
// in the reference.
func (c *Collector) RequiredPermissions() []string {
	return []string{"ThreatHunting.Read.All"}
}

// severityCount is the per-severity instance total, used to size partitions.
type severityCount struct {
	severity string
	count    int64
}

// Collect runs the summary query, emits the bounded gauges, then fetches the
// per-entity twins in row-cap-safe partitions.
//
// The summary query is fatal to the tick if it fails: without it there is no
// posture to report and no partition plan. A twin partition failure is non-fatal
// and aggregated — the gauges and the other partitions still emit — the
// securescore shape rather than quarantine's single-query fail-fast.
func (c *Collector) Collect(ctx context.Context, e telemetry.Emitter) error {
	summary, err := c.c.Query(ctx, "vuln_summary", summaryQuery)
	if err != nil {
		return fmt.Errorf("%s: summary query: %w", collectorName, err)
	}

	perSeverity := c.emitGauges(e, summary)

	var errs []error
	for _, sc := range perSeverity {
		for _, p := range tvm.PlanPartitions(sc.count, c.rowCap) {
			label := "vuln_twin_" + sc.severity
			query := fmt.Sprintf(twinQueryBase, sc.severity) + p.Predicate("DeviceId")
			rows, qerr := c.c.Query(ctx, label, query)
			if qerr != nil {
				c.logger.Warn("vulnerability twin partition failed",
					"collector", collectorName, "severity", sc.severity, "error", qerr)
				errs = append(errs, fmt.Errorf("twin %s: %w", sc.severity, qerr))
				continue
			}
			if len(rows) >= hardRowCap {
				// A partition came back at the hard cap: the shard math under-
				// counted (the table grew, or a single DeviceId hashed heavily).
				// Emit what we have but say so loudly — silent truncation is the
				// one outcome #249 forbids.
				c.logger.Error("vulnerability twin partition hit the hunting row cap; some rows were not emitted",
					"collector", collectorName, "severity", sc.severity, "rows", len(rows), "cap", hardRowCap)
				errs = append(errs, fmt.Errorf("twin %s: hit row cap %d", sc.severity, hardRowCap))
			}
			for _, r := range rows {
				e.LogEvent(vulnTwin(r))
			}
		}
	}
	return errors.Join(errs...)
}

// appendNumPoint appends a gauge point valued at the float64 column src, when
// present. A summarize result always carries every aggregated column, so an
// absent one means the wire changed shape and is skipped rather than emitted as
// zero.
func appendNumPoint(pts []telemetry.GaugePoint, r map[string]any, src string, attrs telemetry.Attrs) []telemetry.GaugePoint {
	f, ok := r[src].(float64)
	if !ok {
		return pts
	}
	return append(pts, telemetry.GaugePoint{Value: f, Attrs: attrs})
}

// emitGauges emits the five bounded gauges from the summary rows and returns the
// per-severity instance totals (summed across the exploit dimension) for
// partition planning.
func (c *Collector) emitGauges(e telemetry.Emitter, summary []map[string]any) []severityCount {
	var instPts, devPts, cvePts, cvssPts, epssPts []telemetry.GaugePoint
	totals := map[string]int64{}

	for _, r := range summary {
		sev, _ := r["VulnerabilitySeverityLevel"].(string)
		if sev == "" {
			continue
		}
		exploit, _ := tvm.SByteBool(r, "IsExploitAvailable")
		attrs := telemetry.Attrs{
			semconv.AttrSeverity:         sev,
			semconv.AttrExploitAvailable: tvm.FmtBool(exploit),
		}
		instPts = appendNumPoint(instPts, r, "instances", attrs)
		devPts = appendNumPoint(devPts, r, "devices", attrs)
		cvePts = appendNumPoint(cvePts, r, "cves", attrs)
		cvssPts = appendNumPoint(cvssPts, r, "max_cvss", attrs)
		epssPts = appendNumPoint(epssPts, r, "max_epss", attrs)
		if n, ok := r["instances"].(float64); ok {
			totals[sev] += int64(n)
		}
	}

	e.GaugeSnapshot(metricInstances, unitVuln,
		"Software-vulnerability instances (device x CVE x software), by severity and exploit availability.", instPts)
	e.GaugeSnapshot(metricDevices, unitDev,
		"Devices with at least one software vulnerability, by severity and exploit availability.", devPts)
	e.GaugeSnapshot(metricCVEs, unitCVE,
		"Distinct CVEs present, by severity and exploit availability.", cvePts)
	e.GaugeSnapshot(metricMaxCVSS, unitScore,
		"Highest CVSS base score present, by severity and exploit availability.", cvssPts)
	e.GaugeSnapshot(metricMaxEPSS, semconv.UnitDimensionless,
		"Highest EPSS probability present, by severity and exploit availability.", epssPts)

	out := make([]severityCount, 0, len(totals))
	for sev, n := range totals {
		out = append(out, severityCount{severity: sev, count: n})
	}
	// Deterministic order so partition queries and tests are stable.
	sort.Slice(out, func(i, j int) bool { return out[i].severity < out[j].severity })
	return out
}

// vulnTwin renders one vulnerability row as an OTLP log record: the per-entity
// detail the gauges collapse. Timestamp is left zero (poll time) — the table
// carries none.
//
// Severity escalates to Error when the vulnerability is Critical OR an exploit is
// available (#249): those are the rows an operator patches first. Everything else
// is Info. CveMitigationStatus is emitted only when non-empty — it is "" (not
// null) on essentially every row, and an empty attribute would be noise.
func vulnTwin(r map[string]any) telemetry.Event {
	attrs := telemetry.Attrs{}
	telemetry.SetStr(attrs, semconv.AttrDeviceId, tvm.Str(r, "DeviceId"))
	telemetry.SetStr(attrs, semconv.AttrDeviceName, tvm.Str(r, "DeviceName"))
	telemetry.SetStr(attrs, semconv.AttrOsPlatform, tvm.Str(r, "OSPlatform"))
	telemetry.SetStr(attrs, semconv.AttrOsVersion, tvm.Str(r, "OSVersion"))
	telemetry.SetStr(attrs, semconv.AttrSoftwareVendor, tvm.Str(r, "SoftwareVendor"))
	telemetry.SetStr(attrs, semconv.AttrSoftwareName, tvm.Str(r, "SoftwareName"))
	telemetry.SetStr(attrs, semconv.AttrSoftwareVersion, tvm.Str(r, "SoftwareVersion"))
	telemetry.SetStr(attrs, semconv.AttrCveId, tvm.Str(r, "CveId"))
	sev := tvm.Str(r, "VulnerabilitySeverityLevel")
	telemetry.SetStr(attrs, semconv.AttrSeverity, sev)
	telemetry.SetStr(attrs, semconv.AttrRecommendedSecurityUpdate, tvm.Str(r, "RecommendedSecurityUpdate"))
	telemetry.SetStr(attrs, semconv.AttrCveMitigationStatus, tvm.Str(r, "CveMitigationStatus"))
	telemetry.SetStr(attrs, semconv.AttrCvssVector, tvm.Str(r, "CvssVector"))
	telemetry.SetStr(attrs, semconv.AttrPublishedDate, tvm.Str(r, "PublishedDate"))
	telemetry.SetNum(attrs, semconv.AttrCvssScore, r, "CvssScore")
	telemetry.SetNum(attrs, semconv.AttrEpssScore, r, "EpssScore")

	exploit, _ := tvm.SByteBool(r, "IsExploitAvailable")
	telemetry.SetBool(attrs, semconv.AttrExploitAvailable, exploit)

	severity := telemetry.SeverityInfo
	if sev == "Critical" || exploit {
		severity = telemetry.SeverityError
	}

	return telemetry.Event{
		Name: eventName,
		Body: fmt.Sprintf("%s on %s (%s %s %s), severity=%s exploit=%t",
			tvm.Str(r, "CveId"), tvm.Str(r, "DeviceName"),
			tvm.Str(r, "SoftwareVendor"), tvm.Str(r, "SoftwareName"), tvm.Str(r, "SoftwareVersion"),
			sev, exploit),
		Severity: severity,
		Attrs:    attrs,
	}
}

func init() {
	collectors.RegisterHunt(func(d collectors.HuntDeps) collector.SnapshotCollector { return New(d) })
}
