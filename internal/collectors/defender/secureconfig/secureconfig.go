// Package secureconfig is the Microsoft Defender threat-and-vulnerability-
// management secure-configuration-assessment collector (#249): which security
// configurations each onboarded device passes or fails, and the impact of the
// gaps.
//
// # Why this is a hunting collector
//
// DeviceTvmSecureConfigurationAssessment has no Graph REST endpoint and is not in
// any Defender streaming-export blob container (#249). The only route is the
// advanced-hunting query API (internal/huntclient), so this sits on the hunting
// registration path (collectors.HuntDeps), alongside defender.vulnerabilities and
// defender.software_inventory.
//
// # Both sides of the cardinality boundary
//
//   - bounded GAUGES: assessment count keyed by configuration category and
//     compliance, plus the noncompliant-device count and summed impact per
//     category. The category set is a small closed list (Security controls, OS,
//     Network, Accounts, Application), so the series count is fixed.
//   - one LOG twin per applicable (device, configuration) assessment carrying the
//     per-entity detail — which device fails which configuration, and the impact
//     weight. Emitting the compliant assessments too, not only the failures, is
//     deliberate: #114 forbids bucketing a count and discarding the entities
//     behind it, and the metric buckets BOTH compliance states.
//
// # A STATE feed
//
// A row is re-emitted every cycle for as long as the assessment stands. Although
// this table DOES carry a Timestamp (the scan time), twins are stamped at POLL
// time (Event.Timestamp left zero), not with that scan time, for the same reason
// defender.mdo_policies is: stamping a re-emitted state record with its last-scan
// instant piles every repeat onto that instant. See the long default interval.
//
// # Wire, not docs
//
// Every column is read off a VERBATIM live query result (2026-07-23). The wire
// fact that drives the mapping: IsCompliant and IsApplicable are booleans encoded
// as SByte NUMBERS (0/1), never JSON bools — see internal/tvm.
package secureconfig

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
	collectorName = "defender.secure_config"
	eventName     = "defender.secure_config"

	// interval is deliberately long — the shared advanced-hunting CPU budget
	// (#106), a state snapshot with nothing to tail. Do NOT shorten without
	// re-reading #106 and #249.
	interval = 6 * time.Hour

	defaultRowCap = 90_000

	metricAssessments         = "defender.secure_config.assessments"
	metricNoncompliantDevices = "defender.secure_config.noncompliant_devices"
	metricImpactAtRisk        = "defender.secure_config.impact_at_risk"

	unitAssessment = "{assessment}"
	unitDevice     = "{device}"
	unitImpact     = "{impact}"
)

// assessmentsQuery counts applicable assessments by category and compliance — the
// 10-series bounded gauge (5 categories x compliant/noncompliant).
const assessmentsQuery = `DeviceTvmSecureConfigurationAssessment
| where IsApplicable == true
| summarize assessments=count() by ConfigurationCategory, IsCompliant`

// riskQuery counts noncompliant devices and sums impact per category — the
// actionable posture-gap gauges.
const riskQuery = `DeviceTvmSecureConfigurationAssessment
| where IsApplicable == true and IsCompliant == false
| summarize noncompliant_devices=dcount(DeviceId), impact_at_risk=sum(ConfigurationImpact) by ConfigurationCategory`

// twinQueryBase is the per-entity query, filtered to one category and (when
// needed) one hash shard.
const twinQueryBase = `DeviceTvmSecureConfigurationAssessment
| where IsApplicable == true and ConfigurationCategory == "%s"`

// Collector reads secure-configuration posture over the advanced-hunting API.
type Collector struct {
	c      collectors.HuntClient
	logger *slog.Logger
	rowCap int
}

// New builds the secure-config collector. A nil logger falls back to
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
func (c *Collector) RequiredPermissions() []string {
	return []string{"ThreatHunting.Read.All"}
}

// Collect runs the two summary queries, emits the bounded gauges, then fetches
// the per-entity twins per category in row-cap-safe partitions. A summary failure
// is fatal to the tick; a twin partition failure is non-fatal and aggregated.
func (c *Collector) Collect(ctx context.Context, e telemetry.Emitter) error {
	assessments, err := c.c.Query(ctx, "secureconfig_assessments", assessmentsQuery)
	if err != nil {
		return fmt.Errorf("%s: assessments query: %w", collectorName, err)
	}
	risk, err := c.c.Query(ctx, "secureconfig_risk", riskQuery)
	if err != nil {
		return fmt.Errorf("%s: risk query: %w", collectorName, err)
	}

	perCategory := c.emitGauges(e, assessments, risk)

	var errs []error
	for _, cat := range perCategory {
		for _, p := range tvm.PlanPartitions(cat.count, c.rowCap) {
			query := fmt.Sprintf(twinQueryBase, cat.category) + p.Predicate("DeviceId")
			rows, qerr := c.c.Query(ctx, "secureconfig_twin_"+cat.category, query)
			if qerr != nil {
				c.logger.Warn("secure config twin partition failed",
					"collector", collectorName, "category", cat.category, "error", qerr)
				errs = append(errs, fmt.Errorf("twin %s: %w", cat.category, qerr))
				continue
			}
			if len(rows) >= tvm.HardRowCap {
				c.logger.Error("secure config twin partition hit the hunting row cap; some rows were not emitted",
					"collector", collectorName, "category", cat.category, "rows", len(rows))
				errs = append(errs, fmt.Errorf("twin %s: hit row cap %d", cat.category, tvm.HardRowCap))
			}
			for _, r := range rows {
				e.LogEvent(configTwin(r))
			}
		}
	}
	return errors.Join(errs...)
}

// categoryCount is the per-category applicable-assessment total, for partitioning.
type categoryCount struct {
	category string
	count    int64
}

// emitGauges emits the three bounded gauges and returns per-category applicable
// totals for partition planning.
func (c *Collector) emitGauges(e telemetry.Emitter, assessments, risk []map[string]any) []categoryCount {
	var assessPts, devPts, impactPts []telemetry.GaugePoint
	totals := map[string]int64{}

	for _, r := range assessments {
		cat, _ := r["ConfigurationCategory"].(string)
		if cat == "" {
			continue
		}
		compliant, _ := tvm.SByteBool(r, "IsCompliant")
		attrs := telemetry.Attrs{
			semconv.AttrConfigurationCategory: cat,
			semconv.AttrIsCompliant:           tvm.FmtBool(compliant),
		}
		assessPts = appendNumPoint(assessPts, r, "assessments", attrs)
		if n, ok := r["assessments"].(float64); ok {
			totals[cat] += int64(n)
		}
	}
	for _, r := range risk {
		cat, _ := r["ConfigurationCategory"].(string)
		if cat == "" {
			continue
		}
		attrs := telemetry.Attrs{semconv.AttrConfigurationCategory: cat}
		devPts = appendNumPoint(devPts, r, "noncompliant_devices", attrs)
		impactPts = appendNumPoint(impactPts, r, "impact_at_risk", attrs)
	}

	e.GaugeSnapshot(metricAssessments, unitAssessment,
		"Applicable secure-configuration assessments, by configuration category and compliance.", assessPts)
	e.GaugeSnapshot(metricNoncompliantDevices, unitDevice,
		"Devices failing at least one configuration, by configuration category.", devPts)
	e.GaugeSnapshot(metricImpactAtRisk, unitImpact,
		"Summed configuration impact of the failing assessments, by configuration category.", impactPts)

	out := make([]categoryCount, 0, len(totals))
	for cat, n := range totals {
		out = append(out, categoryCount{category: cat, count: n})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].category < out[j].category })
	return out
}

// configTwin renders one assessment as an OTLP log record. Timestamp is left zero
// (poll time). Severity escalates to Warn when the device FAILS the configuration
// (IsCompliant present and false) — the actionable posture gap; a passing
// assessment is Info.
func configTwin(r map[string]any) telemetry.Event {
	attrs := telemetry.Attrs{}
	telemetry.SetStr(attrs, semconv.AttrDeviceId, tvm.Str(r, "DeviceId"))
	telemetry.SetStr(attrs, semconv.AttrDeviceName, tvm.Str(r, "DeviceName"))
	telemetry.SetStr(attrs, semconv.AttrOsPlatform, tvm.Str(r, "OSPlatform"))
	telemetry.SetStr(attrs, semconv.AttrConfigurationId, tvm.Str(r, "ConfigurationId"))
	telemetry.SetStr(attrs, semconv.AttrConfigurationCategory, tvm.Str(r, "ConfigurationCategory"))
	telemetry.SetStr(attrs, semconv.AttrConfigurationSubcategory, tvm.Str(r, "ConfigurationSubcategory"))
	telemetry.SetNum(attrs, semconv.AttrConfigurationImpact, r, "ConfigurationImpact")

	compliant, ok := tvm.SByteBool(r, "IsCompliant")
	if ok {
		telemetry.SetBool(attrs, semconv.AttrIsCompliant, compliant)
	}

	severity := telemetry.SeverityInfo
	if ok && !compliant {
		severity = telemetry.SeverityWarn
	}

	return telemetry.Event{
		Name: eventName,
		Body: fmt.Sprintf("%s on %s: %s (%s), compliant=%t",
			tvm.Str(r, "ConfigurationId"), tvm.Str(r, "DeviceName"),
			tvm.Str(r, "ConfigurationCategory"), tvm.Str(r, "ConfigurationSubcategory"), compliant),
		Severity: severity,
		Attrs:    attrs,
	}
}

// appendNumPoint appends a gauge point valued at the float64 column src, when
// present.
func appendNumPoint(pts []telemetry.GaugePoint, r map[string]any, src string, attrs telemetry.Attrs) []telemetry.GaugePoint {
	f, ok := r[src].(float64)
	if !ok {
		return pts
	}
	return append(pts, telemetry.GaugePoint{Value: f, Attrs: attrs})
}

func init() {
	collectors.RegisterHunt(func(d collectors.HuntDeps) collector.SnapshotCollector { return New(d) })
}
