// Package softwareinventory is the Microsoft Defender threat-and-vulnerability-
// management software-inventory collector (#249): what software is installed on
// which onboarded device, and its end-of-support status.
//
// # Why this is a hunting collector
//
// DeviceTvmSoftwareInventory has no Graph REST endpoint and is not in any Defender
// streaming-export blob container (#249). The only route is the advanced-hunting
// query API (internal/huntclient), so this sits on the hunting registration path
// (collectors.HuntDeps), alongside defender.vulnerabilities and
// defender.secure_config.
//
// # Both sides of the cardinality boundary
//
//   - bounded GAUGES from ONE summarize query: install count, affected-device
//     count and distinct-product count, each keyed by end-of-support status. The
//     status set is a small closed list (the empty string for supported, plus
//     "Upcoming EOS Version", "EOS Version", "EOS Software"), so the series count
//     is fixed.
//   - one LOG twin per (device, product, version) install carrying the per-entity
//     detail. Every install is emitted, not only the end-of-life ones (#114): the
//     installs gauge buckets every status, so the entities behind every bucket
//     must be reachable. This is the SIEM-feed half — per-entity detail in logs is
//     the point (CLAUDE.md) — and it complements intune.detected_apps, which
//     catalogs apps but carries no CPE, no EOS status, and only Intune-managed
//     devices (#249 keeps both).
//
// # A STATE feed with no wire timestamp
//
// DeviceTvmSoftwareInventory has no Timestamp column; twins are stamped at POLL
// time (Event.Timestamp left zero), the defender.vulnerabilities shape. Long
// default interval, for the shared advanced-hunting CPU budget (#106).
//
// # Wire, not docs
//
// Every column is read off a VERBATIM live query result (2026-07-23). Two wire
// facts drive the mapping: EndOfSupportStatus is the EMPTY STRING for supported
// software (a real bucket, not missing data), and EndOfSupportDate is {} (an
// empty object) when null — tvm.Str returns "" for it so the attribute is omitted
// rather than stringified. See internal/tvm.
package softwareinventory

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
	collectorName = "defender.software_inventory"
	eventName     = "defender.software"

	// interval is deliberately long — the shared advanced-hunting CPU budget
	// (#106), a state snapshot with nothing to tail. Do NOT shorten without
	// re-reading #106 and #249.
	interval = 6 * time.Hour

	defaultRowCap = 90_000

	metricInstalls   = "defender.software.installs"
	metricEOSDevices = "defender.software.eos_devices"
	metricProducts   = "defender.software.products"

	unitInstall = "{install}"
	unitDevice  = "{device}"
	unitProduct = "{product}"

	// supportedStatus is the empty-string EndOfSupportStatus value — supported
	// software, a real bucket. Named so the partition query and the wire fact are
	// not a bare "" the reader has to interpret.
	supportedStatus = ""
)

// summaryQuery counts installs, affected devices and distinct products by
// end-of-support status — the bounded gauges. A product is (vendor, name); the
// same product on many versions or devices is one product.
const summaryQuery = `DeviceTvmSoftwareInventory
| summarize installs=count(), eos_devices=dcount(DeviceId), products=dcount(strcat(SoftwareVendor, ":", SoftwareName)) by EndOfSupportStatus`

// twinQueryBase is the per-entity query, filtered to one end-of-support status
// and (when needed) one hash shard.
const twinQueryBase = `DeviceTvmSoftwareInventory
| where EndOfSupportStatus == "%s"`

// Collector reads device software inventory over the advanced-hunting API.
type Collector struct {
	c      collectors.HuntClient
	logger *slog.Logger
	rowCap int
}

// New builds the software-inventory collector. A nil logger falls back to
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

// statusCount is the per-status install total, for partitioning.
type statusCount struct {
	status string
	count  int64
}

// Collect runs the summary query, emits the bounded gauges, then fetches the
// per-entity twins per status in row-cap-safe partitions. A summary failure is
// fatal to the tick; a twin partition failure is non-fatal and aggregated.
func (c *Collector) Collect(ctx context.Context, e telemetry.Emitter) error {
	summary, err := c.c.Query(ctx, "software_summary", summaryQuery)
	if err != nil {
		return fmt.Errorf("%s: summary query: %w", collectorName, err)
	}

	perStatus := c.emitGauges(e, summary)

	var errs []error
	for _, sc := range perStatus {
		for _, p := range tvm.PlanPartitions(sc.count, c.rowCap) {
			query := fmt.Sprintf(twinQueryBase, sc.status) + p.Predicate("DeviceId")
			rows, qerr := c.c.Query(ctx, "software_twin", query)
			if qerr != nil {
				c.logger.Warn("software inventory twin partition failed",
					"collector", collectorName, "status", sc.status, "error", qerr)
				errs = append(errs, fmt.Errorf("twin %q: %w", sc.status, qerr))
				continue
			}
			if len(rows) >= tvm.HardRowCap {
				c.logger.Error("software inventory twin partition hit the hunting row cap; some rows were not emitted",
					"collector", collectorName, "status", sc.status, "rows", len(rows))
				errs = append(errs, fmt.Errorf("twin %q: hit row cap %d", sc.status, tvm.HardRowCap))
			}
			for _, r := range rows {
				e.LogEvent(softwareTwin(r))
			}
		}
	}
	return errors.Join(errs...)
}

// emitGauges emits the three bounded gauges and returns per-status install totals
// for partition planning.
func (c *Collector) emitGauges(e telemetry.Emitter, summary []map[string]any) []statusCount {
	var installPts, devPts, prodPts []telemetry.GaugePoint
	var out []statusCount

	for _, r := range summary {
		// EndOfSupportStatus is a real bucket even when "" (supported), so unlike
		// the other collectors' severity/category we do NOT skip the empty value.
		status, ok := r["EndOfSupportStatus"].(string)
		if !ok {
			continue
		}
		attrs := telemetry.Attrs{semconv.AttrEndOfSupportStatus: status}
		installPts = appendNumPoint(installPts, r, "installs", attrs)
		devPts = appendNumPoint(devPts, r, "eos_devices", attrs)
		prodPts = appendNumPoint(prodPts, r, "products", attrs)
		if n, ok := r["installs"].(float64); ok {
			out = append(out, statusCount{status: status, count: int64(n)})
		}
	}

	e.GaugeSnapshot(metricInstalls, unitInstall,
		"Installed-software instances (device x product x version), by end-of-support status.", installPts)
	e.GaugeSnapshot(metricEOSDevices, unitDevice,
		"Devices carrying software in a given end-of-support status.", devPts)
	e.GaugeSnapshot(metricProducts, unitProduct,
		"Distinct products (vendor x name), by end-of-support status.", prodPts)

	sort.Slice(out, func(i, j int) bool { return out[i].status < out[j].status })
	return out
}

// softwareTwin renders one install as an OTLP log record. Timestamp is left zero
// (poll time). Severity escalates to Warn when the software has ANY non-empty
// end-of-support status — past end of life or approaching it, both worth
// surfacing; supported software (empty status) is Info. EndOfSupportDate is
// emitted only when present ({} on the wire when null -> omitted).
func softwareTwin(r map[string]any) telemetry.Event {
	attrs := telemetry.Attrs{}
	telemetry.SetStr(attrs, semconv.AttrDeviceId, tvm.Str(r, "DeviceId"))
	telemetry.SetStr(attrs, semconv.AttrDeviceName, tvm.Str(r, "DeviceName"))
	telemetry.SetStr(attrs, semconv.AttrOsPlatform, tvm.Str(r, "OSPlatform"))
	telemetry.SetStr(attrs, semconv.AttrOsVersion, tvm.Str(r, "OSVersion"))
	telemetry.SetStr(attrs, semconv.AttrSoftwareVendor, tvm.Str(r, "SoftwareVendor"))
	telemetry.SetStr(attrs, semconv.AttrSoftwareName, tvm.Str(r, "SoftwareName"))
	telemetry.SetStr(attrs, semconv.AttrSoftwareVersion, tvm.Str(r, "SoftwareVersion"))
	telemetry.SetStr(attrs, semconv.AttrProductCodeCpe, tvm.Str(r, "ProductCodeCpe"))
	telemetry.SetStr(attrs, semconv.AttrEndOfSupportDate, tvm.Str(r, "EndOfSupportDate"))

	status := tvm.Str(r, "EndOfSupportStatus")
	telemetry.SetStr(attrs, semconv.AttrEndOfSupportStatus, status)

	severity := telemetry.SeverityInfo
	if status != supportedStatus {
		severity = telemetry.SeverityWarn
	}

	return telemetry.Event{
		Name: eventName,
		Body: fmt.Sprintf("%s %s %s on %s (eos=%q)",
			tvm.Str(r, "SoftwareVendor"), tvm.Str(r, "SoftwareName"), tvm.Str(r, "SoftwareVersion"),
			tvm.Str(r, "DeviceName"), status),
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
