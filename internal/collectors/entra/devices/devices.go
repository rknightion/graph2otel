// Package devices is the Entra directory-devices collector: bounded
// aggregate gauges over the directory `/devices` collection (Microsoft Entra
// ID-registered devices), sliced by trust type, compliance state,
// MDM-managed state, and operating system, plus a stale-device gauge from
// `approximateLastSignInDateTime`.
//
// These are directory device objects (created by Device Registration
// Service / hybrid join / workplace join), NOT Intune managedDevices - a
// different Graph workload and license, covered separately under
// internal/collectors/intune. Do not conflate the two: a directory device
// can exist with no Intune enrollment at all, and an Intune managedDevice
// carries a much richer, per-device inventory that belongs in the M4 Intune
// collectors and/or the logs pipeline, never here.
package devices

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/url"
	"strings"
	"time"

	"github.com/rknightion/graph2otel/internal/collector"
	"github.com/rknightion/graph2otel/internal/collectors"
	"github.com/rknightion/graph2otel/internal/semconv"
	"github.com/rknightion/graph2otel/internal/telemetry"
)

// collectorName is the stable key used for config (enable/interval),
// self-observability, and the admin status page.
const collectorName = "entra.devices"

// Metric names this collector emits. Each is its own metric name (rather
// than one entra.devices.total carrying all four slice dimensions at once)
// so that summing a single metric always yields the true device total for
// that breakdown - mixing independent dimensions under one metric name would
// mean a naive `sum()` over it silently multi-counts the same devices once
// per dimension.
const (
	totalMetricName      = "entra.devices.total"
	complianceMetricName = "entra.devices.compliance.total"
	managedMetricName    = "entra.devices.managed.total"
	osMetricName         = "entra.devices.os.total"
	staleMetricName      = "entra.devices.stale.total"
)

// defaultBaseURL is the Graph v1.0 root.
const defaultBaseURL = "https://graph.microsoft.com/v1.0"

// staleThresholdDays is the bounded threshold for the stale-device gauge: a
// device is "stale" when its approximateLastSignInDateTime is older than
// this many days. Fixed (not tenant-configurable in v1) so the
// threshold_days attribute stays a single bounded value rather than a
// config-driven cardinality source.
const staleThresholdDays = 90

// trustTypeBucket pairs a bounded trust_type attribute value with the
// literal Graph trustType value it counts. Per
// https://learn.microsoft.com/en-us/graph/api/resources/device, trustType is
// a read-only String property with exactly three possible values: Workplace
// (BYOD), AzureAd (cloud-only joined), ServerAd (on-premises domain joined,
// synced to Entra ID). It supports $filter eq/ne/not/in.
type trustTypeBucket struct {
	attr  string
	value string
}

var trustTypeBuckets = []trustTypeBucket{
	{"azure_ad", "AzureAd"},
	{"server_ad", "ServerAd"},
	{"workplace", "Workplace"},
}

// osBucket pairs a bounded operating_system attribute value with the
// literal-prefix $filter used to count it. operatingSystem is documented as
// a plain String property with no enum (populated by whatever client
// registered the device), so there is no authoritative value list to slice
// against. These prefixes are the platform names Microsoft's own docs and
// device-registration flows use. A device whose operatingSystem matches none
// of them (different capitalization, an unanticipated platform, or a null
// value) is counted into the "other" bucket via the total-count leftover
// (see osSnapshot), which keeps this series exactly bounded and the true
// device total always exact even if a per-platform label undercounts.
type osBucket struct {
	attr   string
	prefix string
}

var osBuckets = []osBucket{
	{"windows", "Windows"},
	{"macos", "Mac"},
	{"ios", "iOS"},
	{"ipados", "iPadOS"},
	{"android", "Android"},
	{"linux", "Linux"},
}

// Collector polls the directory /devices collection's bounded $count slices.
type Collector struct {
	g       collectors.GraphClient
	baseURL string
	logger  *slog.Logger
	// now returns the current time; overridable in tests so the stale-device
	// cutoff filter is deterministic and assertable.
	now func() time.Time
}

// New builds the devices collector. A nil logger falls back to the slog
// default.
func New(g collectors.GraphClient, logger *slog.Logger) *Collector {
	if logger == nil {
		logger = slog.Default()
	}
	return &Collector{g: g, baseURL: defaultBaseURL, logger: logger, now: time.Now}
}

// Name implements collector.Collector.
func (c *Collector) Name() string { return collectorName }

// DefaultInterval implements collector.Collector. Directory device
// membership and compliance/managed state drift slowly, but this collector
// issues more $count requests per cycle than the single-slice reference
// collector (one total plus per-bucket counts across four dimensions), so it
// gets a longer default cadence than entra.directory_counts.
func (c *Collector) DefaultInterval() time.Duration { return 15 * time.Minute }

// RequiredPermissions declares the least-privilege Graph application scope.
// Per https://learn.microsoft.com/en-us/graph/api/device-list, Device.Read.All
// is the least-privileged application permission for listing/counting
// /devices (Directory.Read.All is a higher-privileged alternative).
func (c *Collector) RequiredPermissions() []string { return []string{"Device.Read.All"} }

// Collect fetches the bounded device-count slices and emits five gauge
// snapshots. Each sub-slice is independently resilient: a failure counting
// one bucket is logged and that bucket is dropped from its snapshot (and, if
// the failed bucket depends on the tenant-wide total, its "unknown"/"other"
// leftover point is omitted too, since it can no longer be computed
// correctly) but every other bucket and every other metric still emits. All
// per-bucket errors are aggregated via errors.Join and returned so partial
// failure stays visible in scrape self-obs without hiding the data that did
// succeed.
func (c *Collector) Collect(ctx context.Context, e telemetry.Emitter) error {
	var errs []error

	total, err := collectors.Count(ctx, c.g, c.baseURL+"/devices/$count")
	haveTotal := err == nil
	if err != nil {
		c.logger.Warn("devices: total device count failed", "collector", collectorName, "error", err)
		errs = append(errs, fmt.Errorf("total count: %w", err))
	}

	trustPoints, trustErrs := c.trustTypeSnapshot(ctx, total, haveTotal)
	errs = append(errs, trustErrs...)
	e.GaugeSnapshot(totalMetricName, "{device}", "Total Entra directory devices, by trust type.", trustPoints)

	compliancePoints, complianceErrs := c.boolSnapshot(ctx, "isCompliant", semconv.AttrIsCompliant)
	errs = append(errs, complianceErrs...)
	e.GaugeSnapshot(complianceMetricName, "{device}", "Total Entra directory devices, by MDM compliance state.", compliancePoints)

	managedPoints, managedErrs := c.boolSnapshot(ctx, "isManaged", semconv.AttrIsManaged)
	errs = append(errs, managedErrs...)
	e.GaugeSnapshot(managedMetricName, "{device}", "Total Entra directory devices, by MDM-managed state.", managedPoints)

	osPoints, osErrs := c.osSnapshot(ctx, total, haveTotal)
	errs = append(errs, osErrs...)
	e.GaugeSnapshot(osMetricName, "{device}", "Total Entra directory devices, by operating system.", osPoints)

	stalePoints, staleErrs := c.staleSnapshot(ctx)
	errs = append(errs, staleErrs...)
	e.GaugeSnapshot(staleMetricName, "{device}", "Entra directory devices whose last sign-in is older than the staleness threshold.", stalePoints)

	return errors.Join(errs...)
}

// trustTypeSnapshot counts each known trustType bucket and, when the
// tenant-wide total is available, adds an "unknown" leftover bucket for
// devices matching none of the three documented trustType values (e.g. a
// null trustType). The leftover is clamped to zero to guard against a
// negative value if the total and per-bucket counts were read at slightly
// different instants against a live, changing directory.
func (c *Collector) trustTypeSnapshot(ctx context.Context, total int64, haveTotal bool) ([]telemetry.GaugePoint, []error) {
	points := make([]telemetry.GaugePoint, 0, len(trustTypeBuckets)+1)
	var errs []error
	var knownSum int64
	ok := true
	for _, b := range trustTypeBuckets {
		n, err := collectors.Count(ctx, c.g, filterCountURL(c.baseURL+"/devices/$count", "trustType eq '"+b.value+"'"))
		if err != nil {
			c.logger.Warn("devices: trust_type count failed", "collector", collectorName, "trust_type", b.attr, "error", err)
			errs = append(errs, fmt.Errorf("trust_type=%s: %w", b.attr, err))
			ok = false
			continue
		}
		knownSum += n
		points = append(points, telemetry.GaugePoint{Value: float64(n), Attrs: telemetry.Attrs{semconv.AttrTrustType: b.attr}})
	}
	if haveTotal && ok {
		points = append(points, telemetry.GaugePoint{Value: float64(clampNonNegative(total - knownSum)), Attrs: telemetry.Attrs{semconv.AttrTrustType: "unknown"}})
	}
	return points, errs
}

// boolSnapshot counts the true/false split of a boolean device property.
// isCompliant and isManaged are non-nullable in current Graph documentation
// (they default false rather than null when Intune hasn't set them), so
// true+false always accounts for every device - no leftover bucket needed.
func (c *Collector) boolSnapshot(ctx context.Context, field, attrKey string) ([]telemetry.GaugePoint, []error) {
	points := make([]telemetry.GaugePoint, 0, 2)
	var errs []error
	for _, v := range []bool{true, false} {
		lit := "false"
		if v {
			lit = "true"
		}
		n, err := collectors.Count(ctx, c.g, filterCountURL(c.baseURL+"/devices/$count", field+" eq "+lit))
		if err != nil {
			c.logger.Warn("devices: bool count failed", "collector", collectorName, "field", field, "value", v, "error", err)
			errs = append(errs, fmt.Errorf("%s=%t: %w", field, v, err))
			continue
		}
		points = append(points, telemetry.GaugePoint{Value: float64(n), Attrs: telemetry.Attrs{attrKey: v}})
	}
	return points, errs
}

// osSnapshot counts each known operating_system bucket by prefix match and,
// when the tenant-wide total is available, adds an "other" leftover bucket
// (clamped to zero) for devices whose operatingSystem matches none of the
// known prefixes - see the osBucket doc comment for why that leftover
// approach, rather than an exhaustive literal value list, is the bounded and
// correct choice here.
func (c *Collector) osSnapshot(ctx context.Context, total int64, haveTotal bool) ([]telemetry.GaugePoint, []error) {
	points := make([]telemetry.GaugePoint, 0, len(osBuckets)+1)
	var errs []error
	var knownSum int64
	ok := true
	for _, b := range osBuckets {
		n, err := collectors.Count(ctx, c.g, filterCountURL(c.baseURL+"/devices/$count", "startswith(operatingSystem,'"+b.prefix+"')"))
		if err != nil {
			c.logger.Warn("devices: os count failed", "collector", collectorName, "operating_system", b.attr, "error", err)
			errs = append(errs, fmt.Errorf("operating_system=%s: %w", b.attr, err))
			ok = false
			continue
		}
		knownSum += n
		points = append(points, telemetry.GaugePoint{Value: float64(n), Attrs: telemetry.Attrs{semconv.AttrOperatingSystem: b.attr}})
	}
	if haveTotal && ok {
		points = append(points, telemetry.GaugePoint{Value: float64(clampNonNegative(total - knownSum)), Attrs: telemetry.Attrs{semconv.AttrOperatingSystem: "other"}})
	}
	return points, errs
}

// staleSnapshot counts devices whose approximateLastSignInDateTime is at or
// before the staleness cutoff. Devices that have NEVER signed in carry a
// null approximateLastSignInDateTime, which a plain `le` filter does not
// match - so this count deliberately excludes them rather than guessing at
// an untested compound `or ... eq null` advanced-query expression. That is a
// known v1 limitation (documented here, not silently dropped): a tenant with
// many never-signed-in stale devices will undercount this gauge.
func (c *Collector) staleSnapshot(ctx context.Context) ([]telemetry.GaugePoint, []error) {
	cutoff := c.now().UTC().Add(-staleThresholdDays * 24 * time.Hour).Format(time.RFC3339)
	n, err := collectors.Count(ctx, c.g, filterCountURL(c.baseURL+"/devices/$count", "approximateLastSignInDateTime le "+cutoff))
	if err != nil {
		c.logger.Warn("devices: stale device count failed", "collector", collectorName, "error", err)
		return nil, []error{fmt.Errorf("stale count: %w", err)}
	}
	return []telemetry.GaugePoint{{
		Value: float64(n),
		Attrs: telemetry.Attrs{semconv.AttrThresholdDays: staleThresholdDays},
	}}, nil
}

// clampNonNegative floors a leftover count at zero, guarding against a
// transient negative value from reading the total and per-bucket counts at
// slightly different instants against a live, changing directory.
func clampNonNegative(n int64) int64 {
	if n < 0 {
		return 0
	}
	return n
}

// filterCountURL builds a $count URL with the given OData $filter expression.
// url.QueryEscape percent-encodes it form-style (spaces become '+'); Graph
// expects standard percent-encoding (%20), so '+' is replaced afterward -
// matching the encoding style Kiota-generated Graph SDKs produce.
func filterCountURL(base, filter string) string {
	encoded := strings.ReplaceAll(url.QueryEscape(filter), "+", "%20")
	return base + "?$filter=" + encoded
}

func init() {
	collectors.Register(func(d collectors.Deps) collector.SnapshotCollector {
		return New(d.Graph, d.Logger)
	})
}
