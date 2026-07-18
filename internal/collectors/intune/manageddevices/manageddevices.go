// Package manageddevices is the core Intune device-fleet collector: bounded
// aggregate gauges over the Intune `/deviceManagement/managedDevices`
// inventory (compliance/OS/encryption/sync-recency), plus a cheap
// cross-check from the pre-aggregated `/deviceManagement/managedDeviceOverview`
// singleton.
//
// These are Intune managedDevice objects (created by MDM enrollment), NOT
// Entra directory devices - see internal/collectors/entra/devices for that,
// distinct workload and license. Per-device detail (hardware inventory,
// per-device compliance drill-down) is deliberately out of scope here: the
// beta-only `hardwareInformation` per-device sweep would cost 10k+ Graph
// calls per cycle on a large fleet and is deferred to the M5 export-job
// subsystem rather than shipped as an opt-in flag with no config plumbing to
// gate it yet (see the package doc on Collect for detail).
//
// # Metric/log split (#114)
//
// Every device contributes to TWO outputs from the one fleet-wide paged
// fetch: the bounded compliance/OS/encryption/staleness gauges described
// above (never carrying a per-device attribute), and one intune.managed_device
// log record per device per cycle, carrying the identity fields the gauges
// cannot - id, deviceName, serialNumber, userPrincipalName - alongside the
// raw (unbucketed) complianceState/operatingSystem/isEncrypted/
// lastSyncDateTime. This fleet-wide $select used to deliberately EXCLUDE
// those identity fields entirely, which made "which device is
// non-compliant/unencrypted/stale" unanswerable even in principle - that was
// the bug (#112/#114), not a privacy control: per-entity identity must never
// become a metric LABEL, but "never a label" means "log twin", not "dropped".
//
// Every device is twinned, not just the non-compliant ones - a maintainer
// decision recorded on #114: the log pipeline is the surviving per-entity
// record (the SIEM record of last resort), so filtering to "problem rows
// only" would break correlation questions like "was device X enrolled on
// date Y". Volume is therefore NOT bounded - it scales with fleet size x poll
// interval, one record per device every cycle (DefaultInterval is hourly, so
// a 10,000-device fleet is 10,000 log records/hour). Severity escalates to
// Warn for the states that actually need attention - non-compliant
// (noncompliant/conflict/error), unencrypted, or sync-stale beyond 30 days -
// and stays Info otherwise; see deviceLogSeverity.
package manageddevices

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"strconv"
	"strings"
	"time"

	"github.com/rknightion/graph2otel/internal/collector"
	"github.com/rknightion/graph2otel/internal/collectors"
	"github.com/rknightion/graph2otel/internal/semconv"
	"github.com/rknightion/graph2otel/internal/telemetry"
)

// collectorName is the stable key used for config (enable/interval),
// self-observability, and the admin status page.
const collectorName = "intune.devices"

// Metric names this collector emits. Each is its own metric name so that
// summing a single metric always yields the true count for that breakdown -
// mixing independent dimensions under one metric name would mean a naive
// `sum()` over it silently multi-counts.
const (
	countMetricName            = "intune.devices.count"
	encryptedMetricName        = "intune.devices.encrypted.count"
	stalenessMetricName        = "intune.devices.sync_staleness_seconds"
	overviewOSMetricName       = "intune.devices.overview.total"
	overviewEnrolledMetricName = "intune.devices.overview.enrolled_device_count"
	overviewMdmMetricName      = "intune.devices.overview.mdm_enrolled_device_count"
	overviewDualEnrolledMetric = "intune.devices.overview.dual_enrolled_device_count"
	// osVersionCountMetricName (#124) is a standalone gauge, deliberately
	// NOT folded into countMetricName's (compliance_state, operating_system)
	// series - see the metric-naming rule above. It carries the fleet count
	// per distinct (operating_system, os_version) pair, one point per pair,
	// counted client-side over the same managedDevices fetch collectFleet
	// already pages (no additional Graph request). os_version rides the raw
	// operatingSystemVersion string unbucketed - see the const's own doc
	// comment for why, and what would change that.
	osVersionCountMetricName = "intune.devices.os_version.count"
)

// defaultBaseURL is the Graph v1.0 root. Both endpoints this collector polls
// (managedDevices, managedDeviceOverview) are v1.0 - this collector is NOT
// Experimental.
const defaultBaseURL = "https://graph.microsoft.com/v1.0"

// eventManagedDevice is the OTLP LogRecord EventName for the per-device log
// twin emitted alongside the fleet gauges - see the package doc's "Metric/log
// split" section. Frozen by #114.
const eventManagedDevice = "intune.managed_device"

// managedDevicesSelect limits the fleet-wide paged fetch to the fields the
// bounded gauges aggregate on (complianceState, operatingSystem, isEncrypted,
// lastSyncDateTime) PLUS the per-device identity fields the intune.managed_device
// log twin carries (id, deviceName, serialNumber, userPrincipalName) - #114 -
// PLUS osVersion (#124), which rides the same fetch to feed the standalone
// intune.devices.os_version.count gauge and the log twin's os_version
// attribute at zero extra Graph cost. Widening this further should stay
// deliberate: every field here rides along on a full-fleet page walk (see the
// package/issue notes on why full-fleet paging is the accepted exception for
// this endpoint).
const managedDevicesSelect = "?$select=id,complianceState,operatingSystem,isEncrypted,lastSyncDateTime,deviceName,serialNumber,userPrincipalName,osVersion"

// complianceBuckets maps every documented managedDevice complianceState
// value (https://learn.microsoft.com/en-us/graph/api/resources/intune-devices-manageddevice)
// to its bounded attribute value. Anything not in this map (a future beta
// enum addition, or a null/unexpected value) falls into "other" rather than
// being passed through raw, so the compliance_state dimension can never grow
// unbounded.
var complianceBuckets = map[string]string{
	"unknown":       "unknown",
	"compliant":     "compliant",
	"noncompliant":  "noncompliant",
	"conflict":      "conflict",
	"error":         "error",
	"inGracePeriod": "in_grace_period",
	"configManager": "config_manager",
}

func complianceBucketFor(raw string) string {
	if b, ok := complianceBuckets[raw]; ok {
		return b
	}
	return "other"
}

// osPrefixes buckets the free-text managedDevice.operatingSystem property
// (no enum in the Graph schema) into a small, fixed set of platform names,
// mirroring entra/devices' operatingSystem bucketing. A value matching none
// of these prefixes falls into "other", keeping the operating_system
// dimension bounded regardless of what clients report.
var osPrefixes = []struct {
	attr   string
	prefix string
}{
	{"windows", "Windows"},
	{"ipados", "iPadOS"},
	{"ios", "iOS"},
	{"macos", "macOS"},
	{"android", "Android"},
	{"linux", "Linux"},
}

func osBucketFor(raw string) string {
	for _, p := range osPrefixes {
		if hasPrefixFold(raw, p.prefix) {
			return p.attr
		}
	}
	return "other"
}

// hasPrefixFold reports whether s starts with prefix, ignoring case - Graph
// clients aren't perfectly consistent about e.g. "macOS" vs "MacOS".
func hasPrefixFold(s, prefix string) bool {
	if len(s) < len(prefix) {
		return false
	}
	return strings.EqualFold(s[:len(prefix)], prefix)
}

// osVersionOrUnknown returns the raw managedDevice.osVersion value verbatim,
// or "unknown" when the device didn't report one (#124). Unlike
// operatingSystem, osVersion is deliberately NOT bucketed further here - it
// ships as the full raw version string on both the os_version.count gauge and
// the intune.managed_device log twin. A live distinct-version-count
// measurement is the documented follow-up: if that count turns out large on
// a real fleet, minor-version bucketing (e.g. major.minor only) is the
// fallback, not a redesign.
func osVersionOrUnknown(raw string) string {
	if raw == "" {
		return "unknown"
	}
	return raw
}

// stalenessBuckets are the fixed sync-recency buckets for
// intune.devices.sync_staleness_seconds. Bounded (5 values) regardless of
// fleet size - never a per-device series.
const (
	stalenessUnder1Day  = "under_1d"
	staleness1To7Days   = "1d_7d"
	staleness7To30Days  = "7d_30d"
	stalenessOver30Days = "over_30d"
	stalenessUnknown    = "unknown"
)

// stalenessBucketFor buckets a device's lastSyncDateTime relative to now. A
// nil lastSyncDateTime (a device that has never synced) buckets to
// "unknown" rather than being guessed at or dropped.
func stalenessBucketFor(now time.Time, lastSync *time.Time) string {
	if lastSync == nil || lastSync.IsZero() {
		return stalenessUnknown
	}
	age := now.Sub(*lastSync)
	switch {
	case age < 24*time.Hour:
		return stalenessUnder1Day
	case age < 7*24*time.Hour:
		return staleness1To7Days
	case age < 30*24*time.Hour:
		return staleness7To30Days
	default:
		return stalenessOver30Days
	}
}

// deviceLogSeverity picks the intune.managed_device log twin's severity: Warn
// for the states an operator actually needs to act on - non-compliant
// (including the conflict/error compliance states, not just the literal
// "noncompliant" value), unencrypted, or sync-stale beyond 30 days - Info
// otherwise. The three triggers are independently sufficient; a device
// matching more than one still gets a single Warn (this reports the fact of
// needing attention, not which reason(s) apply - the reason is still visible
// via the twin's own attributes).
func deviceLogSeverity(complianceBucket string, encrypted bool, stalenessBucket string) telemetry.Severity {
	switch complianceBucket {
	case "noncompliant", "conflict", "error":
		return telemetry.SeverityWarn
	}
	if !encrypted {
		return telemetry.SeverityWarn
	}
	if stalenessBucket == stalenessOver30Days {
		return telemetry.SeverityWarn
	}
	return telemetry.SeverityInfo
}

// deviceLogTwin renders one managedDevice as the intune.managed_device OTLP
// log record - the per-device identity and raw state the fleet gauges above
// cannot carry (see the package doc). complianceBucket/stalenessBucket are
// passed in from collectFleet's own bucketing so the twin never redoes that
// work.
//
// Timestamp is deliberately left zero ("now", i.e. poll time): this is a
// STATE feed, not an event stream - the same device re-emits every cycle for
// as long as it stays enrolled, which is what makes "was device X enrolled on
// date Y" answerable (see the package doc).
func deviceLogTwin(d managedDevice, complianceBucket, stalenessBucket string) telemetry.Event {
	attrs := telemetry.Attrs{}
	telemetry.SetStr(attrs, semconv.AttrId, d.ID)
	telemetry.SetStr(attrs, semconv.AttrDeviceName, d.DeviceName)
	telemetry.SetStr(attrs, semconv.AttrSerialNumber, d.SerialNumber)
	telemetry.SetStr(attrs, semconv.AttrUserPrincipalName, d.UserPrincipalName)
	telemetry.SetStr(attrs, semconv.AttrComplianceState, d.ComplianceState)
	telemetry.SetStr(attrs, semconv.AttrOperatingSystem, d.OperatingSystem)
	telemetry.SetStr(attrs, semconv.AttrOsVersion, osVersionOrUnknown(d.OsVersion))
	attrs[semconv.AttrIsEncrypted] = strconv.FormatBool(d.IsEncrypted)
	attrs[semconv.AttrStalenessBucket] = stalenessBucket
	if d.LastSyncDateTime != nil && !d.LastSyncDateTime.IsZero() {
		attrs[semconv.AttrLastSyncDateTime] = d.LastSyncDateTime.Format(time.RFC3339)
	}

	name := d.DeviceName
	if name == "" {
		name = d.SerialNumber
	}
	if name == "" {
		name = d.ID
	}
	if name == "" {
		name = "unknown"
	}

	return telemetry.Event{
		Name:     eventManagedDevice,
		Body:     fmt.Sprintf("managed device %s: compliance_state=%s operating_system=%s is_encrypted=%t", name, d.ComplianceState, d.OperatingSystem, d.IsEncrypted),
		Severity: deviceLogSeverity(complianceBucket, d.IsEncrypted, stalenessBucket),
		Attrs:    attrs,
	}
}

// managedDevice is the subset of the managedDevice resource this collector
// reads. ComplianceState/OperatingSystem/IsEncrypted/LastSyncDateTime feed the
// bounded gauges (bucketed - see complianceBucketFor/osBucketFor/
// stalenessBucketFor) AND ride along raw onto the intune.managed_device log
// twin. ID/DeviceName/SerialNumber/UserPrincipalName are per-entity
// identifiers that must NEVER become a metric label - but "never a metric
// label" means "log twin", not "dropped" (see the package doc's "Metric/log
// split" section and #114): this collector used to omit them from the Graph
// request entirely, which was the bug, not a privacy control.
type managedDevice struct {
	ComplianceState  string     `json:"complianceState"`
	OperatingSystem  string     `json:"operatingSystem"`
	OsVersion        string     `json:"osVersion"`
	IsEncrypted      bool       `json:"isEncrypted"`
	LastSyncDateTime *time.Time `json:"lastSyncDateTime"`

	ID                string `json:"id"`
	DeviceName        string `json:"deviceName"`
	SerialNumber      string `json:"serialNumber"`
	UserPrincipalName string `json:"userPrincipalName"`
}

// managedDeviceOverview is the managedDeviceOverview singleton
// (https://learn.microsoft.com/en-us/graph/api/resources/intune-devices-manageddeviceoverview),
// a Microsoft-maintained aggregation used here as a cheap cross-check
// alongside the self-rolled fleet count. It can drift slightly from a live
// count (aggregation lag) - it is a sanity gauge, not a replacement.
type managedDeviceOverview struct {
	EnrolledDeviceCount          int64           `json:"enrolledDeviceCount"`
	MdmEnrolledCount             int64           `json:"mdmEnrolledCount"`
	DualEnrolledDeviceCount      int64           `json:"dualEnrolledDeviceCount"`
	DeviceOperatingSystemSummary deviceOSSummary `json:"deviceOperatingSystemSummary"`
}

// deviceOSSummary is Microsoft's fixed schema of overview count fields
// (https://learn.microsoft.com/en-us/graph/api/resources/intune-devices-deviceoperatingsystemsummary).
// Every field maps to exactly one bounded "os" attribute value below - the
// set is fixed by Graph's own schema, not tenant-driven, so it can never
// grow with fleet size.
type deviceOSSummary struct {
	AndroidCount                     int64 `json:"androidCount"`
	IosCount                         int64 `json:"iosCount"`
	MacOSCount                       int64 `json:"macOSCount"`
	WindowsMobileCount               int64 `json:"windowsMobileCount"`
	WindowsCount                     int64 `json:"windowsCount"`
	UnknownCount                     int64 `json:"unknownCount"`
	AndroidDedicatedCount            int64 `json:"androidDedicatedCount"`
	AndroidDeviceAdminCount          int64 `json:"androidDeviceAdminCount"`
	AndroidFullyManagedCount         int64 `json:"androidFullyManagedCount"`
	AndroidWorkProfileCount          int64 `json:"androidWorkProfileCount"`
	AndroidCorporateWorkProfileCount int64 `json:"androidCorporateWorkProfileCount"`
	ConfigMgrDeviceCount             int64 `json:"configMgrDeviceCount"`
}

// points returns the overview OS/management-mode breakdown as bounded gauge
// points, one per fixed schema field.
func (s deviceOSSummary) points() []telemetry.GaugePoint {
	return []telemetry.GaugePoint{
		{Value: float64(s.AndroidCount), Attrs: telemetry.Attrs{semconv.AttrOs: "android"}},
		{Value: float64(s.IosCount), Attrs: telemetry.Attrs{semconv.AttrOs: "ios"}},
		{Value: float64(s.MacOSCount), Attrs: telemetry.Attrs{semconv.AttrOs: "macos"}},
		{Value: float64(s.WindowsMobileCount), Attrs: telemetry.Attrs{semconv.AttrOs: "windows_mobile"}},
		{Value: float64(s.WindowsCount), Attrs: telemetry.Attrs{semconv.AttrOs: "windows"}},
		{Value: float64(s.UnknownCount), Attrs: telemetry.Attrs{semconv.AttrOs: "unknown"}},
		{Value: float64(s.AndroidDedicatedCount), Attrs: telemetry.Attrs{semconv.AttrOs: "android_dedicated"}},
		{Value: float64(s.AndroidDeviceAdminCount), Attrs: telemetry.Attrs{semconv.AttrOs: "android_device_admin"}},
		{Value: float64(s.AndroidFullyManagedCount), Attrs: telemetry.Attrs{semconv.AttrOs: "android_fully_managed"}},
		{Value: float64(s.AndroidWorkProfileCount), Attrs: telemetry.Attrs{semconv.AttrOs: "android_work_profile"}},
		{Value: float64(s.AndroidCorporateWorkProfileCount), Attrs: telemetry.Attrs{semconv.AttrOs: "android_corporate_work_profile"}},
		{Value: float64(s.ConfigMgrDeviceCount), Attrs: telemetry.Attrs{semconv.AttrOs: "config_mgr"}},
	}
}

// Collector polls the Intune managedDevices fleet inventory and the
// managedDeviceOverview singleton.
type Collector struct {
	g       collectors.GraphClient
	baseURL string
	logger  *slog.Logger
	// fleet fetches the managedDevices list. Defaults to an uncached
	// DirectFleetFetcher over g (so unit tests are unchanged); the composition
	// root injects a shared CachingFleetFetcher via the factory so this and
	// intune.malware page the fleet once between them (#87).
	fleet collectors.FleetFetcher
	// now returns the current time; overridable in tests so staleness
	// bucketing is deterministic and assertable.
	now func() time.Time
}

// New builds the managed-devices collector. A nil logger falls back to the
// slog default.
func New(g collectors.GraphClient, logger *slog.Logger) *Collector {
	if logger == nil {
		logger = slog.Default()
	}
	return &Collector{
		g:       g,
		baseURL: defaultBaseURL,
		logger:  logger,
		fleet:   &collectors.DirectFleetFetcher{G: g, URL: defaultBaseURL + "/deviceManagement/managedDevices" + managedDevicesSelect},
		now:     time.Now,
	}
}

// Name implements collector.SnapshotCollector.
func (c *Collector) Name() string { return collectorName }

// DefaultInterval implements collector.SnapshotCollector. A full-fleet page
// walk plus the overview singleton is the most expensive M4 poll cycle (no
// delta query, Elevated Devices throttle tier), and fleet compliance/OS
// composition drifts slowly, so this defaults to a longer cadence than the
// lighter Entra directory-shaped collectors.
func (c *Collector) DefaultInterval() time.Duration { return time.Hour }

// RequiredPermissions declares the least-privilege Graph application scope.
// Per https://learn.microsoft.com/en-us/graph/api/intune-devices-manageddevice-list,
// DeviceManagementManagedDevices.Read.All is the permission both
// managedDevices and managedDeviceOverview document.
func (c *Collector) RequiredPermissions() []string {
	return []string{"DeviceManagementManagedDevices.Read.All"}
}

// Collect fetches the managedDeviceOverview singleton and the full
// managedDevices fleet list, and emits the bounded gauges described in the
// package doc. The two fetches are independently resilient: a failure in one
// is logged and joined into the returned error, but the other's metrics
// still emit.
//
// Paging the full managedDevices collection is normally the wrong pattern
// for a snapshot collector (see internal/collectors.GetAllValues), but it is
// the deliberate exception here: managedDevices' only annotated $filter
// properties don't cover complianceState/operatingSystem/isEncrypted
// aggregation, so there is no bounded $count slice to lean on instead - the
// issue and the M4 authoring guide both call this out as the one case where
// full-fleet paging is correct, provided the result is rolled up into
// bounded buckets (never a per-device series), which is exactly what this
// method does.
//
// The beta-only hardwareInformation per-device sweep described in the
// tracking issue is deliberately NOT implemented here: it would cost one
// Graph call per device (10k+ calls/cycle on a large fleet) and the
// collector framework has no per-collector config-flag plumbing yet to gate
// it safely opt-in/default-off. Deferred rather than shipped enabled - see
// the tracking issue for the follow-up.
func (c *Collector) Collect(ctx context.Context, e telemetry.Emitter) error {
	var errs []error

	if err := c.collectOverview(ctx, e); err != nil {
		c.logger.Warn("manageddevices: overview fetch failed", "collector", collectorName, "error", err)
		errs = append(errs, fmt.Errorf("overview: %w", err))
	}

	if err := c.collectFleet(ctx, e); err != nil {
		c.logger.Warn("manageddevices: managedDevices list failed", "collector", collectorName, "error", err)
		errs = append(errs, fmt.Errorf("managed devices: %w", err))
	}

	return errors.Join(errs...)
}

// collectOverview reads the managedDeviceOverview singleton and emits the
// three scalar cross-check gauges plus the bounded OS/management-mode
// breakdown.
func (c *Collector) collectOverview(ctx context.Context, e telemetry.Emitter) error {
	body, err := c.g.RawGet(ctx, c.baseURL+"/deviceManagement/managedDeviceOverview")
	if err != nil {
		return err
	}
	var ov managedDeviceOverview
	if err := json.Unmarshal(body, &ov); err != nil {
		return fmt.Errorf("decode managedDeviceOverview: %w", err)
	}

	e.Gauge(overviewEnrolledMetricName, "{device}", "Total enrolled Intune device count (managedDeviceOverview cross-check, may lag the live count).", float64(ov.EnrolledDeviceCount), nil)
	e.Gauge(overviewMdmMetricName, "{device}", "Devices enrolled in MDM (managedDeviceOverview cross-check, may lag the live count).", float64(ov.MdmEnrolledCount), nil)
	e.Gauge(overviewDualEnrolledMetric, "{device}", "Devices enrolled in both MDM and EAS (managedDeviceOverview cross-check, may lag the live count).", float64(ov.DualEnrolledDeviceCount), nil)
	e.GaugeSnapshot(overviewOSMetricName, "{device}", "Intune managedDeviceOverview device counts by operating system / Android management mode (Microsoft-aggregated cross-check, may lag the live count).", ov.DeviceOperatingSystemSummary.points())
	return nil
}

// collectFleet pages the full managedDevices collection (see the Collect doc
// comment for why full-fleet paging is the deliberate exception here) and
// rolls it up into the bounded compliance/OS/encryption/staleness gauges. A
// single malformed element is logged and skipped rather than failing the
// whole aggregate.
func (c *Collector) collectFleet(ctx context.Context, e telemetry.Emitter) error {
	raw, err := c.fleet.ManagedDevices(ctx)
	if err != nil {
		return err
	}

	counts := map[[2]string]int64{}
	encrypted := map[string]int64{}
	staleness := map[string]int64{}
	osVersionCounts := map[[2]string]int64{}
	now := c.now()

	for _, r := range raw {
		var d managedDevice
		if err := json.Unmarshal(r, &d); err != nil {
			c.logger.Warn("manageddevices: skipping malformed managedDevice element", "collector", collectorName, "error", err)
			continue
		}
		compliance := complianceBucketFor(d.ComplianceState)
		os := osBucketFor(d.OperatingSystem)
		counts[[2]string{compliance, os}]++
		if d.IsEncrypted {
			encrypted[os]++
		}
		staleBucket := stalenessBucketFor(now, d.LastSyncDateTime)
		staleness[staleBucket]++
		osVersionCounts[[2]string{os, osVersionOrUnknown(d.OsVersion)}]++
		e.LogEvent(deviceLogTwin(d, compliance, staleBucket))
	}

	countPoints := make([]telemetry.GaugePoint, 0, len(counts))
	for k, v := range counts {
		countPoints = append(countPoints, telemetry.GaugePoint{
			Value: float64(v),
			Attrs: telemetry.Attrs{semconv.AttrComplianceState: k[0], semconv.AttrOperatingSystem: k[1]},
		})
	}
	e.GaugeSnapshot(countMetricName, "{device}", "Intune managed device fleet count, by compliance state and operating system.", countPoints)

	encPoints := make([]telemetry.GaugePoint, 0, len(encrypted))
	for os, v := range encrypted {
		encPoints = append(encPoints, telemetry.GaugePoint{Value: float64(v), Attrs: telemetry.Attrs{semconv.AttrOperatingSystem: os}})
	}
	e.GaugeSnapshot(encryptedMetricName, "{device}", "Intune managed devices reporting isEncrypted=true, by operating system.", encPoints)

	stalePoints := make([]telemetry.GaugePoint, 0, len(staleness))
	for bucket, v := range staleness {
		stalePoints = append(stalePoints, telemetry.GaugePoint{Value: float64(v), Attrs: telemetry.Attrs{semconv.AttrStalenessBucket: bucket}})
	}
	e.GaugeSnapshot(stalenessMetricName, "{device}", "Intune managed devices bucketed by time since lastSyncDateTime.", stalePoints)

	osVersionPoints := make([]telemetry.GaugePoint, 0, len(osVersionCounts))
	for k, v := range osVersionCounts {
		osVersionPoints = append(osVersionPoints, telemetry.GaugePoint{
			Value: float64(v),
			Attrs: telemetry.Attrs{semconv.AttrOperatingSystem: k[0], semconv.AttrOsVersion: k[1]},
		})
	}
	e.GaugeSnapshot(osVersionCountMetricName, "{device}", "Intune managed device fleet count, by operating system bucket and raw operatingSystemVersion (unbucketed full version string; osVersion=\"unknown\" when the device reported none).", osVersionPoints)

	return nil
}

var _ collector.SnapshotCollector = (*Collector)(nil)

func init() {
	collectors.Register(func(d collectors.Deps) collector.SnapshotCollector {
		c := New(d.Graph, d.Logger)
		if d.Fleet != nil {
			c.fleet = d.Fleet // shared per-tenant fetch (#87)
		}
		return c
	})
}
