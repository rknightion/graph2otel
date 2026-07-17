// Package appprotection is the Intune app protection / MAM collector:
// bounded aggregate gauges over the `/deviceAppManagement` mobile
// application management (MAM) surface — iOS and Android app protection
// policies, cross-platform targeted app configurations, the legacy Windows
// Information Protection (WIP) policy surface, and a flagged-registration
// count rolled up from the (potentially huge) managedAppRegistrations
// collection.
//
// managedAppRegistrations is one row per user-per-managed-app on the
// tenant and can run into the tens or hundreds of thousands on a large
// estate - this is the same "full-collection paging is the deliberate
// exception, provided the result collapses into bounded buckets" pattern
// documented on internal/collectors/intune/manageddevices. No per-entity
// field (userId, appIdentifier detail beyond its coarse platform, deviceTag)
// is ever read into a metric label here - that data belongs in the logs
// pipeline (see "Metric/log split" below), never a metric dimension.
//
// windowsInformationProtectionPolicies and mdmWindowsInformationProtectionPolicies
// are both v1.0 (not beta) but represent a legacy WIP-without-MAM-SDK
// surface Microsoft has deprecated in favor of MAM app protection policies;
// they are tracked here only as a coarse legacy policy count, not broken out
// further.
//
// # Metric/log split (#114)
//
// The managedAppRegistrations flagged-reason rollup used to read only
// flaggedReasons and appIdentifier's coarse platform, discarding userId and
// deviceTag entirely - so "which user has a rooted device running a managed
// app" was unanswerable even in principle. That was the bug (#112/#114), not
// a privacy control: per-entity identity must never become a metric LABEL,
// but "never a label" means "log twin", not "dropped".
//
// Unlike manageddevices/mfaregistration (twinned EVERY row per #114's
// maintainer decision, because those collections are bounded by device/user
// count), managedAppRegistrations is a user x app CROSS PRODUCT that can run
// into the tens/hundreds of thousands per the package doc above - the same
// unbounded-volume shape that got entra.consent's per-grant twin scoped down
// to "high-privilege grants only" rather than every grant. So this collector
// twins only registrations carrying an actual flagged reason (anything but
// the bounded "none" bucket, including an unrecognized future reason bucketed
// "other" - surfaced rather than silently dropped) as the
// intune.app_registration log record, carrying userId/deviceTag/platform/
// flagged_reasons. An unflagged registration contributes only to the
// flagged_registrations gauge, never a log. Severity escalates to Warn only
// for a recognized rooted/jailbroken signal (the rootedDevice bucket) - an
// unrecognized reason is still twinned but stays Info, since its meaning
// isn't known yet.
package appprotection

import (
	"bytes"
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
const collectorName = "intune.app_protection"

// Metric names this collector emits. Each is its own metric name so that
// summing a single metric always yields the true count for that breakdown -
// mixing independent dimensions under one metric name would mean a naive
// `sum()` over it silently multi-counts.
const (
	policyCountMetricName          = "intune.app_protection.policy.count"
	flaggedRegistrationsMetricName = "intune.app_protection.flagged_registrations"
	wipPolicyCountMetricName       = "intune.wip.policy.count"
)

// eventAppRegistration is the OTLP LogRecord EventName for the per-flagged-
// registration log twin emitted alongside flaggedRegistrationsMetricName -
// see the package doc's "Metric/log split" section. Frozen by #114.
const eventAppRegistration = "intune.app_registration"

// defaultBaseURL is the Graph v1.0 root. Every endpoint this collector polls
// is v1.0 - this collector is NOT Experimental.
const defaultBaseURL = "https://graph.microsoft.com/v1.0"

// policySource pairs a bounded "platform" attribute value with the app
// protection / app configuration list endpoint that provides it.
// targetedManagedAppConfigurations is not platform-specific (it is Intune's
// cross-platform "app configuration policy for managed apps" surface), so it
// buckets to "cross_platform" rather than ios/android.
type policySource struct {
	platform string
	path     string
}

var policySources = []policySource{
	{"ios", "/deviceAppManagement/iosManagedAppProtections"},
	{"android", "/deviceAppManagement/androidManagedAppProtections"},
	{"cross_platform", "/deviceAppManagement/targetedManagedAppConfigurations"},
}

// wipPolicyPaths are the two legacy WIP policy list endpoints rolled up into
// a single combined intune.wip.policy.count series - see the package doc for
// why these are tracked only as a coarse legacy count.
var wipPolicyPaths = []string{
	"/deviceAppManagement/windowsInformationProtectionPolicies",
	"/deviceAppManagement/mdmWindowsInformationProtectionPolicies",
}

// assignablePolicy is the subset every policy/configuration list element in
// this collector is decoded into: only the isAssigned Boolean documented on
// managedAppPolicy-derived (iOS/Android protection, targeted app config) and
// windowsInformationProtection-derived (WIP, MDM WIP) resources. No
// displayName, id, or other per-policy identifier is ever read - policy
// counts are bounded by admin-configured policy count, not by any per-entity
// value, so nothing here needs to become "other"-bucketed.
type assignablePolicy struct {
	IsAssigned bool `json:"isAssigned"`
}

// flaggedReasonBuckets maps every documented managedAppFlaggedReason value
// (https://learn.microsoft.com/en-us/graph/api/resources/intune-mam-managedappflaggedreason)
// to its bounded attribute value. A value not in this map (a future enum
// addition) falls into "other" rather than being passed through raw, so the
// flagged_reason dimension can never grow unbounded.
var flaggedReasonBuckets = map[string]string{
	"none":         "none",
	"rootedDevice": "rooted_device",
}

func flaggedReasonBucketFor(raw string) string {
	if b, ok := flaggedReasonBuckets[raw]; ok {
		return b
	}
	return "other"
}

// registrationPlatformFor buckets a managedAppRegistration's appIdentifier
// @odata.type into a bounded platform value. Graph API responses carry a
// leading '#' on @odata.type; documentation examples sometimes omit it, so
// both forms are accepted. Anything else (a future app-identifier subtype,
// or a registration with no appIdentifier at all) falls into "other".
func registrationPlatformFor(odataType string) string {
	switch strings.TrimPrefix(odataType, "#") {
	case "microsoft.graph.androidMobileAppIdentifier":
		return "android"
	case "microsoft.graph.iosMobileAppIdentifier":
		return "ios"
	default:
		return "other"
	}
}

// appIdentifier mirrors the fields of managedAppRegistration.appIdentifier
// this collector reads. ODataType feeds the bounded platform bucket on the
// METRIC (registrationPlatformFor) and is never anything else. PackageID and
// BundleID are the polymorphic subtype's own concrete per-app identifier -
// androidMobileAppIdentifier.packageId (verified against
// learn.microsoft.com/en-us/graph/api/resources/intune-mam-androidmobileappidentifier)
// and iosMobileAppIdentifier.bundleId (intune-mam-iosmobileappidentifier) -
// mutually exclusive per platform, since a registration decodes as exactly
// one subtype. These ride onto the intune.app_registration log twin ONLY,
// for flagged registrations, as a single app_identifier attribute (see
// registrationLogTwin) - never a metric label. This collector used to decode
// only @odata.type and throw the concrete identifier away entirely: that was
// the #112 decode-and-drop bug, not a privacy control - "which app" is a
// material part of "which user has a rooted device running a managed app",
// and the concrete app set in a tenant is small and admin-configured (dozens
// of managed apps), so it was never a cardinality problem for the log side
// either.
type appIdentifier struct {
	ODataType string `json:"@odata.type"`
	PackageID string `json:"packageId"`
	BundleID  string `json:"bundleId"`
}

// concreteAppID returns whichever of PackageID/BundleID is present - the two
// are mutually exclusive per platform subtype, so at most one is ever
// non-empty.
func (a appIdentifier) concreteAppID() string {
	if a.PackageID != "" {
		return a.PackageID
	}
	return a.BundleID
}

// managedAppRegistration is the subset of the managedAppRegistration
// resource this collector reads. FlaggedReasons/AppIdentifier feed the
// bounded flagged_registrations gauge; UserID/DeviceTag are per-entity
// identifiers that must NEVER become a metric label, but ride along onto the
// intune.app_registration log twin for FLAGGED registrations only - see the
// package doc's "Metric/log split" section. deviceName and every other
// per-entity identifier documented on the resource remain unread: not needed
// by either output.
type managedAppRegistration struct {
	FlaggedReasons []string       `json:"flaggedReasons"`
	AppIdentifier  *appIdentifier `json:"appIdentifier"`
	UserID         string         `json:"userId"`
	DeviceTag      string         `json:"deviceTag"`
}

// Collector polls the Intune MAM app protection / configuration surface and
// the legacy WIP policy surface.
type Collector struct {
	g       collectors.GraphClient
	baseURL string
	logger  *slog.Logger
}

// New builds the app protection collector. A nil logger falls back to the
// slog default.
func New(g collectors.GraphClient, logger *slog.Logger) *Collector {
	if logger == nil {
		logger = slog.Default()
	}
	return &Collector{g: g, baseURL: defaultBaseURL, logger: logger}
}

// Name implements collector.SnapshotCollector.
func (c *Collector) Name() string { return collectorName }

// DefaultInterval implements collector.SnapshotCollector. Policy/config
// lists are small (bounded by admin-configured policy count) and cheap, but
// the managedAppRegistrations paging can be the heaviest fetch in this
// collector on a large estate, so this gets a longer cadence than a
// directory-object-shaped collector while staying shorter than a full-fleet
// device paging collector.
func (c *Collector) DefaultInterval() time.Duration { return 30 * time.Minute }

// RequiredPermissions declares the least-privilege Graph application scope.
// Per https://learn.microsoft.com/en-us/graph/api/intune-mam-iosmanagedappprotection-list
// (and the sibling Android/targeted-config/WIP list endpoints),
// DeviceManagementApps.Read.All is the permission every endpoint this
// collector polls documents.
func (c *Collector) RequiredPermissions() []string {
	return []string{"DeviceManagementApps.Read.All"}
}

// Collect fetches every app protection / configuration source and emits the
// three bounded gauges described in the package doc. Each source is
// independently resilient: a failure fetching one is logged and joined into
// the returned error, but every other metric still emits.
func (c *Collector) Collect(ctx context.Context, e telemetry.Emitter) error {
	var errs []error

	if err := c.collectPolicyCounts(ctx, e); err != nil {
		errs = append(errs, err)
	}
	if err := c.collectFlaggedRegistrations(ctx, e); err != nil {
		errs = append(errs, err)
	}
	if err := c.collectWIPPolicyCounts(ctx, e); err != nil {
		errs = append(errs, err)
	}

	return errors.Join(errs...)
}

// policyBucketKey is the (platform, assigned) key for the combined
// intune.app_protection.policy.count snapshot.
type policyBucketKey struct {
	platform string
	assigned bool
}

// collectPolicyCounts fetches the iOS/Android app protection policy lists
// and the cross-platform targeted app configuration list, and emits one
// combined gauge snapshot bucketed by platform and assignment state. Each
// source is fetched and decoded independently: a failure fetching one
// source is logged and that platform's counts are simply absent from the
// snapshot (not zero-filled), while the other sources still emit.
func (c *Collector) collectPolicyCounts(ctx context.Context, e telemetry.Emitter) error {
	var errs []error
	counts := map[policyBucketKey]int64{}

	for _, src := range policySources {
		raw, err := collectors.GetAllValues(ctx, c.g, c.baseURL+src.path+"?$select=isAssigned", nil)
		if err != nil {
			c.logger.Warn("appprotection: policy list fetch failed", "collector", collectorName, "platform", src.platform, "error", err)
			errs = append(errs, fmt.Errorf("%s policies: %w", src.platform, err))
			continue
		}
		for _, r := range raw {
			var p assignablePolicy
			if err := json.Unmarshal(r, &p); err != nil {
				c.logger.Warn("appprotection: skipping malformed policy element", "collector", collectorName, "platform", src.platform, "error", err)
				continue
			}
			counts[policyBucketKey{platform: src.platform, assigned: p.IsAssigned}]++
		}
	}

	points := make([]telemetry.GaugePoint, 0, len(counts))
	for k, v := range counts {
		points = append(points, telemetry.GaugePoint{
			Value: float64(v),
			Attrs: telemetry.Attrs{semconv.AttrPlatform: k.platform, semconv.AttrAssigned: k.assigned},
		})
	}
	e.GaugeSnapshot(policyCountMetricName, "{policy}", "Intune app protection / app configuration policy count, by platform and assignment state.", points)

	return errors.Join(errs...)
}

// registrationBucketKey is the (reason, platform) key for the
// intune.app_protection.flagged_registrations snapshot.
type registrationBucketKey struct {
	reason   string
	platform string
}

// collectFlaggedRegistrations pages the full managedAppRegistrations
// collection (see the package doc for why full-collection paging is the
// deliberate exception here) and rolls it up into a bounded
// (flagged_reason, platform) gauge snapshot. A registration with no
// flaggedReasons entries is counted under the "none" reason bucket, same as
// an explicit ["none"] entry, so every registration is accounted for
// exactly once per reason it carries. A single malformed element is logged
// and skipped rather than failing the whole aggregate.
func (c *Collector) collectFlaggedRegistrations(ctx context.Context, e telemetry.Emitter) error {
	url := c.baseURL + "/deviceAppManagement/managedAppRegistrations?$select=flaggedReasons,appIdentifier,userId,deviceTag&$top=999"
	raw, err := collectors.GetAllValues(ctx, c.g, url, nil)
	if err != nil {
		c.logger.Warn("appprotection: managedAppRegistrations fetch failed", "collector", collectorName, "error", err)
		return fmt.Errorf("managed app registrations: %w", err)
	}

	counts := map[registrationBucketKey]int64{}
	for _, r := range raw {
		var reg managedAppRegistration
		if err := json.Unmarshal(r, &reg); err != nil {
			c.logger.Warn("appprotection: skipping malformed managedAppRegistration element", "collector", collectorName, "error", err)
			continue
		}
		platform := "other"
		if reg.AppIdentifier != nil {
			platform = registrationPlatformFor(reg.AppIdentifier.ODataType)
		}
		reasons := reg.FlaggedReasons
		if len(reasons) == 0 {
			reasons = []string{"none"}
		}
		reasonBuckets := make([]string, 0, len(reasons))
		flagged := false
		for _, reason := range reasons {
			bucket := flaggedReasonBucketFor(reason)
			counts[registrationBucketKey{reason: bucket, platform: platform}]++
			reasonBuckets = append(reasonBuckets, bucket)
			if bucket != "none" {
				flagged = true
			}
		}
		// Only FLAGGED registrations get a log twin - see the package doc's
		// "Metric/log split" section for why every registration is not
		// twinned (unlike manageddevices/mfaregistration).
		if flagged {
			e.LogEvent(registrationLogTwin(reg, platform, reasonBuckets))
		}
	}

	points := make([]telemetry.GaugePoint, 0, len(counts))
	for k, v := range counts {
		points = append(points, telemetry.GaugePoint{
			Value: float64(v),
			Attrs: telemetry.Attrs{semconv.AttrFlaggedReason: k.reason, semconv.AttrPlatform: k.platform},
		})
	}
	e.GaugeSnapshot(flaggedRegistrationsMetricName, "{registration}", "Intune managed app registrations, by aggregated flagged reason and platform (never a per-user or per-app series).", points)

	return nil
}

// registrationLogTwin renders one FLAGGED managedAppRegistration as the
// intune.app_registration OTLP log record - the per-registration identity
// (userId, deviceTag, and the concrete per-app identifier) the
// flagged_registrations gauge cannot carry, alongside the bucketed flagged
// reasons and platform. Timestamp is left zero (poll time): this is a state
// feed re-emitted every cycle for as long as the registration stays flagged,
// not an event stream.
//
// The concrete app identifier (packageId/bundleId, see appIdentifier) is
// emitted as a SINGLE app_identifier attribute rather than two separately-
// named attributes: the two are mutually exclusive per platform (a
// registration is exactly one subtype), so two attrs would mean one is
// always absent - one attribute that means "whichever concrete identifier
// this platform carries" reads better paired with the platform attribute
// than two sparse ones would.
//
// Severity escalates to Warn only for a recognized rooted/jailbroken signal
// (the "rooted_device" bucket) - an unrecognized future reason (bucketed
// "other") is still twinned, never silently dropped, but stays Info since its
// meaning isn't known yet.
func registrationLogTwin(reg managedAppRegistration, platform string, reasonBuckets []string) telemetry.Event {
	attrs := telemetry.Attrs{}
	telemetry.SetStr(attrs, semconv.AttrUserId, reg.UserID)
	telemetry.SetStr(attrs, semconv.AttrDeviceTag, reg.DeviceTag)
	telemetry.SetStr(attrs, semconv.AttrPlatform, platform)
	if reg.AppIdentifier != nil {
		telemetry.SetStr(attrs, semconv.AttrAppIdentifier, reg.AppIdentifier.concreteAppID())
	}
	reasonsJoined := strings.Join(reasonBuckets, ",")
	telemetry.SetStr(attrs, semconv.AttrFlaggedReasons, reasonsJoined)

	sev := telemetry.SeverityInfo
	for _, b := range reasonBuckets {
		if b == "rooted_device" {
			sev = telemetry.SeverityWarn
			break
		}
	}

	return telemetry.Event{
		Name:     eventAppRegistration,
		Body:     fmt.Sprintf("flagged managed app registration (%s): %s", platform, reasonsJoined),
		Severity: sev,
		Attrs:    attrs,
	}
}

// wipPolicyPage is the odata envelope a WIP policy list page decodes into.
// Kept narrow (only isAssigned) for the same reason as assignablePolicy.
type wipPolicyPage struct {
	Value    []assignablePolicy `json:"value"`
	NextLink string             `json:"@odata.nextLink"`
}

// fetchWIPPolicies pages a WIP policy list endpoint via RawGet (not
// collectors.GetAllValues) so it can tolerate an empty response body as an
// empty page rather than a JSON decode error. windowsInformationProtectionPolicies
// and mdmWindowsInformationProtectionPolicies are both product-deprecated
// (removed as a Windows feature in 24H2+), and at least one tenant has been
// observed live returning a genuinely empty body from these endpoints - Graph
// documents no explicit "zero results" body shape for them, so an empty body
// is treated as "zero WIP policies" here, not a fetch failure. A non-empty
// but unparseable body (or a transport/HTTP error) is still a real failure
// and is returned as such; the caller decides how to degrade.
func (c *Collector) fetchWIPPolicies(ctx context.Context, url string) ([]assignablePolicy, error) {
	var out []assignablePolicy
	next := url
	for next != "" {
		body, err := c.g.RawGet(ctx, next)
		if err != nil {
			return nil, err
		}
		if len(bytes.TrimSpace(body)) == 0 {
			break
		}
		var page wipPolicyPage
		if err := json.Unmarshal(body, &page); err != nil {
			return nil, fmt.Errorf("decode page from %q: %w", next, err)
		}
		out = append(out, page.Value...)
		next = page.NextLink
	}
	return out, nil
}

// collectWIPPolicyCounts fetches both legacy WIP policy list endpoints and
// emits one combined gauge snapshot bucketed only by assignment state - see
// the package doc for why these are tracked as a coarse legacy count rather
// than broken out by endpoint.
//
// Unlike every other source in this collector, a WIP fetch failure is
// deliberately best-effort: these endpoints are product-deprecated, observed
// live to sometimes respond with an empty body Graph's own schema doesn't
// document a shape for, and are not worth failing the whole collector's
// self-obs status over. Any error (fetch error, non-404 HTTP failure, or a
// non-empty-but-unparseable body) from either endpoint is logged at Info and
// the entire intune.wip.policy.count series is dropped for this cycle -
// never partially emitted from whichever endpoint happened to succeed, and
// never appended to the collector's returned error.
func (c *Collector) collectWIPPolicyCounts(ctx context.Context, e telemetry.Emitter) error {
	counts := map[bool]int64{}

	for _, path := range wipPolicyPaths {
		list, err := c.fetchWIPPolicies(ctx, c.baseURL+path+"?$select=isAssigned")
		if err != nil {
			c.logger.Info("appprotection: WIP policies unavailable (deprecated endpoint); skipping WIP metrics", "collector", collectorName, "path", path, "error", err)
			return nil
		}
		for _, p := range list {
			counts[p.IsAssigned]++
		}
	}

	points := make([]telemetry.GaugePoint, 0, len(counts))
	for assigned, v := range counts {
		points = append(points, telemetry.GaugePoint{
			Value: float64(v),
			Attrs: telemetry.Attrs{semconv.AttrAssigned: assigned},
		})
	}
	e.GaugeSnapshot(wipPolicyCountMetricName, "{policy}", "Legacy Windows Information Protection (WIP) policy count (windowsInformationProtectionPolicies + mdmWindowsInformationProtectionPolicies), by assignment state.", points)

	return nil
}

var _ collector.SnapshotCollector = (*Collector)(nil)

func init() {
	collectors.Register(func(d collectors.Deps) collector.SnapshotCollector {
		return New(d.Graph, d.Logger)
	})
}
