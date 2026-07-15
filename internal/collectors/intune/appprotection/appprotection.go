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
// is ever read into a metric label here; that data belongs in the M5 logs
// pipeline, never a metric dimension.
//
// windowsInformationProtectionPolicies and mdmWindowsInformationProtectionPolicies
// are both v1.0 (not beta) but represent a legacy WIP-without-MAM-SDK
// surface Microsoft has deprecated in favor of MAM app protection policies;
// they are tracked here only as a coarse legacy policy count, not broken out
// further.
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

// appIdentifier is the narrow subset of managedAppRegistration.appIdentifier
// this collector reads - only its @odata.type, to bucket a coarse platform.
// The concrete packageId/bundleId fields are per-app identifiers and are
// deliberately never read here.
type appIdentifier struct {
	ODataType string `json:"@odata.type"`
}

// managedAppRegistration is the subset of the managedAppRegistration
// resource this collector aggregates on. userId, deviceTag, deviceName, and
// every other per-entity identifier documented on the resource are
// deliberately never read - see the package doc.
type managedAppRegistration struct {
	FlaggedReasons []string       `json:"flaggedReasons"`
	AppIdentifier  *appIdentifier `json:"appIdentifier"`
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
			Attrs: telemetry.Attrs{"platform": k.platform, "assigned": k.assigned},
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
	url := c.baseURL + "/deviceAppManagement/managedAppRegistrations?$select=flaggedReasons,appIdentifier&$top=999"
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
		for _, reason := range reasons {
			counts[registrationBucketKey{reason: flaggedReasonBucketFor(reason), platform: platform}]++
		}
	}

	points := make([]telemetry.GaugePoint, 0, len(counts))
	for k, v := range counts {
		points = append(points, telemetry.GaugePoint{
			Value: float64(v),
			Attrs: telemetry.Attrs{"flagged_reason": k.reason, "platform": k.platform},
		})
	}
	e.GaugeSnapshot(flaggedRegistrationsMetricName, "{registration}", "Intune managed app registrations, by aggregated flagged reason and platform (never a per-user or per-app series).", points)

	return nil
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
			Attrs: telemetry.Attrs{"assigned": assigned},
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
