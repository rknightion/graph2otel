// Package crosstenantaccess is the Entra cross-tenant access policy collector
// (#321): the tenant's inbound/outbound B2B collaboration, B2B direct-connect,
// tenant-restriction, inbound-trust and automatic-consent boundaries — the
// controls that decide whether an external Entra tenant's users, apps and
// devices can reach into this one, and vice versa.
//
// This is deliberately distinct from Global Secure Access's
// /networkAccess/settings/crossTenantAccess, a different control plane not
// covered here. It is also distinct from B2C/B2B external-identity federation
// generally — this collector reads exactly the
// policies/crossTenantAccessPolicy family: the root singleton
// (allowedCloudEndpoints only), the "default" configuration (the rich one —
// every tenant has exactly one, whether or not it has been customized), and
// the partners collection (per-partner-tenant overrides of the default).
//
// # Three independent fetches, one bounded metric family
//
// The root and default singletons and the partners collection are fetched
// independently; a failure of any one is a non-fatal aggregated error and
// does not stop the others — the same "each singleton fetch is independent"
// shape entra/tenantpolicy uses for its three data-bearing endpoints.
//
// entra.cross_tenant_access.access is the one bounded gauge covering every
// access-control sub-block on the default configuration: b2bCollaborationOutbound/
// Inbound, b2bDirectConnectOutbound/Inbound and tenantRestrictions, each
// broken into its usersAndGroups/applications (and, for tenantRestrictions,
// devices) sub-block. Cardinality is bounded by construction — 3 services ×
// 2 directions × 3 target kinds is a small fixed upper bound, not something
// that grows with tenant configuration.
//
// tenantRestrictions carries NO inbound/outbound split on the wire (unlike
// every other block here) — Microsoft models it as one restriction, not a
// pair. This collector emits it with direction="inbound", the reading that
// matches its actual semantics (it governs whether THIS tenant's own users,
// on THEIR OWN devices, may be treated as external when accessing another
// tenant — i.e. it restricts what comes back INTO this tenant's control from
// the other side of a B2B relationship) — recorded here as a deliberate
// modeling choice, not a wire fact, since Graph itself gives no direction to
// disambiguate.
//
// # Absent configuration is absent, never false or blocked (the load-bearing rule)
//
// Every optional bool on the wire (isMfaAccepted, isCompliantDeviceAccepted,
// isHybridAzureADJoinedDeviceAccepted, inboundAllowed, outboundAllowed) is a
// *bool, and every optional sub-object (inboundTrust,
// automaticUserConsentSettings, each access block, tenantRestrictions.devices)
// is a pointer. A configuration Graph did not return emits NO point for that
// combination — never a fabricated access_type="blocked" or a fabricated 0 —
// because that would tell an operator the tenant is locked down (or open)
// when Graph said nothing at all. tenantRestrictions.devices is null on the
// live tenant (2026-07-28) and is the canonical example this rule exists for.
//
// # Partners: count only, no field mapper (evidence-gated, #321)
//
// The partners collection is empty on the live tenant (2026-07-28, zero
// partners) — the SAME evidence-gated reasoning entra/tenantpolicy's package
// doc applies to its three empty scoped-policy collections: a mapper written
// against a shape nobody has observed is a mapper written against
// documentation, which this project's CLAUDE.md forbids ("mappers are
// written against live samples, never docs or hand-written fixtures"). This
// collector therefore emits ONLY entra.cross_tenant_access.partners.total (a
// plain count, paged via @odata.nextLink so the count is correct even past
// one page) and no per-partner attribute anywhere, in metrics or logs. The
// unblock condition: a real partner configuration exists on some tenant this
// project has poller access to, so its field shapes can be captured and
// mapped with evidence instead of guessed.
//
// # access_type is a deliberately UNWATCHED metric label (#321)
//
// access_type is a Graph-supplied enum used as a metric label on
// entra.cross_tenant_access.access. Only one tenant's one configuration has
// been observed, and it carries exactly two values (allowed, blocked). Per
// CLAUDE.md's wire-value-watching section, one observed pair is not a value
// set — internal/wirecheck deliberately does NOT declare an Enum for this
// field. A third value appearing on some other tenant would report-only
// bucket to the metric's existing cardinality limiter rather than trip a
// watchdog invented over an unconfirmed set.
//
// # Log twins
//
// entra.cross_tenant_access_policy carries the root singleton (id,
// display_name, allowed_cloud_endpoints). entra.cross_tenant_access_default
// carries the default configuration's typed fields: is_service_default, the
// inbound-trust and automatic-consent booleans, and — per sub-block — its
// access_type plus a bounded target-identifier array (capped exactly like
// #317's setTargetIDs: a true count and a truncated flag ride alongside the
// capped id list, and an empty/absent sub-block is omitted rather than
// emitting a hollow measured-empty attribute).
package crosstenantaccess

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/rknightion/graph2otel/internal/collector"
	"github.com/rknightion/graph2otel/internal/collectors"
	entraoutcome "github.com/rknightion/graph2otel/internal/outcomehelper"
	"github.com/rknightion/graph2otel/internal/recordoutcome"
	"github.com/rknightion/graph2otel/internal/semconv"
	"github.com/rknightion/graph2otel/internal/telemetry"
)

// collectorName is the stable key used for config (enable/interval),
// self-observability, and the admin status page.
const collectorName = "entra.cross_tenant_access"

// Metric names this collector emits.
const (
	// accessMetric is the bounded per-service/direction/target_kind
	// accessType gauge.
	accessMetric = "entra.cross_tenant_access.access"
	// inboundTrustMetric is the bounded per-setting 0/1 gauge.
	inboundTrustMetric = "entra.cross_tenant_access.inbound_trust"
	// automaticUserConsentMetric is the bounded per-direction 0/1 gauge.
	automaticUserConsentMetric = "entra.cross_tenant_access.automatic_user_consent"
	// partnersTotalMetric is the plain partner-tenant count.
	partnersTotalMetric = "entra.cross_tenant_access.partners.total"
)

// The two log EventNames this collector emits (#321). Both are LOG-ONLY:
// neither field here becomes a metric label beyond what accessMetric,
// inboundTrustMetric and automaticUserConsentMetric already carry.
const (
	eventPolicy  = "entra.cross_tenant_access_policy"
	eventDefault = "entra.cross_tenant_access_default"
)

// Bounded label values for accessMetric's `service` attribute.
const (
	serviceB2BCollaboration   = "b2b_collaboration"
	serviceB2BDirectConnect   = "b2b_direct_connect"
	serviceTenantRestrictions = "tenant_restrictions"
)

// Bounded label values for accessMetric's `direction` attribute.
const (
	directionInbound  = "inbound"
	directionOutbound = "outbound"
)

// Bounded label values for accessMetric's `target_kind` attribute.
const (
	targetKindUsersAndGroups = "users_and_groups"
	targetKindApplications   = "applications"
	targetKindDevices        = "devices"
)

// Bounded label values for inboundTrustMetric's `setting` attribute.
const (
	settingMfaAccepted                       = "mfa_accepted"
	settingCompliantDeviceAccepted           = "compliant_device_accepted"
	settingHybridAzureADJoinedDeviceAccepted = "hybrid_azure_ad_joined_device_accepted"
)

// maxTargetIdentifiers bounds every target identifier array this collector
// emits — the same defensive backstop role maxTargetIdentifiers plays in
// authmethodspolicy, sized identically since these are likewise
// admin-configured collections (AllUsers/AllApplications sentinels or,
// per-partner in a customized configuration, specific group/app ids) rather
// than tenant-population-sized data.
const maxTargetIdentifiers = 50

// defaultBaseURL is the Graph v1.0 root.
const defaultBaseURL = "https://graph.microsoft.com/v1.0"

const (
	rootPath     = "/policies/crossTenantAccessPolicy"
	defaultPath  = "/policies/crossTenantAccessPolicy/default"
	partnersPath = "/policies/crossTenantAccessPolicy/partners"
)

// accessTarget mirrors one element of an access sub-block's targets array.
// Unlike authmethodspolicy's targetRef (keyed on "id"), Graph's
// crossTenantAccessPolicy targets carry a "target" identifier (a sentinel
// like "AllUsers"/"AllApplications", or a specific group/application id on a
// customized configuration) — a different field name for the same role.
type accessTarget struct {
	Target string `json:"target"`
}

// accessBlock mirrors the shared shape every usersAndGroups/applications
// sub-block uses across all five access-control surfaces this collector
// reads: an accessType plus a targets array. A nil *accessBlock means Graph
// did not return this sub-block at all — never fabricated as blocked.
type accessBlock struct {
	AccessType string         `json:"accessType"`
	Targets    []accessTarget `json:"targets"`
}

// crossTenantAccessDirection mirrors the shape shared by
// b2bCollaborationOutbound/Inbound and b2bDirectConnectOutbound/Inbound: a
// usersAndGroups and an applications sub-block, each independently optional.
type crossTenantAccessDirection struct {
	UsersAndGroups *accessBlock `json:"usersAndGroups"`
	Applications   *accessBlock `json:"applications"`
}

// devicesBlock mirrors tenantRestrictions.devices. No evidence exists yet for
// whether Graph attaches a targets array to this sub-block (it is null on
// the live tenant, #321) — only accessType is read, deliberately, until a
// non-null capture provides evidence for more.
type devicesBlock struct {
	AccessType string `json:"accessType"`
}

// tenantRestrictionsBlock mirrors tenantRestrictions. Unlike the b2b
// direction structs, this has no inbound/outbound split on the wire — see
// the package doc for how this collector models that.
type tenantRestrictionsBlock struct {
	Devices        *devicesBlock `json:"devices"`
	UsersAndGroups *accessBlock  `json:"usersAndGroups"`
	Applications   *accessBlock  `json:"applications"`
}

// inboundTrust mirrors the default configuration's inboundTrust object.
// Every field is a pointer: a plain bool would fabricate false for a
// tenant/configuration where the whole sub-object (or one of its three
// switches) is simply absent from the response.
type inboundTrust struct {
	IsMfaAccepted                       *bool `json:"isMfaAccepted"`
	IsCompliantDeviceAccepted           *bool `json:"isCompliantDeviceAccepted"`
	IsHybridAzureADJoinedDeviceAccepted *bool `json:"isHybridAzureADJoinedDeviceAccepted"`
}

// automaticUserConsentSettings mirrors the default configuration's
// automaticUserConsentSettings object.
type automaticUserConsentSettings struct {
	InboundAllowed  *bool `json:"inboundAllowed"`
	OutboundAllowed *bool `json:"outboundAllowed"`
}

// defaultConfiguration mirrors the subset of
// policies/crossTenantAccessPolicy/default this collector reads. Per the
// package doc, m365CollaborationInbound/Outbound and appServiceConnectInbound
// (both present on the live wire) are deliberately NOT read here — out of
// #321's scope, which names only B2B collaboration, B2B direct-connect,
// tenant restrictions, inbound trust and automatic consent.
type defaultConfiguration struct {
	ID                           string                        `json:"id"`
	IsServiceDefault             *bool                         `json:"isServiceDefault"`
	InboundTrust                 *inboundTrust                 `json:"inboundTrust"`
	B2BCollaborationOutbound     *crossTenantAccessDirection   `json:"b2bCollaborationOutbound"`
	B2BCollaborationInbound      *crossTenantAccessDirection   `json:"b2bCollaborationInbound"`
	B2BDirectConnectOutbound     *crossTenantAccessDirection   `json:"b2bDirectConnectOutbound"`
	B2BDirectConnectInbound      *crossTenantAccessDirection   `json:"b2bDirectConnectInbound"`
	TenantRestrictions           *tenantRestrictionsBlock      `json:"tenantRestrictions"`
	AutomaticUserConsentSettings *automaticUserConsentSettings `json:"automaticUserConsentSettings"`
}

// rootPolicy mirrors the policies/crossTenantAccessPolicy singleton.
type rootPolicy struct {
	ID                    string   `json:"id"`
	DisplayName           string   `json:"displayName"`
	AllowedCloudEndpoints []string `json:"allowedCloudEndpoints"`
}

// Collector polls the policies/crossTenantAccessPolicy family.
type Collector struct {
	g       collectors.GraphClient
	baseURL string
	logger  *slog.Logger
}

// New builds the cross-tenant-access collector. A nil logger falls back to
// the slog default.
func New(g collectors.GraphClient, logger *slog.Logger) *Collector {
	if logger == nil {
		logger = slog.Default()
	}
	return &Collector{g: g, baseURL: defaultBaseURL, logger: logger}
}

// Name implements collector.Collector.
func (c *Collector) Name() string { return collectorName }

// DefaultInterval implements collector.Collector. This is tenant-wide policy
// config, not an event stream — it changes rarely, so fifteen minutes is
// ample.
func (c *Collector) DefaultInterval() time.Duration { return 15 * time.Minute }

// RequiredPermissions declares the Graph application scope every endpoint
// here shares.
func (c *Collector) RequiredPermissions() []string { return []string{"Policy.Read.All"} }

// Collect fetches the root and default singletons and the partners
// collection. Each is independent: a failure of one is a non-fatal
// aggregated error and does not stop the others from emitting.
func (c *Collector) Collect(ctx context.Context, e telemetry.Emitter, outcomes *recordoutcome.Recorder) error {
	var errs []error

	c.collectRoot(ctx, e, outcomes, &errs)
	c.collectDefault(ctx, e, outcomes, &errs)
	c.collectPartners(ctx, e, outcomes, &errs)

	return errors.Join(errs...)
}

func (c *Collector) collectRoot(ctx context.Context, e telemetry.Emitter, outcomes *recordoutcome.Recorder, errs *[]error) {
	body, err := c.g.RawGet(ctx, c.baseURL+rootPath)
	if err != nil {
		entraoutcome.SourceError(outcomes)
		*errs = append(*errs, fmt.Errorf("crosstenantaccess: fetch crossTenantAccessPolicy: %w", err))
		return
	}
	var p rootPolicy
	if err := json.Unmarshal(body, &p); err != nil {
		entraoutcome.Errored(outcomes, 1, recordoutcome.CauseDecodeError)
		*errs = append(*errs, fmt.Errorf("crosstenantaccess: decode crossTenantAccessPolicy: %w", err))
		return
	}

	attrs := telemetry.Attrs{}
	telemetry.SetStr(attrs, semconv.AttrId, p.ID)
	telemetry.SetStr(attrs, semconv.AttrDisplayName, p.DisplayName)
	telemetry.SetStrs(attrs, semconv.AttrAllowedCloudEndpoints, p.AllowedCloudEndpoints)

	e.LogEvent(telemetry.Event{
		Name:     eventPolicy,
		Body:     fmt.Sprintf("cross-tenant access policy %s", p.ID),
		Severity: telemetry.SeverityInfo,
		Attrs:    attrs,
	})
	entraoutcome.Emitted(outcomes, 1)
}

func (c *Collector) collectDefault(ctx context.Context, e telemetry.Emitter, outcomes *recordoutcome.Recorder, errs *[]error) {
	body, err := c.g.RawGet(ctx, c.baseURL+defaultPath)
	if err != nil {
		entraoutcome.SourceError(outcomes)
		*errs = append(*errs, fmt.Errorf("crosstenantaccess: fetch crossTenantAccessPolicy/default: %w", err))
		return
	}
	var d defaultConfiguration
	if err := json.Unmarshal(body, &d); err != nil {
		entraoutcome.Errored(outcomes, 1, recordoutcome.CauseDecodeError)
		*errs = append(*errs, fmt.Errorf("crosstenantaccess: decode crossTenantAccessPolicy/default: %w", err))
		return
	}

	twin := telemetry.Attrs{}

	telemetry.SetStr(twin, semconv.AttrId, d.ID)
	if d.IsServiceDefault != nil {
		telemetry.SetBool(twin, semconv.AttrIsServiceDefault, *d.IsServiceDefault)
	}

	var trustPoints []telemetry.GaugePoint
	if d.InboundTrust != nil {
		trustPoints = appendInboundTrust(trustPoints, twin, d.InboundTrust)
	}
	if len(trustPoints) > 0 {
		e.GaugeSnapshot(inboundTrustMetric, semconv.UnitDimensionless,
			"1 if this tenant accepts the external tenant's own claim for the given inbound-trust setting, else 0, per bounded setting.",
			trustPoints)
	}

	var consentPoints []telemetry.GaugePoint
	if d.AutomaticUserConsentSettings != nil {
		consentPoints = appendAutomaticConsent(consentPoints, twin, d.AutomaticUserConsentSettings)
	}
	if len(consentPoints) > 0 {
		e.GaugeSnapshot(automaticUserConsentMetric, semconv.UnitDimensionless,
			"1 if automatic user consent is enabled for the given direction, else 0.",
			consentPoints)
	}

	var accessPoints []telemetry.GaugePoint
	accessPoints = appendDirectionBlock(accessPoints, twin, serviceB2BCollaboration, directionOutbound, d.B2BCollaborationOutbound,
		semconv.AttrB2bCollabOutboundUsersAccessType, semconv.AttrB2bCollabOutboundUsersTargetIds, semconv.AttrB2bCollabOutboundUsersTargetCount, semconv.AttrB2bCollabOutboundUsersTargetsTruncated,
		semconv.AttrB2bCollabOutboundAppsAccessType, semconv.AttrB2bCollabOutboundAppsTargetIds, semconv.AttrB2bCollabOutboundAppsTargetCount, semconv.AttrB2bCollabOutboundAppsTargetsTruncated)
	accessPoints = appendDirectionBlock(accessPoints, twin, serviceB2BCollaboration, directionInbound, d.B2BCollaborationInbound,
		semconv.AttrB2bCollabInboundUsersAccessType, semconv.AttrB2bCollabInboundUsersTargetIds, semconv.AttrB2bCollabInboundUsersTargetCount, semconv.AttrB2bCollabInboundUsersTargetsTruncated,
		semconv.AttrB2bCollabInboundAppsAccessType, semconv.AttrB2bCollabInboundAppsTargetIds, semconv.AttrB2bCollabInboundAppsTargetCount, semconv.AttrB2bCollabInboundAppsTargetsTruncated)
	accessPoints = appendDirectionBlock(accessPoints, twin, serviceB2BDirectConnect, directionOutbound, d.B2BDirectConnectOutbound,
		semconv.AttrB2bDirectOutboundUsersAccessType, semconv.AttrB2bDirectOutboundUsersTargetIds, semconv.AttrB2bDirectOutboundUsersTargetCount, semconv.AttrB2bDirectOutboundUsersTargetsTruncated,
		semconv.AttrB2bDirectOutboundAppsAccessType, semconv.AttrB2bDirectOutboundAppsTargetIds, semconv.AttrB2bDirectOutboundAppsTargetCount, semconv.AttrB2bDirectOutboundAppsTargetsTruncated)
	accessPoints = appendDirectionBlock(accessPoints, twin, serviceB2BDirectConnect, directionInbound, d.B2BDirectConnectInbound,
		semconv.AttrB2bDirectInboundUsersAccessType, semconv.AttrB2bDirectInboundUsersTargetIds, semconv.AttrB2bDirectInboundUsersTargetCount, semconv.AttrB2bDirectInboundUsersTargetsTruncated,
		semconv.AttrB2bDirectInboundAppsAccessType, semconv.AttrB2bDirectInboundAppsTargetIds, semconv.AttrB2bDirectInboundAppsTargetCount, semconv.AttrB2bDirectInboundAppsTargetsTruncated)

	if d.TenantRestrictions != nil {
		tr := d.TenantRestrictions
		// tenantRestrictions has no inbound/outbound split on the wire — see
		// the package doc for why this collector reads it as direction=inbound.
		accessPoints = appendAccessBlock(accessPoints, twin, serviceTenantRestrictions, directionInbound, targetKindUsersAndGroups, tr.UsersAndGroups,
			semconv.AttrTenantRestrictionsUsersAccessType, semconv.AttrTenantRestrictionsUsersTargetIds, semconv.AttrTenantRestrictionsUsersTargetCount, semconv.AttrTenantRestrictionsUsersTargetsTruncated)
		accessPoints = appendAccessBlock(accessPoints, twin, serviceTenantRestrictions, directionInbound, targetKindApplications, tr.Applications,
			semconv.AttrTenantRestrictionsAppsAccessType, semconv.AttrTenantRestrictionsAppsTargetIds, semconv.AttrTenantRestrictionsAppsTargetCount, semconv.AttrTenantRestrictionsAppsTargetsTruncated)
		if tr.Devices != nil && tr.Devices.AccessType != "" {
			telemetry.SetStr(twin, semconv.AttrTenantRestrictionsDevicesAccessType, tr.Devices.AccessType)
			accessPoints = append(accessPoints, telemetry.GaugePoint{
				Value: 1,
				Attrs: telemetry.Attrs{
					semconv.AttrService:    serviceTenantRestrictions,
					semconv.AttrDirection:  directionInbound,
					semconv.AttrTargetKind: targetKindDevices,
					semconv.AttrAccessType: tr.Devices.AccessType,
				},
			})
		}
	}
	if len(accessPoints) > 0 {
		e.GaugeSnapshot(accessMetric, semconv.UnitDimensionless,
			"1 per configured cross-tenant access control block, attributed by service/direction/target_kind/access_type.",
			accessPoints)
	}

	e.LogEvent(telemetry.Event{
		Name:     eventDefault,
		Body:     fmt.Sprintf("cross-tenant access default configuration %s", d.ID),
		Severity: telemetry.SeverityInfo,
		Attrs:    twin,
	})
	entraoutcome.Emitted(outcomes, 1)
}

// appendInboundTrust emits the bounded inboundTrust gauge points AND their
// typed twin copies, one per switch that is actually present on the wire.
func appendInboundTrust(points []telemetry.GaugePoint, twin telemetry.Attrs, t *inboundTrust) []telemetry.GaugePoint {
	add := func(present *bool, setting, attrKey string) {
		if present == nil {
			return
		}
		telemetry.SetBool(twin, attrKey, *present)
		points = append(points, telemetry.GaugePoint{
			Value: b2f(*present),
			Attrs: telemetry.Attrs{semconv.AttrSetting: setting},
		})
	}
	add(t.IsMfaAccepted, settingMfaAccepted, semconv.AttrInboundTrustMfaAccepted)
	add(t.IsCompliantDeviceAccepted, settingCompliantDeviceAccepted, semconv.AttrInboundTrustCompliantDeviceAccepted)
	add(t.IsHybridAzureADJoinedDeviceAccepted, settingHybridAzureADJoinedDeviceAccepted, semconv.AttrInboundTrustHybridAzureAdJoinedDeviceAccepted)
	return points
}

// appendAutomaticConsent emits the bounded automaticUserConsentSettings gauge
// points AND their typed twin copies, one per direction actually present.
func appendAutomaticConsent(points []telemetry.GaugePoint, twin telemetry.Attrs, a *automaticUserConsentSettings) []telemetry.GaugePoint {
	add := func(present *bool, direction, attrKey string) {
		if present == nil {
			return
		}
		telemetry.SetBool(twin, attrKey, *present)
		points = append(points, telemetry.GaugePoint{
			Value: b2f(*present),
			Attrs: telemetry.Attrs{semconv.AttrDirection: direction},
		})
	}
	add(a.InboundAllowed, directionInbound, semconv.AttrAutomaticConsentInboundAllowed)
	add(a.OutboundAllowed, directionOutbound, semconv.AttrAutomaticConsentOutboundAllowed)
	return points
}

// appendDirectionBlock emits both target-kind sub-blocks (usersAndGroups,
// applications) of one b2b direction struct, if present.
func appendDirectionBlock(
	points []telemetry.GaugePoint, twin telemetry.Attrs, service, direction string, dir *crossTenantAccessDirection,
	usersAccessTypeKey, usersIDsKey, usersCountKey, usersTruncatedKey string,
	appsAccessTypeKey, appsIDsKey, appsCountKey, appsTruncatedKey string,
) []telemetry.GaugePoint {
	if dir == nil {
		return points
	}
	points = appendAccessBlock(points, twin, service, direction, targetKindUsersAndGroups, dir.UsersAndGroups,
		usersAccessTypeKey, usersIDsKey, usersCountKey, usersTruncatedKey)
	points = appendAccessBlock(points, twin, service, direction, targetKindApplications, dir.Applications,
		appsAccessTypeKey, appsIDsKey, appsCountKey, appsTruncatedKey)
	return points
}

// appendAccessBlock emits one accessType gauge point plus its target-id twin
// fields, for exactly one (service, direction, target_kind) combination. A
// nil block is skipped entirely — Graph did not return this sub-block, so no
// point and no twin fields are emitted for it, never a fabricated blocked/0.
func appendAccessBlock(
	points []telemetry.GaugePoint, twin telemetry.Attrs, service, direction, targetKind string, b *accessBlock,
	accessTypeKey, idsKey, countKey, truncatedKey string,
) []telemetry.GaugePoint {
	if b == nil {
		return points
	}
	if b.AccessType != "" {
		telemetry.SetStr(twin, accessTypeKey, b.AccessType)
		points = append(points, telemetry.GaugePoint{
			Value: 1,
			Attrs: telemetry.Attrs{
				semconv.AttrService:    service,
				semconv.AttrDirection:  direction,
				semconv.AttrTargetKind: targetKind,
				semconv.AttrAccessType: b.AccessType,
			},
		})
	}
	setTargetIDs(twin, idsKey, countKey, truncatedKey, b.Targets)
	return points
}

// capStrings caps vals at maxTargetIdentifiers, reporting whether it had to.
// Never mutates vals — the returned slice on the truncated path is a fresh
// subslice header, not vals itself.
func capStrings(vals []string, max int) (out []string, truncated bool) {
	if len(vals) > max {
		return vals[:max:max], true
	}
	return vals, false
}

// setTargetIDs renders a []accessTarget as a bounded id array plus its true
// (uncapped) count and a truncated flag — the same shape #317's
// authmethodspolicy.setTargetIDs uses, adapted to accessTarget's "target"
// field instead of targetRef's "id". An empty input omits all three
// attributes: "no targets configured" is absence, never a measured empty
// array.
func setTargetIDs(attrs telemetry.Attrs, idsKey, countKey, truncatedKey string, targets []accessTarget) {
	if len(targets) == 0 {
		return
	}
	ids := make([]string, 0, len(targets))
	for _, t := range targets {
		if t.Target != "" {
			ids = append(ids, t.Target)
		}
	}
	capped, truncated := capStrings(ids, maxTargetIdentifiers)
	telemetry.SetStrs(attrs, idsKey, capped)
	attrs[countKey] = float64(len(targets))
	telemetry.SetBool(attrs, truncatedKey, truncated)
}

// b2f maps a bool to a 0/1 gauge value.
func b2f(b bool) float64 {
	if b {
		return 1
	}
	return 0
}

// collectPartners pages the partners collection via @odata.nextLink and
// emits ONLY its count (#321) — no field mapper is written against a
// collection with zero live members. See the package doc.
func (c *Collector) collectPartners(ctx context.Context, e telemetry.Emitter, outcomes *recordoutcome.Recorder, errs *[]error) {
	raws, err := collectors.GetAllValuesRecorded(ctx, c.g, c.baseURL+partnersPath, nil, outcomes)
	if err != nil {
		entraoutcome.SourceError(outcomes)
		*errs = append(*errs, fmt.Errorf("crosstenantaccess: fetch partners: %w", err))
		return
	}
	e.Gauge(partnersTotalMetric, "{partner}", "Count of cross-tenant-access partner-tenant configurations.", float64(len(raws)), nil)
	entraoutcome.Emitted(outcomes, uint64(len(raws)))
}

func init() {
	collectors.Register(func(d collectors.Deps) collector.SnapshotCollector {
		return New(d.Graph, d.Logger)
	})
}
