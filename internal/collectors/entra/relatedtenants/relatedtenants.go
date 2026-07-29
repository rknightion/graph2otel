// Package relatedtenants is the Entra Tenant Governance related-tenant
// discovery collector (#336): GET /beta/directory/tenantGovernance/settings and
// .../relatedTenants.
//
// It answers a question nothing else in this project can: which OTHER tenants
// this one is actually entangled with, discovered by Microsoft rather than
// declared by an administrator. entra.cross_tenant_access reports the
// cross-tenant policy an admin has CONFIGURED; this reports the relationships
// that exist whether or not anyone configured them — a partner whose users sign
// in here, a multi-tenant application of theirs in use here, guests registered
// in either direction.
//
// # The documented path does not exist
//
// Microsoft documents this under /beta/tenantRelationships/tenantGovernance,
// which answers 400 `Resource not found for the segment` (live-measured
// 2026-07-28). The tenantGovernance navigation property hangs off `directory`.
// The correct paths are the two constants below, found by grepping the beta
// $metadata EDM for the type name — the same route that corrected #333's
// documented entity set. Another wire-over-docs entry.
//
// # Beta-only, so Experimental
//
// Neither path exists on v1.0 (checked, per the #334 lesson that a `beta-api`
// label is not evidence). So this is a genuine Graph beta surface and takes
// collectors.Experimental per #183.
//
// # The disabled state is DATA, not a 403
//
// Related-tenant discovery is a tenant feature an administrator must enable,
// and Microsoft states the enable is irreversible. The collector reads
// `settings` FIRST and skips the relatedTenants fetch when
// isRelatedTenantsEnabled is false — it never has to eat a 403 to find out.
// When it does skip, the count gauge emits NO POINTS rather than a zero,
// because "discovery is off" and "discovery is on and found nothing" are
// opposite facts and a 0 would assert the second. The discovery_enabled gauge
// carries which one it was.
//
// For the record, the two 403s here are textually distinct and never collapse
// into one bucket: the disabled 403 says `Related tenant discovery has not been
// enabled for tenant <id>`, while a missing app role says `Insufficient
// permissions to perform this operation.` (both live-measured 2026-07-28).
//
// # Null is the common case, so every numeric is a pointer
//
// Live-measured 2026-07-29 on m7kni: 16 related tenants, 13 external and 3
// Microsoft infrastructure. Of the five metric blocks a row can carry,
// multiTenantApplicationMetrics is populated on all 16, the three B2B blocks on
// exactly ONE, and billingMetrics on NONE. So absence is the normal reading on
// this surface rather than an edge case, and a bare int64 would publish a
// fabricated 0 — "no inbound B2B users from this partner" — on fifteen of
// sixteen rows. Every leaf is a *int64 emitted only when the wire sent it, and
// the with_metrics gauge reports how many rows carried each block so an
// operator can see the coverage rather than infer it from missing attributes.
//
// The three blocks also do not share a field set: b2BRegistrationMetrics
// carries lifetime `inboundTotalUsers`/`outboundTotalUsers`,
// b2BSignInActivityMetrics and appB2BSignInActivityMetrics carry MONTHLY user
// and application counters, and multiTenantApplicationMetrics carries
// application counters only. One leaf struct decodes all of them, which is
// exactly why the pointers matter: the fields a block does not send must stay
// absent, not become zero.
//
// billingMetrics' leaves are deliberately UNMODELED. It is null on every live
// row, so there is no observed shape to map and this project does not write a
// mapper from documentation (#142/#165). The twin carries
// has_billing_metrics so the day it appears is visible; the unblock for
// modeling it is a row that actually has one.
//
// # createdDateTime is not an event time
//
// Every one of the 16 rows carries a createdDateTime within one second of the
// others, because it dates the local discovery RECORD — the moment discovery
// was switched on — not the relationship. The twins are therefore STATE twins
// stamped at poll time, never backdated: backdating would date every
// relationship to the day the feature was enabled, and on a re-enable would
// re-stamp them all again. The genuinely time-bearing fields are each metric
// block's watermarkDateTime/updateDateTime, which are emitted as attributes.
//
// # Wirecheck
//
// Nothing is watched, and that is a recorded decision rather than an omission.
// This surface carries no enum at all: the fields are two booleans, a tenant
// id, timestamps and integer counters. There is no value set for a watchdog to
// guard, and a watchdog that cannot fire is worse than none (#233/#234).
package relatedtenants

import (
	"context"
	"encoding/json"
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
const collectorName = "entra.related_tenants"

// betaBaseURL is the Graph beta service root. Both paths below exist only on
// beta — see the package doc.
const betaBaseURL = "https://graph.microsoft.com/beta"

const (
	settingsPath       = "/directory/tenantGovernance/settings"
	relatedTenantsPath = "/directory/tenantGovernance/relatedTenants"
)

const (
	// discoveryEnabledMetric is the tenant's isRelatedTenantsEnabled flag.
	// Always emitted: it is what makes an absent count gauge readable.
	discoveryEnabledMetric = "entra.related_tenants.discovery_enabled"

	// invitationsEnabledMetric is the tenant's canReceiveInvitations flag —
	// whether another tenant can invite this one into a governance
	// relationship, which is a posture question independent of discovery.
	invitationsEnabledMetric = "entra.related_tenants.can_receive_invitations"

	// totalMetric counts discovered related tenants, split by
	// is_microsoft_infrastructure. That split is the whole point: 3 of 16 live
	// rows are Microsoft's own infrastructure tenants, so an unsplit total
	// overstates external entanglement by exactly those.
	totalMetric = "entra.related_tenants.total"

	// withMetricsMetric counts how many discovered tenants carried each
	// metric block. Bounded at five series by construction (one per block
	// kind). This is the coverage signal that keeps the pointer discipline
	// legible: without it, "Microsoft sent no B2B measurement for 15 of 16
	// tenants" is only visible as absent attributes on individual twins.
	withMetricsMetric = "entra.related_tenants.with_metrics"

	// b2bRegisteredUsersMetric sums recent.{inbound,outbound}TotalUsers
	// across every row that carried b2BRegistrationMetrics — guest
	// registrations in each direction, tenant-wide.
	b2bRegisteredUsersMetric = "entra.related_tenants.b2b_registered_users"

	// b2bSigninUsersMetric sums recent.{inbound,outbound}MonthlyTotalUsers
	// across every row that carried b2BSignInActivityMetrics.
	b2bSigninUsersMetric = "entra.related_tenants.b2b_signin_users"

	// multiTenantApplicationsMetric sums
	// recent.{inbound,outbound}MonthlyTotalApplications across every row that
	// carried multiTenantApplicationMetrics.
	multiTenantApplicationsMetric = "entra.related_tenants.multi_tenant_applications"
)

// eventRelatedTenant is the log twin's EventName: one record per discovered
// related tenant.
const eventRelatedTenant = "entra.related_tenant"

// metricKind values for the withMetricsMetric label. Closed set, one per block
// a row can carry.
const (
	kindB2bRegistration = "b2b_registration"
	kindB2bSignin       = "b2b_signin"
	kindAppB2bSignin    = "app_b2b_signin"
	kindMultiTenantApp  = "multi_tenant_application"
	kindBilling         = "billing"
)

// directionInbound / directionOutbound label the summed counter metrics.
const (
	directionInbound  = "inbound"
	directionOutbound = "outbound"
)

// maxPages caps the nextLink walk. The live collection returns all 16 rows in
// one page with no nextLink, so this is a runaway-loop backstop.
const maxPages = 1000

// governanceSettings is the single-object settings response.
type governanceSettings struct {
	IsRelatedTenantsEnabled bool `json:"isRelatedTenantsEnabled"`
	CanReceiveInvitations   bool `json:"canReceiveInvitations"`
}

// metricSnapshot is the leaf shape shared by every metric block's `initial` and
// `recent` object. Every counter is a POINTER: the blocks do not share a field
// set (see the package doc), so a block that never sends a counter must leave
// it absent rather than publish a zero.
type metricSnapshot struct {
	CreatedDateTime   string `json:"createdDateTime"`
	UpdateDateTime    string `json:"updateDateTime"`
	WatermarkDateTime string `json:"watermarkDateTime"`

	InboundTotalUsers  *int64 `json:"inboundTotalUsers"`
	OutboundTotalUsers *int64 `json:"outboundTotalUsers"`

	InboundMonthlyTotalUsers  *int64 `json:"inboundMonthlyTotalUsers"`
	OutboundMonthlyTotalUsers *int64 `json:"outboundMonthlyTotalUsers"`

	InboundMonthlyTotalApplications  *int64 `json:"inboundMonthlyTotalApplications"`
	OutboundMonthlyTotalApplications *int64 `json:"outboundMonthlyTotalApplications"`
}

// metricBlock is the {initial, recent} pair every populated metric block has.
// Both sides are pointers so an absent block and a block with an absent side
// stay distinguishable.
type metricBlock struct {
	Initial *metricSnapshot `json:"initial"`
	Recent  *metricSnapshot `json:"recent"`
}

// relatedTenant mirrors one row of the relatedTenants collection. Every metric
// block is a pointer — four of the five are null on almost every live row.
// BillingMetrics is json.RawMessage on purpose: its presence is reported and
// its contents are not decoded, because no live row has ever carried one.
type relatedTenant struct {
	ID                            string          `json:"id"`
	CreatedDateTime               string          `json:"createdDateTime"`
	IsMicrosoftInfrastructure     bool            `json:"isMicrosoftInfrastructure"`
	B2BRegistrationMetrics        *metricBlock    `json:"b2BRegistrationMetrics"`
	B2BSignInActivityMetrics      *metricBlock    `json:"b2BSignInActivityMetrics"`
	AppB2BSignInActivityMetrics   *metricBlock    `json:"appB2BSignInActivityMetrics"`
	MultiTenantApplicationMetrics *metricBlock    `json:"multiTenantApplicationMetrics"`
	BillingMetrics                json.RawMessage `json:"billingMetrics"`
}

// relatedTenantsPage is the collection envelope.
type relatedTenantsPage struct {
	Value    []relatedTenant `json:"value"`
	NextLink string          `json:"@odata.nextLink"`
}

// Collector polls the tenant-governance settings and the discovered
// related-tenant collection.
type Collector struct {
	g       collectors.GraphClient
	baseURL string
	logger  *slog.Logger
}

// New builds the related-tenants collector. A nil logger falls back to the
// slog default.
func New(g collectors.GraphClient, logger *slog.Logger) *Collector {
	if logger == nil {
		logger = slog.Default()
	}
	return &Collector{g: g, baseURL: betaBaseURL, logger: logger}
}

// Name implements collector.Collector.
func (c *Collector) Name() string { return collectorName }

// DefaultInterval implements collector.Collector. Microsoft's own aggregation
// watermarks move daily (live-measured: watermarkDateTime on a midnight
// boundary, updateDateTime once a day), so nothing here changes faster than
// that. Six-hourly keeps a new relationship visible the same day without
// polling a surface that cannot have changed.
func (c *Collector) DefaultInterval() time.Duration { return 6 * time.Hour }

// Experimental marks this collector beta/opt-in: both paths exist only on the
// Graph beta endpoint, with no v1.0 form (#183).
func (c *Collector) Experimental() bool { return true }

// RequiredPermissions declares the two read-only scopes, granted to
// graph2otel-poller 2026-07-28 and both live-verified 200 (#336).
func (c *Collector) RequiredPermissions() []string {
	return []string{
		"TenantGovernance-Setting.Read.All",
		"TenantGovernance-RelatedTenant.Read.All",
	}
}

// Collect reads the settings singleton, then the related-tenant collection
// only when discovery is enabled.
func (c *Collector) Collect(ctx context.Context, e telemetry.Emitter, outcomes *recordoutcome.Recorder) error {
	settings, err := c.fetchSettings(ctx, outcomes)
	if err != nil {
		return err
	}

	e.GaugeSnapshot(discoveryEnabledMetric, "{setting}",
		"Whether Entra related-tenant discovery is enabled for the tenant (1) or not (0).",
		[]telemetry.GaugePoint{{Value: boolTo01(settings.IsRelatedTenantsEnabled)}})
	e.GaugeSnapshot(invitationsEnabledMetric, "{setting}",
		"Whether the tenant can receive tenant-governance invitations from another tenant (1) or not (0).",
		[]telemetry.GaugePoint{{Value: boolTo01(settings.CanReceiveInvitations)}})
	entraoutcome.Emitted(outcomes, 1)

	if !settings.IsRelatedTenantsEnabled {
		// Deliberately NO points, not a zero: see the package doc. The
		// discovery_enabled gauge above already says which case this is.
		c.emitEmptyTenantMetrics(e)
		c.logger.Info("related-tenant discovery is disabled for this tenant; skipping the relatedTenants fetch",
			"collector", collectorName)
		return nil
	}

	rows, err := c.fetchRelatedTenants(ctx, outcomes)
	if err != nil {
		return err
	}

	c.emitTenantMetrics(e, rows)
	for _, r := range rows {
		e.LogEvent(relatedTenantTwin(r))
	}
	entraoutcome.Emitted(outcomes, uint64(len(rows)))
	return nil
}

// emitEmptyTenantMetrics publishes the discovery-dependent metrics with no
// points at all, so a disabled tenant shows an ABSENT count rather than a
// measured zero.
func (c *Collector) emitEmptyTenantMetrics(e telemetry.Emitter) {
	e.GaugeSnapshot(totalMetric, "{tenant}", totalMetricDesc, nil)
	e.GaugeSnapshot(withMetricsMetric, "{tenant}", withMetricsMetricDesc, nil)
	e.GaugeSnapshot(b2bRegisteredUsersMetric, "{user}", b2bRegisteredUsersDesc, nil)
	e.GaugeSnapshot(b2bSigninUsersMetric, "{user}", b2bSigninUsersDesc, nil)
	e.GaugeSnapshot(multiTenantApplicationsMetric, "{application}", multiTenantApplicationsDesc, nil)
}

// Metric descriptions, hoisted so the empty and populated paths cannot drift
// apart — a metric emitted with two different descriptions depending on the
// branch is a documentation bug that only shows up on the tenant that hits the
// other branch.
const (
	totalMetricDesc             = "Count of tenants discovered by Entra related-tenant discovery, split by whether the tenant is Microsoft infrastructure."
	withMetricsMetricDesc       = "Count of discovered related tenants for which Microsoft supplied each kind of relationship metric."
	b2bRegisteredUsersDesc      = "Total B2B guest registrations across all discovered related tenants, by direction."
	b2bSigninUsersDesc          = "Total monthly B2B sign-in users across all discovered related tenants, by direction."
	multiTenantApplicationsDesc = "Total monthly multi-tenant applications in use across all discovered related tenants, by direction."
)

// emitTenantMetrics publishes the bounded aggregates. Every sum is emitted only
// when at least one row actually carried the block it comes from: a zero would
// otherwise claim Microsoft measured no B2B activity when Microsoft measured
// nothing at all.
func (c *Collector) emitTenantMetrics(e telemetry.Emitter, rows []relatedTenant) {
	byInfra := map[bool]int64{}
	kinds := map[string]int64{}

	var regIn, regOut, signIn, signOut, appIn, appOut int64
	var haveReg, haveSignin, haveApps bool

	for _, r := range rows {
		byInfra[r.IsMicrosoftInfrastructure]++

		if r.B2BRegistrationMetrics != nil {
			kinds[kindB2bRegistration]++
			if s := r.B2BRegistrationMetrics.Recent; s != nil {
				if s.InboundTotalUsers != nil {
					regIn += *s.InboundTotalUsers
					haveReg = true
				}
				if s.OutboundTotalUsers != nil {
					regOut += *s.OutboundTotalUsers
					haveReg = true
				}
			}
		}
		if r.B2BSignInActivityMetrics != nil {
			kinds[kindB2bSignin]++
			if s := r.B2BSignInActivityMetrics.Recent; s != nil {
				if s.InboundMonthlyTotalUsers != nil {
					signIn += *s.InboundMonthlyTotalUsers
					haveSignin = true
				}
				if s.OutboundMonthlyTotalUsers != nil {
					signOut += *s.OutboundMonthlyTotalUsers
					haveSignin = true
				}
			}
		}
		if r.AppB2BSignInActivityMetrics != nil {
			kinds[kindAppB2bSignin]++
		}
		if r.MultiTenantApplicationMetrics != nil {
			kinds[kindMultiTenantApp]++
			if s := r.MultiTenantApplicationMetrics.Recent; s != nil {
				if s.InboundMonthlyTotalApplications != nil {
					appIn += *s.InboundMonthlyTotalApplications
					haveApps = true
				}
				if s.OutboundMonthlyTotalApplications != nil {
					appOut += *s.OutboundMonthlyTotalApplications
					haveApps = true
				}
			}
		}
		if hasBillingMetrics(r.BillingMetrics) {
			kinds[kindBilling]++
		}
	}

	// The total gauge always carries both infrastructure buckets, including a
	// measured 0: "zero external related tenants" is a real and reassuring
	// reading, and an absent point could not be told apart from a fetch that
	// never ran.
	e.GaugeSnapshot(totalMetric, "{tenant}", totalMetricDesc, []telemetry.GaugePoint{
		{Value: float64(byInfra[false]), Attrs: telemetry.Attrs{semconv.AttrIsMicrosoftInfrastructure: false}},
		{Value: float64(byInfra[true]), Attrs: telemetry.Attrs{semconv.AttrIsMicrosoftInfrastructure: true}},
	})

	// with_metrics carries every kind, zero included: this is the coverage
	// signal, and a kind Microsoft has stopped supplying must read as 0 rather
	// than vanish.
	kindPoints := make([]telemetry.GaugePoint, 0, 5)
	for _, k := range []string{kindB2bRegistration, kindB2bSignin, kindAppB2bSignin, kindMultiTenantApp, kindBilling} {
		kindPoints = append(kindPoints, telemetry.GaugePoint{
			Value: float64(kinds[k]),
			Attrs: telemetry.Attrs{semconv.AttrKind: k},
		})
	}
	e.GaugeSnapshot(withMetricsMetric, "{tenant}", withMetricsMetricDesc, kindPoints)

	e.GaugeSnapshot(b2bRegisteredUsersMetric, "{user}", b2bRegisteredUsersDesc,
		directionPoints(haveReg, regIn, regOut))
	e.GaugeSnapshot(b2bSigninUsersMetric, "{user}", b2bSigninUsersDesc,
		directionPoints(haveSignin, signIn, signOut))
	e.GaugeSnapshot(multiTenantApplicationsMetric, "{application}", multiTenantApplicationsDesc,
		directionPoints(haveApps, appIn, appOut))
}

// directionPoints renders an inbound/outbound pair, or nothing at all when no
// row supplied the underlying measurement.
func directionPoints(measured bool, inbound, outbound int64) []telemetry.GaugePoint {
	if !measured {
		return nil
	}
	return []telemetry.GaugePoint{
		{Value: float64(inbound), Attrs: telemetry.Attrs{semconv.AttrDirection: directionInbound}},
		{Value: float64(outbound), Attrs: telemetry.Attrs{semconv.AttrDirection: directionOutbound}},
	}
}

// hasBillingMetrics reports whether the row carried a billingMetrics object.
// A JSON `null` decodes into a non-nil RawMessage holding the four bytes
// "null", so a nil check alone would report every live row as having billing
// metrics — all 16 of them send the key with a null value.
func hasBillingMetrics(raw json.RawMessage) bool {
	return len(raw) > 0 && string(raw) != "null"
}

// fetchSettings reads the settings singleton.
func (c *Collector) fetchSettings(ctx context.Context, outcomes *recordoutcome.Recorder) (governanceSettings, error) {
	var out governanceSettings
	body, err := c.g.RawGet(ctx, c.baseURL+settingsPath)
	if err != nil {
		entraoutcome.SourceError(outcomes)
		c.logger.Warn("tenant-governance settings fetch failed", "collector", collectorName, "error", err)
		return out, fmt.Errorf("relatedtenants: fetch settings: %w", err)
	}
	if err := json.Unmarshal(body, &out); err != nil {
		entraoutcome.Errored(outcomes, 1, recordoutcome.CauseDecodeError)
		c.logger.Warn("tenant-governance settings decode failed", "collector", collectorName, "error", err)
		return out, fmt.Errorf("relatedtenants: decode settings: %w", err)
	}
	return out, nil
}

// fetchRelatedTenants pages through the discovered related-tenant collection.
func (c *Collector) fetchRelatedTenants(ctx context.Context, outcomes *recordoutcome.Recorder) ([]relatedTenant, error) {
	var out []relatedTenant
	url := c.baseURL + relatedTenantsPath
	for pages := 0; url != ""; pages++ {
		if pages >= maxPages {
			entraoutcome.SourceError(outcomes)
			return nil, fmt.Errorf("relatedtenants: pagination exceeded %d pages", maxPages)
		}
		body, err := c.g.RawGet(ctx, url)
		if err != nil {
			entraoutcome.SourceError(outcomes)
			c.logger.Warn("relatedTenants fetch failed", "collector", collectorName, "error", err)
			return nil, fmt.Errorf("relatedtenants: fetch relatedTenants: %w", err)
		}
		var page relatedTenantsPage
		if err := json.Unmarshal(body, &page); err != nil {
			entraoutcome.Errored(outcomes, 1, recordoutcome.CauseDecodeError)
			c.logger.Warn("relatedTenants decode failed", "collector", collectorName, "error", err)
			return nil, fmt.Errorf("relatedtenants: decode relatedTenants: %w", err)
		}
		out = append(out, page.Value...)
		url = page.NextLink
	}
	return out, nil
}

// relatedTenantTwin renders one discovered related tenant as one
// entra.related_tenant record. Timestamp is deliberately left zero (the
// emitter stamps poll time): this is a STATE twin, and createdDateTime dates
// the discovery record rather than the relationship — see the package doc.
func relatedTenantTwin(r relatedTenant) telemetry.Event {
	attrs := telemetry.Attrs{}
	telemetry.SetStr(attrs, semconv.AttrRelatedTenantId, r.ID)
	telemetry.SetStr(attrs, semconv.AttrCreatedDateTime, r.CreatedDateTime)
	attrs[semconv.AttrIsMicrosoftInfrastructure] = r.IsMicrosoftInfrastructure
	attrs[semconv.AttrHasBillingMetrics] = hasBillingMetrics(r.BillingMetrics)

	// First-observed comes from whichever block has an `initial` snapshot with
	// a createdDateTime; they agree where more than one is present on the live
	// row, and the earliest is the honest answer if they ever disagree.
	telemetry.SetStr(attrs, semconv.AttrMetricsFirstObservedDateTime, firstObserved(r))

	if b := r.B2BRegistrationMetrics; b != nil && b.Recent != nil {
		s := b.Recent
		telemetry.SetStr(attrs, semconv.AttrB2bRegistrationWatermarkDateTime, s.WatermarkDateTime)
		telemetry.SetStr(attrs, semconv.AttrB2bRegistrationUpdatedDateTime, s.UpdateDateTime)
		setInt(attrs, semconv.AttrB2bRegistrationInboundUsers, s.InboundTotalUsers)
		setInt(attrs, semconv.AttrB2bRegistrationOutboundUsers, s.OutboundTotalUsers)
	}
	if b := r.B2BSignInActivityMetrics; b != nil && b.Recent != nil {
		s := b.Recent
		telemetry.SetStr(attrs, semconv.AttrB2bSigninWatermarkDateTime, s.WatermarkDateTime)
		telemetry.SetStr(attrs, semconv.AttrB2bSigninUpdatedDateTime, s.UpdateDateTime)
		setInt(attrs, semconv.AttrB2bSigninInboundUsers, s.InboundMonthlyTotalUsers)
		setInt(attrs, semconv.AttrB2bSigninOutboundUsers, s.OutboundMonthlyTotalUsers)
		setInt(attrs, semconv.AttrB2bSigninInboundApplications, s.InboundMonthlyTotalApplications)
		setInt(attrs, semconv.AttrB2bSigninOutboundApplications, s.OutboundMonthlyTotalApplications)
	}
	if b := r.AppB2BSignInActivityMetrics; b != nil && b.Recent != nil {
		s := b.Recent
		telemetry.SetStr(attrs, semconv.AttrAppB2bSigninWatermarkDateTime, s.WatermarkDateTime)
		telemetry.SetStr(attrs, semconv.AttrAppB2bSigninUpdatedDateTime, s.UpdateDateTime)
		setInt(attrs, semconv.AttrAppB2bSigninInboundUsers, s.InboundMonthlyTotalUsers)
		setInt(attrs, semconv.AttrAppB2bSigninOutboundUsers, s.OutboundMonthlyTotalUsers)
		setInt(attrs, semconv.AttrAppB2bSigninInboundApplications, s.InboundMonthlyTotalApplications)
		setInt(attrs, semconv.AttrAppB2bSigninOutboundApplications, s.OutboundMonthlyTotalApplications)
	}
	if b := r.MultiTenantApplicationMetrics; b != nil && b.Recent != nil {
		s := b.Recent
		telemetry.SetStr(attrs, semconv.AttrMultiTenantAppWatermarkDateTime, s.WatermarkDateTime)
		telemetry.SetStr(attrs, semconv.AttrMultiTenantAppUpdatedDateTime, s.UpdateDateTime)
		setInt(attrs, semconv.AttrMultiTenantAppInboundApplications, s.InboundMonthlyTotalApplications)
		setInt(attrs, semconv.AttrMultiTenantAppOutboundApplications, s.OutboundMonthlyTotalApplications)
	}

	kind := "external"
	if r.IsMicrosoftInfrastructure {
		kind = "Microsoft infrastructure"
	}
	return telemetry.Event{
		Name:     eventRelatedTenant,
		Body:     fmt.Sprintf("related tenant %s (%s)", r.ID, kind),
		Severity: telemetry.SeverityInfo,
		Attrs:    attrs,
	}
}

// firstObserved returns the earliest `initial` createdDateTime across the row's
// metric blocks, or "" when none is present.
func firstObserved(r relatedTenant) string {
	var best time.Time
	var bestRaw string
	for _, b := range []*metricBlock{
		r.B2BRegistrationMetrics,
		r.B2BSignInActivityMetrics,
		r.AppB2BSignInActivityMetrics,
		r.MultiTenantApplicationMetrics,
	} {
		if b == nil || b.Initial == nil || b.Initial.CreatedDateTime == "" {
			continue
		}
		t, err := time.Parse(time.RFC3339, b.Initial.CreatedDateTime)
		if err != nil {
			continue
		}
		if bestRaw == "" || t.Before(best) {
			best, bestRaw = t, b.Initial.CreatedDateTime
		}
	}
	return bestRaw
}

// setInt writes a pointer-modeled counter only when the wire carried it. An
// absent value emits NO key rather than a zero — see the package doc.
func setInt(attrs telemetry.Attrs, key string, v *int64) {
	if v != nil {
		attrs[key] = float64(*v)
	}
}

// boolTo01 maps a posture flag to the 0/1 its gauge carries.
func boolTo01(b bool) float64 {
	if b {
		return 1
	}
	return 0
}

func init() {
	collectors.Register(func(d collectors.Deps) collector.SnapshotCollector {
		return New(d.Graph, d.Logger)
	})
}

// Compile-time checks that the collector satisfies every interface the
// composition root type-asserts on.
var (
	_ collector.SnapshotCollector = (*Collector)(nil)
	_ collectors.Experimental     = (*Collector)(nil)
)
