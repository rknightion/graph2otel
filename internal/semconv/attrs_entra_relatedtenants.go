package semconv

// Attribute keys introduced by entra.related_tenants (#336): one
// entra.related_tenant event per tenant Entra's related-tenant discovery has
// found, from GET /beta/directory/tenantGovernance/relatedTenants.
//
// REUSED rather than re-coined (the registry's no-duplicate-values gate would
// fail a second constant carrying any of these strings): AttrCreatedDateTime
// (attrs_entra.go — the discovery record's own createdDateTime), AttrDirection
// (attrs_defender.go — inbound/outbound on the summed counters) and AttrKind
// (attrs.go — which metric block the with_metrics coverage gauge is counting).
//
// The related tenant's own tenant id is AttrRelatedTenantId below and
// deliberately NOT the shared `tenant_id` key: `tenant_id` is stamped on every
// signal by telemetry.WithTenant and means THIS tenant (#143). Naming the
// other party's id `tenant_id` would overwrite that at the emitter boundary
// and make a partner's records look like they came from a different graph2otel
// deployment.
//
// Live-measured 2026-07-29 against m7kni as graph2otel-poller: 16 related
// tenants, 13 external and 3 Microsoft infrastructure. Four of the five metric
// blocks are NULL on almost every row — 15 of 16 rows carry no B2B metrics at
// all and no row carries billing metrics — so every numeric here is a POINTER
// emitted only when the wire sends it. Absence is the common case on this
// surface, not the exception, which makes a fabricated zero the default
// failure mode rather than an edge case.
const (
	// AttrRelatedTenantId is the discovered tenant's own tenant id — the
	// other party in the relationship. See the package comment for why this
	// is not `tenant_id`.
	AttrRelatedTenantId = "related_tenant_id"

	// AttrIsMicrosoftInfrastructure is the row's isMicrosoftInfrastructure
	// flag. It is the one bounded axis on this surface and the only field
	// here that reaches a metric label: 3 of 16 live rows are Microsoft's own
	// infrastructure tenants, so a count that folds them in tells an operator
	// they have 16 external tenant relationships when they have 13.
	AttrIsMicrosoftInfrastructure = "is_microsoft_infrastructure"

	// AttrHasBillingMetrics records whether the row carried a billingMetrics
	// block at all. Its LEAVES are deliberately unmodeled: the block is null
	// on every one of the 16 live rows, so there is no observed field shape
	// to map and this project does not write a mapper from documentation
	// (#142/#165). The boolean is the honest signal — it says "Microsoft sent
	// a billing measurement" without claiming to know what is in it.
	AttrHasBillingMetrics = "has_billing_metrics"

	// AttrMetricsFirstObservedDateTime is the `initial` snapshot's
	// createdDateTime for whichever metric blocks the row carries — when
	// Microsoft first measured this relationship, as distinct from
	// AttrCreatedDateTime, which is when the local discovery RECORD was
	// created. All 16 live rows share one createdDateTime within a second of
	// each other, because that is the moment discovery was enabled; the
	// relationships themselves are older, and this key is where that shows.
	AttrMetricsFirstObservedDateTime = "metrics_first_observed_date_time"

	// AttrB2bRegistrationWatermarkDateTime is the b2BRegistrationMetrics
	// recent snapshot's watermarkDateTime: the date Microsoft's own
	// aggregation had counted up to. A metric block whose watermark is stale
	// is reporting an old measurement, which is invisible from the counts
	// alone.
	AttrB2bRegistrationWatermarkDateTime = "b2b_registration_watermark_date_time"

	// AttrB2bRegistrationUpdatedDateTime is the b2BRegistrationMetrics recent
	// snapshot's updateDateTime.
	AttrB2bRegistrationUpdatedDateTime = "b2b_registration_updated_date_time"

	// AttrB2bRegistrationInboundUsers is recent.inboundTotalUsers: guests
	// from the related tenant registered in this one. Note the leaf name has
	// no "Monthly" — this block's counters are lifetime totals while the
	// sign-in blocks below are monthly, and the two must not be read as the
	// same measure.
	AttrB2bRegistrationInboundUsers = "b2b_registration_inbound_users"

	// AttrB2bRegistrationOutboundUsers is recent.outboundTotalUsers: this
	// tenant's users registered as guests in the related tenant.
	AttrB2bRegistrationOutboundUsers = "b2b_registration_outbound_users"

	// AttrB2bSigninWatermarkDateTime is the b2BSignInActivityMetrics recent
	// snapshot's watermarkDateTime.
	AttrB2bSigninWatermarkDateTime = "b2b_signin_watermark_date_time"

	// AttrB2bSigninUpdatedDateTime is the b2BSignInActivityMetrics recent
	// snapshot's updateDateTime.
	AttrB2bSigninUpdatedDateTime = "b2b_signin_updated_date_time"

	// AttrB2bSigninInboundUsers is recent.inboundMonthlyTotalUsers: users
	// from the related tenant who signed in here this month.
	AttrB2bSigninInboundUsers = "b2b_signin_inbound_users"

	// AttrB2bSigninOutboundUsers is recent.outboundMonthlyTotalUsers.
	AttrB2bSigninOutboundUsers = "b2b_signin_outbound_users"

	// AttrB2bSigninInboundApplications is
	// recent.inboundMonthlyTotalApplications: how many distinct applications
	// those inbound sign-ins reached. 10 on the one live row that carries
	// this block, against 1 inbound user — so the two counters answer
	// genuinely different questions and neither substitutes for the other.
	AttrB2bSigninInboundApplications = "b2b_signin_inbound_applications"

	// AttrB2bSigninOutboundApplications is
	// recent.outboundMonthlyTotalApplications.
	AttrB2bSigninOutboundApplications = "b2b_signin_outbound_applications"

	// AttrAppB2bSigninWatermarkDateTime is the appB2BSignInActivityMetrics
	// recent snapshot's watermarkDateTime. This block is the
	// application-scoped view of the same relationship and is a SEPARATE
	// measurement from b2BSignInActivityMetrics — on the one live row that
	// has both, inbound applications is 1 here and 10 there.
	AttrAppB2bSigninWatermarkDateTime = "app_b2b_signin_watermark_date_time"

	// AttrAppB2bSigninUpdatedDateTime is the appB2BSignInActivityMetrics
	// recent snapshot's updateDateTime.
	AttrAppB2bSigninUpdatedDateTime = "app_b2b_signin_updated_date_time"

	// AttrAppB2bSigninInboundUsers is recent.inboundMonthlyTotalUsers on the
	// application-scoped block.
	AttrAppB2bSigninInboundUsers = "app_b2b_signin_inbound_users"

	// AttrAppB2bSigninOutboundUsers is recent.outboundMonthlyTotalUsers on
	// the application-scoped block.
	AttrAppB2bSigninOutboundUsers = "app_b2b_signin_outbound_users"

	// AttrAppB2bSigninInboundApplications is
	// recent.inboundMonthlyTotalApplications on the application-scoped block.
	AttrAppB2bSigninInboundApplications = "app_b2b_signin_inbound_applications"

	// AttrAppB2bSigninOutboundApplications is
	// recent.outboundMonthlyTotalApplications on the application-scoped
	// block.
	AttrAppB2bSigninOutboundApplications = "app_b2b_signin_outbound_applications"

	// AttrMultiTenantAppWatermarkDateTime is the
	// multiTenantApplicationMetrics recent snapshot's watermarkDateTime. This
	// is the ONLY block populated on all 16 live rows.
	AttrMultiTenantAppWatermarkDateTime = "multi_tenant_app_watermark_date_time"

	// AttrMultiTenantAppUpdatedDateTime is the multiTenantApplicationMetrics
	// recent snapshot's updateDateTime.
	AttrMultiTenantAppUpdatedDateTime = "multi_tenant_app_updated_date_time"

	// AttrMultiTenantAppInboundApplications is
	// recent.inboundMonthlyTotalApplications: the related tenant's
	// multi-tenant applications used here. This block carries NO user
	// counters at all, unlike the two sign-in blocks — a shared leaf struct
	// decodes all three, so the absent user fields must stay pointers or this
	// block would publish two fabricated zero user counts on every row.
	AttrMultiTenantAppInboundApplications = "multi_tenant_app_inbound_applications"

	// AttrMultiTenantAppOutboundApplications is
	// recent.outboundMonthlyTotalApplications.
	AttrMultiTenantAppOutboundApplications = "multi_tenant_app_outbound_applications"
)
