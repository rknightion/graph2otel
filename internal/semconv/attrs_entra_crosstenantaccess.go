package semconv

// Attribute keys introduced by the entra.cross_tenant_access collector (#321):
// GET /policies/crossTenantAccessPolicy (root singleton, allowedCloudEndpoints
// only) and GET /policies/crossTenantAccessPolicy/default (the rich default
// configuration — inbound trust, the five b2b/tenant-restriction access
// blocks, automatic user consent). Partners
// (/policies/crossTenantAccessPolicy/partners) is counted only — #321's
// decision, mirrored from entra/tenantpolicy's three empty scoped-policy
// collections, is that a collection with zero live members gets no field
// mapper, so it contributes no attribute keys here.
//
// REUSED rather than re-coined (the registry's no-duplicate-values gate would
// fail a second constant carrying any of these strings): AttrId
// (attrs_shared.go, both singletons' id), AttrDisplayName (attrs_shared.go,
// the root singleton's displayName), AttrService / AttrDirection
// (attrs_m365.go / attrs_defender.go, the entra.cross_tenant_access.access
// metric's own labels).
//
// # Metric label value sets are documented on the collector, not here
//
// `access_type` is a Graph-supplied enum value (allowed/blocked observed
// live) used as a metric label on entra.cross_tenant_access.access. Per
// CLAUDE.md's wire-value-watching section, one tenant's one observed value
// pair is not a value set: the collector package doc records the decision to
// leave it explicitly UNWATCHED by internal/wirecheck rather than invent a
// watchdog over an unconfirmed enum.
//
// # Why the default-configuration twin has this many keys
//
// The default configuration has five independent access-control surfaces
// (b2bCollaborationOutbound/Inbound, b2bDirectConnectOutbound/Inbound,
// tenantRestrictions), each carrying its own usersAndGroups/applications
// (and, for tenantRestrictions only, devices) sub-block with an accessType
// plus a target list. The bounded metric already exposes accessType per
// service/direction/target_kind combination, but only the log twin can carry
// the bounded target IDENTIFIER arrays (#321, mirroring #317's
// setTargetIDs pattern) — so every sub-block gets its own access_type +
// target_ids/target_count/targets_truncated key trio, flattened onto the one
// entra.cross_tenant_access_default record rather than a nested object,
// matching this codebase's fixed-typed-field convention over raw JSON.
const (
	// AttrTargetKind is entra.cross_tenant_access.access's third label,
	// alongside the shared AttrService/AttrDirection: which sub-block of the
	// access-control surface (usersAndGroups, applications, or — tenant
	// restrictions only — devices) the point describes.
	AttrTargetKind = "target_kind"

	// AttrAccessType is entra.cross_tenant_access.access's value-carrying
	// label: the Graph-supplied accessType string (allowed/blocked observed
	// live). Deliberately left UNWATCHED by internal/wirecheck — see the
	// collector package doc.
	AttrAccessType = "access_type"

	// AttrIsServiceDefault reports whether the default configuration is still
	// Microsoft's service default (never customized) or has been edited by
	// the tenant.
	AttrIsServiceDefault = "is_service_default"

	// AttrAllowedCloudEndpoints is the root singleton's allowedCloudEndpoints
	// array (national cloud endpoints this tenant permits cross-tenant
	// access to travel through). Observed empty live 2026-07-28 — an empty
	// array is emitted as absent by telemetry.SetStrs, not a fabricated
	// empty-list attribute.
	AttrAllowedCloudEndpoints = "allowed_cloud_endpoints"

	// Inbound-trust settings (inboundTrust.*): whether this tenant accepts an
	// external tenant's own MFA / device-compliance / hybrid-join claim
	// instead of re-enforcing it. Each is ALSO the bounded `setting` label
	// value on entra.cross_tenant_access.inbound_trust; these are the twin's
	// typed copies for the same three switches.
	AttrInboundTrustMfaAccepted                       = "inbound_trust_mfa_accepted"
	AttrInboundTrustCompliantDeviceAccepted           = "inbound_trust_compliant_device_accepted"
	AttrInboundTrustHybridAzureAdJoinedDeviceAccepted = "inbound_trust_hybrid_azure_ad_joined_device_accepted"

	// Automatic user consent settings (automaticUserConsentSettings.*):
	// whether cross-tenant B2B collaboration invitations are silently
	// pre-consented rather than requiring an explicit admin/user click.
	AttrAutomaticConsentInboundAllowed  = "automatic_consent_inbound_allowed"
	AttrAutomaticConsentOutboundAllowed = "automatic_consent_outbound_allowed"

	// b2bCollaborationOutbound.usersAndGroups.
	AttrB2bCollabOutboundUsersAccessType       = "b2b_collab_outbound_users_access_type"
	AttrB2bCollabOutboundUsersTargetIds        = "b2b_collab_outbound_users_target_ids"
	AttrB2bCollabOutboundUsersTargetCount      = "b2b_collab_outbound_users_target_count"
	AttrB2bCollabOutboundUsersTargetsTruncated = "b2b_collab_outbound_users_targets_truncated"
	// b2bCollaborationOutbound.applications.
	AttrB2bCollabOutboundAppsAccessType       = "b2b_collab_outbound_apps_access_type"
	AttrB2bCollabOutboundAppsTargetIds        = "b2b_collab_outbound_apps_target_ids"
	AttrB2bCollabOutboundAppsTargetCount      = "b2b_collab_outbound_apps_target_count"
	AttrB2bCollabOutboundAppsTargetsTruncated = "b2b_collab_outbound_apps_targets_truncated"

	// b2bCollaborationInbound.usersAndGroups.
	AttrB2bCollabInboundUsersAccessType       = "b2b_collab_inbound_users_access_type"
	AttrB2bCollabInboundUsersTargetIds        = "b2b_collab_inbound_users_target_ids"
	AttrB2bCollabInboundUsersTargetCount      = "b2b_collab_inbound_users_target_count"
	AttrB2bCollabInboundUsersTargetsTruncated = "b2b_collab_inbound_users_targets_truncated"
	// b2bCollaborationInbound.applications.
	AttrB2bCollabInboundAppsAccessType       = "b2b_collab_inbound_apps_access_type"
	AttrB2bCollabInboundAppsTargetIds        = "b2b_collab_inbound_apps_target_ids"
	AttrB2bCollabInboundAppsTargetCount      = "b2b_collab_inbound_apps_target_count"
	AttrB2bCollabInboundAppsTargetsTruncated = "b2b_collab_inbound_apps_targets_truncated"

	// b2bDirectConnectOutbound.usersAndGroups.
	AttrB2bDirectOutboundUsersAccessType       = "b2b_direct_outbound_users_access_type"
	AttrB2bDirectOutboundUsersTargetIds        = "b2b_direct_outbound_users_target_ids"
	AttrB2bDirectOutboundUsersTargetCount      = "b2b_direct_outbound_users_target_count"
	AttrB2bDirectOutboundUsersTargetsTruncated = "b2b_direct_outbound_users_targets_truncated"
	// b2bDirectConnectOutbound.applications.
	AttrB2bDirectOutboundAppsAccessType       = "b2b_direct_outbound_apps_access_type"
	AttrB2bDirectOutboundAppsTargetIds        = "b2b_direct_outbound_apps_target_ids"
	AttrB2bDirectOutboundAppsTargetCount      = "b2b_direct_outbound_apps_target_count"
	AttrB2bDirectOutboundAppsTargetsTruncated = "b2b_direct_outbound_apps_targets_truncated"

	// b2bDirectConnectInbound.usersAndGroups.
	AttrB2bDirectInboundUsersAccessType       = "b2b_direct_inbound_users_access_type"
	AttrB2bDirectInboundUsersTargetIds        = "b2b_direct_inbound_users_target_ids"
	AttrB2bDirectInboundUsersTargetCount      = "b2b_direct_inbound_users_target_count"
	AttrB2bDirectInboundUsersTargetsTruncated = "b2b_direct_inbound_users_targets_truncated"
	// b2bDirectConnectInbound.applications.
	AttrB2bDirectInboundAppsAccessType       = "b2b_direct_inbound_apps_access_type"
	AttrB2bDirectInboundAppsTargetIds        = "b2b_direct_inbound_apps_target_ids"
	AttrB2bDirectInboundAppsTargetCount      = "b2b_direct_inbound_apps_target_count"
	AttrB2bDirectInboundAppsTargetsTruncated = "b2b_direct_inbound_apps_targets_truncated"

	// tenantRestrictions.usersAndGroups.
	AttrTenantRestrictionsUsersAccessType       = "tenant_restrictions_users_access_type"
	AttrTenantRestrictionsUsersTargetIds        = "tenant_restrictions_users_target_ids"
	AttrTenantRestrictionsUsersTargetCount      = "tenant_restrictions_users_target_count"
	AttrTenantRestrictionsUsersTargetsTruncated = "tenant_restrictions_users_targets_truncated"
	// tenantRestrictions.applications.
	AttrTenantRestrictionsAppsAccessType       = "tenant_restrictions_apps_access_type"
	AttrTenantRestrictionsAppsTargetIds        = "tenant_restrictions_apps_target_ids"
	AttrTenantRestrictionsAppsTargetCount      = "tenant_restrictions_apps_target_count"
	AttrTenantRestrictionsAppsTargetsTruncated = "tenant_restrictions_apps_targets_truncated"
	// tenantRestrictions.devices — deliberately access_type ONLY (no target
	// array): this sub-block is null on the live tenant (#321's ground truth)
	// and no evidence exists yet for whether Graph gives it a targets list at
	// all, so the collector reads only the one field it can be confident
	// about the shape of.
	AttrTenantRestrictionsDevicesAccessType = "tenant_restrictions_devices_access_type"
)
