package semconv

// Attribute keys for entra.agent_governance (#333): Entra Agent ID blueprints
// and agent identities, their lineage, and the sponsor/owner governance gaps.
//
// Reused where a key already exists: AttrId / AttrAppId / AttrDisplayName
// (attrs_shared.go), AttrCreatedDateTime / AttrServicePrincipalType /
// AttrSignInAudience / AttrAccountEnabled (attrs_entra.go), AttrOdataType
// (attrs_intune.go), AttrTags (attrs_defender.go), AttrBlueprintId
// (attrs_entra.go — already "blueprint_id", exactly the lineage field this
// collector's agent twin needs), AttrHasOwner / AttrOwnerCount
// (attrs_entra.go, #244's appownership collector — the same "does this
// principal have an owner" shape). Only the names below are genuinely new.
const (
	// AttrCreatedByAppId is the appId of the application that created this
	// blueprint/principal/agent — distinct from AttrAppId (the object's own
	// application id).
	AttrCreatedByAppId = "created_by_app_id"
	// AttrDisabledByMicrosoftStatus mirrors disabledByMicrosoftStatus. Always
	// null on every live-measured row (2026-07-28); kept as a pointer/omit-when-
	// absent field for the day Microsoft actually sets it, same reasoning as
	// authmethodspolicy's PolicyMigrationState.
	AttrDisabledByMicrosoftStatus = "disabled_by_microsoft_status"
	// AttrAppRoleAssignmentRequired mirrors appRoleAssignmentRequired on an
	// agent identity or blueprint principal.
	AttrAppRoleAssignmentRequired = "app_role_assignment_required"
	// AttrPublisherDomain mirrors a blueprint application's publisherDomain.
	AttrPublisherDomain = "publisher_domain"
	// AttrAppOwnerOrganizationId mirrors a blueprint principal's
	// appOwnerOrganizationId — the tenant that owns the underlying app
	// registration, distinct from the tenant graph2otel is polling.
	AttrAppOwnerOrganizationId = "app_owner_organization_id"
	// AttrHasSponsor is the agent-identity governance-gap counterpart to
	// AttrHasOwner: whether $expand=sponsors returned at least one sponsor.
	AttrHasSponsor = "has_sponsor"
	// AttrSponsorIds / AttrSponsorCount / AttrSponsorsTruncated carry an
	// agent's sponsors as bounded identifiers only (#112) — never the full
	// directoryObject Graph's $expand returns. See maxPrincipalIdentifiers in
	// agentgovernance.go.
	AttrSponsorIds        = "sponsor_ids"
	AttrSponsorCount      = "sponsor_count"
	AttrSponsorsTruncated = "sponsors_truncated"
	// AttrOwnerIds / AttrOwnersTruncated are this collector's owner-identifier
	// counterparts (AttrOwnerCount above is reused from appownership).
	AttrOwnerIds        = "owner_ids"
	AttrOwnersTruncated = "owners_truncated"
	// AttrTagsTruncated flags when a blueprint/principal/agent's tags array was
	// cut to maxPrincipalIdentifiers.
	AttrTagsTruncated = "tags_truncated"
)
