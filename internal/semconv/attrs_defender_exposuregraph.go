package semconv

// defender.exposure_graph attributes (#350) — the Defender Exposure Management
// graph, read through the advanced-hunting ExposureGraphNodes and
// ExposureGraphEdges tables.
//
// Reused where a key already exists: AttrCategories (attrs_defender.go, the
// node's category ontology), AttrAccountEnabled / AttrAccountDisplayName /
// AttrAccountUpn / AttrAccountDomain / AttrEmailAddress / AttrIdentityType /
// AttrAppId / AttrServicePrincipalType / AttrAppOwnerOrganizationId /
// AttrPublisherDomain / AttrCreatedDateTime / AttrTags (identity-shaped nodes),
// AttrDeviceName / AttrDeviceType / AttrDeviceSubtype / AttrDeviceCategory /
// AttrOsPlatform / AttrOnboardingStatus / AttrSensorHealthState / AttrRiskScore /
// AttrIsExcluded / AttrAadDeviceId (device-shaped nodes), AttrSeverity
// (finding-shaped nodes), AttrCreatedBy / AttrPlatform (AI-shaped nodes),
// AttrVendor / AttrCriticalityLevel (SaaS-shaped nodes), AttrAgentId
// (attrs_entra.go) and AttrTenantId (stamped centrally).
//
// # Why the twin carries a flat union rather than a per-label sub-struct
//
// NodeProperties is a `dynamicColumnValue` — an arbitrarily deep object whose
// shape is chosen by NodeLabel (live-measured 2026-07-28, #350: 19 labels, at
// least seven distinct property shapes). The field set below is the UNION
// observed across those labels, and the mapper attempts every field on every
// node, omitting the ones the wire did not send. That is the same one-builder-
// many-shapes pattern defender.mdo_policies uses for its seven policy types, and
// it is what makes the acceptance criterion "unknown labels/properties do not
// drop rows" true by construction: a label nobody has seen yet still produces a
// twin carrying whatever subset of these fields it happens to have, plus
// AttrNodeLabel as the discriminator a reader keys off.
//
// # What is deliberately NOT mapped
//
// The finding-shaped labels (mdcManagementRecommendation, mdcAuditingRecommen-
// dation, mde-healthFinding, aadSecurityRecommendation) carry a `description`
// that is multi-paragraph HTML — one live sample ran past 600 characters of
// markup for a single PostgreSQL setting. It is remediation prose, it is
// identical for every tenant, and it is not a fact about this tenant's graph, so
// it is not emitted. Neither is NodeProperties itself: shipping the raw dynamic
// object would put an unbounded, unreviewed blob on every record. AttrSeverity
// and AttrRecommendationCategory carry the parts of a finding that a reader can
// actually act on.
const (
	// Node identity. AttrNodeLabel is the ONLY one of these that is also a
	// metric label — it is Microsoft's node ontology (19 values across 993,292
	// live nodes), bounded by the ontology rather than by tenant size. NodeId
	// and NodeName are per-entity and are twin-only (#112).
	AttrNodeId    = "node_id"
	AttrNodeLabel = "node_label"
	AttrNodeName  = "node_name"

	// EntityIds arrives as a collection of JSON STRINGS, each
	// {"type":…,"id":…}, not as objects — a mapper that treats an element as a
	// plain identifier emits the whole JSON blob where an id belongs. The two
	// keys below hold the decoded halves: the id values and their type names,
	// index-aligned.
	AttrEntityIds     = "entity_ids"
	AttrEntityIdTypes = "entity_id_types"

	// AttrTwinned is the metric-only dimension recording whether nodes/edges of
	// this label were emitted as twins or only counted. A label whose population
	// exceeds the per-label twin threshold is counted and NOT twinned, and this
	// is how that shows up in the metric rather than as a silent absence.
	AttrTwinned = "twinned"

	// Edge identity and endpoints. AttrEdgeLabel is a metric label; the endpoint
	// ids and names are twin-only.
	AttrEdgeId          = "edge_id"
	AttrEdgeLabel       = "edge_label"
	AttrSourceNodeId    = "source_node_id"
	AttrSourceNodeName  = "source_node_name"
	AttrSourceNodeLabel = "source_node_label"
	AttrTargetNodeId    = "target_node_id"
	AttrTargetNodeName  = "target_node_name"
	AttrTargetNodeLabel = "target_node_label"

	// Edge properties. EdgeProperties is a dynamicColumnValue like
	// NodeProperties and is empty for most edge labels; the one live-observed
	// shape is `userRightsOnDevice` on a "can authenticate to" edge, which is
	// the edge worth reading — it says what the source identity can DO on the
	// target device. AttrIsLocalAdmin already exists in the registry.
	AttrUserRights   = "user_rights"
	AttrLogonMethods = "logon_methods"

	// The other three live edge-property shapes. Each is the reason its edge
	// label exists at all, so mapping only userRightsOnDevice would leave the
	// second-largest edge label (`has permissions to`, 120 of 337) carrying no
	// fact beyond its endpoints.
	//
	// The permission and role collections repeat the EntityIds trap in a
	// different place: their elements are JSON STRINGS —
	// `{"permissionValue":"DeviceManagementApps.ReadWrite.All"}` and
	// `{"roleValue":"Owner"}` — so they need the same second decode, and the
	// keys below hold the decoded VALUES, never the wrapper objects.
	AttrDelegatedPermissions   = "delegated_permissions"
	AttrApplicationPermissions = "application_permissions"
	AttrRolePermissions        = "role_permissions"
	// AttrHasPrimaryRefreshToken rides the `has credentials of` edge. A PRT is
	// the token that lets a device act as the user, so an edge asserting one
	// exists is a real authentication-path fact; the token itself is never on
	// the wire, only the boolean.
	AttrHasPrimaryRefreshToken = "has_primary_refresh_token"

	// Identity-shaped node properties not already in the registry.
	AttrPublisherName          = "publisher_name"
	AttrPrimaryProvider        = "primary_provider"
	AttrAlternativeNames       = "alternative_names"
	AttrHasLeakedCredentials   = "has_leaked_credentials"
	AttrHasAdLeakedCredentials = "has_ad_leaked_credentials"

	// Device-shaped node properties not already in the registry. The two
	// *FriendlyName fields are separate wire fields from osPlatform/osVersion,
	// not renderings of them, so they get their own keys rather than
	// overwriting AttrOsPlatform.
	AttrOsPlatformFriendlyName = "os_platform_friendly_name"
	AttrOsVersionFriendlyName  = "os_version_friendly_name"
	AttrExposureScore          = "exposure_score"
	AttrIsCustomerFacing       = "is_customer_facing"
	AttrIsHybridAzureAdJoined  = "is_hybrid_azure_ad_joined"
	AttrDeviceRole             = "device_role"
	AttrFirstSeen              = "first_seen"
	AttrLastSeen               = "last_seen"

	// Finding-shaped node properties. `description` is deliberately absent —
	// see the package comment above.
	AttrRecommendationCategory = "recommendation_category"
	AttrSecurityIssue          = "security_issue"

	// AI-model-shaped node properties (label baseModel). AttrDeprecationDate is
	// spelled correctly here; the WIRE field is `depricationDate`, Microsoft's
	// typo, live-observed 2026-07-28 — the mapper reads their spelling and
	// publishes ours.
	AttrModelName        = "model_name"
	AttrModelVersion     = "model_version"
	AttrBaseModelName    = "base_model_name"
	AttrBaseModelVersion = "base_model_version"
	AttrCollectionType   = "collection_type"
	AttrIsExpired        = "is_expired"
	AttrDeprecationDate  = "deprecation_date"
	AttrTaskCapabilities = "task_capabilities"

	// AI-agent-shaped node properties (label ai-agent). The agent's own
	// free-text `description` is not emitted, for the same reason the finding
	// description is not.
	AttrAgentName               = "agent_name"
	AttrAgentVersion            = "agent_version"
	AttrPublishedStatus         = "published_status"
	AttrPublishedAgentIndicator = "published_agent_indicator"

	// SaaS-application-shaped node properties (label "SaaS Application").
	AttrSaasName                  = "saas_name"
	AttrRuleBasedCriticalityLevel = "rule_based_criticality_level"
	AttrCriticalityRuleNames      = "criticality_rule_names"

	// Cloud-account-shaped node properties (label subscriptions).
	AttrSubscriptionName    = "subscription_name"
	AttrHierarchyIdentifier = "hierarchy_identifier"
	AttrHierarchyType       = "hierarchy_type"
)
