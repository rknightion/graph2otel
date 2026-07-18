package semconv

// Attribute keys used only by m365.* collectors.
const (
	AttrActorIds               = "actor_ids"
	AttrAzureAdEventType       = "azure_ad_event_type"
	AttrClientIp               = "client_ip"
	AttrExtendedPropertyNames  = "extended_property_names"
	AttrExtendedPropertyValues = "extended_property_values"
	AttrObjectId               = "object_id"
	AttrOperation              = "operation"
	AttrOrganizationId         = "organization_id"
	AttrRecordType             = "record_type"
	AttrRecordTypeId           = "record_type_id"
	AttrResultStatus           = "result_status"

	// Service-health issue (m365/servicehealth, #119) attribute keys.
	AttrFeature              = "feature"
	AttrFeatureGroup         = "feature_group"
	AttrImpactDescription    = "impact_description"
	AttrIsResolved           = "is_resolved"
	AttrLastModifiedDateTime = "last_modified_date_time"
	AttrOrigin               = "origin"

	// AttrService and AttrWorkload are DELIBERATELY ALIASED: m365/activity sets
	// both from one source value (auditData.Workload) at activity.go — see
	// setStr(attrs, "workload", workload) / setStr(attrs, "service", workload).
	// "service" is a stable alias of "workload" kept for consumers that filter on
	// either name; the two keys carry the same value by design. Do NOT resolve or
	// dedupe them into one attribute. The attrs_registry_test allowlist blesses
	// this pair as the one place two constants may share a value. [#141]
	AttrService = "service"

	// AttrUserKey holds the classic Office 365 UserKey (an opaque key) on BOTH
	// m365 transports — m365/activity maps wire UserKey and m365/unifiedaudit maps
	// wire userId into it, because the unified-audit wire field named `userId`
	// actually CONTAINS the classic UserKey (#151). See AttrUserId for the pairing.
	AttrUserKey    = "user_key"
	AttrUserType   = "user_type"
	AttrUserTypeId = "user_type_id"
	AttrVersion    = "version"

	// AttrWorkload is the O365 workload (e.g. "Exchange", "SharePoint"). See
	// AttrService above — the two are the deliberately-aliased pair, both fed from
	// one Workload value. [#141]
	AttrWorkload = "workload"
)
