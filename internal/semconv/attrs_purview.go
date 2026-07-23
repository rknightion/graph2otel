package semconv

// Attribute keys used only by purview.* collectors.
const (
	AttrActionAfterRetention    = "action_after_retention"
	AttrApplicableTo            = "applicable_to"
	AttrBehaviorDuringRetention = "behavior_during_retention"
	AttrClosedDateTime          = "closed_date_time"
	AttrDescription             = "description"
	AttrDescriptionForAdmins    = "description_for_admins"
	AttrDescriptionForUsers     = "description_for_users"
	AttrExternalId              = "external_id"
	AttrName                    = "name"
	AttrRetentionTrigger        = "retention_trigger"
)

// Attribute keys for the purview.dlp_* collector (#246): DLP policy definition
// inventory + enforcement mode. Reuses AttrWorkload ("workload"), AttrAction
// ("action"), AttrEnabled ("enabled"), AttrSeverity ("severity"), AttrPolicyId
// ("policy_id"), AttrPolicyName ("policy_name") and AttrRuleId ("rule_id") from
// the other domains rather than redefining those values. AttrEnforcementMode is
// deliberately NOT "mode" — that value is already AttrClipMode — and reads
// better anyway (Enforce vs AuditAndNotify is an enforcement mode).
const (
	AttrEnforcementMode      = "enforcement_mode"
	AttrBindingType          = "binding_type"
	AttrManagementRuleId     = "management_rule_id"
	AttrActions              = "actions"
	AttrRuleName             = "rule_name"
	AttrBoundWorkloads       = "bound_workloads"
	AttrWhenChangedUtc       = "when_changed_utc"
	AttrWhenRulesChangedUtc  = "when_rules_changed_utc"
	AttrLastModifiedUtc      = "last_modified_utc"
	AttrSensitiveInfoTypeIds = "sensitive_info_type_ids"
	AttrMinConfidence        = "min_confidence"
	AttrMaxConfidence        = "max_confidence"
	AttrMinCount             = "min_count"
	AttrMaxCount             = "max_count"
)
