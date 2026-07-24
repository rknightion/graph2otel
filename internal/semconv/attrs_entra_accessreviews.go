package semconv

// Attribute keys introduced by entra.access_reviews (#260), the Entra ID
// Governance access-review DEFINITION inventory.
//
// # Every key here is LOG-ONLY
//
// The collector's only metric is entra.access_reviews.total, labeled by
// `status` alone (the existing AttrStatus). Nothing below may become a metric
// label: a review definition is an entity, so a series keyed by its id, its
// display name, its scope queries or its reviewer list is the #112 failure
// exactly. The bounded count answers "how many reviews are in each state"; the
// twin answers "which one, scoped to what, reviewed by whom".
//
// # Reused rather than re-coined
//
// Seven of the record's fields already have a constant, and those are REUSED:
//
//	id                      -> AttrId
//	displayName             -> AttrDisplayName
//	status                  -> AttrStatus
//	createdDateTime         -> AttrCreatedDateTime
//	lastModifiedDateTime    -> AttrLastModifiedDateTime
//	descriptionForAdmins    -> AttrDescriptionForAdmins   (coined by purview)
//	createdBy.displayName   -> AttrCreatedBy              (coined by m365; the
//	                           same meaning — who created this object, in
//	                           human-readable form)
//
// The registry's no-duplicate-values gate enforces this from the other side: a
// second constant carrying "display_name" is a build failure.
//
// # The createdBy family, and why it is three keys and not one
//
// createdBy arrives as a userIdentity OBJECT, and on the live wire its
// `displayName` and `userPrincipalName` are EMPTY STRINGS while `id` is set
// (live-measured 2026-07-24, #260) — Graph did not resolve the principal, it
// did not merely omit it. The three parts therefore travel as three keys, each
// set through telemetry.SetStr so an empty one is OMITTED rather than stamped
// blank. A blank user_principal_name on a twin reads as "this review has no
// creator", which is false; an absent one reads as "not resolved", which is
// true.
const (
	// AttrCreatedById is createdBy.id — the object id of the principal that
	// created the review. On the live tenant this is a SERVICE PRINCIPAL, not a
	// user, which is why the id is carried even when the name is not: it is the
	// only part of createdBy that is ever populated there.
	AttrCreatedById = "created_by_id"
	// AttrCreatedByUserPrincipalName is createdBy.userPrincipalName. Empty on
	// the live wire, so omitted; see the family note above.
	AttrCreatedByUserPrincipalName = "created_by_user_principal_name"
	// AttrCreatedByType is createdBy.type. Null on the live wire, so omitted.
	AttrCreatedByType = "created_by_type"

	// AttrDescriptionForReviewers is descriptionForReviewers — the text shown to
	// the reviewer, distinct from AttrDescriptionForAdmins. Empty on the live
	// wire, so omitted.
	AttrDescriptionForReviewers = "description_for_reviewers"
)

// The scope family. `scope` is POLYMORPHIC: its concrete shape is named by an
// `@odata.type` discriminator, and the collector switches on that rather than
// probing for fields it hopes are there. AttrScopeODataType carries the discriminator
// with the "#microsoft.graph." prefix stripped; the remaining three carry the
// query strings the chosen shape actually holds, so which of them is present is
// itself a function of the scope type.
//
// These are deliberately NOT the existing AttrScope/AttrScopes, which carry
// OAuth permission scopes elsewhere in this codebase — an unrelated meaning.
const (
	// AttrScopeODataType is the scope's @odata.type, prefix-stripped
	// (e.g. "principalResourceMembershipsScope").
	//
	// Deliberately NOT "scope_type", which intune.rbac already uses for a
	// genuinely different thing: the wire's own `scopeType` enum on a role
	// assignment (`allDevicesAndLicensedUsers` and friends). Both were coined as
	// "scope_type" independently and collided at compile time — which was lucky,
	// because the alternative is one attribute key meaning two things depending
	// on which collector wrote the record, and a query filtering on it silently
	// matching the wrong shape. That is the tpm_version collision from #199,
	// caught earlier this time.
	AttrScopeODataType = "scope_odata_type"
	// AttrScopeQuery is the single `query` a plain accessReviewQueryScope holds.
	AttrScopeQuery = "scope_query"
	// AttrScopePrincipalQueries is principalResourceMembershipsScope.principalScopes'
	// queries — WHO is being reviewed (e.g. "/v1.0/users").
	AttrScopePrincipalQueries = "scope_principal_queries"
	// AttrScopeResourceQueries is principalResourceMembershipsScope.resourceScopes'
	// queries — WHAT access is being reviewed (e.g. a directory roleDefinition
	// URL, which is how a "review the Global Administrators" review identifies
	// itself).
	AttrScopeResourceQueries = "scope_resource_queries"
)

// The reviewer family. Counts are safe to read at a glance; the identities are
// the per-entity half and ride the twin only, never a metric label.
const (
	// AttrReviewerCount is len(reviewers).
	AttrReviewerCount = "reviewer_count"
	// AttrReviewerQueries is each reviewer's `query` — a Graph URL naming the
	// principal (e.g. "/v1.0/users/{guid}"), which is the identity form this
	// endpoint returns. There is no separate id field to prefer.
	AttrReviewerQueries = "reviewer_queries"
	// AttrFallbackReviewerCount is len(fallbackReviewers).
	//
	// There is NO backup_reviewer_count key, on purpose. `backupReviewers` is
	// returned by the BETA endpoint and NOT by v1.0 (live-measured 2026-07-24,
	// #260 — both were probed), and this collector reads v1.0. Emitting a zero
	// for a field the chosen endpoint never sends would publish a fabricated
	// fact, which is the failure mode CLAUDE.md's "absent field is not a
	// sentinel" rule exists to stop.
	AttrFallbackReviewerCount = "fallback_reviewer_count"
	// AttrAdditionalNotificationRecipientCount is
	// len(additionalNotificationRecipients).
	AttrAdditionalNotificationRecipientCount = "additional_notification_recipient_count"
	// AttrStageCount is len(stageSettings) — how many stages a multi-stage
	// review runs. Zero on the live wire (a single-stage review).
	AttrStageCount = "stage_count"
)

// The recurrence family — a review's expected CADENCE, read off
// settings.recurrence. It is the context a reader needs to judge whether a
// review is overdue, but this collector deliberately does NOT make that
// judgement itself (see the package doc of
// internal/collectors/entra/accessreviews on why instances are out of scope).
//
// There is no recurrence_end_date key: the live wire's range.endDate is
// "9999-12-31" for a never-ending recurrence, a sentinel rather than a date, and
// AttrRecurrenceRangeType already says "noEnd" without inventing a year-9999
// deadline.
const (
	// AttrRecurrencePatternType is recurrence.pattern.type (e.g. "absoluteMonthly").
	AttrRecurrencePatternType = "recurrence_pattern_type"
	// AttrRecurrenceInterval is recurrence.pattern.interval — the number of
	// pattern units between occurrences (3 absoluteMonthly = quarterly).
	AttrRecurrenceInterval = "recurrence_interval"
	// AttrRecurrenceRangeType is recurrence.range.type (e.g. "noEnd").
	AttrRecurrenceRangeType = "recurrence_range_type"
	// AttrRecurrenceStartDate is recurrence.range.startDate, a bare date.
	AttrRecurrenceStartDate = "recurrence_start_date"
)

// The settings family — the governance knobs that decide whether a review can
// actually change anything. Each is emitted only when the record carried a
// `settings` object at all, so an absent settings block omits the whole family
// rather than publishing a row of fabricated falses.
const (
	// AttrInstanceDurationDays is settings.instanceDurationInDays — how long each
	// recurrence stays open for reviewers.
	AttrInstanceDurationDays = "instance_duration_days"
	// AttrMailNotificationsEnabled is settings.mailNotificationsEnabled. With
	// AttrReminderNotificationsEnabled it is the collector's one WARN condition:
	// both false means reviewers are never told the review exists and never
	// reminded.
	AttrMailNotificationsEnabled = "mail_notifications_enabled"
	// AttrReminderNotificationsEnabled is settings.reminderNotificationsEnabled.
	AttrReminderNotificationsEnabled = "reminder_notifications_enabled"
	// AttrAutoApplyDecisionsEnabled is settings.autoApplyDecisionsEnabled —
	// whether decisions are applied without a human pressing apply.
	AttrAutoApplyDecisionsEnabled = "auto_apply_decisions_enabled"
	// AttrDefaultDecisionEnabled is settings.defaultDecisionEnabled — whether
	// non-responses take AttrDefaultDecision.
	AttrDefaultDecisionEnabled = "default_decision_enabled"
	// AttrDefaultDecision is settings.defaultDecision (e.g. "None"). Carried
	// verbatim: its value set has not been established from the wire, so it is
	// neither bucketed nor watched.
	AttrDefaultDecision = "default_decision"
	// AttrJustificationRequiredOnApproval is
	// settings.justificationRequiredOnApproval.
	AttrJustificationRequiredOnApproval = "justification_required_on_approval"
	// AttrRecommendationsEnabled is settings.recommendationsEnabled — whether
	// reviewers are shown Microsoft's approve/deny recommendation.
	AttrRecommendationsEnabled = "recommendations_enabled"
	// AttrApplyActionTypes is settings.applyActions' @odata.type discriminators,
	// prefix-stripped (e.g. "removeAccessApplyAction") — WHAT happens to access
	// when a decision is applied. The second polymorphic member on this record,
	// read the same way as `scope`: by discriminator, never structurally.
	AttrApplyActionTypes = "apply_action_types"
)
