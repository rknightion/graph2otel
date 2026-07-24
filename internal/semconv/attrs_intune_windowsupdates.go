package semconv

// Attribute keys introduced by intune.windows_updates (#259), the Windows Update
// for Business DEPLOYMENT SERVICE surface at /beta/admin/windows/updates.
//
// # Four keys are reused rather than re-coined
//
// The two record shapes this collector maps carry four fields that already have
// a constant in this package, and they use those:
//
//	updatePolicy.id                  -> AttrPolicyId            ("policy_id")
//	*.createdDateTime                -> AttrCreatedDateTime     ("created_date_time")
//	deployment.lastModifiedDateTime  -> AttrLastModifiedDateTime("last_modified_date_time")
//	catalogEntry.displayName         -> AttrDisplayName         ("display_name")
//
// The registry's no-duplicate-values gate makes this mandatory rather than
// polite: a second constant carrying "policy_id" is a build failure.
//
// # What is a metric label and what is not
//
// Exactly four of the keys below are ever used as a METRIC label, and all four
// are bounded Graph wire enums whose value set does not grow with the tenant:
// AttrUpdateCategory, AttrDeploymentEffectiveState, AttrDeploymentRequestedState
// and AttrCatalogEntryType. Everything else is per-entity or unbounded twin
// detail — a policy id, an audience id, a rule's evaluation timestamps, a
// catalog entry id — and rides the log twin only (#112/#114).
const (
	// AttrUpdateCategory is one member of a policy's
	// autoEnrollmentUpdateCategories array (`quality`, `driver`, `feature`), and
	// the sole label on the policy gauge. A policy can enroll in several, so it
	// contributes one to each of its categories — see the gauge's description.
	AttrUpdateCategory = "update_category"
	// AttrAudienceId is the deployment-audience object a policy or deployment
	// targets (`audience.id`). Per-entity: it is a GUID naming one audience, so
	// it rides the twin and never a metric label. graph2otel does not expand the
	// audience — its members are updatable assets (devices), an unbounded
	// per-entity fan-out with its own scope story.
	AttrAudienceId = "audience_id"
	// AttrAutoEnrollmentUpdateCategories is the policy's full
	// autoEnrollmentUpdateCategories array, verbatim, so the twin still says what
	// a single policy enrolled in after the gauge has split it by member.
	AttrAutoEnrollmentUpdateCategories = "auto_enrollment_update_categories"

	// AttrComplianceChangeRuleTypes lists the @odata.type DISCRIMINATOR of each
	// complianceChangeRule on a policy, short-formed (`contentApprovalRule`).
	// Read from the discriminator, never inferred from which fields happen to be
	// present — a rule variant carries a different field set.
	AttrComplianceChangeRuleTypes = "compliance_change_rule_types"
	// AttrContentFilterTypes lists each rule's contentFilter @odata.type,
	// short-formed (`qualityUpdateFilter`, `driverUpdateFilter`). Both are
	// live-observed on one tenant, and they carry DIFFERENT fields — which is
	// exactly why the discriminator is emitted rather than guessed at.
	AttrContentFilterTypes = "content_filter_types"
	// AttrContentFilterClassifications lists the `classification` of each
	// qualityUpdateFilter (`security`, `nonSecurity`, `all`). Only the quality
	// variant has this field, so the list is shorter than
	// AttrContentFilterTypes whenever a policy mixes variants.
	AttrContentFilterClassifications = "content_filter_classifications"
	// AttrContentFilterCadences lists the `cadence` of each qualityUpdateFilter
	// (`monthly`, `outOfBand`). Quality-variant-only, like the classification.
	AttrContentFilterCadences = "content_filter_cadences"
	// AttrDeploymentStartDelays lists each rule's durationBeforeDeploymentStart
	// VERBATIM, as the ISO-8601 duration string Graph sends (`PT0S`, `P2D`). It
	// is deliberately not converted to seconds: a policy may carry several rules,
	// telemetry.Attrs has no numeric-list type, and picking one rule's delay or
	// summing them would publish a number the wire never carried.
	AttrDeploymentStartDelays = "deployment_start_delays"
	// AttrRuleLastEvaluatedDateTimes lists the lastEvaluatedDateTime of each rule
	// that has ACTUALLY been evaluated. Rules that never have carry the .NET zero
	// date (`0001-01-01T00:00:00Z`), which is omitted here and counted in
	// AttrRulesNeverEvaluated instead — emitting it would date an evaluation to
	// the year 1.
	AttrRuleLastEvaluatedDateTimes = "rule_last_evaluated_date_times"
	// AttrRulesNeverEvaluated counts the policy's complianceChangeRules whose
	// lastEvaluatedDateTime is the .NET zero date. It is the positive half of
	// dropping that sentinel: the fact "this rule has never run" survives, as a
	// number, instead of vanishing with the bogus timestamp.
	AttrRulesNeverEvaluated = "rules_never_evaluated"

	// AttrDaysUntilForcedReboot is deploymentSettings.userExperience's field of
	// the same name. It is a POINTER on the wire model: 0 means "reboot is forced
	// immediately", null means "not configured", and the two must not collapse —
	// null omits the attribute, 0 emits a real 0.
	AttrDaysUntilForcedReboot = "days_until_forced_reboot"
	// AttrOfferAsOptional is deploymentSettings.userExperience.offerAsOptional —
	// whether the update is offered as optional rather than pushed. Nullable,
	// so absent means "not configured", not false.
	AttrOfferAsOptional = "offer_as_optional"
	// AttrIsHotpatchEnabled is deploymentSettings.userExperience.isHotpatchEnabled
	// — whether quality updates apply without a reboot. Nullable.
	AttrIsHotpatchEnabled = "is_hotpatch_enabled"
	// AttrOfferWhileRecommendedBy is
	// deploymentSettings.contentApplicability.offerWhileRecommendedBy: who has to
	// recommend a driver before the policy offers it (`microsoft`).
	AttrOfferWhileRecommendedBy = "offer_while_recommended_by"

	// AttrDeploymentId is a deployment's own id. Per-entity: twin only.
	AttrDeploymentId = "deployment_id"
	// AttrDeploymentEffectiveState is state.effectiveValue — what the deployment
	// is ACTUALLY doing (`offering`, `paused`, `none`, `scheduled`). Bounded wire
	// enum, so it is a metric label.
	AttrDeploymentEffectiveState = "deployment_effective_state"
	// AttrDeploymentRequestedState is state.requestedValue — what was ASKED FOR.
	// It is a separate key, not a collapsed one, because the live wire shows the
	// two disagreeing (`effectiveValue: offering` under `requestedValue: none`)
	// and that disagreement is the signal this collector exists for.
	AttrDeploymentRequestedState = "deployment_requested_state"
	// AttrDeploymentStateReasons is state.reasons — WHY the effective state is
	// what it is. Free-form-ish and per-deployment, so twin only.
	AttrDeploymentStateReasons = "deployment_state_reasons"
	// AttrDeploymentStateMatchesRequest is the derived answer to "is this
	// deployment doing what was asked?" — "true"/"false". It exists because LogQL
	// label filters compare a label to a LITERAL, not to another label, so
	// without it the mismatch the twin's two state keys describe is not directly
	// queryable. Omitted entirely when either side is absent: an unknown value
	// cannot prove a match or a mismatch.
	AttrDeploymentStateMatchesRequest = "deployment_state_matches_request"

	// AttrUpdateContentType is the deployment's content @odata.type,
	// short-formed (`catalogContent`). Twin only — it is near-constant, so the
	// gauge breaks down by AttrCatalogEntryType instead, which says whether a
	// stuck deployment is a quality, feature or driver update.
	AttrUpdateContentType = "update_content_type"
	// AttrCatalogEntryType is the nested catalogEntry's @odata.type, short-formed
	// (`qualityUpdateCatalogEntry`, `featureUpdateCatalogEntry`). Bounded, and
	// the dimension that makes the deployment gauge worth reading.
	AttrCatalogEntryType = "catalog_entry_type"
	// AttrCatalogEntryId is the catalogEntry's id. Live-measured empty ("") on
	// this tenant's only deployment, and an empty id is not an identifier — it is
	// omitted rather than emitted, so the twin never claims to name an update it
	// cannot name.
	AttrCatalogEntryId = "catalog_entry_id"
	// AttrUpdateReleaseDateTime is the catalogEntry's releaseDateTime — when
	// Microsoft published the update, not when it was deployed.
	AttrUpdateReleaseDateTime = "update_release_date_time"
	// AttrUpdateClassification is qualityUpdateCatalogEntry.qualityUpdateClassification
	// (`security`, `nonSecurity`). Read ONLY when the catalogEntry discriminator
	// says quality — a feature entry has no such field, and reading it
	// structurally would silently map a different variant's shape.
	AttrUpdateClassification = "update_classification"
	// AttrUpdateCadence is qualityUpdateCatalogEntry.qualityUpdateCadence
	// (`monthly`, `outOfBand`). Quality-variant-only, same rule.
	AttrUpdateCadence = "update_cadence"
	// AttrIsExpeditable is catalogEntry.isExpeditable — whether this update CAN
	// be expedited at all, as opposed to whether it was.
	AttrIsExpeditable = "is_expeditable"
	// AttrIsExpedited is settings.expedite.isExpedited — whether this deployment
	// WAS expedited.
	AttrIsExpedited = "is_expedited"
	// AttrIsReadinessTest is settings.expedite.isReadinessTest — whether the
	// expedite is a rehearsal rather than a real rollout.
	AttrIsReadinessTest = "is_readiness_test"
)
