package semconv

// Attribute keys introduced by entra.recommendations (#315), the Entra
// directory-recommendations state twin.
//
// # Every key here is LOG-ONLY
//
// The collector's two metrics are entra.recommendations.total (labeled by the
// existing AttrStatus/AttrPriority) and
// entra.recommendations.impacted_resources.total (labeled by the existing
// AttrRecommendation, i.e. recommendationType). Nothing below may become a
// metric label: a recommendation is an entity, so a series keyed by its id,
// display name, or free-text fields is the #112 failure exactly. The bounded
// gauges answer "how many, in what state" and "how many resources impacted per
// type"; the twin answers "which recommendation, with what remediation
// guidance".
//
// # Reused rather than re-coined
//
// Several of the record's fields already have a constant, and those are
// REUSED (the registry's no-duplicate-values gate enforces this from the other
// side — a second constant carrying the same value is a build failure):
//
//	id                   -> AttrId
//	displayName          -> AttrDisplayName
//	category             -> AttrCategory
//	status               -> AttrStatus            (also a metric label)
//	priority             -> AttrPriority           (also a metric label)
//	recommendationType   -> AttrRecommendation     (also a metric label)
//	createdDateTime      -> AttrCreatedDateTime
//	lastModifiedDateTime -> AttrLastModifiedDateTime
//	lastModifiedBy       -> AttrLastModifiedBy
//	currentScore         -> AttrScore              (attrs_entra.go; securescore
//	                        uses the same constant for the same "a score value"
//	                        meaning)
//	maxScore             -> AttrMaxScore            (attrs_entra.go; same reuse)
const (
	// AttrBenefits is the recommendation's benefits free-text field.
	AttrBenefits = "benefits"
	// AttrRemediationImpact is remediationImpact — what changes for end users
	// once the recommendation is acted on.
	AttrRemediationImpact = "remediation_impact"
	// AttrRequiredLicenses is requiredLicenses (e.g. "microsoftEntraIdP2") — the
	// license SKU the recommendation needs to be actionable, carried verbatim
	// (its value set has not been established from the wire, so it is neither
	// bucketed nor watched).
	AttrRequiredLicenses = "required_licenses"
	// AttrReleaseType is releaseType (e.g. "generallyAvailable").
	AttrReleaseType = "release_type"
	// AttrImpactType is impactType (e.g. "users") — what kind of directory
	// object the recommendation's impact is measured against.
	AttrImpactType = "impact_type"
	// AttrInsights is the insights free-text field — the tenant-specific
	// evidence behind the recommendation (e.g. "You have 1 of 4 users that
	// don't have a user risk policy enabled.").
	AttrInsights = "insights"
	// AttrImpactStartDateTime is impactStartDateTime.
	AttrImpactStartDateTime = "impact_start_date_time"
	// AttrPostponeUntilDateTime is postponeUntilDateTime. Null on a
	// non-postponed recommendation, which SetStr omits rather than stamping
	// blank.
	AttrPostponeUntilDateTime = "postpone_until_date_time"
	// AttrFeatureAreas is featureAreas (e.g. ["conditionalAccess"]).
	AttrFeatureAreas = "feature_areas"
	// AttrActionStepTexts is each actionSteps[].text, in step order — the
	// human-readable remediation walkthrough. The actionUrl/stepNumber parts of
	// each step are not carried: the text already reads as a numbered list
	// ("1. ...", "2. ..."), so stepNumber is redundant, and the URLs are
	// secondary reference links rather than the point of the twin.
	AttrActionStepTexts = "action_step_texts"
	// AttrImpactedResourceCount is len(impactedResources) — the per-recommendation
	// twin's copy of the count the bounded impacted-resources gauge aggregates by
	// type. Emitted only when the navigation property was present on the record
	// (an omitted relationship omits this attribute, mirroring the gauge's
	// no-series-when-omitted rule — #315).
	AttrImpactedResourceCount = "impacted_resource_count"
)
