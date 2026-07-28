package semconv

// entra.access_reviews instance + decision attributes (#319) — the residual
// #260 deliberately left open after proving the inline `instances` array empty.
//
// Reused where a key already exists: AttrStatus (the instance status, also a
// metric label), AttrStartDateTime / AttrEndDateTime (the instance window),
// AttrDisplayName, AttrPrincipalId / AttrPrincipalType /
// AttrUserPrincipalName (the reviewed principal), AttrResourceDisplayName /
// AttrResourceType (the reviewed resource), AttrRecommendation (Graph's own
// Approve/Deny hint, also a metric label), AttrJustification, and
// AttrReviewerCount-style counts already on the definition twin.
//
// # The zero-GUID sentinel, live-measured 2026-07-28
//
// An undecided decision arrives with a FULLY POPULATED `reviewedBy` object
// whose id is `00000000-0000-0000-0000-000000000000` and whose displayName and
// userPrincipalName are empty strings — not a null object, and not an absent
// key. The same is true of `appliedBy`. Emitting it verbatim would publish a
// reviewer that does not exist, and a LogQL `count by (reviewed_by_id)` would
// show a phantom reviewer holding every pending decision on the tenant.
//
// It is the same class of trap as the `0001-01-01T00:00:00Z` DateTime.MinValue
// sentinel already recorded on #323 and #350, and it must be handled the same
// way: recognized and treated as ABSENT, never mapped through. `reviewedDateTime`
// and `appliedDateTime` are genuinely `null` on the same records, and
// `principal.lastUserSignInDateTime` is an EMPTY STRING rather than null — three
// different spellings of "no value" on one record.
const (
	// Identity of the decision and its parents. All twin-only: a decision id or
	// an instance id keyed as a metric label would grow with review volume
	// (#112). The bounded metric dimensions are AttrDecision, AttrAppliedResult,
	// AttrRecommendation and AttrStatus, all closed enums fixed by Graph.
	AttrDecisionId   = "decision_id"
	AttrInstanceId   = "instance_id"
	AttrDefinitionId = "definition_id"

	// AttrDecision is the reviewer's verdict (NotReviewed, Approve, Deny,
	// DontKnow, NotNotified) and AttrAppliedResult is what happened to it
	// afterwards (New, AppliedSuccessfully, AppliedWithUnknownFailure, …). They
	// are different questions and conflating them is the easy mistake: a
	// decision can be Deny and still never have been applied, which is exactly
	// the "the review ran and changed nothing" case this issue exists to
	// surface.
	AttrDecision      = "decision"
	AttrAppliedResult = "applied_result"

	// Timestamps, twin-only. Both are null on an undecided decision and are
	// omitted rather than zero-stamped.
	AttrReviewedDateTime = "reviewed_date_time"
	AttrAppliedDateTime  = "applied_date_time"

	// Who acted. Omitted entirely when the wire carries the zero-GUID sentinel
	// described above.
	AttrReviewedById          = "reviewed_by_id"
	AttrReviewedByDisplayName = "reviewed_by_display_name"
	AttrAppliedById           = "applied_by_id"

	// Graph's own self-links to the reviewed principal and resource. Kept
	// because they carry the API VERSION the review was scoped against
	// (`/beta/roleManagement/...` on a v1.0 decision, live-observed), which the
	// separate id fields lose.
	AttrPrincipalLink = "principal_link"
	AttrResourceLink  = "resource_link"

	// AttrLastUserSignInDateTime is the reviewed principal's last sign-in as the
	// review sees it — the single most useful field for deciding a stale-access
	// review. It arrives as an EMPTY STRING when unknown, never null, so an
	// empty check is required and a bare presence check is not enough.
	AttrLastUserSignInDateTime = "last_user_sign_in_date_time"
)
