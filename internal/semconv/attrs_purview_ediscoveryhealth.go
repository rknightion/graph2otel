package semconv

// Attribute keys for the Purview eDiscovery case-health collector (#323): the
// legal holds, per-hold data sources, and long-running case operations hanging
// off each eDiscovery case that internal/collectors/purview/ediscoverycases
// counts but never inspects.
//
// Reused where a key already exists: AttrId / AttrDisplayName / AttrStatus /
// AttrUserPrincipalName (attrs_shared.go), AttrDescription (attrs_purview.go),
// AttrCreatedDateTime / AttrLastModifiedDateTime (attrs_entra.go /
// attrs_m365.go), AttrEnabled (attrs_intune.go), AttrAction (attrs_defender.go).
// Only genuinely new keys are declared below.
//
// # Every key here is log-twin only except the four named metric labels
//
// The gauges carry exactly AttrEnabled, AttrHasErrors, AttrHoldStatus,
// AttrSourceType and AttrAction/AttrStatus — all bounded by a closed EDM enum or
// a boolean. Everything else on this file is per-entity (#112): case ids, hold
// ids, source ids, display names, mail addresses. A tenant with a thousand cases
// must not produce a thousand series.
//
// # Wire traps this file exists to document [live-measured 2026-07-28, #323]
//
// Each of these was measured on m7kni as graph2otel-poller against three real
// eDiscovery Premium cases. They are recorded here rather than only in the
// collector because each one invalidates the obvious mapping.
//
// ## legalHold.status is null on every healthy hold — do NOT bucket on it
//
// #323's body proposed counting "disabled/erroring holds" by the hold's own
// `status` field. On the wire, every healthy hold carries:
//
//	"isEnabled": true, "errors": [], "status": null
//
// `status` is declared in the EDM but is null in practice. A gauge keyed on it
// buckets a healthy tenant entirely into "unknown" and reports clean success
// over nothing — the "a green tick is not evidence of data" trap. The health
// gauge therefore keys on AttrEnabled (from `isEnabled`) and AttrHasErrors
// (from `len(errors) > 0`), both of which ARE populated. AttrHoldState carries
// the raw `status` into the log twin so a future non-null value is visible
// without the metric depending on it.
//
// ## userSource.id is NOT always a GUID
//
// An inactive mailbox on case `26179e8a` returned
//
//	"id": "00000000-0000-0000-0000-000000000000.vmuser@m7kni.io"
//
// — the .NET zero GUID concatenated with the address — sitting beside a normal
// GUID row in the SAME collection on the SAME hold. Anything that treats a
// source id as a GUID breaks, and the value is identity-bearing, so it is log
// twin only.
//
// ## createdBy.user uses three different conventions across sibling routes
//
//	legalHolds          {"id": "Rob Knight", "displayName": null}   <- name in the ID field
//	operations/searches {"id": "<guid>", "displayName": "Rob Knight", "userPrincipalName": "..."}
//	case object/sources {"id": null, "displayName": "Rob Knight"}
//
// One case, one poll, three shapes. AttrCreatedByDisplayName is therefore
// populated by a helper that prefers `displayName` and falls back to `id` ONLY
// when `displayName` is empty and `id` does not parse as a GUID. There is
// deliberately no created_by_id attribute: on the legalHolds route it would
// publish a person's name into an id-shaped key.
//
// ## The .NET DateTime.MinValue sentinel is live on siteSource.site
//
//	"site": {"createdDateTime": "0001-01-01T00:00:00Z"}
//
// Same trap the case object carried (#102). It PARSES, so it sails past the
// emitter's non-zero-timestamp check and would publish a site as created in year
// 1. Every date on every child route goes through realDateTime.
//
// ## unifiedGroupSources 400s on a legal hold
//
// The v1.0 EDM declares unifiedGroupSources only on ediscoveryCustodian, not on
// the hold. Fetching it per-hold is a guaranteed 400 — it is not fetched.
//
// # There is deliberately no custodian field mapper — a closed question
//
// GET .../ediscoveryCases/{id}/custodians returns 200 with zero rows on every
// case, and that is not a tenant gap that a maintainer action can close. The
// unified eDiscovery experience (classic retired 2025-08-31) demoted custodians
// from the primary organizing unit to cases and renamed them "People" in the
// portal. People data sources attached to a hold policy materialize as
// legalHolds/{id}/userSources and siteSources — verified across three attempts
// on two cases, each confirmed by `operations` gaining a holdPolicySync while
// `custodians` stayed at zero. The custodian COUNT is still emitted (it is
// honestly zero), but no ediscoveryCustodian field mapper is written, because
// there is no live shape to write it against and no action that would produce
// one. Same disposition as entra/tenantpolicy.
//
// If Microsoft ever repopulates the collection, the source-level mapper already
// covers its children: the EDM declares ediscoveryCustodian/userSources and
// /siteSources as Collection(self.userSource) and Collection(self.siteSource) —
// the identical types sampled live from a hold.
const (
	// AttrHasErrors is a metric label: whether a legal hold's `errors` array is
	// non-empty. Boolean-valued ("true"/"false"), so the gauge stays bounded at
	// two series per enabled state. It replaces the null `status` field the
	// issue proposed bucketing on — see the package doc.
	AttrHasErrors = "has_errors"

	// AttrHoldState is the legal hold's raw `status` field, carried into the log
	// twin ONLY. It is null on every hold observed live; it exists here so a
	// future non-null value shows up in logs without any metric depending on a
	// field that is currently always absent.
	AttrHoldState = "hold_state"

	// AttrHoldStatus is a metric label: the dataSourceHoldStatus of a hold's
	// data source (notApplied / applied / applying / removing / partial).
	// Bounded by the EDM enum. Observed live: "applied".
	AttrHoldStatus = "hold_status"

	// AttrSourceType is a metric label distinguishing a hold's userSources from
	// its siteSources. Two values plus the unknown bucket — this is the
	// COLLECTION the row came from, not the wire's `sourceType` enum, which does
	// not appear on these records.
	AttrSourceType = "source_type"

	// AttrIncludedSources is the userSource `includedSources` field ("mailbox").
	// Log twin only: it is a flags-style value whose full value set has not been
	// observed, so it must not key a metric label.
	AttrIncludedSources = "included_sources"

	// AttrHoldId is the parent legal hold's id, stamped on every source log so a
	// source can be traced back to its hold. Per-entity — log twin only.
	AttrHoldId = "hold_id"

	// AttrCaseId / AttrCaseDisplayName tie every child record back to its case.
	// Per-entity — log twin only. A case_id metric label would grow the series
	// count with the tenant's case count, which is exactly #112's bug.
	AttrCaseId          = "case_id"
	AttrCaseDisplayName = "case_display_name"

	// AttrCreatedByDisplayName is the human who created a hold or operation,
	// resolved across the three inconsistent createdBy shapes described in the
	// package doc. Null for system-generated operations (holdPolicySync), so it
	// is frequently absent by design. There is deliberately no created_by_id.
	AttrCreatedByDisplayName = "created_by_display_name"

	// AttrCompletedDateTime is a caseOperation's completedDateTime. Absent while
	// an operation is still running.
	AttrCompletedDateTime = "completed_date_time"

	// AttrPercentProgress is a caseOperation's percentProgress (0-100). Log twin
	// only — it is a per-operation instantaneous value, not a tenant aggregate.
	AttrPercentProgress = "percent_progress"

	// AttrSiteWebUrl is a siteSource's site.webUrl (a OneDrive or SharePoint
	// URL). Per-entity and unbounded — log twin only.
	AttrSiteWebUrl = "site_web_url"

	// AttrErrorCount is the number of entries in a legal hold's `errors` array,
	// carried into the log twin alongside the boolean AttrHasErrors metric label
	// so an operator can see how many without the metric growing a series per
	// count.
	AttrErrorCount = "error_count"
)
