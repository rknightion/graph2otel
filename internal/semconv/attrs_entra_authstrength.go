package semconv

// Attribute keys introduced by entra.auth_strength's log twin (#322): one
// entra.auth_strength_policy event per policy returned by
// GET /policies/authenticationStrengthPolicies (live-measured 2026-07-28, 3
// built-in policies, no @odata.nextLink).
//
// REUSED rather than re-coined (the registry's no-duplicate-values gate would
// fail a second constant carrying any of these strings): AttrId
// (attrs_shared.go, the policy's own id), AttrDisplayName (attrs_shared.go),
// AttrDescription (attrs_purview.go), AttrCreatedDateTime (attrs_entra.go,
// the policy's createdDateTime), and AttrPolicyType (attrs_intune.go, the
// policy's policyType — also this collector's bounded metric label).
//
// AttrModifiedDateTime is coined rather than reusing AttrLastModifiedDateTime
// (attrs_m365.go, "last_modified_date_time") because the wire field here is
// literally `modifiedDateTime`, not `lastModifiedDateTime` — a different
// Graph resource shape, not the same field under a different collector.
const (
	// AttrModifiedDateTime is the policy's modifiedDateTime.
	AttrModifiedDateTime = "modified_date_time"

	// AttrRequirementsSatisfied is the policy's requirementsSatisfied (e.g.
	// "mfa") — this collector's other bounded metric label alongside
	// AttrPolicyType. Left UNWATCHED by wirecheck (see the package doc): only
	// one value has ever been observed on the wire.
	AttrRequirementsSatisfied = "requirements_satisfied"

	// AttrAllowedCombinations is the bounded array of the policy's raw,
	// VERBATIM allowedCombinations strings, capped at maxAllowedCombinations.
	// A comma-joined entry such as "password,microsoftAuthenticatorPush" is
	// ONE array element meaning "both methods together" — it is never split,
	// because splitting a conjunction into two independent methods would
	// silently change what the policy says (see the package doc).
	AttrAllowedCombinations = "allowed_combinations"

	// AttrAllowedCombinationCount is the TRUE (uncapped) count of
	// allowedCombinations entries, so a capped array never silently
	// understates how many combinations the policy actually allows.
	AttrAllowedCombinationCount = "allowed_combination_count"

	// AttrAllowedCombinationsTruncated reports whether AttrAllowedCombinations
	// was cut at maxAllowedCombinations.
	AttrAllowedCombinationsTruncated = "allowed_combinations_truncated"

	// AttrCombinationConfigurationCount is the count of the policy's
	// combinationConfigurations entries. COUNT ONLY: this array is empty on
	// every live-measured policy (2026-07-28), so no field mapper is written
	// against unseen data — the same evidence-gated discipline
	// entra/tenantpolicy applies to its own empty scoped-policy collections
	// (#142/#165). See the package doc for the unblock condition.
	AttrCombinationConfigurationCount = "combination_configuration_count"
)
