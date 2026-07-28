package semconv

// Attribute keys introduced by the entra.conditional_access log twins (#318):
// one entra.conditional_access_policy record per returned CA policy and one
// entra.named_location record per returned named location, added alongside
// the collector's existing bounded aggregate gauges (never replacing them —
// see CLAUDE.md's "metrics carry aggregates, logs carry entities" rule).
//
// id, display_name, state, type, is_trusted, created_date_time and
// last_modified_date_time are REUSED from attrs_shared.go / attrs_entra.go /
// attrs_m365.go rather than re-coined — the registry's no-duplicate-values
// gate would fail a second constant carrying any of those strings.
//
// Every key below is LOG-ONLY: this collector's two metrics stay exactly as
// they are (bounded by state / type+is_trusted), and none of these new
// attributes are ever added to a GaugePoint.
const (
	// AttrTemplateId is a conditionalAccessPolicy's templateId — nil on the
	// wire for a hand-built policy, a GUID for one created from a Microsoft
	// template. Omitted (via telemetry.SetStr) when empty.
	AttrTemplateId = "template_id"

	// AttrClientAppTypes is conditions.clientAppTypes verbatim — the bounded
	// client-application-type enum Conditional Access evaluates against
	// (browser, mobileAppsAndDesktopClients, exchangeActiveSync, other, all),
	// never restricted by this mapper. Omitted when empty.
	AttrClientAppTypes = "client_app_types"

	// AttrSignInRiskLevels and AttrUserRiskLevels are conditions.signInRiskLevels
	// / conditions.userRiskLevels: the Identity Protection risk levels this
	// policy's condition matches against (distinct from entra/risk's CURRENT
	// risk state — these are policy CONFIGURATION, not a live assessment).
	// Omitted when empty.
	AttrSignInRiskLevels = "sign_in_risk_levels"
	AttrUserRiskLevels   = "user_risk_levels"

	// AttrIncludeUsers/AttrExcludeUsers/AttrIncludeGroups/AttrExcludeGroups/
	// AttrIncludeRoles/AttrExcludeRoles are conditions.users' six target-id
	// arrays — flat lists of object ids (or the literal "All"/"None"/
	// "GuestsOrExternalUsers") on the ONE policy record, not a per-target
	// child record (the maintainer-rejected normalised alternative, #318).
	// Each is bounded by maxArrayAttr and omitted when empty.
	AttrIncludeUsers  = "include_users"
	AttrExcludeUsers  = "exclude_users"
	AttrIncludeGroups = "include_groups"
	AttrExcludeGroups = "exclude_groups"
	AttrIncludeRoles  = "include_roles"
	AttrExcludeRoles  = "exclude_roles"

	// AttrIncludeLocations/AttrExcludeLocations are conditions.locations'
	// target-id arrays (named-location ids, or "All"/"AllTrusted"), the same
	// flat-array-not-child-record shape as the six above. A value here is a
	// natural join key onto the entra.named_location twin's id attribute.
	// Bounded and omitted when empty.
	AttrIncludeLocations = "include_locations"
	AttrExcludeLocations = "exclude_locations"

	// AttrHasGrantControls and AttrHasSessionControls are ALWAYS emitted
	// (true or false, never omitted) — grantControls/sessionControls being
	// null is a real configured fact (a policy can report-only with no grant
	// requirement at all), and collapsing "null" and "present but empty" into
	// one omitted attribute would erase that distinction. See
	// AttrGrantControlsOperator/AttrBuiltInControls below for what only
	// appears when true.
	AttrHasGrantControls   = "has_grant_controls"
	AttrHasSessionControls = "has_session_controls"

	// AttrGrantControlsOperator is grantControls.operator ("AND"/"OR"),
	// emitted only when grantControls is non-null. Omitted when empty.
	AttrGrantControlsOperator = "grant_controls_operator"

	// AttrBuiltInControls is grantControls.builtInControls, emitted only when
	// grantControls is non-null. Omitted when empty (a policy can require
	// custom/passwordless-strength controls with no builtInControls at all).
	AttrBuiltInControls = "built_in_controls"

	// AttrAuthenticationStrengthDisplayName is
	// grantControls.authenticationStrength.displayName — the one
	// human-readable field pulled from that nested object; the rest of it
	// (its own id/description/allowedCombinations) is left unmapped rather
	// than growing this twin into a second child record. Omitted when the
	// nested object is null or its displayName is empty.
	AttrAuthenticationStrengthDisplayName = "authentication_strength_display_name"

	// AttrArraysTruncated is true when ANY bounded array on this log record
	// (see maxArrayAttr in conditionalaccess.go) was capped this cycle —
	// never emitted false. One flag per record rather than a
	// "<field>_truncated" flag per array: the record already says WHICH
	// arrays are present, so this only needs to say whether the record as a
	// whole lost tail elements.
	AttrArraysTruncated = "arrays_truncated"

	// AttrCountries is a countryNamedLocation's countriesAndRegions (ISO
	// 3166-1 alpha-2 codes, or the sentinel "Unknown"). Omitted when empty
	// (never emitted at all for an ipNamedLocation, which has no such field).
	AttrCountries = "countries"

	// AttrCountryLookupMethod is a countryNamedLocation's countryLookupMethod
	// ("clientIpAddress" or "authenticatorAppGps"). Omitted when empty.
	AttrCountryLookupMethod = "country_lookup_method"

	// AttrIncludeUnknownCountriesAndRegions is a countryNamedLocation's
	// includeUnknownCountriesAndRegions. A POINTER field on the Go side (see
	// namedLocation in conditionalaccess.go): emitted as the native bool only
	// when the wire carried the key at all, never asserted for an
	// ipNamedLocation (which has no such property).
	AttrIncludeUnknownCountriesAndRegions = "include_unknown_countries_and_regions"

	// AttrIPv4CidrRanges and AttrIPv6CidrRanges are an ipNamedLocation's
	// ipRanges, split by their @odata.type discriminator
	// (#microsoft.graph.iPv4CidrRange / #microsoft.graph.iPv6CidrRange) into
	// two typed arrays rather than one mixed list — telling the two apart is
	// part of the signal (#318). Each is bounded and omitted when empty;
	// never emitted at all for a countryNamedLocation.
	AttrIPv4CidrRanges = "ipv4_cidr_ranges"
	AttrIPv6CidrRanges = "ipv6_cidr_ranges"
)
