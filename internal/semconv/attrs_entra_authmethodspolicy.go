package semconv

// Attribute keys introduced by entra.auth_methods_policy's log twins (#317):
// one entra.auth_methods_policy event for the tenant-wide singleton and one
// entra.auth_method_configuration event per returned
// authenticationMethodConfigurations entry. Both events are LOG-ONLY — this
// collector's two gauges (entra.auth_methods_policy.method.enabled,
// entra.auth_methods_policy.legacy_enabled.total) are unchanged by #317 and
// none of these keys become metric labels.
//
// REUSED rather than re-coined (the registry's no-duplicate-values gate would
// fail a second constant carrying any of these strings): AttrId
// (attrs_shared.go, the policy id / configuration id), AttrState
// (attrs_shared.go, the configuration's or the registration campaign's
// state), AttrDisplayName / AttrDescription (attrs_shared.go /
// attrs_purview.go, the policy's own display name/description),
// AttrLastModifiedDateTime (attrs_m365.go, the policy's
// lastModifiedDateTime), AttrOdataType (attrs_intune.go, the configuration's
// full "#microsoft.graph.xAuthenticationMethodConfiguration" discriminator),
// and AttrMethod (attrs_entra.go, a normalized short method name — reused
// here as a log attribute on a KNOWN configuration's twin, distinct from its
// existing use as this same collector's metric label).
//
// # The unknown-subtype rule this file exists to support
//
// Per the #317 decision-gate comment (binding, 2026-07-28): a configuration
// whose @odata.type is not one of the seven observed on the live-measured
// 2026-07-17 fixture (#165) — fido2, microsoftAuthenticator, sms, voice,
// x509Certificate, verifiableCredentials, qrCodePin — emits ONLY AttrId,
// AttrState and AttrOdataType. None of the constants below (including the
// include/exclude target arrays, which ARE common to every configuration
// type per the Graph base resource) are emitted for an unrecognized subtype.
// Temporary Access Pass, hardware/software OATH, email and custom/external
// configurations therefore arrive deliberately under-described until someone
// captures them and extends the known-subtype set with evidence — the same
// discipline CLAUDE.md's wire-value-watching section applies to metric
// labels, applied here to which fields a log twin is allowed to claim.
const (
	// AttrPolicyVersion is the policy event's policyVersion (e.g. "1.5").
	AttrPolicyVersion = "policy_version"

	// AttrPolicyMigrationState is the policy event's policyMigrationState.
	// Observed null on the live tenant (2026-07-28) — SetStr / a nil pointer
	// omits the attribute rather than emitting an empty string for it, so
	// "the wire sent null" and "the field wasn't in the response" are both
	// simply absent, never a fabricated value.
	AttrPolicyMigrationState = "policy_migration_state"

	// AttrIncludeTargetIds / AttrExcludeTargetIds are the bounded arrays of
	// target identifiers the #317 decision requires in place of raw target
	// objects. Used on BOTH events: the policy event's registration campaign
	// (registrationEnforcement.authenticationMethodsRegistrationCampaign)
	// and a known configuration's own includeTargets/excludeTargets. Capped
	// at maxTargetIdentifiers per array — see
	// AttrIncludeTargetsTruncated/AttrExcludeTargetsTruncated for the
	// companion "was this list cut" flags.
	AttrIncludeTargetIds = "include_target_ids"
	AttrExcludeTargetIds = "exclude_target_ids"

	// AttrIncludeTargetCount / AttrExcludeTargetCount are the TRUE (uncapped)
	// counts of targets on the wire, so a capped id array never silently
	// understates how many targets actually exist.
	AttrIncludeTargetCount = "include_target_count"
	AttrExcludeTargetCount = "exclude_target_count"

	// AttrIncludeTargetsTruncated / AttrExcludeTargetsTruncated report
	// whether the corresponding id array above was cut at the cap — the
	// "capped, and say so" half of CLAUDE.md's bounded-array rule.
	AttrIncludeTargetsTruncated = "include_targets_truncated"
	AttrExcludeTargetsTruncated = "exclude_targets_truncated"

	// AttrSnoozeDurationInDays is the registration campaign's
	// snoozeDurationInDays, on the policy event only.
	AttrSnoozeDurationInDays = "snooze_duration_in_days"

	// Fido2-specific fields, observed live 2026-07-28 on the Fido2
	// configuration only (see the collector's mapper for exactly which
	// @odata.type each applies to).
	AttrIsSelfServiceRegistrationAllowed = "is_self_service_registration_allowed"
	AttrIsAttestationEnforced            = "is_attestation_enforced"
	AttrDefaultPasskeyProfileId          = "default_passkey_profile_id"
	AttrKeyRestrictionEnforced           = "key_restriction_enforced"
	AttrKeyRestrictionEnforcementType    = "key_restriction_enforcement_type"
	// AttrKeyRestrictionAaguids is a bounded array of the Fido2
	// configuration's keyRestrictions.aaGuids (hardware authenticator model
	// identifiers, not secrets) capped at maxTargetIdentifiers, with
	// AttrKeyRestrictionAaguidsTruncated recording whether it was cut.
	AttrKeyRestrictionAaguids          = "key_restriction_aaguids"
	AttrKeyRestrictionAaguidsTruncated = "key_restriction_aaguids_truncated"
	// AttrPasskeyProfileIds is a bounded array of the Fido2 configuration's
	// top-level passkeyProfiles[].id — identifiers only, never the nested
	// attestationEnforcement/keyRestrictions each profile carries, per the
	// no-raw-JSON / fixed-typed-schema rule.
	AttrPasskeyProfileIds          = "passkey_profile_ids"
	AttrPasskeyProfileIdsTruncated = "passkey_profile_ids_truncated"

	// AttrIsSoftwareOathEnabled is the MicrosoftAuthenticator configuration's
	// isSoftwareOathEnabled.
	AttrIsSoftwareOathEnabled = "is_software_oath_enabled"

	// AttrIsOfficePhoneAllowed is the Voice configuration's
	// isOfficePhoneAllowed.
	AttrIsOfficePhoneAllowed = "is_office_phone_allowed"

	// AttrPinLength / AttrStandardQrCodeLifetimeInDays are the QRCodePin
	// configuration's pinLength and standardQRCodeLifetimeInDays.
	AttrPinLength                    = "pin_length"
	AttrStandardQrCodeLifetimeInDays = "standard_qr_code_lifetime_in_days"
)
