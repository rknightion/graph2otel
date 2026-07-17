// Package productstatus is the ONE canonical vocabulary for Microsoft's
// windowsDefenderProductStatus enum: the snake_case attribute values graph2otel
// emits for it, and nothing else.
//
// # Why this package exists (#156)
//
// The same enum reaches graph2otel over two transports that serialize it two
// different ways:
//
//   - the Intune entity endpoint (GET managedDevices/{id}/windowsProtectionState,
//     collected by internal/collectors/intune/malware) sends a COMMA-SEPARATED
//     LIST OF MEMBER NAMES - "noQuickScanHappenedForSpecifiedPeriod,noStatusFlagsSet";
//   - the DefenderAgents export report (collected by
//     internal/collectors/intune/defenderreport) sends an INTEGER BITMASK -
//     524416.
//
// Those are genuinely different wire formats, so each collector keeps its own
// decoder - a comma-split against a name-keyed table on one side, a bit-walk
// against a bit-keyed table on the other. What they must NOT keep separately is
// the vocabulary they decode INTO. A device's Defender state must not produce a
// different label value depending on which transport observed it, or
// intune.defender.product_status{status} and
// intune.defender_agents.product_status{status} stop being queryable with one
// vocabulary and an operator's filter silently matches one transport's devices
// and not the other's.
//
// That is not hypothetical. Bit 24 had already drifted: the entity side rendered
// it "windows_s_mode_signatures_in_use_on_non_win10s_install" while the export
// side rendered it "..._non_win10_s_install" - one flag, two labels, no gate. It
// was found by hand, not by a test.
//
// So the values live here as constants and NOWHERE else. Neither collector
// spells a productStatus value; both reference these identifiers. Two spellings
// of one flag cannot be written, because there is only one place a spelling can
// be written. That is the whole point of this package: drift is not detected
// here, it is unrepresentable.
//
// # Scope: values only
//
// This package deliberately holds NO decode and NO wire knowledge - no member
// names, no bit positions, no parsing. Those are per-transport facts and stay
// with the transport that observes them (and carry that transport's own
// evidence class). This package is the vocabulary, not the reader of it.
//
// Each collector's transport-specific values stay with that collector too: the
// entity side names an unrecognized flag unknown_<name>, the export side names
// an unrecognized bit unknown_bit_<n>. Those are decode-miss diagnostics rather
// than enum members, and they are shaped by the wire format, so they are not
// shared vocabulary.
//
// # Evidence
//
// Per the project's evidence-class rule, the flags below are NOT equally
// established, and the difference is load-bearing:
//
//   - NoStatusFlagsSet and NoQuickScanHappenedForSpecifiedPeriod are
//     live-measured (2026-07-17, #142/#150/#156), and by BOTH transports
//     independently: the same three m7kni devices report "noStatusFlagsSet" /
//     "noQuickScanHappenedForSpecifiedPeriod,noStatusFlagsSet" through the
//     entity endpoint and export 524288 (2^19) / 524416 (2^19 + 2^7) through
//     DefenderAgents, agreeing device-for-device.
//   - Every OTHER flag here is docs-only, from Microsoft's
//     windowsDefenderProductStatus reference
//     (https://learn.microsoft.com/en-us/graph/api/resources/intune-devices-windowsdefenderproductstatus).
//     Microsoft's published tables have been wrong or incomplete on essentially
//     every load-bearing detail on this project (#100, #142, #150), so treat an
//     unobserved flag as a hypothesis. Both decoders name what they cannot
//     recognize rather than discarding it, so a wrong or missing entry surfaces
//     as unknown_* instead of vanishing.
//
// Sharing the vocabulary does not upgrade docs-only to live-measured. It only
// guarantees that a docs-only flag is wrong in exactly one way on both
// transports rather than two different ways.
package productstatus

// The flag values. Each is one member of windowsDefenderProductStatus rendered
// as snake_case. Ordered by the bit position Microsoft documents (0..24), which
// is the order Flags below preserves - it is a convenient reading order, not a
// wire fact this package knows how to use.
//
// Both flags marked live-measured are corroborated across both transports; every
// other value here is docs-only. See the package doc.
const (
	ServiceNotRunning                      = "service_not_running"
	ServiceStartedWithoutMalwareProtection = "service_started_without_malware_protection"
	PendingFullScanDueToThreatAction       = "pending_full_scan_due_to_threat_action"
	PendingRebootDueToThreatAction         = "pending_reboot_due_to_threat_action"
	PendingManualStepsDueToThreatAction    = "pending_manual_steps_due_to_threat_action"
	AVSignaturesOutOfDate                  = "av_signatures_out_of_date"
	ASSignaturesOutOfDate                  = "as_signatures_out_of_date"
	// NoQuickScanHappenedForSpecifiedPeriod is live-measured (2026-07-17, #156):
	// entity "noQuickScanHappenedForSpecifiedPeriod" on DESKTOP-CB3D9AB, and the
	// 2^7 term of that same device's exported 524416.
	NoQuickScanHappenedForSpecifiedPeriod = "no_quick_scan_happened_for_specified_period"
	NoFullScanHappenedForSpecifiedPeriod  = "no_full_scan_happened_for_specified_period"
	SystemInitiatedScanInProgress         = "system_initiated_scan_in_progress"
	SystemInitiatedCleanInProgress        = "system_initiated_clean_in_progress"
	SamplesPendingSubmission              = "samples_pending_submission"
	ProductRunningInEvaluationMode        = "product_running_in_evaluation_mode"
	ProductRunningInNonGenuineMode        = "product_running_in_non_genuine_mode"
	ProductExpired                        = "product_expired"
	OfflineScanRequired                   = "offline_scan_required"
	ServiceShutdownAsPartOfSystemShutdown = "service_shutdown_as_part_of_system_shutdown"
	ThreatRemediationFailedCritically     = "threat_remediation_failed_critically"
	ThreatRemediationFailedNonCritically  = "threat_remediation_failed_non_critically"
	// NoStatusFlagsSet is live-measured (2026-07-17, #156): entity
	// "noStatusFlagsSet" on all three m7kni Windows devices, and the 2^19 term of
	// their exported 524288 / 524416. It means "Defender reported, and reported
	// nothing wrong" - it is NOT the same thing as NoStatus.
	NoStatusFlagsSet                                = "no_status_flags_set"
	PlatformOutOfDate                               = "platform_out_of_date"
	PlatformUpdateInProgress                        = "platform_update_in_progress"
	PlatformAboutToBeOutdated                       = "platform_about_to_be_outdated"
	SignatureOrPlatformEndOfLifeIsPastOrIsImpending = "signature_or_platform_end_of_life_is_past_or_is_impending"
	// WindowsSModeSignaturesInUseOnNonWin10SInstall is the flag that proved this
	// package necessary (#156). The two transports rendered it two different ways
	// - the entity side "..._non_win10s_install", the export side
	// "..._non_win10_s_install" - so one device setting it would have produced two
	// different label values depending on which transport saw it. #142's claim
	// that its bit values were "carried over verbatim" from the name-keyed map is
	// FALSE (verified against git history, 2026-07-17): #142 introduced the slip.
	//
	// The export spelling won: NonWin10SInstall snake_cases to non_win10_s_install
	// because the trailing S is "Windows 10 S mode", a separate word. Neither
	// spelling was ever live-observed - this flag has never been seen on the wire
	// (docs-only) - so nothing is known to have queried the retired one.
	WindowsSModeSignaturesInUseOnNonWin10SInstall = "windows_s_mode_signatures_in_use_on_non_win10_s_install"
)

// The two values that are not flags. Both transports need them, so they are
// canonical here too, but neither is a member of Flags.
const (
	// NoStatus is windowsDefenderProductStatus's `noStatus` member, whose value
	// is 0 - the absence of every flag. It is NOT NoStatusFlagsSet: that is a
	// real set bit (2^19) meaning Defender reported and found nothing wrong,
	// whereas NoStatus is Defender reporting no flags at all, which is evidence
	// of nothing. Each transport reaches it its own way (the entity endpoint
	// sends the literal name "noStatus"; the export sends the integer 0, which a
	// bit-walk would otherwise render as nothing at all), which is exactly why
	// the value they land on has to be one value.
	NoStatus = "no_status"
	// Unknown labels an ABSENT or unparseable productStatus - no flag was
	// reported. Distinct from NoStatus, which is a real reported value, and
	// distinct from a flag that was reported but not recognized (that decodes to
	// each transport's own unknown_* diagnostic, which is not shared vocabulary).
	Unknown = "unknown"
)

// Flags is the canonical set of every windowsDefenderProductStatus FLAG value -
// all 25 members except `noStatus` (value 0, the absence of flags, which is
// NoStatus above and is not a flag).
//
// It exists so each transport's decode table can be checked against the
// vocabulary as a WHOLE rather than value by value: a table that is missing a
// flag, or that has invented one, is as broken as a table that misspells one,
// and neither transport's own tests can see the other's table. See
// TestVocabularyIsExactlyTheDocumentedFlagSet in each collector.
//
// Order is Microsoft's documented bit order (0..24). Nothing depends on it -
// both consumers compare as a set - but it keeps this list diffable against
// Microsoft's reference table.
var Flags = []string{
	ServiceNotRunning,
	ServiceStartedWithoutMalwareProtection,
	PendingFullScanDueToThreatAction,
	PendingRebootDueToThreatAction,
	PendingManualStepsDueToThreatAction,
	AVSignaturesOutOfDate,
	ASSignaturesOutOfDate,
	NoQuickScanHappenedForSpecifiedPeriod,
	NoFullScanHappenedForSpecifiedPeriod,
	SystemInitiatedScanInProgress,
	SystemInitiatedCleanInProgress,
	SamplesPendingSubmission,
	ProductRunningInEvaluationMode,
	ProductRunningInNonGenuineMode,
	ProductExpired,
	OfflineScanRequired,
	ServiceShutdownAsPartOfSystemShutdown,
	ThreatRemediationFailedCritically,
	ThreatRemediationFailedNonCritically,
	NoStatusFlagsSet,
	PlatformOutOfDate,
	PlatformUpdateInProgress,
	PlatformAboutToBeOutdated,
	SignatureOrPlatformEndOfLifeIsPastOrIsImpending,
	WindowsSModeSignaturesInUseOnNonWin10SInstall,
}

// FlagSet returns Flags as a set, for callers checking membership or comparing a
// decode table against the vocabulary. A fresh map each call - callers are test
// helpers and small decode-table builders, and a shared mutable map is how a
// "canonical" set stops being canonical.
func FlagSet() map[string]bool {
	set := make(map[string]bool, len(Flags))
	for _, f := range Flags {
		set[f] = true
	}
	return set
}
