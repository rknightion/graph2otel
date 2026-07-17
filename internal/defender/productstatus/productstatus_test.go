package productstatus

import "testing"

// TestFlagsIsTheWholeEnumAndNothingElse pins the size of the vocabulary.
//
// Microsoft documents windowsDefenderProductStatus with 26 members: `noStatus`
// (value 0) plus 25 flag bits (2^0..2^24). NoStatus is not a flag, so Flags
// holds the other 25. A count is a weak check on its own, but it is the one that
// fires when a flag is dropped during an edit - the set-equality tests in each
// collector would then agree with each other on a vocabulary that is quietly
// missing a member.
func TestFlagsIsTheWholeEnumAndNothingElse(t *testing.T) {
	const documentedFlags = 25
	if len(Flags) != documentedFlags {
		t.Errorf("len(Flags) = %d, want %d (windowsDefenderProductStatus documents 25 flag bits, 2^0..2^24, plus the non-flag noStatus)", len(Flags), documentedFlags)
	}
}

// TestNoDuplicateFlags catches the copy-paste failure this file's shape invites:
// two constants rendering to the same string would make one enum member
// unrepresentable, and FlagSet would silently be smaller than Flags.
func TestNoDuplicateFlags(t *testing.T) {
	seen := map[string]bool{}
	for _, f := range Flags {
		if seen[f] {
			t.Errorf("Flags contains %q twice - two enum members cannot share one value", f)
		}
		seen[f] = true
	}
	if len(FlagSet()) != len(Flags) {
		t.Errorf("len(FlagSet()) = %d, len(Flags) = %d - they must agree", len(FlagSet()), len(Flags))
	}
}

// TestValuesAreSnakeCase pins the house rendering. Every value is an attribute
// value on a metric label and a log attribute, so a stray capital or hyphen
// would be a queryable difference from every sibling value.
func TestValuesAreSnakeCase(t *testing.T) {
	all := append(append([]string{}, Flags...), NoStatus, Unknown)
	for _, v := range all {
		if v == "" {
			t.Error("empty value in the vocabulary")
			continue
		}
		for _, r := range v {
			if (r < 'a' || r > 'z') && (r < '0' || r > '9') && r != '_' {
				t.Errorf("%q is not snake_case (bad rune %q)", v, r)
			}
		}
	}
}

// TestNoStatusIsNotNoStatusFlagsSet pins the distinction the export transport
// special-cases 0 for and the entity transport carries a literal name for. They
// are opposite facts - "Defender reported nothing at all" vs "Defender reported,
// and reported nothing wrong" - and collapsing them would make a silent agent
// look healthy.
func TestNoStatusIsNotNoStatusFlagsSet(t *testing.T) {
	if NoStatus == NoStatusFlagsSet {
		t.Fatal("NoStatus and NoStatusFlagsSet must be distinct values")
	}
	if FlagSet()[NoStatus] {
		t.Errorf("NoStatus (%q) must not be in Flags - it is the enum's 0 member, not a flag bit", NoStatus)
	}
	if !FlagSet()[NoStatusFlagsSet] {
		t.Errorf("NoStatusFlagsSet (%q) must be in Flags - it is bit 19, live-measured on both transports", NoStatusFlagsSet)
	}
}

// TestBit24SpellingIsTheConvergedOne is the #156 history case, kept explicit.
//
// This flag is why this package exists. The entity transport rendered it
// "windows_s_mode_signatures_in_use_on_non_win10s_install" and the export
// transport "..._non_win10_s_install" - one enum member, two label values,
// shipped, found by hand. The export spelling won (the trailing S of
// NonWin10SInstall is "Windows 10 S mode", a separate word).
//
// The set-equality tests in the two collectors are what make that class of
// divergence unrepresentable now. This test does something narrower and
// deliberate: it pins the surviving spelling, so the retired one cannot come
// back as a "tidy-up" of an identifier that reads oddly. Neither spelling was
// ever live-observed (docs-only), so nothing external is known to depend on it -
// which is exactly why it needs a test rather than a bug report to protect it.
func TestBit24SpellingIsTheConvergedOne(t *testing.T) {
	const want = "windows_s_mode_signatures_in_use_on_non_win10_s_install"
	if WindowsSModeSignaturesInUseOnNonWin10SInstall != want {
		t.Errorf("WindowsSModeSignaturesInUseOnNonWin10SInstall = %q, want %q (the spelling #156 converged both transports onto)",
			WindowsSModeSignaturesInUseOnNonWin10SInstall, want)
	}
	const retired = "windows_s_mode_signatures_in_use_on_non_win10s_install"
	if WindowsSModeSignaturesInUseOnNonWin10SInstall == retired {
		t.Error("the pre-#156 entity-transport spelling is back")
	}
}

// TestFlagSetIsNotShared guards the one way a canonical set stops being
// canonical: handing every caller the same mutable map.
func TestFlagSetIsNotShared(t *testing.T) {
	a := FlagSet()
	a["mutated_by_a_caller"] = true
	if FlagSet()["mutated_by_a_caller"] {
		t.Error("FlagSet returns a shared map - one caller's mutation is now everyone's vocabulary")
	}
}
