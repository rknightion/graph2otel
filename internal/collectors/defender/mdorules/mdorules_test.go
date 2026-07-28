package mdorules

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"maps"
	"os"
	"reflect"
	"testing"

	"github.com/rknightion/graph2otel/internal/collectors"
	"github.com/rknightion/graph2otel/internal/semconv"
	"github.com/rknightion/graph2otel/internal/telemetry"
	"github.com/rknightion/graph2otel/internal/telemetrytest"
)

// ruleCmdletSample maps each of the ten rule cmdlets to the verbatim live
// capture that drives it — real m7kni tenant responses read as
// graph2otel-poller over the Exchange Online admin API, 2026-07-28 (#354).
// These are the shape authority for every rule field this collector maps.
// Seven of the ten returned zero rows live (the tenant uses preset security
// policies exclusively) — those fixtures are the verbatim empty envelope, not
// a stand-in.
var ruleCmdletSample = map[string]string{
	"Get-ATPProtectionPolicyRule":      "testdata/atpprotection.json",
	"Get-EOPProtectionPolicyRule":      "testdata/eopprotection.json",
	"Get-ATPBuiltInProtectionRule":     "testdata/atpbuiltin.json",
	"Get-HostedContentFilterRule":      "testdata/hostedcontent.json",
	"Get-MalwareFilterRule":            "testdata/malware.json",
	"Get-AntiPhishRule":                "testdata/antiphish.json",
	"Get-SafeLinksRule":                "testdata/safelinks.json",
	"Get-SafeAttachmentRule":           "testdata/safeattachment.json",
	"Get-TeamsProtectionPolicyRule":    "testdata/teamsprotection.json",
	"Get-HostedOutboundSpamFilterRule": "testdata/hostedoutboundspam.json",
}

// baselinePolicyCmdlets provides the seven Get-*Policy cmdlets the join reads.
// UNLIKE the rule fixtures, these are hand-built (m7kni holds no custom
// policies beyond the presets already named on the live rule captures, and
// defender.mdo_policies's own richer testdata is that package's file, not
// this one's — see the package doc on why this collector re-fetches rather
// than shares). Each entry names exactly the policies the three non-empty
// live rule captures already reference, so the baseline join has zero
// orphans; individual tests override entries to construct an orphan.
func baselinePolicyCmdlets() map[string][]map[string]any {
	return map[string][]map[string]any{
		"Get-HostedContentFilterPolicy": {{"Name": "Standard Preset Security Policy1784144691483"}},
		"Get-MalwareFilterPolicy":       {{"Name": "Standard Preset Security Policy1784144693315"}},
		"Get-AntiPhishPolicy":           {{"Name": "Standard Preset Security Policy1784144689723"}},
		"Get-SafeLinksPolicy": {
			{"Name": "Standard Preset Security Policy1784144696455"},
			{"Name": "Built-In Protection Policy"},
		},
		"Get-SafeAttachmentPolicy": {
			{"Name": "Standard Preset Security Policy1784144694781"},
			{"Name": "Built-In Protection Policy"},
		},
		"Get-AtpPolicyForO365":      {},
		"Get-TeamsProtectionPolicy": {},
	}
}

// loadValue reads a live sample file and returns its "value" array as the
// decoded records the EXOClient.Invoke seam yields.
func loadValue(t *testing.T, path string) []map[string]any {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	var env struct {
		Value []map[string]any `json:"value"`
	}
	if err := json.Unmarshal(b, &env); err != nil {
		t.Fatalf("decode %s: %v", path, err)
	}
	return env.Value
}

// fakeEXO serves canned records per cmdlet and records every Invoke.
type fakeEXO struct {
	byCmdlet map[string][]map[string]any
	errs     map[string]error
	calls    []string
}

func (f *fakeEXO) Invoke(_ context.Context, cmdlet string, _ map[string]any) ([]map[string]any, error) {
	f.calls = append(f.calls, cmdlet)
	if err := f.errs[cmdlet]; err != nil {
		return nil, err
	}
	return f.byCmdlet[cmdlet], nil
}

var _ collectors.EXOClient = (*fakeEXO)(nil)

// liveFake loads all ten live rule samples plus the hand-built baseline policy
// set, so a single Collect drives the richest available fixtures end-to-end.
func liveFake(t *testing.T) *fakeEXO {
	t.Helper()
	by := map[string][]map[string]any{}
	for cmdlet, path := range ruleCmdletSample {
		by[cmdlet] = loadValue(t, path)
	}
	maps.Copy(by, baselinePolicyCmdlets())
	return &fakeEXO{byCmdlet: by}
}

func newCollector(t *testing.T, f *fakeEXO) *Collector {
	t.Helper()
	return New(collectors.EXODeps{
		Client:   f,
		TenantID: "4b8c18bd-2f9f-4227-af55-9f1061cf9c32",
		Logger:   slog.New(slog.DiscardHandler),
	})
}

func collectLive(t *testing.T) *telemetrytest.Recorder {
	t.Helper()
	f := liveFake(t)
	rec := telemetrytest.New()
	if err := newCollector(t, f).Collect(context.Background(), rec.Emitter(), nil); err != nil {
		t.Fatalf("Collect over the live samples: %v", err)
	}
	return rec
}

// TestCollectInvokesSeventeenCmdletsWithNoParams pins the request shape: one
// Invoke per rule cmdlet AND per policy cmdlet, seventeen total, no
// parameters.
func TestCollectInvokesSeventeenCmdletsWithNoParams(t *testing.T) {
	f := liveFake(t)
	rec := telemetrytest.New()
	if err := newCollector(t, f).Collect(context.Background(), rec.Emitter(), nil); err != nil {
		t.Fatalf("Collect: %v", err)
	}
	if len(f.calls) != 17 {
		t.Fatalf("invoked %d cmdlets, want 17 (10 rule + 7 policy), got calls=%v", len(f.calls), f.calls)
	}
	known := map[string]bool{}
	for c := range ruleCmdletSample {
		known[c] = true
	}
	for c := range baselinePolicyCmdlets() {
		known[c] = true
	}
	for _, c := range f.calls {
		if !known[c] {
			t.Errorf("unexpected cmdlet invoked: %q", c)
		}
	}
}

// TestPresetEOPRuleMapsInFull pins the twin against the live EOP preset rule
// capture — every field this collector claims to map, checked against the
// wire's actual values (testdata/eopprotection.json, 2026-07-28).
func TestPresetEOPRuleMapsInFull(t *testing.T) {
	recs := loadValue(t, "testdata/eopprotection.json")
	if len(recs) != 1 {
		t.Fatalf("fixture has %d records, want 1", len(recs))
	}
	rf := ruleFamilies[1] // eop_protection
	if rf.name != "eop_protection" {
		t.Fatalf("ruleFamilies[1] = %q, want eop_protection", rf.name)
	}
	refs := referencedPolicyNames(rf, recs[0])
	ev := ruleTwin(rf.name, refs, recs[0])

	wantStr := map[string]string{
		semconv.AttrRuleFamily:   "eop_protection",
		semconv.AttrRuleName:     "Standard Preset Security Policy",
		semconv.AttrRuleIdentity: "Standard Preset Security Policy",
		semconv.AttrGuid:         "0c13168e-3b97-4e6c-b108-0ddd32197339",
		semconv.AttrState:        "Enabled",
		semconv.AttrRuleVersion:  "14.0.0.0",
		semconv.AttrWhenChanged:  "2026-07-15T19:45:06.0000000+00:00",
	}
	for k, want := range wantStr {
		if got, _ := ev.Attrs[k].(string); got != want {
			t.Errorf("attr %q = %q, want %q", k, got, want)
		}
	}
	if p, ok := ev.Attrs[semconv.AttrPriority].(float64); !ok || p != 0 {
		t.Errorf("priority = %v (ok=%v), want 0", ev.Attrs[semconv.AttrPriority], ok)
	}
	if got := ev.Attrs[semconv.AttrIsValid]; got != "true" {
		t.Errorf("is_valid = %v, want %q (SetBool stores a string)", got, "true")
	}
	wantRefs := []string{
		"Standard Preset Security Policy1784144691483",
		"Standard Preset Security Policy1784144689723",
		"Standard Preset Security Policy1784144693315",
	}
	gotRefs, _ := ev.Attrs[semconv.AttrReferencedPolicies].([]string)
	if !reflect.DeepEqual(gotRefs, wantRefs) {
		t.Errorf("referenced_policies = %#v, want %#v", gotRefs, wantRefs)
	}
	// Three policies referenced -> policy_name must NOT be set (ambiguous).
	if _, present := ev.Attrs[semconv.AttrPolicyName]; present {
		t.Errorf("policy_name must be absent when the rule references %d policies", len(wantRefs))
	}
	// Every recipient condition is NULL on this record -> none of the six
	// attributes may be present.
	for _, cond := range conditions {
		if _, present := ev.Attrs[cond.attrKey]; present {
			t.Errorf("attr %q must be absent (wire value is null)", cond.attrKey)
		}
	}
	if ev.Severity != telemetry.SeverityInfo {
		t.Errorf("severity = %v, want Info (state=Enabled)", ev.Severity)
	}
	if ev.Name != eventRule {
		t.Errorf("event name = %q, want %q", ev.Name, eventRule)
	}
}

// TestCustomRuleCarriesRecipientListsAsStringSlices covers a rule with real
// SentTo/SentToMemberOf/RecipientDomainIs values. HAND-BUILT: m7kni has no
// custom rule of this shape, so this fixture is constructed from the observed
// wire shape (testdata/*.json), not captured.
//
// Asserted directly on the []string in Event.Attrs, never through a
// comma-joined rendering: telemetrytest joins a []string with ",", and a
// rendered-form assertion cannot distinguish ["a,b", "c"] from ["a", "b,c"] —
// exactly the blindness that shipped a prior useless guard. One of the
// addresses below deliberately contains a comma (a display-name-form
// recipient) to prove the []string boundary is real.
func TestCustomRuleCarriesRecipientListsAsStringSlices(t *testing.T) {
	rec := map[string]any{
		"State":                     "Enabled",
		"Priority":                  float64(1),
		"RuleVersion":               "14.0.0.0",
		"Identity":                  "Custom Hosted Content Rule",
		"Name":                      "Custom Hosted Content Rule",
		"Guid":                      "11111111-1111-1111-1111-111111111111",
		"IsValid":                   true,
		"Description":               "Take the following actions:\n\tApply hosted content filter policy \"Custom Policy\".\n",
		"WhenChanged":               "2026-07-20T10:00:00.0000000+00:00",
		"HostedContentFilterPolicy": "Custom Policy",
		"SentTo":                    []any{"alice@m7kni.com", "\"Bob, Team\" <bob@m7kni.com>"},
		"SentToMemberOf":            []any{"Executives@m7kni.com"},
		"RecipientDomainIs":         []any{"m7kni.com"},
	}
	rf := ruleFamilies[3] // hosted_content
	if rf.name != "hosted_content" {
		t.Fatalf("ruleFamilies[3] = %q, want hosted_content", rf.name)
	}
	ev := ruleTwin(rf.name, referencedPolicyNames(rf, rec), rec)

	wantSentTo := []string{"alice@m7kni.com", "\"Bob, Team\" <bob@m7kni.com>"}
	gotSentTo, ok := ev.Attrs[semconv.AttrSentTo].([]string)
	if !ok || !reflect.DeepEqual(gotSentTo, wantSentTo) {
		t.Errorf("sent_to = %#v (ok=%v), want %#v", ev.Attrs[semconv.AttrSentTo], ok, wantSentTo)
	}
	wantMemberOf := []string{"Executives@m7kni.com"}
	gotMemberOf, ok := ev.Attrs[semconv.AttrSentToMemberOf].([]string)
	if !ok || !reflect.DeepEqual(gotMemberOf, wantMemberOf) {
		t.Errorf("sent_to_member_of = %#v (ok=%v), want %#v", ev.Attrs[semconv.AttrSentToMemberOf], ok, wantMemberOf)
	}
	wantDomain := []string{"m7kni.com"}
	gotDomain, ok := ev.Attrs[semconv.AttrRecipientDomainIs].([]string)
	if !ok || !reflect.DeepEqual(gotDomain, wantDomain) {
		t.Errorf("recipient_domain_is = %#v (ok=%v), want %#v", ev.Attrs[semconv.AttrRecipientDomainIs], ok, wantDomain)
	}
	// Exactly one referenced policy -> policy_name IS set.
	if got := ev.Attrs[semconv.AttrPolicyName]; got != "Custom Policy" {
		t.Errorf("policy_name = %v, want %q", got, "Custom Policy")
	}
	// A scoped rule with SentTo present must not count as unscoped.
	if isUnscoped(rec) {
		t.Error("a rule with SentTo present must not be reported unscoped")
	}
}

// TestExclusionRuleCarriesExceptFields covers ExceptIfSentTo/
// ExceptIfSentToMemberOf/ExceptIfRecipientDomainIs. HAND-BUILT for the same
// reason as the custom-rule test above.
func TestExclusionRuleCarriesExceptFields(t *testing.T) {
	rec := map[string]any{
		"State":                     "Enabled",
		"Priority":                  float64(2),
		"Name":                      "Rule With Exclusions",
		"Identity":                  "Rule With Exclusions",
		"MalwareFilterPolicy":       "Standard Preset Security Policy1784144693315",
		"ExceptIfSentTo":            []any{"vip@m7kni.com"},
		"ExceptIfSentToMemberOf":    []any{"Board@m7kni.com"},
		"ExceptIfRecipientDomainIs": []any{"partner.example"},
	}
	rf := ruleFamilies[4] // malware
	ev := ruleTwin(rf.name, referencedPolicyNames(rf, rec), rec)

	wantExceptSentTo := []string{"vip@m7kni.com"}
	if got, ok := ev.Attrs[semconv.AttrExceptIfSentTo].([]string); !ok || !reflect.DeepEqual(got, wantExceptSentTo) {
		t.Errorf("except_if_sent_to = %#v (ok=%v), want %#v", ev.Attrs[semconv.AttrExceptIfSentTo], ok, wantExceptSentTo)
	}
	wantExceptMemberOf := []string{"Board@m7kni.com"}
	if got, ok := ev.Attrs[semconv.AttrExceptIfSentToMemberOf].([]string); !ok || !reflect.DeepEqual(got, wantExceptMemberOf) {
		t.Errorf("except_if_sent_to_member_of = %#v (ok=%v), want %#v", ev.Attrs[semconv.AttrExceptIfSentToMemberOf], ok, wantExceptMemberOf)
	}
	wantExceptDomain := []string{"partner.example"}
	if got, ok := ev.Attrs[semconv.AttrExceptIfRecipientDomainIs].([]string); !ok || !reflect.DeepEqual(got, wantExceptDomain) {
		t.Errorf("except_if_recipient_domain_is = %#v (ok=%v), want %#v", ev.Attrs[semconv.AttrExceptIfRecipientDomainIs], ok, wantExceptDomain)
	}
	// An exclusion alone (no include axis) does not make the rule scoped —
	// it is still org-wide MINUS the exclusion.
	if !isUnscoped(rec) {
		t.Error("a rule with only ExceptIf* set and no include axis must still count as unscoped")
	}
}

// TestStringListOmitsAbsentNullAndPresentEmptyValues is a DIRECT,
// function-level guard on stringList's contract — the exact function two
// review sabotage runs targeted (#354 follow-up review). Both sabotages
// (hardcoding the missing-key branch to `return []string{}, true`, and
// deleting the `len(vals) == 0` empty-after-filtering branch) left the WHOLE
// SUITE GREEN, including the attrs-presence checks in
// TestPresetEOPRuleMapsInFull above, because telemetry.SetStrs applies its own
// non-empty filter before ever writing to Attrs — a second safety net that
// silently absorbs a broken stringList at the attrs layer. isUnscoped and the
// metricConditions counting in Collect have NO such second filter: they read
// stringList's `ok` return directly, so a broken stringList there silently
// miscounts a rule as SCOPED, or as carrying a condition it does not, with
// no attrs-level symptom at all. This test (and the two below) close that gap
// by asserting on stringList's return values directly, independent of
// SetStrs.
func TestStringListOmitsAbsentNullAndPresentEmptyValues(t *testing.T) {
	cases := []struct {
		name string
		rec  map[string]any
	}{
		{"key absent entirely", map[string]any{}},
		{"JSON null", map[string]any{"SentTo": nil}},
		{"present but empty array", map[string]any{"SentTo": []any{}}},
		{"present array of only empty strings", map[string]any{"SentTo": []any{"", ""}}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			vals, ok := stringList(tc.rec, "SentTo")
			if ok {
				t.Errorf("stringList ok = true, want false")
			}
			if vals != nil {
				t.Errorf("stringList vals = %#v, want nil", vals)
			}
		})
	}
}

// TestNullConditionRuleFromLiveFixtureCountsAsUnscoped is the direct guard the
// #354 follow-up review specifically asked for: taken from the LIVE preset
// EOP rule capture (all six recipient conditions NULL on the wire), it
// asserts isUnscoped directly — not merely that the twin's attrs omit the six
// keys (TestPresetEOPRuleMapsInFull already does that, but passed unchanged
// under both sabotage runs above because of SetStrs's masking). isUnscoped
// has no such masking, so this fails immediately if stringList ever reports a
// NULL condition as present.
func TestNullConditionRuleFromLiveFixtureCountsAsUnscoped(t *testing.T) {
	rec := loadValue(t, "testdata/eopprotection.json")[0]
	for _, field := range unscopedFields {
		if _, present := rec[field]; !present {
			t.Fatalf("fixture is missing %q entirely; test is not exercising the NULL case", field)
		}
		if rec[field] != nil {
			t.Fatalf("fixture's %q is not JSON null (%#v); test is not exercising the NULL case", field, rec[field])
		}
	}
	if !isUnscoped(rec) {
		t.Error("the live preset EOP rule has all recipient conditions NULL; isUnscoped must be true")
	}
}

// TestPresentEmptyRecipientArrayDoesNotScopeOrCountAsCondition covers the
// second sabotage directly: a present-but-empty array (or an array of only
// empty strings) must be indistinguishable from NULL at every layer —
// isUnscoped, the twin attrs, AND the metricConditions counting in Collect.
// HAND-BUILT: m7kni sends null rather than [], so no live fixture exercises
// this branch.
func TestPresentEmptyRecipientArrayDoesNotScopeOrCountAsCondition(t *testing.T) {
	rec := map[string]any{
		"State":               "Enabled",
		"Name":                "Empty Array Rule",
		"Identity":            "Empty Array Rule",
		"MalwareFilterPolicy": "Some Policy",
		"SentTo":              []any{},
		"SentToMemberOf":      []any{"", ""},
	}
	if !isUnscoped(rec) {
		t.Error("a present-but-empty recipient array must not count as scoping (isUnscoped must stay true)")
	}
	ev := ruleTwin("malware", referencedPolicyNames(ruleFamilies[4], rec), rec)
	if _, present := ev.Attrs[semconv.AttrSentTo]; present {
		t.Error("sent_to must be absent for a present-but-empty array")
	}
	if _, present := ev.Attrs[semconv.AttrSentToMemberOf]; present {
		t.Error("sent_to_member_of must be absent for an array of only empty strings")
	}

	// Same fixture through a full Collect: metricConditions must not count
	// either axis as present for this family.
	f := liveFake(t)
	f.byCmdlet["Get-MalwareFilterRule"] = append(f.byCmdlet["Get-MalwareFilterRule"], rec)
	recorder := telemetrytest.New()
	if err := newCollector(t, f).Collect(context.Background(), recorder.Emitter(), nil); err != nil {
		t.Fatalf("Collect: %v", err)
	}
	for _, p := range recorder.MetricPoints(metricConditions) {
		if p.Attrs[semconv.AttrRuleFamily] != "malware" {
			continue
		}
		if p.Attrs[semconv.AttrCondition] == "sent_to" || p.Attrs[semconv.AttrCondition] == "sent_to_member_of" {
			t.Errorf("metricConditions counted %q for a present-but-empty array: %+v", p.Attrs[semconv.AttrCondition], p)
		}
	}
}

// TestDisabledRuleWarnsAndBucketsUnderDisabledState pins the severity ladder:
// a rule whose State is not Enabled is Warn, and its state metric bucket
// reflects the wire value.
func TestDisabledRuleWarnsAndBucketsUnderDisabledState(t *testing.T) {
	f := liveFake(t)
	disabled := map[string]any{
		"State":               "Disabled",
		"Priority":            float64(9),
		"Name":                "Disabled Malware Rule",
		"Identity":            "Disabled Malware Rule",
		"MalwareFilterPolicy": "Standard Preset Security Policy1784144693315",
	}
	f.byCmdlet["Get-MalwareFilterRule"] = append(f.byCmdlet["Get-MalwareFilterRule"], disabled)

	rec := telemetrytest.New()
	if err := newCollector(t, f).Collect(context.Background(), rec.Emitter(), nil); err != nil {
		t.Fatalf("Collect: %v", err)
	}

	var found *telemetrytest.LogRecord
	for i, l := range rec.LogRecords() {
		if l.EventName == eventRule && l.Attrs[semconv.AttrRuleName] == "Disabled Malware Rule" {
			found = &rec.LogRecords()[i]
		}
	}
	if found == nil {
		t.Fatal("no twin for the disabled malware rule")
	}
	if found.SeverityText != "WARN" {
		t.Errorf("severity = %q, want WARN", found.SeverityText)
	}

	gotDisabled := 0.0
	for _, p := range rec.MetricPoints(metricRules) {
		if p.Attrs[semconv.AttrRuleFamily] == "malware" && p.Attrs[semconv.AttrState] == "Disabled" {
			gotDisabled = p.Value
		}
	}
	if gotDisabled != 1 {
		t.Errorf("malware/Disabled bucket = %v, want 1", gotDisabled)
	}
}

// TestEmptyRuleFamilyIsSeededZeroNotError covers the healthy steady state:
// seven of the ten rule cmdlets return zero rows live, and that must be a
// seeded zero series, not an error and not a missing series.
func TestEmptyRuleFamilyIsSeededZeroNotError(t *testing.T) {
	rec := collectLive(t)

	got := map[[2]string]float64{}
	for _, p := range rec.MetricPoints(metricRules) {
		got[[2]string{p.Attrs[semconv.AttrRuleFamily], p.Attrs[semconv.AttrState]}] = p.Value
	}
	for _, want := range []struct {
		family string
		state  string
	}{
		{"hosted_content", stateEnabled}, {"hosted_content", stateDisabled},
		{"malware", stateEnabled}, {"malware", stateDisabled},
		{"anti_phish", stateEnabled}, {"anti_phish", stateDisabled},
		{"safe_links", stateEnabled}, {"safe_links", stateDisabled},
		{"safe_attachment", stateEnabled}, {"safe_attachment", stateDisabled},
		{"teams_protection", stateEnabled}, {"teams_protection", stateDisabled},
		{"hosted_outbound_spam", stateEnabled}, {"hosted_outbound_spam", stateDisabled},
	} {
		if v, ok := got[[2]string{want.family, want.state}]; !ok || v != 0 {
			t.Errorf("%s/%s = %v (present=%v), want a seeded 0", want.family, want.state, v, ok)
		}
	}
	for _, l := range rec.LogRecords() {
		if l.EventName == eventRule && (l.Attrs[semconv.AttrRuleFamily] == "hosted_content" || l.Attrs[semconv.AttrRuleFamily] == "teams_protection") {
			t.Errorf("family with zero live rows emitted a twin: %+v", l.Attrs)
		}
	}
}

// TestUnreferencedPolicyEmitsGaugeAndWarnTwin proves the join's core purpose:
// a policy no enabled rule references gets a Warn twin and increments the
// gauge under its policy_type.
func TestUnreferencedPolicyEmitsGaugeAndWarnTwin(t *testing.T) {
	f := liveFake(t)
	f.byCmdlet["Get-SafeLinksPolicy"] = append(f.byCmdlet["Get-SafeLinksPolicy"],
		map[string]any{"Name": "Orphaned Safe Links Policy"})

	rec := telemetrytest.New()
	if err := newCollector(t, f).Collect(context.Background(), rec.Emitter(), nil); err != nil {
		t.Fatalf("Collect: %v", err)
	}

	gotCount := -1.0
	for _, p := range rec.MetricPoints(metricUnrefPolicy) {
		if p.Attrs[semconv.AttrPolicyType] == "safe_links" {
			gotCount = p.Value
		}
	}
	if gotCount != 1 {
		t.Fatalf("safe_links unreferenced count = %v, want 1", gotCount)
	}

	var twin *telemetrytest.LogRecord
	for i, l := range rec.LogRecords() {
		if l.EventName == eventUnrefPolicy && l.Attrs[semconv.AttrPolicyName] == "Orphaned Safe Links Policy" {
			twin = &rec.LogRecords()[i]
		}
	}
	if twin == nil {
		t.Fatal("no unreferenced-policy twin for the orphan")
	}
	if twin.Attrs[semconv.AttrPolicyType] != "safe_links" {
		t.Errorf("policy_type = %q, want safe_links", twin.Attrs[semconv.AttrPolicyType])
	}
	if twin.SeverityText != "WARN" {
		t.Errorf("severity = %q, want WARN", twin.SeverityText)
	}
}

// TestRuleReferencingMissingPolicyStillEmitsTwin proves orphaning is
// symmetric: a rule naming a policy that the policy fetch never returns still
// gets its own rule twin in full.
func TestRuleReferencingMissingPolicyStillEmitsTwin(t *testing.T) {
	f := liveFake(t)
	// Remove every safe-attachment policy: the ATP protection rule's
	// SafeAttachmentPolicy reference now names a policy that does not exist.
	f.byCmdlet["Get-SafeAttachmentPolicy"] = nil

	rec := telemetrytest.New()
	if err := newCollector(t, f).Collect(context.Background(), rec.Emitter(), nil); err != nil {
		t.Fatalf("Collect: %v", err)
	}

	var found *telemetrytest.LogRecord
	for i, l := range rec.LogRecords() {
		if l.EventName == eventRule && l.Attrs[semconv.AttrRuleFamily] == "atp_protection" {
			found = &rec.LogRecords()[i]
		}
	}
	if found == nil {
		t.Fatal("atp_protection rule twin must still be emitted when its referenced policy does not exist")
	}
	if found.Attrs[semconv.AttrReferencedPolicies] == "" {
		t.Error("referenced_policies must still name the (now-nonexistent) policy")
	}
}

// TestUnreferencedPolicyMatchIsCaseInsensitive proves the join compares policy
// names case-insensitively, matching Exchange's own case-insensitive identity
// semantics.
func TestUnreferencedPolicyMatchIsCaseInsensitive(t *testing.T) {
	f := liveFake(t)
	// The live EOP rule references "Standard Preset Security
	// Policy1784144691483"; report the policy back in a different case.
	f.byCmdlet["Get-HostedContentFilterPolicy"] = []map[string]any{
		{"Name": "STANDARD PRESET SECURITY POLICY1784144691483"},
	}

	rec := telemetrytest.New()
	if err := newCollector(t, f).Collect(context.Background(), rec.Emitter(), nil); err != nil {
		t.Fatalf("Collect: %v", err)
	}
	for _, p := range rec.MetricPoints(metricUnrefPolicy) {
		if p.Attrs[semconv.AttrPolicyType] == "hosted_content" && p.Value != 0 {
			t.Errorf("hosted_content unreferenced count = %v, want 0 (case-insensitive match)", p.Value)
		}
	}
	for _, l := range rec.LogRecords() {
		if l.EventName == eventUnrefPolicy && l.Attrs[semconv.AttrPolicyType] == "hosted_content" {
			t.Error("no unreferenced-policy twin expected: the name matches case-insensitively")
		}
	}
}

// TestPolicyFetchFailureSuppressesUnrefMetricEntirely covers the one-directional
// error rule: a failing policy cmdlet must drop metricUnrefPolicy and its
// twins ENTIRELY (never a false zero), while the rule twins are unaffected.
func TestPolicyFetchFailureSuppressesUnrefMetricEntirely(t *testing.T) {
	f := liveFake(t)
	sentinel := errors.New("503: throttled")
	f.errs = map[string]error{"Get-SafeLinksPolicy": sentinel}

	rec := telemetrytest.New()
	err := newCollector(t, f).Collect(context.Background(), rec.Emitter(), nil)
	if !errors.Is(err, sentinel) {
		t.Fatalf("Collect error = %v, want it to wrap %v", err, sentinel)
	}
	if pts := rec.MetricPoints(metricUnrefPolicy); len(pts) != 0 {
		t.Errorf("got %d metricUnrefPolicy points after a policy fetch failure, want 0", len(pts))
	}
	for _, l := range rec.LogRecords() {
		if l.EventName == eventUnrefPolicy {
			t.Error("no unreferenced-policy twin may be emitted when a policy fetch failed")
		}
	}
	ruleTwins := 0
	for _, l := range rec.LogRecords() {
		if l.EventName == eventRule {
			ruleTwins++
		}
	}
	if ruleTwins != 3 {
		t.Errorf("got %d rule twins despite an unrelated policy-cmdlet failure, want 3", ruleTwins)
	}
}

// TestRuleFetchFailureAggregatesAndOthersStillEmit mirrors
// defender.mdo_policies's resilience shape: one failing rule cmdlet is
// surfaced as a non-fatal aggregated error while the other nine still run.
//
// It also pins the #240 asymmetry: the FAILED family (eop_protection) must
// emit NO point at all on metricRules or metricUnscoped — not a confident
// seeded zero, which would misreport "unavailable" as "measured empty" — while
// every family that WAS successfully read (including atp_protection, and the
// seven empty-but-successful families) still emits its seeded points.
func TestRuleFetchFailureAggregatesAndOthersStillEmit(t *testing.T) {
	f := liveFake(t)
	sentinel := errors.New("403: missing directory role")
	f.errs = map[string]error{"Get-EOPProtectionPolicyRule": sentinel}

	rec := telemetrytest.New()
	err := newCollector(t, f).Collect(context.Background(), rec.Emitter(), nil)
	if !errors.Is(err, sentinel) {
		t.Fatalf("Collect error = %v, want it to wrap %v", err, sentinel)
	}
	for _, l := range rec.LogRecords() {
		if l.Attrs[semconv.AttrRuleFamily] == "eop_protection" {
			t.Error("eop_protection must have no twin when its cmdlet failed")
		}
	}
	found := false
	for _, l := range rec.LogRecords() {
		if l.Attrs[semconv.AttrRuleFamily] == "atp_protection" {
			found = true
		}
	}
	if !found {
		t.Error("atp_protection twin missing despite an unrelated cmdlet failing")
	}

	for _, metricName := range []string{metricRules, metricUnscoped} {
		for _, p := range rec.MetricPoints(metricName) {
			if p.Attrs[semconv.AttrRuleFamily] == "eop_protection" {
				t.Errorf("%s must emit NO point for eop_protection after its fetch failed, got %+v", metricName, p)
			}
		}
	}

	gotRuleFamilies := map[string]bool{}
	for _, p := range rec.MetricPoints(metricRules) {
		gotRuleFamilies[p.Attrs[semconv.AttrRuleFamily]] = true
	}
	for _, family := range []string{"atp_protection", "atp_built_in", "hosted_content", "malware", "anti_phish", "safe_links", "safe_attachment", "teams_protection", "hosted_outbound_spam"} {
		if !gotRuleFamilies[family] {
			t.Errorf("metricRules is missing its seeded point for family %q, which fetched successfully", family)
		}
	}
	gotUnscopedFamilies := map[string]bool{}
	for _, p := range rec.MetricPoints(metricUnscoped) {
		gotUnscopedFamilies[p.Attrs[semconv.AttrRuleFamily]] = true
	}
	if gotUnscopedFamilies["eop_protection"] {
		t.Error("metricUnscoped must not carry eop_protection after its fetch failed")
	}
	if !gotUnscopedFamilies["atp_protection"] {
		t.Error("metricUnscoped is missing its seeded point for atp_protection, which fetched successfully")
	}
}

// TestUnrecognizedOrMissingStateBucketsAsUnknown proves an empty or
// unrecognized State never mints a state="" (or otherwise blank) series —
// the least debuggable value a metric label can carry.
func TestUnrecognizedOrMissingStateBucketsAsUnknown(t *testing.T) {
	if got := ruleStateLabel(map[string]any{}); got != stateUnknown {
		t.Errorf("ruleStateLabel(no State field) = %q, want %q", got, stateUnknown)
	}
	if got := ruleStateLabel(map[string]any{"State": ""}); got != stateUnknown {
		t.Errorf("ruleStateLabel(State=\"\") = %q, want %q", got, stateUnknown)
	}
	if got := ruleStateLabel(map[string]any{"State": "PartiallyEnabled"}); got != stateUnknown {
		t.Errorf("ruleStateLabel(State=%q) = %q, want %q", "PartiallyEnabled", got, stateUnknown)
	}
	if got := ruleStateLabel(map[string]any{"State": "Enabled"}); got != stateEnabled {
		t.Errorf("ruleStateLabel(State=Enabled) = %q, want %q", got, stateEnabled)
	}

	f := liveFake(t)
	f.byCmdlet["Get-MalwareFilterRule"] = append(f.byCmdlet["Get-MalwareFilterRule"],
		map[string]any{"Name": "No State Rule", "MalwareFilterPolicy": "Some Policy"})
	rec := telemetrytest.New()
	if err := newCollector(t, f).Collect(context.Background(), rec.Emitter(), nil); err != nil {
		t.Fatalf("Collect: %v", err)
	}
	gotUnknown := -1.0
	for _, p := range rec.MetricPoints(metricRules) {
		if p.Attrs[semconv.AttrRuleFamily] == "malware" && p.Attrs[semconv.AttrState] == stateUnknown {
			gotUnknown = p.Value
		}
	}
	if gotUnknown != 1 {
		t.Errorf("malware/%s bucket = %v, want 1", stateUnknown, gotUnknown)
	}
}

// TestPriorityZeroIsEmitted proves the falsy-zero trap does not exist here: a
// rule at priority 0 (the highest precedence) must publish 0, not omit it.
func TestPriorityZeroIsEmitted(t *testing.T) {
	rec := map[string]any{
		"State":               "Enabled",
		"Priority":            float64(0),
		"Name":                "Zero Priority Rule",
		"MalwareFilterPolicy": "Some Policy",
	}
	ev := ruleTwin("malware", referencedPolicyNames(ruleFamilies[4], rec), rec)
	p, ok := ev.Attrs[semconv.AttrPriority].(float64)
	if !ok {
		t.Fatal("priority attribute missing for a rule at Priority=0")
	}
	if p != 0 {
		t.Errorf("priority = %v, want 0", p)
	}
}

// TestSidecarKeysNeverBecomeAttributes proves the "<Name>@data.type" /
// "<Name>@odata.type" sidecar keys the wire interleaves (Priority@data.type,
// Guid@odata.type, WhenChanged@data.type) never leak into the twin: no
// attribute key contains "@", and none of the sidecar STRING VALUES
// ("System.Int32", "System.Guid", "System.DateTime") appear as an attribute
// value either.
func TestSidecarKeysNeverBecomeAttributes(t *testing.T) {
	rec := loadValue(t, "testdata/eopprotection.json")[0]
	// Sanity: the fixture really does carry sidecar keys.
	if _, ok := rec["Priority@data.type"]; !ok {
		t.Fatal("fixture is missing its Priority@data.type sidecar; test is not exercising anything")
	}
	ev := ruleTwin("eop_protection", referencedPolicyNames(ruleFamilies[1], rec), rec)
	for k, v := range ev.Attrs {
		if containsAt(k) {
			t.Errorf("attribute key %q contains '@' — a sidecar leaked through", k)
		}
		if sv, ok := v.(string); ok && (sv == "System.Int32" || sv == "System.Guid" || sv == "System.DateTime") {
			t.Errorf("attribute %q = %q looks like a leaked sidecar TYPE value", k, sv)
		}
	}
}

func containsAt(s string) bool {
	for _, r := range s {
		if r == '@' {
			return true
		}
	}
	return false
}

// TestTimestampsAreZero proves this is a STATE feed: both twin kinds leave
// Event.Timestamp at zero (poll time), never the wire's WhenChanged.
func TestTimestampsAreZero(t *testing.T) {
	f := liveFake(t)
	f.byCmdlet["Get-SafeLinksPolicy"] = append(f.byCmdlet["Get-SafeLinksPolicy"],
		map[string]any{"Name": "Orphaned Policy For Timestamp Test"})
	rec := telemetrytest.New()
	if err := newCollector(t, f).Collect(context.Background(), rec.Emitter(), nil); err != nil {
		t.Fatalf("Collect: %v", err)
	}
	sawRule, sawUnref := false, false
	for _, l := range rec.LogRecords() {
		if !l.Timestamp.IsZero() {
			t.Errorf("event %q has a non-zero Timestamp %v, want zero (poll time)", l.EventName, l.Timestamp)
		}
		if l.EventName == eventRule {
			sawRule = true
		}
		if l.EventName == eventUnrefPolicy {
			sawUnref = true
		}
	}
	if !sawRule || !sawUnref {
		t.Fatalf("test did not exercise both event kinds: rule=%v unref=%v", sawRule, sawUnref)
	}
}

// TestMetricsCarryNoPerEntityLabel guards #112: every gauge here must carry
// ONLY its bounded label set, never a rule name or policy name.
func TestMetricsCarryNoPerEntityLabel(t *testing.T) {
	f := liveFake(t)
	f.byCmdlet["Get-SafeLinksPolicy"] = append(f.byCmdlet["Get-SafeLinksPolicy"],
		map[string]any{"Name": "Orphaned Policy"})
	rec := telemetrytest.New()
	if err := newCollector(t, f).Collect(context.Background(), rec.Emitter(), nil); err != nil {
		t.Fatalf("Collect: %v", err)
	}
	banned := []string{
		semconv.AttrRuleName, semconv.AttrRuleIdentity, semconv.AttrPolicyName,
		semconv.AttrGuid, semconv.AttrSentTo, semconv.AttrSentToMemberOf, semconv.AttrRecipientDomainIs,
	}
	for _, name := range []string{metricRules, metricConditions, metricUnscoped, metricUnrefPolicy} {
		for _, p := range rec.MetricPoints(name) {
			for _, b := range banned {
				if _, present := p.Attrs[b]; present {
					t.Errorf("metric %q carries per-entity label %q", name, b)
				}
			}
		}
	}
}

// TestRecordsAreStampedWithTheExchangeOnlineTransport guards the #141 stamp.
func TestRecordsAreStampedWithTheExchangeOnlineTransport(t *testing.T) {
	f := liveFake(t)
	rec := telemetrytest.New()
	c := newCollector(t, f)
	if err := c.Collect(context.Background(), rec.Emitter(), nil); err != nil {
		t.Fatalf("Collect: %v", err)
	}
	for _, r := range rec.LogRecords() {
		if got := r.Attrs[semconv.AttrIngestTransport]; got != string(telemetry.TransportExchangeOnline) {
			t.Fatalf("%s = %q, want %q", semconv.AttrIngestTransport, got, telemetry.TransportExchangeOnline)
		}
	}
	if got := c.IngestTransport(); got != telemetry.TransportExchangeOnline {
		t.Errorf("IngestTransport() = %q, want %q", got, telemetry.TransportExchangeOnline)
	}
	for _, p := range rec.MetricPoints(metricRules) {
		if _, present := p.Attrs[semconv.AttrIngestTransport]; present {
			t.Error("ingest_transport must not be a metric label")
		}
	}
}

// TestCollectEmitsConditionsMetricAndRecipientAttrsEndToEnd drives a custom
// scoped rule and an exclusion rule through a full Collect (rather than
// calling ruleTwin directly, as the unit tests above do), so metricConditions
// and the six recipient-list twin attributes actually reach a Recorder. This
// is also what keeps testdata/signals.json (#164's thin-golden gate) honest:
// a golden built only from the unit-level ruleTwin calls above would never see
// these series at all.
func TestCollectEmitsConditionsMetricAndRecipientAttrsEndToEnd(t *testing.T) {
	f := liveFake(t)
	f.byCmdlet["Get-HostedContentFilterRule"] = append(f.byCmdlet["Get-HostedContentFilterRule"],
		map[string]any{
			"State":                     "Enabled",
			"Priority":                  float64(1),
			"Name":                      "Custom Hosted Content Rule",
			"Identity":                  "Custom Hosted Content Rule",
			"HostedContentFilterPolicy": "Custom Policy",
			"SentTo":                    []any{"alice@m7kni.com"},
			"SentToMemberOf":            []any{"Executives@m7kni.com"},
			"RecipientDomainIs":         []any{"m7kni.com"},
		})
	f.byCmdlet["Get-MalwareFilterRule"] = append(f.byCmdlet["Get-MalwareFilterRule"],
		map[string]any{
			"State":                     "Enabled",
			"Priority":                  float64(2),
			"Name":                      "Rule With Exclusions",
			"Identity":                  "Rule With Exclusions",
			"MalwareFilterPolicy":       "Standard Preset Security Policy1784144693315",
			"ExceptIfSentTo":            []any{"vip@m7kni.com"},
			"ExceptIfSentToMemberOf":    []any{"Board@m7kni.com"},
			"ExceptIfRecipientDomainIs": []any{"partner.example"},
		})

	rec := telemetrytest.New()
	if err := newCollector(t, f).Collect(context.Background(), rec.Emitter(), nil); err != nil {
		t.Fatalf("Collect: %v", err)
	}

	gotConditions := map[string]bool{}
	for _, p := range rec.MetricPoints(metricConditions) {
		if p.Attrs[semconv.AttrRuleFamily] == "hosted_content" {
			gotConditions[p.Attrs[semconv.AttrCondition]] = true
		}
	}
	for _, want := range []string{"sent_to", "sent_to_member_of", "recipient_domain_is"} {
		if !gotConditions[want] {
			t.Errorf("metricConditions missing hosted_content/%s", want)
		}
	}

	var scoped, excluded *telemetrytest.LogRecord
	for i, l := range rec.LogRecords() {
		if l.Attrs[semconv.AttrRuleName] == "Custom Hosted Content Rule" {
			scoped = &rec.LogRecords()[i]
		}
		if l.Attrs[semconv.AttrRuleName] == "Rule With Exclusions" {
			excluded = &rec.LogRecords()[i]
		}
	}
	if scoped == nil || excluded == nil {
		t.Fatal("expected twins for both the custom scoped rule and the exclusion rule")
	}
	if scoped.Attrs[semconv.AttrSentTo] == "" {
		t.Error("scoped twin missing sent_to")
	}
	if excluded.Attrs[semconv.AttrExceptIfSentTo] == "" {
		t.Error("excluded twin missing except_if_sent_to")
	}
}

func TestNameAndPermissions(t *testing.T) {
	c := New(collectors.EXODeps{})
	if c.Name() != collectorName {
		t.Errorf("Name = %q, want %q", c.Name(), collectorName)
	}
	if perms := c.RequiredPermissions(); perms != nil {
		t.Errorf("RequiredPermissions = %v, want nil", perms)
	}
	if c.DefaultInterval() != interval {
		t.Errorf("DefaultInterval = %v, want %v", c.DefaultInterval(), interval)
	}
}
