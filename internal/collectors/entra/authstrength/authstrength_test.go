package authstrength

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"testing"

	"github.com/rknightion/graph2otel/internal/collectors"
	"github.com/rknightion/graph2otel/internal/semconv"
	"github.com/rknightion/graph2otel/internal/telemetrytest"
)

// fakeGraph maps request URLs to canned JSON bodies (or errors). Pagination is
// modeled by chaining bodies through "@odata.nextLink"; an unmapped URL
// returns an empty collection, which is how a followed nextLink terminates
// (mirrors entra/consent's fakeGraph).
type fakeGraph struct {
	bodies map[string]string
	errs   map[string]error
}

func (f *fakeGraph) RawGet(ctx context.Context, url string) ([]byte, error) {
	return f.RawGetWithHeaders(ctx, url, nil)
}

func (f *fakeGraph) RawGetWithHeaders(_ context.Context, url string, _ map[string]string) ([]byte, error) {
	if err, ok := f.errs[url]; ok {
		return nil, err
	}
	body, ok := f.bodies[url]
	if !ok {
		return []byte(`{"value":[]}`), nil
	}
	return []byte(body), nil
}

var _ collectors.GraphClient = (*fakeGraph)(nil)

func policyURL() string { return defaultBaseURL + policyPath }

// livePolicies is the VERBATIM GET /policies/authenticationStrengthPolicies
// response — 3 built-in policies, no @odata.nextLink — captured from the
// tenant as graph2otel-poller on 2026-07-28 (#322). Read from testdata so the
// wire capture is never hand-retyped into a Go string literal.
func livePolicies(t *testing.T) []byte {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("testdata", "live-authstrength-policies.json"))
	if err != nil {
		t.Fatalf("read live fixture: %v", err)
	}
	return raw
}

// liveMFAPolicy decodes the live capture and returns the "Multifactor
// authentication" built-in policy — the widest one (19 allowedCombinations,
// several of them comma-joined), so it is the row every element-boundary
// assertion is made against.
func liveMFAPolicy(t *testing.T) authStrengthPolicy {
	t.Helper()
	var policies struct {
		Value []authStrengthPolicy `json:"value"`
	}
	if err := json.Unmarshal(livePolicies(t), &policies); err != nil {
		t.Fatalf("decode live capture: %v", err)
	}
	for _, p := range policies.Value {
		if p.ID == "00000000-0000-0000-0000-000000000002" {
			return p
		}
	}
	t.Fatal("live capture has no Multifactor authentication policy")
	return authStrengthPolicy{}
}

func collect(t *testing.T, g *fakeGraph) *telemetrytest.Recorder {
	t.Helper()
	rec := telemetrytest.New()
	if err := New(g, nil).Collect(context.Background(), rec.Emitter(), nil); err != nil {
		t.Fatalf("Collect: %v", err)
	}
	return rec
}

func findTwin(rec *telemetrytest.Recorder, id string) *telemetrytest.LogRecord {
	for _, r := range rec.LogRecords() {
		if r.EventName == eventPolicy && r.Attrs["id"] == id {
			r := r
			return &r
		}
	}
	return nil
}

// TestCollectEndToEndLiveCapture drives the VERBATIM live 3-policy capture
// through the real collector into a recorder and pins the gauge bucket for
// (builtIn, mfa) at 3 — every live policy shares that same pair, so the whole
// tenant's authentication-strength posture collapses onto one series.
func TestCollectEndToEndLiveCapture(t *testing.T) {
	g := &fakeGraph{bodies: map[string]string{policyURL(): string(livePolicies(t))}}
	rec := collect(t, g)

	pts := rec.MetricPoints(metricPolicies)
	if len(pts) != 1 {
		t.Fatalf("got %d series, want exactly 1 (builtIn,mfa): %+v", len(pts), pts)
	}
	p := pts[0]
	if got := p.Attrs["policy_type"]; got != "builtIn" {
		t.Errorf("policy_type = %q, want %q", got, "builtIn")
	}
	if got := p.Attrs["requirements_satisfied"]; got != "mfa" {
		t.Errorf("requirements_satisfied = %q, want %q", got, "mfa")
	}
	if p.Value != 3 {
		t.Errorf("bucket value = %v, want 3", p.Value)
	}

	// One log twin per policy.
	var twins int
	for _, r := range rec.LogRecords() {
		if r.EventName == eventPolicy {
			twins++
		}
	}
	if twins != 3 {
		t.Errorf("got %d %s twins, want 3", twins, eventPolicy)
	}
}

// TestCollectPreservesCommaJoinedCombinationAsOneElement pins the
// load-bearing half of the #322 contract: "password,microsoftAuthenticatorPush"
// (present on the live "Multifactor authentication" policy) survives as ONE
// array element, and no element equals "password" alone.
//
// This asserts on the mapper's OWN []string, not on the recorder's rendered
// attribute, and that distinction is the whole test. telemetrytest joins a
// []string attribute with "," and the join is LOSSY in exactly the way that
// matters here: strings.Join(split(x, ","), ",") == strings.Join(x, ","), so a
// mapper that split every combination on its comma renders a byte-identical
// string. No assertion made against the rendered form — reconstructed,
// re-split, or compared whole — can distinguish the two, which was verified by
// breaking the mapper and watching an earlier rendered-form version of this
// test pass over the sabotage. Reading the pre-render []string is the only
// place the property is observable.
func TestCollectPreservesCommaJoinedCombinationAsOneElement(t *testing.T) {
	mfa := liveMFAPolicy(t)
	got, ok := policyTwin(mfa).Attrs[semconv.AttrAllowedCombinations].([]string)
	if !ok {
		t.Fatalf("allowed_combinations is %T, want []string", policyTwin(mfa).Attrs[semconv.AttrAllowedCombinations])
	}

	// Element-for-element identity with the wire array. This catches splitting,
	// joining, reordering and dropping in one assertion; a membership check
	// would catch only the last.
	if !reflect.DeepEqual(got, mfa.AllowedCombinations) {
		t.Errorf("allowed_combinations = %#v, want the wire array verbatim %#v", got, mfa.AllowedCombinations)
	}
	for _, c := range got {
		if c == "password" {
			t.Errorf("allowed_combinations contains bare %q as its own element — a comma-joined combination was split", "password")
		}
	}
	const wantJoined = "password,microsoftAuthenticatorPush"
	var found bool
	for _, c := range got {
		if c == wantJoined {
			found = true
		}
	}
	if !found {
		t.Errorf("allowed_combinations = %#v, missing %q as a single element", got, wantJoined)
	}
}

// TestCollectDoesNotTruncateAt19 pins that the live policy's 19
// allowedCombinations entries (the largest on the live tenant) survive
// uncapped and unflagged.
func TestCollectDoesNotTruncateAt19(t *testing.T) {
	g := &fakeGraph{bodies: map[string]string{policyURL(): string(livePolicies(t))}}
	rec := collect(t, g)

	mfaTwin := findTwin(rec, "00000000-0000-0000-0000-000000000002")
	if mfaTwin == nil {
		t.Fatal("no twin for the Multifactor authentication policy")
	}
	if got := mfaTwin.Attrs["allowed_combination_count"]; got != "19" {
		t.Errorf("allowed_combination_count = %q, want %q", got, "19")
	}
	if got := mfaTwin.Attrs["allowed_combinations_truncated"]; got != "false" {
		t.Errorf("allowed_combinations_truncated = %q, want %q", got, "false")
	}
	// Element count is read from the mapper's []string, not the rendered
	// attribute: see TestCollectPreservesCommaJoinedCombinationAsOneElement for
	// why the rendered form cannot answer questions about element boundaries.
	if got := len(liveMFAPolicy(t).AllowedCombinations); got != 19 {
		t.Errorf("live capture has %d allowedCombinations, want 19", got)
	}
}

// syntheticPolicyWithNCombinations builds a single-policy response whose
// allowedCombinations array has n synthetic (non-live) entries, to exercise
// the cap deterministically without depending on a tenant ever configuring
// that many. None of the synthetic entries contain a comma, so the rendered
// attribute can be split naively for counting.
func syntheticPolicyWithNCombinations(n int) string {
	var b strings.Builder
	b.WriteString(`{"value":[{"id":"synthetic-policy","policyType":"custom","requirementsSatisfied":"mfa","allowedCombinations":[`)
	for i := 0; i < n; i++ {
		if i > 0 {
			b.WriteByte(',')
		}
		b.WriteByte('"')
		b.WriteString("synthetic")
		b.WriteString(strconv.Itoa(i))
		b.WriteByte('"')
	}
	b.WriteString(`]}]}`)
	return b.String()
}

// TestCollectCapsAt100 pins the cap behavior a synthetic 101-entry policy
// must exercise: allowed_combination_count stays the TRUE uncapped 101, the
// emitted array holds exactly 100, and truncated is true.
func TestCollectCapsAt100(t *testing.T) {
	const n = 101
	g := &fakeGraph{bodies: map[string]string{policyURL(): syntheticPolicyWithNCombinations(n)}}
	rec := collect(t, g)

	twin := findTwin(rec, "synthetic-policy")
	if twin == nil {
		t.Fatal("no twin emitted")
	}
	if got := twin.Attrs["allowed_combination_count"]; got != "101" {
		t.Errorf("allowed_combination_count = %q, want %q", got, "101")
	}
	if got := twin.Attrs["allowed_combinations_truncated"]; got != "true" {
		t.Errorf("allowed_combinations_truncated = %q, want %q", got, "true")
	}
	elements := strings.Split(twin.Attrs["allowed_combinations"], ",")
	if len(elements) != maxAllowedCombinations {
		t.Errorf("got %d allowed_combinations elements, want capped at %d", len(elements), maxAllowedCombinations)
	}
}

// TestCollectCombinationConfigurationCountAbsent pins that a policy with no
// combinationConfigurations key at all yields count 0 and, critically, no
// per-entry attributes — there is no field mapper to leak one from.
func TestCollectCombinationConfigurationCountAbsent(t *testing.T) {
	g := &fakeGraph{bodies: map[string]string{policyURL(): string(livePolicies(t))}}
	rec := collect(t, g)

	for _, r := range rec.LogRecords() {
		if r.EventName != eventPolicy {
			continue
		}
		if got := r.Attrs["combination_configuration_count"]; got != "0" {
			t.Errorf("policy %v: combination_configuration_count = %q, want %q", r.Attrs["id"], got, "0")
		}
	}
}

// TestCollectCombinationConfigurationCountOnlyNoFieldMapper pins the
// evidence-gated gap itself: a SYNTHETIC policy with 2 combinationConfigurations
// entries (a shape never observed live) still yields count 2 and STILL no
// per-entry attributes. This is the pin that stops a later change from
// quietly starting to map unseen fields.
func TestCollectCombinationConfigurationCountOnlyNoFieldMapper(t *testing.T) {
	body := `{"value":[{
		"id": "synthetic-policy",
		"policyType": "custom",
		"requirementsSatisfied": "mfa",
		"allowedCombinations": ["fido2"],
		"combinationConfigurations": [
			{"@odata.type": "#microsoft.graph.fido2CombinationConfiguration", "appliesToCombinations": ["fido2"], "allowedAAGUIDs": ["some-guid"]},
			{"@odata.type": "#microsoft.graph.fido2CombinationConfiguration", "appliesToCombinations": ["fido2"], "allowedAAGUIDs": ["other-guid"]}
		]
	}]}`
	g := &fakeGraph{bodies: map[string]string{policyURL(): body}}
	rec := collect(t, g)

	twin := findTwin(rec, "synthetic-policy")
	if twin == nil {
		t.Fatal("no twin emitted")
	}
	if got := twin.Attrs["combination_configuration_count"]; got != "2" {
		t.Errorf("combination_configuration_count = %q, want %q", got, "2")
	}
	for _, k := range []string{"applies_to_combinations", "allowed_aaguids", "combination_configuration_odata_type"} {
		if _, ok := twin.Attrs[k]; ok {
			t.Errorf("twin unexpectedly carries per-entry key %s — a field mapper was written against unseen data", k)
		}
	}
}

// TestCollectEmptyValueEmitsNothing pins that an empty `value` array is a
// legitimate steady state, not an error: no gauge points, no twins, no error.
func TestCollectEmptyValueEmitsNothing(t *testing.T) {
	g := &fakeGraph{bodies: map[string]string{policyURL(): `{"value":[]}`}}
	rec := telemetrytest.New()

	if err := New(g, nil).Collect(context.Background(), rec.Emitter(), nil); err != nil {
		t.Fatalf("Collect: %v", err)
	}
	if pts := rec.MetricPoints(metricPolicies); len(pts) != 0 {
		t.Errorf("got %d series for empty collection, want 0", len(pts))
	}
	var twins int
	for _, r := range rec.LogRecords() {
		if r.EventName == eventPolicy {
			twins++
		}
	}
	if twins != 0 {
		t.Errorf("got %d twins for empty collection, want 0", twins)
	}
}

// TestCollectSurfacesFetchError pins that a transport failure propagates as
// an error and emits no partial gauge.
func TestCollectSurfacesFetchError(t *testing.T) {
	g := &fakeGraph{errs: map[string]error{policyURL(): errors.New("throttled")}}
	rec := telemetrytest.New()

	err := New(g, nil).Collect(context.Background(), rec.Emitter(), nil)
	if err == nil {
		t.Fatal("expected Collect to surface the fetch error")
	}
	if pts := rec.MetricPoints(metricPolicies); len(pts) != 0 {
		t.Errorf("got %d series after a fetch error, want 0", len(pts))
	}
}

// TestCollectFollowsPagination pins that a fixture split across two pages via
// @odata.nextLink is followed to completion, with both pages' policies
// counted and twinned.
func TestCollectFollowsPagination(t *testing.T) {
	page2URL := policyURL() + "?$skiptoken=abc"
	page1 := `{"value":[{"id":"p1","policyType":"builtIn","requirementsSatisfied":"mfa","allowedCombinations":["fido2"]}],"@odata.nextLink":"` + page2URL + `"}`
	page2 := `{"value":[{"id":"p2","policyType":"custom","requirementsSatisfied":"mfa","allowedCombinations":["password,sms"]}]}`

	g := &fakeGraph{bodies: map[string]string{
		policyURL(): page1,
		page2URL:    page2,
	}}
	rec := collect(t, g)

	var ids []string
	for _, r := range rec.LogRecords() {
		if r.EventName == eventPolicy {
			ids = append(ids, r.Attrs["id"])
		}
	}
	if len(ids) != 2 {
		t.Fatalf("got %d twins %v, want 2 (both pages)", len(ids), ids)
	}
	want := map[string]bool{"p1": true, "p2": true}
	for _, id := range ids {
		if !want[id] {
			t.Errorf("unexpected twin id %q", id)
		}
		delete(want, id)
	}
	if len(want) != 0 {
		t.Errorf("missing twins for %v", want)
	}

	pts := rec.MetricPoints(metricPolicies)
	if len(pts) != 2 {
		t.Fatalf("got %d gauge buckets, want 2 (builtIn/mfa and custom/mfa): %+v", len(pts), pts)
	}
}

func TestNameAndPermissions(t *testing.T) {
	c := New(&fakeGraph{}, nil)
	if c.Name() != collectorName {
		t.Errorf("Name = %q, want %q", c.Name(), collectorName)
	}
	perms := c.RequiredPermissions()
	if len(perms) != 1 || perms[0] != "Policy.Read.All" {
		t.Errorf("RequiredPermissions = %v, want [Policy.Read.All]", perms)
	}
}

func TestDefaultInterval(t *testing.T) {
	c := New(&fakeGraph{}, nil)
	if c.DefaultInterval() <= 0 {
		t.Errorf("DefaultInterval = %v, want positive", c.DefaultInterval())
	}
}
