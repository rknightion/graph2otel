package conditionalaccess

import (
	"context"
	"errors"
	"testing"

	"github.com/rknightion/graph2otel/internal/collectors"
	"github.com/rknightion/graph2otel/internal/license"
	"github.com/rknightion/graph2otel/internal/telemetrytest"
)

// fakeGraph maps request URLs to canned page bodies (or errors) and records
// the ConsistencyLevel header seen on each request. GetAllValues follows
// @odata.nextLink, but every fixture here is a single page.
type fakeGraph struct {
	bodies      map[string]string
	errs        map[string]error
	seenHeaders map[string]string // url -> ConsistencyLevel
}

func (f *fakeGraph) RawGet(ctx context.Context, url string) ([]byte, error) {
	return f.RawGetWithHeaders(ctx, url, nil)
}

func (f *fakeGraph) RawGetWithHeaders(_ context.Context, url string, headers map[string]string) ([]byte, error) {
	if f.seenHeaders == nil {
		f.seenHeaders = map[string]string{}
	}
	f.seenHeaders[url] = headers["ConsistencyLevel"]
	if err, ok := f.errs[url]; ok {
		return nil, err
	}
	return []byte(f.bodies[url]), nil
}

var _ collectors.GraphClient = (*fakeGraph)(nil)

const (
	base         = "https://graph.microsoft.com/v1.0"
	policiesURL  = base + "/identity/conditionalAccess/policies"
	locationsURL = base + "/identity/conditionalAccess/namedLocations"
)

func policiesPage(policiesJSON string) string {
	return `{"value":[` + policiesJSON + `]}`
}

func locationsPage(locationsJSON string) string {
	return `{"value":[` + locationsJSON + `]}`
}

const samplePolicies = `
{"id":"p1","displayName":"CA001","state":"enabled"},
{"id":"p2","displayName":"CA002","state":"enabled"},
{"id":"p3","displayName":"CA003","state":"disabled"},
{"id":"p4","displayName":"CA004","state":"enabledForReportingButNotEnforced"}
`

const sampleLocations = `
{"@odata.type":"#microsoft.graph.ipNamedLocation","id":"l1","displayName":"Trusted IP","isTrusted":true,"ipRanges":[{"cidrAddress":"1.2.3.0/24"}]},
{"@odata.type":"#microsoft.graph.ipNamedLocation","id":"l2","displayName":"Untrusted IP","isTrusted":false,"ipRanges":[{"cidrAddress":"5.6.7.0/24"}]},
{"@odata.type":"#microsoft.graph.countryNamedLocation","id":"l3","displayName":"US/CA","countriesAndRegions":["US","CA"]}
`

func fullFixture() map[string]string {
	return map[string]string{
		policiesURL:  policiesPage(samplePolicies),
		locationsURL: locationsPage(sampleLocations),
	}
}

func TestCollectEmitsPolicyCountsByState(t *testing.T) {
	g := &fakeGraph{bodies: fullFixture()}
	rec := telemetrytest.New()

	if err := New(g, nil).Collect(context.Background(), rec.Emitter()); err != nil {
		t.Fatalf("Collect: %v", err)
	}

	pts := rec.MetricPoints(policiesMetricName)
	got := map[string]float64{}
	for _, p := range pts {
		got[p.Attrs["state"]] = p.Value
	}
	want := map[string]float64{
		"enabled":                                2,
		"disabled":                               1,
		"enabled_for_reporting_but_not_enforced": 1,
	}
	if len(got) != len(want) {
		t.Fatalf("got %d series, want %d: %v", len(got), len(want), got)
	}
	for state, v := range want {
		if got[state] != v {
			t.Errorf("series state=%s value = %v, want %v", state, got[state], v)
		}
	}
}

func TestCollectEmitsNamedLocationCountsByTypeAndTrust(t *testing.T) {
	g := &fakeGraph{bodies: fullFixture()}
	rec := telemetrytest.New()

	if err := New(g, nil).Collect(context.Background(), rec.Emitter()); err != nil {
		t.Fatalf("Collect: %v", err)
	}

	pts := rec.MetricPoints(namedLocationsMetricName)
	type key struct{ typ, trusted string }
	got := map[key]float64{}
	for _, p := range pts {
		got[key{p.Attrs["type"], p.Attrs["is_trusted"]}] = p.Value
	}
	want := map[key]float64{
		{"ip", "true"}:       1,
		{"ip", "false"}:      1,
		{"country", "true"}:  0,
		{"country", "false"}: 1,
	}
	if len(got) != len(want) {
		t.Fatalf("got %d series, want %d: %v", len(got), len(want), got)
	}
	for k, v := range want {
		if got[k] != v {
			t.Errorf("series type=%s is_trusted=%s value = %v, want %v", k.typ, k.trusted, got[k], v)
		}
	}
}

func TestCollectSkipsUnrecognizedPolicyStateAndLocationType(t *testing.T) {
	bodies := map[string]string{
		policiesURL: policiesPage(`
			{"id":"p1","state":"enabled"},
			{"id":"p2","state":"someFutureState"}
		`),
		locationsURL: locationsPage(`
			{"@odata.type":"#microsoft.graph.ipNamedLocation","id":"l1","isTrusted":true},
			{"@odata.type":"#microsoft.graph.someFutureLocationType","id":"l2"}
		`),
	}
	g := &fakeGraph{bodies: bodies}
	rec := telemetrytest.New()

	if err := New(g, nil).Collect(context.Background(), rec.Emitter()); err != nil {
		t.Fatalf("Collect: %v", err)
	}

	policyPts := rec.MetricPoints(policiesMetricName)
	var totalPolicies float64
	for _, p := range policyPts {
		totalPolicies += p.Value
	}
	if totalPolicies != 1 {
		t.Errorf("total policy count = %v, want 1 (unrecognized state excluded)", totalPolicies)
	}

	locPts := rec.MetricPoints(namedLocationsMetricName)
	var totalLocations float64
	for _, p := range locPts {
		totalLocations += p.Value
	}
	if totalLocations != 1 {
		t.Errorf("total named location count = %v, want 1 (unrecognized type excluded)", totalLocations)
	}
}

func TestCollectSetsConsistencyLevelHeaderIsNotRequired(t *testing.T) {
	// Conditional Access policies/namedLocations are plain collection reads
	// (no advanced $filter/$search), so unlike Count-based collectors this one
	// must NOT force ConsistencyLevel: eventual on every request.
	g := &fakeGraph{bodies: fullFixture()}
	rec := telemetrytest.New()

	if err := New(g, nil).Collect(context.Background(), rec.Emitter()); err != nil {
		t.Fatalf("Collect: %v", err)
	}
	for url, cl := range g.seenHeaders {
		if cl != "" {
			t.Errorf("request %s had ConsistencyLevel=%q, want unset", url, cl)
		}
	}
}

func TestCollectIsResilientToPolicyFetchError(t *testing.T) {
	g := &fakeGraph{
		bodies: fullFixture(),
		errs:   map[string]error{policiesURL: errors.New("throttled")},
	}
	rec := telemetrytest.New()

	err := New(g, nil).Collect(context.Background(), rec.Emitter())
	if err == nil {
		t.Error("expected Collect to surface the policies fetch failure as an error")
	}

	if pts := rec.MetricPoints(policiesMetricName); len(pts) != 0 {
		t.Errorf("expected no policy series when the fetch failed, got %d", len(pts))
	}
	// Named locations must still emit even though policies failed.
	if pts := rec.MetricPoints(namedLocationsMetricName); len(pts) == 0 {
		t.Error("expected named location series to still be emitted despite policies failing")
	}
}

func TestCollectIsResilientToNamedLocationsFetchError(t *testing.T) {
	g := &fakeGraph{
		bodies: fullFixture(),
		errs:   map[string]error{locationsURL: errors.New("throttled")},
	}
	rec := telemetrytest.New()

	err := New(g, nil).Collect(context.Background(), rec.Emitter())
	if err == nil {
		t.Error("expected Collect to surface the named locations fetch failure as an error")
	}

	if pts := rec.MetricPoints(namedLocationsMetricName); len(pts) != 0 {
		t.Errorf("expected no named location series when the fetch failed, got %d", len(pts))
	}
	if pts := rec.MetricPoints(policiesMetricName); len(pts) == 0 {
		t.Error("expected policy series to still be emitted despite named locations failing")
	}
}

func TestNameAndPermissions(t *testing.T) {
	c := New(&fakeGraph{}, nil)
	if c.Name() != "entra.conditional_access" {
		t.Errorf("Name = %q", c.Name())
	}
	perms := c.RequiredPermissions()
	if len(perms) != 1 || perms[0] != "Policy.Read.All" {
		t.Errorf("RequiredPermissions = %v, want [Policy.Read.All]", perms)
	}
}

func TestRequiredCapabilityIsEntraP1(t *testing.T) {
	c := New(&fakeGraph{}, nil)
	var requirer license.CapabilityRequirer = c
	if got := requirer.RequiredCapability(); got != license.CapEntraP1 {
		t.Errorf("RequiredCapability() = %q, want %q", got, license.CapEntraP1)
	}
}

// TestNoPerEntitySeries guards the cardinality rule: neither metric may carry
// a per-policy or per-location identifier (id/displayName) as an attribute.
func TestNoPerEntitySeries(t *testing.T) {
	g := &fakeGraph{bodies: fullFixture()}
	rec := telemetrytest.New()

	if err := New(g, nil).Collect(context.Background(), rec.Emitter()); err != nil {
		t.Fatalf("Collect: %v", err)
	}

	allowedPolicyAttrs := map[string]bool{"state": true}
	for _, p := range rec.MetricPoints(policiesMetricName) {
		for k := range p.Attrs {
			if !allowedPolicyAttrs[k] {
				t.Errorf("policies series has unexpected attribute %q (possible per-entity leak): %v", k, p.Attrs)
			}
		}
	}

	allowedLocationAttrs := map[string]bool{"type": true, "is_trusted": true}
	for _, p := range rec.MetricPoints(namedLocationsMetricName) {
		for k := range p.Attrs {
			if !allowedLocationAttrs[k] {
				t.Errorf("named locations series has unexpected attribute %q (possible per-entity leak): %v", k, p.Attrs)
			}
		}
	}

	// Cardinality is bounded regardless of how many policies/locations exist:
	// 3 states, at most 4 type x trust combos.
	if n := len(rec.MetricPoints(policiesMetricName)); n > 3 {
		t.Errorf("policies series count = %d, want <= 3", n)
	}
	if n := len(rec.MetricPoints(namedLocationsMetricName)); n > 4 {
		t.Errorf("named locations series count = %d, want <= 4", n)
	}
}
