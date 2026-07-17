package agreements

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
	base          = "https://graph.microsoft.com/v1.0"
	agreementsURL = base + "/identityGovernance/termsOfUse/agreements"
)

func acceptancesURL(agreementID string) string {
	return base + "/identityGovernance/termsOfUse/agreements/" + agreementID + "/acceptances"
}

func page(itemsJSON string) string {
	return `{"value":[` + itemsJSON + `]}`
}

// twoAgreements is the primary fixture data for this package's tests.
//
// Provenance: docs-derived; endpoint returns 0 rows / not-configured on the
// m7kni tenant, live-checked 2026-07-17 (#165) — no live sample to pin. No
// terms-of-use agreement is configured on the tenant, so termsOfUse/agreements
// returned 0 rows and no wire record could be captured.
const twoAgreements = `
{"id":"a1","displayName":"All users terms of use"},
{"id":"a2","displayName":"Contoso ToU for guest users"}
`

func fullFixture() map[string]string {
	return map[string]string{
		agreementsURL: page(twoAgreements),
		acceptancesURL("a1"): page(`
			{"id":"a1_u1","agreementId":"a1","userId":"u1","state":"accepted"},
			{"id":"a1_u2","agreementId":"a1","userId":"u2","state":"accepted"},
			{"id":"a1_u3","agreementId":"a1","userId":"u3","state":"declined"}
		`),
		acceptancesURL("a2"): page(`
			{"id":"a2_u1","agreementId":"a2","userId":"u1","state":"declined"}
		`),
	}
}

func TestCollectEmitsAgreementsTotal(t *testing.T) {
	g := &fakeGraph{bodies: fullFixture()}
	rec := telemetrytest.New()

	if err := New(g, nil).Collect(context.Background(), rec.Emitter()); err != nil {
		t.Fatalf("Collect: %v", err)
	}

	pts := rec.MetricPoints(agreementsMetricName)
	if len(pts) != 1 {
		t.Fatalf("got %d agreements.total series, want 1: %v", len(pts), pts)
	}
	if pts[0].Value != 2 {
		t.Errorf("agreements.total = %v, want 2", pts[0].Value)
	}
}

func TestCollectEmitsPerAgreementAcceptanceCounts(t *testing.T) {
	g := &fakeGraph{bodies: fullFixture()}
	rec := telemetrytest.New()

	if err := New(g, nil).Collect(context.Background(), rec.Emitter()); err != nil {
		t.Fatalf("Collect: %v", err)
	}

	pts := rec.MetricPoints(acceptancesMetricName)
	type key struct{ agreement, state string }
	got := map[key]float64{}
	for _, p := range pts {
		got[key{p.Attrs["agreement"], p.Attrs["state"]}] = p.Value
	}
	want := map[key]float64{
		{"a1", "accepted"}: 2,
		{"a1", "declined"}: 1,
		{"a2", "accepted"}: 0,
		{"a2", "declined"}: 1,
	}
	if len(got) != len(want) {
		t.Fatalf("got %d series, want %d: %v", len(got), len(want), got)
	}
	for k, v := range want {
		if got[k] != v {
			t.Errorf("series agreement=%s state=%s value = %v, want %v", k.agreement, k.state, got[k], v)
		}
	}
}

func TestCollectSetsConsistencyLevelHeaderIsNotRequired(t *testing.T) {
	// Agreements/acceptances are plain collection reads (no advanced
	// $filter/$search), so unlike Count-based collectors this one must NOT
	// force ConsistencyLevel: eventual on every request.
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

func TestCollectIsResilientToPerAgreementAcceptanceFetchError(t *testing.T) {
	g := &fakeGraph{
		bodies: fullFixture(),
		errs:   map[string]error{acceptancesURL("a2"): errors.New("throttled")},
	}
	rec := telemetrytest.New()

	err := New(g, nil).Collect(context.Background(), rec.Emitter())
	if err == nil {
		t.Fatal("expected Collect to surface the per-agreement acceptance failure as an error")
	}

	// a1's acceptance counts must still be emitted despite a2 failing.
	pts := rec.MetricPoints(acceptancesMetricName)
	type key struct{ agreement, state string }
	got := map[key]float64{}
	for _, p := range pts {
		got[key{p.Attrs["agreement"], p.Attrs["state"]}] = p.Value
	}
	if got[key{"a1", "accepted"}] != 2 || got[key{"a1", "declined"}] != 1 {
		t.Errorf("a1 counts missing/wrong despite a2 failure: %v", got)
	}
	for k := range got {
		if k.agreement == "a2" {
			t.Errorf("a2 series should be absent when its acceptances fetch failed: %v", got)
		}
	}

	// agreements.total must still emit even though one agreement's
	// acceptances call failed.
	if pts := rec.MetricPoints(agreementsMetricName); len(pts) != 1 || pts[0].Value != 2 {
		t.Errorf("agreements.total should still emit as 2 despite the per-agreement failure, got %v", pts)
	}
}

func TestCollectSurfacesAgreementsFetchFailure(t *testing.T) {
	g := &fakeGraph{
		bodies: fullFixture(),
		errs:   map[string]error{agreementsURL: errors.New("throttled")},
	}
	rec := telemetrytest.New()

	err := New(g, nil).Collect(context.Background(), rec.Emitter())
	if err == nil {
		t.Fatal("expected Collect to surface the agreements list fetch failure as an error")
	}
	if pts := rec.MetricPoints(agreementsMetricName); len(pts) != 0 {
		t.Errorf("expected no agreements.total series when the list fetch failed, got %v", pts)
	}
	if pts := rec.MetricPoints(acceptancesMetricName); len(pts) != 0 {
		t.Errorf("expected no acceptance series when the agreements list fetch failed, got %v", pts)
	}
}

func TestCollectSkipsUnrecognizedAcceptanceState(t *testing.T) {
	bodies := map[string]string{
		agreementsURL: page(`{"id":"a1","displayName":"ToU"}`),
		acceptancesURL("a1"): page(`
			{"id":"a1_u1","agreementId":"a1","userId":"u1","state":"accepted"},
			{"id":"a1_u2","agreementId":"a1","userId":"u2","state":"someFutureState"}
		`),
	}
	g := &fakeGraph{bodies: bodies}
	rec := telemetrytest.New()

	if err := New(g, nil).Collect(context.Background(), rec.Emitter()); err != nil {
		t.Fatalf("Collect: %v", err)
	}

	pts := rec.MetricPoints(acceptancesMetricName)
	var total float64
	for _, p := range pts {
		total += p.Value
	}
	if total != 1 {
		t.Errorf("total acceptance count = %v, want 1 (unrecognized state excluded)", total)
	}
}

func TestNameAndPermissions(t *testing.T) {
	c := New(&fakeGraph{}, nil)
	if c.Name() != "entra.agreements" {
		t.Errorf("Name = %q, want entra.agreements", c.Name())
	}
	perms := c.RequiredPermissions()
	want := map[string]bool{"Agreement.Read.All": true, "AgreementAcceptance.Read.All": true}
	if len(perms) != len(want) {
		t.Fatalf("RequiredPermissions = %v, want %v", perms, want)
	}
	for _, p := range perms {
		if !want[p] {
			t.Errorf("unexpected permission %q", p)
		}
	}
}

func TestRequiredCapabilityIsEntraP1(t *testing.T) {
	c := New(&fakeGraph{}, nil)
	var requirer license.CapabilityRequirer = c
	if got := requirer.RequiredCapability(); got != license.CapEntraP1 {
		t.Errorf("RequiredCapability() = %q, want %q", got, license.CapEntraP1)
	}
}

// TestNoPerUserSeries guards the cardinality rule: the acceptances metric may
// carry only the bounded (agreement, state) dimensions -- never a per-user
// identifier (userId/userPrincipalName/userEmail) as an attribute.
func TestNoPerUserSeries(t *testing.T) {
	g := &fakeGraph{bodies: fullFixture()}
	rec := telemetrytest.New()

	if err := New(g, nil).Collect(context.Background(), rec.Emitter()); err != nil {
		t.Fatalf("Collect: %v", err)
	}

	allowedAttrs := map[string]bool{"agreement": true, "state": true}
	pts := rec.MetricPoints(acceptancesMetricName)
	for _, p := range pts {
		for k := range p.Attrs {
			if !allowedAttrs[k] {
				t.Errorf("acceptances series has unexpected attribute %q (possible per-user leak): %v", k, p.Attrs)
			}
		}
	}
	// Cardinality is bounded by agreement count x 2 states, never by user count.
	if n := len(pts); n > len(twoAgreementIDs())*2 {
		t.Errorf("acceptances series count = %d, want <= %d", n, len(twoAgreementIDs())*2)
	}

	if len(rec.MetricPoints(agreementsMetricName)) != 1 {
		t.Fatalf("expected exactly one agreements.total series")
	}
	for k := range rec.MetricPoints(agreementsMetricName)[0].Attrs {
		t.Errorf("agreements.total should carry no attributes, got %q", k)
	}
}

func twoAgreementIDs() []string { return []string{"a1", "a2"} }
