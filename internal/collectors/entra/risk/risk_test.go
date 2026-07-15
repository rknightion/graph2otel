package risk

import (
	"context"
	"errors"
	"testing"

	"github.com/rknightion/graph2otel/internal/collectors"
	"github.com/rknightion/graph2otel/internal/license"
	"github.com/rknightion/graph2otel/internal/telemetrytest"
)

// fakeGraph maps request URLs to canned page bodies (or errors). It satisfies
// collectors.GraphClient so Collector can be driven through
// collectors.GetAllValues without any live Graph call.
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
	return []byte(f.bodies[url]), nil
}

var _ collectors.GraphClient = (*fakeGraph)(nil)

const base = "https://graph.microsoft.com/v1.0"

const usersURL = base + "/identityProtection/riskyUsers"
const spsURL = base + "/identityProtection/riskyServicePrincipals"

const usersBody = `{"value":[
	{"id":"u1","riskLevel":"high","riskState":"atRisk","userPrincipalName":"should-not-leak@example.com"},
	{"id":"u2","riskLevel":"high","riskState":"atRisk"},
	{"id":"u3","riskLevel":"medium","riskState":"confirmedCompromised"}
]}`

const spsBody = `{"value":[
	{"id":"sp1","riskLevel":"low","riskState":"remediated","appId":"should-not-leak-app-id"}
]}`

func fullFixture() *fakeGraph {
	return &fakeGraph{bodies: map[string]string{
		usersURL: usersBody,
		spsURL:   spsBody,
	}}
}

func bothCaps() license.Capabilities {
	return license.Capabilities{
		license.CapEntraP2:                   true,
		license.CapWorkloadIdentitiesPremium: true,
	}
}

func metricAttrCounts(pts []telemetrytest.MetricPoint) map[[2]string]float64 {
	got := map[[2]string]float64{}
	for _, p := range pts {
		got[[2]string{p.Attrs["risk_level"], p.Attrs["risk_state"]}] = p.Value
	}
	return got
}

func TestCollectBothLicensedEmitsBothMetrics(t *testing.T) {
	g := fullFixture()
	rec := telemetrytest.New()

	c := New(g, bothCaps(), nil)
	if err := c.Collect(context.Background(), rec.Emitter()); err != nil {
		t.Fatalf("Collect: %v", err)
	}

	userPts := rec.MetricPoints(metricRiskyUsers)
	gotUsers := metricAttrCounts(userPts)
	wantUsers := map[[2]string]float64{
		{"high", "atRisk"}:                 2,
		{"medium", "confirmedCompromised"}: 1,
	}
	if len(gotUsers) != len(wantUsers) {
		t.Fatalf("got %d risky-user series, want %d: %v", len(gotUsers), len(wantUsers), gotUsers)
	}
	for k, v := range wantUsers {
		if gotUsers[k] != v {
			t.Errorf("risky users level=%s state=%s = %v, want %v", k[0], k[1], gotUsers[k], v)
		}
	}

	spPts := rec.MetricPoints(metricRiskyServicePrincipals)
	gotSPs := metricAttrCounts(spPts)
	wantSPs := map[[2]string]float64{{"low", "remediated"}: 1}
	if len(gotSPs) != len(wantSPs) {
		t.Fatalf("got %d risky-SP series, want %d: %v", len(gotSPs), len(wantSPs), gotSPs)
	}
	for k, v := range wantSPs {
		if gotSPs[k] != v {
			t.Errorf("risky SPs level=%s state=%s = %v, want %v", k[0], k[1], gotSPs[k], v)
		}
	}
}

func TestCollectNoPerEntitySeries(t *testing.T) {
	g := fullFixture()
	rec := telemetrytest.New()

	if err := New(g, bothCaps(), nil).Collect(context.Background(), rec.Emitter()); err != nil {
		t.Fatalf("Collect: %v", err)
	}

	for _, name := range []string{metricRiskyUsers, metricRiskyServicePrincipals} {
		for _, p := range rec.MetricPoints(name) {
			for k := range p.Attrs {
				if k != "risk_level" && k != "risk_state" {
					t.Errorf("metric %s has unexpected attribute %q (per-entity leak?): %v", name, k, p.Attrs)
				}
			}
		}
	}
}

func TestCollectOnlyP2EmitsUsersSkipsServicePrincipals(t *testing.T) {
	g := fullFixture()
	rec := telemetrytest.New()

	caps := license.Capabilities{license.CapEntraP2: true}
	if err := New(g, caps, nil).Collect(context.Background(), rec.Emitter()); err != nil {
		t.Fatalf("Collect: %v", err)
	}

	if pts := rec.MetricPoints(metricRiskyUsers); len(pts) == 0 {
		t.Error("expected risky-user series to be emitted under CapEntraP2")
	}
	if pts := rec.MetricPoints(metricRiskyServicePrincipals); len(pts) != 0 {
		t.Errorf("expected risky-SP series to be skipped without CapWorkloadIdentitiesPremium, got %v", pts)
	}
}

func TestCollectOnlyWorkloadIDEmitsServicePrincipalsSkipsUsers(t *testing.T) {
	g := fullFixture()
	rec := telemetrytest.New()

	caps := license.Capabilities{license.CapWorkloadIdentitiesPremium: true}
	if err := New(g, caps, nil).Collect(context.Background(), rec.Emitter()); err != nil {
		t.Fatalf("Collect: %v", err)
	}

	if pts := rec.MetricPoints(metricRiskyServicePrincipals); len(pts) == 0 {
		t.Error("expected risky-SP series to be emitted under CapWorkloadIdentitiesPremium")
	}
	if pts := rec.MetricPoints(metricRiskyUsers); len(pts) != 0 {
		t.Errorf("expected risky-user series to be skipped without CapEntraP2, got %v", pts)
	}
}

func TestCollectNeitherLicenseSkipsBothWithoutError(t *testing.T) {
	g := fullFixture()
	rec := telemetrytest.New()

	err := New(g, license.Capabilities{}, nil).Collect(context.Background(), rec.Emitter())
	if err != nil {
		t.Fatalf("Collect: %v, want nil (both halves gated off, not an error)", err)
	}
	if pts := rec.MetricPoints(metricRiskyUsers); len(pts) != 0 {
		t.Errorf("expected no risky-user series, got %v", pts)
	}
	if pts := rec.MetricPoints(metricRiskyServicePrincipals); len(pts) != 0 {
		t.Errorf("expected no risky-SP series, got %v", pts)
	}
}

func TestCollectNilCapabilitiesSkipsBothWithoutError(t *testing.T) {
	g := fullFixture()
	rec := telemetrytest.New()

	// A nil Capabilities map (Has is documented safe on nil) must behave
	// exactly like the empty set: both halves skipped, no panic, no error.
	err := New(g, nil, nil).Collect(context.Background(), rec.Emitter())
	if err != nil {
		t.Fatalf("Collect: %v, want nil", err)
	}
}

func TestCollectSurfacesPerHalfFailureButOtherHalfStillEmits(t *testing.T) {
	g := fullFixture()
	g.errs = map[string]error{usersURL: errors.New("throttled")}
	rec := telemetrytest.New()

	err := New(g, bothCaps(), nil).Collect(context.Background(), rec.Emitter())
	if err == nil {
		t.Fatal("expected Collect to surface the risky-users failure")
	}
	if pts := rec.MetricPoints(metricRiskyUsers); len(pts) != 0 {
		t.Errorf("risky-users should have no data on failure, got %v", pts)
	}
	if pts := rec.MetricPoints(metricRiskyServicePrincipals); len(pts) == 0 {
		t.Error("risky-SPs should still emit despite the risky-users failure")
	}
}

func TestNameAndPermissions(t *testing.T) {
	c := New(&fakeGraph{}, license.Capabilities{}, nil)
	if c.Name() != "entra.risk" {
		t.Errorf("Name = %q, want entra.risk", c.Name())
	}
	perms := c.RequiredPermissions()
	want := map[string]bool{"IdentityRiskyUser.Read.All": true, "IdentityRiskyServicePrincipal.Read.All": true}
	if len(perms) != len(want) {
		t.Fatalf("RequiredPermissions = %v, want %v", perms, want)
	}
	for _, p := range perms {
		if !want[p] {
			t.Errorf("unexpected permission %q", p)
		}
	}
}
