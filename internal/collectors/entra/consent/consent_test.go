package consent

import (
	"context"
	"errors"
	"strconv"
	"strings"
	"testing"

	"github.com/rknightion/graph2otel/internal/collectors"
	"github.com/rknightion/graph2otel/internal/telemetrytest"
)

// fakeGraph maps request URLs to canned JSON bodies (or errors). Pagination is
// modeled by chaining bodies through "@odata.nextLink".
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

const base = "https://graph.microsoft.com/v1.0"

const grantsURL = base + "/oauth2PermissionGrants"

func spFilterURL(appID string) string {
	return base + "/servicePrincipals?$filter=appId eq '" + appID + "'&$select=id,appRoles"
}

func assignedToURL(spID string) string {
	return base + "/servicePrincipals/" + spID + "/appRoleAssignedTo"
}

// emptyResourceLookups returns bodies for both well-known resource SP filter
// lookups resolving to "not provisioned in this tenant" (empty collection),
// so tests that only care about delegated grants don't need to fake the
// application side too.
func emptyResourceLookups() map[string]string {
	out := map[string]string{}
	for _, ra := range resourceApps {
		out[spFilterURL(ra.appID)] = `{"value":[]}`
	}
	return out
}

func merge(maps ...map[string]string) map[string]string {
	out := map[string]string{}
	for _, m := range maps {
		for k, v := range m {
			out[k] = v
		}
	}
	return out
}

func TestCollectClassifiesDelegatedGrantsByPrivilege(t *testing.T) {
	bodies := merge(emptyResourceLookups(), map[string]string{
		grantsURL: `{"value":[
			{"clientId":"c1","consentType":"Principal","scope":"User.Read"},
			{"clientId":"c2","consentType":"AllPrincipals","scope":"User.Read Directory.ReadWrite.All"},
			{"clientId":"c3","consentType":"Principal","scope":"Mail.Read Calendars.Read"},
			{"clientId":"c4","consentType":"AllPrincipals","scope":"profile openid"}
		]}`,
	})
	g := &fakeGraph{bodies: bodies}
	rec := telemetrytest.New()

	if err := New(g, nil).Collect(context.Background(), rec.Emitter()); err != nil {
		t.Fatalf("Collect: %v", err)
	}

	got := seriesMap(t, rec, metricName)
	// c2 (Directory.ReadWrite.All) and c3 (Mail.Read) are privileged; c1 and c4 are standard.
	want := map[[2]string]float64{
		{"delegated", "privileged"}:   2,
		{"delegated", "standard"}:     2,
		{"application", "privileged"}: 0,
		{"application", "standard"}:   0,
	}
	assertSeries(t, got, want)
}

func TestCollectClassifiesAppRoleAssignmentsByPrivilege(t *testing.T) {
	graphSP := resourceApps[0]
	otherSP := resourceApps[1]

	spBody := `{"value":[{"id":"graph-sp-id","appRoles":[
		{"id":"role-directory-rw","value":"Directory.ReadWrite.All"},
		{"id":"role-user-read","value":"User.Read.All"}
	]}]}`
	assignments := `{"value":[
		{"appRoleId":"role-directory-rw","principalId":"p1"},
		{"appRoleId":"role-user-read","principalId":"p2"},
		{"appRoleId":"role-user-read","principalId":"p3"}
	]}`

	bodies := map[string]string{
		grantsURL:                    `{"value":[]}`,
		spFilterURL(graphSP.appID):   spBody,
		assignedToURL("graph-sp-id"): assignments,
		spFilterURL(otherSP.appID):   `{"value":[]}`,
	}
	g := &fakeGraph{bodies: bodies}
	rec := telemetrytest.New()

	if err := New(g, nil).Collect(context.Background(), rec.Emitter()); err != nil {
		t.Fatalf("Collect: %v", err)
	}

	got := seriesMap(t, rec, metricName)
	want := map[[2]string]float64{
		{"delegated", "privileged"}:   0,
		{"delegated", "standard"}:     0,
		{"application", "privileged"}: 1, // role-directory-rw
		{"application", "standard"}:   2, // role-user-read x2
	}
	assertSeries(t, got, want)
}

func TestCollectSkipsResourceNotProvisionedInTenant(t *testing.T) {
	// Both well-known resource service principals resolve to an empty
	// collection (e.g. Exchange Online isn't provisioned in this tenant) --
	// this must be treated as "nothing to count", not an error.
	bodies := merge(emptyResourceLookups(), map[string]string{
		grantsURL: `{"value":[]}`,
	})
	g := &fakeGraph{bodies: bodies}
	rec := telemetrytest.New()

	err := New(g, nil).Collect(context.Background(), rec.Emitter())
	if err != nil {
		t.Fatalf("Collect: %v, want nil (unprovisioned resource is not a failure)", err)
	}
	pts := rec.MetricPoints(metricName)
	if len(pts) != 4 {
		t.Fatalf("got %d series, want 4 (all-zero bounded set)", len(pts))
	}
}

func TestCollectIsResilientToPartialFailure(t *testing.T) {
	bodies := merge(emptyResourceLookups(), map[string]string{})
	g := &fakeGraph{
		bodies: bodies,
		errs:   map[string]error{grantsURL: errors.New("throttled")},
	}
	rec := telemetrytest.New()

	err := New(g, nil).Collect(context.Background(), rec.Emitter())
	if err == nil {
		t.Error("expected Collect to surface the oauth2PermissionGrants failure as an error")
	}
	// The application-side counts must still be emitted (bounded, all zero here).
	pts := rec.MetricPoints(metricName)
	if len(pts) != 4 {
		t.Fatalf("got %d series, want 4 even under partial failure", len(pts))
	}
}

func TestCollectEmitsOnlyBoundedSeriesRegardlessOfGrantVolume(t *testing.T) {
	// Cardinality guard: build a large synthetic grant list and assert the
	// emitted series count never grows past the fixed 2x2 classification set,
	// and that no attribute carries a per-grant identifier (clientId, id, ...).
	var sb strings.Builder
	sb.WriteString(`{"value":[`)
	for i := 0; i < 500; i++ {
		if i > 0 {
			sb.WriteString(",")
		}
		sb.WriteString(`{"clientId":"c` + strconv.Itoa(i) + `","consentType":"Principal","scope":"User.Read"}`)
	}
	sb.WriteString(`]}`)

	bodies := merge(emptyResourceLookups(), map[string]string{grantsURL: sb.String()})
	g := &fakeGraph{bodies: bodies}
	rec := telemetrytest.New()

	if err := New(g, nil).Collect(context.Background(), rec.Emitter()); err != nil {
		t.Fatalf("Collect: %v", err)
	}
	pts := rec.MetricPoints(metricName)
	if len(pts) != 4 {
		t.Fatalf("got %d series for 500 grants, want 4 (bounded)", len(pts))
	}
	for _, p := range pts {
		for k := range p.Attrs {
			if k != "consent_type" && k != "privilege" {
				t.Errorf("unexpected attribute key %q on emitted series (potential cardinality leak)", k)
			}
		}
	}
}

func TestNameIntervalAndPermissions(t *testing.T) {
	c := New(&fakeGraph{}, nil)
	if c.Name() != "entra.consent" {
		t.Errorf("Name = %q, want entra.consent", c.Name())
	}
	if c.DefaultInterval() <= 0 {
		t.Error("DefaultInterval must be positive")
	}
	perms := c.RequiredPermissions()
	want := map[string]bool{"Directory.Read.All": true, "Application.Read.All": true}
	if len(perms) != len(want) {
		t.Fatalf("RequiredPermissions = %v, want %v", perms, want)
	}
	for _, p := range perms {
		if !want[p] {
			t.Errorf("unexpected permission %q", p)
		}
	}
}

// seriesMap flattens the recorded points for metric into a
// (consent_type, privilege) -> value map, failing the test on any unexpected
// attribute shape.
func seriesMap(t *testing.T, rec *telemetrytest.Recorder, metric string) map[[2]string]float64 {
	t.Helper()
	pts := rec.MetricPoints(metric)
	out := map[[2]string]float64{}
	for _, p := range pts {
		key := [2]string{p.Attrs["consent_type"], p.Attrs["privilege"]}
		out[key] = p.Value
	}
	return out
}

func assertSeries(t *testing.T, got map[[2]string]float64, want map[[2]string]float64) {
	t.Helper()
	if len(got) != len(want) {
		t.Fatalf("got %d series, want %d: %v", len(got), len(want), got)
	}
	for k, v := range want {
		if got[k] != v {
			t.Errorf("series %v = %v, want %v", k, got[k], v)
		}
	}
}
