package consent

import (
	"context"
	"errors"
	neturl "net/url"
	"strconv"
	"strings"
	"testing"

	"github.com/rknightion/graph2otel/internal/collectors"
	"github.com/rknightion/graph2otel/internal/telemetry"
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
	// Mirrors the collector's URL-encoded $filter (spaces/quotes percent-encoded,
	// required or Graph returns HTTP 400).
	filter := "appId eq '" + appID + "'"
	return base + "/servicePrincipals?$filter=" + neturl.QueryEscape(filter) + "&$select=id,appRoles"
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

// logsNamed returns the recorded log records carrying the given EventName.
func logsNamed(recs []telemetrytest.LogRecord, name string) []telemetrytest.LogRecord {
	var out []telemetrytest.LogRecord
	for _, r := range recs {
		if r.EventName == name {
			out = append(out, r)
		}
	}
	return out
}

// TestCollectTwinsOnlyHighPrivilegeDelegatedGrants is the scoping guard for the
// delegated side: g1 (standard scope) must NOT produce a log; g2 (a
// Directory.ReadWrite.All grant) must produce exactly one, carrying the raw
// identifying fields the metric can never hold.
func TestCollectTwinsOnlyHighPrivilegeDelegatedGrants(t *testing.T) {
	bodies := merge(emptyResourceLookups(), map[string]string{
		grantsURL: `{"value":[
			{"id":"g1","clientId":"c1","consentType":"Principal","principalId":"p1","resourceId":"r1","scope":"User.Read"},
			{"id":"g2","clientId":"c2","consentType":"AllPrincipals","resourceId":"r2","scope":"User.Read Directory.ReadWrite.All"}
		]}`,
	})
	g := &fakeGraph{bodies: bodies}
	rec := telemetrytest.New()

	if err := New(g, nil).Collect(context.Background(), rec.Emitter()); err != nil {
		t.Fatalf("Collect: %v", err)
	}

	all := logsNamed(rec.LogRecords(), eventConsentGrant)
	var delegated []telemetrytest.LogRecord
	for _, r := range all {
		if r.Attrs["consent_type"] == consentTypeDelegated {
			delegated = append(delegated, r)
		}
	}
	if len(delegated) != 1 {
		t.Fatalf("emitted %d delegated %s logs, want 1 (standard-scope grant g1 must not be twinned)", len(delegated), eventConsentGrant)
	}

	r := delegated[0]
	want := map[string]string{
		"id":           "g2",
		"consent_type": "delegated",
		"privilege":    "privileged",
		"client_id":    "c2",
		"resource_id":  "r2",
		"scope":        "User.Read Directory.ReadWrite.All",
	}
	for k, v := range want {
		if r.Attrs[k] != v {
			t.Errorf("delegated grant log attr %q = %q, want %q", k, r.Attrs[k], v)
		}
	}
	if v, ok := r.Attrs["principal_id"]; ok {
		t.Errorf("AllPrincipals grant (empty principalId) emitted principal_id attr %q, want omitted", v)
	}
}

// TestCollectTwinsOnlyHighPrivilegeAppRoleAssignments is the scoping guard for
// the application side: the two role-user-read (standard) assignments must
// NOT produce logs; the one role-directory-rw (privileged) assignment must,
// carrying the display names Graph already returns inline plus the resolved
// app role value.
func TestCollectTwinsOnlyHighPrivilegeAppRoleAssignments(t *testing.T) {
	graphSP := resourceApps[0]
	otherSP := resourceApps[1]

	spBody := `{"value":[{"id":"graph-sp-id","appRoles":[
		{"id":"role-directory-rw","value":"Directory.ReadWrite.All"},
		{"id":"role-user-read","value":"User.Read.All"}
	]}]}`
	assignments := `{"value":[
		{"id":"a1","appRoleId":"role-directory-rw","principalId":"p1","principalDisplayName":"Contoso Sync","principalType":"ServicePrincipal","resourceId":"graph-sp-id","resourceDisplayName":"Microsoft Graph"},
		{"id":"a2","appRoleId":"role-user-read","principalId":"p2","principalDisplayName":"Some App","principalType":"ServicePrincipal","resourceId":"graph-sp-id","resourceDisplayName":"Microsoft Graph"},
		{"id":"a3","appRoleId":"role-user-read","principalId":"p3","principalDisplayName":"Other App","principalType":"ServicePrincipal","resourceId":"graph-sp-id","resourceDisplayName":"Microsoft Graph"}
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

	all := logsNamed(rec.LogRecords(), eventConsentGrant)
	var application []telemetrytest.LogRecord
	for _, r := range all {
		if r.Attrs["consent_type"] == consentTypeApplication {
			application = append(application, r)
		}
	}
	if len(application) != 1 {
		t.Fatalf("emitted %d application %s logs, want 1 (the two standard role-user-read assignments must not be twinned)", len(application), eventConsentGrant)
	}

	r := application[0]
	want := map[string]string{
		"id":                     "a1",
		"consent_type":           "application",
		"privilege":              "privileged",
		"resource_label":         "microsoft_graph",
		"resource_id":            "graph-sp-id",
		"resource_display_name":  "Microsoft Graph",
		"app_role_id":            "role-directory-rw",
		"app_role":               "Directory.ReadWrite.All",
		"principal_id":           "p1",
		"principal_display_name": "Contoso Sync",
		"principal_type":         "ServicePrincipal",
	}
	for k, v := range want {
		if r.Attrs[k] != v {
			t.Errorf("app role assignment log attr %q = %q, want %q", k, r.Attrs[k], v)
		}
	}
}

// TestLogTwinNeverReachesMetricAttrs re-runs the mixed high/standard fixtures
// above and asserts that none of the per-entity fields carried by the log
// twin (id, client_id, principal_id, resource_id, scope, app_role_id, ...)
// ever leak onto a metric point's attributes -- the metric stays bounded to
// (consent_type, privilege) regardless of what the log twin now carries.
func TestLogTwinNeverReachesMetricAttrs(t *testing.T) {
	bodies := merge(emptyResourceLookups(), map[string]string{
		grantsURL: `{"value":[
			{"id":"g1","clientId":"c1","consentType":"Principal","principalId":"p1","resourceId":"r1","scope":"User.Read"},
			{"id":"g2","clientId":"c2","consentType":"AllPrincipals","resourceId":"r2","scope":"Directory.ReadWrite.All"}
		]}`,
	})
	g := &fakeGraph{bodies: bodies}
	rec := telemetrytest.New()

	if err := New(g, nil).Collect(context.Background(), rec.Emitter()); err != nil {
		t.Fatalf("Collect: %v", err)
	}

	for _, p := range rec.MetricPoints(metricName) {
		for k := range p.Attrs {
			if k != "consent_type" && k != "privilege" {
				t.Errorf("metric %s has unexpected attribute %q (per-entity leak from the log twin?): %v", metricName, k, p.Attrs)
			}
		}
	}
}

// TestConsentGrantLogTwinSeverityIsWarn drives the log-twin builders directly
// (the risk-collector idiom) so the assertion compares telemetry.Severity
// values rather than the recorder's already-translated OTEL wire numbers.
// Every twinned grant is, by definition, already classified high-privilege --
// there is no lower-severity case to branch on here (contrast risk.logTwin,
// which twins every risk level and escalates only "high").
func TestConsentGrantLogTwinSeverityIsWarn(t *testing.T) {
	delegatedEv := delegatedGrantLogTwin(oauth2Grant{ID: "g1", ClientID: "c1", Scope: "Directory.ReadWrite.All"})
	if delegatedEv.Severity != telemetry.SeverityWarn {
		t.Errorf("delegated grant twin severity = %v, want SeverityWarn", delegatedEv.Severity)
	}
	if delegatedEv.Name != eventConsentGrant {
		t.Errorf("delegated grant twin EventName = %q, want %q", delegatedEv.Name, eventConsentGrant)
	}

	appEv := appRoleAssignmentLogTwin(appRoleAssignment{ID: "a1", AppRoleID: "role1"}, resourceApps[0], "Directory.ReadWrite.All")
	if appEv.Severity != telemetry.SeverityWarn {
		t.Errorf("app role assignment twin severity = %v, want SeverityWarn", appEv.Severity)
	}
	if appEv.Name != eventConsentGrant {
		t.Errorf("app role assignment twin EventName = %q, want %q", appEv.Name, eventConsentGrant)
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
