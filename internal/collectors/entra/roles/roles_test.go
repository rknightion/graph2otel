package roles

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"strings"
	"testing"

	"github.com/rknightion/graph2otel/internal/collectors"
	"github.com/rknightion/graph2otel/internal/license"
	"github.com/rknightion/graph2otel/internal/telemetrytest"
)

// fakeGraph maps request URLs to canned response bodies (or errors).
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
	if body, ok := f.bodies[url]; ok {
		return []byte(body), nil
	}
	return []byte(`{"value": []}`), nil
}

var _ collectors.GraphClient = (*fakeGraph)(nil)

const base = "https://graph.microsoft.com/v1.0"

const directoryRolesURL = base + "/directoryRoles"

const directoryRolesBody = `{
	"value": [
		{"id": "role-ga", "displayName": "Global Administrator", "roleTemplateId": "62e90394-69f5-4237-9190-012177145e10"},
		{"id": "role-hd", "displayName": "Helpdesk Administrator", "roleTemplateId": "729827e3-9c14-49f7-bb1b-9608f156bbb8"}
	]
}`

const gaMembersURL = base + "/directoryRoles/role-ga/members"
const hdMembersURL = base + "/directoryRoles/role-hd/members"

// Directory-role members are a polymorphic directoryObject collection, so the
// shape differs per member kind (@odata.type discriminates). u2 is deliberately
// sparse — it exercises the omit-absent-attrs path — and sp1 is a service
// principal, which carries appId instead of a UPN.
const gaMembersBody = `{"value": [
	{"@odata.type": "#microsoft.graph.user", "id": "u1", "displayName": "Alice Example", "userPrincipalName": "alice@example.com"},
	{"id": "u2"},
	{"@odata.type": "#microsoft.graph.servicePrincipal", "id": "sp1", "displayName": "Automation App", "appId": "11111111-2222-3333-4444-555555555555"}
]}`
const hdMembersBody = `{"value": [
	{"@odata.type": "#microsoft.graph.user", "id": "u3", "displayName": "Carol Example", "userPrincipalName": "carol@example.com"}
]}`

const activeInstancesURL = base + "/roleManagement/directory/roleAssignmentScheduleInstances?$expand=roleDefinition"
const eligibleInstancesURL = base + "/roleManagement/directory/roleEligibilityScheduleInstances?$expand=roleDefinition"

const activeInstancesBody = `{
	"value": [
		{"principalId": "p1", "roleDefinitionId": "62e90394-69f5-4237-9190-012177145e10", "endDateTime": null, "roleDefinition": {"displayName": "Global Administrator"}},
		{"principalId": "p2", "roleDefinitionId": "62e90394-69f5-4237-9190-012177145e10", "endDateTime": "2026-08-01T00:00:00Z", "roleDefinition": {"displayName": "Global Administrator"}},
		{"principalId": "p3", "roleDefinitionId": "729827e3-9c14-49f7-bb1b-9608f156bbb8", "endDateTime": null, "roleDefinition": {"displayName": "Helpdesk Administrator"}}
	]
}`

const eligibleInstancesBody = `{
	"value": [
		{"principalId": "p4", "roleDefinitionId": "62e90394-69f5-4237-9190-012177145e10", "endDateTime": null, "roleDefinition": {"displayName": "Global Administrator"}}
	]
}`

func allBodies() map[string]string {
	return map[string]string{
		directoryRolesURL:    directoryRolesBody,
		gaMembersURL:         gaMembersBody,
		hdMembersURL:         hdMembersBody,
		activeInstancesURL:   activeInstancesBody,
		eligibleInstancesURL: eligibleInstancesBody,
	}
}

func capsWithP2() license.Capabilities {
	return license.Capabilities{license.CapEntraP2: true}
}

func TestCollectEmitsStandingMemberCountsOnFreeTier(t *testing.T) {
	g := &fakeGraph{bodies: allBodies()}
	rec := telemetrytest.New()

	c := New(g, license.Capabilities{}, nil)
	if err := c.Collect(context.Background(), rec.Emitter()); err != nil {
		t.Fatalf("Collect: %v", err)
	}

	got := map[string]float64{}
	for _, p := range rec.MetricPoints(membersMetricName) {
		got[p.Attrs["role_name"]] = p.Value
	}
	want := map[string]float64{"Global Administrator": 3, "Helpdesk Administrator": 1}
	if len(got) != len(want) {
		t.Fatalf("got %d series, want %d: %v", len(got), len(want), got)
	}
	for role, v := range want {
		if got[role] != v {
			t.Errorf("members[%s] = %v, want %v", role, got[role], v)
		}
	}
}

func TestCollectSkipsPIMHalfAndLogsOnFreeTier(t *testing.T) {
	g := &fakeGraph{bodies: allBodies()}
	rec := telemetrytest.New()

	var logBuf bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&logBuf, nil))

	c := New(g, license.Capabilities{}, logger)
	if err := c.Collect(context.Background(), rec.Emitter()); err != nil {
		t.Fatalf("Collect: %v", err)
	}

	// Standing counts must still be emitted.
	if len(rec.MetricPoints(membersMetricName)) != 2 {
		t.Fatalf("got %d member series, want 2 even without P2", len(rec.MetricPoints(membersMetricName)))
	}

	// The PIM-half metrics must be entirely absent, not emitted as empty.
	for _, name := range rec.MetricNames() {
		if name == pimAssignmentsMetricName || name == pimPermanentMetricName {
			t.Errorf("metric %q must not be emitted on a non-P2 tenant", name)
		}
	}

	if !strings.Contains(logBuf.String(), "entra_p2") {
		t.Errorf("expected a skip-and-log line mentioning entra_p2, got log: %s", logBuf.String())
	}
}

func TestCollectEmitsPIMCountsOnP2Tenant(t *testing.T) {
	g := &fakeGraph{bodies: allBodies()}
	rec := telemetrytest.New()

	c := New(g, capsWithP2(), nil)
	if err := c.Collect(context.Background(), rec.Emitter()); err != nil {
		t.Fatalf("Collect: %v", err)
	}

	type key struct{ role, assignmentType string }
	got := map[key]float64{}
	for _, p := range rec.MetricPoints(pimAssignmentsMetricName) {
		got[key{p.Attrs["role_name"], p.Attrs["assignment_type"]}] = p.Value
	}
	want := map[key]float64{
		{"Global Administrator", "active"}:   2,
		{"Helpdesk Administrator", "active"}: 1,
		{"Global Administrator", "eligible"}: 1,
	}
	if len(got) != len(want) {
		t.Fatalf("got %d assignment series, want %d: %v", len(got), len(want), got)
	}
	for k, v := range want {
		if got[k] != v {
			t.Errorf("assignments[%+v] = %v, want %v", k, got[k], v)
		}
	}

	permanent := map[string]float64{}
	for _, p := range rec.MetricPoints(pimPermanentMetricName) {
		permanent[p.Attrs["role_name"]] = p.Value
	}
	wantPermanent := map[string]float64{"Global Administrator": 1, "Helpdesk Administrator": 1}
	if len(permanent) != len(wantPermanent) {
		t.Fatalf("got %d permanent series, want %d: %v", len(permanent), len(wantPermanent), permanent)
	}
	for role, v := range wantPermanent {
		if permanent[role] != v {
			t.Errorf("permanent[%s] = %v, want %v", role, permanent[role], v)
		}
	}
}

func TestCollectNeverEmitsPerPrincipalSeries(t *testing.T) {
	g := &fakeGraph{bodies: allBodies()}
	rec := telemetrytest.New()

	c := New(g, capsWithP2(), nil)
	if err := c.Collect(context.Background(), rec.Emitter()); err != nil {
		t.Fatalf("Collect: %v", err)
	}

	for _, name := range rec.MetricNames() {
		for _, p := range rec.MetricPoints(name) {
			for k := range p.Attrs {
				if k != "role_name" && k != "assignment_type" {
					t.Errorf("%s point has unexpected attribute %q (must be bounded role/assignment-type only): %v", name, k, p.Attrs)
				}
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

// byPrincipal indexes role-member twins by their principal_id attribute.
func byPrincipal(recs []telemetrytest.LogRecord) map[string]telemetrytest.LogRecord {
	out := map[string]telemetrytest.LogRecord{}
	for _, r := range recs {
		out[r.Attrs["principal_id"]] = r
	}
	return out
}

// TestStandingMembersEmitLogTwin is the point of #114's top finding: the
// collector already pages every member object, so the identity of every Global
// Admin is in memory — it was being discarded and only len() kept. "Who is in
// Global Admin" must be answerable from the logs.
func TestStandingMembersEmitLogTwin(t *testing.T) {
	rec := telemetrytest.New()
	if err := New(&fakeGraph{bodies: allBodies()}, license.Capabilities{}, nil).Collect(context.Background(), rec.Emitter()); err != nil {
		t.Fatalf("Collect: %v", err)
	}

	twins := logsNamed(rec.LogRecords(), eventRoleMember)
	standing := []telemetrytest.LogRecord{}
	for _, r := range twins {
		if r.Attrs["assignment_type"] == "standing" {
			standing = append(standing, r)
		}
	}
	if len(standing) != 4 {
		t.Fatalf("got %d standing role-member twins, want 4 (3 GA + 1 helpdesk): %+v", len(standing), standing)
	}

	got := byPrincipal(standing)

	// A user member carries its UPN; the role name matches the gauge's dimension.
	alice, ok := got["u1"]
	if !ok {
		t.Fatalf("no twin for member u1; got %v", got)
	}
	want := map[string]string{
		"principal_id":                  "u1",
		"principal_type":                "user",
		"principal_display_name":        "Alice Example",
		"principal_user_principal_name": "alice@example.com",
		"role_name":                     "Global Administrator",
		"role_id":                       "role-ga",
		"assignment_type":               "standing",
	}
	for k, v := range want {
		if alice.Attrs[k] != v {
			t.Errorf("standing twin attr %q = %q, want %q", k, alice.Attrs[k], v)
		}
	}

	// A service-principal member carries appId instead of a UPN.
	sp, ok := got["sp1"]
	if !ok {
		t.Fatalf("no twin for member sp1; got %v", got)
	}
	if sp.Attrs["principal_type"] != "service_principal" {
		t.Errorf("SP twin principal_type = %q, want service_principal", sp.Attrs["principal_type"])
	}
	if sp.Attrs["principal_app_id"] != "11111111-2222-3333-4444-555555555555" {
		t.Errorf("SP twin principal_app_id = %q, want the appId", sp.Attrs["principal_app_id"])
	}
	if _, ok := sp.Attrs["principal_user_principal_name"]; ok {
		t.Error("SP twin must not carry a user_principal_name attr")
	}

	// A sparse member omits absent attrs rather than emitting empty strings.
	sparse, ok := got["u2"]
	if !ok {
		t.Fatalf("no twin for sparse member u2; got %v", got)
	}
	for _, k := range []string{"principal_display_name", "principal_user_principal_name", "principal_app_id"} {
		if v, ok := sparse.Attrs[k]; ok {
			t.Errorf("sparse member emitted absent attr %q = %q, want it omitted", k, v)
		}
	}
	if sparse.Attrs["principal_type"] != "unknown" {
		t.Errorf("member with no @odata.type = %q, want unknown", sparse.Attrs["principal_type"])
	}
}

// TestPIMAssignmentsEmitLogTwin covers the other half: scheduleInstance never
// decoded principalId even though the response carries it, so "who is ELIGIBLE
// for Global Admin" was equally unanswerable.
func TestPIMAssignmentsEmitLogTwin(t *testing.T) {
	rec := telemetrytest.New()
	if err := New(&fakeGraph{bodies: allBodies()}, capsWithP2(), nil).Collect(context.Background(), rec.Emitter()); err != nil {
		t.Fatalf("Collect: %v", err)
	}

	twins := logsNamed(rec.LogRecords(), eventRoleMember)
	pim := []telemetrytest.LogRecord{}
	for _, r := range twins {
		if t := r.Attrs["assignment_type"]; t == "active" || t == "eligible" {
			pim = append(pim, r)
		}
	}
	if len(pim) != 4 {
		t.Fatalf("got %d PIM twins, want 4 (3 active + 1 eligible): %+v", len(pim), pim)
	}

	got := byPrincipal(pim)

	// p1 is a permanent active assignment (endDateTime null) — the standout risk
	// the gauge already counts separately.
	p1, ok := got["p1"]
	if !ok {
		t.Fatalf("no twin for PIM principal p1; got %v", got)
	}
	if p1.Attrs["assignment_type"] != "active" {
		t.Errorf("p1 assignment_type = %q, want active", p1.Attrs["assignment_type"])
	}
	if p1.Attrs["permanent"] != "true" {
		t.Errorf("p1 permanent = %q, want \"true\" (endDateTime is null)", p1.Attrs["permanent"])
	}
	if _, ok := p1.Attrs["end_date_time"]; ok {
		t.Error("a permanent assignment must not carry an end_date_time attr")
	}

	// p2 is time-bound.
	p2 := got["p2"]
	if p2.Attrs["permanent"] != "false" {
		t.Errorf("p2 permanent = %q, want \"false\"", p2.Attrs["permanent"])
	}
	if p2.Attrs["end_date_time"] != "2026-08-01T00:00:00Z" {
		t.Errorf("p2 end_date_time = %q, want the fixture value", p2.Attrs["end_date_time"])
	}

	// p4 is eligible, not active.
	if got["p4"].Attrs["assignment_type"] != "eligible" {
		t.Errorf("p4 assignment_type = %q, want eligible", got["p4"].Attrs["assignment_type"])
	}
}

// TestFreeTierEmitsNoPIMTwin asserts the license gate short-circuits the twin
// too — a Free tenant emits standing twins but no PIM ones.
func TestFreeTierEmitsNoPIMTwin(t *testing.T) {
	rec := telemetrytest.New()
	if err := New(&fakeGraph{bodies: allBodies()}, license.Capabilities{}, nil).Collect(context.Background(), rec.Emitter()); err != nil {
		t.Fatalf("Collect: %v", err)
	}
	for _, r := range logsNamed(rec.LogRecords(), eventRoleMember) {
		if at := r.Attrs["assignment_type"]; at != "standing" {
			t.Errorf("Free tenant emitted a %q twin (principal %q); PIM must be gated", at, r.Attrs["principal_id"])
		}
	}
}

func TestCollectIsResilientToPerRoleMemberError(t *testing.T) {
	bodies := allBodies()
	g := &fakeGraph{
		bodies: bodies,
		errs:   map[string]error{hdMembersURL: errors.New("throttled")},
	}
	rec := telemetrytest.New()

	err := New(g, license.Capabilities{}, nil).Collect(context.Background(), rec.Emitter())
	if err == nil {
		t.Error("expected Collect to surface the per-role member-count failure as an error")
	}

	pts := rec.MetricPoints(membersMetricName)
	if len(pts) != 1 {
		t.Fatalf("got %d member series, want 1 (helpdesk failed, global admin survived): %v", len(pts), pts)
	}
	if pts[0].Attrs["role_name"] != "Global Administrator" {
		t.Errorf("surviving series role_name = %q, want Global Administrator", pts[0].Attrs["role_name"])
	}
}

func TestCollectSurfacesDirectoryRolesFetchError(t *testing.T) {
	g := &fakeGraph{errs: map[string]error{directoryRolesURL: errors.New("throttled")}}
	rec := telemetrytest.New()

	err := New(g, license.Capabilities{}, nil).Collect(context.Background(), rec.Emitter())
	if err == nil {
		t.Fatal("expected Collect to surface the directoryRoles fetch error")
	}
	if len(rec.MetricPoints(membersMetricName)) != 0 {
		t.Error("expected no member series when directoryRoles itself fails")
	}
}

func TestCollectUnresolvedRoleDefinitionBucketsAsUnknown(t *testing.T) {
	bodies := map[string]string{
		directoryRolesURL: `{"value": []}`,
		activeInstancesURL: `{
			"value": [
				{"principalId": "p1", "roleDefinitionId": "deadbeef-0000-0000-0000-000000000000", "endDateTime": null}
			]
		}`,
		eligibleInstancesURL: `{"value": []}`,
	}
	g := &fakeGraph{bodies: bodies}
	rec := telemetrytest.New()

	if err := New(g, capsWithP2(), nil).Collect(context.Background(), rec.Emitter()); err != nil {
		t.Fatalf("Collect: %v", err)
	}

	pts := rec.MetricPoints(pimAssignmentsMetricName)
	if len(pts) != 1 {
		t.Fatalf("got %d assignment series, want 1: %v", len(pts), pts)
	}
	if pts[0].Attrs["role_name"] != unknownRoleName {
		t.Errorf("role_name = %q, want %q for an instance with no expanded roleDefinition", pts[0].Attrs["role_name"], unknownRoleName)
	}
}

func TestNameIntervalAndPermissions(t *testing.T) {
	c := New(&fakeGraph{}, license.Capabilities{}, nil)
	if c.Name() != "entra.roles" {
		t.Errorf("Name = %q, want entra.roles", c.Name())
	}
	if c.DefaultInterval() <= 0 {
		t.Error("DefaultInterval must be positive")
	}
	perms := c.RequiredPermissions()
	want := map[string]bool{
		"RoleManagement.Read.Directory":          true,
		"RoleAssignmentSchedule.Read.Directory":  true,
		"RoleEligibilitySchedule.Read.Directory": true,
	}
	if len(perms) != len(want) {
		t.Fatalf("RequiredPermissions = %v, want %v", perms, want)
	}
	for _, p := range perms {
		if !want[p] {
			t.Errorf("unexpected permission %q", p)
		}
	}
}

// TestCollectorDoesNotImplementCapabilityRequirer pins the partial-degrade
// contract: this collector must run on every tier (it emits a useful free
// signal), so it must NOT implement license.CapabilityRequirer - the
// composition root would otherwise skip it entirely on a non-P2 tenant.
func TestCollectorDoesNotImplementCapabilityRequirer(t *testing.T) {
	c := New(&fakeGraph{}, license.Capabilities{}, nil)
	if _, ok := any(c).(license.CapabilityRequirer); ok {
		t.Error("Collector must not implement license.CapabilityRequirer (it partially degrades, it does not fully gate)")
	}
}
