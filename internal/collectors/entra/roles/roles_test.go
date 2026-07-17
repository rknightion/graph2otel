package roles

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"reflect"
	"sort"
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

// CONSTRUCTED, not measured. These member bodies exercise wire-shape branches
// the live #165 capture does NOT contain: a service-principal member (sp1,
// carrying appId instead of a UPN) and a sparse member (u2, exercising the
// omit-absent-attrs path). Directory-role members are a polymorphic
// directoryObject collection (@odata.type discriminates), so these branches are
// real per Graph, but m7kni's directory roles currently hold ONLY user members
// (all 14 are #microsoft.graph.user — see liveRolesCapture, which is the
// authority for the real user-member shape). Keep these so principal_app_id and
// the sparse-omit path stay covered; do not treat their placeholder values
// (alice@example.com, u1) as measured.
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

// DOCS-DERIVED, not measured. The live #165 capture only reaches
// GET /directoryRoles and GET /directoryRoles/{id}/members — it carries no PIM
// schedule-instance data (this tenant surfaced no active/eligible assignments on
// those two endpoints). These PIM bodies therefore remain hand-written to keep
// the P2 active/eligible/permanent/unknown-roleDefinition branches covered; their
// principalId values (p1..p4) are placeholders, not tenant principals.
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

// liveRolesCapture is a VERBATIM capture of GET /directoryRoles joined with, per
// role, GET /directoryRoles/{id}/members, from the m7kni tenant, read as
// graph2otel-poller on 2026-07-17 `[live-measured 2026-07-17, #165]`. It is a
// JSON array of {role, members} objects: 16 activated directory roles, 12 with
// members, 14 standing members in total — every one a #microsoft.graph.user.
//
// It is pinned, not hand-written, for the reason #165 exists: the previous
// standing-member fixture used Microsoft's documentation placeholders
// (alice@example.com / u1 / Alice Example), so the mapper's user-member path had
// never once been driven by a real directoryObject off the wire — the same class
// of unverified fixture that let #142's `"platform": "windows"` and #153's
// invented `riskType` key survive green. This capture is the authority for the
// real shape; the constructed gaMembersBody/hdMembersBody above only cover the
// service-principal (appId) and sparse-member branches this tenant does not hold.
//
// Note what real records carry that the collector deliberately does NOT map
// (identity is the log twin's job, not a full profile — #112): mail, mobilePhone,
// businessPhones, givenName, surname, jobTitle, officeLocation, preferredLanguage
// on each member, and description/roleTemplateId/deletedDateTime on each role.
// For a guest the emitted userPrincipalName is the mangled #EXT# form
// (peter.hewitt_grafana.com#EXT#@m7knio.onmicrosoft.com), NOT the friendly mail
// (peter.hewitt@grafana.com) — the UPN is the stable identifier, so this is the
// correct choice, but it is what a "who holds Cloud App Admin" query returns.
//
// The capture carries no PIM schedule-instance data — the two roleManagement
// endpoints are a separate fetch, still exercised only by the docs-derived
// active/eligibleInstancesBody above.
const liveRolesCapture = `[
  {
    "members": [
      {
        "@odata.type": "#microsoft.graph.user",
        "businessPhones": [],
        "displayName": "Rob Knight",
        "givenName": "Rob",
        "id": "bbcfc3c5-0b93-4135-9ef9-18477a9fb504",
        "jobTitle": null,
        "mail": "rob@m7kni.io",
        "mobilePhone": null,
        "officeLocation": null,
        "preferredLanguage": "en",
        "surname": "Knight",
        "userPrincipalName": "rob@m7kni.io"
      }
    ],
    "role": {
      "deletedDateTime": null,
      "description": "Manage or purge data from Microsoft 365 when accessing from the Microsoft Purview portal.",
      "displayName": "Purview Workload Content Administrator",
      "id": "0241dab5-463c-4d69-8f45-539ad645168c",
      "roleTemplateId": "3f04f91a-4ad7-4bd3-bcfa-49882ea1a88a"
    }
  },
  {
    "members": [
      {
        "@odata.type": "#microsoft.graph.user",
        "businessPhones": [],
        "displayName": "Rob Knight",
        "givenName": "Rob",
        "id": "bbcfc3c5-0b93-4135-9ef9-18477a9fb504",
        "jobTitle": null,
        "mail": "rob@m7kni.io",
        "mobilePhone": null,
        "officeLocation": null,
        "preferredLanguage": "en",
        "surname": "Knight",
        "userPrincipalName": "rob@m7kni.io"
      },
      {
        "@odata.type": "#microsoft.graph.user",
        "businessPhones": [],
        "displayName": "emergency",
        "givenName": null,
        "id": "c55ddc8b-52ee-44c6-a0bc-b388be43cd2f",
        "jobTitle": null,
        "mail": null,
        "mobilePhone": null,
        "officeLocation": null,
        "preferredLanguage": null,
        "surname": null,
        "userPrincipalName": "emergency@m7knio.onmicrosoft.com"
      }
    ],
    "role": {
      "deletedDateTime": null,
      "description": "Can manage all aspects of Microsoft Entra ID and Microsoft services that use Microsoft Entra identities.",
      "displayName": "Global Administrator",
      "id": "13c082e4-25d5-4de9-979c-2ae90a4fe77b",
      "roleTemplateId": "62e90394-69f5-4237-9190-012177145e10"
    }
  },
  {
    "members": [
      {
        "@odata.type": "#microsoft.graph.user",
        "businessPhones": [],
        "displayName": "Peter Hewitt",
        "givenName": null,
        "id": "e755e472-f2eb-4ea6-829d-5a908600fdb1",
        "jobTitle": null,
        "mail": "peter.hewitt@grafana.com",
        "mobilePhone": null,
        "officeLocation": null,
        "preferredLanguage": null,
        "surname": null,
        "userPrincipalName": "peter.hewitt_grafana.com#EXT#@m7knio.onmicrosoft.com"
      }
    ],
    "role": {
      "deletedDateTime": null,
      "description": "Can create and manage all aspects of app registrations and enterprise apps except App Proxy.",
      "displayName": "Cloud Application Administrator",
      "id": "2359615f-b41d-4005-9ea2-19374c1aff22",
      "roleTemplateId": "158c047a-c907-4556-b7ef-446551a6b5f7"
    }
  },
  {
    "members": [
      {
        "@odata.type": "#microsoft.graph.user",
        "businessPhones": [],
        "displayName": "Rob Knight",
        "givenName": "Rob",
        "id": "bbcfc3c5-0b93-4135-9ef9-18477a9fb504",
        "jobTitle": null,
        "mail": "rob@m7kni.io",
        "mobilePhone": null,
        "officeLocation": null,
        "preferredLanguage": "en",
        "surname": "Knight",
        "userPrincipalName": "rob@m7kni.io"
      }
    ],
    "role": {
      "deletedDateTime": null,
      "description": "Creates and manages compliance content.",
      "displayName": "Compliance Data Administrator",
      "id": "5e440ad5-f447-4f49-92ba-c5e1cdd07c5b",
      "roleTemplateId": "e6d1a23a-da11-4be4-9570-befc86d067a7"
    }
  },
  {
    "members": [],
    "role": {
      "deletedDateTime": null,
      "description": "Can manage all aspects of the Exchange product.",
      "displayName": "Exchange Administrator",
      "id": "77e9970e-ec42-47ab-b1c8-a6dc279b1c5b",
      "roleTemplateId": "29232cdf-9323-42fd-ade2-1d097af3e4de"
    }
  },
  {
    "members": [
      {
        "@odata.type": "#microsoft.graph.user",
        "businessPhones": [],
        "displayName": "Rob Knight",
        "givenName": "Rob",
        "id": "bbcfc3c5-0b93-4135-9ef9-18477a9fb504",
        "jobTitle": null,
        "mail": "rob@m7kni.io",
        "mobilePhone": null,
        "officeLocation": null,
        "preferredLanguage": "en",
        "surname": "Knight",
        "userPrincipalName": "rob@m7kni.io"
      }
    ],
    "role": {
      "deletedDateTime": null,
      "description": "Can read sign-in and audit reports.",
      "displayName": "Reports Reader",
      "id": "7d37cc01-48d5-4d33-9ab2-60d17c54ad73",
      "roleTemplateId": "4a5d8f65-41da-4de4-8968-e035b65339cf"
    }
  },
  {
    "members": [
      {
        "@odata.type": "#microsoft.graph.user",
        "businessPhones": [],
        "displayName": "Rob Knight",
        "givenName": "Rob",
        "id": "bbcfc3c5-0b93-4135-9ef9-18477a9fb504",
        "jobTitle": null,
        "mail": "rob@m7kni.io",
        "mobilePhone": null,
        "officeLocation": null,
        "preferredLanguage": "en",
        "surname": "Knight",
        "userPrincipalName": "rob@m7kni.io"
      },
      {
        "@odata.type": "#microsoft.graph.user",
        "businessPhones": [],
        "displayName": "emergency",
        "givenName": null,
        "id": "c55ddc8b-52ee-44c6-a0bc-b388be43cd2f",
        "jobTitle": null,
        "mail": null,
        "mobilePhone": null,
        "officeLocation": null,
        "preferredLanguage": null,
        "surname": null,
        "userPrincipalName": "emergency@m7knio.onmicrosoft.com"
      }
    ],
    "role": {
      "deletedDateTime": null,
      "description": "Security Administrator allows ability to read and manage security configuration and reports.",
      "displayName": "Security Administrator",
      "id": "8fb230f3-536b-4139-aff6-6fbe3c8eb80c",
      "roleTemplateId": "194ae4cb-b126-40b2-bd5b-6091b380977d"
    }
  },
  {
    "members": [
      {
        "@odata.type": "#microsoft.graph.user",
        "businessPhones": [],
        "displayName": "Rob Knight",
        "givenName": "Rob",
        "id": "bbcfc3c5-0b93-4135-9ef9-18477a9fb504",
        "jobTitle": null,
        "mail": "rob@m7kni.io",
        "mobilePhone": null,
        "officeLocation": null,
        "preferredLanguage": "en",
        "surname": "Knight",
        "userPrincipalName": "rob@m7kni.io"
      }
    ],
    "role": {
      "deletedDateTime": null,
      "description": "Can manage all aspects of the Cloud App Security product.",
      "displayName": "Cloud App Security Administrator",
      "id": "97b9d181-f83c-4c7e-9629-176fbb324377",
      "roleTemplateId": "892c5842-a9a6-463a-8041-72aa08ca3cf6"
    }
  },
  {
    "members": [
      {
        "@odata.type": "#microsoft.graph.user",
        "businessPhones": [],
        "displayName": "Rob Knight",
        "givenName": "Rob",
        "id": "bbcfc3c5-0b93-4135-9ef9-18477a9fb504",
        "jobTitle": null,
        "mail": "rob@m7kni.io",
        "mobilePhone": null,
        "officeLocation": null,
        "preferredLanguage": "en",
        "surname": "Knight",
        "userPrincipalName": "rob@m7kni.io"
      }
    ],
    "role": {
      "deletedDateTime": null,
      "description": "Creates and manages security events.",
      "displayName": "Security Operator",
      "id": "a45ca9c5-7759-42c8-b032-a1b176a641bd",
      "roleTemplateId": "5f2222b1-57c3-48ba-8ad5-d4759f1fde6f"
    }
  },
  {
    "members": [],
    "role": {
      "deletedDateTime": null,
      "description": "Users assigned to this role are added to the local administrators group on Microsoft Entra joined devices.",
      "displayName": "Azure AD Joined Device Local Administrator",
      "id": "ae7cdd8e-c30f-4e17-a61b-ef92c501af17",
      "roleTemplateId": "9f06204d-73c1-4d4c-880a-6edb90606fd8"
    }
  },
  {
    "members": [
      {
        "@odata.type": "#microsoft.graph.user",
        "businessPhones": [],
        "displayName": "Rob Knight",
        "givenName": "Rob",
        "id": "bbcfc3c5-0b93-4135-9ef9-18477a9fb504",
        "jobTitle": null,
        "mail": "rob@m7kni.io",
        "mobilePhone": null,
        "officeLocation": null,
        "preferredLanguage": "en",
        "surname": "Knight",
        "userPrincipalName": "rob@m7kni.io"
      }
    ],
    "role": {
      "deletedDateTime": null,
      "description": "Can read security information and reports in Microsoft Entra ID and Office 365.",
      "displayName": "Security Reader",
      "id": "db6b1cdd-bb95-4b74-87a0-355a847e95e0",
      "roleTemplateId": "5d6b6bb7-de71-4623-b4af-96380a352509"
    }
  },
  {
    "members": [
      {
        "@odata.type": "#microsoft.graph.user",
        "businessPhones": [],
        "displayName": "Rob Knight",
        "givenName": "Rob",
        "id": "bbcfc3c5-0b93-4135-9ef9-18477a9fb504",
        "jobTitle": null,
        "mail": "rob@m7kni.io",
        "mobilePhone": null,
        "officeLocation": null,
        "preferredLanguage": "en",
        "surname": "Knight",
        "userPrincipalName": "rob@m7kni.io"
      }
    ],
    "role": {
      "deletedDateTime": null,
      "description": "Can manage all aspects of the Intune product.",
      "displayName": "Intune Administrator",
      "id": "ebe793f7-0493-4a51-829a-db4e747fc635",
      "roleTemplateId": "3a2c62db-5318-420d-8d74-23affee5d9d5"
    }
  },
  {
    "members": [],
    "role": {
      "deletedDateTime": null,
      "description": "Can read basic directory information. Commonly used to grant directory read access to applications and guests.",
      "displayName": "Directory Readers",
      "id": "ef8df17e-5739-47de-9835-7488a01bdd55",
      "roleTemplateId": "88d8e3e3-8f55-4a1e-953a-9b9898b8876b"
    }
  },
  {
    "members": [],
    "role": {
      "deletedDateTime": null,
      "description": "Read and edit data from Microsoft 365 when accessing from the Microsoft Purview portal.",
      "displayName": "Purview Workload Content Writer",
      "id": "f6c6461b-08a5-4c27-939f-bd60624169ce",
      "roleTemplateId": "02d5655b-c1cf-4e5f-98da-5fb919085bf6"
    }
  },
  {
    "members": [
      {
        "@odata.type": "#microsoft.graph.user",
        "businessPhones": [],
        "displayName": "Rob Knight",
        "givenName": "Rob",
        "id": "bbcfc3c5-0b93-4135-9ef9-18477a9fb504",
        "jobTitle": null,
        "mail": "rob@m7kni.io",
        "mobilePhone": null,
        "officeLocation": null,
        "preferredLanguage": "en",
        "surname": "Knight",
        "userPrincipalName": "rob@m7kni.io"
      }
    ],
    "role": {
      "deletedDateTime": null,
      "description": "Can read and manage compliance configuration and reports in Microsoft Entra ID and Microsoft 365.",
      "displayName": "Compliance Administrator",
      "id": "f81f2c57-5b19-4c2f-8ab1-717daf8e9e68",
      "roleTemplateId": "17315797-102d-40b4-93e0-432062caca18"
    }
  },
  {
    "members": [
      {
        "@odata.type": "#microsoft.graph.user",
        "businessPhones": [],
        "displayName": "Juraj Michalek (babe)",
        "givenName": "Juraj",
        "id": "61851b42-fef7-4b43-ae43-4e335a60b306",
        "jobTitle": null,
        "mail": "juraj@m7kni.io",
        "mobilePhone": null,
        "officeLocation": null,
        "preferredLanguage": null,
        "surname": "Michalek",
        "userPrincipalName": "juraj@m7kni.io"
      }
    ],
    "role": {
      "deletedDateTime": null,
      "description": "Can manage the Microsoft Teams service.",
      "displayName": "Teams Administrator",
      "id": "f8c70379-e0e4-445b-873f-ffcb842c89ef",
      "roleTemplateId": "69091246-20e8-4a56-aa4d-066075b2a7a8"
    }
  }
]`

// liveGraphFromCapture reconstructs the two-level fetch the collector drives
// (GET /directoryRoles, then per role GET /directoryRoles/{id}/members) out of
// the verbatim liveRolesCapture, so real directoryObject records reach the
// mapper byte-for-byte. Role and member JSON is carried as json.RawMessage and
// re-emitted unmodified inside each endpoint's {"value":[...]} envelope — no
// field is normalized on the way through.
func liveGraphFromCapture(t *testing.T) *fakeGraph {
	t.Helper()
	var caps []struct {
		Role    json.RawMessage   `json:"role"`
		Members []json.RawMessage `json:"members"`
	}
	if err := json.Unmarshal([]byte(liveRolesCapture), &caps); err != nil {
		t.Fatalf("decode live capture: %v", err)
	}

	bodies := map[string]string{}
	roles := make([]string, 0, len(caps))
	for _, c := range caps {
		roles = append(roles, string(c.Role))

		var idOnly struct {
			ID string `json:"id"`
		}
		if err := json.Unmarshal(c.Role, &idOnly); err != nil {
			t.Fatalf("decode role id: %v", err)
		}
		members := make([]string, 0, len(c.Members))
		for _, m := range c.Members {
			members = append(members, string(m))
		}
		bodies[base+"/directoryRoles/"+idOnly.ID+"/members"] = `{"value": [` + strings.Join(members, ",") + `]}`
	}
	bodies[directoryRolesURL] = `{"value": [` + strings.Join(roles, ",") + `]}`
	return &fakeGraph{bodies: bodies}
}

// TestCollectorEmitsLiveStandingMembersEndToEnd drives the verbatim #165 capture
// through Collect into a Recorder on the Free tier (no PIM), proving the mapper's
// standing user-member path handles the real wire — the exact thing the old
// docs-derived fixture could not do. Every value asserted here is a real tenant
// principal.
func TestCollectorEmitsLiveStandingMembersEndToEnd(t *testing.T) {
	rec := telemetrytest.New()
	if err := New(liveGraphFromCapture(t), license.Capabilities{}, nil).Collect(context.Background(), rec.Emitter()); err != nil {
		t.Fatalf("Collect: %v", err)
	}

	// One gauge series per activated role, including the 4 empty ones (count 0);
	// per-role counts match the capture.
	gauges := map[string]float64{}
	for _, p := range rec.MetricPoints(membersMetricName) {
		gauges[p.Attrs["role_name"]] = p.Value
	}
	wantGauges := map[string]float64{
		"Purview Workload Content Administrator":     1,
		"Global Administrator":                       2,
		"Cloud Application Administrator":            1,
		"Compliance Data Administrator":              1,
		"Exchange Administrator":                     0,
		"Reports Reader":                             1,
		"Security Administrator":                     2,
		"Cloud App Security Administrator":           1,
		"Security Operator":                          1,
		"Azure AD Joined Device Local Administrator": 0,
		"Security Reader":                            1,
		"Intune Administrator":                       1,
		"Directory Readers":                          0,
		"Purview Workload Content Writer":            0,
		"Compliance Administrator":                   1,
		"Teams Administrator":                        1,
	}
	if len(gauges) != len(wantGauges) {
		t.Fatalf("got %d role gauge series, want %d: %v", len(gauges), len(wantGauges), gauges)
	}
	for role, v := range wantGauges {
		if gauges[role] != v {
			t.Errorf("members[%s] = %v, want %v", role, gauges[role], v)
		}
	}

	// 14 standing twins total — one per real member, none for the empty roles.
	twins := logsNamed(rec.LogRecords(), eventRoleMember)
	standing := 0
	for _, r := range twins {
		if r.Attrs["assignment_type"] != "standing" {
			t.Errorf("unexpected non-standing twin on Free tier: %v", r.Attrs)
			continue
		}
		standing++
	}
	if standing != 14 {
		t.Fatalf("got %d standing twins, want 14 (sum of members across the 12 populated roles)", standing)
	}

	// Teams Administrator has exactly one member, so its twin is unambiguous:
	// pin the full attribute set a real user member produces. No principal_app_id
	// (users carry no appId) — the exact-set discipline that catches a fabricated
	// or dropped attribute.
	var juraj *telemetrytest.LogRecord
	for i := range twins {
		if twins[i].Attrs["role_id"] == "f8c70379-e0e4-445b-873f-ffcb842c89ef" {
			juraj = &twins[i]
		}
	}
	if juraj == nil {
		t.Fatal("no twin for the Teams Administrator member")
	}
	gotKeys := make([]string, 0, len(juraj.Attrs))
	for k := range juraj.Attrs {
		gotKeys = append(gotKeys, k)
	}
	sort.Strings(gotKeys)
	wantKeys := []string{
		"assignment_type",
		"principal_display_name",
		"principal_id",
		"principal_type",
		"principal_user_principal_name",
		"role_id",
		"role_name",
	}
	if !reflect.DeepEqual(gotKeys, wantKeys) {
		t.Errorf("real user-member twin key set\n got: %v\nwant: %v", gotKeys, wantKeys)
	}
	wantAttrs := map[string]string{
		"assignment_type":               "standing",
		"role_name":                     "Teams Administrator",
		"role_id":                       "f8c70379-e0e4-445b-873f-ffcb842c89ef",
		"principal_id":                  "61851b42-fef7-4b43-ae43-4e335a60b306",
		"principal_type":                "user",
		"principal_display_name":        "Juraj Michalek (babe)",
		"principal_user_principal_name": "juraj@m7kni.io",
	}
	for k, want := range wantAttrs {
		if got := juraj.Attrs[k]; got != want {
			t.Errorf("twin attr %q = %q, want %q", k, got, want)
		}
	}
}

// TestLiveGuestMemberEmitsExtUpnNotMail pins the guest-principal wire fact behind
// this fixture: a B2B guest (Peter Hewitt) carries a friendly mail
// (peter.hewitt@grafana.com) alongside a mangled #EXT# userPrincipalName, and the
// collector emits the UPN, never the mail. This is the correct stable identifier,
// but it is what a "who holds Cloud App Admin" query returns, so it is pinned
// rather than left implicit — and it documents that mail is present-and-unmapped
// on real records by design (#112), not by oversight.
func TestLiveGuestMemberEmitsExtUpnNotMail(t *testing.T) {
	rec := telemetrytest.New()
	if err := New(liveGraphFromCapture(t), license.Capabilities{}, nil).Collect(context.Background(), rec.Emitter()); err != nil {
		t.Fatalf("Collect: %v", err)
	}

	var guest *telemetrytest.LogRecord
	for _, r := range logsNamed(rec.LogRecords(), eventRoleMember) {
		if r.Attrs["principal_id"] == "e755e472-f2eb-4ea6-829d-5a908600fdb1" {
			r := r
			guest = &r
		}
	}
	if guest == nil {
		t.Fatal("no twin for the guest member Peter Hewitt")
	}
	if got, want := guest.Attrs["principal_user_principal_name"], "peter.hewitt_grafana.com#EXT#@m7knio.onmicrosoft.com"; got != want {
		t.Errorf("guest UPN = %q, want the #EXT# form %q", got, want)
	}
	for k, v := range guest.Attrs {
		if v == "peter.hewitt@grafana.com" {
			t.Errorf("attr %q = %q; the friendly mail is deliberately unmapped, only the UPN is emitted", k, v)
		}
	}
}
