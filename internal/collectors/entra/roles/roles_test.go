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

const gaMembersBody = `{"value": [{"id": "u1"}, {"id": "u2"}]}`
const hdMembersBody = `{"value": [{"id": "u3"}]}`

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
	want := map[string]float64{"Global Administrator": 2, "Helpdesk Administrator": 1}
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
