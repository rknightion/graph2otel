package rbac

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/rknightion/graph2otel/internal/collectors"
	"github.com/rknightion/graph2otel/internal/semconv"
	"github.com/rknightion/graph2otel/internal/telemetrytest"
)

// fakeGraph maps request URLs to canned page bodies (or errors), satisfying
// collectors.GraphClient so Collector runs through collectors.GetAllValues with
// no live Graph call.
type fakeGraph struct {
	bodies map[string]string
	errs   map[string]error
	// seen records every URL requested, so the fan-out shape is assertable.
	seen []string
}

func (f *fakeGraph) RawGet(ctx context.Context, url string) ([]byte, error) {
	return f.RawGetWithHeaders(ctx, url, nil)
}

func (f *fakeGraph) RawGetWithHeaders(_ context.Context, url string, _ map[string]string) ([]byte, error) {
	f.seen = append(f.seen, url)
	if err := f.errs[url]; err != nil {
		return nil, err
	}
	body, ok := f.bodies[url]
	if !ok {
		return nil, fmt.Errorf("fakeGraph: no body for %q", url)
	}
	return []byte(body), nil
}

var _ collectors.GraphClient = (*fakeGraph)(nil)

func definitionsURL() string { return defaultBaseURL + roleDefinitionsPath }
func assignmentsURL() string { return defaultBaseURL + roleAssignmentsPath }
func linkURL(defID string) string {
	return defaultBaseURL + roleDefinitionsPath + "/" + defID + roleAssignmentsSegment
}

// Live role-definition rows, copied VERBATIM off the v1.0 wire (probed as
// graph2otel-poller on m7kni 2026-07-24; the tenant returns 10, three of which
// are reproduced here in full). Note both isBuiltIn and isBuiltInRoleDefinition
// on every row, and that rolePermissions duplicates permissions exactly.
const liveDefinitionRows = `
 {"@odata.type":"#microsoft.graph.deviceAndAppManagementRoleDefinition","id":"9553af24-bd83-4ac3-a339-0e58f9e5478e","displayName":"Endpoint Privilege Reader","description":"Endpoint Privilege Readers can view Endpoint Privilege Management (EPM) policies in the Intune console.","isBuiltInRoleDefinition":true,"isBuiltIn":true,"roleScopeTagIds":[],"permissions":[{"actions":["Microsoft.Intune_Organization_Read","Microsoft.Intune_EpmPolicy_Read","Microsoft.Intune_EpmPolicy_ViewReports","Microsoft.Intune_EpmPolicy_ViewElevationRequests","Microsoft.Intune_ManagedDevices_Read","Microsoft.Intune_AdminTasks_Read"],"resourceActions":[{"allowedResourceActions":["Microsoft.Intune_Organization_Read","Microsoft.Intune_EpmPolicy_Read","Microsoft.Intune_EpmPolicy_ViewReports","Microsoft.Intune_EpmPolicy_ViewElevationRequests","Microsoft.Intune_ManagedDevices_Read","Microsoft.Intune_AdminTasks_Read"],"notAllowedResourceActions":[]}]}],"rolePermissions":[{"actions":["Microsoft.Intune_Organization_Read","Microsoft.Intune_EpmPolicy_Read","Microsoft.Intune_EpmPolicy_ViewReports","Microsoft.Intune_EpmPolicy_ViewElevationRequests","Microsoft.Intune_ManagedDevices_Read","Microsoft.Intune_AdminTasks_Read"],"resourceActions":[{"allowedResourceActions":["Microsoft.Intune_Organization_Read","Microsoft.Intune_EpmPolicy_Read","Microsoft.Intune_EpmPolicy_ViewReports","Microsoft.Intune_EpmPolicy_ViewElevationRequests","Microsoft.Intune_ManagedDevices_Read","Microsoft.Intune_AdminTasks_Read"],"notAllowedResourceActions":[]}]}]},
 {"@odata.type":"#microsoft.graph.deviceAndAppManagementRoleDefinition","id":"c56d53a2-73d0-4502-b6bd-4a9d3dba28d5","displayName":"Endpoint Security Manager","description":"Manages security and compliance features such as security baselines, device compliance, conditional access, and Microsoft Defender for Endpoint.","isBuiltInRoleDefinition":true,"isBuiltIn":true,"roleScopeTagIds":[],"permissions":[{"actions":["Microsoft.Intune_ManagedDevices_Read","Microsoft.Intune_ManagedDevices_Update","Microsoft.Intune_ManagedDevices_Delete"],"resourceActions":[{"allowedResourceActions":["Microsoft.Intune_ManagedDevices_Read","Microsoft.Intune_ManagedDevices_Update","Microsoft.Intune_ManagedDevices_Delete"],"notAllowedResourceActions":[]}]}],"rolePermissions":[{"actions":["Microsoft.Intune_ManagedDevices_Read","Microsoft.Intune_ManagedDevices_Update","Microsoft.Intune_ManagedDevices_Delete"],"resourceActions":[{"allowedResourceActions":["Microsoft.Intune_ManagedDevices_Read","Microsoft.Intune_ManagedDevices_Update","Microsoft.Intune_ManagedDevices_Delete"],"notAllowedResourceActions":[]}]}]},
 {"@odata.type":"#microsoft.graph.deviceAndAppManagementRoleDefinition","id":"fb2603eb-3c87-4be3-8b5b-d58a5b4a0bc0","displayName":"Intune Role Administrator","description":"Intune Role Administrators manage custom Intune roles and add assignments for built-in Intune roles. It is the only Intune role that can assign permissions to Administrators.","isBuiltInRoleDefinition":true,"isBuiltIn":true,"roleScopeTagIds":[],"permissions":[{"actions":["Microsoft.Intune_Organization_Read","Microsoft.Intune_Roles_Create","Microsoft.Intune_Roles_Read","Microsoft.Intune_Roles_Update","Microsoft.Intune_Roles_Delete","Microsoft.Intune_Roles_Assign"],"resourceActions":[{"allowedResourceActions":["Microsoft.Intune_Organization_Read","Microsoft.Intune_Roles_Create","Microsoft.Intune_Roles_Read","Microsoft.Intune_Roles_Update","Microsoft.Intune_Roles_Delete","Microsoft.Intune_Roles_Assign"],"notAllowedResourceActions":[]}]}],"rolePermissions":[{"actions":["Microsoft.Intune_Organization_Read","Microsoft.Intune_Roles_Create","Microsoft.Intune_Roles_Read","Microsoft.Intune_Roles_Update","Microsoft.Intune_Roles_Delete","Microsoft.Intune_Roles_Assign"],"resourceActions":[{"allowedResourceActions":["Microsoft.Intune_Organization_Read","Microsoft.Intune_Roles_Create","Microsoft.Intune_Roles_Read","Microsoft.Intune_Roles_Update","Microsoft.Intune_Roles_Delete","Microsoft.Intune_Roles_Assign"],"notAllowedResourceActions":[]}]}]}`

// customDefinitionRow is the one row on this tenant that does NOT exist: m7kni
// has no custom Intune role, so the whole reason this collector was built —
// a hand-made role with sweeping device rights — is never exercised by live
// data. It is derived from the live shape above with only the two built-in
// flags flipped, `isBuiltInRoleDefinition` deliberately DISAGREEING with
// `isBuiltIn`, and a deny entry populated, so the mapper's assumptions are
// tested rather than assumed (the green-tick rule).
const customDefinitionRow = `
 {"@odata.type":"#microsoft.graph.deviceAndAppManagementRoleDefinition","id":"11111111-2222-3333-4444-555555555555","displayName":"Fleet Wipe Operator","description":null,"isBuiltInRoleDefinition":false,"isBuiltIn":false,"roleScopeTagIds":["0"],"permissions":[{"actions":["Microsoft.Intune_ManagedDevices_Wipe","Microsoft.Intune_ManagedDevices_Retire"],"resourceActions":[{"allowedResourceActions":["Microsoft.Intune_ManagedDevices_Wipe","Microsoft.Intune_ManagedDevices_Retire"],"notAllowedResourceActions":["Microsoft.Intune_ManagedDevices_Delete"]}]}]}`

// liveAssignmentRow is the tenant's single role assignment, verbatim off the
// v1.0 wire. Note `members` is a bare principal guid with no name, and the row
// carries NO reference to the role definition it grants — that link exists only
// through the roleDefinitions/{id}/roleAssignments navigation.
const liveAssignmentRow = `
 {"id":"1257e69a-b38e-4b89-864f-0b1662fc8202","displayName":"MDE Endpoint Security Managers","description":null,"scopeMembers":[],"scopeType":"allDevicesAndLicensedUsers","resourceScopes":[],"members":["c118ea33-87b7-4c8a-9bb3-e72b80bb75dd"],"roleScopeTagIds":[]}`

// customAssignmentRow binds the synthetic custom role at the widest possible
// scope — the exact shape #257 exists to make visible.
const customAssignmentRow = `
 {"id":"99999999-8888-7777-6666-555555555555","displayName":"Fleet Wipe Admins","description":"wipe everything","scopeMembers":["aaaa1111-2222-3333-4444-555555555555"],"scopeType":"allDevicesAndLicensedUsers","resourceScopes":["dddd1111-2222-3333-4444-555555555555"],"members":["bbbb1111-2222-3333-4444-555555555555","cccc1111-2222-3333-4444-555555555555"],"roleScopeTagIds":["0"]}`

// liveGraph wires the live rows plus the synthetic custom role/assignment pair.
// The per-definition roleAssignments navigation returns the assignment TRUNCATED
// (empty members, no scopeType) exactly as the live wire does — the reason the
// full assignment list is fetched separately and joined, rather than read off
// the navigation.
func liveGraph() *fakeGraph {
	return &fakeGraph{bodies: map[string]string{
		definitionsURL(): `{"value":[` + liveDefinitionRows + `,` + customDefinitionRow + `]}`,
		assignmentsURL(): `{"value":[` + liveAssignmentRow + `,` + customAssignmentRow + `]}`,
		linkURL("9553af24-bd83-4ac3-a339-0e58f9e5478e"): `{"value":[]}`,
		linkURL("c56d53a2-73d0-4502-b6bd-4a9d3dba28d5"): `{"value":[{"@odata.type":"#microsoft.graph.deviceAndAppManagementRoleAssignment","id":"1257e69a-b38e-4b89-864f-0b1662fc8202","displayName":"MDE Endpoint Security Managers","description":null,"resourceScopes":[],"members":[]}]}`,
		linkURL("fb2603eb-3c87-4be3-8b5b-d58a5b4a0bc0"): `{"value":[]}`,
		linkURL("11111111-2222-3333-4444-555555555555"): `{"value":[{"@odata.type":"#microsoft.graph.deviceAndAppManagementRoleAssignment","id":"99999999-8888-7777-6666-555555555555","displayName":"Fleet Wipe Admins","description":"wipe everything","resourceScopes":[],"members":[]}]}`,
	}}
}

func collect(t *testing.T, g *fakeGraph) *telemetrytest.Recorder {
	t.Helper()
	rec := telemetrytest.New()
	if err := New(g, nil).Collect(context.Background(), rec.Emitter()); err != nil {
		t.Fatalf("Collect: %v", err)
	}
	return rec
}

func twinFor(t *testing.T, rec *telemetrytest.Recorder, event, attrKey, want string) telemetrytest.LogRecord {
	t.Helper()
	for _, l := range rec.LogRecords() {
		if l.EventName == event && l.Attrs[attrKey] == want {
			return l
		}
	}
	t.Fatalf("no %s twin with %s=%q", event, attrKey, want)
	return telemetrytest.LogRecord{}
}

func TestRoleDefinitionGaugeIsBoundedAndCarriesBothBuiltInFlags(t *testing.T) {
	rec := collect(t, liveGraph())

	points := rec.MetricPoints(definitionsMetricName)
	want := map[[3]string]float64{
		{"true", "true", "deviceAndAppManagementRoleDefinition"}:   3,
		{"false", "false", "deviceAndAppManagementRoleDefinition"}: 1,
	}
	if len(points) != len(want) {
		t.Fatalf("got %d definition series, want %d: %+v", len(points), len(want), points)
	}
	for _, p := range points {
		if p.Kind != "gauge" {
			t.Errorf("metric kind = %q, want gauge", p.Kind)
		}
		key := [3]string{
			fmt.Sprint(p.Attrs[semconv.AttrIsBuiltIn]),
			fmt.Sprint(p.Attrs[semconv.AttrIsBuiltInRoleDefinition]),
			fmt.Sprint(p.Attrs[semconv.AttrRoleDefinitionType]),
		}
		w, ok := want[key]
		if !ok {
			t.Errorf("unexpected series %+v", p.Attrs)
			continue
		}
		if p.Value != w {
			t.Errorf("series %v = %v, want %v", key, p.Value, w)
		}
		delete(want, key)
	}
	if len(want) != 0 {
		t.Errorf("missing series: %v", want)
	}
}

// The two built-in flags are separate gauge dimensions precisely so a
// disagreement shows up as its own series instead of being resolved silently by
// a mapper that assumed one was a rename of the other (#142).
func TestDisagreeingBuiltInFlagsProduceTheirOwnSeries(t *testing.T) {
	g := &fakeGraph{bodies: map[string]string{
		definitionsURL(): `{"value":[{"@odata.type":"#microsoft.graph.deviceAndAppManagementRoleDefinition","id":"d1","displayName":"Skewed","isBuiltIn":true,"isBuiltInRoleDefinition":false,"permissions":[]}]}`,
		assignmentsURL(): `{"value":[]}`,
		linkURL("d1"):    `{"value":[]}`,
	}}
	rec := collect(t, g)

	points := rec.MetricPoints(definitionsMetricName)
	if len(points) != 1 {
		t.Fatalf("got %d series, want 1: %+v", len(points), points)
	}
	if got := fmt.Sprint(points[0].Attrs[semconv.AttrIsBuiltIn]); got != "true" {
		t.Errorf("is_built_in = %q, want true", got)
	}
	if got := fmt.Sprint(points[0].Attrs[semconv.AttrIsBuiltInRoleDefinition]); got != "false" {
		t.Errorf("is_built_in_role_definition = %q, want false — the flags must not be collapsed", got)
	}

	tw := twinFor(t, rec, eventRoleDefinition, semconv.AttrRoleId, "d1")
	if tw.Attrs[semconv.AttrIsBuiltIn] != "true" || tw.Attrs[semconv.AttrIsBuiltInRoleDefinition] != "false" {
		t.Errorf("twin flags = %v/%v, want true/false", tw.Attrs[semconv.AttrIsBuiltIn], tw.Attrs[semconv.AttrIsBuiltInRoleDefinition])
	}
}

func TestRoleAssignmentGaugeIsBoundedByScopeTypeAndBuiltIn(t *testing.T) {
	rec := collect(t, liveGraph())

	points := rec.MetricPoints(assignmentsMetricName)
	want := map[[2]string]float64{
		{"allDevicesAndLicensedUsers", "true"}:  1,
		{"allDevicesAndLicensedUsers", "false"}: 1,
	}
	if len(points) != len(want) {
		t.Fatalf("got %d assignment series, want %d: %+v", len(points), len(want), points)
	}
	for _, p := range points {
		key := [2]string{fmt.Sprint(p.Attrs[semconv.AttrScopeType]), fmt.Sprint(p.Attrs[semconv.AttrIsBuiltIn])}
		w, ok := want[key]
		if !ok {
			t.Errorf("unexpected series %+v", p.Attrs)
			continue
		}
		if p.Value != w {
			t.Errorf("series %v = %v, want %v", key, p.Value, w)
		}
		delete(want, key)
	}
	if len(want) != 0 {
		t.Errorf("missing series: %v", want)
	}
}

func TestRoleDefinitionTwinCarriesTheUnboundedActionList(t *testing.T) {
	rec := collect(t, liveGraph())

	tw := twinFor(t, rec, eventRoleDefinition, semconv.AttrRoleId, "11111111-2222-3333-4444-555555555555")
	if !tw.Timestamp.IsZero() {
		t.Errorf("twin timestamp = %v, want zero (state snapshot, not an event)", tw.Timestamp)
	}
	wantActions := "Microsoft.Intune_ManagedDevices_Retire,Microsoft.Intune_ManagedDevices_Wipe"
	if got := tw.Attrs[semconv.AttrActions]; got != wantActions {
		t.Errorf("actions = %q, want %q (sorted union, never dropped — #114)", got, wantActions)
	}
	if got := tw.Attrs[semconv.AttrNotAllowedActions]; got != "Microsoft.Intune_ManagedDevices_Delete" {
		t.Errorf("not_allowed_actions = %q, want the single deny entry", got)
	}
	if got := tw.Attrs[semconv.AttrAssignmentCount]; got != "1" {
		t.Errorf("assignment_count = %q, want 1", got)
	}
	if got := tw.Attrs[semconv.AttrRoleName]; got != "Fleet Wipe Operator" {
		t.Errorf("role_name = %q", got)
	}
	if _, ok := tw.Attrs[semconv.AttrDescription]; ok {
		t.Errorf("description present for a null wire value: %q", tw.Attrs[semconv.AttrDescription])
	}
	if tw.SeverityText != "INFO" {
		t.Errorf("definition severity = %q, want INFO — a definition grants nothing until it is assigned", tw.SeverityText)
	}
}

// A built-in role's action list is emitted in full: it is the only description
// of what the role can do, and 6 entries here stands in for the 121 the live
// School Administrator row carries.
func TestBuiltInRoleDefinitionTwinKeepsEveryAction(t *testing.T) {
	rec := collect(t, liveGraph())

	tw := twinFor(t, rec, eventRoleDefinition, semconv.AttrRoleId, "fb2603eb-3c87-4be3-8b5b-d58a5b4a0bc0")
	if n := len(strings.Split(tw.Attrs[semconv.AttrActions], ",")); n != 6 {
		t.Errorf("actions = %q (%d entries), want all 6 wire actions", tw.Attrs[semconv.AttrActions], n)
	}
	if _, ok := tw.Attrs[semconv.AttrNotAllowedActions]; ok {
		t.Errorf("not_allowed_actions present for an empty wire deny list: %v", tw.Attrs[semconv.AttrNotAllowedActions])
	}
	if got := tw.Attrs[semconv.AttrAssignmentCount]; got != "0" {
		t.Errorf("assignment_count = %q, want 0", got)
	}
}

func TestWideScopedCustomRoleAssignmentWarns(t *testing.T) {
	rec := collect(t, liveGraph())

	tw := twinFor(t, rec, eventRoleAssignment, semconv.AttrRoleAssignmentId, "99999999-8888-7777-6666-555555555555")
	if tw.SeverityText != "WARN" {
		t.Errorf("severity = %q, want WARN — a custom role at allDevicesAndLicensedUsers", tw.SeverityText)
	}
	if got := tw.Attrs[semconv.AttrRoleName]; got != "Fleet Wipe Operator" {
		t.Errorf("role_name = %q, want the resolved definition name", got)
	}
	if got := tw.Attrs[semconv.AttrRoleId]; got != "11111111-2222-3333-4444-555555555555" {
		t.Errorf("role_id = %q, want the resolved definition id", got)
	}
	wantMembers := "bbbb1111-2222-3333-4444-555555555555,cccc1111-2222-3333-4444-555555555555"
	if got := tw.Attrs[semconv.AttrMembers]; got != wantMembers {
		t.Errorf("members = %q, want %q — guids are emitted verbatim, never resolved to names", got, wantMembers)
	}
	if got := tw.Attrs[semconv.AttrMembersCount]; got != "2" {
		t.Errorf("members_count = %q, want 2", got)
	}
	if got := tw.Attrs[semconv.AttrScopeMembers]; got != "aaaa1111-2222-3333-4444-555555555555" {
		t.Errorf("scope_members = %q, want the single scope group", got)
	}
	if got := tw.Attrs[semconv.AttrResourceScopes]; got != "dddd1111-2222-3333-4444-555555555555" {
		t.Errorf("resource_scopes = %q, want the single resource scope", got)
	}
}

func TestWideScopedBuiltInRoleAssignmentIsInfo(t *testing.T) {
	rec := collect(t, liveGraph())

	tw := twinFor(t, rec, eventRoleAssignment, semconv.AttrRoleAssignmentId, "1257e69a-b38e-4b89-864f-0b1662fc8202")
	if tw.SeverityText != "INFO" {
		t.Errorf("severity = %q, want INFO — a BUILT-IN role at the widest scope is normal", tw.SeverityText)
	}
	if got := tw.Attrs[semconv.AttrRoleName]; got != "Endpoint Security Manager" {
		t.Errorf("role_name = %q, want the resolved definition name", got)
	}
	if got := tw.Attrs[semconv.AttrScopeType]; got != "allDevicesAndLicensedUsers" {
		t.Errorf("scope_type = %q", got)
	}
	if _, ok := tw.Attrs[semconv.AttrScopeMembers]; ok {
		t.Errorf("scope_members present for an empty wire list: %v", tw.Attrs[semconv.AttrScopeMembers])
	}
}

// An assignment whose role definition cannot be resolved at the tenant's widest
// scope is at least as bad as a custom one: something holds tenant-wide device
// management and graph2otel cannot say what it is.
func TestUnresolvedWideScopedAssignmentWarnsAndOmitsRoleFields(t *testing.T) {
	g := &fakeGraph{bodies: map[string]string{
		definitionsURL(): `{"value":[]}`,
		assignmentsURL(): `{"value":[` + liveAssignmentRow + `]}`,
	}}
	rec := collect(t, g)

	tw := twinFor(t, rec, eventRoleAssignment, semconv.AttrRoleAssignmentId, "1257e69a-b38e-4b89-864f-0b1662fc8202")
	if tw.SeverityText != "WARN" {
		t.Errorf("severity = %q, want WARN", tw.SeverityText)
	}
	for _, k := range []string{semconv.AttrRoleId, semconv.AttrRoleName, semconv.AttrIsBuiltIn} {
		if _, ok := tw.Attrs[k]; ok {
			t.Errorf("attribute %q present for an unresolved role definition: %v — an unresolved link must be silent, not guessed", k, tw.Attrs[k])
		}
	}
	points := rec.MetricPoints(assignmentsMetricName)
	if len(points) != 1 || fmt.Sprint(points[0].Attrs[semconv.AttrIsBuiltIn]) != unknownValue {
		t.Errorf("assignment series = %+v, want is_built_in=%q", points, unknownValue)
	}
}

// TestPerEntityFieldsNeverBecomeMetricLabels is the #112/#114 guard: the
// principal guids and the unbounded action list ride the twins, never a metric
// label. signalcapture.Main covers a fixed banned list; this pins THIS
// collector's own per-entity fields.
func TestPerEntityFieldsNeverBecomeMetricLabels(t *testing.T) {
	rec := collect(t, liveGraph())

	banned := map[string]bool{
		semconv.AttrRoleId:            true,
		semconv.AttrRoleName:          true,
		semconv.AttrRoleAssignmentId:  true,
		semconv.AttrDisplayName:       true,
		semconv.AttrActions:           true,
		semconv.AttrNotAllowedActions: true,
		semconv.AttrMembers:           true,
		semconv.AttrScopeMembers:      true,
		semconv.AttrResourceScopes:    true,
		semconv.AttrDescription:       true,
	}
	allowed := map[string]bool{
		semconv.AttrIsBuiltIn:               true,
		semconv.AttrIsBuiltInRoleDefinition: true,
		semconv.AttrRoleDefinitionType:      true,
		semconv.AttrScopeType:               true,
	}
	for _, name := range []string{definitionsMetricName, assignmentsMetricName} {
		for _, p := range rec.MetricPoints(name) {
			for k := range p.Attrs {
				if banned[k] {
					t.Errorf("%s carries per-entity metric label %q — it belongs on the twin (#112/#114)", name, k)
				}
				if !allowed[k] {
					t.Errorf("%s carries unexpected metric label %q", name, k)
				}
			}
		}
	}
}

// The per-definition navigation is the ONLY link between an assignment and the
// role it grants: the assignment row carries no roleDefinitionId, and
// $expand=roleDefinition returns null while silently dropping scopeType,
// scopeMembers and roleScopeTagIds (live-measured 2026-07-24).
func TestLinkFanOutIsOnePerRoleDefinition(t *testing.T) {
	g := liveGraph()
	collect(t, g)

	links := 0
	for _, u := range g.seen {
		if strings.HasPrefix(u, definitionsURL()+"/") && strings.HasSuffix(u, roleAssignmentsSegment) {
			links++
		}
	}
	if links != 4 {
		t.Errorf("issued %d link requests, want one per role definition (4): %v", links, g.seen)
	}
}

// A failing link fetch must not fail the collection or invent a role: that one
// definition's assignments simply stay unresolved.
func TestLinkFetchFailureDegradesToUnresolved(t *testing.T) {
	g := liveGraph()
	g.errs = map[string]error{linkURL("c56d53a2-73d0-4502-b6bd-4a9d3dba28d5"): errors.New("boom")}
	rec := collect(t, g)

	tw := twinFor(t, rec, eventRoleAssignment, semconv.AttrRoleAssignmentId, "1257e69a-b38e-4b89-864f-0b1662fc8202")
	if _, ok := tw.Attrs[semconv.AttrRoleName]; ok {
		t.Errorf("role_name = %v, want it omitted when the link fetch failed", tw.Attrs[semconv.AttrRoleName])
	}
	if tw.SeverityText != "WARN" {
		t.Errorf("severity = %q, want WARN (wide scope, role unknown)", tw.SeverityText)
	}
	// The custom role's link still resolved, so its assignment still names it.
	custom := twinFor(t, rec, eventRoleAssignment, semconv.AttrRoleAssignmentId, "99999999-8888-7777-6666-555555555555")
	if got := custom.Attrs[semconv.AttrRoleName]; got != "Fleet Wipe Operator" {
		t.Errorf("role_name = %q — one failing link must not poison the others", got)
	}
}

func TestForbiddenSkipsGracefully(t *testing.T) {
	g := &fakeGraph{errs: map[string]error{definitionsURL(): errors.New("graphclient: GET ...: status 403: forbidden")}}
	rec := telemetrytest.New()
	if err := New(g, nil).Collect(context.Background(), rec.Emitter()); err != nil {
		t.Fatalf("403 should be a graceful skip, got: %v", err)
	}
	if len(rec.LogRecords()) != 0 || len(rec.MetricPoints(definitionsMetricName)) != 0 {
		t.Error("expected no emissions on 403")
	}
}

func TestDefinitionListErrorIsSurfaced(t *testing.T) {
	g := &fakeGraph{errs: map[string]error{definitionsURL(): errors.New("boom")}}
	if err := New(g, nil).Collect(context.Background(), telemetrytest.New().Emitter()); err == nil {
		t.Error("a non-403 list error must be surfaced")
	}
}

func TestCollectFollowsNextLink(t *testing.T) {
	page2 := definitionsURL() + "?$skiptoken=abc"
	g := &fakeGraph{bodies: map[string]string{
		definitionsURL(): `{"@odata.nextLink":"` + page2 + `","value":[{"id":"d1","displayName":"One","isBuiltIn":true,"isBuiltInRoleDefinition":true,"permissions":[]}]}`,
		page2:            `{"value":[{"id":"d2","displayName":"Two","isBuiltIn":true,"isBuiltInRoleDefinition":true,"permissions":[]}]}`,
		assignmentsURL(): `{"value":[]}`,
		linkURL("d1"):    `{"value":[]}`,
		linkURL("d2"):    `{"value":[]}`,
	}}
	rec := collect(t, g)
	if n := len(rec.LogRecords()); n != 2 {
		t.Fatalf("got %d twins, want 2 (both pages consumed)", n)
	}
}

func TestEmptyTenantEmitsNoTwins(t *testing.T) {
	g := &fakeGraph{bodies: map[string]string{
		definitionsURL(): `{"value":[]}`,
		assignmentsURL(): `{"value":[]}`,
	}}
	rec := collect(t, g)
	if len(rec.LogRecords()) != 0 {
		t.Error("no rows => no twins")
	}
}

func TestCollectorContract(t *testing.T) {
	c := New(nil, nil)
	if c.Name() != collectorName || collectorName != "intune.rbac" {
		t.Errorf("Name() = %q, want intune.rbac", c.Name())
	}
	// Both v1.0 and beta serve these collections (200/200, live-measured
	// 2026-07-24), so this is a v1.0 collector and NOT Experimental (#183).
	if defaultBaseURL != "https://graph.microsoft.com/v1.0" {
		t.Errorf("defaultBaseURL = %q, want the v1.0 root", defaultBaseURL)
	}
	if _, ok := any(c).(collectors.Experimental); ok {
		t.Error("intune.rbac must not implement Experimental: the endpoints are v1.0")
	}
	perms := c.RequiredPermissions()
	if len(perms) != 1 || perms[0] != "DeviceManagementRBAC.Read.All" {
		t.Errorf("RequiredPermissions = %v, want the single read-only RBAC scope", perms)
	}
	if c.DefaultInterval() != 6*time.Hour {
		t.Errorf("DefaultInterval = %v, want 6h", c.DefaultInterval())
	}
}
