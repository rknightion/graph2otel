package roledefinitions

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"testing"

	"github.com/rknightion/graph2otel/internal/collectors"
	"github.com/rknightion/graph2otel/internal/telemetrytest"
)

// fakeGraph maps request URLs to canned response bodies (or errors), and
// records every URL it was asked for so tests can assert on the exact request
// shape (notably: that $top is never sent - see TestCollectNeverSendsTopParam).
type fakeGraph struct {
	bodies map[string]string
	errs   map[string]error
	calls  []string
}

func (f *fakeGraph) RawGet(_ context.Context, url string) ([]byte, error) {
	f.calls = append(f.calls, url)
	if err, ok := f.errs[url]; ok {
		return nil, err
	}
	if body, ok := f.bodies[url]; ok {
		return []byte(body), nil
	}
	return []byte(`{"value": []}`), nil
}

func (f *fakeGraph) RawGetWithHeaders(ctx context.Context, url string, _ map[string]string) ([]byte, error) {
	return f.RawGet(ctx, url)
}

var _ collectors.GraphClient = (*fakeGraph)(nil)

const base = "https://graph.microsoft.com/v1.0"
const definitionsURL = base + "/roleManagement/directory/roleDefinitions"

// mustReadFile reads a testdata fixture or fails the test. Both fixtures below
// are VERBATIM captures (see their own comments) from the m7kni tenant, read
// as graph2otel-poller on 2026-07-28, `[live-measured 2026-07-28, #320]`.
func mustReadFile(t *testing.T, name string) string {
	t.Helper()
	b, err := os.ReadFile("testdata/" + name)
	if err != nil {
		t.Fatalf("read testdata/%s: %v", name, err)
	}
	return string(b)
}

// TestCollectFullLiveCaptureGaugeSumsTo145 drives the VERBATIM full
// GET /roleManagement/directory/roleDefinitions capture (145 definitions, no
// @odata.nextLink) end-to-end through the real collector into a recorder,
// pinning that every returned definition lands in the gauge. This tenant's
// full catalog is built-in and enabled only (0 custom, 0 disabled), so the
// gauge must carry exactly one bucket: (is_built_in=true, is_enabled=true).
func TestCollectFullLiveCaptureGaugeSumsTo145(t *testing.T) {
	g := &fakeGraph{bodies: map[string]string{definitionsURL: mustReadFile(t, "live_full.json")}}
	rec := telemetrytest.New()

	if err := New(g, nil).Collect(context.Background(), rec.Emitter(), nil); err != nil {
		t.Fatalf("Collect: %v", err)
	}

	pts := rec.MetricPoints(definitionsMetric)
	var sum float64
	for _, p := range pts {
		sum += p.Value
	}
	const wantTotal = 145
	if sum != wantTotal {
		t.Fatalf("gauge sum = %v across %d bucket(s) %+v, want %v", sum, len(pts), pts, wantTotal)
	}
	if len(pts) != 1 {
		t.Fatalf("got %d buckets, want exactly 1 (this tenant has only built-in, enabled roles): %+v", len(pts), pts)
	}
	if pts[0].Attrs["is_built_in"] != "true" || pts[0].Attrs["is_enabled"] != "true" {
		t.Errorf("bucket attrs = %+v, want is_built_in=true is_enabled=true", pts[0].Attrs)
	}

	logs := rec.LogRecords()
	var twins int
	for _, r := range logs {
		if r.EventName == eventDefinition {
			twins++
		}
	}
	if twins != wantTotal {
		t.Errorf("got %d %s log twins, want %d", twins, eventDefinition, wantTotal)
	}
}

// TestCollectNeverSendsTopParam pins the live-measured trap (#320): `$top` at
// ANY value 400s on this endpoint (Request_UnsupportedQuery), so the collector
// must never append it, at any page.
func TestCollectNeverSendsTopParam(t *testing.T) {
	g := &fakeGraph{bodies: map[string]string{definitionsURL: mustReadFile(t, "live_subset.json")}}
	rec := telemetrytest.New()

	if err := New(g, nil).Collect(context.Background(), rec.Emitter(), nil); err != nil {
		t.Fatalf("Collect: %v", err)
	}

	if len(g.calls) == 0 {
		t.Fatal("collector made no requests")
	}
	for _, url := range g.calls {
		if got := url; contains(got, "$top") {
			t.Errorf("request URL %q contains $top, which this endpoint rejects at any value", got)
		}
	}
}

func contains(s, substr string) bool {
	return len(s) >= len(substr) && (func() bool {
		for i := 0; i+len(substr) <= len(s); i++ {
			if s[i:i+len(substr)] == substr {
				return true
			}
		}
		return false
	})()
}

// TestCollect262ActionsNotTruncated pins the live capture's widest role
// (Global Administrator, 262 allowedResourceActions in one rolePermissions
// element - live-measured 2026-07-28) against maxAllowedActions=300: it must
// NOT be truncated, and its inheritsPermissionsFrom (one element, live) must
// come through as a bounded id array.
func TestCollect262ActionsNotTruncated(t *testing.T) {
	g := &fakeGraph{bodies: map[string]string{definitionsURL: mustReadFile(t, "live_subset.json")}}
	rec := telemetrytest.New()

	if err := New(g, nil).Collect(context.Background(), rec.Emitter(), nil); err != nil {
		t.Fatalf("Collect: %v", err)
	}

	ga := findTwin(t, rec, "Global Administrator")
	if got := ga.Attrs["allowed_action_count"]; got != "262" {
		t.Errorf("allowed_action_count = %q, want 262", got)
	}
	if got := ga.Attrs["allowed_actions_truncated"]; got != "false" {
		t.Errorf("allowed_actions_truncated = %q, want false", got)
	}
	if got := ga.Attrs["role_permission_count"]; got != "1" {
		t.Errorf("role_permission_count = %q, want 1", got)
	}
	if got := ga.Attrs["inherits_permissions_from_ids"]; got != "88d8e3e3-8f55-4a1e-953a-9b9898b8876b" {
		t.Errorf("inherits_permissions_from_ids = %q, want the single live inherited id", got)
	}
	if got := ga.Attrs["inherits_permissions_from_truncated"]; got != "false" {
		t.Errorf("inherits_permissions_from_truncated = %q, want false", got)
	}
}

// TestCollect301ActionsIsTruncated is a SYNTHETIC (hand-built, not a live
// capture) single-definition body carrying 301 allowedResourceActions - one
// more than maxAllowedActions=300 - built to exercise the cap deterministically
// rather than waiting for a tenant to grow a wider built-in role than the
// widest one observed (Global Administrator, 262). It must be truncated to
// exactly 300 while allowed_action_count still reports the true, uncapped 301.
func TestCollect301ActionsIsTruncated(t *testing.T) {
	actions := make([]string, 301)
	for i := range actions {
		actions[i] = fmt.Sprintf("microsoft.directory/synthetic/action%d", i)
	}
	body := synthDefinitionsBody(t, []synthDef{{
		ID: "synthetic-301", DisplayName: "Synthetic Wide Role", IsBuiltIn: false, IsEnabled: true,
		RolePermissions: [][]string{actions},
	}})
	g := &fakeGraph{bodies: map[string]string{definitionsURL: body}}
	rec := telemetrytest.New()

	if err := New(g, nil).Collect(context.Background(), rec.Emitter(), nil); err != nil {
		t.Fatalf("Collect: %v", err)
	}

	twin := findTwin(t, rec, "Synthetic Wide Role")
	if got := twin.Attrs["allowed_action_count"]; got != "301" {
		t.Errorf("allowed_action_count = %q, want the TRUE uncapped 301", got)
	}
	if got := twin.Attrs["allowed_actions_truncated"]; got != "true" {
		t.Errorf("allowed_actions_truncated = %q, want true", got)
	}
	gotActions, ok := twin.Attrs["allowed_actions"]
	if !ok {
		t.Fatal("allowed_actions missing")
	}
	// The recorder flattens []string attrs to a comma-joined string; count the
	// commas plus one rather than assuming the exact separator, so this
	// assertion survives a recorder formatting change.
	n := countCSVFields(gotActions)
	if n != maxAllowedActions {
		t.Errorf("allowed_actions holds %d entries, want exactly the cap %d", n, maxAllowedActions)
	}
}

// TestCollectZeroRolePermissionsOmitsAllowedActions pins Device Join - a live
// 2026-07-28 row with an EMPTY rolePermissions array - through the real
// mapper: allowed_action_count must report the true 0, and allowed_actions
// must be ABSENT entirely (an omitted attribute, not a present-but-empty
// array), matching this collector's "absence is absence" convention.
func TestCollectZeroRolePermissionsOmitsAllowedActions(t *testing.T) {
	g := &fakeGraph{bodies: map[string]string{definitionsURL: mustReadFile(t, "live_subset.json")}}
	rec := telemetrytest.New()

	if err := New(g, nil).Collect(context.Background(), rec.Emitter(), nil); err != nil {
		t.Fatalf("Collect: %v", err)
	}

	dj := findTwin(t, rec, "Device Join")
	if got := dj.Attrs["allowed_action_count"]; got != "0" {
		t.Errorf("allowed_action_count = %q, want 0", got)
	}
	if got := dj.Attrs["role_permission_count"]; got != "0" {
		t.Errorf("role_permission_count = %q, want 0", got)
	}
	if _, ok := dj.Attrs["allowed_actions"]; ok {
		t.Errorf("allowed_actions present = %q, want absent for an empty rolePermissions array", dj.Attrs["allowed_actions"])
	}
	if _, ok := dj.Attrs["allowed_actions_truncated"]; ok {
		t.Errorf("allowed_actions_truncated present, want absent alongside the omitted array")
	}
}

// TestCollectFlattensRealMultiElementRolePermissions pins live rows with MORE
// THAN ONE rolePermissions element - "User" (3 elements: 70+86+16=172 live
// 2026-07-28) and "Guest User" (2 elements: 24+24=48) - proving the mapper
// sums EVERY element rather than reading only the first (under-flattening) or
// double-counting (over-flattening). Both are real tenant data, not
// synthesized, so this is also evidence the live catalog actually exercises
// the multi-element shape the #320 brief calls out.
func TestCollectFlattensRealMultiElementRolePermissions(t *testing.T) {
	g := &fakeGraph{bodies: map[string]string{definitionsURL: mustReadFile(t, "live_subset.json")}}
	rec := telemetrytest.New()

	if err := New(g, nil).Collect(context.Background(), rec.Emitter(), nil); err != nil {
		t.Fatalf("Collect: %v", err)
	}

	user := findTwin(t, rec, "User")
	if got := user.Attrs["allowed_action_count"]; got != "172" {
		t.Errorf("User allowed_action_count = %q, want 172 (70+86+16 across 3 elements)", got)
	}
	if got := user.Attrs["role_permission_count"]; got != "3" {
		t.Errorf("User role_permission_count = %q, want 3", got)
	}

	guest := findTwin(t, rec, "Guest User")
	if got := guest.Attrs["allowed_action_count"]; got != "48" {
		t.Errorf("Guest User allowed_action_count = %q, want 48 (24+24 across 2 elements)", got)
	}
	if got := guest.Attrs["role_permission_count"]; got != "2" {
		t.Errorf("Guest User role_permission_count = %q, want 2", got)
	}
}

// TestCollectFlattensSyntheticTwoByTwoRolePermissions is the minimal SYNTHETIC
// case the #320 brief calls out by name: 2 rolePermissions elements of 2
// actions each must yield 4, not 2 - wrong in either direction (reading only
// one element, or treating the outer array's length as the action count) is a
// silent, opposite-sign bug.
func TestCollectFlattensSyntheticTwoByTwoRolePermissions(t *testing.T) {
	body := synthDefinitionsBody(t, []synthDef{{
		ID: "synthetic-2x2", DisplayName: "Synthetic Two By Two", IsBuiltIn: false, IsEnabled: true,
		RolePermissions: [][]string{
			{"microsoft.directory/a/create", "microsoft.directory/a/delete"},
			{"microsoft.directory/b/create", "microsoft.directory/b/delete"},
		},
	}})
	g := &fakeGraph{bodies: map[string]string{definitionsURL: body}}
	rec := telemetrytest.New()

	if err := New(g, nil).Collect(context.Background(), rec.Emitter(), nil); err != nil {
		t.Fatalf("Collect: %v", err)
	}

	twin := findTwin(t, rec, "Synthetic Two By Two")
	if got := twin.Attrs["allowed_action_count"]; got != "4" {
		t.Fatalf("allowed_action_count = %q, want 4 (2 elements x 2 actions each)", got)
	}
}

// TestCollectFollowsPaginationAcrossTwoPages is a SYNTHETIC two-page fixture
// (the live capture returns everything in one page with no @odata.nextLink,
// so this exercises a code path the live tenant does not currently reach).
// Both pages' definitions must be emitted.
func TestCollectFollowsPaginationAcrossTwoPages(t *testing.T) {
	page2URL := definitionsURL + "?$skiptoken=page2"
	page1 := fmt.Sprintf(`{"value":[{"id":"d1","templateId":"d1","displayName":"Page One Role","isBuiltIn":true,"isEnabled":true,"resourceScopes":["/"],"rolePermissions":[]}],"@odata.nextLink":%q}`, page2URL)
	page2 := `{"value":[{"id":"d2","templateId":"d2","displayName":"Page Two Role","isBuiltIn":true,"isEnabled":true,"resourceScopes":["/"],"rolePermissions":[]}]}`

	g := &fakeGraph{bodies: map[string]string{
		definitionsURL: page1,
		page2URL:       page2,
	}}
	rec := telemetrytest.New()

	if err := New(g, nil).Collect(context.Background(), rec.Emitter(), nil); err != nil {
		t.Fatalf("Collect: %v", err)
	}

	pts := rec.MetricPoints(definitionsMetric)
	var sum float64
	for _, p := range pts {
		sum += p.Value
	}
	if sum != 2 {
		t.Fatalf("gauge sum = %v, want 2 (one definition per page)", sum)
	}
	findTwin(t, rec, "Page One Role")
	findTwin(t, rec, "Page Two Role")
	if len(g.calls) != 2 {
		t.Fatalf("got %d requests, want exactly 2 (one per page): %v", len(g.calls), g.calls)
	}
}

// TestCollectFetchErrorNeverEmitsPartialGauge pins that a transport failure
// propagates as an error and emits NOTHING - a partial gauge from whatever
// happened to be buffered before the failure would read as "the tenant has
// fewer roles now", which is worse than reporting nothing this cycle.
func TestCollectFetchErrorNeverEmitsPartialGauge(t *testing.T) {
	g := &fakeGraph{errs: map[string]error{definitionsURL: errors.New("throttled")}}
	rec := telemetrytest.New()

	err := New(g, nil).Collect(context.Background(), rec.Emitter(), nil)
	if err == nil {
		t.Fatal("expected Collect to surface the fetch error")
	}
	if pts := rec.MetricPoints(definitionsMetric); len(pts) != 0 {
		t.Errorf("got %d gauge points after a fetch error, want 0", len(pts))
	}
	if logs := rec.LogRecords(); len(logs) != 0 {
		t.Errorf("got %d log records after a fetch error, want 0", len(logs))
	}
}

// TestCollectSecondPageErrorNeverEmitsPartialGauge is the same guarantee as
// above, but with the failure on the SECOND page - proving the collector
// discards page-1 results already buffered rather than emitting a
// partial/wrong-lower count.
func TestCollectSecondPageErrorNeverEmitsPartialGauge(t *testing.T) {
	page2URL := definitionsURL + "?$skiptoken=page2"
	page1 := fmt.Sprintf(`{"value":[{"id":"d1","templateId":"d1","displayName":"Page One Role","isBuiltIn":true,"isEnabled":true,"resourceScopes":["/"],"rolePermissions":[]}],"@odata.nextLink":%q}`, page2URL)

	g := &fakeGraph{
		bodies: map[string]string{definitionsURL: page1},
		errs:   map[string]error{page2URL: errors.New("throttled")},
	}
	rec := telemetrytest.New()

	err := New(g, nil).Collect(context.Background(), rec.Emitter(), nil)
	if err == nil {
		t.Fatal("expected Collect to surface the second-page fetch error")
	}
	if pts := rec.MetricPoints(definitionsMetric); len(pts) != 0 {
		t.Errorf("got %d gauge points after a second-page fetch error, want 0", len(pts))
	}
}

// TestCollectDecodeErrorSurfaces pins that an unparseable response is
// surfaced as an error rather than silently producing an empty snapshot.
func TestCollectDecodeErrorSurfaces(t *testing.T) {
	g := &fakeGraph{bodies: map[string]string{definitionsURL: "not json"}}
	rec := telemetrytest.New()

	if err := New(g, nil).Collect(context.Background(), rec.Emitter(), nil); err == nil {
		t.Fatal("expected Collect to surface the decode error")
	}
}

// TestCollectUnrecognizedActionStringNeverDropsDefinition pins the
// acceptance criterion explicitly: an action string this collector has never
// seen before (it validates nothing about the RBAC action namespace) rides
// through unchanged and must never be grounds to drop the whole definition.
func TestCollectUnrecognizedActionStringNeverDropsDefinition(t *testing.T) {
	body := synthDefinitionsBody(t, []synthDef{{
		ID: "synthetic-weird", DisplayName: "Synthetic Weird Action Role", IsBuiltIn: true, IsEnabled: true,
		RolePermissions: [][]string{{"microsoft.directory/totallyMadeUp/doAThing"}},
	}})
	g := &fakeGraph{bodies: map[string]string{definitionsURL: body}}
	rec := telemetrytest.New()

	if err := New(g, nil).Collect(context.Background(), rec.Emitter(), nil); err != nil {
		t.Fatalf("Collect: %v", err)
	}

	twin := findTwin(t, rec, "Synthetic Weird Action Role")
	if got := twin.Attrs["allowed_actions"]; got != "microsoft.directory/totallyMadeUp/doAThing" {
		t.Errorf("allowed_actions = %q, want the unrecognized action string emitted as-is", got)
	}
	if got := twin.Attrs["allowed_action_count"]; got != "1" {
		t.Errorf("allowed_action_count = %q, want 1", got)
	}
}

func TestNameAndPermissions(t *testing.T) {
	c := New(&fakeGraph{}, nil)
	if c.Name() != "entra.role_definitions" {
		t.Errorf("Name = %q", c.Name())
	}
	perms := c.RequiredPermissions()
	if len(perms) != 1 || perms[0] != "RoleManagement.Read.Directory" {
		t.Errorf("RequiredPermissions = %v, want [RoleManagement.Read.Directory]", perms)
	}
}

func TestDefaultInterval(t *testing.T) {
	c := New(&fakeGraph{}, nil)
	if c.DefaultInterval() <= 0 {
		t.Errorf("DefaultInterval = %v, want positive", c.DefaultInterval())
	}
}

// findTwin locates the entra.role_definition twin with the given
// display_name, failing the test if none is found.
func findTwin(t *testing.T, rec *telemetrytest.Recorder, displayName string) telemetrytest.LogRecord {
	t.Helper()
	for _, r := range rec.LogRecords() {
		if r.EventName == eventDefinition && r.Attrs["display_name"] == displayName {
			return r
		}
	}
	t.Fatalf("no %s log twin found for display_name=%q", eventDefinition, displayName)
	return telemetrytest.LogRecord{}
}

// countCSVFields counts comma-separated fields in s (s must be non-empty).
func countCSVFields(s string) int {
	if s == "" {
		return 0
	}
	n := 1
	for i := 0; i < len(s); i++ {
		if s[i] == ',' {
			n++
		}
	}
	return n
}

// synthDef is a compact description used to build a SYNTHETIC (hand-built,
// not live) roleDefinitions page body for tests that exercise a boundary
// condition (a cap, a code path) the live tenant does not itself carry.
type synthDef struct {
	ID              string
	DisplayName     string
	IsBuiltIn       bool
	IsEnabled       bool
	RolePermissions [][]string // one []string per rolePermissions element
}

// synthDefinitionsBody marshals defs as a roleDefinitions collection response
// body, matching the wire shape roledefinitions.go decodes.
func synthDefinitionsBody(t *testing.T, defs []synthDef) string {
	t.Helper()
	type wireRolePermission struct {
		AllowedResourceActions []string `json:"allowedResourceActions"`
	}
	type wireDef struct {
		ID              string               `json:"id"`
		TemplateID      string               `json:"templateId"`
		DisplayName     string               `json:"displayName"`
		IsBuiltIn       bool                 `json:"isBuiltIn"`
		IsEnabled       bool                 `json:"isEnabled"`
		ResourceScopes  []string             `json:"resourceScopes"`
		RolePermissions []wireRolePermission `json:"rolePermissions"`
	}
	wire := struct {
		Value []wireDef `json:"value"`
	}{}
	for _, d := range defs {
		wd := wireDef{
			ID: d.ID, TemplateID: d.ID, DisplayName: d.DisplayName,
			IsBuiltIn: d.IsBuiltIn, IsEnabled: d.IsEnabled,
			ResourceScopes: []string{"/"},
		}
		for _, actions := range d.RolePermissions {
			wd.RolePermissions = append(wd.RolePermissions, wireRolePermission{AllowedResourceActions: actions})
		}
		wire.Value = append(wire.Value, wd)
	}
	b, err := json.Marshal(wire)
	if err != nil {
		t.Fatalf("marshal synthetic definitions body: %v", err)
	}
	return string(b)
}
