package agentgovernance

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"
	"testing"

	"github.com/rknightion/graph2otel/internal/collectors"
	"github.com/rknightion/graph2otel/internal/telemetrytest"
)

// fakeGraph is a URL-keyed fake, mirroring appownership's multi-endpoint test
// style. It also records every URL requested, so tests can assert the shape
// of the requests themselves (never combining $expand=sponsors,owners — a
// live-measured 400, see the package doc).
type fakeGraph struct {
	bodies map[string]string
	errs   map[string]error
	called []string
}

func (f *fakeGraph) RawGet(ctx context.Context, url string) ([]byte, error) {
	return f.RawGetWithHeaders(ctx, url, nil)
}

func (f *fakeGraph) RawGetWithHeaders(_ context.Context, url string, _ map[string]string) ([]byte, error) {
	f.called = append(f.called, url)
	if err, ok := f.errs[url]; ok {
		return nil, err
	}
	body, ok := f.bodies[url]
	if !ok {
		return nil, fmt.Errorf("fakeGraph: no body stubbed for %s", url)
	}
	return []byte(body), nil
}

var _ collectors.GraphClient = (*fakeGraph)(nil)

const v1 = "https://graph.microsoft.com/v1.0"

func mustReadFile(t *testing.T, name string) string {
	t.Helper()
	b, err := os.ReadFile("testdata/" + name)
	if err != nil {
		t.Fatalf("read testdata/%s: %v", name, err)
	}
	return string(b)
}

// liveGraph builds a fakeGraph stubbed with the four VERBATIM live captures
// `[live-measured 2026-07-28, #333]`: 1 blueprint, 2 blueprint principals, and
// 3 agents (returned in a DIFFERENT ORDER between the sponsors and owners
// fetches — see agents_owners.json — to prove the join is keyed on id, not
// list position).
func liveGraph(t *testing.T) *fakeGraph {
	t.Helper()
	return &fakeGraph{bodies: map[string]string{
		v1 + blueprintsPath:     mustReadFile(t, "blueprints.json"),
		v1 + principalsPath:     mustReadFile(t, "blueprint_principals.json"),
		v1 + agentsSponsorsPath: mustReadFile(t, "agents_sponsors.json"),
		v1 + agentsOwnersPath:   mustReadFile(t, "agents_owners.json"),
	}}
}

// (1) All four live captures driven end-to-end through the real collector.
func TestCollectEmitsInventoryCounts(t *testing.T) {
	rec := telemetrytest.New()
	if err := New(liveGraph(t), nil).Collect(context.Background(), rec.Emitter(), nil); err != nil {
		t.Fatalf("Collect: %v", err)
	}

	bp := rec.MetricPoints(metricBlueprintsTotal)
	if len(bp) != 1 || bp[0].Value != 1 {
		t.Fatalf("blueprints.total = %+v, want a single point with value 1", bp)
	}

	var principalTotal float64
	for _, p := range rec.MetricPoints(metricBlueprintPrincipals) {
		principalTotal += p.Value
	}
	if principalTotal != 2 {
		t.Errorf("blueprint_principals total = %v, want 2", principalTotal)
	}

	var agentTotal float64
	for _, p := range rec.MetricPoints(metricAgents) {
		agentTotal += p.Value
	}
	if agentTotal != 3 {
		t.Errorf("agents total = %v, want 3", agentTotal)
	}

	var blueprintTwins, principalTwins, agentTwins int
	for _, r := range rec.LogRecords() {
		switch r.EventName {
		case eventBlueprint:
			blueprintTwins++
		case eventBlueprintPrincipal:
			principalTwins++
		case eventAgentIdentity:
			agentTwins++
		}
	}
	if blueprintTwins != 1 || principalTwins != 2 || agentTwins != 3 {
		t.Errorf("twin counts = blueprint=%d principal=%d agent=%d, want 1/2/3", blueprintTwins, principalTwins, agentTwins)
	}
}

// (2) The zero-owner agent: without_owner=1, owner_ids absent (not empty),
// owner_count=0 — all three, since any one alone can pass over a wrong mapper.
func TestCollectZeroOwnerAgentIsExact(t *testing.T) {
	rec := telemetrytest.New()
	if err := New(liveGraph(t), nil).Collect(context.Background(), rec.Emitter(), nil); err != nil {
		t.Fatalf("Collect: %v", err)
	}

	pts := rec.MetricPoints(metricAgentsWithoutOwner)
	if len(pts) != 1 || pts[0].Value != 1 {
		t.Fatalf("agents.without_owner = %+v, want a single point with value 1", pts)
	}

	var grafana *telemetrytest.LogRecord
	for _, r := range rec.LogRecords() {
		if r.EventName == eventAgentIdentity && r.Attrs["id"] == "b587ba6a-06b7-46b8-bcb0-26ac17ae43a3" {
			r := r
			grafana = &r
			break
		}
	}
	if grafana == nil {
		t.Fatal("no agent twin for the zero-owner agent")
	}
	if _, ok := grafana.Attrs["owner_ids"]; ok {
		t.Errorf("owner_ids present = %q, want absent for zero owners", grafana.Attrs["owner_ids"])
	}
	if got, want := grafana.Attrs["owner_count"], "0"; got != want {
		t.Errorf("owner_count = %q, want %q", got, want)
	}
	// This agent DOES have a sponsor: sponsor_ids must still be present.
	if got := grafana.Attrs["sponsor_ids"]; got == "" {
		t.Errorf("sponsor_ids missing on the zero-owner agent, which has one sponsor")
	}
}

// (3) The sponsors/owners join is keyed on agent id: agents_owners.json
// returns the SAME three agents in a DIFFERENT order than
// agents_sponsors.json. A positional join would attach the wrong owner to
// the wrong agent (or the zero-owner agent's empty slice to the wrong
// record). Pin that "testagent" (order position 2 in sponsors, position 2 in
// owners after the reordering) gets exactly its own owner, and the
// zero-owner agent (last in sponsors, first in owners) is the one with no
// owner.
func TestCollectJoinsSponsorsAndOwnersByIdNotPosition(t *testing.T) {
	rec := telemetrytest.New()
	if err := New(liveGraph(t), nil).Collect(context.Background(), rec.Emitter(), nil); err != nil {
		t.Fatalf("Collect: %v", err)
	}

	byID := map[string]telemetrytest.LogRecord{}
	for _, r := range rec.LogRecords() {
		if r.EventName == eventAgentIdentity {
			byID[r.Attrs["id"]] = r
		}
	}

	robsBlueprint, ok := byID["20ab59ca-9775-4b98-a90b-c23c2620dc3b"]
	if !ok {
		t.Fatal("missing robs-blueprint agent twin")
	}
	if got := robsBlueprint.Attrs["owner_ids"]; got != "bbcfc3c5-0b93-4135-9ef9-18477a9fb504" {
		t.Errorf("robs-blueprint owner_ids = %q, want the sponsor's id (joined by id)", got)
	}

	grafana, ok := byID["b587ba6a-06b7-46b8-bcb0-26ac17ae43a3"]
	if !ok {
		t.Fatal("missing grafana agent twin")
	}
	if _, present := grafana.Attrs["owner_ids"]; present {
		t.Errorf("grafana agent owner_ids present = %q, want absent — a positional join would have attached robs-blueprint's owner here", grafana.Attrs["owner_ids"])
	}
}

// (4) An expanded sponsor's extra directory fields (business phone, mobile
// phone, mail, UPN) appear NOWHERE in any emitted attribute — asserted
// against the full fixture, which carries those fields precisely to prove
// this.
func TestCollectNeverLeaksSponsorDirectoryFields(t *testing.T) {
	rec := telemetrytest.New()
	if err := New(liveGraph(t), nil).Collect(context.Background(), rec.Emitter(), nil); err != nil {
		t.Fatalf("Collect: %v", err)
	}

	forbidden := []string{"+447869113493", "rob@m7kni.io"}
	for _, r := range rec.LogRecords() {
		for k, v := range r.Attrs {
			for _, f := range forbidden {
				if strings.Contains(v, f) {
					t.Errorf("event %s attr %s=%q leaks a sponsor/owner directory field %q", r.EventName, k, v, f)
				}
			}
		}
	}
	for _, name := range rec.MetricNames() {
		for _, p := range rec.MetricPoints(name) {
			for _, v := range p.Attrs {
				for _, f := range forbidden {
					if strings.Contains(v, f) {
						t.Errorf("metric %s attr value %q leaks a sponsor/owner directory field %q", name, v, f)
					}
				}
			}
		}
	}
}

// (5a) Absent-is-not-false, the absent half: an agent with accountEnabled
// absent omits the attribute and does not emit "false".
func TestCollectAgentAccountEnabledAbsentIsOmitted(t *testing.T) {
	const body = `{"value": [
		{"id": "a1", "displayName": "no-flag-agent", "agentIdentityBlueprintId": "bp1"}
	]}`
	g := &fakeGraph{bodies: map[string]string{
		v1 + blueprintsPath:     `{"value": []}`,
		v1 + principalsPath:     `{"value": []}`,
		v1 + agentsSponsorsPath: body,
		v1 + agentsOwnersPath:   body,
	}}
	rec := telemetrytest.New()
	if err := New(g, nil).Collect(context.Background(), rec.Emitter(), nil); err != nil {
		t.Fatalf("Collect: %v", err)
	}
	var twin *telemetrytest.LogRecord
	for _, r := range rec.LogRecords() {
		if r.EventName == eventAgentIdentity {
			r := r
			twin = &r
			break
		}
	}
	if twin == nil {
		t.Fatal("no agent twin emitted")
	}
	if _, ok := twin.Attrs["account_enabled"]; ok {
		t.Errorf("account_enabled present = %q, want absent (wire omitted it)", twin.Attrs["account_enabled"])
	}
}

// (5b) Absent-is-not-false, the false half: an agent with a wire `false` DOES
// emit false, and the metric label reads "false" too (not "unknown").
func TestCollectAgentAccountEnabledFalseIsEmitted(t *testing.T) {
	const body = `{"value": [
		{"id": "a1", "displayName": "disabled-agent", "agentIdentityBlueprintId": "bp1", "accountEnabled": false, "appRoleAssignmentRequired": false}
	]}`
	g := &fakeGraph{bodies: map[string]string{
		v1 + blueprintsPath:     `{"value": []}`,
		v1 + principalsPath:     `{"value": []}`,
		v1 + agentsSponsorsPath: body,
		v1 + agentsOwnersPath:   body,
	}}
	rec := telemetrytest.New()
	if err := New(g, nil).Collect(context.Background(), rec.Emitter(), nil); err != nil {
		t.Fatalf("Collect: %v", err)
	}
	var twin *telemetrytest.LogRecord
	for _, r := range rec.LogRecords() {
		if r.EventName == eventAgentIdentity {
			r := r
			twin = &r
			break
		}
	}
	if twin == nil {
		t.Fatal("no agent twin emitted")
	}
	if got, want := twin.Attrs["account_enabled"], "false"; got != want {
		t.Errorf("account_enabled = %q, want %q", got, want)
	}
	pts := rec.MetricPoints(metricAgents)
	found := false
	for _, p := range pts {
		if p.Attrs["account_enabled"] == "false" {
			found = true
		}
	}
	if !found {
		t.Errorf("no agents series with account_enabled=false, got %+v", pts)
	}
}

// (6) Independent degradation: the blueprint fetch failing still emits the
// agent inventory (blueprints down does not stop agents).
func TestCollectBlueprintFailureStillEmitsAgents(t *testing.T) {
	g := liveGraph(t)
	g.errs = map[string]error{v1 + blueprintsPath: errors.New("throttled")}

	rec := telemetrytest.New()
	err := New(g, nil).Collect(context.Background(), rec.Emitter(), nil)
	if err == nil {
		t.Fatal("expected Collect to surface the blueprint fetch error")
	}

	var agentTotal float64
	for _, p := range rec.MetricPoints(metricAgents) {
		agentTotal += p.Value
	}
	if agentTotal != 3 {
		t.Errorf("agents total after blueprint failure = %v, want 3 (independent degradation)", agentTotal)
	}
	if pts := rec.MetricPoints(metricBlueprintsTotal); len(pts) != 0 {
		t.Errorf("blueprints.total emitted %v after its own fetch failed, want none", pts)
	}
}

// (6) Independent degradation: the sponsors fetch failing still emits agents,
// but emits no has_sponsor value that would read as a governance gap — no
// "false", and no fabricated agents.without_sponsor count.
func TestCollectSponsorsFailureNeverReadsAsGovernanceGap(t *testing.T) {
	g := liveGraph(t)
	g.errs = map[string]error{v1 + agentsSponsorsPath: errors.New("throttled")}

	rec := telemetrytest.New()
	err := New(g, nil).Collect(context.Background(), rec.Emitter(), nil)
	if err == nil {
		t.Fatal("expected Collect to surface the sponsors fetch error")
	}

	var agentTotal float64
	for _, p := range rec.MetricPoints(metricAgents) {
		if p.Attrs["has_sponsor"] == "false" {
			t.Errorf("has_sponsor=false emitted after the sponsors fetch failed — an unknown must never read as a governance gap: %+v", p)
		}
		agentTotal += p.Value
	}
	if agentTotal != 3 {
		t.Errorf("agents total after sponsors failure = %v, want 3", agentTotal)
	}
	if pts := rec.MetricPoints(metricAgentsWithoutSponsor); len(pts) != 0 {
		t.Errorf("agents.without_sponsor emitted %v after the sponsors fetch failed, want none (not a fabricated count)", pts)
	}
	for _, r := range rec.LogRecords() {
		if r.EventName == eventAgentIdentity {
			if _, ok := r.Attrs["sponsor_ids"]; ok {
				t.Errorf("sponsor_ids present on twin %v after the sponsors fetch failed", r.Attrs)
			}
			if _, ok := r.Attrs["sponsor_count"]; ok {
				t.Errorf("sponsor_count present on twin %v after the sponsors fetch failed", r.Attrs)
			}
		}
	}
}

// (7) Pagination on @odata.nextLink for each of the three collections. One
// representative collection (blueprints) is enough to pin the mechanism —
// collectBlueprints/collectBlueprintPrincipals/collectAgents all delegate to
// the shared collectors.GetAllValuesRecorded helper for pagination, so this
// exercises the same code path all three call through.
func TestCollectFollowsNextLinkPagination(t *testing.T) {
	const page1 = `{"value": [{"id": "bp1", "appId": "app1", "displayName": "first"}], "@odata.nextLink": "` + v1 + blueprintsPath + `&$skip=1"}`
	const page2 = `{"value": [{"id": "bp2", "appId": "app2", "displayName": "second"}]}`

	g := &fakeGraph{bodies: map[string]string{
		v1 + blueprintsPath:              page1,
		v1 + blueprintsPath + "&$skip=1": page2,
		v1 + principalsPath:              `{"value": []}`,
		v1 + agentsSponsorsPath:          `{"value": []}`,
		v1 + agentsOwnersPath:            `{"value": []}`,
	}}
	rec := telemetrytest.New()
	if err := New(g, nil).Collect(context.Background(), rec.Emitter(), nil); err != nil {
		t.Fatalf("Collect: %v", err)
	}
	pts := rec.MetricPoints(metricBlueprintsTotal)
	if len(pts) != 1 || pts[0].Value != 2 {
		t.Fatalf("blueprints.total = %+v, want a single point with value 2 (both pages)", pts)
	}
}

// (8) $expand=sponsors,owners is never requested in a single URL — a
// live-measured 400 (see package doc) and a natural "optimization" for a
// later reader to reintroduce. Assert the two agent-identity URLs actually
// requested are exactly the single-property $expand forms.
func TestCollectNeverCombinesExpandInOneRequest(t *testing.T) {
	g := liveGraph(t)
	rec := telemetrytest.New()
	if err := New(g, nil).Collect(context.Background(), rec.Emitter(), nil); err != nil {
		t.Fatalf("Collect: %v", err)
	}
	for _, u := range g.called {
		if strings.Contains(u, "sponsors") && strings.Contains(u, "owners") {
			t.Fatalf("requested URL combines both expands: %s", u)
		}
		if strings.Contains(u, "$expand=") && strings.Contains(u, ",") {
			t.Fatalf("requested URL expands more than one property: %s", u)
		}
	}
	var sawSponsors, sawOwners bool
	for _, u := range g.called {
		if u == v1+agentsSponsorsPath {
			sawSponsors = true
		}
		if u == v1+agentsOwnersPath {
			sawOwners = true
		}
	}
	if !sawSponsors || !sawOwners {
		t.Fatalf("expected both single-property expand requests, called=%v", g.called)
	}
}

func TestCollectSurfacesTotalFailure(t *testing.T) {
	g := &fakeGraph{errs: map[string]error{
		v1 + blueprintsPath:     errors.New("throttled"),
		v1 + principalsPath:     errors.New("throttled"),
		v1 + agentsSponsorsPath: errors.New("throttled"),
		v1 + agentsOwnersPath:   errors.New("throttled"),
	}}
	rec := telemetrytest.New()
	err := New(g, nil).Collect(context.Background(), rec.Emitter(), nil)
	if err == nil {
		t.Fatal("expected Collect to surface every fetch error")
	}
	if names := rec.MetricNames(); len(names) != 0 {
		t.Errorf("metrics emitted after total failure: %v", names)
	}
}

func TestNameIntervalAndPermissions(t *testing.T) {
	c := New(&fakeGraph{}, nil)
	if c.Name() != "entra.agent_governance" {
		t.Errorf("Name = %q", c.Name())
	}
	if c.DefaultInterval() <= 0 {
		t.Errorf("DefaultInterval = %v, want positive", c.DefaultInterval())
	}
	perms := c.RequiredPermissions()
	if len(perms) != 1 || perms[0] != "Application.Read.All" {
		t.Errorf("RequiredPermissions = %v, want [Application.Read.All]", perms)
	}
}
