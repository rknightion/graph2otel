package groups

import (
	"context"
	"errors"
	"testing"

	"github.com/rknightion/graph2otel/internal/collectors"
	"github.com/rknightion/graph2otel/internal/telemetrytest"
)

// fakeGraph maps request URLs to canned $count bodies (or errors) and records
// the ConsistencyLevel header seen on each request, mirroring the
// directorycounts reference test's fake.
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
	body, ok := f.bodies[url]
	if !ok {
		return nil, errors.New("fakeGraph: no canned response for " + url)
	}
	return []byte(body), nil
}

var _ collectors.GraphClient = (*fakeGraph)(nil)

const base = "https://graph.microsoft.com/v1.0"

// allCounts returns a canned body for every URL the collector is expected to
// issue: one per groupSlices entry plus the role-assignable count.
//
// count-only collector — wire is a scalar $count integer per filter, no record
// shape to pin; docs-provenance N/A (#165).
func allCounts() map[string]string {
	bodies := map[string]string{
		filterCountURL(base, roleAssignableFilter): "9",
	}
	for i, s := range groupSlices {
		bodies[filterCountURL(base, s.filter)] = countBody(i)
	}
	return bodies
}

// countBody returns a distinct, deterministic canned count per slice index so
// tests can tell series apart.
func countBody(i int) string {
	vals := []string{"12", "34", "5", "1", "20", "22", "18", "24", "30", "12"}
	if i < len(vals) {
		return vals[i]
	}
	return "0"
}

func TestCollectEmitsOneBoundedSeriesPerSlice(t *testing.T) {
	g := &fakeGraph{bodies: allCounts()}
	rec := telemetrytest.New()

	c := New(g, nil)
	if err := c.Collect(context.Background(), rec.Emitter()); err != nil {
		t.Fatalf("Collect: %v", err)
	}

	pts := rec.MetricPoints(totalMetricName)
	if len(pts) != len(groupSlices) {
		t.Fatalf("got %d points for %s, want %d (one per bounded slice)", len(pts), totalMetricName, len(groupSlices))
	}

	// Every point must carry exactly one of the known bounded dimension keys,
	// never a per-group identifier.
	allowedKeys := map[string]bool{
		"group_type": true, "membership_type": true, "security_enabled": true, "mail_enabled": true,
	}
	for _, p := range pts {
		if len(p.Attrs) != 1 {
			t.Fatalf("point has %d attrs, want exactly 1: %v", len(p.Attrs), p.Attrs)
		}
		for k := range p.Attrs {
			if !allowedKeys[k] {
				t.Errorf("unexpected attribute key %q on %s (possible cardinality violation)", k, totalMetricName)
			}
		}
	}
}

func TestCollectEmitsRoleAssignableAsSingleGauge(t *testing.T) {
	g := &fakeGraph{bodies: allCounts()}
	rec := telemetrytest.New()

	if err := New(g, nil).Collect(context.Background(), rec.Emitter()); err != nil {
		t.Fatalf("Collect: %v", err)
	}

	pts := rec.MetricPoints(roleAssignableMetricName)
	if len(pts) != 1 {
		t.Fatalf("got %d points for %s, want 1", len(pts), roleAssignableMetricName)
	}
	if pts[0].Value != 9 {
		t.Errorf("role_assignable value = %v, want 9", pts[0].Value)
	}
	if len(pts[0].Attrs) != 0 {
		t.Errorf("role_assignable point has attrs %v, want none (no per-group dimension)", pts[0].Attrs)
	}
}

func TestCollectSetsConsistencyLevelOnEveryRequest(t *testing.T) {
	g := &fakeGraph{bodies: allCounts()}
	rec := telemetrytest.New()

	if err := New(g, nil).Collect(context.Background(), rec.Emitter()); err != nil {
		t.Fatalf("Collect: %v", err)
	}
	if len(g.seenHeaders) == 0 {
		t.Fatal("no requests observed")
	}
	for url, cl := range g.seenHeaders {
		if cl != "eventual" {
			t.Errorf("request %s had ConsistencyLevel=%q, want eventual", url, cl)
		}
	}
	wantRequests := len(groupSlices) + 1 // +1 for role-assignable
	if len(g.seenHeaders) != wantRequests {
		t.Errorf("saw %d requests, want %d", len(g.seenHeaders), wantRequests)
	}
}

func TestCollectIsResilientToPerSliceError(t *testing.T) {
	bodies := allCounts()
	failing := filterCountURL(base, groupSlices[0].filter)
	g := &fakeGraph{
		bodies: bodies,
		errs:   map[string]error{failing: errors.New("throttled")},
	}
	rec := telemetrytest.New()

	err := New(g, nil).Collect(context.Background(), rec.Emitter())
	if err == nil {
		t.Error("expected Collect to surface the per-slice failure as an error")
	}

	pts := rec.MetricPoints(totalMetricName)
	if len(pts) != len(groupSlices)-1 {
		t.Fatalf("got %d points, want %d (one slice failed)", len(pts), len(groupSlices)-1)
	}

	// The role-assignable gauge (independent request) must still emit.
	rolePts := rec.MetricPoints(roleAssignableMetricName)
	if len(rolePts) != 1 {
		t.Fatalf("got %d role_assignable points, want 1 (independent of the failing slice)", len(rolePts))
	}
}

func TestCollectIsResilientToRoleAssignableError(t *testing.T) {
	bodies := allCounts()
	g := &fakeGraph{
		bodies: bodies,
		errs:   map[string]error{filterCountURL(base, roleAssignableFilter): errors.New("throttled")},
	}
	rec := telemetrytest.New()

	err := New(g, nil).Collect(context.Background(), rec.Emitter())
	if err == nil {
		t.Error("expected Collect to surface the role-assignable failure as an error")
	}

	if pts := rec.MetricPoints(roleAssignableMetricName); len(pts) != 0 {
		t.Errorf("got %d role_assignable points, want 0 when the count call failed", len(pts))
	}
	if pts := rec.MetricPoints(totalMetricName); len(pts) != len(groupSlices) {
		t.Errorf("got %d total points, want %d (unaffected by the role-assignable failure)", len(pts), len(groupSlices))
	}
}

func TestNameIntervalAndPermissions(t *testing.T) {
	c := New(&fakeGraph{}, nil)
	if c.Name() != "entra.groups" {
		t.Errorf("Name = %q, want entra.groups", c.Name())
	}
	if c.DefaultInterval() <= 0 {
		t.Errorf("DefaultInterval = %v, want > 0", c.DefaultInterval())
	}
	perms := c.RequiredPermissions()
	if len(perms) != 1 || perms[0] != "Group.Read.All" {
		t.Errorf("RequiredPermissions = %v, want [Group.Read.All]", perms)
	}
}
