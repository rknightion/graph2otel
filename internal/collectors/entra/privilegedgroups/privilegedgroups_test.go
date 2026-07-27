package privilegedgroups

import (
	"context"
	"errors"
	"testing"

	"github.com/rknightion/graph2otel/internal/collectors"
	"github.com/rknightion/graph2otel/internal/telemetrytest"
)

// fakeGraph maps request URLs to canned $count bodies (or errors), mirroring
// the groups package's fake — count-only collector, no record shape to pin.
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
		return nil, errors.New("fakeGraph: no canned response for " + url)
	}
	return []byte(body), nil
}

var _ collectors.GraphClient = (*fakeGraph)(nil)

const base = "https://graph.microsoft.com/v1.0"

const (
	groupA = "11111111-1111-1111-1111-111111111111"
	groupB = "22222222-2222-2222-2222-222222222222"
)

func TestCollectEmitsMemberCountAndAccessibleForEachConfiguredGroup(t *testing.T) {
	g := &fakeGraph{bodies: map[string]string{
		memberCountURL(base, groupA): "7",
		memberCountURL(base, groupB): "3",
	}}
	rec := telemetrytest.New()

	c := New(g, []string{groupA, groupB}, nil)
	if err := c.Collect(context.Background(), rec.Emitter(), nil); err != nil {
		t.Fatalf("Collect: %v", err)
	}

	pts := rec.MetricPoints(metricMembers)
	if len(pts) != 2 {
		t.Fatalf("got %d member-count points, want 2", len(pts))
	}
	byGroup := map[string]float64{}
	for _, p := range pts {
		if len(p.Attrs) != 1 {
			t.Fatalf("point has %d attrs, want exactly 1 (group_id only): %v", len(p.Attrs), p.Attrs)
		}
		byGroup[p.Attrs["group_id"]] = p.Value
	}
	if byGroup[groupA] != 7 {
		t.Errorf("group A member count = %v, want 7", byGroup[groupA])
	}
	if byGroup[groupB] != 3 {
		t.Errorf("group B member count = %v, want 3", byGroup[groupB])
	}

	accPts := rec.MetricPoints(metricAccessible)
	if len(accPts) != 2 {
		t.Fatalf("got %d accessible points, want 2 (one per configured group, success or failure)", len(accPts))
	}
	for _, p := range accPts {
		if p.Value != 1 {
			t.Errorf("accessible point for %v = %v, want 1 (both groups succeeded)", p.Attrs, p.Value)
		}
	}
}

// TestInaccessibleGroupIsDistinguishableFromZeroMembers is the acceptance-
// criterion test: a group graph2otel cannot read must never silently report 0
// members. It must be absent from the member-count gauge this cycle AND
// explicitly flagged inaccessible on the accessible gauge, so an operator
// cannot mistake "could not look" for "looked, found nobody".
func TestInaccessibleGroupIsDistinguishableFromZeroMembers(t *testing.T) {
	g := &fakeGraph{
		bodies: map[string]string{
			memberCountURL(base, groupA): "0", // genuinely zero members — must still emit
		},
		errs: map[string]error{
			memberCountURL(base, groupB): errors.New("graphclient: GET x: status 404: not found"),
		},
	}
	rec := telemetrytest.New()

	c := New(g, []string{groupA, groupB}, nil)
	if err := c.Collect(context.Background(), rec.Emitter(), nil); err == nil {
		t.Fatal("expected Collect to surface the inaccessible group as an error")
	}

	memberPts := rec.MetricPoints(metricMembers)
	if len(memberPts) != 1 {
		t.Fatalf("got %d member-count points, want 1 (only the accessible group)", len(memberPts))
	}
	if memberPts[0].Attrs["group_id"] != groupA || memberPts[0].Value != 0 {
		t.Errorf("member point = %+v, want group A with value 0 (a real, measured zero)", memberPts[0])
	}
	for _, p := range memberPts {
		if p.Attrs["group_id"] == groupB {
			t.Fatal("inaccessible group B must not appear in the member-count gauge at all, not even as 0")
		}
	}

	accPts := rec.MetricPoints(metricAccessible)
	if len(accPts) != 2 {
		t.Fatalf("got %d accessible points, want 2 (every configured group reports accessibility every cycle)", len(accPts))
	}
	acc := map[string]float64{}
	for _, p := range accPts {
		acc[p.Attrs["group_id"]] = p.Value
	}
	if acc[groupA] != 1 {
		t.Errorf("group A accessible = %v, want 1", acc[groupA])
	}
	if acc[groupB] != 0 {
		t.Errorf("group B accessible = %v, want 0 (inaccessible)", acc[groupB])
	}

	// The log twin must name WHICH group failed and WHY, since the accessible
	// gauge alone cannot carry a reason string.
	logs := rec.LogRecords()
	var sawFailure bool
	for _, l := range logs {
		if l.Attrs["group_id"] == groupB {
			sawFailure = true
			if l.Attrs["accessible"] != "false" {
				t.Errorf("group B log twin accessible attr = %q, want false", l.Attrs["accessible"])
			}
			if l.Attrs["reason"] != "not_found" {
				t.Errorf("group B log twin reason = %q, want not_found", l.Attrs["reason"])
			}
			if l.SeverityText != "WARN" {
				t.Errorf("group B log twin severity = %q, want WARN", l.SeverityText)
			}
		}
	}
	if !sawFailure {
		t.Fatal("no log twin emitted for the inaccessible group")
	}
}

func TestCollectEmitsOneLogTwinPerConfiguredGroup(t *testing.T) {
	g := &fakeGraph{bodies: map[string]string{
		memberCountURL(base, groupA): "7",
		memberCountURL(base, groupB): "3",
	}}
	rec := telemetrytest.New()

	if err := New(g, []string{groupA, groupB}, nil).Collect(context.Background(), rec.Emitter(), nil); err != nil {
		t.Fatalf("Collect: %v", err)
	}

	logs := rec.LogRecords()
	if len(logs) != 2 {
		t.Fatalf("got %d log records, want 2 (one per configured group)", len(logs))
	}
	for _, l := range logs {
		if l.EventName != eventPrivilegedGroup {
			t.Errorf("event name = %q, want %q", l.EventName, eventPrivilegedGroup)
		}
	}
}

func TestNoAllowlistedGroupsCollectIsANoop(t *testing.T) {
	g := &fakeGraph{}
	rec := telemetrytest.New()

	if err := New(g, nil, nil).Collect(context.Background(), rec.Emitter(), nil); err != nil {
		t.Fatalf("Collect with empty allowlist: %v", err)
	}
	if pts := rec.MetricPoints(metricMembers); len(pts) != 0 {
		t.Errorf("got %d member points with no allowlist, want 0", len(pts))
	}
	if pts := rec.MetricPoints(metricAccessible); len(pts) != 0 {
		t.Errorf("got %d accessible points with no allowlist, want 0", len(pts))
	}
}

func TestNameIntervalAndPermissions(t *testing.T) {
	c := New(&fakeGraph{}, nil, nil)
	if c.Name() != "entra.privileged_groups" {
		t.Errorf("Name = %q, want entra.privileged_groups", c.Name())
	}
	if c.DefaultInterval() <= 0 {
		t.Errorf("DefaultInterval = %v, want > 0", c.DefaultInterval())
	}
	perms := c.RequiredPermissions()
	if len(perms) != 1 || perms[0] != "Group.Read.All" {
		t.Errorf("RequiredPermissions = %v, want [Group.Read.All]", perms)
	}
}
