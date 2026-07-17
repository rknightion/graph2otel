package directorycounts

import (
	"context"
	"errors"
	"testing"

	"github.com/rknightion/graph2otel/internal/collectors"
	"github.com/rknightion/graph2otel/internal/telemetrytest"
)

// fakeGraph maps request URLs to canned $count bodies (or errors) and records
// the ConsistencyLevel header seen on each request.
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
	return []byte(f.bodies[url]), nil
}

var _ collectors.GraphClient = (*fakeGraph)(nil)

const base = "https://graph.microsoft.com/v1.0"

// allCounts returns the canned $count bodies for every directory object type.
//
// count-only collector — wire is a scalar $count integer per filter, no record
// shape to pin; docs-provenance N/A (#165).
func allCounts() map[string]string {
	return map[string]string{
		base + "/users/$count":             "100",
		base + "/groups/$count":            "20",
		base + "/devices/$count":           "50",
		base + "/servicePrincipals/$count": "7",
		base + "/applications/$count":      "3",
	}
}

func TestCollectEmitsOneSeriesPerType(t *testing.T) {
	g := &fakeGraph{bodies: allCounts()}
	rec := telemetrytest.New()

	c := New(g, nil)
	if err := c.Collect(context.Background(), rec.Emitter()); err != nil {
		t.Fatalf("Collect: %v", err)
	}

	pts := rec.MetricPoints(metricName)
	got := map[string]float64{}
	for _, p := range pts {
		got[p.Attrs["type"]] = p.Value
	}
	want := map[string]float64{
		"user": 100, "group": 20, "device": 50, "service_principal": 7, "application": 3,
	}
	if len(got) != len(want) {
		t.Fatalf("got %d series, want %d: %v", len(got), len(want), got)
	}
	for typ, v := range want {
		if got[typ] != v {
			t.Errorf("series type=%s value = %v, want %v", typ, got[typ], v)
		}
	}
}

func TestCollectSetsConsistencyLevelOnEveryRequest(t *testing.T) {
	g := &fakeGraph{bodies: allCounts()}
	rec := telemetrytest.New()

	if err := New(g, nil).Collect(context.Background(), rec.Emitter()); err != nil {
		t.Fatalf("Collect: %v", err)
	}
	for url, cl := range g.seenHeaders {
		if cl != "eventual" {
			t.Errorf("request %s had ConsistencyLevel=%q, want eventual", url, cl)
		}
	}
	if len(g.seenHeaders) != 5 {
		t.Errorf("saw %d requests, want 5", len(g.seenHeaders))
	}
}

func TestCollectIsResilientToPerTypeError(t *testing.T) {
	g := &fakeGraph{
		bodies: allCounts(),
		errs:   map[string]error{base + "/devices/$count": errors.New("throttled")},
	}
	rec := telemetrytest.New()

	// A single type failing must surface as a (non-fatal) error but MUST NOT
	// stop the other types from being emitted.
	err := New(g, nil).Collect(context.Background(), rec.Emitter())
	if err == nil {
		t.Error("expected Collect to surface the per-type failure as an error")
	}

	pts := rec.MetricPoints(metricName)
	if len(pts) != 4 {
		t.Fatalf("got %d series, want 4 (devices failed, others survived)", len(pts))
	}
	for _, p := range pts {
		if p.Attrs["type"] == "device" {
			t.Error("device series should be absent when its count failed")
		}
	}
}

func TestNameAndPermissions(t *testing.T) {
	c := New(&fakeGraph{}, nil)
	if c.Name() != "entra.directory_counts" {
		t.Errorf("Name = %q", c.Name())
	}
	perms := c.RequiredPermissions()
	if len(perms) != 1 || perms[0] != "Directory.Read.All" {
		t.Errorf("RequiredPermissions = %v, want [Directory.Read.All]", perms)
	}
}
