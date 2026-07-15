package recommendations

import (
	"context"
	"errors"
	"testing"

	"github.com/rknightion/graph2otel/internal/collectors"
	"github.com/rknightion/graph2otel/internal/telemetrytest"
)

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
	b, ok := f.bodies[url]
	if !ok {
		return nil, errors.New("no canned body for " + url)
	}
	return []byte(b), nil
}

var _ collectors.GraphClient = (*fakeGraph)(nil)

const listURL = "https://graph.microsoft.com/beta/directory/recommendations"

func TestCollectEmitsStatusPriorityAndImpactedCounts(t *testing.T) {
	body := `{"value":[
	  {"recommendationType":"turnOnMFA","status":"active","priority":"high","impactedResources":[{"id":"a"},{"id":"b"}]},
	  {"recommendationType":"turnOnMFA","status":"active","priority":"high","impactedResources":[{"id":"c"}]},
	  {"recommendationType":"removeUnusedApps","status":"dismissed","priority":"low","impactedResources":[]}
	]}`
	g := &fakeGraph{bodies: map[string]string{listURL: body}}
	rec := telemetrytest.New()

	if err := New(g, nil).Collect(context.Background(), rec.Emitter()); err != nil {
		t.Fatalf("Collect: %v", err)
	}

	// status x priority counts
	counts := map[string]float64{}
	for _, p := range rec.MetricPoints(totalMetric) {
		counts[p.Attrs["status"]+"/"+p.Attrs["priority"]] = p.Value
	}
	if counts["active/high"] != 2 {
		t.Errorf("active/high = %v, want 2", counts["active/high"])
	}
	if counts["dismissed/low"] != 1 {
		t.Errorf("dismissed/low = %v, want 1", counts["dismissed/low"])
	}

	// impacted resources by recommendation type
	impacted := map[string]float64{}
	for _, p := range rec.MetricPoints(impactedMetric) {
		impacted[p.Attrs["recommendation"]] = p.Value
	}
	if impacted["turnOnMFA"] != 3 {
		t.Errorf("turnOnMFA impacted = %v, want 3", impacted["turnOnMFA"])
	}
	if impacted["removeUnusedApps"] != 0 {
		t.Errorf("removeUnusedApps impacted = %v, want 0", impacted["removeUnusedApps"])
	}
}

func TestCollectGracefulOn403(t *testing.T) {
	g := &fakeGraph{errs: map[string]error{
		listURL: errors.New("graphclient: GET " + listURL + ": status 403: {\"error\":{\"code\":\"Authorization_RequestDenied\"}}"),
	}}
	rec := telemetrytest.New()

	// A 403 (endpoint unavailable / unlicensed) must be skipped-and-logged, not
	// surfaced as a collector error.
	if err := New(g, nil).Collect(context.Background(), rec.Emitter()); err != nil {
		t.Errorf("Collect should swallow a 403 as skip-and-log, got: %v", err)
	}
	if len(rec.MetricNames()) != 0 {
		t.Errorf("no metrics should be emitted on a 403, got %v", rec.MetricNames())
	}
}

func TestCollectSurfacesNon4xxError(t *testing.T) {
	g := &fakeGraph{errs: map[string]error{
		listURL: errors.New("graphclient: GET " + listURL + ": status 500: server error"),
	}}
	rec := telemetrytest.New()
	if err := New(g, nil).Collect(context.Background(), rec.Emitter()); err == nil {
		t.Error("a 500 should surface as a collector error, not be swallowed")
	}
}

func TestExperimentalAndName(t *testing.T) {
	c := New(&fakeGraph{}, nil)
	if !c.Experimental() {
		t.Error("recommendations is a beta collector; Experimental() must be true")
	}
	if c.Name() != "entra.recommendations" {
		t.Errorf("Name = %q", c.Name())
	}
	if got := c.RequiredPermissions(); len(got) != 1 || got[0] != "DirectoryRecommendations.Read.All" {
		t.Errorf("RequiredPermissions = %v", got)
	}
}
