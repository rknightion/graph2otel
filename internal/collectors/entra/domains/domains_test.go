package domains

import (
	"context"
	"errors"
	"testing"

	"github.com/rknightion/graph2otel/internal/collectors"
	"github.com/rknightion/graph2otel/internal/telemetrytest"
)

// fakeGraph maps request URLs to canned page bodies (or errors) and records
// the ConsistencyLevel header seen on each request, mirroring the
// directorycounts/groups reference tests' fake.
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

const domainsURL = "https://graph.microsoft.com/v1.0/domains"

// fourDomainsBody covers all four (authentication_type, is_verified) posture
// combinations: managed/verified, managed/unverified, federated/verified,
// federated/unverified. isDefault and domain id/name are deliberately varied
// too, to prove they never leak into a metric attribute.
const fourDomainsBody = `{
  "value": [
    {"id": "contoso.com", "authenticationType": "Managed", "isVerified": true, "isDefault": true, "supportedServices": ["Email"]},
    {"id": "sub.contoso.com", "authenticationType": "Managed", "isVerified": false, "isDefault": false, "supportedServices": []},
    {"id": "fabrikam.com", "authenticationType": "Federated", "isVerified": true, "isDefault": false, "supportedServices": ["Email", "Intune"]},
    {"id": "adatum.com", "authenticationType": "Federated", "isVerified": false, "isDefault": false, "supportedServices": []}
  ]
}`

func TestCollectEmitsBoundedPostureCounts(t *testing.T) {
	g := &fakeGraph{bodies: map[string]string{domainsURL: fourDomainsBody}}
	rec := telemetrytest.New()

	c := New(g, nil)
	if err := c.Collect(context.Background(), rec.Emitter()); err != nil {
		t.Fatalf("Collect: %v", err)
	}

	pts := rec.MetricPoints(metricTotal)
	if len(pts) != 4 {
		t.Fatalf("got %d points for %s, want 4 (one per posture combination)", len(pts), metricTotal)
	}

	got := map[string]float64{}
	for _, p := range pts {
		if len(p.Attrs) != 2 {
			t.Fatalf("point has %d attrs, want exactly 2 (authentication_type, is_verified): %v", len(p.Attrs), p.Attrs)
		}
		key := p.Attrs["authentication_type"] + "/" + p.Attrs["is_verified"]
		got[key] = p.Value
	}
	want := map[string]float64{
		"managed/true":    1,
		"managed/false":   1,
		"federated/true":  1,
		"federated/false": 1,
	}
	for k, v := range want {
		if got[k] != v {
			t.Errorf("series %s = %v, want %v (got map: %v)", k, got[k], v, got)
		}
	}

	fedPts := rec.MetricPoints(metricFederatedTotal)
	if len(fedPts) != 1 {
		t.Fatalf("got %d points for %s, want 1", len(fedPts), metricFederatedTotal)
	}
	if fedPts[0].Value != 2 {
		t.Errorf("%s = %v, want 2", metricFederatedTotal, fedPts[0].Value)
	}
	if len(fedPts[0].Attrs) != 0 {
		t.Errorf("%s has attrs %v, want none", metricFederatedTotal, fedPts[0].Attrs)
	}
}

func TestCollectEmitsNoPerDomainSeries(t *testing.T) {
	// Cardinality guard: however many domains exist, entra.domains.total must
	// stay bounded to at most 4 series (2 authentication types x 2 verification
	// states), never one series per domain (id/name must never be a label).
	g := &fakeGraph{bodies: map[string]string{domainsURL: fourDomainsBody}}
	rec := telemetrytest.New()

	if err := New(g, nil).Collect(context.Background(), rec.Emitter()); err != nil {
		t.Fatalf("Collect: %v", err)
	}

	pts := rec.MetricPoints(metricTotal)
	if len(pts) > 4 {
		t.Fatalf("got %d points, want <= 4 (bounded posture combinations, not per-domain)", len(pts))
	}
	for _, p := range pts {
		for k := range p.Attrs {
			if k != "authentication_type" && k != "is_verified" {
				t.Errorf("unexpected attribute key %q (possible cardinality/PII violation)", k)
			}
		}
	}
}

func TestCollectSetsNoConsistencyLevelHeader(t *testing.T) {
	// GET /domains is a plain list with no $filter/$search/$count=true, so it
	// must NOT send ConsistencyLevel: eventual (that header is reserved for
	// advanced-query requests per the collectors.GetAllValues contract).
	g := &fakeGraph{bodies: map[string]string{domainsURL: fourDomainsBody}}
	rec := telemetrytest.New()

	if err := New(g, nil).Collect(context.Background(), rec.Emitter()); err != nil {
		t.Fatalf("Collect: %v", err)
	}
	cl, seen := g.seenHeaders[domainsURL]
	if !seen {
		t.Fatal("expected a request to /domains")
	}
	if cl != "" {
		t.Errorf("ConsistencyLevel header = %q, want empty (no advanced query used)", cl)
	}
}

func TestCollectIsResilientToMalformedDomainEntry(t *testing.T) {
	body := `{
  "value": [
    {"id": "contoso.com", "authenticationType": "Managed", "isVerified": true},
    [1,2,3],
    {"id": "fabrikam.com", "authenticationType": "Federated", "isVerified": true}
  ]
}`
	g := &fakeGraph{bodies: map[string]string{domainsURL: body}}
	rec := telemetrytest.New()

	err := New(g, nil).Collect(context.Background(), rec.Emitter())
	if err == nil {
		t.Error("expected Collect to surface the malformed-entry failure as an error")
	}

	pts := rec.MetricPoints(metricTotal)
	if len(pts) != 2 {
		t.Fatalf("got %d points, want 2 (malformed entry skipped, other two survive)", len(pts))
	}
}

func TestCollectPropagatesListFailure(t *testing.T) {
	g := &fakeGraph{errs: map[string]error{domainsURL: errors.New("throttled")}}
	rec := telemetrytest.New()

	if err := New(g, nil).Collect(context.Background(), rec.Emitter()); err == nil {
		t.Error("expected Collect to return an error when listing domains fails")
	}

	if pts := rec.MetricPoints(metricTotal); len(pts) != 0 {
		t.Errorf("got %d points for %s, want 0 when the list call failed", len(pts), metricTotal)
	}
	if pts := rec.MetricPoints(metricFederatedTotal); len(pts) != 0 {
		t.Errorf("got %d points for %s, want 0 when the list call failed", len(pts), metricFederatedTotal)
	}
}

func TestNameIntervalAndPermissions(t *testing.T) {
	c := New(&fakeGraph{}, nil)
	if c.Name() != "entra.domains" {
		t.Errorf("Name = %q, want entra.domains", c.Name())
	}
	if c.DefaultInterval() <= 0 {
		t.Errorf("DefaultInterval = %v, want > 0", c.DefaultInterval())
	}
	perms := c.RequiredPermissions()
	if len(perms) != 1 || perms[0] != "Domain.Read.All" {
		t.Errorf("RequiredPermissions = %v, want [Domain.Read.All]", perms)
	}
}
