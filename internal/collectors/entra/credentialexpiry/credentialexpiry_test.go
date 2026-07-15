package credentialexpiry

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/rknightion/graph2otel/internal/collectors"
	"github.com/rknightion/graph2otel/internal/telemetrytest"
)

// fakeGraph maps request URLs to canned collection-page bodies (or errors) and
// records the ConsistencyLevel header seen on each request (a plain $select
// list query needs no ConsistencyLevel, unlike $count/$filter/$search).
type fakeGraph struct {
	bodies      map[string]string
	errs        map[string]error
	seenHeaders map[string]map[string]string // url -> headers
}

func (f *fakeGraph) RawGet(ctx context.Context, url string) ([]byte, error) {
	return f.RawGetWithHeaders(ctx, url, nil)
}

func (f *fakeGraph) RawGetWithHeaders(_ context.Context, url string, headers map[string]string) ([]byte, error) {
	if f.seenHeaders == nil {
		f.seenHeaders = map[string]map[string]string{}
	}
	f.seenHeaders[url] = headers
	if err, ok := f.errs[url]; ok {
		return nil, err
	}
	return []byte(f.bodies[url]), nil
}

var _ collectors.GraphClient = (*fakeGraph)(nil)

const (
	base    = "https://graph.microsoft.com/v1.0"
	appsURL = base + "/applications?$select=keyCredentials,passwordCredentials"
	spURL   = base + "/servicePrincipals?$select=keyCredentials,passwordCredentials"
)

// fixedNow anchors every bucket-boundary computation in the tests so they are
// deterministic regardless of wall-clock time.
var fixedNow = time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)

func at(offset time.Duration) string {
	return fixedNow.Add(offset).Format(time.RFC3339)
}

const day = 24 * time.Hour

func withFixedClock(c *Collector) *Collector {
	c.now = func() time.Time { return fixedNow }
	return c
}

func TestCollectBucketsCredentialsByOwnerTypeCredentialTypeAndWindow(t *testing.T) {
	apps := `{"value":[
		{"keyCredentials":[{"endDateTime":"` + at(-1*day) + `"},{"endDateTime":"` + at(3*day) + `"}],
		 "passwordCredentials":[{"endDateTime":"` + at(15*day) + `"}]},
		{"keyCredentials":[{"endDateTime":"` + at(200*day) + `"}],
		 "passwordCredentials":[{"endDateTime":"` + at(60*day) + `"},{"endDateTime":"` + at(7*day) + `"}]}
	]}`
	sps := `{"value":[
		{"keyCredentials":[{"endDateTime":"` + at(0) + `"}],
		 "passwordCredentials":[{"endDateTime":"` + at(91*day) + `"}]}
	]}`

	g := &fakeGraph{bodies: map[string]string{appsURL: apps, spURL: sps}}
	rec := telemetrytest.New()
	c := withFixedClock(New(g, nil))

	if err := c.Collect(context.Background(), rec.Emitter()); err != nil {
		t.Fatalf("Collect: %v", err)
	}

	pts := rec.MetricPoints(metricName)
	if len(pts) != 20 {
		t.Fatalf("got %d series, want 20 (2 owner_type x 2 credential_type x 5 expiry_bucket, always dense)", len(pts))
	}

	got := map[[3]string]float64{}
	for _, p := range pts {
		key := [3]string{p.Attrs["owner_type"], p.Attrs["credential_type"], p.Attrs["expiry_bucket"]}
		got[key] = p.Value
	}

	want := map[[3]string]float64{
		{"application", "certificate", "expired"}: 1,
		{"application", "certificate", "lt_7d"}:   1,
		{"application", "certificate", "lt_30d"}:  0,
		{"application", "certificate", "lt_90d"}:  0,
		{"application", "certificate", "gt_90d"}:  1,

		{"application", "secret", "expired"}: 0,
		{"application", "secret", "lt_7d"}:   1, // exactly +7d is inclusive
		{"application", "secret", "lt_30d"}:  1,
		{"application", "secret", "lt_90d"}:  1,
		{"application", "secret", "gt_90d"}:  0,

		{"service_principal", "certificate", "expired"}: 1, // exactly now is expired
		{"service_principal", "certificate", "lt_7d"}:   0,
		{"service_principal", "certificate", "lt_30d"}:  0,
		{"service_principal", "certificate", "lt_90d"}:  0,
		{"service_principal", "certificate", "gt_90d"}:  0,

		{"service_principal", "secret", "expired"}: 0,
		{"service_principal", "secret", "lt_7d"}:   0,
		{"service_principal", "secret", "lt_30d"}:  0,
		{"service_principal", "secret", "lt_90d"}:  0,
		{"service_principal", "secret", "gt_90d"}:  1, // exactly +91d is just past the 90d boundary
	}

	for k, v := range want {
		if got[k] != v {
			t.Errorf("owner_type=%s credential_type=%s expiry_bucket=%s = %v, want %v", k[0], k[1], k[2], got[k], v)
		}
	}
}

// TestCollectCardinalityIsBoundedByTenantScale pins the flagship cardinality
// guarantee: however many applications/service principals/credentials a
// tenant has, only the fixed 20-series aggregate is emitted, and no attribute
// carries per-entity identity.
func TestCollectCardinalityIsBoundedByTenantScale(t *testing.T) {
	var apps strings.Builder
	apps.WriteString(`{"value":[`)
	const n = 2000
	for i := 0; i < n; i++ {
		if i > 0 {
			apps.WriteString(",")
		}
		apps.WriteString(`{"keyCredentials":[{"endDateTime":"` + at(200*day) + `","keyId":"11111111-1111-1111-1111-111111111111","displayName":"whatever"}],"passwordCredentials":[]}`)
	}
	apps.WriteString(`]}`)

	g := &fakeGraph{bodies: map[string]string{appsURL: apps.String(), spURL: `{"value":[]}`}}
	rec := telemetrytest.New()
	c := withFixedClock(New(g, nil))

	if err := c.Collect(context.Background(), rec.Emitter()); err != nil {
		t.Fatalf("Collect: %v", err)
	}

	pts := rec.MetricPoints(metricName)
	if len(pts) != 20 {
		t.Fatalf("got %d series for %d source credentials, want 20 (bounded, not per-entity)", len(pts), n)
	}

	forbidden := []string{"app_id", "appId", "app_display_name", "displayName", "display_name", "key_id", "keyId", "id"}
	for _, p := range pts {
		for _, bad := range forbidden {
			if _, ok := p.Attrs[bad]; ok {
				t.Errorf("series has forbidden per-entity attribute %q: %v", bad, p.Attrs)
			}
		}
		for k := range p.Attrs {
			if k != "owner_type" && k != "credential_type" && k != "expiry_bucket" {
				t.Errorf("series has unexpected attribute %q (only owner_type/credential_type/expiry_bucket allowed): %v", k, p.Attrs)
			}
		}
	}

	var total float64
	for _, p := range pts {
		if p.Attrs["owner_type"] == "application" && p.Attrs["credential_type"] == "certificate" && p.Attrs["expiry_bucket"] == "gt_90d" {
			total = p.Value
		}
	}
	if total != n {
		t.Errorf("gt_90d application/certificate count = %v, want %v", total, n)
	}
}

func TestCollectIsResilientToPerOwnerTypeError(t *testing.T) {
	apps := `{"value":[{"keyCredentials":[{"endDateTime":"` + at(200*day) + `"}],"passwordCredentials":[]}]}`
	g := &fakeGraph{
		bodies: map[string]string{appsURL: apps},
		errs:   map[string]error{spURL: errors.New("throttled")},
	}
	rec := telemetrytest.New()
	c := withFixedClock(New(g, nil))

	err := c.Collect(context.Background(), rec.Emitter())
	if err == nil {
		t.Error("expected Collect to surface the servicePrincipals failure as an error")
	}

	pts := rec.MetricPoints(metricName)
	if len(pts) != 10 {
		t.Fatalf("got %d series, want 10 (only application's 2 credential_type x 5 bucket; service_principal absent since its fetch failed)", len(pts))
	}
	for _, p := range pts {
		if p.Attrs["owner_type"] == "service_principal" {
			t.Errorf("service_principal series should be absent when its fetch failed, got %v", p.Attrs)
		}
	}
}

func TestCollectSkipsUnparsableEndDateTimeWithoutFailing(t *testing.T) {
	apps := `{"value":[
		{"keyCredentials":[{"endDateTime":"not-a-date"},{"endDateTime":"` + at(200*day) + `"}],"passwordCredentials":[]}
	]}`
	g := &fakeGraph{bodies: map[string]string{appsURL: apps, spURL: `{"value":[]}`}}
	rec := telemetrytest.New()
	c := withFixedClock(New(g, nil))

	if err := c.Collect(context.Background(), rec.Emitter()); err != nil {
		t.Fatalf("Collect: %v", err)
	}

	pts := rec.MetricPoints(metricName)
	for _, p := range pts {
		if p.Attrs["owner_type"] == "application" && p.Attrs["credential_type"] == "certificate" && p.Attrs["expiry_bucket"] == "gt_90d" {
			if p.Value != 1 {
				t.Errorf("gt_90d application/certificate = %v, want 1 (the unparsable entry must be skipped, not counted)", p.Value)
			}
		}
	}
}

func TestCollectSendsNoConsistencyLevelHeader(t *testing.T) {
	g := &fakeGraph{bodies: map[string]string{appsURL: `{"value":[]}`, spURL: `{"value":[]}`}}
	rec := telemetrytest.New()
	c := withFixedClock(New(g, nil))

	if err := c.Collect(context.Background(), rec.Emitter()); err != nil {
		t.Fatalf("Collect: %v", err)
	}
	for url, h := range g.seenHeaders {
		if h["ConsistencyLevel"] != "" {
			t.Errorf("request %s sent ConsistencyLevel=%q, want none (plain $select needs no advanced-query header)", url, h["ConsistencyLevel"])
		}
	}
}

func TestNameIntervalAndPermissions(t *testing.T) {
	c := New(&fakeGraph{}, nil)
	if c.Name() != "entra.credential_expiry" {
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
