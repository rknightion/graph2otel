package users

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"net/url"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/rknightion/graph2otel/internal/collectors"
	"github.com/rknightion/graph2otel/internal/license"
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

func (f *fakeGraph) RawGet(ctx context.Context, u string) ([]byte, error) {
	return f.RawGetWithHeaders(ctx, u, nil)
}

func (f *fakeGraph) RawGetWithHeaders(_ context.Context, u string, headers map[string]string) ([]byte, error) {
	if f.seenHeaders == nil {
		f.seenHeaders = map[string]string{}
	}
	f.seenHeaders[u] = headers["ConsistencyLevel"]
	if err, ok := f.errs[u]; ok {
		return nil, err
	}
	body, ok := f.bodies[u]
	if !ok {
		return nil, errors.New("fakeGraph: no canned body for " + u)
	}
	return []byte(body), nil
}

var _ collectors.GraphClient = (*fakeGraph)(nil)

const base = "https://graph.microsoft.com/v1.0"

// populationFilters is the fixed set of (attr, value, filter) triples the
// collector is expected to query for the population gauge, independent of
// the production populationAxes var, so the test catches an accidental
// change to the query shape as well as the emitted values.
var populationFilters = []struct {
	attr   string
	value  string
	filter string
}{
	{"account_enabled", "true", "accountEnabled eq true"},
	{"account_enabled", "false", "accountEnabled eq false"},
	{"user_type", "member", "userType eq 'Member'"},
	{"user_type", "guest", "userType eq 'Guest'"},
	{"on_premises_sync_enabled", "true", "onPremisesSyncEnabled eq true"},
	{"on_premises_sync_enabled", "false", "onPremisesSyncEnabled eq false or onPremisesSyncEnabled eq null"},
}

func countURL(filter string) string {
	return base + "/users/$count?$filter=" + url.QueryEscape(filter)
}

// allPopulationCounts returns canned $count bodies for every population
// bucket, each with a distinct value so a test can catch a mislabeled attr.
func allPopulationCounts() map[string]string {
	bodies := map[string]string{}
	for i, pf := range populationFilters {
		bodies[countURL(pf.filter)] = strconv.Itoa((i + 1) * 10)
	}
	return bodies
}

// staleURL builds the collection $count=true form the stale gauge uses (the
// /users/$count segment 502s on a signInActivity filter).
func staleURL(now time.Time, days int) string {
	cutoff := now.UTC().AddDate(0, 0, -days).Truncate(time.Second).Format("2006-01-02T15:04:05Z")
	filter := "signInActivity/lastSignInDateTime le " + cutoff
	return base + "/users?$filter=" + url.QueryEscape(filter) + "&$count=true&$top=1&$select=id"
}

// staleBody is the @odata.count envelope the collection-count form returns.
func staleBody(n int) string {
	return `{"@odata.count":` + strconv.Itoa(n) + `,"value":[]}`
}

func fixedNow() time.Time {
	return time.Date(2026, 7, 15, 12, 0, 0, 0, time.UTC)
}

func TestCollectEmitsPopulationGaugesWithCorrectAttrs(t *testing.T) {
	g := &fakeGraph{bodies: allPopulationCounts()}
	rec := telemetrytest.New()

	c := New(g, license.Capabilities{}, nil)
	if err := c.Collect(context.Background(), rec.Emitter()); err != nil {
		t.Fatalf("Collect: %v", err)
	}

	pts := rec.MetricPoints(metricPopulation)
	if len(pts) != len(populationFilters) {
		t.Fatalf("got %d population series, want %d", len(pts), len(populationFilters))
	}

	for i, pf := range populationFilters {
		want := float64((i + 1) * 10)
		found := false
		for _, p := range pts {
			if p.Attrs[pf.attr] == pf.value {
				found = true
				if p.Value != want {
					t.Errorf("series %s=%s value = %v, want %v", pf.attr, pf.value, p.Value, want)
				}
			}
		}
		if !found {
			t.Errorf("no series found with %s=%s", pf.attr, pf.value)
		}
	}
}

func TestCollectSetsConsistencyLevelOnEveryPopulationRequest(t *testing.T) {
	g := &fakeGraph{bodies: allPopulationCounts()}
	rec := telemetrytest.New()

	if err := New(g, license.Capabilities{}, nil).Collect(context.Background(), rec.Emitter()); err != nil {
		t.Fatalf("Collect: %v", err)
	}
	if len(g.seenHeaders) != len(populationFilters) {
		t.Fatalf("saw %d requests, want %d", len(g.seenHeaders), len(populationFilters))
	}
	for u, cl := range g.seenHeaders {
		if cl != "eventual" {
			t.Errorf("request %s had ConsistencyLevel=%q, want eventual", u, cl)
		}
	}
}

func TestCollectWithoutP1SkipsStaleAndStillEmitsPopulation(t *testing.T) {
	g := &fakeGraph{bodies: allPopulationCounts()}
	rec := telemetrytest.New()

	var logBuf bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&logBuf, nil))

	c := New(g, license.Capabilities{}, logger) // empty caps: no P1, no P2
	if err := c.Collect(context.Background(), rec.Emitter()); err != nil {
		t.Fatalf("Collect: %v", err)
	}

	if pts := rec.MetricPoints(metricPopulation); len(pts) != len(populationFilters) {
		t.Fatalf("population series = %d, want %d (must still emit without P1)", len(pts), len(populationFilters))
	}
	if pts := rec.MetricPoints(metricStale); len(pts) != 0 {
		t.Fatalf("stale series = %d, want 0 (must be skipped without P1/P2)", len(pts))
	}

	logged := logBuf.String()
	if !strings.Contains(logged, "skipping") || !strings.Contains(logged, metricStale) {
		t.Errorf("expected a skip-and-log line mentioning %q, got log: %s", metricStale, logged)
	}

	// No request should have been made for the licensed signInActivity query.
	for u := range g.seenHeaders {
		if strings.Contains(u, "signInActivity") {
			t.Errorf("unexpected signInActivity request without P1/P2: %s", u)
		}
	}
}

func TestCollectEmitsStaleGaugeUnderEntraP1(t *testing.T) {
	now := fixedNow()
	bodies := allPopulationCounts()
	bodies[staleURL(now, 30)] = staleBody(5)
	bodies[staleURL(now, 90)] = staleBody(12)
	g := &fakeGraph{bodies: bodies}
	rec := telemetrytest.New()

	c := New(g, license.Capabilities{license.CapEntraP1: true}, nil)
	c.now = func() time.Time { return now }

	if err := c.Collect(context.Background(), rec.Emitter()); err != nil {
		t.Fatalf("Collect: %v", err)
	}

	pts := rec.MetricPoints(metricStale)
	if len(pts) != 2 {
		t.Fatalf("got %d stale series, want 2", len(pts))
	}
	want := map[string]float64{"30": 5, "90": 12}
	for _, p := range pts {
		v, ok := want[p.Attrs["threshold_days"]]
		if !ok {
			t.Errorf("unexpected threshold_days=%q", p.Attrs["threshold_days"])
			continue
		}
		if p.Value != v {
			t.Errorf("threshold_days=%s value = %v, want %v", p.Attrs["threshold_days"], p.Value, v)
		}
	}
}

func TestCollectEmitsStaleGaugeUnderEntraP2Only(t *testing.T) {
	// signInActivity is licensed under EITHER P1 or P2 per Microsoft's docs, so
	// a tenant holding only P2 (no P1) must still get the stale gauge.
	now := fixedNow()
	bodies := allPopulationCounts()
	bodies[staleURL(now, 30)] = staleBody(1)
	bodies[staleURL(now, 90)] = staleBody(2)
	g := &fakeGraph{bodies: bodies}
	rec := telemetrytest.New()

	c := New(g, license.Capabilities{license.CapEntraP2: true}, nil)
	c.now = func() time.Time { return now }

	if err := c.Collect(context.Background(), rec.Emitter()); err != nil {
		t.Fatalf("Collect: %v", err)
	}
	if pts := rec.MetricPoints(metricStale); len(pts) != 2 {
		t.Fatalf("got %d stale series under P2-only, want 2", len(pts))
	}
}

func TestCollectIsResilientToPerBucketError(t *testing.T) {
	bodies := allPopulationCounts()
	failing := countURL("accountEnabled eq true")
	g := &fakeGraph{
		bodies: bodies,
		errs:   map[string]error{failing: errors.New("throttled")},
	}
	rec := telemetrytest.New()

	err := New(g, license.Capabilities{}, nil).Collect(context.Background(), rec.Emitter())
	if err == nil {
		t.Error("expected Collect to surface the per-bucket failure as an error")
	}

	pts := rec.MetricPoints(metricPopulation)
	if len(pts) != len(populationFilters)-1 {
		t.Fatalf("got %d series, want %d (one bucket failed, others survived)", len(pts), len(populationFilters)-1)
	}
	for _, p := range pts {
		if p.Attrs["account_enabled"] == "true" {
			t.Error("account_enabled=true series should be absent when its count failed")
		}
	}
}

// TestCollectNeverEmitsPerUserSeries guards the cardinality rule: however
// large the tenant, this collector only ever calls $count (a bare scalar) —
// it never pages the user collection — so the number of emitted series is
// bounded by the fixed axis/threshold sets, never by tenant size.
func TestCollectNeverEmitsPerUserSeries(t *testing.T) {
	now := fixedNow()
	bodies := allPopulationCounts()
	// Simulate a huge tenant: every count is enormous, but that must not
	// translate into more than one series per bounded bucket.
	for k := range bodies {
		bodies[k] = "123456789"
	}
	bodies[staleURL(now, 30)] = staleBody(654321)
	bodies[staleURL(now, 90)] = staleBody(987654)
	g := &fakeGraph{bodies: bodies}
	rec := telemetrytest.New()

	c := New(g, license.Capabilities{license.CapEntraP1: true}, nil)
	c.now = func() time.Time { return now }

	if err := c.Collect(context.Background(), rec.Emitter()); err != nil {
		t.Fatalf("Collect: %v", err)
	}

	popPts := rec.MetricPoints(metricPopulation)
	stalePts := rec.MetricPoints(metricStale)
	if len(popPts) != len(populationFilters) {
		t.Fatalf("population series = %d, want exactly %d regardless of tenant size", len(popPts), len(populationFilters))
	}
	if len(stalePts) != len(staleThresholdsDays) {
		t.Fatalf("stale series = %d, want exactly %d regardless of tenant size", len(stalePts), len(staleThresholdsDays))
	}

	// Every request made must be a $count request (URL ends in the $count
	// scalar segment) — never a paged /users listing, which would risk a
	// per-user series if ever unmarshaled into attributes.
	for u := range g.seenHeaders {
		isSegmentCount := strings.Contains(u, "/users/$count")
		isCollectionCount := strings.Contains(u, "/users?") && strings.Contains(u, "$count=true")
		if !isSegmentCount && !isCollectionCount {
			t.Errorf("unexpected non-count request (would risk a per-user series): %s", u)
		}
	}
}

func TestNameIntervalAndPermissions(t *testing.T) {
	c := New(&fakeGraph{}, license.Capabilities{}, nil)
	if c.Name() != "entra.users" {
		t.Errorf("Name = %q, want entra.users", c.Name())
	}
	if c.DefaultInterval() <= 0 {
		t.Errorf("DefaultInterval = %v, want positive", c.DefaultInterval())
	}
	perms := c.RequiredPermissions()
	want := map[string]bool{"User.Read.All": true, "AuditLog.Read.All": true}
	if len(perms) != len(want) {
		t.Fatalf("RequiredPermissions = %v, want %v", perms, want)
	}
	for _, p := range perms {
		if !want[p] {
			t.Errorf("unexpected permission %q", p)
		}
	}
}

// TestCollectorDoesNotImplementCapabilityRequirer documents (via a compile-time
// style assertion) that this collector must NOT be gated off entirely by
// license.ShouldRun — it partially degrades instead, so it must keep running
// on every tier to emit the population gauges.
func TestCollectorDoesNotImplementCapabilityRequirer(t *testing.T) {
	c := New(&fakeGraph{}, license.Capabilities{}, nil)
	if _, ok := any(c).(license.CapabilityRequirer); ok {
		t.Error("Collector must not implement license.CapabilityRequirer; it partially degrades instead")
	}
}
