package devices

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/rknightion/graph2otel/internal/collectors"
	"github.com/rknightion/graph2otel/internal/telemetrytest"
)

// fakeGraph maps request URLs to canned $count bodies (or errors) and records
// the ConsistencyLevel header seen on each request, mirroring the
// directorycounts reference collector's test fake.
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
	if body, ok := f.bodies[url]; ok {
		return []byte(body), nil
	}
	// Unmapped URL: surface as a body of "0" so an accidentally-wrong URL
	// shows up as a suspicious zero count rather than a panic, but tests
	// should always map every URL they expect to be hit.
	return []byte("0"), nil
}

var _ collectors.GraphClient = (*fakeGraph)(nil)

const base = "https://graph.microsoft.com/v1.0"

// fixedClock returns a deterministic "now" so the stale-device cutoff filter
// is a stable, assertable URL.
var fixedNow = time.Date(2026, 7, 15, 12, 0, 0, 0, time.UTC)

func fixedClock() time.Time { return fixedNow }

// totalURL and the helpers below build the same $count URLs production code
// issues (via the unexported filterCountURL / plain $count helpers), so
// tests never hand-encode OData filter strings.
func totalURL() string { return base + "/devices/$count" }

func trustTypeURL(value string) string {
	return filterCountURL(base+"/devices/$count", "trustType eq '"+value+"'")
}

func boolURL(field string, value bool) string {
	v := "false"
	if value {
		v = "true"
	}
	return filterCountURL(base+"/devices/$count", field+" eq "+v)
}

func osURL(prefix string) string {
	return filterCountURL(base+"/devices/$count", "startswith(operatingSystem,'"+prefix+"')")
}

func staleURL(t time.Time) string {
	cutoff := t.UTC().Add(-time.Duration(staleThresholdDays) * 24 * time.Hour).Format(time.RFC3339)
	return filterCountURL(base+"/devices/$count", "approximateLastSignInDateTime le "+cutoff)
}

// fullFixture builds a self-consistent set of canned bodies: total=100,
// trust_type sums to 98 (leaving 2 "unknown"), compliance/managed sum
// exactly to total (no leftover expected there), and OS buckets sum to 90
// (leaving 10 "other").
func fullFixture() map[string]string {
	m := map[string]string{
		totalURL(): "100",

		trustTypeURL("AzureAd"):   "60",
		trustTypeURL("ServerAd"):  "30",
		trustTypeURL("Workplace"): "8",

		boolURL("isCompliant", true):  "70",
		boolURL("isCompliant", false): "30",

		boolURL("isManaged", true):  "65",
		boolURL("isManaged", false): "35",

		osURL("Windows"): "50",
		osURL("Mac"):     "20",
		osURL("iOS"):     "10",
		osURL("iPadOS"):  "5",
		osURL("Android"): "5",
		osURL("Linux"):   "0",

		staleURL(fixedNow): "12",
	}
	return m
}

func newTestCollector(g collectors.GraphClient) *Collector {
	c := New(g, nil)
	c.now = fixedClock
	return c
}

func TestCollectEmitsTrustTypeBreakdownWithUnknownLeftover(t *testing.T) {
	g := &fakeGraph{bodies: fullFixture()}
	rec := telemetrytest.New()

	if err := newTestCollector(g).Collect(context.Background(), rec.Emitter()); err != nil {
		t.Fatalf("Collect: %v", err)
	}

	pts := rec.MetricPoints(totalMetricName)
	got := map[string]float64{}
	for _, p := range pts {
		got[p.Attrs["trust_type"]] = p.Value
	}
	want := map[string]float64{"azure_ad": 60, "server_ad": 30, "workplace": 8, "unknown": 2}
	if len(got) != len(want) {
		t.Fatalf("got %d trust_type series, want %d: %v", len(got), len(want), got)
	}
	for k, v := range want {
		if got[k] != v {
			t.Errorf("trust_type=%s value = %v, want %v", k, got[k], v)
		}
	}
}

func TestCollectEmitsComplianceBreakdown(t *testing.T) {
	g := &fakeGraph{bodies: fullFixture()}
	rec := telemetrytest.New()

	if err := newTestCollector(g).Collect(context.Background(), rec.Emitter()); err != nil {
		t.Fatalf("Collect: %v", err)
	}

	pts := rec.MetricPoints(complianceMetricName)
	if len(pts) != 2 {
		t.Fatalf("got %d compliance series, want 2: %+v", len(pts), pts)
	}
	got := map[string]float64{}
	for _, p := range pts {
		got[p.Attrs["is_compliant"]] = p.Value
	}
	if got["true"] != 70 || got["false"] != 30 {
		t.Errorf("compliance series = %v, want true=70 false=30", got)
	}
}

func TestCollectEmitsManagedBreakdown(t *testing.T) {
	g := &fakeGraph{bodies: fullFixture()}
	rec := telemetrytest.New()

	if err := newTestCollector(g).Collect(context.Background(), rec.Emitter()); err != nil {
		t.Fatalf("Collect: %v", err)
	}

	pts := rec.MetricPoints(managedMetricName)
	if len(pts) != 2 {
		t.Fatalf("got %d managed series, want 2: %+v", len(pts), pts)
	}
	got := map[string]float64{}
	for _, p := range pts {
		got[p.Attrs["is_managed"]] = p.Value
	}
	if got["true"] != 65 || got["false"] != 35 {
		t.Errorf("managed series = %v, want true=65 false=35", got)
	}
}

func TestCollectEmitsOSBreakdownWithOtherBucket(t *testing.T) {
	g := &fakeGraph{bodies: fullFixture()}
	rec := telemetrytest.New()

	if err := newTestCollector(g).Collect(context.Background(), rec.Emitter()); err != nil {
		t.Fatalf("Collect: %v", err)
	}

	pts := rec.MetricPoints(osMetricName)
	got := map[string]float64{}
	for _, p := range pts {
		got[p.Attrs["operating_system"]] = p.Value
	}
	// 50+20+10+5+5+0 = 90 known, total 100 => other = 10.
	want := map[string]float64{
		"windows": 50, "macos": 20, "ios": 10, "ipados": 5, "android": 5, "linux": 0, "other": 10,
	}
	if len(got) != len(want) {
		t.Fatalf("got %d os series, want %d: %v", len(got), len(want), got)
	}
	for k, v := range want {
		if got[k] != v {
			t.Errorf("operating_system=%s value = %v, want %v", k, got[k], v)
		}
	}
}

func TestCollectClampsNegativeOtherToZero(t *testing.T) {
	bodies := fullFixture()
	// Make the known OS buckets sum to MORE than total (simulating a race
	// between the total count and the per-bucket counts against a live,
	// changing directory) and assert the "other" bucket never goes negative.
	bodies[totalURL()] = "80" // less than the 90 known-bucket sum above
	g := &fakeGraph{bodies: bodies}
	rec := telemetrytest.New()

	if err := newTestCollector(g).Collect(context.Background(), rec.Emitter()); err != nil {
		t.Fatalf("Collect: %v", err)
	}

	pts := rec.MetricPoints(osMetricName)
	for _, p := range pts {
		if p.Attrs["operating_system"] == "other" && p.Value < 0 {
			t.Errorf("other bucket = %v, want >= 0", p.Value)
		}
	}
}

func TestCollectEmitsStaleGaugeWithThresholdAttr(t *testing.T) {
	g := &fakeGraph{bodies: fullFixture()}
	rec := telemetrytest.New()

	if err := newTestCollector(g).Collect(context.Background(), rec.Emitter()); err != nil {
		t.Fatalf("Collect: %v", err)
	}

	pts := rec.MetricPoints(staleMetricName)
	if len(pts) != 1 {
		t.Fatalf("got %d stale series, want exactly 1 (bounded, single threshold): %+v", len(pts), pts)
	}
	if pts[0].Value != 12 {
		t.Errorf("stale count = %v, want 12", pts[0].Value)
	}
	if pts[0].Attrs["threshold_days"] != "90" {
		t.Errorf("threshold_days attr = %q, want %q", pts[0].Attrs["threshold_days"], "90")
	}
}

func TestCollectSetsConsistencyLevelOnEveryRequest(t *testing.T) {
	g := &fakeGraph{bodies: fullFixture()}
	rec := telemetrytest.New()

	if err := newTestCollector(g).Collect(context.Background(), rec.Emitter()); err != nil {
		t.Fatalf("Collect: %v", err)
	}
	if len(g.seenHeaders) == 0 {
		t.Fatal("expected at least one request")
	}
	for url, cl := range g.seenHeaders {
		if cl != "eventual" {
			t.Errorf("request %s had ConsistencyLevel=%q, want eventual", url, cl)
		}
	}
}

func TestCollectIsResilientToPerBucketError(t *testing.T) {
	bodies := fullFixture()
	g := &fakeGraph{
		bodies: bodies,
		errs:   map[string]error{trustTypeURL("ServerAd"): errors.New("throttled")},
	}
	rec := telemetrytest.New()

	err := newTestCollector(g).Collect(context.Background(), rec.Emitter())
	if err == nil {
		t.Fatal("expected Collect to surface the per-bucket failure as an error")
	}

	pts := rec.MetricPoints(totalMetricName)
	for _, p := range pts {
		if p.Attrs["trust_type"] == "server_ad" {
			t.Error("server_ad series should be absent when its count failed")
		}
	}
	// The other trust_type buckets, and every other metric, must still emit
	// despite the one failure.
	if len(pts) == 0 {
		t.Error("expected surviving trust_type series to still emit")
	}
	if len(rec.MetricPoints(complianceMetricName)) != 2 {
		t.Error("compliance series should be unaffected by the trust_type failure")
	}
	if len(rec.MetricPoints(staleMetricName)) != 1 {
		t.Error("stale series should be unaffected by the trust_type failure")
	}
}

func TestCollectOmitsUnknownAndOtherLeftoverWhenTotalCountFails(t *testing.T) {
	bodies := fullFixture()
	g := &fakeGraph{
		bodies: bodies,
		errs:   map[string]error{totalURL(): errors.New("throttled")},
	}
	rec := telemetrytest.New()

	err := newTestCollector(g).Collect(context.Background(), rec.Emitter())
	if err == nil {
		t.Fatal("expected Collect to surface the total-count failure as an error")
	}

	trustPts := rec.MetricPoints(totalMetricName)
	for _, p := range trustPts {
		if p.Attrs["trust_type"] == "unknown" {
			t.Error("unknown trust_type bucket should be omitted when the total count is unavailable")
		}
	}
	if len(trustPts) != 3 {
		t.Errorf("got %d trust_type series, want 3 known buckets (no leftover)", len(trustPts))
	}

	osPts := rec.MetricPoints(osMetricName)
	for _, p := range osPts {
		if p.Attrs["operating_system"] == "other" {
			t.Error("other os bucket should be omitted when the total count is unavailable")
		}
	}
}

func TestNoPerDeviceSeries(t *testing.T) {
	g := &fakeGraph{bodies: fullFixture()}
	rec := telemetrytest.New()

	if err := newTestCollector(g).Collect(context.Background(), rec.Emitter()); err != nil {
		t.Fatalf("Collect: %v", err)
	}

	// Every emitted series must stay within the fixed, bounded dimension
	// sets this collector declares - never grow with the number of devices
	// in the tenant (which fullFixture's counts imply is at least 100).
	checks := []struct {
		metric string
		max    int
	}{
		{totalMetricName, len(trustTypeBuckets) + 1},
		{complianceMetricName, 2},
		{managedMetricName, 2},
		{osMetricName, len(osBuckets) + 1},
		{staleMetricName, 1},
	}
	for _, c := range checks {
		pts := rec.MetricPoints(c.metric)
		if len(pts) > c.max {
			t.Errorf("metric %s emitted %d series, want at most %d (bounded)", c.metric, len(pts), c.max)
		}
		for _, p := range pts {
			for k := range p.Attrs {
				if k == "id" || k == "deviceId" || k == "displayName" || k == "device_id" || k == "device_name" {
					t.Errorf("metric %s has a per-device attribute %q - cardinality violation", c.metric, k)
				}
			}
		}
	}
}

func TestNameIntervalAndPermissions(t *testing.T) {
	c := New(&fakeGraph{}, nil)
	if c.Name() != "entra.devices" {
		t.Errorf("Name = %q, want entra.devices", c.Name())
	}
	if c.DefaultInterval() <= 0 {
		t.Errorf("DefaultInterval = %v, want positive", c.DefaultInterval())
	}
	perms := c.RequiredPermissions()
	if len(perms) != 1 || perms[0] != "Device.Read.All" {
		t.Errorf("RequiredPermissions = %v, want [Device.Read.All]", perms)
	}
}
