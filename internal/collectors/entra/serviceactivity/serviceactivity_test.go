package serviceactivity

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/rknightion/graph2otel/internal/collectors"
	"github.com/rknightion/graph2otel/internal/telemetrytest"
)

// fakeGraph maps request URLs to canned response bodies (or errors). It
// satisfies collectors.GraphClient without any live Graph call.
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
		return nil, fmt.Errorf("fakeGraph: no body stubbed for %s", url)
	}
	return []byte(body), nil
}

var _ collectors.GraphClient = (*fakeGraph)(nil)

// fixedNow pins the injectable clock. 12:15 truncates DOWN to a 12:00 window
// end (30-minute boundary), so the request window is
// [2026-07-28T10:00:00Z, 2026-07-28T12:00:00Z) — four complete 30-minute
// buckets: 10:00, 10:30, 11:00, 11:30.
var fixedNow = time.Date(2026, 7, 28, 12, 15, 0, 0, time.UTC)

const (
	wantStart = "2026-07-28T10:00:00Z"
	wantEnd   = "2026-07-28T12:00:00Z"
)

// bucketTimes are the four bucket starts the fixed window can return.
var bucketTimes = [4]string{
	"2026-07-28T10:00:00Z",
	"2026-07-28T10:30:00Z",
	"2026-07-28T11:00:00Z",
	"2026-07-28T11:30:00Z",
}

// liveValues is the per-function bucket sequence for the fixed window,
// VERBATIM against the live 2026-07-28 receipts (#368) at those four bucket
// starts: 18 of 19 functions are a measured zero across the whole 24h sample;
// getMetricsForConditionalAccessCompliantDevicesSignInSuccess carries the one
// real signal (values 5, 2, 2, 5), so its LATEST bucket (11:30) is 5 — not the
// largest value in the window, pinning that "latest" means latest, not max.
var liveValues = map[string][4]float64{
	"getMetricsForMfaSignInSuccess":                                     {0, 0, 0, 0},
	"getMetricsForMfaSignInFailure":                                     {0, 0, 0, 0},
	"getMetricsForSamlSignInSuccess":                                    {0, 0, 0, 0},
	"getMetricsForConditionalAccessBlockedSignIn":                       {0, 0, 0, 0},
	"getMetricsForConditionalAccessCompliantDevicesSignInSuccess":       {5, 2, 2, 5},
	"getMetricsForConditionalAccessManagedDevicesSignInSuccess":         {0, 0, 0, 0},
	"getMetricsForNetworkAccessInternetAppPolicyAllowedApps":            {0, 0, 0, 0},
	"getMetricsForNetworkAccessInternetAppPolicyBlockedApps":            {0, 0, 0, 0},
	"getMetricsForNetworkAccessPrivateAppsAllowedByConnector":           {0, 0, 0, 0},
	"getMetricsForNetworkAccessPrivateAppsBlockedByConnector":           {0, 0, 0, 0},
	"getMetricsForNetworkAccessInternetAppPolicyAllowedUsers":           {0, 0, 0, 0},
	"getMetricsForNetworkAccessInternetAppPolicyBlockedUsers":           {0, 0, 0, 0},
	"getMetricsForNetworkAccessPrivateAppUsersAllowedByConnector":       {0, 0, 0, 0},
	"getMetricsForNetworkAccessPrivateAppUsersBlockedByConnector":       {0, 0, 0, 0},
	"getMetricsForNetworkAccessRemoteNetworkBranchesAlive":              {0, 0, 0, 0},
	"getMetricsForNetworkAccessRemoteNetworkBranchesBGPConnected":       {0, 0, 0, 0},
	"getMetricsForNetworkAccessRemoteNetworkBranchesBGPDisconnected":    {0, 0, 0, 0},
	"getMetricsForNetworkAccessRemoteNetworkBranchesTunnelConnected":    {0, 0, 0, 0},
	"getMetricsForNetworkAccessRemoteNetworkBranchesTunnelDisconnected": {0, 0, 0, 0},
}

// fixtureBody renders a serviceActivityResponse JSON body for the four fixed
// bucket times, in the exact wire shape live-captured 2026-07-28: an
// "@odata.context" companion field (ignored by the mapper) plus "value".
func fixtureBody(vals [4]float64) string {
	type bucket struct {
		IntervalStartDateTime string  `json:"intervalStartDateTime"`
		Value                 float64 `json:"value"`
	}
	buckets := make([]bucket, 4)
	for i, t := range bucketTimes {
		buckets[i] = bucket{IntervalStartDateTime: t, Value: vals[i]}
	}
	body, err := json.Marshal(struct {
		Context string   `json:"@odata.context"`
		Value   []bucket `json:"value"`
	}{
		Context: "https://graph.microsoft.com/beta/$metadata#Collection(microsoft.graph.serviceActivityValueMetric)",
		Value:   buckets,
	})
	if err != nil {
		panic(err)
	}
	return string(body)
}

// liveGraph returns a fakeGraph stubbed with all nineteen functions' fixed-
// window fixtures, keyed by the exact URL the collector must build.
func liveGraph() *fakeGraph {
	bodies := make(map[string]string, len(functions))
	for _, mf := range functions {
		vals, ok := liveValues[mf.fn]
		if !ok {
			panic("no fixture values for " + mf.fn)
		}
		bodies[buildURL(betaBaseURL, mf.fn, wantStart, wantEnd)] = fixtureBody(vals)
	}
	return &fakeGraph{bodies: bodies}
}

func newCollector(g collectors.GraphClient) *Collector {
	c := New(g, nil)
	c.now = func() time.Time { return fixedNow }
	return c
}

// TestAllNineteenFunctionsMapLatestBucket is table-driven over every metric
// function: it issues the request, maps the LATEST bucket, and checks the
// activity label, the metric it lands on, and the value.
func TestAllNineteenFunctionsMapLatestBucket(t *testing.T) {
	if len(functions) != 19 {
		t.Fatalf("len(functions) = %d, want 19", len(functions))
	}

	rec := telemetrytest.New()
	if err := newCollector(liveGraph()).Collect(context.Background(), rec.Emitter(), nil); err != nil {
		t.Fatalf("Collect: %v", err)
	}

	byMetricActivity := map[string]map[string]telemetrytest.MetricPoint{}
	for _, name := range metricOrder {
		byMetricActivity[name] = map[string]telemetrytest.MetricPoint{}
		for _, p := range rec.MetricPoints(name) {
			byMetricActivity[name][p.Attrs["activity"]] = p
		}
	}

	for _, mf := range functions {
		t.Run(mf.fn, func(t *testing.T) {
			p, ok := byMetricActivity[mf.metric][mf.activity]
			if !ok {
				t.Fatalf("no point for metric=%s activity=%s", mf.metric, mf.activity)
			}
			wantLatest := liveValues[mf.fn][3] // bucketTimes[3] = 11:30, the latest
			if p.Value != wantLatest {
				t.Errorf("value = %v, want latest bucket value %v", p.Value, wantLatest)
			}
			if p.Attrs["aggregation_interval_minutes"] != "30" {
				t.Errorf("aggregation_interval_minutes = %q, want 30", p.Attrs["aggregation_interval_minutes"])
			}
		})
	}
}

// TestBucketWithZeroValueIsEmitted pins that 18 of 19 functions carry a
// measured ZERO, and a zero IS a point, not an absence.
func TestBucketWithZeroValueIsEmitted(t *testing.T) {
	rec := telemetrytest.New()
	if err := newCollector(liveGraph()).Collect(context.Background(), rec.Emitter(), nil); err != nil {
		t.Fatalf("Collect: %v", err)
	}
	pts := rec.MetricPoints(metricSignins)
	var found bool
	for _, p := range pts {
		if p.Attrs["activity"] == "mfa_signin_success" {
			found = true
			if p.Value != 0 {
				t.Errorf("mfa_signin_success = %v, want measured zero", p.Value)
			}
		}
	}
	if !found {
		t.Fatal("mfa_signin_success point absent — a measured zero must still be emitted")
	}
}

// TestURLUsesUnquotedTimesAndThirtyMinuteAggregation pins the exact wire shape
// live-measured 2026-07-28: unquoted ISO-8601 bounds and
// aggregationIntervalInMinutes=30.
func TestURLUsesUnquotedTimesAndThirtyMinuteAggregation(t *testing.T) {
	got := buildURL(betaBaseURL, "getMetricsForMfaSignInSuccess", wantStart, wantEnd)
	want := "https://graph.microsoft.com/beta/reports/serviceActivity/getMetricsForMfaSignInSuccess(" +
		"inclusiveIntervalStartDateTime=2026-07-28T10:00:00Z," +
		"exclusiveIntervalEndDateTime=2026-07-28T12:00:00Z," +
		"aggregationIntervalInMinutes=30)"
	if got != want {
		t.Errorf("buildURL = %q, want %q", got, want)
	}
}

// TestWindowEndTruncatedToThirtyMinuteBoundary pins that the window end is
// truncated DOWN under the pinned clock — a partial trailing bucket must never
// be requested. The fakeGraph only stubs the truncated URLs; a wrong boundary
// would make every request 404 as "no body stubbed", so Collect returning no
// error here IS the assertion.
func TestWindowEndTruncatedToThirtyMinuteBoundary(t *testing.T) {
	rec := telemetrytest.New()
	c := newCollector(liveGraph())
	c.now = func() time.Time { return time.Date(2026, 7, 28, 12, 29, 59, 0, time.UTC) } // still truncates to 12:00
	if err := c.Collect(context.Background(), rec.Emitter(), nil); err != nil {
		t.Fatalf("Collect: %v (window boundary likely computed wrong)", err)
	}
}

// TestFailedFunctionEmitsNoPointOthersStillEmit pins independent degradation:
// a failure in one function contributes NOTHING (not a zero), and the other
// eighteen still emit.
func TestFailedFunctionEmitsNoPointOthersStillEmit(t *testing.T) {
	g := liveGraph()
	failURL := buildURL(betaBaseURL, "getMetricsForMfaSignInSuccess", wantStart, wantEnd)
	g.errs = map[string]error{failURL: errors.New("throttled")}

	rec := telemetrytest.New()
	err := newCollector(g).Collect(context.Background(), rec.Emitter(), nil)
	if err == nil {
		t.Fatal("expected Collect to surface the failed function as an error")
	}

	for _, p := range rec.MetricPoints(metricSignins) {
		if p.Attrs["activity"] == "mfa_signin_success" {
			t.Fatalf("got a point for the failed function: %+v", p)
		}
	}
	// The other five signin functions must still have emitted.
	var otherSignins int
	for _, p := range rec.MetricPoints(metricSignins) {
		if p.Attrs["activity"] != "mfa_signin_success" {
			otherSignins++
		}
	}
	if otherSignins != 5 {
		t.Errorf("got %d other signin series despite succeeding independently, want 5", otherSignins)
	}
	// An unrelated metric group must be fully intact.
	if len(rec.MetricPoints(metricNABranch)) != 5 {
		t.Errorf("got %d network_access_branches series, want 5 (unaffected by the signin failure)", len(rec.MetricPoints(metricNABranch)))
	}
}

// TestEmptyValueArrayEmitsNoPoint pins that an empty `value` array is a GAP,
// not a measured zero: no point, no error, and the other functions are
// unaffected.
func TestEmptyValueArrayEmitsNoPoint(t *testing.T) {
	g := liveGraph()
	emptyURL := buildURL(betaBaseURL, "getMetricsForSamlSignInSuccess", wantStart, wantEnd)
	g.bodies[emptyURL] = `{"@odata.context":"x","value":[]}`

	rec := telemetrytest.New()
	if err := newCollector(g).Collect(context.Background(), rec.Emitter(), nil); err != nil {
		t.Fatalf("Collect: %v, want nil (an empty response is a gap, not a failure)", err)
	}
	for _, p := range rec.MetricPoints(metricSignins) {
		if p.Attrs["activity"] == "saml_signin_success" {
			t.Fatalf("got a point for an empty-value-array function: %+v", p)
		}
	}
	var otherSignins int
	for _, p := range rec.MetricPoints(metricSignins) {
		if p.Attrs["activity"] != "saml_signin_success" {
			otherSignins++
		}
	}
	if otherSignins != 5 {
		t.Errorf("got %d other signin series, want 5 (unaffected by the empty response)", otherSignins)
	}
}

// TestBucketMissingValueFieldEmitsNoPoint pins the other gap shape: a bucket
// present but carrying no "value" at all is likewise not a measured zero.
func TestBucketMissingValueFieldEmitsNoPoint(t *testing.T) {
	g := liveGraph()
	url := buildURL(betaBaseURL, "getMetricsForConditionalAccessBlockedSignIn", wantStart, wantEnd)
	g.bodies[url] = `{"@odata.context":"x","value":[{"intervalStartDateTime":"2026-07-28T10:00:00Z"}]}`

	rec := telemetrytest.New()
	if err := newCollector(g).Collect(context.Background(), rec.Emitter(), nil); err != nil {
		t.Fatalf("Collect: %v", err)
	}
	for _, p := range rec.MetricPoints(metricSignins) {
		if p.Attrs["activity"] == "ca_blocked_signin" {
			t.Fatalf("got a point despite every bucket omitting value: %+v", p)
		}
	}
}

// TestFourMetricsCarryDistinctUnits pins that signins/apps/users/branches are
// four metrics with four distinct units, not one metric with a mixed unit.
func TestFourMetricsCarryDistinctUnits(t *testing.T) {
	rec := telemetrytest.New()
	if err := newCollector(liveGraph()).Collect(context.Background(), rec.Emitter(), nil); err != nil {
		t.Fatalf("Collect: %v", err)
	}
	wantUnits := map[string]string{
		metricSignins:  "{signin}",
		metricNAApps:   "{app}",
		metricNAUsers:  "{user}",
		metricNABranch: "{branch}",
	}
	for name, wantUnit := range wantUnits {
		pts := rec.MetricPoints(name)
		if len(pts) == 0 {
			t.Fatalf("no points for %s", name)
		}
		if pts[0].Unit != wantUnit {
			t.Errorf("%s unit = %q, want %q", name, pts[0].Unit, wantUnit)
		}
	}
}

// TestNameInterfacesAndPermissions pins the collector identity, the beta gate,
// and the honestly-reused (not invented) permission.
func TestNameInterfacesAndPermissions(t *testing.T) {
	c := New(&fakeGraph{}, nil)
	if c.Name() != "entra.service_activity" {
		t.Errorf("Name = %q, want entra.service_activity", c.Name())
	}
	if !c.Experimental() {
		t.Error("Experimental() = false, want true (pure-beta collector)")
	}
	if got := c.DefaultInterval(); got != 30*time.Minute {
		t.Errorf("DefaultInterval = %v, want 30m", got)
	}
	perms := c.RequiredPermissions()
	if len(perms) != 1 || perms[0] != "Reports.Read.All" {
		t.Errorf("RequiredPermissions = %v, want [Reports.Read.All]", perms)
	}
}

// TestEmittedAttributeKeysAreExactly is an ALLOW-list, not a denylist of one
// name: it is the guard the interval_start mistake needed. internal/
// signalcapture's per-entity check is an exact-match denylist that has no
// way to flag a key it was never told about, which is exactly how a
// timestamp-valued label shipped once already (see the package doc's
// "no interval_start attribute" section and attrs_entra_serviceactivity.go's
// correction block). This test instead states the POSITIVE, closed set every
// emitted metric point may carry, so a future attribute added here — whatever
// its name — fails this test unless it is added to wantKeys deliberately.
func TestEmittedAttributeKeysAreExactly(t *testing.T) {
	wantKeys := map[string]struct{}{
		"activity":                     {},
		"aggregation_interval_minutes": {},
	}

	rec := telemetrytest.New()
	if err := newCollector(liveGraph()).Collect(context.Background(), rec.Emitter(), nil); err != nil {
		t.Fatalf("Collect: %v", err)
	}

	for _, name := range metricOrder {
		pts := rec.MetricPoints(name)
		if len(pts) == 0 {
			t.Fatalf("no points for %s", name)
		}
		for _, p := range pts {
			if len(p.Attrs) != len(wantKeys) {
				t.Errorf("%s point %v carries %d attrs, want exactly %d (%v)", name, p.Attrs, len(p.Attrs), len(wantKeys), wantKeys)
				continue
			}
			for k := range p.Attrs {
				if _, ok := wantKeys[k]; !ok {
					t.Errorf("%s point carries unexpected attribute %q (attrs=%v) — this test is an allow-list: "+
						"add it to wantKeys deliberately, or remove it", name, k, p.Attrs)
				}
			}
		}
	}
}
