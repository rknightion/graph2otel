package clouddiscovery

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"
	"testing"

	"github.com/rknightion/graph2otel/internal/collectors"
	"github.com/rknightion/graph2otel/internal/telemetrytest"
	"github.com/rknightion/graph2otel/internal/wirecheck"
)

// fakeGraph maps request URLs to canned bodies or errors, mirroring the
// tenantpolicy test's style. Any aggregatedAppsDetails URL with no explicit
// stub answers an empty page — most of the 6 live streams carry no apps in
// these fixtures, and stubbing all of them by hand would bury the signal.
type fakeGraph struct {
	bodies map[string]string
	errs   map[string]error
	calls  []string
}

func (f *fakeGraph) RawGet(_ context.Context, url string) ([]byte, error) {
	f.calls = append(f.calls, url)
	if err, ok := f.errs[url]; ok {
		return nil, err
	}
	if body, ok := f.bodies[url]; ok {
		return []byte(body), nil
	}
	if strings.Contains(url, "aggregatedAppsDetails") {
		return []byte(`{"value":[]}`), nil
	}
	return nil, fmt.Errorf("fakeGraph: no body stubbed for %s", url)
}

func (f *fakeGraph) RawGetWithHeaders(ctx context.Context, url string, _ map[string]string) ([]byte, error) {
	return f.RawGet(ctx, url)
}

var _ collectors.GraphClient = (*fakeGraph)(nil)

const streamsURL = betaBaseURL + streamsPath

func appsURL(streamID string) string {
	return betaBaseURL + streamsPath + "/" + streamID + "/aggregatedAppsDetails(period=duration'P30D')"
}

// The 6 live stream ids captured 2026-07-28 (#361).
var liveStreamIDs = []string{
	"6a5960087f54c9655cc99e40",
	"6a58043433e90bcbda5b88b4",
	"6a57f209f118769b99e398ee",
	"68c3fe754607bb32e87d44cc",
	"68c2d5c64607bb32e8a6d494",
	"68c2ae143b26fdeeff83dad4",
}

// mustReadFile is a small helper so every test reads the SAME verbatim
// captures rather than each hand-copying a path.
func mustReadFile(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	return string(b)
}

// TestCollectEmitsSixStreamTwinsAndHundredAppTwins drives BOTH live captures
// (#361) end-to-end through the real collector: the verbatim 6-stream list and
// the verbatim 100-app first page (stubbed against stream
// 6a5960087f54c9655cc99e40, the stream whose @odata.nextLink the live capture
// actually returned; the other 5 streams have no apps in this fixture, which
// is itself a real live shape — most streams have no discovered apps in a
// given tenant). A thin golden is a defect (internal/signalcapture): this
// pins the full 6+100 twin count and that category buckets sum to 100, not
// just that Collect returns without error.
func TestCollectEmitsSixStreamTwinsAndHundredAppTwins(t *testing.T) {
	g := &fakeGraph{
		bodies: map[string]string{
			streamsURL:                          mustReadFile(t, "testdata/streams.json"),
			appsURL("6a5960087f54c9655cc99e40"): mustReadFile(t, "testdata/apps_page1.json"),
			appsURL("6a5960087f54c9655cc99e40") + "?$skip=100": `{"value":[]}`,
		},
	}
	rec := telemetrytest.New()

	if err := New(g, nil).Collect(context.Background(), rec.Emitter(), nil); err != nil {
		t.Fatalf("Collect: %v", err)
	}

	var streamTwins, appTwins []string
	for _, r := range rec.LogRecords() {
		switch r.EventName {
		case eventStream:
			streamTwins = append(streamTwins, r.Attrs["id"])
		case eventApp:
			appTwins = append(appTwins, r.Attrs["id"])
		}
	}
	if len(streamTwins) != 6 {
		t.Fatalf("got %d stream twins, want 6: %v", len(streamTwins), streamTwins)
	}
	for _, want := range liveStreamIDs {
		found := false
		for _, got := range streamTwins {
			if got == want {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("missing stream twin for id=%s", want)
		}
	}
	if len(appTwins) != 100 {
		t.Fatalf("got %d app twins, want 100", len(appTwins))
	}

	pts := rec.MetricPoints(metricApps)
	total := 0.0
	seenCategories := map[string]bool{}
	for _, p := range pts {
		total += p.Value
		seenCategories[p.Attrs["category"]] = true
	}
	if total != 100 {
		t.Errorf("category buckets sum to %v, want 100", total)
	}
	if len(seenCategories) != 28 {
		t.Errorf("got %d distinct category series, want 28: %v", len(seenCategories), seenCategories)
	}
}

// TestDomainsCappedWithTrueCount pins the 355-domain app (Amazon CloudFront,
// id=26075, live #361): the twin's domains array is capped at maxDomains,
// domain_count reports the TRUE uncapped count, and domains_truncated is set
// — all three, since the count is the load-bearing half (a reader must be able
// to tell 355 from 50 without recounting the capped array).
func TestDomainsCappedWithTrueCount(t *testing.T) {
	g := &fakeGraph{
		bodies: map[string]string{
			streamsURL:                          mustReadFile(t, "testdata/streams.json"),
			appsURL("6a5960087f54c9655cc99e40"): mustReadFile(t, "testdata/apps_page1.json"),
		},
	}
	rec := telemetrytest.New()

	if err := New(g, nil).Collect(context.Background(), rec.Emitter(), nil); err != nil {
		t.Fatalf("Collect: %v", err)
	}

	var cloudfront *telemetrytest.LogRecord
	for _, r := range rec.LogRecords() {
		if r.EventName == eventApp && r.Attrs["id"] == "26075" {
			r := r
			cloudfront = &r
			break
		}
	}
	if cloudfront == nil {
		t.Fatal("no twin found for app id=26075 (Amazon CloudFront)")
	}
	domains := strings.Split(cloudfront.Attrs["domains"], ",")
	if len(domains) != maxDomains {
		t.Errorf("capped domains list has %d entries, want %d", len(domains), maxDomains)
	}
	if got := cloudfront.Attrs["domain_count"]; got != "355" {
		t.Errorf("domain_count = %q, want \"355\"", got)
	}
	if got := cloudfront.Attrs["domains_truncated"]; got != "true" {
		t.Errorf("domains_truncated = %q, want \"true\"", got)
	}
}

// TestNoPerEntityDataLeaksIntoAnyMetricLabel is the #112 cardinality assertion
// over EVERY emitted metric point, not a sample of one: no app id, display
// name, or domain from the live fixture may appear as a metric attribute
// value anywhere.
func TestNoPerEntityDataLeaksIntoAnyMetricLabel(t *testing.T) {
	g := &fakeGraph{
		bodies: map[string]string{
			streamsURL:                          mustReadFile(t, "testdata/streams.json"),
			appsURL("6a5960087f54c9655cc99e40"): mustReadFile(t, "testdata/apps_page1.json"),
		},
	}
	rec := telemetrytest.New()

	if err := New(g, nil).Collect(context.Background(), rec.Emitter(), nil); err != nil {
		t.Fatalf("Collect: %v", err)
	}

	forbidden := map[string]bool{
		"26075":                    true, // Amazon CloudFront app id
		"Amazon CloudFront":        true,
		"cloudflare.com":           true, // a domain from the CloudFlare app
		"6a5960087f54c9655cc99e40": true, // a stream id
		"zenupload":                true, // a stream display name
	}

	for _, name := range rec.MetricNames() {
		for _, p := range rec.MetricPoints(name) {
			for k, v := range p.Attrs {
				if forbidden[v] {
					t.Errorf("metric %s attr %s=%q leaks per-entity data into a metric label", name, k, v)
				}
			}
		}
	}
}

// TestRiskBandBoundaries pins the exact banding edges so an off-by-one in the
// switch is impossible: 3/4 (low/medium) and 6/7 (medium/high) and 8/9
// (high/critical).
func TestRiskBandBoundaries(t *testing.T) {
	cases := []struct {
		score int64
		want  string
	}{
		{1, "low"}, {3, "low"},
		{4, "medium"}, {6, "medium"},
		{7, "high"}, {8, "high"},
		{9, "critical"}, {10, "critical"},
	}
	for _, tc := range cases {
		t.Run(strconv.FormatInt(tc.score, 10), func(t *testing.T) {
			if got := riskBand(tc.score); got != tc.want {
				t.Errorf("riskBand(%d) = %q, want %q", tc.score, got, tc.want)
			}
		})
	}
}

// syntheticStreams builds a two-stream uploadedStreams response: one carries
// anonymizeUserData=false explicitly, the other omits the field entirely —
// exercising both halves of "absent is not false".
const syntheticStreams = `{"value":[
  {"id":"stream-present","displayName":"present","anonymizeUserData":false,"anonymizeMachineData":true,"isSnapshotReport":false,"logFileCount":10},
  {"id":"stream-absent","displayName":"absent","logFileCount":5}
]}`

func TestAbsentIsNotFalse(t *testing.T) {
	g := &fakeGraph{bodies: map[string]string{streamsURL: syntheticStreams}}
	rec := telemetrytest.New()

	if err := New(g, nil).Collect(context.Background(), rec.Emitter(), nil); err != nil {
		t.Fatalf("Collect: %v", err)
	}

	var present, absent *telemetrytest.LogRecord
	for _, r := range rec.LogRecords() {
		if r.EventName != eventStream {
			continue
		}
		r := r
		switch r.Attrs["id"] {
		case "stream-present":
			present = &r
		case "stream-absent":
			absent = &r
		}
	}
	if present == nil || absent == nil {
		t.Fatal("expected both synthetic stream twins")
	}
	if got := present.Attrs["anonymize_user_data"]; got != "false" {
		t.Errorf("present stream anonymize_user_data = %q, want \"false\" (wire said false)", got)
	}
	if got := present.Attrs["anonymize_machine_data"]; got != "true" {
		t.Errorf("present stream anonymize_machine_data = %q, want \"true\"", got)
	}
	if _, ok := absent.Attrs["anonymize_user_data"]; ok {
		t.Errorf("absent stream anonymize_user_data = %q, want omitted entirely (wire never carried the key)", absent.Attrs["anonymize_user_data"])
	}
	if _, ok := absent.Attrs["anonymize_machine_data"]; ok {
		t.Error("absent stream anonymize_machine_data present, want omitted")
	}
	if _, ok := absent.Attrs["is_snapshot_report"]; ok {
		t.Error("absent stream is_snapshot_report present, want omitted")
	}

	// The streams metric buckets the stream lacking the field under "unknown",
	// never silently joining "false".
	byBucket := map[string]float64{}
	for _, p := range rec.MetricPoints(metricStreams) {
		byBucket[p.Attrs["is_snapshot_report"]] += p.Value
	}
	if byBucket["false"] != 1 {
		t.Errorf("false bucket = %v, want 1", byBucket["false"])
	}
	if byBucket["unknown"] != 1 {
		t.Errorf("unknown bucket = %v, want 1", byBucket["unknown"])
	}
}

// TestOneStreamAppFetchFailureDoesNotBlockTheOthers pins independent
// degradation: streams and apps degrade independently. One stream's
// aggregatedAppsDetails failing must still emit every stream twin and every
// OTHER stream's apps, with the failure surfaced as a non-nil returned error.
func TestOneStreamAppFetchFailureDoesNotBlockTheOthers(t *testing.T) {
	failingID := "6a58043433e90bcbda5b88b4"
	g := &fakeGraph{
		bodies: map[string]string{
			streamsURL:                          mustReadFile(t, "testdata/streams.json"),
			appsURL("6a5960087f54c9655cc99e40"): mustReadFile(t, "testdata/apps_page1.json"),
		},
		errs: map[string]error{
			appsURL(failingID): errors.New("throttled"),
		},
	}
	rec := telemetrytest.New()

	err := New(g, nil).Collect(context.Background(), rec.Emitter(), nil)
	if err == nil {
		t.Fatal("expected Collect to surface the per-stream fetch failure")
	}

	var streamTwins []string
	appCount := 0
	for _, r := range rec.LogRecords() {
		switch r.EventName {
		case eventStream:
			streamTwins = append(streamTwins, r.Attrs["id"])
		case eventApp:
			appCount++
		}
	}
	if len(streamTwins) != 6 {
		t.Fatalf("got %d stream twins after one stream's app fetch failed, want all 6: %v", len(streamTwins), streamTwins)
	}
	if appCount != 100 {
		t.Fatalf("got %d app twins, want 100 (the other stream's apps must still be emitted)", appCount)
	}
}

// buildAppsPage builds a synthetic aggregatedAppsDetails page JSON body with n
// apps (ids app-<start>..app-<start+n-1>) and an optional nextLink.
func buildAppsPage(start, n int, nextLink string) string {
	var b strings.Builder
	b.WriteString(`{"value":[`)
	for i := 0; i < n; i++ {
		if i > 0 {
			b.WriteString(",")
		}
		fmt.Fprintf(&b, `{"id":"app-%d","displayName":"App %d","category":"productivity","riskScore":5}`, start+i, start+i)
	}
	b.WriteString(`]`)
	if nextLink != "" {
		fmt.Fprintf(&b, `,"@odata.nextLink":%q`, nextLink)
	}
	b.WriteString(`}`)
	return b.String()
}

// TestAppPagingFollowsNextLink is a SYNTHETIC (hand-built) two-page fixture:
// the point is the paging CODE PATH, not a claim about a real page size.
func TestAppPagingFollowsNextLink(t *testing.T) {
	streamID := "6a57f209f118769b99e398ee" // "main", a real live id
	page2URL := appsURL(streamID) + "?$skip=2"
	g := &fakeGraph{
		bodies: map[string]string{
			streamsURL:        mustReadFile(t, "testdata/streams.json"),
			appsURL(streamID): buildAppsPage(0, 2, page2URL),
			page2URL:          buildAppsPage(2, 3, ""),
		},
	}
	rec := telemetrytest.New()

	if err := New(g, nil).Collect(context.Background(), rec.Emitter(), nil); err != nil {
		t.Fatalf("Collect: %v", err)
	}

	count := 0
	for _, r := range rec.LogRecords() {
		if r.EventName == eventApp {
			count++
		}
	}
	if count != 5 {
		t.Fatalf("got %d app twins across two pages, want 5 (2 + 3)", count)
	}
}

// TestAppsCapAtMaxPerStream pins the load-bearing cap: a stream returning 501
// apps across many synthetic pages yields exactly maxAppsPerStream twins, the
// stream twin and the tenant-wide truncated-count metric both report it, and
// the collector stops paging once the cap is reached (never fetches a page
// past it).
func TestAppsCapAtMaxPerStream(t *testing.T) {
	streamID := "68c3fe754607bb32e87d44cc" // "Defender-managed endpoints", a real live id
	const pageSize = 100
	const totalApps = maxAppsPerStream + 1 // 501

	bodies := map[string]string{streamsURL: mustReadFile(t, "testdata/streams.json")}
	next := appsURL(streamID)
	remaining := totalApps
	start := 0
	var pageURLs []string
	for remaining > 0 {
		n := pageSize
		if remaining < n {
			n = remaining
		}
		remaining -= n
		var nextLink string
		if remaining > 0 {
			nextLink = fmt.Sprintf("%s?$skip=%d", appsURL(streamID), start+n)
		}
		bodies[next] = buildAppsPage(start, n, nextLink)
		pageURLs = append(pageURLs, next)
		start += n
		next = nextLink
	}

	g := &fakeGraph{bodies: bodies}
	rec := telemetrytest.New()

	if err := New(g, nil).Collect(context.Background(), rec.Emitter(), nil); err != nil {
		t.Fatalf("Collect: %v", err)
	}

	count := 0
	var streamTwin *telemetrytest.LogRecord
	for _, r := range rec.LogRecords() {
		switch r.EventName {
		case eventApp:
			count++
		case eventStream:
			if r.Attrs["id"] == streamID {
				r := r
				streamTwin = &r
			}
		}
	}
	if count != maxAppsPerStream {
		t.Fatalf("got %d app twins, want exactly %d (the cap)", count, maxAppsPerStream)
	}
	if streamTwin == nil {
		t.Fatal("no stream twin for the capped stream")
	}
	if got := streamTwin.Attrs["apps_truncated"]; got != "true" {
		t.Errorf("stream twin apps_truncated = %q, want \"true\"", got)
	}
	if got := streamTwin.Attrs["apps_discovered"]; got != strconv.Itoa(maxAppsPerStream) {
		t.Errorf("stream twin apps_discovered = %q, want %d", got, maxAppsPerStream)
	}

	pts := rec.MetricPoints(metricAppsTruncated)
	if len(pts) != 1 || pts[0].Value != 1 {
		t.Fatalf("apps_truncated metric = %+v, want exactly one point with value 1", pts)
	}

	// The cap must stop the page walk: with 501 apps at 100/page that is 6
	// pages (500 reached exactly on page 5, so page 6 is never requested).
	calledPages := 0
	for _, u := range g.calls {
		for _, pu := range pageURLs {
			if u == pu {
				calledPages++
			}
		}
	}
	const wantPagesCalled = 5 // 5*100 = 500 = the cap, reached without needing page 6
	if calledPages != wantPagesCalled {
		t.Errorf("fetched %d pages for the capped stream, want %d (paging must stop once the cap is reached)", calledPages, wantPagesCalled)
	}
}

// TestUnknownCategoryStillEmitsAndReports pins the report-only half of the
// wirecheck contract: a category outside the known set must never drop the
// app (it still becomes the twin's and the metric's category value), while
// wirecheck counts the anomaly.
func TestUnknownCategoryStillEmitsAndReports(t *testing.T) {
	body := `{"value":[{"id":"app-x","displayName":"Xapp","category":"quantumComputing","riskScore":2}]}`
	streamID := "68c2d5c64607bb32e8a6d494" // "Global view", a real live id
	g := &fakeGraph{
		bodies: map[string]string{
			streamsURL:        mustReadFile(t, "testdata/streams.json"),
			appsURL(streamID): body,
		},
	}
	rec := telemetrytest.New()

	if err := New(g, nil).Collect(context.Background(), rec.Emitter(), nil); err != nil {
		t.Fatalf("Collect: %v", err)
	}

	var twin *telemetrytest.LogRecord
	for _, r := range rec.LogRecords() {
		if r.EventName == eventApp && r.Attrs["id"] == "app-x" {
			r := r
			twin = &r
			break
		}
	}
	if twin == nil {
		t.Fatal("unknown-category app was dropped, want it still emitted")
	}
	if got := twin.Attrs["category"]; got != "quantumComputing" {
		t.Errorf("category = %q, want \"quantumComputing\"", got)
	}

	found := false
	for _, p := range rec.MetricPoints(metricApps) {
		if p.Attrs["category"] == "quantumComputing" {
			found = true
		}
	}
	if !found {
		t.Error("unknown category did not reach the metric — report-only means it must still count")
	}

	unexpected := rec.MetricPoints(wirecheck.MetricUnexpected)
	if len(unexpected) == 0 {
		t.Error("wirecheck did not report the unknown category")
	}
}

func TestCollectSurfacesStreamsFetchError(t *testing.T) {
	g := &fakeGraph{errs: map[string]error{streamsURL: errors.New("boom")}}
	rec := telemetrytest.New()

	if err := New(g, nil).Collect(context.Background(), rec.Emitter(), nil); err == nil {
		t.Fatal("expected Collect to surface the streams fetch error")
	}
}

func TestNameIntervalPermissionsExperimental(t *testing.T) {
	c := New(&fakeGraph{}, nil)
	if c.Name() != "mdca.cloud_discovery" {
		t.Errorf("Name = %q", c.Name())
	}
	if c.DefaultInterval() <= 0 {
		t.Errorf("DefaultInterval = %v, want positive", c.DefaultInterval())
	}
	perms := c.RequiredPermissions()
	if len(perms) != 1 || perms[0] != "CloudApp-Discovery.Read.All" {
		t.Errorf("RequiredPermissions = %v, want [CloudApp-Discovery.Read.All]", perms)
	}
	if !c.Experimental() {
		t.Error("Experimental() = false, want true (genuine Graph beta surface)")
	}
}
