package detectedapps

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

const listURL = "https://graph.microsoft.com/v1.0/deviceManagement/detectedApps"

// liveDetectedAppsPage is a VERBATIM first page of
// GET /deviceManagement/detectedApps read as graph2otel-poller against the
// m7kni tenant `[live-measured 2026-07-17, #165]`. It is the collector's own
// exact query (the engine requests the largest page size via a Prefer header,
// not a query param, so the first-page URL is the bare endpoint; Graph paged it
// at $top=5, hence the @odata.nextLink).
//
// It is pinned, not hand-written, so the wire shape stays honest: every field
// name (displayName, platform, deviceCount) the mapper reads is present exactly
// as Graph spells it, alongside the fields it deliberately ignores (publisher,
// sizeInByte, version, id) — a docs-derived fixture is what let "platform" get
// invented on the wrong resource (#142). Trimmed of nothing.
//
// The live top-of-catalog carries NONE of defaultAllowedApps: the first five
// rows are long-tail consumer apps ("Pizza Plus", 1Blocker, 23andMe,
// 50onPaletteServer), which is exactly why the allow-list promotion path can
// only be exercised by the synthetic fixtures below — no live row matches it —
// while catalog_size counts every row regardless.
const liveDetectedAppsPage = `{
  "@odata.context": "https://graph.microsoft.com/v1.0/$metadata#deviceManagement/detectedApps",
  "@odata.count": 1115,
  "@odata.nextLink": "https://graph.microsoft.com/v1.0/deviceManagement/detectedApps?$top=5&$skip=5",
  "value": [
    {
      "deviceCount": 1,
      "displayName": "\"Pizza Plus\"",
      "id": "004d72f9549b60ec78f335983adae52bfae6e116d5b57d50c25dbe87f5bcfe50",
      "platform": "ios",
      "publisher": "",
      "sizeInByte": 0,
      "version": "9 (12.1)"
    },
    {
      "deviceCount": 1,
      "displayName": "1Blocker",
      "id": "25970763056e35c86bc478ed4f622109958ade693c1bcd3d07adc3ea1d299c8c",
      "platform": "macOS",
      "publisher": "",
      "sizeInByte": 0,
      "version": "6.5.3"
    },
    {
      "deviceCount": 1,
      "displayName": "1Blocker",
      "id": "f5303158d1794b08316e956c9014da014d75c745afe9304ff9664e4885723d10",
      "platform": "ios",
      "publisher": "",
      "sizeInByte": 0,
      "version": "1352 (6.5.3)"
    },
    {
      "deviceCount": 1,
      "displayName": "23andMe",
      "id": "4b86f95be87b26cacf5cf393e15515da64cd4f316621450e70e862f302593559",
      "platform": "ios",
      "publisher": "",
      "sizeInByte": 0,
      "version": "115.27.0 (15.27.0)"
    },
    {
      "deviceCount": 1,
      "displayName": "50onPaletteServer",
      "id": "bc1ba865da5b79a600c574e8a1c63b187db8851a56e9edd150f805746ff993d5",
      "platform": "macOS",
      "publisher": "",
      "sizeInByte": 0,
      "version": "1.1.0"
    }
  ]
}`

func TestCollectEmitsDeviceCountForAllowListedAppsOnlyGroupedByPlatform(t *testing.T) {
	body := `{"value":[
	  {"id":"1","displayName":"Google Chrome","version":"120.0","deviceCount":50,"platform":"windows"},
	  {"id":"2","displayName":"google chrome","version":"121.0","deviceCount":25,"platform":"windows"},
	  {"id":"3","displayName":"Google Chrome","version":"120.0","deviceCount":10,"platform":"macOS"},
	  {"id":"4","displayName":"Totally Unlisted Bespoke App","version":"1.0","deviceCount":9999,"platform":"windows"},
	  {"id":"5","displayName":"Slack","version":"4.36","deviceCount":7,"platform":"windows"}
	]}`
	g := &fakeGraph{bodies: map[string]string{listURL: body}}
	rec := telemetrytest.New()

	if err := New(g, nil).Collect(context.Background(), rec.Emitter()); err != nil {
		t.Fatalf("Collect: %v", err)
	}

	got := map[string]float64{}
	for _, p := range rec.MetricPoints(deviceCountMetric) {
		got[p.Attrs["app_name"]+"/"+p.Attrs["platform"]] = p.Value
	}

	// The two Chrome/windows rows (case-insensitive match) collapse into one
	// bucket summed across versions.
	if got["Google Chrome/windows"] != 75 {
		t.Errorf("Google Chrome/windows = %v, want 75", got["Google Chrome/windows"])
	}
	if got["Google Chrome/macOS"] != 10 {
		t.Errorf("Google Chrome/macOS = %v, want 10", got["Google Chrome/macOS"])
	}
	if got["Slack/windows"] != 7 {
		t.Errorf("Slack/windows = %v, want 7", got["Slack/windows"])
	}
	// The unlisted app must never appear as a series - that's the whole
	// cardinality guard.
	for key := range got {
		if key == "Totally Unlisted Bespoke App/windows" {
			t.Errorf("unlisted app leaked into device_count series: %v", got)
		}
	}
	if len(got) != 3 {
		t.Errorf("want exactly 3 allow-listed buckets, got %d: %v", len(got), got)
	}
}

func TestCollectEmitsCatalogSizeForEveryEntryRegardlessOfAllowList(t *testing.T) {
	body := `{"value":[
	  {"id":"1","displayName":"Google Chrome","deviceCount":50,"platform":"windows"},
	  {"id":"2","displayName":"Totally Unlisted Bespoke App","deviceCount":9999,"platform":"windows"},
	  {"id":"3","displayName":"Another Unlisted App","deviceCount":3,"platform":"ios"}
	]}`
	g := &fakeGraph{bodies: map[string]string{listURL: body}}
	rec := telemetrytest.New()

	if err := New(g, nil).Collect(context.Background(), rec.Emitter()); err != nil {
		t.Fatalf("Collect: %v", err)
	}

	points := rec.MetricPoints(catalogSizeMetric)
	if len(points) != 1 {
		t.Fatalf("want exactly 1 catalog_size point, got %d", len(points))
	}
	if points[0].Value != 3 {
		t.Errorf("catalog_size = %v, want 3", points[0].Value)
	}
	if len(points[0].Attrs) != 0 {
		t.Errorf("catalog_size must carry no labels, got %v", points[0].Attrs)
	}
}

// TestCollectEmitsLiveCatalogEndToEnd drives the one real capture this package
// has through the full Collect path into a Recorder, rather than a hand-built
// success body. It pins two live facts: catalog_size reflects every fetched row
// (the second page is empty here, so 5), and the live top-of-catalog promotes
// ZERO device_count series because none of its rows are allow-listed — the
// steady state on a real tenant, and the reason the allow-list assertions above
// must stay synthetic.
func TestCollectEmitsLiveCatalogEndToEnd(t *testing.T) {
	g := &fakeGraph{bodies: map[string]string{
		listURL: liveDetectedAppsPage,
		// GetAllValues follows @odata.nextLink verbatim; terminate the walk with
		// an empty continuation so the collector sees exactly the captured page.
		listURL + "?$top=5&$skip=5": `{"value":[]}`,
	}}
	rec := telemetrytest.New()

	if err := New(g, nil).Collect(context.Background(), rec.Emitter()); err != nil {
		t.Fatalf("Collect: %v", err)
	}

	catalog := rec.MetricPoints(catalogSizeMetric)
	if len(catalog) != 1 {
		t.Fatalf("want exactly 1 catalog_size point, got %d", len(catalog))
	}
	if catalog[0].Value != 5 {
		t.Errorf("catalog_size = %v, want 5 (the captured page's rows)", catalog[0].Value)
	}
	if len(catalog[0].Attrs) != 0 {
		t.Errorf("catalog_size must carry no labels, got %v", catalog[0].Attrs)
	}

	if pts := rec.MetricPoints(deviceCountMetric); len(pts) != 0 {
		t.Errorf("device_count = %+v, want no series (no live top-of-catalog row is allow-listed)", pts)
	}
}

func TestCollectSkipsUnparseableEntriesWithoutFailing(t *testing.T) {
	body := `{"value":[
	  {"id":"1","displayName":"Slack","deviceCount":5,"platform":"windows"},
	  "not an object"
	]}`
	g := &fakeGraph{bodies: map[string]string{listURL: body}}
	rec := telemetrytest.New()

	if err := New(g, nil).Collect(context.Background(), rec.Emitter()); err != nil {
		t.Fatalf("Collect should tolerate one bad entry, got: %v", err)
	}
	got := map[string]float64{}
	for _, p := range rec.MetricPoints(deviceCountMetric) {
		got[p.Attrs["app_name"]] = p.Value
	}
	if got["Slack"] != 5 {
		t.Errorf("Slack = %v, want 5", got["Slack"])
	}
}

func TestCollectGracefulOn403(t *testing.T) {
	g := &fakeGraph{errs: map[string]error{
		listURL: errors.New("graphclient: GET " + listURL + ": status 403: {\"error\":{\"code\":\"Authorization_RequestDenied\"}}"),
	}}
	rec := telemetrytest.New()

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

func TestNameIntervalAndPermissions(t *testing.T) {
	c := New(&fakeGraph{}, nil)
	if c.Name() != "intune.detected_apps" {
		t.Errorf("Name = %q", c.Name())
	}
	if got := c.RequiredPermissions(); len(got) != 1 || got[0] != "DeviceManagementManagedDevices.Read.All" {
		t.Errorf("RequiredPermissions = %v", got)
	}
	if c.DefaultInterval() <= 0 {
		t.Error("DefaultInterval must be positive")
	}
}
