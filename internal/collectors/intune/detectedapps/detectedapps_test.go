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
