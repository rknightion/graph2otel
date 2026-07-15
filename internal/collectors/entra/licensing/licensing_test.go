package licensing

import (
	"context"
	"errors"
	"testing"

	"github.com/rknightion/graph2otel/internal/collectors"
	"github.com/rknightion/graph2otel/internal/telemetrytest"
)

// fakeGraph maps request URLs to canned response bodies (or errors) and
// records the headers seen on each request.
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

const base = "https://graph.microsoft.com/v1.0"
const skusURL = base + "/subscribedSkus"

const twoSkusBody = `{
	"value": [
		{
			"skuId": "sku-1",
			"skuPartNumber": "ENTERPRISEPACK",
			"consumedUnits": 42,
			"prepaidUnits": {"enabled": 50, "suspended": 0, "warning": 0}
		},
		{
			"skuId": "sku-2",
			"skuPartNumber": "POWER_BI_STANDARD",
			"consumedUnits": 7,
			"prepaidUnits": {"enabled": 100, "suspended": 0, "warning": 0}
		}
	]
}`

func TestCollectEmitsPerSKUConsumedAndEnabledGauges(t *testing.T) {
	g := &fakeGraph{bodies: map[string]string{skusURL: twoSkusBody}}
	rec := telemetrytest.New()

	c := New(g, nil)
	if err := c.Collect(context.Background(), rec.Emitter()); err != nil {
		t.Fatalf("Collect: %v", err)
	}

	consumed := map[string]float64{}
	for _, p := range rec.MetricPoints(consumedMetricName) {
		consumed[p.Attrs["sku"]] = p.Value
	}
	wantConsumed := map[string]float64{"ENTERPRISEPACK": 42, "POWER_BI_STANDARD": 7}
	if len(consumed) != len(wantConsumed) {
		t.Fatalf("got %d consumed series, want %d: %v", len(consumed), len(wantConsumed), consumed)
	}
	for sku, v := range wantConsumed {
		if consumed[sku] != v {
			t.Errorf("consumed[%s] = %v, want %v", sku, consumed[sku], v)
		}
	}

	enabled := map[string]float64{}
	for _, p := range rec.MetricPoints(enabledMetricName) {
		enabled[p.Attrs["sku"]] = p.Value
	}
	wantEnabled := map[string]float64{"ENTERPRISEPACK": 50, "POWER_BI_STANDARD": 100}
	if len(enabled) != len(wantEnabled) {
		t.Fatalf("got %d enabled series, want %d: %v", len(enabled), len(wantEnabled), enabled)
	}
	for sku, v := range wantEnabled {
		if enabled[sku] != v {
			t.Errorf("enabled[%s] = %v, want %v", sku, enabled[sku], v)
		}
	}
}

func TestCollectFollowsPagination(t *testing.T) {
	page1 := base + "/subscribedSkus?$top=1"
	body1 := `{
		"value": [{"skuId": "sku-1", "skuPartNumber": "ENTERPRISEPACK", "consumedUnits": 1, "prepaidUnits": {"enabled": 2}}],
		"@odata.nextLink": "` + base + `/subscribedSkus?$top=1&$skip=1"
	}`
	page2URL := base + "/subscribedSkus?$top=1&$skip=1"
	body2 := `{"value": [{"skuId": "sku-2", "skuPartNumber": "POWER_BI_STANDARD", "consumedUnits": 3, "prepaidUnits": {"enabled": 4}}]}`

	g := &fakeGraph{bodies: map[string]string{
		skusURL:  `{"value": [], "@odata.nextLink": "` + page1 + `"}`,
		page1:    body1,
		page2URL: body2,
	}}
	rec := telemetrytest.New()

	c := New(g, nil)
	if err := c.Collect(context.Background(), rec.Emitter()); err != nil {
		t.Fatalf("Collect: %v", err)
	}

	pts := rec.MetricPoints(consumedMetricName)
	if len(pts) != 2 {
		t.Fatalf("got %d consumed series across pages, want 2: %+v", len(pts), pts)
	}
}

func TestCollectSurfacesGraphError(t *testing.T) {
	g := &fakeGraph{errs: map[string]error{skusURL: errors.New("throttled")}}
	rec := telemetrytest.New()

	c := New(g, nil)
	err := c.Collect(context.Background(), rec.Emitter())
	if err == nil {
		t.Fatal("expected Collect to surface the subscribedSkus fetch error")
	}
	if len(rec.MetricPoints(consumedMetricName)) != 0 {
		t.Error("expected no consumed series to be emitted on fetch failure")
	}
	if len(rec.MetricPoints(enabledMetricName)) != 0 {
		t.Error("expected no enabled series to be emitted on fetch failure")
	}
}

func TestCollectHandlesEmptyTenant(t *testing.T) {
	g := &fakeGraph{bodies: map[string]string{skusURL: `{"value": []}`}}
	rec := telemetrytest.New()

	c := New(g, nil)
	if err := c.Collect(context.Background(), rec.Emitter()); err != nil {
		t.Fatalf("Collect: %v", err)
	}
	if len(rec.MetricPoints(consumedMetricName)) != 0 {
		t.Errorf("expected zero consumed series for an empty tenant, got %d", len(rec.MetricPoints(consumedMetricName)))
	}
}

// TestCollectNeverEmitsPerUserOrAssignmentErrorSeries is the cardinality guard
// the authoring guide requires: assignment-error detection would require
// paging every user's licenseAssignmentStates (a per-user, expensive scan with
// no v1.0 tenant-level aggregate) and is deliberately deferred rather than
// implemented as a per-user series. This asserts the collector emits ONLY the
// two bounded per-SKU gauges and nothing else, no matter what the fake backend
// returns.
func TestCollectNeverEmitsPerUserOrAssignmentErrorSeries(t *testing.T) {
	g := &fakeGraph{bodies: map[string]string{skusURL: twoSkusBody}}
	rec := telemetrytest.New()

	c := New(g, nil)
	if err := c.Collect(context.Background(), rec.Emitter()); err != nil {
		t.Fatalf("Collect: %v", err)
	}

	names := rec.MetricNames()
	want := map[string]bool{consumedMetricName: true, enabledMetricName: true}
	for _, n := range names {
		if !want[n] {
			t.Errorf("unexpected metric %q emitted; only %v are expected (assignment-errors aggregate is deferred, see collector doc comment)", n, want)
		}
	}
	if len(names) != len(want) {
		t.Errorf("got metrics %v, want exactly %v", names, want)
	}

	// Every emitted point's only attribute must be the bounded "sku" key -
	// never a per-user identifier.
	for _, name := range names {
		for _, p := range rec.MetricPoints(name) {
			if len(p.Attrs) != 1 {
				t.Errorf("%s point has %d attrs, want exactly 1 (sku): %v", name, len(p.Attrs), p.Attrs)
			}
			if _, ok := p.Attrs["sku"]; !ok {
				t.Errorf("%s point missing sku attr: %v", name, p.Attrs)
			}
		}
	}
}

func TestCollectSkipsMalformedSKUButEmitsOthers(t *testing.T) {
	body := `{
		"value": [
			{"skuId": "sku-1", "skuPartNumber": "", "consumedUnits": 1, "prepaidUnits": {"enabled": 2}},
			{"skuId": "sku-2", "skuPartNumber": "POWER_BI_STANDARD", "consumedUnits": 3, "prepaidUnits": {"enabled": 4}}
		]
	}`
	g := &fakeGraph{bodies: map[string]string{skusURL: body}}
	rec := telemetrytest.New()

	c := New(g, nil)
	if err := c.Collect(context.Background(), rec.Emitter()); err != nil {
		t.Fatalf("Collect: %v", err)
	}

	pts := rec.MetricPoints(consumedMetricName)
	if len(pts) != 1 {
		t.Fatalf("got %d consumed series, want 1 (blank skuPartNumber dropped): %+v", len(pts), pts)
	}
	if pts[0].Attrs["sku"] != "POWER_BI_STANDARD" {
		t.Errorf("surviving series sku = %q, want POWER_BI_STANDARD", pts[0].Attrs["sku"])
	}
}

func TestNameIntervalAndPermissions(t *testing.T) {
	c := New(&fakeGraph{}, nil)
	if c.Name() != "entra.licensing" {
		t.Errorf("Name = %q, want entra.licensing", c.Name())
	}
	if c.DefaultInterval() <= 0 {
		t.Error("DefaultInterval must be positive")
	}
	perms := c.RequiredPermissions()
	if len(perms) != 1 || perms[0] != "LicenseAssignment.Read.All" {
		t.Errorf("RequiredPermissions = %v, want [LicenseAssignment.Read.All]", perms)
	}
}
