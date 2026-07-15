package enrollment

import (
	"context"
	"errors"
	"testing"

	"github.com/rknightion/graph2otel/internal/collectors"
	"github.com/rknightion/graph2otel/internal/telemetrytest"
)

// fakeGraph maps request URLs to canned page bodies (or errors). Every
// fixture here is a single page; GetAllValues follows @odata.nextLink but
// none of these tests exercise pagination.
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
	return []byte(f.bodies[url]), nil
}

var _ collectors.GraphClient = (*fakeGraph)(nil)

const (
	base           = "https://graph.microsoft.com/v1.0"
	enrollmentsURL = base + "/deviceManagement/deviceEnrollmentConfigurations"
)

func page(itemsJSON string) string {
	return `{"value":[` + itemsJSON + `]}`
}

// sampleConfigs mixes every known deviceEnrollmentConfiguration subtype plus
// one unrecognized future subtype, so tests can assert both the known
// buckets and the "other" leftover bucket in one fixture.
const sampleConfigs = `
{"@odata.type":"#microsoft.graph.deviceEnrollmentLimitConfiguration","id":"e1","displayName":"All users","priority":0,"version":1},
{"@odata.type":"#microsoft.graph.deviceEnrollmentPlatformRestrictionsConfiguration","id":"e2","displayName":"Platform restrictions","priority":1,"version":2},
{"@odata.type":"#microsoft.graph.windows10EnrollmentCompletionPageConfiguration","id":"e3","displayName":"ESP - Corp devices","priority":2,"version":5},
{"@odata.type":"#microsoft.graph.deviceEnrollmentWindowsHelloForBusinessConfiguration","id":"e4","displayName":"WHfB default","priority":3,"version":1},
{"@odata.type":"#microsoft.graph.deviceComanagementAuthorityConfiguration","id":"e5","displayName":"Co-management","priority":4,"version":1},
{"@odata.type":"#microsoft.graph.someFutureConfigurationType","id":"e6","displayName":"Unknown future type","priority":5,"version":1}
`

func fixture() map[string]string {
	return map[string]string{enrollmentsURL: page(sampleConfigs)}
}

func TestCollectEmitsCountByConfigType(t *testing.T) {
	g := &fakeGraph{bodies: fixture()}
	rec := telemetrytest.New()

	if err := New(g, nil).Collect(context.Background(), rec.Emitter()); err != nil {
		t.Fatalf("Collect: %v", err)
	}

	got := map[string]float64{}
	for _, p := range rec.MetricPoints(countMetricName) {
		got[p.Attrs["config_type"]] = p.Value
	}
	want := map[string]float64{
		"limit":                      1,
		"platform_restrictions":      1,
		"esp":                        1,
		"windows_hello_for_business": 1,
		"comanagement_authority":     1,
		"other":                      1,
	}
	if len(got) != len(want) {
		t.Fatalf("got %d config_type series, want %d: %v", len(got), len(want), got)
	}
	for typ, v := range want {
		if got[typ] != v {
			t.Errorf("config_type=%s count = %v, want %v", typ, got[typ], v)
		}
	}
}

func TestCollectEmitsPriorityByTypeAndName(t *testing.T) {
	g := &fakeGraph{bodies: fixture()}
	rec := telemetrytest.New()

	if err := New(g, nil).Collect(context.Background(), rec.Emitter()); err != nil {
		t.Fatalf("Collect: %v", err)
	}

	type key struct{ typ, name string }
	got := map[key]float64{}
	for _, p := range rec.MetricPoints(priorityMetricName) {
		got[key{p.Attrs["config_type"], p.Attrs["config_name"]}] = p.Value
	}
	want := map[key]float64{
		{"limit", "All users"}:                             0,
		{"platform_restrictions", "Platform restrictions"}: 1,
		{"esp", "ESP - Corp devices"}:                      2,
		{"windows_hello_for_business", "WHfB default"}:     3,
		{"comanagement_authority", "Co-management"}:        4,
		{"other", "Unknown future type"}:                   5,
	}
	if len(got) != len(want) {
		t.Fatalf("got %d priority series, want %d: %v", len(got), len(want), got)
	}
	for k, v := range want {
		if got[k] != v {
			t.Errorf("priority[%+v] = %v, want %v", k, got[k], v)
		}
	}
}

func TestCollectEmitsVersionByConfigName(t *testing.T) {
	g := &fakeGraph{bodies: fixture()}
	rec := telemetrytest.New()

	if err := New(g, nil).Collect(context.Background(), rec.Emitter()); err != nil {
		t.Fatalf("Collect: %v", err)
	}

	got := map[string]float64{}
	for _, p := range rec.MetricPoints(versionMetricName) {
		got[p.Attrs["config_name"]] = p.Value
	}
	want := map[string]float64{
		"All users":             1,
		"Platform restrictions": 2,
		"ESP - Corp devices":    5,
		"WHfB default":          1,
		"Co-management":         1,
		"Unknown future type":   1,
	}
	if len(got) != len(want) {
		t.Fatalf("got %d version series, want %d: %v", len(got), len(want), got)
	}
	for name, v := range want {
		if got[name] != v {
			t.Errorf("version[%s] = %v, want %v", name, got[name], v)
		}
	}
}

func TestCollectIsResilientToFetchError(t *testing.T) {
	g := &fakeGraph{errs: map[string]error{enrollmentsURL: errors.New("403 Forbidden: missing scope")}}
	rec := telemetrytest.New()

	if err := New(g, nil).Collect(context.Background(), rec.Emitter()); err == nil {
		t.Error("expected Collect to surface the fetch failure as an error")
	}

	for _, name := range []string{countMetricName, priorityMetricName, versionMetricName} {
		if pts := rec.MetricPoints(name); len(pts) != 0 {
			t.Errorf("metric %s: expected no points when the fetch failed, got %d", name, len(pts))
		}
	}
}

func TestCollectSkipsUnparseableEntryButEmitsTheRest(t *testing.T) {
	bodies := map[string]string{
		enrollmentsURL: page(`
			{"@odata.type":"#microsoft.graph.deviceEnrollmentLimitConfiguration","id":"e1","displayName":"All users","priority":0,"version":1},
			{"priority": "not-a-number"}
		`),
	}
	g := &fakeGraph{bodies: bodies}
	rec := telemetrytest.New()

	err := New(g, nil).Collect(context.Background(), rec.Emitter())
	if err == nil {
		t.Error("expected Collect to surface the decode failure as an error")
	}

	pts := rec.MetricPoints(countMetricName)
	var total float64
	for _, p := range pts {
		total += p.Value
	}
	if total != 1 {
		t.Errorf("total config count = %v, want 1 (unparseable entry excluded)", total)
	}
}

func TestNameAndPermissions(t *testing.T) {
	c := New(&fakeGraph{}, nil)
	if c.Name() != "intune.enrollment" {
		t.Errorf("Name = %q, want intune.enrollment", c.Name())
	}
	perms := c.RequiredPermissions()
	if len(perms) != 1 || perms[0] != "DeviceManagementServiceConfig.Read.All" {
		t.Errorf("RequiredPermissions = %v, want [DeviceManagementServiceConfig.Read.All]", perms)
	}
}

// TestNoPerEntitySeries guards the cardinality rule: no metric may carry a
// per-device or per-user identifier as an attribute — only the bounded
// config_type/config_name dimensions (admin-configured object count, not
// tenant device/user count).
func TestNoPerEntitySeries(t *testing.T) {
	g := &fakeGraph{bodies: fixture()}
	rec := telemetrytest.New()

	if err := New(g, nil).Collect(context.Background(), rec.Emitter()); err != nil {
		t.Fatalf("Collect: %v", err)
	}

	allowed := map[string]map[string]bool{
		countMetricName:    {"config_type": true},
		priorityMetricName: {"config_type": true, "config_name": true},
		versionMetricName:  {"config_name": true},
	}
	for name, allowedAttrs := range allowed {
		for _, p := range rec.MetricPoints(name) {
			for k := range p.Attrs {
				if !allowedAttrs[k] {
					t.Errorf("%s series has unexpected attribute %q (possible per-entity leak): %v", name, k, p.Attrs)
				}
			}
		}
	}
}
