package organization

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/rknightion/graph2otel/internal/collectors"
	"github.com/rknightion/graph2otel/internal/telemetrytest"
)

// fakeGraph maps request URLs to canned response bodies (or errors).
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

const base = "https://graph.microsoft.com/v1.0"
const orgURL = base + "/organization"

// fixedNow is the deterministic "now" every test injects via Collector.now so
// sync-age / tenant-age assertions never flake against wall-clock time.
var fixedNow = time.Date(2026, 7, 15, 12, 0, 0, 0, time.UTC)

func newCollectorAt(g collectors.GraphClient, now time.Time) *Collector {
	c := New(g, nil)
	c.now = func() time.Time { return now }
	return c
}

func hybridSyncedBody(lastSync string) string {
	return `{
		"value": [
			{
				"id": "tenant-1",
				"displayName": "Contoso",
				"tenantType": "AAD",
				"createdDateTime": "2020-01-01T00:00:00Z",
				"onPremisesSyncEnabled": true,
				"onPremisesLastSyncDateTime": "` + lastSync + `",
				"verifiedDomains": [
					{"name": "contoso.com", "isDefault": true},
					{"name": "contoso.onmicrosoft.com", "isDefault": false}
				]
			}
		]
	}`
}

func TestCollectEmitsSyncEnabledAndAgeWhenHybridSyncActive(t *testing.T) {
	// 2 hours before fixedNow.
	lastSync := "2026-07-15T10:00:00Z"
	g := &fakeGraph{bodies: map[string]string{orgURL: hybridSyncedBody(lastSync)}}
	rec := telemetrytest.New()

	c := newCollectorAt(g, fixedNow)
	if err := c.Collect(context.Background(), rec.Emitter()); err != nil {
		t.Fatalf("Collect: %v", err)
	}

	enabled := rec.MetricPoints(syncEnabledMetricName)
	if len(enabled) != 1 || enabled[0].Value != 1 {
		t.Fatalf("on_premises_sync_enabled points = %+v, want single point value=1", enabled)
	}

	age := rec.MetricPoints(syncAgeMetricName)
	if len(age) != 1 {
		t.Fatalf("sync age points = %+v, want exactly 1", age)
	}
	wantSeconds := 2 * time.Hour.Seconds()
	if age[0].Value != wantSeconds {
		t.Errorf("sync age = %v, want %v", age[0].Value, wantSeconds)
	}
}

func TestCollectOmitsSyncAgeWhenSyncDisabled(t *testing.T) {
	body := `{
		"value": [
			{
				"id": "tenant-1",
				"tenantType": "AAD",
				"onPremisesSyncEnabled": false,
				"onPremisesLastSyncDateTime": "2026-07-15T10:00:00Z"
			}
		]
	}`
	g := &fakeGraph{bodies: map[string]string{orgURL: body}}
	rec := telemetrytest.New()

	c := newCollectorAt(g, fixedNow)
	if err := c.Collect(context.Background(), rec.Emitter()); err != nil {
		t.Fatalf("Collect: %v", err)
	}

	enabled := rec.MetricPoints(syncEnabledMetricName)
	if len(enabled) != 1 || enabled[0].Value != 0 {
		t.Fatalf("on_premises_sync_enabled points = %+v, want single point value=0", enabled)
	}
	if age := rec.MetricPoints(syncAgeMetricName); len(age) != 0 {
		t.Errorf("expected no sync-age series when sync disabled, got %+v", age)
	}
}

func TestCollectOmitsSyncAgeWhenNeverSynced(t *testing.T) {
	// Cloud-only tenant: both fields null (the documented default).
	body := `{
		"value": [
			{
				"id": "tenant-1",
				"tenantType": "AAD",
				"onPremisesSyncEnabled": null,
				"onPremisesLastSyncDateTime": null
			}
		]
	}`
	g := &fakeGraph{bodies: map[string]string{orgURL: body}}
	rec := telemetrytest.New()

	c := newCollectorAt(g, fixedNow)
	if err := c.Collect(context.Background(), rec.Emitter()); err != nil {
		t.Fatalf("Collect: %v", err)
	}

	enabled := rec.MetricPoints(syncEnabledMetricName)
	if len(enabled) != 1 || enabled[0].Value != 0 {
		t.Fatalf("on_premises_sync_enabled points = %+v, want single point value=0 for a cloud-only tenant", enabled)
	}
	if age := rec.MetricPoints(syncAgeMetricName); len(age) != 0 {
		t.Errorf("expected no sync-age series for a never-synced tenant, got %+v", age)
	}
}

func TestCollectOmitsSyncAgeWhenEnabledButLastSyncMissing(t *testing.T) {
	// onPremisesSyncEnabled true but onPremisesLastSyncDateTime null: age is
	// not computable, must not emit a misleading value.
	body := `{
		"value": [
			{
				"id": "tenant-1",
				"tenantType": "AAD",
				"onPremisesSyncEnabled": true,
				"onPremisesLastSyncDateTime": null
			}
		]
	}`
	g := &fakeGraph{bodies: map[string]string{orgURL: body}}
	rec := telemetrytest.New()

	c := newCollectorAt(g, fixedNow)
	if err := c.Collect(context.Background(), rec.Emitter()); err != nil {
		t.Fatalf("Collect: %v", err)
	}
	if age := rec.MetricPoints(syncAgeMetricName); len(age) != 0 {
		t.Errorf("expected no sync-age series when last-sync timestamp is absent, got %+v", age)
	}
}

func TestCollectEmitsAgeDaysFromCreatedDateTime(t *testing.T) {
	g := &fakeGraph{bodies: map[string]string{orgURL: hybridSyncedBody("2026-07-15T10:00:00Z")}}
	rec := telemetrytest.New()

	c := newCollectorAt(g, fixedNow)
	if err := c.Collect(context.Background(), rec.Emitter()); err != nil {
		t.Fatalf("Collect: %v", err)
	}

	pts := rec.MetricPoints(ageDaysMetricName)
	if len(pts) != 1 {
		t.Fatalf("age_days points = %+v, want exactly 1", pts)
	}
	wantDays := fixedNow.Sub(time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC)).Hours() / 24
	if pts[0].Value != wantDays {
		t.Errorf("age_days = %v, want %v", pts[0].Value, wantDays)
	}
}

func TestCollectEmitsVerifiedDomainsTotal(t *testing.T) {
	g := &fakeGraph{bodies: map[string]string{orgURL: hybridSyncedBody("2026-07-15T10:00:00Z")}}
	rec := telemetrytest.New()

	c := newCollectorAt(g, fixedNow)
	if err := c.Collect(context.Background(), rec.Emitter()); err != nil {
		t.Fatalf("Collect: %v", err)
	}

	pts := rec.MetricPoints(verifiedDomainsMetricName)
	if len(pts) != 1 || pts[0].Value != 2 {
		t.Fatalf("verified domains points = %+v, want single point value=2", pts)
	}
}

func TestCollectEmitsInfoGaugeWithBoundedTenantType(t *testing.T) {
	g := &fakeGraph{bodies: map[string]string{orgURL: hybridSyncedBody("2026-07-15T10:00:00Z")}}
	rec := telemetrytest.New()

	c := newCollectorAt(g, fixedNow)
	if err := c.Collect(context.Background(), rec.Emitter()); err != nil {
		t.Fatalf("Collect: %v", err)
	}

	pts := rec.MetricPoints(infoMetricName)
	if len(pts) != 1 || pts[0].Value != 1 {
		t.Fatalf("info points = %+v, want single point value=1", pts)
	}
	if got := pts[0].Attrs["tenant_type"]; got != "AAD" {
		t.Errorf("info tenant_type attr = %q, want %q", got, "AAD")
	}
}

func TestCollectHandlesEmptyOrganizationCollection(t *testing.T) {
	g := &fakeGraph{bodies: map[string]string{orgURL: `{"value": []}`}}
	rec := telemetrytest.New()

	c := newCollectorAt(g, fixedNow)
	if err := c.Collect(context.Background(), rec.Emitter()); err != nil {
		t.Fatalf("Collect: %v", err)
	}
	if names := rec.MetricNames(); len(names) != 0 {
		t.Errorf("expected no metrics for an empty /organization collection, got %v", names)
	}
}

func TestCollectSurfacesGraphFetchError(t *testing.T) {
	g := &fakeGraph{errs: map[string]error{orgURL: errors.New("throttled")}}
	rec := telemetrytest.New()

	c := newCollectorAt(g, fixedNow)
	if err := c.Collect(context.Background(), rec.Emitter()); err == nil {
		t.Fatal("expected Collect to surface the /organization fetch error")
	}
	if names := rec.MetricNames(); len(names) != 0 {
		t.Errorf("expected no metrics emitted on fetch failure, got %v", names)
	}
}

func TestNameIntervalAndPermissions(t *testing.T) {
	c := New(&fakeGraph{}, nil)
	if c.Name() != "entra.organization" {
		t.Errorf("Name = %q", c.Name())
	}
	if c.DefaultInterval() <= 0 {
		t.Errorf("DefaultInterval = %v, want positive", c.DefaultInterval())
	}
	perms := c.RequiredPermissions()
	if len(perms) != 1 || perms[0] != "Organization.Read.All" {
		t.Errorf("RequiredPermissions = %v, want [Organization.Read.All]", perms)
	}
}

// TestCollectNeverEmitsHighCardinalityLabels is the cardinality guard the
// authoring guide requires: this is a single tenant-wide object, so nothing
// here may carry the tenant id or displayName (both high-cardinality across a
// fleet of tenants) as a metric label. tenant_id is applied by the scheduler,
// not by the collector. Only the bounded "tenant_type" attribute is allowed,
// and only on the info gauge.
func TestCollectNeverEmitsHighCardinalityLabels(t *testing.T) {
	g := &fakeGraph{bodies: map[string]string{orgURL: hybridSyncedBody("2026-07-15T10:00:00Z")}}
	rec := telemetrytest.New()

	c := newCollectorAt(g, fixedNow)
	if err := c.Collect(context.Background(), rec.Emitter()); err != nil {
		t.Fatalf("Collect: %v", err)
	}

	for _, name := range rec.MetricNames() {
		for _, p := range rec.MetricPoints(name) {
			for k, v := range p.Attrs {
				if k != "tenant_type" {
					t.Errorf("metric %s has unexpected attribute %q=%q (only tenant_type is allowed)", name, k, v)
				}
				if v == "tenant-1" || v == "Contoso" {
					t.Errorf("metric %s attribute %q=%q looks like a leaked tenant id/displayName", name, k, v)
				}
			}
		}
	}
}
