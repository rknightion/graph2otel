package updates

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/rknightion/graph2otel/internal/collectors"
	"github.com/rknightion/graph2otel/internal/telemetrytest"
)

// fakeGraph maps request URLs to canned raw bodies (or errors), mirroring the
// entra/devices and intune/manageddevices reference collectors' test fake.
type fakeGraph struct {
	bodies map[string]string
	errs   map[string]error
}

func (f *fakeGraph) RawGet(_ context.Context, url string) ([]byte, error) {
	if err, ok := f.errs[url]; ok {
		return nil, err
	}
	if body, ok := f.bodies[url]; ok {
		return []byte(body), nil
	}
	return nil, errors.New("unmapped url: " + url)
}

func (f *fakeGraph) RawGetWithHeaders(ctx context.Context, url string, _ map[string]string) ([]byte, error) {
	return f.RawGet(ctx, url)
}

var _ collectors.GraphClient = (*fakeGraph)(nil)

const (
	v1Base   = "https://graph.microsoft.com/v1.0"
	betaBase = "https://graph.microsoft.com/beta"
)

var fixedNow = time.Date(2026, 7, 15, 12, 0, 0, 0, time.UTC)

func fixedClock() time.Time { return fixedNow }

func newTestCollector(g collectors.GraphClient) *Collector {
	c := New(g, nil)
	c.now = fixedClock
	return c
}

func configsURL() string { return v1Base + "/deviceManagement/deviceConfigurations" }
func statusOverviewURL(id string) string {
	return v1Base + "/deviceManagement/deviceConfigurations/" + id + "/deviceStatusOverview"
}
func featureProfilesURL() string { return betaBase + "/deviceManagement/windowsFeatureUpdateProfiles" }
func qualityProfilesURL() string { return betaBase + "/deviceManagement/windowsQualityUpdateProfiles" }
func qualityPoliciesURL() string { return betaBase + "/deviceManagement/windowsQualityUpdatePolicies" }
func driverProfilesURL() string  { return betaBase + "/deviceManagement/windowsDriverUpdateProfiles" }

func page(values ...map[string]any) string {
	b, err := json.Marshal(map[string]any{"value": values})
	if err != nil {
		panic(err)
	}
	return string(b)
}

func ring(id, name string, qualityPaused, featurePaused, qualityRollback, featureRollback bool) map[string]any {
	return map[string]any{
		"@odata.type":                       "#microsoft.graph.windowsUpdateForBusinessConfiguration",
		"id":                                id,
		"displayName":                       name,
		"qualityUpdatesPaused":              qualityPaused,
		"featureUpdatesPaused":              featurePaused,
		"qualityUpdatesPauseExpiryDateTime": "2026-08-01T00:00:00Z",
		"featureUpdatesPauseExpiryDateTime": nil,
		"qualityUpdatesWillBeRolledBack":    qualityRollback,
		"featureUpdatesWillBeRolledBack":    featureRollback,
	}
}

func otherConfig(id, name string) map[string]any {
	return map[string]any{
		"@odata.type": "#microsoft.graph.windows10GeneralConfiguration",
		"id":          id,
		"displayName": name,
	}
}

func statusOverview(pending, notApplicable, success, errCount, failed int) string {
	b, err := json.Marshal(map[string]any{
		"pendingCount":       pending,
		"notApplicableCount": notApplicable,
		"successCount":       success,
		"errorCount":         errCount,
		"failedCount":        failed,
	})
	if err != nil {
		panic(err)
	}
	return string(b)
}

func fullFixtureBodies() map[string]string {
	return map[string]string{
		configsURL(): page(
			ring("ring-1", "Broad Ring", false, true, false, true),
			otherConfig("other-1", "Some Restriction Policy"),
		),
		statusOverviewURL("ring-1"): statusOverview(1, 2, 3, 4, 5),
		featureProfilesURL(): page(map[string]any{
			"id":                   "feat-1",
			"displayName":          "21H2 Feature Profile",
			"featureUpdateVersion": "21H2",
			"endOfSupportDate":     "2026-10-14",
		}),
		qualityProfilesURL(): page(map[string]any{
			"id":          "qp-1",
			"displayName": "Quality Profile 1",
		}),
		qualityPoliciesURL(): page(map[string]any{
			"id":          "qpol-1",
			"displayName": "Quality Policy 1",
		}),
		driverProfilesURL(): page(map[string]any{
			"id":              "drv-1",
			"displayName":     "Driver Profile 1",
			"newUpdates":      7,
			"deviceReporting": 100,
			"inventorySyncStatus": map[string]any{
				"lastSuccessfulSyncDateTime": "2026-07-14T12:00:00Z",
			},
		}),
	}
}

func assertPoints(t *testing.T, rec *telemetrytest.Recorder, metric string, want map[string]float64, keyFn func(attrs map[string]string) string) {
	t.Helper()
	pts := rec.MetricPoints(metric)
	got := map[string]float64{}
	for _, p := range pts {
		got[keyFn(p.Attrs)] = p.Value
	}
	if len(got) != len(want) {
		t.Fatalf("metric %s: got %d series, want %d: %+v", metric, len(got), len(want), got)
	}
	for k, v := range want {
		gv, ok := got[k]
		if !ok {
			t.Errorf("metric %s: missing series %q", metric, k)
			continue
		}
		if gv != v {
			t.Errorf("metric %s: series %q = %v, want %v", metric, k, gv, v)
		}
	}
}

func TestCollectFiltersToUpdateForBusinessRingsOnly(t *testing.T) {
	g := &fakeGraph{bodies: fullFixtureBodies()}
	rec := telemetrytest.New()

	if err := newTestCollector(g).Collect(context.Background(), rec.Emitter()); err != nil {
		t.Fatalf("Collect: %v", err)
	}

	// Only "Broad Ring" (the windowsUpdateForBusinessConfiguration element)
	// should ever appear as ring_name; "Some Restriction Policy" (the other
	// @odata.type, owned by #53) must never surface in any ring metric.
	for _, metric := range []string{pauseStateMetric, rollbackActiveMetric, ringStatusMetric} {
		for _, p := range rec.MetricPoints(metric) {
			if p.Attrs["ring_name"] == "Some Restriction Policy" {
				t.Errorf("metric %s emitted a point for the non-update-ring config - Group B partition violated", metric)
			}
		}
	}
}

func TestCollectEmitsPauseState(t *testing.T) {
	g := &fakeGraph{bodies: fullFixtureBodies()}
	rec := telemetrytest.New()

	if err := newTestCollector(g).Collect(context.Background(), rec.Emitter()); err != nil {
		t.Fatalf("Collect: %v", err)
	}

	assertPoints(t, rec, pauseStateMetric, map[string]float64{
		"Broad Ring/quality": 0,
		"Broad Ring/feature": 1,
	}, func(a map[string]string) string { return a["ring_name"] + "/" + a["update_type"] })
}

func TestCollectEmitsPauseExpiryOnlyWhenSet(t *testing.T) {
	g := &fakeGraph{bodies: fullFixtureBodies()}
	rec := telemetrytest.New()

	if err := newTestCollector(g).Collect(context.Background(), rec.Emitter()); err != nil {
		t.Fatalf("Collect: %v", err)
	}

	pts := rec.MetricPoints(pauseExpiryMetric)
	if len(pts) != 1 {
		t.Fatalf("got %d pause_expiry_seconds points, want 1 (only quality has a non-null expiry): %+v", len(pts), pts)
	}
	if pts[0].Attrs["ring_name"] != "Broad Ring" || pts[0].Attrs["update_type"] != "quality" {
		t.Errorf("pause_expiry point attrs = %+v, want ring_name=Broad Ring update_type=quality", pts[0].Attrs)
	}
	wantSeconds := time.Date(2026, 8, 1, 0, 0, 0, 0, time.UTC).Sub(fixedNow).Seconds()
	if pts[0].Value != wantSeconds {
		t.Errorf("pause_expiry_seconds = %v, want %v", pts[0].Value, wantSeconds)
	}
}

func TestCollectEmitsRollbackActive(t *testing.T) {
	g := &fakeGraph{bodies: fullFixtureBodies()}
	rec := telemetrytest.New()

	if err := newTestCollector(g).Collect(context.Background(), rec.Emitter()); err != nil {
		t.Fatalf("Collect: %v", err)
	}

	assertPoints(t, rec, rollbackActiveMetric, map[string]float64{
		"Broad Ring/quality": 0,
		"Broad Ring/feature": 1,
	}, func(a map[string]string) string { return a["ring_name"] + "/" + a["update_type"] })
}

func TestCollectEmitsRingStatusFromDeviceStatusOverview(t *testing.T) {
	g := &fakeGraph{bodies: fullFixtureBodies()}
	rec := telemetrytest.New()

	if err := newTestCollector(g).Collect(context.Background(), rec.Emitter()); err != nil {
		t.Fatalf("Collect: %v", err)
	}

	assertPoints(t, rec, ringStatusMetric, map[string]float64{
		"Broad Ring/pending":        1,
		"Broad Ring/not_applicable": 2,
		"Broad Ring/success":        3,
		"Broad Ring/error":          4,
		"Broad Ring/failed":         5,
	}, func(a map[string]string) string { return a["ring_name"] + "/" + a["state"] })
}

func TestCollectEmitsFeatureUpdateProfileEOLTarget(t *testing.T) {
	g := &fakeGraph{bodies: fullFixtureBodies()}
	rec := telemetrytest.New()

	if err := newTestCollector(g).Collect(context.Background(), rec.Emitter()); err != nil {
		t.Fatalf("Collect: %v", err)
	}

	pts := rec.MetricPoints(featureEOLMetric)
	if len(pts) != 1 {
		t.Fatalf("got %d eol_target points, want 1: %+v", len(pts), pts)
	}
	if pts[0].Attrs["profile_name"] != "21H2 Feature Profile" {
		t.Errorf("profile_name = %q, want %q", pts[0].Attrs["profile_name"], "21H2 Feature Profile")
	}
	wantSeconds := time.Date(2026, 10, 14, 0, 0, 0, 0, time.UTC).Sub(fixedNow).Seconds()
	if pts[0].Value != wantSeconds {
		t.Errorf("eol_target = %v, want %v", pts[0].Value, wantSeconds)
	}
}

func TestCollectEmitsDriverUpdateGauges(t *testing.T) {
	g := &fakeGraph{bodies: fullFixtureBodies()}
	rec := telemetrytest.New()

	if err := newTestCollector(g).Collect(context.Background(), rec.Emitter()); err != nil {
		t.Fatalf("Collect: %v", err)
	}

	pending := rec.MetricPoints(driverPendingMetric)
	if len(pending) != 1 || pending[0].Value != 7 || pending[0].Attrs["profile_name"] != "Driver Profile 1" {
		t.Fatalf("pending_approval points = %+v, want one point value=7 profile_name=Driver Profile 1", pending)
	}

	staleness := rec.MetricPoints(driverStalenessMetric)
	if len(staleness) != 1 {
		t.Fatalf("got %d staleness points, want 1: %+v", len(staleness), staleness)
	}
	wantSeconds := fixedNow.Sub(time.Date(2026, 7, 14, 12, 0, 0, 0, time.UTC)).Seconds()
	if staleness[0].Value != wantSeconds {
		t.Errorf("sync_staleness_seconds = %v, want %v", staleness[0].Value, wantSeconds)
	}
}

func TestCollectEmitsQualityUpdateConfigCounts(t *testing.T) {
	g := &fakeGraph{bodies: fullFixtureBodies()}
	rec := telemetrytest.New()

	if err := newTestCollector(g).Collect(context.Background(), rec.Emitter()); err != nil {
		t.Fatalf("Collect: %v", err)
	}

	assertPoints(t, rec, qualityConfigCountMetric, map[string]float64{
		"profile": 1,
		"policy":  1,
	}, func(a map[string]string) string { return a["resource_type"] })
}

func TestCollectSkipsUnavailableBetaFamilyWithoutError(t *testing.T) {
	bodies := fullFixtureBodies()
	g := &fakeGraph{
		bodies: bodies,
		errs: map[string]error{
			driverProfilesURL(): errors.New("graph: request failed: status 404 Not Found"),
		},
	}
	rec := telemetrytest.New()

	if err := newTestCollector(g).Collect(context.Background(), rec.Emitter()); err != nil {
		t.Fatalf("Collect should skip-and-log an unavailable beta family, not error: %v", err)
	}
	if len(rec.MetricPoints(driverPendingMetric)) != 0 {
		t.Error("driver metrics should be absent when the family 404s")
	}
	// Every other section must still emit.
	if len(rec.MetricPoints(pauseStateMetric)) == 0 {
		t.Error("ring metrics should still emit despite the driver family being unavailable")
	}
}

func TestCollectIsResilientToRingListFailure(t *testing.T) {
	bodies := fullFixtureBodies()
	g := &fakeGraph{
		bodies: bodies,
		errs:   map[string]error{configsURL(): errors.New("throttled")},
	}
	rec := telemetrytest.New()

	err := newTestCollector(g).Collect(context.Background(), rec.Emitter())
	if err == nil {
		t.Fatal("expected Collect to surface the deviceConfigurations failure as an error")
	}
	if len(rec.MetricPoints(pauseStateMetric)) != 0 {
		t.Error("ring metrics should be absent when the deviceConfigurations fetch failed")
	}
	// Independent sections still emit.
	if len(rec.MetricPoints(driverPendingMetric)) == 0 {
		t.Error("driver metrics should still emit despite the ring list failure")
	}
}

func TestNoPerDeviceAttributes(t *testing.T) {
	g := &fakeGraph{bodies: fullFixtureBodies()}
	rec := telemetrytest.New()

	if err := newTestCollector(g).Collect(context.Background(), rec.Emitter()); err != nil {
		t.Fatalf("Collect: %v", err)
	}

	for _, metric := range []string{pauseStateMetric, pauseExpiryMetric, rollbackActiveMetric, ringStatusMetric, featureEOLMetric, qualityConfigCountMetric, driverPendingMetric, driverStalenessMetric} {
		for _, p := range rec.MetricPoints(metric) {
			for k := range p.Attrs {
				switch k {
				case "id", "deviceId", "device_id", "userPrincipalName", "user_principal_name":
					t.Errorf("metric %s has a per-device/per-user attribute %q - cardinality violation", metric, k)
				}
			}
		}
	}
}

func TestNameIntervalPermissionsAndExperimental(t *testing.T) {
	c := New(&fakeGraph{}, nil)
	if c.Name() != "intune.updates" {
		t.Errorf("Name = %q, want intune.updates", c.Name())
	}
	if c.DefaultInterval() <= 0 {
		t.Errorf("DefaultInterval = %v, want positive", c.DefaultInterval())
	}
	perms := c.RequiredPermissions()
	if len(perms) != 1 || perms[0] != "DeviceManagementConfiguration.Read.All" {
		t.Errorf("RequiredPermissions = %v, want [DeviceManagementConfiguration.Read.All]", perms)
	}
	if !c.Experimental() {
		t.Error("Experimental() = false, want true (beta profile families make this opt-in)")
	}
}
