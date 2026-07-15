package gpoanalytics

import (
	"context"
	"errors"
	"testing"

	"github.com/rknightion/graph2otel/internal/collectors"
	"github.com/rknightion/graph2otel/internal/telemetrytest"
)

// fakeGraph maps request URLs to canned raw bodies (or errors), mirroring the
// entra/recommendations and intune/manageddevices reference collectors' test
// fakes.
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

const (
	migrationReportsURL = "https://graph.microsoft.com/beta/deviceManagement/groupPolicyMigrationReports"
	configurationsURL   = "https://graph.microsoft.com/beta/deviceManagement/groupPolicyConfigurations"
)

func fullFixtureBodies() map[string]string {
	return map[string]string{
		migrationReportsURL: `{"value":[
			{"displayName":"Finance GPO","migrationReadiness":"complete","totalSettingsCount":10,"supportedSettingsCount":10},
			{"displayName":"Legacy GPO","migrationReadiness":"partial","totalSettingsCount":8,"supportedSettingsCount":2},
			{"displayName":"Empty GPO","migrationReadiness":"notApplicable","totalSettingsCount":0,"supportedSettingsCount":0}
		]}`,
		configurationsURL: `{"value":[
			{"displayName":"Config A","policyConfigurationIngestionType":"builtIn"},
			{"displayName":"Config B","policyConfigurationIngestionType":"builtIn"},
			{"displayName":"Config C","policyConfigurationIngestionType":"custom"}
		]}`,
	}
}

func TestCollectEmitsMigrationReadiness(t *testing.T) {
	g := &fakeGraph{bodies: fullFixtureBodies()}
	rec := telemetrytest.New()

	if err := New(g, nil).Collect(context.Background(), rec.Emitter()); err != nil {
		t.Fatalf("Collect: %v", err)
	}

	got := map[string]float64{}
	for _, p := range rec.MetricPoints(migrationReadinessMetric) {
		got[p.Attrs["report_name"]+"/"+p.Attrs["readiness"]] = p.Value
	}
	want := map[string]float64{
		"Finance GPO/complete":    1,
		"Legacy GPO/partial":      1,
		"Empty GPO/notApplicable": 1,
	}
	if len(got) != len(want) {
		t.Fatalf("got %d readiness points, want %d: %v", len(got), len(want), got)
	}
	for k, v := range want {
		if got[k] != v {
			t.Errorf("%s = %v, want %v", k, got[k], v)
		}
	}
}

// TestCollectComputesPercentFromCounts pins the acceptance criterion that the
// supported-settings-percent gauge is computed from supportedSettingsCount /
// totalSettingsCount, not trusted from any raw percent field on the wire.
func TestCollectComputesPercentFromCounts(t *testing.T) {
	g := &fakeGraph{bodies: fullFixtureBodies()}
	rec := telemetrytest.New()

	if err := New(g, nil).Collect(context.Background(), rec.Emitter()); err != nil {
		t.Fatalf("Collect: %v", err)
	}

	got := map[string]float64{}
	for _, p := range rec.MetricPoints(supportedSettingsPercentMetric) {
		got[p.Attrs["report_name"]] = p.Value
	}
	want := map[string]float64{
		"Finance GPO": 100,
		"Legacy GPO":  25,
		// Empty GPO: 0/0 must not divide by zero; percent buckets to 0.
		"Empty GPO": 0,
	}
	for k, v := range want {
		if got[k] != v {
			t.Errorf("percent[%s] = %v, want %v", k, got[k], v)
		}
	}
}

func TestCollectAggregatesConfigCountByIngestionType(t *testing.T) {
	g := &fakeGraph{bodies: fullFixtureBodies()}
	rec := telemetrytest.New()

	if err := New(g, nil).Collect(context.Background(), rec.Emitter()); err != nil {
		t.Fatalf("Collect: %v", err)
	}

	got := map[string]float64{}
	for _, p := range rec.MetricPoints(configCountMetric) {
		got[p.Attrs["ingestion_type"]] = p.Value
	}
	want := map[string]float64{"builtIn": 2, "custom": 1}
	if len(got) != len(want) {
		t.Fatalf("got %d ingestion_type series, want %d: %v", len(got), len(want), got)
	}
	for k, v := range want {
		if got[k] != v {
			t.Errorf("ingestion_type=%s = %v, want %v", k, got[k], v)
		}
	}
}

// TestCollectBucketsUnknownReadinessAndIngestionType pins the bounded-enum
// fallback: a value outside the documented enum must fall into "other" rather
// than being passed through raw (unbounded) or dropped.
func TestCollectBucketsUnknownReadinessAndIngestionType(t *testing.T) {
	g := &fakeGraph{bodies: map[string]string{
		migrationReportsURL: `{"value":[{"displayName":"Weird GPO","migrationReadiness":"somethingNew","totalSettingsCount":4,"supportedSettingsCount":1}]}`,
		configurationsURL:   `{"value":[{"displayName":"Weird Config","policyConfigurationIngestionType":"somethingElse"}]}`,
	}}
	rec := telemetrytest.New()

	if err := New(g, nil).Collect(context.Background(), rec.Emitter()); err != nil {
		t.Fatalf("Collect: %v", err)
	}

	readiness := rec.MetricPoints(migrationReadinessMetric)
	if len(readiness) != 1 || readiness[0].Attrs["readiness"] != "other" {
		t.Errorf("unmapped migrationReadiness should bucket to \"other\", got %+v", readiness)
	}

	ingestion := rec.MetricPoints(configCountMetric)
	if len(ingestion) != 1 || ingestion[0].Attrs["ingestion_type"] != "other" {
		t.Errorf("unmapped policyConfigurationIngestionType should bucket to \"other\", got %+v", ingestion)
	}
}

// TestCollectPagesMigrationReportsToExhaustion pins pagination following via
// @odata.nextLink.
func TestCollectPagesMigrationReportsToExhaustion(t *testing.T) {
	page2URL := migrationReportsURL + "?$skiptoken=abc"
	page1 := `{"value":[{"displayName":"A","migrationReadiness":"complete","totalSettingsCount":1,"supportedSettingsCount":1}],"@odata.nextLink":"` + page2URL + `"}`
	page2 := `{"value":[{"displayName":"B","migrationReadiness":"complete","totalSettingsCount":1,"supportedSettingsCount":1}]}`

	g := &fakeGraph{bodies: map[string]string{
		migrationReportsURL: page1,
		page2URL:            page2,
		configurationsURL:   `{"value":[]}`,
	}}
	rec := telemetrytest.New()

	if err := New(g, nil).Collect(context.Background(), rec.Emitter()); err != nil {
		t.Fatalf("Collect: %v", err)
	}

	pts := rec.MetricPoints(migrationReadinessMetric)
	if len(pts) != 2 {
		t.Errorf("got %d readiness points across pages, want 2 (one per page)", len(pts))
	}
}

func TestCollectGracefulOn403(t *testing.T) {
	g := &fakeGraph{errs: map[string]error{
		migrationReportsURL: errors.New("graphclient: GET " + migrationReportsURL + ": status 403: {\"error\":{\"code\":\"Authorization_RequestDenied\"}}"),
		configurationsURL:   errors.New("graphclient: GET " + configurationsURL + ": status 403: {\"error\":{\"code\":\"Authorization_RequestDenied\"}}"),
	}}
	rec := telemetrytest.New()

	if err := New(g, nil).Collect(context.Background(), rec.Emitter()); err != nil {
		t.Errorf("Collect should swallow a 403 as skip-and-log, got: %v", err)
	}
	if len(rec.MetricNames()) != 0 {
		t.Errorf("no metrics should be emitted on a 403, got %v", rec.MetricNames())
	}
}

func TestCollectGracefulOn404(t *testing.T) {
	g := &fakeGraph{errs: map[string]error{
		migrationReportsURL: errors.New("graphclient: GET " + migrationReportsURL + ": status 404: not found"),
		configurationsURL:   errors.New("graphclient: GET " + configurationsURL + ": status 404: not found"),
	}}
	rec := telemetrytest.New()

	if err := New(g, nil).Collect(context.Background(), rec.Emitter()); err != nil {
		t.Errorf("Collect should swallow a 404 as skip-and-log, got: %v", err)
	}
}

func TestCollectSurfacesNon4xxError(t *testing.T) {
	g := &fakeGraph{errs: map[string]error{
		migrationReportsURL: errors.New("graphclient: GET " + migrationReportsURL + ": status 500: server error"),
		configurationsURL:   errors.New("graphclient: GET " + configurationsURL + ": status 500: server error"),
	}}
	rec := telemetrytest.New()
	if err := New(g, nil).Collect(context.Background(), rec.Emitter()); err == nil {
		t.Error("a 500 should surface as a collector error, not be swallowed")
	}
}

// TestCollectIsResilientToOneFetchFailure pins that a failure in one of the
// two independent fetches doesn't prevent the other's metrics from emitting.
func TestCollectIsResilientToOneFetchFailure(t *testing.T) {
	g := &fakeGraph{
		bodies: fullFixtureBodies(),
		errs:   map[string]error{migrationReportsURL: errors.New("throttled")},
	}
	rec := telemetrytest.New()

	err := New(g, nil).Collect(context.Background(), rec.Emitter())
	if err == nil {
		t.Fatal("expected Collect to surface the migration-reports failure as an error")
	}
	if len(rec.MetricPoints(migrationReadinessMetric)) != 0 {
		t.Error("readiness gauges should be absent when the migration-reports fetch failed")
	}
	if len(rec.MetricPoints(configCountMetric)) == 0 {
		t.Error("config-count series should still emit despite the migration-reports failure")
	}
}

// TestNeverEmitsRawGPOContent pins the hard rule that groupPolicyObjectFile
// content (raw GPO XML) is never read into telemetry: this collector never
// even fetches groupPolicyObjectFiles, and no emitted attribute is named
// "content" or any per-entity identifier.
func TestNeverEmitsRawGPOContent(t *testing.T) {
	g := &fakeGraph{bodies: fullFixtureBodies()}
	rec := telemetrytest.New()

	if err := New(g, nil).Collect(context.Background(), rec.Emitter()); err != nil {
		t.Fatalf("Collect: %v", err)
	}

	for _, metric := range []string{migrationReadinessMetric, supportedSettingsPercentMetric, configCountMetric} {
		for _, p := range rec.MetricPoints(metric) {
			for k := range p.Attrs {
				switch k {
				case "content", "id", "groupPolicyObjectId", "group_policy_object_id", "ouDistinguishedName", "ou_distinguished_name":
					t.Errorf("metric %s has forbidden attribute %q", metric, k)
				}
			}
		}
	}
}

func TestNameIntervalPermissionsAndExperimental(t *testing.T) {
	c := New(&fakeGraph{}, nil)
	if c.Name() != "intune.gpo_analytics" {
		t.Errorf("Name = %q, want intune.gpo_analytics", c.Name())
	}
	if c.DefaultInterval() <= 0 {
		t.Errorf("DefaultInterval = %v, want positive", c.DefaultInterval())
	}
	if !c.Experimental() {
		t.Error("gpoanalytics is a beta collector; Experimental() must be true")
	}
	perms := c.RequiredPermissions()
	if len(perms) != 1 || perms[0] != "DeviceManagementConfiguration.Read.All" {
		t.Errorf("RequiredPermissions = %v, want [DeviceManagementConfiguration.Read.All]", perms)
	}
}
