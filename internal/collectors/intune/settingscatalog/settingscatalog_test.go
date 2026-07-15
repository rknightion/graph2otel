package settingscatalog

import (
	"context"
	"fmt"
	"testing"

	"github.com/rknightion/graph2otel/internal/collector"
	"github.com/rknightion/graph2otel/internal/collectors"
	"github.com/rknightion/graph2otel/internal/telemetrytest"
)

// fakeGraph maps request URLs to canned response bodies (or errors) and
// records every URL requested, mirroring the fixture used across the other
// M4 Intune collector tests (see internal/collectors/intune/compliance).
type fakeGraph struct {
	bodies       map[string]string
	errs         map[string]error
	requestedURL []string
}

func (f *fakeGraph) RawGet(ctx context.Context, url string) ([]byte, error) {
	return f.RawGetWithHeaders(ctx, url, nil)
}

func (f *fakeGraph) RawGetWithHeaders(_ context.Context, url string, _ map[string]string) ([]byte, error) {
	f.requestedURL = append(f.requestedURL, url)
	if err, ok := f.errs[url]; ok {
		return nil, err
	}
	body, ok := f.bodies[url]
	if !ok {
		return nil, fmt.Errorf("fakeGraph: no canned body for %s", url)
	}
	return []byte(body), nil
}

var _ collectors.GraphClient = (*fakeGraph)(nil)

const base = "https://graph.microsoft.com/beta"

const (
	configPoliciesURL = base + "/deviceManagement/configurationPolicies"
	intentsURL        = base + "/deviceManagement/intents"
	baselinesURL      = base + "/deviceManagement/templates?$filter=templateType%20eq%20%27securityBaseline%27"
)

func intentSummaryURL(id string) string {
	return base + "/deviceManagement/intents/" + id + "/deviceStateSummary"
}

func baselineSummaryURL(id string) string {
	return base + "/deviceManagement/templates/" + id + "/deviceStateSummary"
}

// forbidden403 mimics the graphclient error format for an HTTP 403, so
// isUnavailable's substring check is exercised the way it would be against
// the real client.
func forbidden403(url string) error {
	return fmt.Errorf("graphclient: GET %s: status 403: Forbidden", url)
}

func notFound404(url string) error {
	return fmt.Errorf("graphclient: GET %s: status 404: Not Found", url)
}

// summaryNotFound400 mimics the real Graph response observed live for a
// template/baseline/intent type that exposes no deviceStateSummary
// navigation property at all - HTTP 400, not 404, with a segment-not-found
// message rather than a generic error.
func summaryNotFound400(url string) error {
	return fmt.Errorf("graphclient: GET %s: status 400: Resource not found for the segment 'deviceStateSummary'.", url)
}

// emptyEndpoints answers every endpoint this collector polls with an
// empty/zero result, so a test can override just what it cares about.
func emptyEndpoints() map[string]string {
	return map[string]string{
		configPoliciesURL: `{"value":[]}`,
		intentsURL:        `{"value":[]}`,
		baselinesURL:      `{"value":[]}`,
	}
}

func merge(maps ...map[string]string) map[string]string {
	out := map[string]string{}
	for _, m := range maps {
		for k, v := range m {
			out[k] = v
		}
	}
	return out
}

func TestNameIntervalPermissionsExperimental(t *testing.T) {
	c := New(&fakeGraph{}, nil)
	if c.Name() != "intune.settings_catalog" {
		t.Errorf("Name() = %q, want intune.settings_catalog", c.Name())
	}
	if c.DefaultInterval() <= 0 {
		t.Error("DefaultInterval() must be positive")
	}
	perms := c.RequiredPermissions()
	if len(perms) != 1 || perms[0] != "DeviceManagementConfiguration.Read.All" {
		t.Errorf("RequiredPermissions() = %v, want [DeviceManagementConfiguration.Read.All]", perms)
	}
	if !c.Experimental() {
		t.Error("Experimental() = false, want true (beta-only endpoints)")
	}
	var _ collector.SnapshotCollector = c
	var _ collectors.Experimental = c
}

func TestCollectEmitsConfigurationPolicyCounts(t *testing.T) {
	bodies := merge(emptyEndpoints(), map[string]string{
		configPoliciesURL: `{"value":[
			{"id":"cp1","name":"Win Disk Encryption","platforms":"windows10","technologies":"mdm","templateReference":{"templateId":"t-bitlocker","templateFamily":"endpointSecurityDiskEncryption"}},
			{"id":"cp2","name":"iOS Restrictions","platforms":"iOS","technologies":"mdm","templateReference":null},
			{"id":"cp3","name":"Win Disk Encryption 2","platforms":"windows10","technologies":"mdm","templateReference":{"templateId":"t-bitlocker2","templateFamily":"endpointSecurityDiskEncryption"}}
		]}`,
	})
	g := &fakeGraph{bodies: bodies}
	rec := telemetrytest.New()

	if err := New(g, nil).Collect(context.Background(), rec.Emitter()); err != nil {
		t.Fatalf("Collect: %v", err)
	}

	pts := rec.MetricPoints(policyCountMetricName)
	got := map[string]float64{}
	for _, p := range pts {
		got[p.Attrs["platform"]+"|"+p.Attrs["technology"]+"|"+p.Attrs["template_family"]] += p.Value
	}
	want := map[string]float64{
		"windows10|mdm|endpointSecurityDiskEncryption": 2,
		"iOS|mdm|none": 1,
	}
	if len(got) != len(want) {
		t.Fatalf("got %d policy count series, want %d: %v", len(got), len(want), got)
	}
	for k, v := range want {
		if got[k] != v {
			t.Errorf("series %s = %v, want %v", k, got[k], v)
		}
	}
}

func TestCollectEmitsIntentCountsByMigratingFlagAndDeviceStates(t *testing.T) {
	bodies := merge(emptyEndpoints(), map[string]string{
		intentsURL: `{"value":[
			{"id":"i1","displayName":"Defender AV","templateId":"t-av","isMigratingToConfigurationPolicy":false},
			{"id":"i2","displayName":"Firewall","templateId":"t-fw","isMigratingToConfigurationPolicy":true}
		]}`,
		intentSummaryURL("i1"): `{"compliantDeviceCount":10,"nonCompliantDeviceCount":2,"errorDeviceCount":0,"conflictDeviceCount":0,"remediatedDeviceCount":1,"unknownDeviceCount":0,"notApplicableDeviceCount":3}`,
		intentSummaryURL("i2"): `{"compliantDeviceCount":5,"nonCompliantDeviceCount":1,"errorDeviceCount":0,"conflictDeviceCount":0,"remediatedDeviceCount":0,"unknownDeviceCount":0,"notApplicableDeviceCount":0}`,
	})
	g := &fakeGraph{bodies: bodies}
	rec := telemetrytest.New()

	if err := New(g, nil).Collect(context.Background(), rec.Emitter()); err != nil {
		t.Fatalf("Collect: %v", err)
	}

	countPts := rec.MetricPoints(intentCountMetricName)
	gotCounts := map[string]float64{}
	for _, p := range countPts {
		gotCounts[p.Attrs["migrating"]] = p.Value
	}
	wantCounts := map[string]float64{"false": 1, "true": 1}
	if len(gotCounts) != len(wantCounts) {
		t.Fatalf("got %d migrating buckets, want %d: %v", len(gotCounts), len(wantCounts), gotCounts)
	}
	for k, v := range wantCounts {
		if gotCounts[k] != v {
			t.Errorf("migrating=%s count = %v, want %v", k, gotCounts[k], v)
		}
	}

	devPts := rec.MetricPoints(intentDevicesMetricName)
	gotDev := map[string]float64{}
	for _, p := range devPts {
		gotDev[p.Attrs["intent_name"]+"|"+p.Attrs["compliance_status"]] = p.Value
	}
	if gotDev["Defender AV|compliant"] != 10 || gotDev["Firewall|compliant"] != 5 {
		t.Errorf("intent device states = %v, want Defender AV|compliant=10, Firewall|compliant=5", gotDev)
	}
}

func TestCollectReconciliationExcludesMigratedIntentFromCountButKeepsDeviceStates(t *testing.T) {
	// i1 has isMigratingToConfigurationPolicy=true and templateId "t-bitlocker",
	// which matches cp1's templateReference.templateId below — i.e. this
	// intent's content already exists as a Settings Catalog policy, so it
	// must not also be counted in intune.intent.count (that would double
	// count the same underlying policy across both metrics). Its
	// deviceStateSummary compliance gauge must still be emitted — migration
	// state never silently drops compliance coverage.
	bodies := merge(emptyEndpoints(), map[string]string{
		configPoliciesURL: `{"value":[
			{"id":"cp1","name":"Win Disk Encryption","platforms":"windows10","technologies":"mdm","templateReference":{"templateId":"t-bitlocker","templateFamily":"endpointSecurityDiskEncryption"}}
		]}`,
		intentsURL: `{"value":[
			{"id":"i1","displayName":"Disk Encryption (legacy intent)","templateId":"t-bitlocker","isMigratingToConfigurationPolicy":true},
			{"id":"i2","displayName":"Not Yet Migrated","templateId":"t-other","isMigratingToConfigurationPolicy":true}
		]}`,
		intentSummaryURL("i1"): `{"compliantDeviceCount":7,"nonCompliantDeviceCount":0,"errorDeviceCount":0,"conflictDeviceCount":0,"remediatedDeviceCount":0,"unknownDeviceCount":0,"notApplicableDeviceCount":0}`,
		intentSummaryURL("i2"): `{"compliantDeviceCount":4,"nonCompliantDeviceCount":0,"errorDeviceCount":0,"conflictDeviceCount":0,"remediatedDeviceCount":0,"unknownDeviceCount":0,"notApplicableDeviceCount":0}`,
	})
	g := &fakeGraph{bodies: bodies}
	rec := telemetrytest.New()

	if err := New(g, nil).Collect(context.Background(), rec.Emitter()); err != nil {
		t.Fatalf("Collect: %v", err)
	}

	countPts := rec.MetricPoints(intentCountMetricName)
	var totalCounted float64
	for _, p := range countPts {
		totalCounted += p.Value
	}
	// Only i2 (migrating=true, no matching configurationPolicy twin) is
	// counted; i1 is reconciled away since cp1 already represents it.
	if totalCounted != 1 {
		t.Errorf("total reconciled intent.count = %v, want 1 (i1 excluded as already counted via configurationPolicies)", totalCounted)
	}

	devPts := rec.MetricPoints(intentDevicesMetricName)
	gotDev := map[string]float64{}
	for _, p := range devPts {
		gotDev[p.Attrs["intent_name"]+"|"+p.Attrs["compliance_status"]] = p.Value
	}
	if gotDev["Disk Encryption (legacy intent)|compliant"] != 7 {
		t.Errorf("reconciled intent i1 must still emit device state coverage, got %v", gotDev)
	}
	if gotDev["Not Yet Migrated|compliant"] != 4 {
		t.Errorf("non-reconciled intent i2 device state missing, got %v", gotDev)
	}
}

func TestCollectEmitsSecurityBaselineDevices(t *testing.T) {
	bodies := merge(emptyEndpoints(), map[string]string{
		baselinesURL: `{"value":[
			{"id":"b1","displayName":"Windows 11 Security Baseline","templateType":"securityBaseline"}
		]}`,
		baselineSummaryURL("b1"): `{"secureDeviceCount":40,"notSecureDeviceCount":5,"errorDeviceCount":1,"conflictDeviceCount":0,"notApplicableDeviceCount":2,"unknownDeviceCount":0}`,
	})
	g := &fakeGraph{bodies: bodies}
	rec := telemetrytest.New()

	if err := New(g, nil).Collect(context.Background(), rec.Emitter()); err != nil {
		t.Fatalf("Collect: %v", err)
	}

	pts := rec.MetricPoints(baselineDevicesMetricName)
	got := map[string]float64{}
	for _, p := range pts {
		got[p.Attrs["baseline_name"]+"|"+p.Attrs["state"]] = p.Value
	}
	want := map[string]float64{
		"Windows 11 Security Baseline|secure":         40,
		"Windows 11 Security Baseline|not_secure":     5,
		"Windows 11 Security Baseline|error":          1,
		"Windows 11 Security Baseline|conflict":       0,
		"Windows 11 Security Baseline|not_applicable": 2,
		"Windows 11 Security Baseline|unknown":        0,
	}
	for k, v := range want {
		if got[k] != v {
			t.Errorf("series %s = %v, want %v", k, got[k], v)
		}
	}

	// Confirm the securityBaseline $filter is actually sent, percent-encoded.
	found := false
	for _, u := range g.requestedURL {
		if u == baselinesURL {
			found = true
		}
	}
	if !found {
		t.Errorf("expected a request to %s, got %v", baselinesURL, g.requestedURL)
	}
}

func TestCollectSkipsUnavailableEndpointsWithoutFailing(t *testing.T) {
	bodies := map[string]string{
		configPoliciesURL: `{"value":[]}`,
		intentsURL:        `{"value":[]}`,
		// baselines missing on this tenant (beta, unlicensed) - 404.
	}
	errs := map[string]error{
		baselinesURL: notFound404(baselinesURL),
	}
	g := &fakeGraph{bodies: bodies, errs: errs}
	rec := telemetrytest.New()

	if err := New(g, nil).Collect(context.Background(), rec.Emitter()); err != nil {
		t.Fatalf("Collect: expected nil error on a 404 skip, got %v", err)
	}
}

func TestCollectJoinsRealErrorsButKeepsOtherMetrics(t *testing.T) {
	bodies := merge(emptyEndpoints(), map[string]string{
		intentsURL: `{"value":[{"id":"i1","displayName":"Defender AV","templateId":"","isMigratingToConfigurationPolicy":false}]}`,
	})
	errs := map[string]error{
		intentSummaryURL("i1"): fmt.Errorf("graphclient: GET %s: status 500: Internal Server Error", intentSummaryURL("i1")),
	}
	g := &fakeGraph{bodies: bodies, errs: errs}
	rec := telemetrytest.New()

	err := New(g, nil).Collect(context.Background(), rec.Emitter())
	if err == nil {
		t.Fatal("expected a joined error for the failed deviceStateSummary fetch")
	}

	// Even though i1's deviceStateSummary failed, its migrating-bucket count
	// must still have been emitted.
	countPts := rec.MetricPoints(intentCountMetricName)
	if len(countPts) != 1 || countPts[0].Attrs["migrating"] != "false" {
		t.Errorf("intent.count must still emit despite the per-item deviceStateSummary failure, got %+v", countPts)
	}
}

func TestCollectConfigurationPoliciesForbiddenIsSkippedNotFailed(t *testing.T) {
	bodies := merge(emptyEndpoints(), map[string]string{})
	delete(bodies, configPoliciesURL)
	errs := map[string]error{configPoliciesURL: forbidden403(configPoliciesURL)}
	g := &fakeGraph{bodies: bodies, errs: errs}
	rec := telemetrytest.New()

	if err := New(g, nil).Collect(context.Background(), rec.Emitter()); err != nil {
		t.Fatalf("Collect: expected nil error on a 403 skip, got %v", err)
	}
	if pts := rec.MetricPoints(policyCountMetricName); len(pts) != 0 {
		t.Errorf("expected no policy count points when the endpoint is forbidden, got %v", pts)
	}
}

// TestCollectSkipsSummaryNotFoundSegmentWithoutFailing reproduces the live
// gotcha: a template/intent type that exposes no deviceStateSummary
// navigation property answers HTTP 400 (not 404) with a
// "Resource not found for the segment 'deviceStateSummary'" message. That
// must be treated as a per-item skip - like a 403/404 - not a collector
// failure, and must not suppress the base inventory counts (which come from
// the list responses, not the summary sub-fetch).
func TestCollectSkipsSummaryNotFoundSegmentWithoutFailing(t *testing.T) {
	bodies := merge(emptyEndpoints(), map[string]string{
		configPoliciesURL: `{"value":[
			{"id":"cp1","name":"Win Disk Encryption","platforms":"windows10","technologies":"mdm","templateReference":null}
		]}`,
		intentsURL: `{"value":[
			{"id":"i1","displayName":"Defender AV","templateId":"","isMigratingToConfigurationPolicy":false}
		]}`,
		baselinesURL: `{"value":[
			{"id":"b1","displayName":"Windows 11 Security Baseline","templateType":"securityBaseline"}
		]}`,
	})
	errs := map[string]error{
		intentSummaryURL("i1"):   summaryNotFound400(intentSummaryURL("i1")),
		baselineSummaryURL("b1"): summaryNotFound400(baselineSummaryURL("b1")),
	}
	g := &fakeGraph{bodies: bodies, errs: errs}
	rec := telemetrytest.New()

	if err := New(g, nil).Collect(context.Background(), rec.Emitter()); err != nil {
		t.Fatalf("Collect: expected nil error when a summary sub-fetch 400s with a not-found-segment message, got %v", err)
	}

	if pts := rec.MetricPoints(policyCountMetricName); len(pts) != 1 || pts[0].Value != 1 {
		t.Errorf("policy.count must still emit despite the intent/baseline summary failures, got %+v", pts)
	}
	countPts := rec.MetricPoints(intentCountMetricName)
	if len(countPts) != 1 || countPts[0].Attrs["migrating"] != "false" || countPts[0].Value != 1 {
		t.Errorf("intent.count must still emit despite its own deviceStateSummary failing, got %+v", countPts)
	}
	// Neither i1 nor b1 has a device-state breakdown (their summary fetch
	// failed with the not-found-segment shape), so both per-item gauges are
	// legitimately empty this cycle - the point is Collect did not fail.
	if pts := rec.MetricPoints(intentDevicesMetricName); len(pts) != 0 {
		t.Errorf("expected no intent device-state points, got %+v", pts)
	}
	if pts := rec.MetricPoints(baselineDevicesMetricName); len(pts) != 0 {
		t.Errorf("expected no baseline device-state points, got %+v", pts)
	}
}
