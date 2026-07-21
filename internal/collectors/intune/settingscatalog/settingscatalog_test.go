package settingscatalog

import (
	"context"
	_ "embed"
	"encoding/json"
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
	// Filtered by TYPE, not templateType (#223): "security baseline" is an
	// inheritance spread across five templateType values, and the old
	// templateType filter matched 1 of the 7 real baselines.
	baselinesURL = base + "/deviceManagement/templates?$filter=isof%28%27microsoft.graph.securityBaselineTemplate%27%29"
)

func intentSummaryURL(id string) string {
	return base + "/deviceManagement/intents/" + id + "/deviceStateSummary"
}

// baselineSummaryURL is the WORKING path, live-verified 2026-07-21 as
// graph2otel-poller: deviceStateSummary is bound on the DERIVED
// securityBaselineTemplate, so the request needs the cast segment. Without it
// Graph answers 400 "Resource not found for the segment 'deviceStateSummary'"
// (#222) — which this collector used to send on every single run.
func baselineSummaryURL(id string) string {
	return base + "/deviceManagement/templates/" + id + "/microsoft.graph.securityBaselineTemplate/deviceStateSummary"
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
		// Live wire field names (#222): secureCount, NOT secureDeviceCount. The
		// beta EDM binds this to microsoft.graph.securityBaselineStateSummary,
		// whose six properties carry no "Device" infix — Microsoft's docs say
		// otherwise and are wrong. The old names decoded to a permanent zero.
		baselineSummaryURL("b1"): `{"secureCount":40,"notSecureCount":5,"errorCount":1,"conflictCount":0,"notApplicableCount":2,"unknownCount":0}`,
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
// Verbatim live captures, read as graph2otel-poller against the m7kni tenant on
// 2026-07-17 `[live-measured 2026-07-17, #165]`, one file per exact beta
// endpoint this collector polls. None of these list calls sends $select — the
// collector reads the full entity — so the captures carry every field the wire
// returns:
//
//	live-configurationPolicies.json  GET /beta/deviceManagement/configurationPolicies
//	live-intents-empty.json          GET /beta/deviceManagement/intents
//	live-templates-securityBaseline.json  GET /beta/deviceManagement/templates?$filter=templateType eq 'securityBaseline'
//	live-template-deviceStateSummary-400.json  GET /beta/deviceManagement/templates/{id}/deviceStateSummary (HTTP 400 body — the UNCAST path)
//	live-template-deviceStateSummary-200.json  GET /beta/deviceManagement/templates/{id}/microsoft.graph.securityBaselineTemplate/deviceStateSummary (HTTP 200, captured 2026-07-21)
//
// The intents surface is genuinely empty on this tenant — the capture is a real
// empty page, kept as the pinned empty shape. The configurationPolicies capture
// is page 1 of 25 (@odata.count=25) and carries a real @odata.nextLink.
//
// The two deviceStateSummary captures are the before/after of #222: the UNCAST
// path answers HTTP 400 "Resource not found for the segment 'deviceStateSummary'"
// — that capture is kept as pinned evidence, and the earlier reading of it, that
// securityBaselineTemplate simply exposes no such navigation property, was WRONG.
// It is bound on the DERIVED type, so the cast path answers 200 with the six
// *Count fields (no "Device" infix).
var (
	//go:embed testdata/live-configurationPolicies.json
	liveConfigPolicies string
	//go:embed testdata/live-template-deviceStateSummary-200.json
	liveTemplateSummary200 string
	//go:embed testdata/live-intents-empty.json
	liveIntentsEmpty string
	//go:embed testdata/live-templates-securityBaseline.json
	liveTemplatesBaseline string
)

// configPoliciesNextLink is the exact @odata.nextLink carried by page 1 of the
// live configurationPolicies capture. GetAllValues follows it, so the live
// end-to-end test serves an empty terminating page here rather than editing the
// verbatim page-1 body to drop its nextLink.
const configPoliciesNextLink = "https://graph.microsoft.com/beta/deviceManagement/configurationPolicies?$skiptoken=%255Bcosmosdb%255D%255B%257B%2522compositeToken%2522%253A%257B%2522token%2522%253Anull%252C%2522range%2522%253A%257B%2522min%2522%253A%2522033E6C6FD4E03029BD670DBC28A0E77A%2522%252C%2522max%2522%253A%252206C46D1EDD04AA76D43667BE6AA13245%2522%257D%257D%252C%2522resumeValues%2522%253A%255B%2522macos%2520defender%2520dlp%2522%255D%252C%2522rid%2522%253A%2522z2oNAPrcMybcKBUAAACAAw%253D%253D%2522%252C%2522skipCount%2522%253A1%257D%255D"

// TestCollectAgainstLiveCaptures drives the VERBATIM live captures through the
// real Collect path.
//
// Unlike the scripts collector, settingscatalog decodes each deviceStateSummary
// singleton directly (no {"value":{…}} envelope), so there is no decode defect
// to expose here — this test confirms the real wire shapes flow correctly:
//
//   - the 5 real configurationPolicies (page 1 of 25) bucket into 5 distinct
//     (platform, technology, template_family) series, each value 1 — including
//     the templateReference.templateFamily=="none"/templateId=="" row, which
//     must land in a "none" family bucket, not crash on the empty templateId;
//   - the empty intents page emits present-but-empty intent metrics;
//   - all SEVEN security-baseline templates emit a full six-state gauge set.
func TestCollectAgainstLiveCaptures(t *testing.T) {
	bodies := map[string]string{
		configPoliciesURL:      liveConfigPolicies,
		configPoliciesNextLink: `{"value":[]}`, // terminating page for the verbatim nextLink
		intentsURL:             liveIntentsEmpty,
		baselinesURL:           liveTemplatesBaseline,
	}
	// Serve every baseline id the live capture lists. All seven answered 200 on
	// the cast path with a byte-identical body apart from the id (live-probed
	// 2026-07-21), so the one verbatim capture stands in for each — driving the
	// ids off the fixture rather than a hand-typed list means this test grows a
	// baseline whenever the recapture does. The uncast path still 400s, and
	// testdata/live-template-deviceStateSummary-400.json keeps that response as
	// pinned evidence of #222.
	for _, id := range liveBaselineTemplateIDs(t) {
		bodies[baselineSummaryURL(id)] = liveTemplateSummary200
	}
	g := &fakeGraph{bodies: bodies}
	rec := telemetrytest.New()

	if err := New(g, nil).Collect(context.Background(), rec.Emitter()); err != nil {
		t.Fatalf("Collect against live captures: %v", err)
	}

	// The 5 real page-1 policies bucket into 5 distinct series, each count 1.
	pts := rec.MetricPoints(policyCountMetricName)
	got := map[string]float64{}
	for _, p := range pts {
		got[p.Attrs["platform"]+"|"+p.Attrs["technology"]+"|"+p.Attrs["template_family"]] += p.Value
	}
	want := map[string]float64{
		"windows10|enrollment|enrollmentConfiguration":                        1,
		"windows10|mdm|none":                                                  1,
		"windows10|mdm|endpointSecurityAccountProtection":                     1,
		"windows10|mdm,microsoftSense|endpointSecurityAttackSurfaceReduction": 1,
		"windows10|mdm,microsoftSense|endpointSecurityAntivirus":              1,
	}
	if len(got) != len(want) {
		t.Fatalf("policy.count series = %d, want %d: %v", len(got), len(want), got)
	}
	for k, v := range want {
		if got[k] != v {
			t.Errorf("policy.count series %s = %v, want %v", k, got[k], v)
		}
	}

	// intents is empty on the tenant → present-but-empty intent metrics.
	if pts := rec.MetricPoints(intentCountMetricName); len(pts) != 0 {
		t.Errorf("intent.count points = %d, want 0 (intents empty on tenant), got %+v", len(pts), pts)
	}
	if pts := rec.MetricPoints(intentDevicesMetricName); len(pts) != 0 {
		t.Errorf("intent.devices points = %d, want 0, got %+v", len(pts), pts)
	}

	// The one securityBaseline template's deviceStateSummary answers 200 on the
	// cast path, so all six states emit. Every count is genuinely 0 on this
	// tenant (no devices are assigned to the baseline) — which is exactly why
	// #222 hid for so long: a permanent zero from decoding the WRONG field names
	// is indistinguishable from an honest zero. The assertion is therefore on
	// the SERIES SET, not the values: six states present, one baseline.
	// Every baseline emits all six states. Counts are genuinely 0 on this tenant
	// (nothing is assigned), which is exactly why #222 hid for so long: a
	// permanent zero from decoding the WRONG field names is indistinguishable
	// from an honest zero. So the assertion is on the SERIES SET, never values.
	//
	// The count is load-bearing for #223: the old templateType filter matched 1
	// of these 7, so a regression to it drops this from 42 points to 6.
	ids := liveBaselineTemplateIDs(t)
	basePts := rec.MetricPoints(baselineDevicesMetricName)
	if want := len(ids) * 6; len(basePts) != want {
		t.Fatalf("baseline.devices points = %d, want %d (%d baselines x 6 states)", len(basePts), want, len(ids))
	}
	perBaseline := map[string]map[string]bool{}
	for _, p := range basePts {
		if perBaseline[p.Attrs["baseline_name"]] == nil {
			perBaseline[p.Attrs["baseline_name"]] = map[string]bool{}
		}
		perBaseline[p.Attrs["baseline_name"]][p.Attrs["state"]] = true
	}
	if len(perBaseline) != len(ids) {
		t.Errorf("got %d distinct baselines, want %d: %v", len(perBaseline), len(ids), perBaseline)
	}
	// The Defender and Edge baselines carry non-'securityBaseline' templateTypes
	// and were the ones the old filter silently dropped (#223) — name them so a
	// regression fails loudly rather than just changing a count.
	for _, name := range []string{
		"Microsoft Defender for Endpoint baseline",
		"Microsoft Edge baseline",
		"MDM Security Baseline for Windows 10 and later for November 2021",
	} {
		if perBaseline[name] == nil {
			t.Errorf("baseline %q emitted no series (the #223 filter regression)", name)
		}
	}
	for name, states := range perBaseline {
		for _, want := range []string{"secure", "not_secure", "error", "conflict", "not_applicable", "unknown"} {
			if !states[want] {
				t.Errorf("baseline %q missing state %q; got %v", name, want, states)
			}
		}
	}
}

// liveBaselineTemplateIDs reads the template ids straight out of the verbatim
// live capture, so the live test covers whatever the recapture actually
// contains rather than a list that can drift away from it.
func liveBaselineTemplateIDs(t *testing.T) []string {
	t.Helper()
	var page struct {
		Value []struct {
			ID string `json:"id"`
		} `json:"value"`
	}
	if err := json.Unmarshal([]byte(liveTemplatesBaseline), &page); err != nil {
		t.Fatalf("decode live templates capture: %v", err)
	}
	ids := make([]string, 0, len(page.Value))
	for _, v := range page.Value {
		ids = append(ids, v.ID)
	}
	if len(ids) == 0 {
		t.Fatal("live templates capture contains no templates")
	}
	return ids
}

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
