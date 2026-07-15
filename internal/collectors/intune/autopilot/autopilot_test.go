package autopilot

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
// manageddevices reference collector's test fake. GetAllValues pagination is
// supported via nextURL chaining on the map.
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

func devicesURL() string  { return v1Base + "/deviceManagement/windowsAutopilotDeviceIdentities" }
func profilesURL() string { return betaBase + "/deviceManagement/windowsAutopilotDeploymentProfiles" }
func assignmentsURL(id string) string {
	return betaBase + "/deviceManagement/windowsAutopilotDeploymentProfiles/" + id + "/assignments"
}

func page(items ...map[string]any) string {
	b, err := json.Marshal(map[string]any{"value": items})
	if err != nil {
		panic(err)
	}
	return string(b)
}

func identity(enrollmentState, groupTag string, lastContacted *time.Time) map[string]any {
	d := map[string]any{
		"enrollmentState": enrollmentState,
		"groupTag":        groupTag,
	}
	if lastContacted != nil {
		d["lastContactedDateTime"] = lastContacted.Format(time.RFC3339)
	} else {
		d["lastContactedDateTime"] = nil
	}
	return d
}

func daysAgo(d int) *time.Time {
	t := fixedNow.Add(-time.Duration(d) * 24 * time.Hour)
	return &t
}

func profile(id, displayName, deviceType string, preprovisioningAllowed, hashExtraction bool) map[string]any {
	return map[string]any{
		"id":                            id,
		"displayName":                   displayName,
		"deviceType":                    deviceType,
		"preprovisioningAllowed":        preprovisioningAllowed,
		"hardwareHashExtractionEnabled": hashExtraction,
		"enrollmentStatusScreenSettings": map[string]any{
			"hideInstallationProgress":                         true,
			"allowDeviceUseBeforeProfileAndAppInstallComplete": false,
			"blockDeviceSetupRetryByUser":                      true,
			"allowLogCollectionOnInstallFailure":               false,
			"installProgressTimeoutInMinutes":                  60,
			"allowDeviceUseOnInstallFailure":                   false,
		},
	}
}

func baseFixtures() map[string]string {
	return map[string]string{
		devicesURL(): page(
			identity("enrolled", "site-a", daysAgo(1)),
			identity("enrolled", "site-a", daysAgo(2)),
			identity("notContacted", "site-b", nil),
			identity("failed", "", daysAgo(45)),
		),
		profilesURL(): page(
			profile("p1", "Corp Profile", "windowsPc", true, true),
		),
		assignmentsURL("p1"): page(
			map[string]any{"target": map[string]any{"@odata.type": "#microsoft.graph.groupAssignmentTarget"}},
			map[string]any{"target": map[string]any{"@odata.type": "#microsoft.graph.groupAssignmentTarget"}},
		),
	}
}

func TestCollectEmitsDeviceGaugesByStateAndGroupTag(t *testing.T) {
	g := &fakeGraph{bodies: baseFixtures()}
	rec := telemetrytest.New()

	if err := newTestCollector(g).Collect(context.Background(), rec.Emitter()); err != nil {
		t.Fatalf("Collect: %v", err)
	}

	pts := rec.MetricPoints(devicesMetricName)
	got := map[string]float64{}
	for _, p := range pts {
		got[p.Attrs["enrollment_state"]+"/"+p.Attrs["group_tag"]] = p.Value
	}
	want := map[string]float64{
		"enrolled/site-a":      2,
		"not_contacted/site-b": 1,
		"failed/unassigned":    1,
	}
	if len(got) != len(want) {
		t.Fatalf("got %d device series, want %d: %v", len(got), len(want), got)
	}
	for k, v := range want {
		if got[k] != v {
			t.Errorf("%s = %v, want %v", k, got[k], v)
		}
	}
}

func TestCollectCountsStaleContacts(t *testing.T) {
	g := &fakeGraph{bodies: baseFixtures()}
	rec := telemetrytest.New()

	if err := newTestCollector(g).Collect(context.Background(), rec.Emitter()); err != nil {
		t.Fatalf("Collect: %v", err)
	}

	pts := rec.MetricPoints(staleContactMetricName)
	got := map[string]float64{}
	for _, p := range pts {
		got[p.Attrs["group_tag"]] = p.Value
	}
	// Only the "failed"/45-days-ago identity is past the 30-day threshold;
	// the never-contacted (nil lastContactedDateTime) identity is excluded
	// since its actual staleness can't be determined.
	want := map[string]float64{"unassigned": 1}
	if len(got) != len(want) {
		t.Fatalf("got %d stale series, want %d: %v", len(got), len(want), got)
	}
	for k, v := range want {
		if got[k] != v {
			t.Errorf("%s = %v, want %v", k, got[k], v)
		}
	}
}

// TestCollectCapsGroupTagCardinality pins the cardinality guard: with more
// distinct group tags than maxGroupTags, only the top maxGroupTags (by device
// count) keep their own series and every other tag rolls into "other".
func TestCollectCapsGroupTagCardinality(t *testing.T) {
	items := make([]map[string]any, 0, maxGroupTags+5)
	// 3 devices each on maxGroupTags distinct "popular" tags (guaranteed to
	// survive the cap), then 5 more distinct tags with a single device each
	// (guaranteed to be dropped to "other").
	for i := 0; i < maxGroupTags; i++ {
		tag := "popular-" + string(rune('a'+i))
		items = append(items, identity("enrolled", tag, daysAgo(0)), identity("enrolled", tag, daysAgo(0)), identity("enrolled", tag, daysAgo(0)))
	}
	for i := 0; i < 5; i++ {
		tag := "rare-" + string(rune('a'+i))
		items = append(items, identity("enrolled", tag, daysAgo(0)))
	}

	bodies := baseFixtures()
	bodies[devicesURL()] = page(items...)
	g := &fakeGraph{bodies: bodies}
	rec := telemetrytest.New()

	if err := newTestCollector(g).Collect(context.Background(), rec.Emitter()); err != nil {
		t.Fatalf("Collect: %v", err)
	}

	pts := rec.MetricPoints(devicesMetricName)
	tags := map[string]float64{}
	for _, p := range pts {
		tags[p.Attrs["group_tag"]] += p.Value
	}
	if len(tags) != maxGroupTags+1 {
		t.Fatalf("got %d distinct group_tag series, want %d (%d popular + 1 other): %v", len(tags), maxGroupTags+1, maxGroupTags, tags)
	}
	if got := tags["other"]; got != 5 {
		t.Errorf(`"other" bucket = %v, want 5 (the rare tags rolled up)`, got)
	}
	for i := 0; i < maxGroupTags; i++ {
		tag := "popular-" + string(rune('a'+i))
		if got := tags[tag]; got != 3 {
			t.Errorf("tag %s = %v, want 3", tag, got)
		}
	}
}

func TestCollectEmitsProfileCountByDeviceTypeAndPreprovisioning(t *testing.T) {
	g := &fakeGraph{bodies: baseFixtures()}
	rec := telemetrytest.New()

	if err := newTestCollector(g).Collect(context.Background(), rec.Emitter()); err != nil {
		t.Fatalf("Collect: %v", err)
	}

	pts := rec.MetricPoints(profileCountMetricName)
	got := map[string]float64{}
	for _, p := range pts {
		got[p.Attrs["device_type"]+"/"+p.Attrs["preprovisioning_allowed"]] = p.Value
	}
	want := map[string]float64{"windows_pc/true": 1}
	if len(got) != len(want) {
		t.Fatalf("got %d profile count series, want %d: %v", len(got), len(want), got)
	}
	for k, v := range want {
		if got[k] != v {
			t.Errorf("%s = %v, want %v", k, got[k], v)
		}
	}
}

func TestCollectEmitsProfileSettingGauges(t *testing.T) {
	g := &fakeGraph{bodies: baseFixtures()}
	rec := telemetrytest.New()

	if err := newTestCollector(g).Collect(context.Background(), rec.Emitter()); err != nil {
		t.Fatalf("Collect: %v", err)
	}

	pts := rec.MetricPoints(profileSettingMetricName)
	got := map[string]float64{}
	for _, p := range pts {
		if p.Attrs["profile_name"] != "Corp Profile" {
			t.Errorf("unexpected profile_name %q", p.Attrs["profile_name"])
			continue
		}
		got[p.Attrs["setting"]] = p.Value
	}
	want := map[string]float64{
		"preprovisioning_allowed":                      1,
		"hardware_hash_extraction_enabled":             1,
		"esp_hide_installation_progress":               1,
		"esp_allow_device_use_before_install_complete": 0,
		"esp_block_device_setup_retry_by_user":         1,
		"esp_allow_log_collection_on_install_failure":  0,
		"esp_allow_device_use_on_install_failure":      0,
	}
	if len(got) != len(want) {
		t.Fatalf("got %d setting series, want %d: %v", len(got), len(want), got)
	}
	for k, v := range want {
		if got[k] != v {
			t.Errorf("setting=%s = %v, want %v", k, got[k], v)
		}
	}
}

func TestCollectEmitsProfileEspTimeout(t *testing.T) {
	g := &fakeGraph{bodies: baseFixtures()}
	rec := telemetrytest.New()

	if err := newTestCollector(g).Collect(context.Background(), rec.Emitter()); err != nil {
		t.Fatalf("Collect: %v", err)
	}

	pts := rec.MetricPoints(profileEspTimeoutMetricName)
	if len(pts) != 1 {
		t.Fatalf("got %d esp timeout points, want 1: %+v", len(pts), pts)
	}
	if pts[0].Value != 60 {
		t.Errorf("esp timeout = %v, want 60", pts[0].Value)
	}
	if pts[0].Attrs["profile_name"] != "Corp Profile" {
		t.Errorf("profile_name = %q, want Corp Profile", pts[0].Attrs["profile_name"])
	}
}

func TestCollectEmitsProfileAssignmentCounts(t *testing.T) {
	g := &fakeGraph{bodies: baseFixtures()}
	rec := telemetrytest.New()

	if err := newTestCollector(g).Collect(context.Background(), rec.Emitter()); err != nil {
		t.Fatalf("Collect: %v", err)
	}

	pts := rec.MetricPoints(profileAssignmentsMetricName)
	if len(pts) != 1 {
		t.Fatalf("got %d assignment points, want 1: %+v", len(pts), pts)
	}
	if pts[0].Value != 2 {
		t.Errorf("assignment count = %v, want 2", pts[0].Value)
	}
}

// TestCollectPagesDeviceIdentitiesToExhaustion pins the acceptance criterion
// that pagination is followed across multiple @odata.nextLink pages.
func TestCollectPagesDeviceIdentitiesToExhaustion(t *testing.T) {
	page2URL := devicesURL() + "?$skiptoken=abc"
	page1 := `{"value":[{"enrollmentState":"enrolled","groupTag":"a","lastContactedDateTime":"2026-07-15T12:00:00Z"}],"@odata.nextLink":"` + page2URL + `"}`
	page2 := `{"value":[{"enrollmentState":"enrolled","groupTag":"a","lastContactedDateTime":"2026-07-15T12:00:00Z"}]}`

	bodies := baseFixtures()
	bodies[devicesURL()] = page1
	bodies[page2URL] = page2
	g := &fakeGraph{bodies: bodies}
	rec := telemetrytest.New()

	if err := newTestCollector(g).Collect(context.Background(), rec.Emitter()); err != nil {
		t.Fatalf("Collect: %v", err)
	}

	var total float64
	for _, p := range rec.MetricPoints(devicesMetricName) {
		total += p.Value
	}
	if total != 2 {
		t.Errorf("total device count across pages = %v, want 2", total)
	}
}

func TestCollectIsResilientToDeviceIdentitiesFailure(t *testing.T) {
	bodies := baseFixtures()
	g := &fakeGraph{
		bodies: bodies,
		errs:   map[string]error{devicesURL(): errors.New("throttled")},
	}
	rec := telemetrytest.New()

	err := newTestCollector(g).Collect(context.Background(), rec.Emitter())
	if err == nil {
		t.Fatal("expected Collect to surface the device identities failure as an error")
	}
	if len(rec.MetricPoints(devicesMetricName)) != 0 {
		t.Error("device gauges should be absent when the identities fetch failed")
	}
	// Profile-derived metrics must still emit despite the device failure.
	if len(rec.MetricPoints(profileCountMetricName)) == 0 {
		t.Error("profile count series should still emit despite the device identities failure")
	}
}

func TestCollectIsResilientToProfilesFailure(t *testing.T) {
	bodies := baseFixtures()
	g := &fakeGraph{
		bodies: bodies,
		errs:   map[string]error{profilesURL(): errors.New("throttled")},
	}
	rec := telemetrytest.New()

	err := newTestCollector(g).Collect(context.Background(), rec.Emitter())
	if err == nil {
		t.Fatal("expected Collect to surface the profiles failure as an error")
	}
	if len(rec.MetricPoints(profileCountMetricName)) != 0 {
		t.Error("profile count series should be absent when the profiles fetch failed")
	}
	// Device-derived metrics must still emit despite the profiles failure.
	if len(rec.MetricPoints(devicesMetricName)) == 0 {
		t.Error("device series should still emit despite the profiles failure")
	}
}

// TestCollectSkipsUnavailableProfilesEndpoint pins the beta-unavailability
// graceful-skip rule (M1 #9): a 403/404 from the beta profiles endpoint is
// skipped-and-logged, not surfaced as a Collect error, since it usually means
// the tenant isn't licensed for the beta surface rather than a real failure.
func TestCollectSkipsUnavailableProfilesEndpoint(t *testing.T) {
	bodies := baseFixtures()
	g := &fakeGraph{
		bodies: bodies,
		errs:   map[string]error{profilesURL(): errors.New("graph request failed: status 404")},
	}
	rec := telemetrytest.New()

	if err := newTestCollector(g).Collect(context.Background(), rec.Emitter()); err != nil {
		t.Fatalf("Collect should skip-and-log an unavailable beta endpoint, got error: %v", err)
	}
	if len(rec.MetricPoints(profileCountMetricName)) != 0 {
		t.Error("profile count series should be absent when the endpoint is unavailable")
	}
	if len(rec.MetricPoints(devicesMetricName)) == 0 {
		t.Error("device series should still emit despite the profiles endpoint being unavailable")
	}
}

// TestNoPerDeviceAttributes pins the cardinality/PII rule: no metric ever
// carries a per-entity identifier (serial number, managed device id, AAD
// device id, UPN) as a label. profile_name is intentionally excluded from
// this check - it is bounded by admin-configured profile count, the same
// precedent as mobileapps' policy_name label.
func TestNoPerDeviceAttributes(t *testing.T) {
	g := &fakeGraph{bodies: baseFixtures()}
	rec := telemetrytest.New()

	if err := newTestCollector(g).Collect(context.Background(), rec.Emitter()); err != nil {
		t.Fatalf("Collect: %v", err)
	}

	for _, metric := range rec.MetricNames() {
		for _, p := range rec.MetricPoints(metric) {
			for k := range p.Attrs {
				switch k {
				case "id", "serialNumber", "serial_number", "managedDeviceId", "managed_device_id",
					"azureActiveDirectoryDeviceId", "azure_active_directory_device_id",
					"userPrincipalName", "user_principal_name", "displayName", "device_name":
					t.Errorf("metric %s has a per-device attribute %q - cardinality violation", metric, k)
				}
			}
		}
	}
}

func TestNameIntervalPermissionsAndExperimental(t *testing.T) {
	c := New(&fakeGraph{}, nil)
	if c.Name() != "intune.autopilot" {
		t.Errorf("Name = %q, want intune.autopilot", c.Name())
	}
	if c.DefaultInterval() <= 0 {
		t.Errorf("DefaultInterval = %v, want positive", c.DefaultInterval())
	}
	perms := c.RequiredPermissions()
	if len(perms) != 1 || perms[0] != "DeviceManagementServiceConfig.Read.All" {
		t.Errorf("RequiredPermissions = %v, want [DeviceManagementServiceConfig.Read.All]", perms)
	}
	var _ collectors.Experimental = c
	if !c.Experimental() {
		t.Error("Experimental() = false, want true (deployment profiles are beta-only)")
	}
}
