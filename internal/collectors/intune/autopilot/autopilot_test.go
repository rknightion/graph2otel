package autopilot

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/rknightion/graph2otel/internal/collectors"
	"github.com/rknightion/graph2otel/internal/semconv"
	"github.com/rknightion/graph2otel/internal/telemetrytest"
	"github.com/rknightion/graph2otel/internal/wirecheck"
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

// fixedNow is the deterministic clock; it sits just after the live captures
// below so their lastContactedDateTime lands in the past.
var fixedNow = time.Date(2026, 7, 17, 18, 0, 0, 0, time.UTC)

func fixedClock() time.Time { return fixedNow }

// Verbatim GET captures read as graph2otel-poller against the m7kni tenant on
// 2026-07-17 `[live-measured 2026-07-17, #165]`, each from the exact endpoint
// this collector polls. Trimmed of nothing — the tenant has exactly one
// Autopilot device identity, one deployment profile, and one assignment on it.
//
//   - liveDevicesBody: GET
//     /v1.0/deviceManagement/windowsAutopilotDeviceIdentities (1 identity).
//     The per-device identifiers it carries (serialNumber, managedDeviceId,
//     userPrincipalName, ...) are exactly the fields this collector must never
//     read onto a metric label — kept verbatim so the cardinality guard is
//     tested against the real shape. groupTag is "" on the wire → "unassigned".
//   - liveProfilesBody: GET
//     /beta/deviceManagement/windowsAutopilotDeploymentProfiles (1 profile;
//     beta — v1.0 404s). enrollmentStatusScreenSettings is null on the live
//     profile, so no ESP settings/timeout are derivable from it — the ESP
//     coverage below uses a dedicated synthetic profile. The profile also
//     carries BOTH the modern field names this collector reads
//     (preprovisioningAllowed, hardwareHashExtractionEnabled) and their
//     deprecated predecessors (enableWhiteGlove, extractHardwareHash); kept
//     verbatim to prove the mapper binds the modern names.
//   - liveAssignmentsBody: GET .../windowsAutopilotDeploymentProfiles('<id>')/
//     assignments (1 allDevicesAssignmentTarget assignment; beta).
const (
	liveProfileID = "39778baa-907f-4f7d-9bb8-a4f76a4ce69f"

	liveDevicesBody = `{
  "@odata.context": "https://graph.microsoft.com/v1.0/$metadata#deviceManagement/windowsAutopilotDeviceIdentities",
  "@odata.count": 1,
  "value": [
    {
      "addressableUserName": "Rob Knight",
      "azureActiveDirectoryDeviceId": "8a114385-b11b-4dda-bc33-a8725775e27e",
      "displayName": "LAPHAM",
      "enrollmentState": "enrolled",
      "groupTag": "",
      "id": "f50c7b4b-87ed-4d24-b8b2-31d007e6c115",
      "lastContactedDateTime": "2026-07-16T15:13:29Z",
      "managedDeviceId": "d5900d67-e50c-44ef-9d5c-6a2f891099c6",
      "manufacturer": "PCSpecialist",
      "model": "Standard",
      "productKey": "",
      "purchaseOrderIdentifier": "",
      "resourceName": "",
      "serialNumber": "PH4TRX1S2146S0097",
      "skuNumber": "0001",
      "systemFamily": "TGL",
      "userPrincipalName": "rob@m7kni.io"
    }
  ]
}`

	liveProfilesBody = `{
  "@odata.context": "https://graph.microsoft.com/beta/$metadata#deviceManagement/windowsAutopilotDeploymentProfiles",
  "value": [
    {
      "@odata.type": "#microsoft.graph.azureADWindowsAutopilotDeploymentProfile",
      "createdDateTime": "2026-01-17T10:43:18.496716Z",
      "description": "",
      "deviceNameTemplate": "",
      "deviceType": "windowsPc",
      "displayName": "deployment profile",
      "enableWhiteGlove": true,
      "enrollmentStatusScreenSettings": null,
      "extractHardwareHash": true,
      "hardwareHashExtractionEnabled": true,
      "id": "39778baa-907f-4f7d-9bb8-a4f76a4ce69f",
      "language": "en-GB",
      "lastModifiedDateTime": "2026-01-17T10:43:18.496716Z",
      "locale": "en-GB",
      "managementServiceAppId": null,
      "outOfBoxExperienceSetting": {
        "deviceUsageType": "singleUser",
        "escapeLinkHidden": true,
        "eulaHidden": true,
        "keyboardSelectionPageSkipped": true,
        "privacySettingsHidden": true,
        "userType": "administrator"
      },
      "outOfBoxExperienceSettings": {
        "deviceUsageType": "singleUser",
        "hideEULA": true,
        "hideEscapeLink": true,
        "hidePrivacySettings": true,
        "skipKeyboardSelectionPage": true,
        "userType": "administrator"
      },
      "preprovisioningAllowed": true,
      "roleScopeTagIds": [
        "0"
      ]
    }
  ]
}`

	liveAssignmentsBody = `{
  "@odata.context": "https://graph.microsoft.com/beta/$metadata#deviceManagement/windowsAutopilotDeploymentProfiles('39778baa-907f-4f7d-9bb8-a4f76a4ce69f')/assignments",
  "value": [
    {
      "id": "39778baa-907f-4f7d-9bb8-a4f76a4ce69f_adadadad-808e-44e2-905a-0b7873a8a531_0",
      "source": "direct",
      "sourceId": "39778baa-907f-4f7d-9bb8-a4f76a4ce69f",
      "target": {
        "@odata.type": "#microsoft.graph.allDevicesAssignmentTarget",
        "deviceAndAppManagementAssignmentFilterId": null,
        "deviceAndAppManagementAssignmentFilterType": "none"
      }
    }
  ]
}`
)

func newTestCollector(g collectors.GraphClient) *Collector {
	c := New(g, nil)
	c.now = fixedClock
	return c
}

func devicesURL() string      { return v1Base + "/deviceManagement/windowsAutopilotDeviceIdentities" }
func profilesURL() string     { return betaBase + "/deviceManagement/windowsAutopilotDeploymentProfiles" }
func syncSettingsURL() string { return betaBase + "/deviceManagement/windowsAutopilotSettings" }
func assignmentsURL(id string) string {
	return betaBase + "/deviceManagement/windowsAutopilotDeploymentProfiles/" + id + "/assignments"
}

// baseSyncSettingsBody is a healthy (completed) windowsAutopilotSettings
// singleton dated one hour before fixedNow, wired into baseFixtures so every
// test's Collect gets a sane device-registration sync clock. The VERBATIM live
// capture (dated 2026-07-23) is exercised separately in
// TestCollectEmitsLiveSyncSettingsEndToEnd, and the unhealthy/Warn path in
// TestCollectEmitsSyncTwinWhenSyncNotCompleted.
const baseSyncSettingsBody = `{
  "id": "e933bb26-3dff-49f0-a41a-bd722a92f1fb",
  "lastSyncDateTime": "2026-07-17T17:00:00Z",
  "lastManualSyncTriggerDateTime": "2026-07-17T16:59:59Z",
  "syncStatus": "completed"
}`

// liveSyncSettingsBody is a VERBATIM GET
// /beta/deviceManagement/windowsAutopilotSettings read as graph2otel-poller
// against the m7kni tenant `[live-measured 2026-07-23, #248]`. A singleton (no
// {value:[]} envelope): the last device-registration sync completed cleanly.
const liveSyncSettingsBody = `{
  "@odata.context": "https://graph.microsoft.com/beta/$metadata#deviceManagement/windowsAutopilotSettings/$entity",
  "id": "e933bb26-3dff-49f0-a41a-bd722a92f1fb",
  "lastSyncDateTime": "2026-07-23T11:23:15.0768271Z",
  "lastManualSyncTriggerDateTime": "2026-07-23T11:23:14.5754524Z",
  "syncStatus": "completed"
}`

// liveSyncNow is one hour after the live lastSyncDateTime, so sync_age is 3600s.
var liveSyncNow = time.Date(2026, 7, 23, 12, 23, 15, 76827100, time.UTC)

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

// baseFixtures wires the three verbatim live captures to the URLs this
// collector polls: the single Autopilot device identity, the single deployment
// profile, and its single assignment.
func baseFixtures() map[string]string {
	return map[string]string{
		devicesURL():                  liveDevicesBody,
		profilesURL():                 liveProfilesBody,
		assignmentsURL(liveProfileID): liveAssignmentsBody,
		syncSettingsURL():             baseSyncSettingsBody,
	}
}

// TestCollectEmitsLiveCaptureEndToEnd drives the verbatim live captures through
// Collect into a Recorder — the real device identity, deployment profile, and
// assignment this tenant has — proving the collector's headline series come out
// of the exact bytes the endpoints returned, not a docs-shaped fixture.
func TestCollectEmitsLiveCaptureEndToEnd(t *testing.T) {
	g := &fakeGraph{bodies: baseFixtures()}
	rec := telemetrytest.New()

	if err := newTestCollector(g).Collect(context.Background(), rec.Emitter()); err != nil {
		t.Fatalf("Collect: %v", err)
	}

	// One enrolled device, empty groupTag → "unassigned".
	devices := rec.MetricPoints(devicesMetricName)
	if len(devices) != 1 {
		t.Fatalf("device series = %d, want 1: %+v", len(devices), devices)
	}
	if devices[0].Value != 1 || devices[0].Attrs["enrollment_state"] != "enrolled" || devices[0].Attrs["group_tag"] != "unassigned" {
		t.Errorf("device point = %+v, want value=1 enrolled/unassigned", devices[0])
	}

	// The live device was contacted the day before fixedNow → not stale.
	if pts := rec.MetricPoints(staleContactMetricName); len(pts) != 0 {
		t.Errorf("stale_contact points = %+v, want none (live device contacted <30d ago)", pts)
	}

	// One windowsPc profile with preprovisioning allowed.
	profiles := rec.MetricPoints(profileCountMetricName)
	if len(profiles) != 1 || profiles[0].Value != 1 ||
		profiles[0].Attrs["device_type"] != "windows_pc" || profiles[0].Attrs["preprovisioning_allowed"] != "true" {
		t.Errorf("profile count = %+v, want one windows_pc/true point", profiles)
	}

	// enrollmentStatusScreenSettings is null on the live profile, so every ESP
	// setting reads false and no esp_timeout point is emitted.
	espSettings := map[string]float64{}
	for _, p := range rec.MetricPoints(profileSettingMetricName) {
		espSettings[p.Attrs["setting"]] = p.Value
	}
	if espSettings["preprovisioning_allowed"] != 1 || espSettings["hardware_hash_extraction_enabled"] != 1 {
		t.Errorf("profile settings = %+v, want preprovisioning_allowed=1 hardware_hash_extraction_enabled=1", espSettings)
	}
	if espSettings["esp_hide_installation_progress"] != 0 {
		t.Errorf("esp_hide_installation_progress = %v, want 0 (ESP settings null on live profile)", espSettings["esp_hide_installation_progress"])
	}
	if pts := rec.MetricPoints(profileEspTimeoutMetricName); len(pts) != 0 {
		t.Errorf("esp_timeout points = %+v, want none (ESP settings null on live profile)", pts)
	}

	// One assignment on the profile.
	assignments := rec.MetricPoints(profileAssignmentsMetricName)
	if len(assignments) != 1 || assignments[0].Value != 1 {
		t.Errorf("assignment points = %+v, want one point value=1", assignments)
	}
}

// syntheticDevicesFixture returns a base fixture whose device list is replaced
// with a hand-built multi-state, multi-tag set. The live tenant has only one
// (enrolled, not-stale, untagged) device, so the enrollment-state spread, the
// stale-contact threshold, and the group_tag cardinality cap can only be
// exercised against synthetic identities — the deployment profile and
// assignment stay the verbatim live captures.
func syntheticDevicesFixture(identities ...map[string]any) map[string]string {
	bodies := baseFixtures()
	bodies[devicesURL()] = page(identities...)
	return bodies
}

func TestCollectEmitsDeviceGaugesByStateAndGroupTag(t *testing.T) {
	g := &fakeGraph{bodies: syntheticDevicesFixture(
		identity("enrolled", "site-a", daysAgo(1)),
		identity("enrolled", "site-a", daysAgo(2)),
		identity("notContacted", "site-b", nil),
		identity("failed", "", daysAgo(45)),
	)}
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
	g := &fakeGraph{bodies: syntheticDevicesFixture(
		identity("enrolled", "site-a", daysAgo(1)),
		identity("enrolled", "site-a", daysAgo(2)),
		identity("notContacted", "site-b", nil),
		identity("failed", "", daysAgo(45)),
	)}
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

// syntheticProfileFixture replaces the single live deployment profile (whose
// enrollmentStatusScreenSettings are null on the wire) with a hand-built
// ESP-configured profile, so the ESP config-drift settings and the ESP
// install-progress timeout have coverage. The device identity stays the
// verbatim live capture.
func syntheticProfileFixture() map[string]string {
	bodies := baseFixtures()
	delete(bodies, assignmentsURL(liveProfileID))
	bodies[profilesURL()] = page(profile("esp-1", "Corp Profile", "windowsPc", true, true))
	bodies[assignmentsURL("esp-1")] = page(
		map[string]any{"target": map[string]any{"@odata.type": "#microsoft.graph.groupAssignmentTarget"}},
	)
	return bodies
}

func TestCollectEmitsProfileSettingGauges(t *testing.T) {
	g := &fakeGraph{bodies: syntheticProfileFixture()}
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
	g := &fakeGraph{bodies: syntheticProfileFixture()}
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
	// The live profile has exactly one assignment (an allDevicesAssignmentTarget).
	if pts[0].Value != 1 {
		t.Errorf("assignment count = %v, want 1", pts[0].Value)
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

// TestCollectEmitsLiveSyncSettingsEndToEnd drives the verbatim live
// windowsAutopilotSettings singleton (#248) through Collect: a healthy
// (completed) sync emits sync_age_seconds and the sync_status gauge but NO twin.
func TestCollectEmitsLiveSyncSettingsEndToEnd(t *testing.T) {
	bodies := baseFixtures()
	bodies[syncSettingsURL()] = liveSyncSettingsBody
	g := &fakeGraph{bodies: bodies}
	c := New(g, nil)
	c.now = func() time.Time { return liveSyncNow }
	rec := telemetrytest.New()

	if err := c.Collect(context.Background(), rec.Emitter()); err != nil {
		t.Fatalf("Collect: %v", err)
	}

	age := rec.MetricPoints(syncAgeMetricName)
	if len(age) != 1 || age[0].Value != (1*time.Hour).Seconds() {
		t.Errorf("sync_age = %+v, want one point value=3600", age)
	}
	if len(age) == 1 && len(age[0].Attrs) != 0 {
		t.Errorf("sync_age carries labels %+v, want none", age[0].Attrs)
	}

	status := rec.MetricPoints(syncStatusMetricName)
	if len(status) != 1 || status[0].Value != 1 || status[0].Attrs["sync_status"] != "completed" {
		t.Errorf("sync_status = %+v, want one completed point value=1", status)
	}

	for _, r := range rec.LogRecords() {
		if r.EventName == eventSync {
			t.Errorf("intune.autopilot.sync twin emitted for a completed sync: %+v", r)
		}
	}
}

// TestCollectEmitsSyncTwinWhenSyncNotCompleted pins the Warn/twin path: a sync
// whose status is not "completed" emits the bounded sync_status gauge in that
// bucket AND one intune.autopilot.sync log twin at WARN — the only way
// "registrations stopped arriving from the OEM/partner" becomes detectable.
func TestCollectEmitsSyncTwinWhenSyncNotCompleted(t *testing.T) {
	bodies := baseFixtures()
	bodies[syncSettingsURL()] = `{"id":"ap-1","lastSyncDateTime":"2026-07-10T00:00:00Z","lastManualSyncTriggerDateTime":"2026-07-10T00:00:00Z","syncStatus":"failed"}`
	g := &fakeGraph{bodies: bodies}
	rec := telemetrytest.New()

	if err := newTestCollector(g).Collect(context.Background(), rec.Emitter()); err != nil {
		t.Fatalf("Collect: %v", err)
	}

	status := rec.MetricPoints(syncStatusMetricName)
	if len(status) != 1 || status[0].Value != 1 || status[0].Attrs["sync_status"] != "failed" {
		t.Errorf("sync_status = %+v, want one failed point value=1", status)
	}

	var twins []telemetrytest.LogRecord
	for _, r := range rec.LogRecords() {
		if r.EventName == eventSync {
			twins = append(twins, r)
		}
	}
	if len(twins) != 1 {
		t.Fatalf("intune.autopilot.sync twins = %d, want 1: %+v", len(twins), twins)
	}
	tw := twins[0]
	if tw.SeverityText != "WARN" {
		t.Errorf("twin severity = %q, want WARN (sync not completed)", tw.SeverityText)
	}
	if tw.Attrs["sync_status"] != "failed" || tw.Attrs["id"] != "ap-1" {
		t.Errorf("twin attrs = %+v, want sync_status=failed id=ap-1", tw.Attrs)
	}
	if tw.Attrs["last_sync_date_time"] == "" {
		t.Errorf("twin missing last_sync_date_time: %+v", tw.Attrs)
	}
}

// TestCollectSkipsUnavailableSyncSettingsEndpoint pins the beta-unavailability
// graceful-skip: a 403/404 from windowsAutopilotSettings is skipped-and-logged,
// not a Collect error, and the device/profile signals still emit.
func TestCollectSkipsUnavailableSyncSettingsEndpoint(t *testing.T) {
	g := &fakeGraph{
		bodies: baseFixtures(),
		errs:   map[string]error{syncSettingsURL(): errors.New("graph request failed: status 404")},
	}
	rec := telemetrytest.New()

	if err := newTestCollector(g).Collect(context.Background(), rec.Emitter()); err != nil {
		t.Fatalf("Collect should skip-and-log an unavailable beta sync endpoint, got error: %v", err)
	}
	if len(rec.MetricPoints(syncAgeMetricName)) != 0 || len(rec.MetricPoints(syncStatusMetricName)) != 0 {
		t.Error("sync signals should be absent when the endpoint is unavailable")
	}
	if len(rec.MetricPoints(devicesMetricName)) == 0 {
		t.Error("device series should still emit despite the sync endpoint being unavailable")
	}
}

// TestCollectIsResilientToSyncSettingsFailure: a real (non-4xx) sync failure is
// surfaced as an error but does not suppress the device/profile signals.
func TestCollectIsResilientToSyncSettingsFailure(t *testing.T) {
	g := &fakeGraph{
		bodies: baseFixtures(),
		errs:   map[string]error{syncSettingsURL(): errors.New("throttled")},
	}
	rec := telemetrytest.New()

	err := newTestCollector(g).Collect(context.Background(), rec.Emitter())
	if err == nil {
		t.Fatal("expected Collect to surface the sync settings failure as an error")
	}
	if len(rec.MetricPoints(syncAgeMetricName)) != 0 {
		t.Error("sync signals should be absent when the sync fetch failed")
	}
	if len(rec.MetricPoints(devicesMetricName)) == 0 || len(rec.MetricPoints(profileCountMetricName)) == 0 {
		t.Error("device and profile series should still emit despite the sync failure")
	}
}

func TestSyncStatusBucketFor(t *testing.T) {
	cases := map[string]string{
		"completed":    "completed",
		"inProgress":   "in_progress",
		"failed":       "failed",
		"unknown":      "unknown",
		"":             "unknown",
		"somethingNew": "other",
	}
	for raw, want := range cases {
		if got := syncStatusBucketFor(raw); got != want {
			t.Errorf("syncStatusBucketFor(%q) = %q, want %q", raw, got, want)
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

// --- wire-assumption watchdog (#233/#234) --------------------------------
//
// enrollment_state, device_type and sync_status are METRIC LABELS derived from
// three explicit bucket maps in this package. A Microsoft addition to any of
// those enums lands in "other"/"unknown" and silently moves a series, so each
// is declared to wirecheck and reported rather than swallowed.

func findings(rec *telemetrytest.Recorder) map[string]float64 {
	out := map[string]float64{}
	for _, p := range rec.MetricPoints(wirecheck.MetricUnexpected) {
		out[p.Attrs[semconv.AttrKind]+"/"+p.Attrs[semconv.AttrField]] += p.Value
	}
	return out
}

// The verbatim live captures are the steady state. A watchdog that fires on
// them is worse than no watchdog at all.
func TestLiveCaptureReportsNothingUnexpected(t *testing.T) {
	g := &fakeGraph{bodies: baseFixtures()}
	rec := telemetrytest.New()
	if err := newTestCollector(g).Collect(context.Background(), rec.Emitter()); err != nil {
		t.Fatalf("Collect: %v", err)
	}
	if got := findings(rec); len(got) != 0 {
		t.Errorf("live capture produced findings %v, want none", got)
	}
}

func TestUnmappedEnumsOnMetricLabelsAreReported(t *testing.T) {
	for _, tc := range []struct{ name, from, to, field string }{
		{"enrollmentState", `"enrollmentState": "enrolled"`, `"enrollmentState": "quarantined"`, semconv.AttrEnrollmentState},
		{"deviceType", `"deviceType": "windowsPc"`, `"deviceType": "windowsIoT"`, semconv.AttrDeviceType},
		{"syncStatus", `"syncStatus": "completed"`, `"syncStatus": "throttled"`, semconv.AttrSyncStatus},
	} {
		t.Run(tc.name, func(t *testing.T) {
			bodies := baseFixtures()
			replaced := false
			for url, body := range bodies {
				if next := strings.Replace(body, tc.from, tc.to, 1); next != body {
					bodies[url] = next
					replaced = true
				}
			}
			if !replaced {
				t.Fatalf("no fixture contains %q — the test is not exercising what it claims", tc.from)
			}
			rec := telemetrytest.New()
			if err := newTestCollector(&fakeGraph{bodies: bodies}).Collect(context.Background(), rec.Emitter()); err != nil {
				t.Fatalf("Collect: %v", err)
			}
			key := wirecheck.KindUnmappedValue + "/" + tc.field
			if got := findings(rec)[key]; got != 1 {
				t.Errorf("findings[%s] = %v, want 1; all=%v", key, got, findings(rec))
			}
			// Report-only: the rows must still be counted. An unexpected value is
			// never a reason to lose data.
			if len(rec.MetricPoints(devicesMetricName)) == 0 || len(rec.MetricPoints(profileCountMetricName)) == 0 {
				t.Error("an unexpected enum value must not stop the collector emitting")
			}
		})
	}
}
