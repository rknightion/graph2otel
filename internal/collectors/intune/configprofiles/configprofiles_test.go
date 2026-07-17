package configprofiles

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/rknightion/graph2otel/internal/collectors"
	"github.com/rknightion/graph2otel/internal/telemetrytest"
)

// fakeGraph maps request URLs to canned response bodies (or errors) and
// records every URL requested, so tests can assert both what was emitted and
// exactly which endpoints were (or were not) called - mirrors the
// intune/compliance reference collector's test fake.
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
		return nil, errors.New("fakeGraph: no canned body for " + url)
	}
	return []byte(body), nil
}

var _ collectors.GraphClient = (*fakeGraph)(nil)

const base = "https://graph.microsoft.com/v1.0"

const profilesURL = base + "/deviceManagement/deviceConfigurations"

func statusOverviewURL(id string) string {
	return base + "/deviceManagement/deviceConfigurations/" + id + "/deviceStatusOverview"
}

// forbidden403 mimics the graphclient error format that Count/RawGet produce
// for an HTTP 403, so isForbidden's substring check is exercised the way it
// would be against the real client.
func forbidden403(url string) error {
	return errors.New("graphclient: GET " + url + ": status 403: Forbidden")
}

func emptyEndpoints() map[string]string {
	return map[string]string{profilesURL: `{"value":[]}`}
}

// The live* consts below are VERBATIM GET responses from the m7kni tenant, read
// as graph2otel-poller on 2026-07-17 `[live-measured 2026-07-17, #165]`,
// replacing the hand-written docs-derived fixtures. Endpoints, both Graph v1.0:
//
//	liveDeviceConfigurations   GET /deviceManagement/deviceConfigurations
//	liveDeviceStatusOverview   GET /deviceManagement/deviceConfigurations/{id}/deviceStatusOverview
//
// The overview singleton was captured against firstProfileID below (iOS Device
// Features) — every field statusOverview reads (pending/notApplicable/success/
// error/failedCount) is present, alongside id/configurationVersion/
// lastUpdateDateTime the collector ignores.
//
// TRIMMING: the tenant's deviceConfigurations collection returned 5 whole
// elements across exactly two @odata.type variants
// (#microsoft.graph.iosDeviceFeaturesConfiguration and
// #microsoft.graph.iosCustomConfiguration). Per the whole-array-element trim
// rule this fixture keeps ONE of each variant VERBATIM — the two smallest that
// still preserve both branches the collector buckets on. Three whole elements
// were dropped, none of whose fields the collector reads:
//   - "iOS Home Screen" (id 422f562a…, iosDeviceFeaturesConfiguration): ~1400
//     lines of nested homeScreenPages app inventory, redundant with the kept
//     iosDeviceFeaturesConfiguration variant.
//   - "iOS WiFi" (id dbc608ca…, iosCustomConfiguration): its base64 `payload`
//     mobileconfig embeds a live Wi-Fi PSK — a secret, excluded from the repo.
//   - "iOS Google Account" (id db167a8b…, iosCustomConfiguration): its `payload`
//     embeds a personal email address.
//
// iosDeviceFeaturesConfiguration is NOT in odataTypeBuckets, so it buckets to
// "other"; iosCustomConfiguration buckets to "ios_custom". The kept iOS
// Tailscale VPN element retains its real `payload` (a VPN mobileconfig with no
// plaintext credential) so the iosCustomConfiguration wire shape stays honest.
const liveDeviceConfigurations = `{
  "@odata.context": "https://graph.microsoft.com/v1.0/$metadata#deviceManagement/deviceConfigurations",
  "value": [
    {
      "@odata.type": "#microsoft.graph.iosDeviceFeaturesConfiguration",
      "assetTagTemplate": null,
      "createdDateTime": "2025-09-12T14:14:09.1129465Z",
      "description": "SSO",
      "displayName": "iOS Device Features",
      "homeScreenDockIcons": [],
      "homeScreenPages": [],
      "id": "811467ae-0e0f-4d7a-9d50-c557dda16078",
      "lastModifiedDateTime": "2025-09-21T17:44:34.3424844Z",
      "lockScreenFootnote": null,
      "notificationSettings": [],
      "version": 3
    },
    {
      "@odata.type": "#microsoft.graph.iosCustomConfiguration",
      "createdDateTime": "2025-09-26T16:45:40.4477863Z",
      "description": null,
      "displayName": "iOS Tailscale VPN",
      "id": "52b454c6-fa6f-4383-8857-de01e567022e",
      "lastModifiedDateTime": "2025-09-26T16:45:40.4477863Z",
      "payload": "PD94bWwgdmVyc2lvbj0iMS4wIiBlbmNvZGluZz0iVVRGLTgiPz4KPCFET0NUWVBFIHBsaXN0IFBVQkxJQyAiLS8vQXBwbGUvL0RURCBQTElTVCAxLjAvL0VOIiAiaHR0cDovL3d3dy5hcHBsZS5jb20vRFREcy9Qcm9wZXJ0eUxpc3QtMS4wLmR0ZCI+CjxwbGlzdCB2ZXJzaW9uPSIxLjAiPgo8ZGljdD4KICA8a2V5PlBheWxvYWREaXNwbGF5TmFtZTwva2V5PgogIDxzdHJpbmc+VGFpbHNjYWxlIGlPUyBWUE4gQ29uZmlndXJhdGlvbiBQcm9maWxlPC9zdHJpbmc+CiAgPGtleT5QYXlsb2FkVHlwZTwva2V5PgogIDxzdHJpbmc+Q29uZmlndXJhdGlvbjwvc3RyaW5nPgogIDxrZXk+UGF5bG9hZFZlcnNpb248L2tleT4KICA8aW50ZWdlcj4xPC9pbnRlZ2VyPgogIDxrZXk+UGF5bG9hZElkZW50aWZpZXI8L2tleT4KICA8c3RyaW5nPmNvbS55b3VyLWNvbXBhbnktbmFtZS50YWlsc2NhbGUuNzk3ZDQ0NjEtODM3Yy00ZjVhLWIxOGUtN2UzMDBhMDU3MDIwPC9zdHJpbmc+CiAgPGtleT5QYXlsb2FkVVVJRDwva2V5PgogIDxzdHJpbmc+MGY0NTE4ODEtN2FjNC00MTcxLTgwZmQtYjU1MjUxMDUzMjMzPC9zdHJpbmc+CiAgPGtleT5QYXlsb2FkQ29udGVudDwva2V5PgogIDxhcnJheT4KICAgICAgICA8ZGljdD4KICAgICAgICA8a2V5PlBheWxvYWREaXNwbGF5TmFtZTwva2V5PgogICAgICAgIDxzdHJpbmc+VGFpbHNjYWxlIFZQTiBDb25maWd1cmF0aW9uPC9zdHJpbmc+CiAgICAgICAgPGtleT5QYXlsb2FkVHlwZTwva2V5PgogICAgICAgIDxzdHJpbmc+Y29tLmFwcGxlLnZwbi5tYW5hZ2VkPC9zdHJpbmc+CiAgICAgICAgPGtleT5QYXlsb2FkVmVyc2lvbjwva2V5PgogICAgICAgIDxpbnRlZ2VyPjE8L2ludGVnZXI+CiAgICAgICAgPGtleT5QYXlsb2FkSWRlbnRpZmllcjwva2V5PgogICAgICAgIDxzdHJpbmc+Y29tLnlvdXItY29tcGFueS1uYW1lLnRhaWxzY2FsZS10dW5uZWw8L3N0cmluZz4KICAgICAgICA8a2V5PlBheWxvYWRVVUlEPC9rZXk+CiAgICAgICAgPHN0cmluZz43ZWM5NTdlMi1iMTY1LTRkMWYtOTk0Ni0zYTdhMTZhZTBmOWM8L3N0cmluZz4KICAgICAgICA8a2V5PlVzZXJEZWZpbmVkTmFtZTwva2V5PgogICAgICAgIDxzdHJpbmc+VGFpbHNjYWxlIE1vYmlsZUNvbmZpZzwvc3RyaW5nPgogICAgICAgIDxrZXk+VlBOVHlwZTwva2V5PgogICAgICAgIDxzdHJpbmc+VlBOPC9zdHJpbmc+CiAgICAgICAgPGtleT5WUE5TdWJUeXBlPC9rZXk+CiAgICAgICAgPHN0cmluZz5pby50YWlsc2NhbGUuaXBuLmlvczwvc3RyaW5nPgogICAgICAgIDxrZXk+VlBOPC9rZXk+CiAgICAgICAgIDxkaWN0PgogICAgICAgICAgICA8a2V5PlJlbW90ZUFkZHJlc3M8L2tleT4KICAgICAgICAgICAgPHN0cmluZz5UYWlsc2NhbGUgTWVzaDwvc3RyaW5nPgogICAgICAgICAgICA8a2V5PkF1dGhlbnRpY2F0aW9uTWV0aG9kPC9rZXk+CiAgICAgICAgICAgIDxzdHJpbmc+UGFzc3dvcmQ8L3N0cmluZz4KICAgICAgICAgICAgPGtleT5Qcm92aWRlckJ1bmRsZUlkZW50aWZpZXI8L2tleT4KICAgICAgICAgICAgPHN0cmluZz5pby50YWlsc2NhbGUuaXBuLmlvcy5uZXR3b3JrLWV4dGVuc2lvbjwvc3RyaW5nPgogICAgICAgIDwvZGljdD4KICAgIDwvZGljdD4KICA8L2FycmF5Pgo8L2RpY3Q+CjwvcGxpc3Q+Cg==",
      "payloadFileName": "Tailscale-VPN-iOS.mobileconfig",
      "payloadName": "iOS Tailscale VPN",
      "version": 1
    }
  ]
}`

const liveDeviceStatusOverview = `{
  "@odata.context": "https://graph.microsoft.com/v1.0/$metadata#deviceManagement/deviceConfigurations('811467ae-0e0f-4d7a-9d50-c557dda16078')/deviceStatusOverview/$entity",
  "configurationVersion": 3,
  "errorCount": 0,
  "failedCount": 0,
  "id": "811467ae-0e0f-4d7a-9d50-c557dda16078",
  "lastUpdateDateTime": "2026-07-16T20:06:57Z",
  "notApplicableCount": 2,
  "pendingCount": 0,
  "successCount": 2
}`

// firstProfileID is the id of liveDeviceConfigurations[0] (iOS Device Features),
// the profile the overview singleton was captured against. secondProfileID (iOS
// Tailscale VPN) had no captured overview, so the live end-to-end test answers
// its overview URL with an empty (all-zero) singleton.
const (
	firstProfileID  = "811467ae-0e0f-4d7a-9d50-c557dda16078"
	secondProfileID = "52b454c6-fa6f-4383-8857-de01e567022e"
)

func merge(maps ...map[string]string) map[string]string {
	out := map[string]string{}
	for _, m := range maps {
		for k, v := range m {
			out[k] = v
		}
	}
	return out
}

func TestCollectEmitsProfileCountByODataType(t *testing.T) {
	bodies := merge(emptyEndpoints(), map[string]string{
		profilesURL: `{"value":[
			{"id":"p1","displayName":"Win10 General","version":1,"@odata.type":"#microsoft.graph.windows10GeneralConfiguration"},
			{"id":"p2","displayName":"Win10 General 2","version":1,"@odata.type":"#microsoft.graph.windows10GeneralConfiguration"},
			{"id":"p3","displayName":"iOS Wifi","version":1,"@odata.type":"#microsoft.graph.iosWiFiConfiguration"},
			{"id":"p4","displayName":"Something New","version":1,"@odata.type":"#microsoft.graph.someBrandNewConfigurationType"}
		]}`,
		statusOverviewURL("p1"): `{}`,
		statusOverviewURL("p2"): `{}`,
		statusOverviewURL("p3"): `{}`,
		statusOverviewURL("p4"): `{}`,
	})
	g := &fakeGraph{bodies: bodies}
	rec := telemetrytest.New()

	if err := New(g, nil).Collect(context.Background(), rec.Emitter()); err != nil {
		t.Fatalf("Collect: %v", err)
	}

	pts := rec.MetricPoints(countMetricName)
	got := map[string]float64{}
	for _, p := range pts {
		got[p.Attrs["odata_type"]] = p.Value
	}
	want := map[string]float64{"windows_general": 2, "ios_wifi": 1, "other": 1}
	if len(got) != len(want) {
		t.Fatalf("got %d odata_type series, want %d: %v", len(got), len(want), got)
	}
	for k, v := range want {
		if got[k] != v {
			t.Errorf("odata_type=%s = %v, want %v", k, got[k], v)
		}
	}
}

func TestCollectExcludesWindowsUpdateForBusinessConfiguration(t *testing.T) {
	bodies := merge(emptyEndpoints(), map[string]string{
		profilesURL: `{"value":[
			{"id":"p1","displayName":"Win10 General","version":1,"@odata.type":"#microsoft.graph.windows10GeneralConfiguration"},
			{"id":"ring1","displayName":"Update Ring","version":1,"@odata.type":"#microsoft.graph.windowsUpdateForBusinessConfiguration"}
		]}`,
		statusOverviewURL("p1"): `{}`,
	})
	g := &fakeGraph{bodies: bodies}
	rec := telemetrytest.New()

	if err := New(g, nil).Collect(context.Background(), rec.Emitter()); err != nil {
		t.Fatalf("Collect: %v", err)
	}

	// Not counted under any bucket.
	for _, p := range rec.MetricPoints(countMetricName) {
		if p.Value > 0 && p.Attrs["odata_type"] != "windows_general" {
			t.Errorf("unexpected odata_type bucket %q counted a Group-B-excluded profile: %+v", p.Attrs["odata_type"], p)
		}
	}
	total := 0.0
	for _, p := range rec.MetricPoints(countMetricName) {
		total += p.Value
	}
	if total != 1 {
		t.Errorf("total profile count = %v, want 1 (the windowsUpdateForBusinessConfiguration profile must be excluded, owned by #59)", total)
	}

	// Not version-tracked.
	for _, p := range rec.MetricPoints(versionMetricName) {
		if p.Attrs["profile_name"] == "Update Ring" {
			t.Error("Update Ring should have no version series - excluded Group B type")
		}
	}

	// Its status overview must never be fetched at all.
	for _, url := range g.requestedURL {
		if url == statusOverviewURL("ring1") {
			t.Errorf("requested %q - the excluded windowsUpdateForBusinessConfiguration profile's status overview must never be fetched", url)
		}
	}
}

// TestCollectEmitsLiveSnapshotEndToEnd drives the verbatim live captures
// through the whole Collect path into a telemetrytest Recorder, pinning the
// metric surface from what the endpoints actually return rather than from
// hand-written docs-derived JSON. It replaces the docs-fixture version-gauge and
// status-overview happy-path tests; the synthetic bucket, exclusion, resilience,
// forbidden, and version-bump tests stay, since the live capture cannot exercise
// those branches (only "other" and "ios_custom" buckets appear on the wire).
func TestCollectEmitsLiveSnapshotEndToEnd(t *testing.T) {
	g := &fakeGraph{bodies: map[string]string{
		profilesURL:                        liveDeviceConfigurations,
		statusOverviewURL(firstProfileID):  liveDeviceStatusOverview,
		statusOverviewURL(secondProfileID): `{}`,
	}}
	rec := telemetrytest.New()

	if err := New(g, nil).Collect(context.Background(), rec.Emitter()); err != nil {
		t.Fatalf("Collect: %v", err)
	}

	// Count by odata_type: iosDeviceFeaturesConfiguration -> "other" (not in the
	// bucket map), iosCustomConfiguration -> "ios_custom".
	counts := map[string]float64{}
	for _, p := range rec.MetricPoints(countMetricName) {
		counts[p.Attrs["odata_type"]] = p.Value
	}
	wantCounts := map[string]float64{"other": 1, "ios_custom": 1}
	if len(counts) != len(wantCounts) {
		t.Fatalf("got %d odata_type series, want %d: %v", len(counts), len(wantCounts), counts)
	}
	for k, v := range wantCounts {
		if counts[k] != v {
			t.Errorf("odata_type %q = %v, want %v", k, counts[k], v)
		}
	}

	// Version gauge: one point per profile, keyed by the real profile_name.
	versions := map[string]float64{}
	for _, p := range rec.MetricPoints(versionMetricName) {
		versions[p.Attrs["profile_name"]] = p.Value
	}
	wantVersions := map[string]float64{"iOS Device Features": 3, "iOS Tailscale VPN": 1}
	if len(versions) != len(wantVersions) {
		t.Fatalf("got %d version series, want %d: %v", len(versions), len(wantVersions), versions)
	}
	for k, v := range wantVersions {
		if versions[k] != v {
			t.Errorf("profile %q version = %v, want %v", k, versions[k], v)
		}
	}

	// Status overview: 2 profiles * 5 states. iOS Device Features carries the
	// captured overview (success=2, not_applicable=2); iOS Tailscale VPN is the
	// empty singleton.
	statusPts := rec.MetricPoints(statusMetricName)
	if len(statusPts) != 10 {
		t.Fatalf("got %d config_profile.status series, want 10 (2 profiles * 5 states)", len(statusPts))
	}
	gotStatus := map[[2]string]float64{}
	for _, p := range statusPts {
		gotStatus[[2]string{p.Attrs["profile_name"], p.Attrs["state"]}] = p.Value
	}
	if v := gotStatus[[2]string{"iOS Device Features", "success"}]; v != 2 {
		t.Errorf("iOS Device Features success = %v, want 2", v)
	}
	if v := gotStatus[[2]string{"iOS Device Features", "not_applicable"}]; v != 2 {
		t.Errorf("iOS Device Features not_applicable = %v, want 2", v)
	}
}

func TestCollectSurfacesVersionBumpBetweenPolls(t *testing.T) {
	g := &fakeGraph{bodies: merge(emptyEndpoints(), map[string]string{
		profilesURL:             `{"value":[{"id":"p1","displayName":"Win10 General","version":3,"@odata.type":"#microsoft.graph.windows10GeneralConfiguration"}]}`,
		statusOverviewURL("p1"): `{}`,
	})}
	rec := telemetrytest.New()
	c := New(g, nil)

	if err := c.Collect(context.Background(), rec.Emitter()); err != nil {
		t.Fatalf("first Collect: %v", err)
	}
	first := rec.MetricPoints(versionMetricName)
	if len(first) != 1 || first[0].Value != 3 {
		t.Fatalf("first poll version = %+v, want a single point at 3", first)
	}

	g.bodies[profilesURL] = `{"value":[{"id":"p1","displayName":"Win10 General","version":4,"@odata.type":"#microsoft.graph.windows10GeneralConfiguration"}]}`
	if err := c.Collect(context.Background(), rec.Emitter()); err != nil {
		t.Fatalf("second Collect: %v", err)
	}
	second := rec.MetricPoints(versionMetricName)
	if len(second) != 1 || second[0].Value != 4 {
		t.Fatalf("second poll version = %+v, want a single point at 4 (the bump)", second)
	}
}

func TestCollectIsResilientToOneProfileStatusOverviewFailure(t *testing.T) {
	bodies := merge(emptyEndpoints(), map[string]string{
		profilesURL: `{"value":[
			{"id":"p1","displayName":"Win10 General","version":1,"@odata.type":"#microsoft.graph.windows10GeneralConfiguration"},
			{"id":"p2","displayName":"iOS Wifi","version":1,"@odata.type":"#microsoft.graph.iosWiFiConfiguration"}
		]}`,
		statusOverviewURL("p2"): `{"successCount":9}`,
	})
	g := &fakeGraph{
		bodies: bodies,
		errs:   map[string]error{statusOverviewURL("p1"): errors.New("throttled")},
	}
	rec := telemetrytest.New()

	err := New(g, nil).Collect(context.Background(), rec.Emitter())
	if err == nil {
		t.Fatal("expected Collect to surface the per-profile status overview failure as an error")
	}

	pts := rec.MetricPoints(statusMetricName)
	got := map[[2]string]float64{}
	for _, p := range pts {
		got[[2]string{p.Attrs["profile_name"], p.Attrs["state"]}] = p.Value
	}
	if _, ok := got[[2]string{"Win10 General", "success"}]; ok {
		t.Error("Win10 General should have no status series since its overview fetch failed")
	}
	if got[[2]string{"iOS Wifi", "success"}] != 9 {
		t.Errorf("iOS Wifi success = %v, want 9 (unaffected by the other profile's failure)", got[[2]string{"iOS Wifi", "success"}])
	}
	if len(rec.MetricPoints(versionMetricName)) != 2 {
		t.Error("version series should be unaffected by the status-overview failure")
	}
}

func TestCollectGracefullySkipsForbiddenProfileList(t *testing.T) {
	g := &fakeGraph{
		bodies: emptyEndpoints(),
		errs:   map[string]error{profilesURL: forbidden403(profilesURL)},
	}
	rec := telemetrytest.New()

	if err := New(g, nil).Collect(context.Background(), rec.Emitter()); err != nil {
		t.Fatalf("Collect should gracefully skip a 403, not surface an error: %v", err)
	}
	if pts := rec.MetricPoints(countMetricName); len(pts) != 0 {
		t.Errorf("expected no count series when the profile list is forbidden, got %+v", pts)
	}
	if pts := rec.MetricPoints(versionMetricName); len(pts) != 0 {
		t.Errorf("expected no version series when the profile list is forbidden, got %+v", pts)
	}
}

func TestCollectGracefullySkipsForbiddenStatusOverview(t *testing.T) {
	bodies := merge(emptyEndpoints(), map[string]string{
		profilesURL: `{"value":[{"id":"p1","displayName":"Win10 General","version":1,"@odata.type":"#microsoft.graph.windows10GeneralConfiguration"}]}`,
	})
	g := &fakeGraph{
		bodies: bodies,
		errs:   map[string]error{statusOverviewURL("p1"): forbidden403(statusOverviewURL("p1"))},
	}
	rec := telemetrytest.New()

	if err := New(g, nil).Collect(context.Background(), rec.Emitter()); err != nil {
		t.Fatalf("Collect should gracefully skip a 403, not surface an error: %v", err)
	}
	if pts := rec.MetricPoints(statusMetricName); len(pts) != 0 {
		t.Errorf("expected no status series when the overview is forbidden, got %+v", pts)
	}
}

func TestCollectNeverFetchesPerDeviceStatusChildren(t *testing.T) {
	bodies := merge(emptyEndpoints(), map[string]string{
		profilesURL:             `{"value":[{"id":"p1","displayName":"Win10 General","version":1,"@odata.type":"#microsoft.graph.windows10GeneralConfiguration"}]}`,
		statusOverviewURL("p1"): `{}`,
	})
	g := &fakeGraph{bodies: bodies}
	rec := telemetrytest.New()

	if err := New(g, nil).Collect(context.Background(), rec.Emitter()); err != nil {
		t.Fatalf("Collect: %v", err)
	}

	forbiddenSubstrings := []string{"/deviceStatuses", "/userStatuses", "/deviceSettingStateSummaries", "$expand"}
	for _, url := range g.requestedURL {
		for _, sub := range forbiddenSubstrings {
			if strings.Contains(url, sub) {
				t.Errorf("requested %q, which touches the per-device status children this collector must never fetch", url)
			}
		}
	}
}

func TestNoPerEntityAttribute(t *testing.T) {
	bodies := merge(emptyEndpoints(), map[string]string{
		profilesURL:             `{"value":[{"id":"p1","displayName":"Win10 General","version":1,"@odata.type":"#microsoft.graph.windows10GeneralConfiguration"}]}`,
		statusOverviewURL("p1"): `{"successCount":1}`,
	})
	g := &fakeGraph{bodies: bodies}
	rec := telemetrytest.New()

	if err := New(g, nil).Collect(context.Background(), rec.Emitter()); err != nil {
		t.Fatalf("Collect: %v", err)
	}

	forbiddenAttrs := []string{"id", "deviceId", "device_id", "userId", "user_id", "upn"}
	for _, metric := range []string{countMetricName, versionMetricName, statusMetricName} {
		for _, p := range rec.MetricPoints(metric) {
			for _, bad := range forbiddenAttrs {
				if _, ok := p.Attrs[bad]; ok {
					t.Errorf("metric %s has a per-entity attribute %q - cardinality violation", metric, bad)
				}
			}
		}
	}
}

func TestNameIntervalAndPermissions(t *testing.T) {
	c := New(&fakeGraph{}, nil)
	if c.Name() != "intune.config_profiles" {
		t.Errorf("Name = %q, want intune.config_profiles", c.Name())
	}
	if c.DefaultInterval() <= 0 {
		t.Errorf("DefaultInterval = %v, want positive", c.DefaultInterval())
	}
	perms := c.RequiredPermissions()
	if len(perms) != 1 || perms[0] != "DeviceManagementConfiguration.Read.All" {
		t.Errorf("RequiredPermissions = %v, want [DeviceManagementConfiguration.Read.All]", perms)
	}
}
