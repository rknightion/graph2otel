package compliance

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/rknightion/graph2otel/internal/collectors"
	"github.com/rknightion/graph2otel/internal/telemetrytest"
)

// fakeGraph maps request URLs to canned response bodies (or errors) and
// records every URL requested, so tests can assert both what was emitted and
// exactly which endpoints were (or were not) called.
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

const base = "https://graph.microsoft.com/v1.0"

const (
	stateSummaryURL     = base + "/deviceManagement/deviceCompliancePolicyDeviceStateSummary"
	policiesURL         = base + "/deviceManagement/deviceCompliancePolicies"
	settingSummariesURL = base + "/deviceManagement/deviceCompliancePolicySettingStateSummaries"
)

func deviceOverviewURL(id string) string {
	return base + "/deviceManagement/deviceCompliancePolicies/" + id + "/deviceStatusOverview"
}

func userOverviewURL(id string) string {
	return base + "/deviceManagement/deviceCompliancePolicies/" + id + "/userStatusOverview"
}

// forbidden403 mimics the graphclient error format that Count/RawGet produce
// for an HTTP 403, so isForbidden's substring check is exercised the way it
// would be against the real client.
func forbidden403(url string) error {
	return fmt.Errorf("graphclient: GET %s: status 403: Forbidden", url)
}

// The live* consts below are VERBATIM GET responses from the m7kni tenant, read
// as graph2otel-poller on 2026-07-17 `[live-measured 2026-07-17, #165]`. They
// replace the hand-written docs-derived fixtures that previously stood in for
// what these endpoints return, so the collector's field names/nesting are now
// pinned against the wire rather than against Microsoft's docs (which have been
// wrong on this project's path). Endpoints, all Graph v1.0:
//
//	liveDeviceStateSummary     GET /deviceManagement/deviceCompliancePolicyDeviceStateSummary
//	livePolicies               GET /deviceManagement/deviceCompliancePolicies
//	liveDeviceStatusOverview   GET /deviceManagement/deviceCompliancePolicies/{id}/deviceStatusOverview
//	liveUserStatusOverview     GET /deviceManagement/deviceCompliancePolicies/{id}/userStatusOverview
//	liveSettingStateSummaries  GET /deviceManagement/deviceCompliancePolicySettingStateSummaries
//
// Trimmed of nothing: the tenant returns exactly these 5 policies and 5
// setting-state summaries. The two per-policy overview singletons were captured
// against the FIRST policy (Android Compliance, firstPolicyID below) — every
// field the statusOverview struct reads (pending/notApplicable/success/error/
// failedCount) is present on the wire, alongside id/configurationVersion/
// lastUpdateDateTime the collector deliberately ignores.
//
// Note the heterogeneity the collector reads straight past: livePolicies[0]
// carries NO "@odata.type" and none of the platform-subtype rule fields (the
// base deviceCompliancePolicy shape), while the other four carry a concrete
// "#microsoft.graph.<platform>CompliancePolicy" type and that subtype's fields.
// The collector reads only id/displayName/version off all of them, so the
// variety is invisible to it but faithfully preserved here. Likewise
// liveSettingStateSummaries carries both a "setting" and a "settingName" key
// (identical values on this tenant) plus platformType values "all" and "iOS" —
// the collector keys on settingName + platformType.
const liveDeviceStateSummary = `{
  "@odata.context": "https://graph.microsoft.com/v1.0/$metadata#deviceManagement/deviceCompliancePolicyDeviceStateSummary/$entity",
  "compliantDeviceCount": 7,
  "configManagerCount": 0,
  "conflictDeviceCount": 0,
  "errorDeviceCount": 0,
  "id": "e933bb26-3dff-49f0-a41a-bd722a92f1fb",
  "inGracePeriodCount": 0,
  "nonCompliantDeviceCount": 2,
  "notApplicableDeviceCount": 0,
  "remediatedDeviceCount": 0,
  "unknownDeviceCount": 2
}`

const livePolicies = `{
  "@odata.context": "https://graph.microsoft.com/v1.0/$metadata#deviceManagement/deviceCompliancePolicies",
  "value": [
    {
      "createdDateTime": "2025-10-04T19:57:36.8479259Z",
      "description": null,
      "displayName": "Android Compliance",
      "id": "0100930b-518a-42dc-b670-bff867d2bf35",
      "lastModifiedDateTime": "2025-10-06T14:23:27.5956591Z",
      "version": 2
    },
    {
      "@odata.type": "#microsoft.graph.iosCompliancePolicy",
      "createdDateTime": "2025-10-20T11:36:49.0677733Z",
      "description": null,
      "deviceThreatProtectionEnabled": false,
      "deviceThreatProtectionRequiredSecurityLevel": "unavailable",
      "displayName": "iPad Wallboard Compliance",
      "id": "43e7022f-bafb-467b-8cd3-f53953d69316",
      "lastModifiedDateTime": "2025-10-20T11:36:49.0677733Z",
      "managedEmailProfileRequired": false,
      "osMaximumVersion": null,
      "osMinimumVersion": null,
      "passcodeBlockSimple": false,
      "passcodeExpirationDays": null,
      "passcodeMinimumCharacterSetCount": null,
      "passcodeMinimumLength": null,
      "passcodeMinutesOfInactivityBeforeLock": null,
      "passcodePreviousPasscodeBlockCount": null,
      "passcodeRequired": false,
      "passcodeRequiredType": "deviceDefault",
      "securityBlockJailbrokenDevices": true,
      "version": 1
    },
    {
      "@odata.type": "#microsoft.graph.iosCompliancePolicy",
      "createdDateTime": "2025-09-11T16:19:36.356115Z",
      "description": null,
      "deviceThreatProtectionEnabled": true,
      "deviceThreatProtectionRequiredSecurityLevel": "unavailable",
      "displayName": "iOS Compliance",
      "id": "6290fe56-bc5e-4492-9dd8-7288f5d00221",
      "lastModifiedDateTime": "2026-07-15T15:52:05.8158209Z",
      "managedEmailProfileRequired": false,
      "osMaximumVersion": null,
      "osMinimumVersion": null,
      "passcodeBlockSimple": false,
      "passcodeExpirationDays": null,
      "passcodeMinimumCharacterSetCount": null,
      "passcodeMinimumLength": null,
      "passcodeMinutesOfInactivityBeforeLock": null,
      "passcodePreviousPasscodeBlockCount": null,
      "passcodeRequired": true,
      "passcodeRequiredType": "deviceDefault",
      "securityBlockJailbrokenDevices": true,
      "version": 2
    },
    {
      "@odata.type": "#microsoft.graph.macOSCompliancePolicy",
      "createdDateTime": "2025-09-15T13:17:31.607627Z",
      "description": null,
      "deviceThreatProtectionEnabled": true,
      "deviceThreatProtectionRequiredSecurityLevel": "low",
      "displayName": "MacOS Compliance",
      "firewallBlockAllIncoming": false,
      "firewallEnableStealthMode": false,
      "firewallEnabled": true,
      "id": "6f007afa-3126-4ad7-a5a3-3bdaab8b45d3",
      "lastModifiedDateTime": "2026-07-13T20:26:49.1529526Z",
      "osMaximumVersion": null,
      "osMinimumVersion": null,
      "passwordBlockSimple": false,
      "passwordExpirationDays": 65535,
      "passwordMinimumCharacterSetCount": null,
      "passwordMinimumLength": null,
      "passwordMinutesOfInactivityBeforeLock": null,
      "passwordPreviousPasswordBlockCount": null,
      "passwordRequired": true,
      "passwordRequiredType": "alphanumeric",
      "storageRequireEncryption": true,
      "systemIntegrityProtectionEnabled": true,
      "version": 2
    },
    {
      "@odata.type": "#microsoft.graph.windows10CompliancePolicy",
      "bitLockerEnabled": true,
      "codeIntegrityEnabled": true,
      "createdDateTime": "2025-09-11T16:18:51.2668885Z",
      "description": null,
      "displayName": "WinCompliance",
      "earlyLaunchAntiMalwareDriverEnabled": false,
      "id": "f4eb5cca-8c67-4bd1-9162-6434e34da468",
      "lastModifiedDateTime": "2026-07-14T14:02:05.5922366Z",
      "mobileOsMaximumVersion": null,
      "mobileOsMinimumVersion": null,
      "osMaximumVersion": null,
      "osMinimumVersion": null,
      "passwordBlockSimple": false,
      "passwordExpirationDays": null,
      "passwordMinimumCharacterSetCount": null,
      "passwordMinimumLength": null,
      "passwordMinutesOfInactivityBeforeLock": null,
      "passwordPreviousPasswordBlockCount": null,
      "passwordRequired": false,
      "passwordRequiredToUnlockFromIdle": false,
      "passwordRequiredType": "deviceDefault",
      "requireHealthyDeviceReport": false,
      "secureBootEnabled": true,
      "storageRequireEncryption": true,
      "version": 4
    }
  ]
}`

const liveDeviceStatusOverview = `{
  "@odata.context": "https://graph.microsoft.com/v1.0/$metadata#deviceManagement/deviceCompliancePolicies('0100930b-518a-42dc-b670-bff867d2bf35')/deviceStatusOverview/$entity",
  "configurationVersion": 2,
  "errorCount": 0,
  "failedCount": 0,
  "id": "0100930b-518a-42dc-b670-bff867d2bf35",
  "lastUpdateDateTime": "2026-07-17T16:08:48Z",
  "notApplicableCount": 0,
  "pendingCount": 0,
  "successCount": 0
}`

const liveUserStatusOverview = `{
  "@odata.context": "https://graph.microsoft.com/v1.0/$metadata#deviceManagement/deviceCompliancePolicies('0100930b-518a-42dc-b670-bff867d2bf35')/userStatusOverview/$entity",
  "configurationVersion": 0,
  "errorCount": 0,
  "failedCount": 0,
  "id": "0100930b-518a-42dc-b670-bff867d2bf35",
  "lastUpdateDateTime": "2026-07-17T16:08:49.1614326Z",
  "notApplicableCount": 0,
  "pendingCount": 0,
  "successCount": 0
}`

const liveSettingStateSummaries = `{
  "@odata.context": "https://graph.microsoft.com/v1.0/$metadata#deviceManagement/deviceCompliancePolicySettingStateSummaries",
  "value": [
    {
      "compliantDeviceCount": 12,
      "conflictDeviceCount": 0,
      "errorDeviceCount": 1,
      "id": "DefaultDeviceCompliancePolicy.RequireDeviceCompliancePolicyAssigned",
      "nonCompliantDeviceCount": 1,
      "notApplicableDeviceCount": 0,
      "platformType": "all",
      "remediatedDeviceCount": 0,
      "setting": "DefaultDeviceCompliancePolicy.RequireDeviceCompliancePolicyAssigned",
      "settingName": "DefaultDeviceCompliancePolicy.RequireDeviceCompliancePolicyAssigned",
      "unknownDeviceCount": 0
    },
    {
      "compliantDeviceCount": 11,
      "conflictDeviceCount": 0,
      "errorDeviceCount": 0,
      "id": "DefaultDeviceCompliancePolicy.RequireRemainContact",
      "nonCompliantDeviceCount": 3,
      "notApplicableDeviceCount": 0,
      "platformType": "all",
      "remediatedDeviceCount": 0,
      "setting": "DefaultDeviceCompliancePolicy.RequireRemainContact",
      "settingName": "DefaultDeviceCompliancePolicy.RequireRemainContact",
      "unknownDeviceCount": 0
    },
    {
      "compliantDeviceCount": 14,
      "conflictDeviceCount": 0,
      "errorDeviceCount": 0,
      "id": "DefaultDeviceCompliancePolicy.RequireUserExistence",
      "nonCompliantDeviceCount": 0,
      "notApplicableDeviceCount": 0,
      "platformType": "all",
      "remediatedDeviceCount": 0,
      "setting": "DefaultDeviceCompliancePolicy.RequireUserExistence",
      "settingName": "DefaultDeviceCompliancePolicy.RequireUserExistence",
      "unknownDeviceCount": 0
    },
    {
      "compliantDeviceCount": 2,
      "conflictDeviceCount": 0,
      "errorDeviceCount": 0,
      "id": "IOSCompliancePolicy.AdvancedThreatProtectionRequiredSecurityLevel",
      "nonCompliantDeviceCount": 0,
      "notApplicableDeviceCount": 1,
      "platformType": "iOS",
      "remediatedDeviceCount": 0,
      "setting": "IOSCompliancePolicy.AdvancedThreatProtectionRequiredSecurityLevel",
      "settingName": "IOSCompliancePolicy.AdvancedThreatProtectionRequiredSecurityLevel",
      "unknownDeviceCount": 0
    },
    {
      "compliantDeviceCount": 2,
      "conflictDeviceCount": 0,
      "errorDeviceCount": 1,
      "id": "IOSCompliancePolicy.PasscodeRequired",
      "nonCompliantDeviceCount": 0,
      "notApplicableDeviceCount": 0,
      "platformType": "iOS",
      "remediatedDeviceCount": 0,
      "setting": "IOSCompliancePolicy.PasscodeRequired",
      "settingName": "IOSCompliancePolicy.PasscodeRequired",
      "unknownDeviceCount": 0
    }
  ]
}`

// firstPolicyID is the id of livePolicies[0] (Android Compliance) — the policy
// the two overview singletons above were captured against.
const firstPolicyID = "0100930b-518a-42dc-b670-bff867d2bf35"

// otherPolicyIDs are livePolicies[1:] — no overview singleton was captured for
// them, so the live end-to-end test answers their overview URLs with an empty
// (all-zero) singleton, which is what the tenant returns for a policy with no
// assigned devices.
var otherPolicyIDs = []string{
	"43e7022f-bafb-467b-8cd3-f53953d69316",
	"6290fe56-bc5e-4492-9dd8-7288f5d00221",
	"6f007afa-3126-4ad7-a5a3-3bdaab8b45d3",
	"f4eb5cca-8c67-4bd1-9162-6434e34da468",
}

// emptyEndpoints returns a fixture with every endpoint answering with an
// empty/zero result, so a test can override just the endpoint(s) it cares
// about without hand-filling the rest.
func emptyEndpoints() map[string]string {
	return map[string]string{
		stateSummaryURL:     `{}`,
		policiesURL:         `{"value":[]}`,
		settingSummariesURL: `{"value":[]}`,
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

// TestCollectEmitsLiveSnapshotEndToEnd drives the verbatim live captures
// through the whole Collect path into a telemetrytest Recorder, pinning the
// metric surface this collector produces from what the endpoints actually
// return rather than from hand-written docs-derived JSON. It is the
// intune/compliance analog of the riskdetections reference's end-to-end live
// test, and it replaces the three separate docs-fixture happy-path tests that
// previously covered the state summary, the policy/overview fan-out, and the
// setting-state summaries.
func TestCollectEmitsLiveSnapshotEndToEnd(t *testing.T) {
	bodies := map[string]string{
		stateSummaryURL:                  liveDeviceStateSummary,
		policiesURL:                      livePolicies,
		settingSummariesURL:              liveSettingStateSummaries,
		deviceOverviewURL(firstPolicyID): liveDeviceStatusOverview,
		userOverviewURL(firstPolicyID):   liveUserStatusOverview,
	}
	for _, id := range otherPolicyIDs {
		bodies[deviceOverviewURL(id)] = `{}`
		bodies[userOverviewURL(id)] = `{}`
	}
	g := &fakeGraph{bodies: bodies}
	rec := telemetrytest.New()

	if err := New(g, nil).Collect(context.Background(), rec.Emitter()); err != nil {
		t.Fatalf("Collect: %v", err)
	}

	// Tenant-wide device state summary — the real rollup, all 9 states present.
	devState := map[string]float64{}
	for _, p := range rec.MetricPoints(devicesMetricName) {
		devState[p.Attrs["state"]] = p.Value
	}
	wantState := map[string]float64{
		"compliant": 7, "non_compliant": 2, "unknown": 2,
		"in_grace_period": 0, "config_manager": 0, "not_applicable": 0,
		"remediated": 0, "error": 0, "conflict": 0,
	}
	if len(devState) != len(wantState) {
		t.Fatalf("got %d device state series, want %d: %v", len(devState), len(wantState), devState)
	}
	for k, v := range wantState {
		if devState[k] != v {
			t.Errorf("device state %q = %v, want %v", k, devState[k], v)
		}
	}

	// Policy-version gauge: one point per policy (5), keyed by policy_name.
	versions := map[string]float64{}
	for _, p := range rec.MetricPoints(policyVersionMetricName) {
		versions[p.Attrs["policy_name"]] = p.Value
	}
	wantVersions := map[string]float64{
		"Android Compliance": 2, "iPad Wallboard Compliance": 1, "iOS Compliance": 2,
		"MacOS Compliance": 2, "WinCompliance": 4,
	}
	if len(versions) != len(wantVersions) {
		t.Fatalf("got %d policy.version series, want %d: %v", len(versions), len(wantVersions), versions)
	}
	for k, v := range wantVersions {
		if versions[k] != v {
			t.Errorf("policy %q version = %v, want %v", k, versions[k], v)
		}
	}

	// Per-policy device overview: 5 policies * 5 states = 25 series. Android
	// Compliance (the captured overview) contributes all-zero points; assert it
	// emitted the 5 states rather than nothing.
	if pts := rec.MetricPoints(policyDevicesMetricName); len(pts) != 25 {
		t.Errorf("got %d policy.devices series, want 25 (5 policies * 5 states)", len(pts))
	}
	androidStates := map[string]struct{}{}
	for _, p := range rec.MetricPoints(policyDevicesMetricName) {
		if p.Attrs["policy_name"] == "Android Compliance" {
			androidStates[p.Attrs["state"]] = struct{}{}
		}
	}
	if len(androidStates) != 5 {
		t.Errorf("Android Compliance device-overview states = %v, want all 5", androidStates)
	}
	if pts := rec.MetricPoints(policyUsersMetricName); len(pts) != 25 {
		t.Errorf("got %d policy.users series, want 25 (5 policies * 5 states)", len(pts))
	}

	// Setting-state summaries: 5 unique (setting, platform) pairs * 7 states,
	// with platformType "all" and "iOS" both flowing straight through.
	settingPts := rec.MetricPoints(settingDevicesMetricName)
	if len(settingPts) != 35 {
		t.Fatalf("got %d setting.devices series, want 35 (5 settings * 7 states)", len(settingPts))
	}
	gotSetting := map[[3]string]float64{}
	for _, p := range settingPts {
		gotSetting[[3]string{p.Attrs["setting_name"], p.Attrs["platform"], p.Attrs["state"]}] = p.Value
	}
	if v := gotSetting[[3]string{"DefaultDeviceCompliancePolicy.RequireRemainContact", "all", "non_compliant"}]; v != 3 {
		t.Errorf("RequireRemainContact/all/non_compliant = %v, want 3", v)
	}
	if v := gotSetting[[3]string{"IOSCompliancePolicy.PasscodeRequired", "iOS", "error"}]; v != 1 {
		t.Errorf("PasscodeRequired/iOS/error = %v, want 1", v)
	}
	if v := gotSetting[[3]string{"DefaultDeviceCompliancePolicy.RequireUserExistence", "all", "compliant"}]; v != 14 {
		t.Errorf("RequireUserExistence/all/compliant = %v, want 14", v)
	}
}

func TestCollectSurfacesPolicyVersionBumpBetweenPolls(t *testing.T) {
	firstBodies := merge(emptyEndpoints(), map[string]string{
		policiesURL:             `{"value":[{"id":"p1","displayName":"Windows Baseline","version":3}]}`,
		deviceOverviewURL("p1"): `{}`,
		userOverviewURL("p1"):   `{}`,
	})
	g := &fakeGraph{bodies: firstBodies}
	rec := telemetrytest.New()
	c := New(g, nil)

	if err := c.Collect(context.Background(), rec.Emitter()); err != nil {
		t.Fatalf("first Collect: %v", err)
	}
	first := rec.MetricPoints(policyVersionMetricName)
	if len(first) != 1 || first[0].Value != 3 {
		t.Fatalf("first poll version = %+v, want a single point at 3", first)
	}

	// Second poll: the policy's version has bumped, simulating a
	// policy-content change between collection cycles.
	g.bodies[policiesURL] = `{"value":[{"id":"p1","displayName":"Windows Baseline","version":4}]}`
	if err := c.Collect(context.Background(), rec.Emitter()); err != nil {
		t.Fatalf("second Collect: %v", err)
	}
	second := rec.MetricPoints(policyVersionMetricName)
	if len(second) != 1 || second[0].Value != 4 {
		t.Fatalf("second poll version = %+v, want a single point at 4 (the bump)", second)
	}
}

func TestCollectNeverFetchesPerDeviceStatusChildren(t *testing.T) {
	bodies := merge(emptyEndpoints(), map[string]string{
		policiesURL:             `{"value":[{"id":"p1","displayName":"Windows Baseline","version":1}]}`,
		deviceOverviewURL("p1"): `{}`,
		userOverviewURL("p1"):   `{}`,
	})
	g := &fakeGraph{bodies: bodies}
	rec := telemetrytest.New()

	if err := New(g, nil).Collect(context.Background(), rec.Emitter()); err != nil {
		t.Fatalf("Collect: %v", err)
	}

	forbiddenSubstrings := []string{
		"/deviceStatuses", "/userStatuses", "/deviceComplianceSettingStates", "/deviceCompliancePolicyStates",
	}
	for _, url := range g.requestedURL {
		for _, sub := range forbiddenSubstrings {
			if strings.Contains(url, sub) {
				t.Errorf("requested %q, which touches the per-device status children this collector must never fetch", url)
			}
		}
	}
}

func TestCollectGracefullySkipsForbiddenDeviceStateSummary(t *testing.T) {
	bodies := emptyEndpoints()
	g := &fakeGraph{
		bodies: bodies,
		errs:   map[string]error{stateSummaryURL: forbidden403(stateSummaryURL)},
	}
	rec := telemetrytest.New()

	if err := New(g, nil).Collect(context.Background(), rec.Emitter()); err != nil {
		t.Fatalf("Collect should gracefully skip a 403, not surface an error: %v", err)
	}
	if pts := rec.MetricPoints(devicesMetricName); len(pts) != 0 {
		t.Errorf("expected no devices series when the state summary is forbidden, got %+v", pts)
	}
}

func TestCollectGracefullySkipsForbiddenPolicyList(t *testing.T) {
	bodies := emptyEndpoints()
	g := &fakeGraph{
		bodies: bodies,
		errs:   map[string]error{policiesURL: forbidden403(policiesURL)},
	}
	rec := telemetrytest.New()

	if err := New(g, nil).Collect(context.Background(), rec.Emitter()); err != nil {
		t.Fatalf("Collect should gracefully skip a 403, not surface an error: %v", err)
	}
	if pts := rec.MetricPoints(policyVersionMetricName); len(pts) != 0 {
		t.Errorf("expected no policy.version series when the policy list is forbidden, got %+v", pts)
	}
}

func TestCollectIsResilientToOnePolicyOverviewFailure(t *testing.T) {
	bodies := merge(emptyEndpoints(), map[string]string{
		policiesURL: `{"value":[
			{"id":"p1","displayName":"Windows Baseline","version":1},
			{"id":"p2","displayName":"iOS Baseline","version":1}
		]}`,
		deviceOverviewURL("p2"): `{"successCount":9}`,
		userOverviewURL("p1"):   `{}`,
		userOverviewURL("p2"):   `{}`,
	})
	g := &fakeGraph{
		bodies: bodies,
		errs:   map[string]error{deviceOverviewURL("p1"): errors.New("throttled")},
	}
	rec := telemetrytest.New()

	err := New(g, nil).Collect(context.Background(), rec.Emitter())
	if err == nil {
		t.Fatal("expected Collect to surface the per-policy overview failure as an error")
	}

	pts := rec.MetricPoints(policyDevicesMetricName)
	got := map[[2]string]float64{}
	for _, p := range pts {
		got[[2]string{p.Attrs["policy_name"], p.Attrs["state"]}] = p.Value
	}
	if _, ok := got[[2]string{"Windows Baseline", "success"}]; ok {
		t.Error("Windows Baseline should have no policy.devices series since its overview fetch failed")
	}
	if got[[2]string{"iOS Baseline", "success"}] != 9 {
		t.Errorf("iOS Baseline success = %v, want 9 (unaffected by the other policy's failure)", got[[2]string{"iOS Baseline", "success"}])
	}
	// Every other metric must still emit despite the one failure.
	if len(rec.MetricPoints(devicesMetricName)) == 0 {
		t.Error("devices series should be unaffected by the policy-overview failure")
	}
}

func TestNoPerDeviceOrPerUserAttribute(t *testing.T) {
	bodies := merge(emptyEndpoints(), map[string]string{
		policiesURL:             `{"value":[{"id":"p1","displayName":"Windows Baseline","version":1}]}`,
		deviceOverviewURL("p1"): `{"successCount":1}`,
		userOverviewURL("p1"):   `{"successCount":1}`,
		settingSummariesURL:     `{"value":[{"settingName":"Require BitLocker","platformType":"windows10","compliantDeviceCount":1}]}`,
	})
	g := &fakeGraph{bodies: bodies}
	rec := telemetrytest.New()

	if err := New(g, nil).Collect(context.Background(), rec.Emitter()); err != nil {
		t.Fatalf("Collect: %v", err)
	}

	forbiddenAttrs := []string{"id", "deviceId", "device_id", "userId", "user_id", "upn"}
	for _, metric := range []string{devicesMetricName, policyDevicesMetricName, policyUsersMetricName, settingDevicesMetricName, policyVersionMetricName} {
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
	if c.Name() != "intune.compliance" {
		t.Errorf("Name = %q, want intune.compliance", c.Name())
	}
	if c.DefaultInterval() <= 0 {
		t.Errorf("DefaultInterval = %v, want positive", c.DefaultInterval())
	}
	perms := c.RequiredPermissions()
	if len(perms) != 1 || perms[0] != "DeviceManagementConfiguration.Read.All" {
		t.Errorf("RequiredPermissions = %v, want [DeviceManagementConfiguration.Read.All]", perms)
	}
}
