package mobileapps

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/rknightion/graph2otel/internal/collectors"
	"github.com/rknightion/graph2otel/internal/telemetrytest"
)

// fakeGraph maps request URLs to canned bodies (or errors). Every fixture
// here is a single page, since GetAllValues' @odata.nextLink following is
// exercised by internal/collectors' own tests, not re-tested per collector.
type fakeGraph struct {
	bodies    map[string]string
	errs      map[string]error
	requested []string
}

func (f *fakeGraph) RawGet(ctx context.Context, url string) ([]byte, error) {
	return f.RawGetWithHeaders(ctx, url, nil)
}

func (f *fakeGraph) RawGetWithHeaders(_ context.Context, url string, _ map[string]string) ([]byte, error) {
	f.requested = append(f.requested, url)
	if err, ok := f.errs[url]; ok {
		return nil, err
	}
	return []byte(f.bodies[url]), nil
}

var _ collectors.GraphClient = (*fakeGraph)(nil)

const (
	base             = "https://graph.microsoft.com/v1.0"
	mobileAppsURL    = base + "/deviceAppManagement/mobileApps"
	mobileConfigsURL = base + "/deviceAppManagement/mobileAppConfigurations"
)

// Config ids come straight off the live capture (see liveConfigs), so the
// deviceStatusSummary sub-path URLs the collector builds match the fixture.
const (
	tailscaleCfgID = "02e7c6b0-6139-49ea-8c15-7425ca571370"
	defenderCfgID  = "f1358e77-31b3-4f76-940a-7bf5680a51c5"
)

func deviceStatusSummaryURL(id string) string {
	return base + "/deviceAppManagement/mobileAppConfigurations/" + id + "/deviceStatusSummary"
}

func page(itemsJSON string) string {
	return `{"value":[` + itemsJSON + `]}`
}

// liveApps is a VERBATIM slice of GET /v1.0/deviceAppManagement/mobileApps,
// read as graph2otel-poller against the m7kni tenant
// `[live-measured 2026-07-17, #165]`.
//
// The live collection carried 4 mobileApps; three whole elements are kept here
// preserving the @odata.type variety the wire actually had — which is NOT the
// win32/store mix the docs fixture invented. Every real app was an iosVppApp
// (this tenant only VPP-syncs App Store apps), and one element carried NO
// @odata.type field at all (a bare microsoft.graph.mobileApp projection). The
// 23andMe element was dropped as a whole element; the two iosVppApp elements
// and the no-@odata.type element are byte-verbatim.
//
// The no-@odata.type element is the load-bearing one: appTypeOf must map an
// absent @odata.type to "unknown", and only a real record proves the wire
// actually omits the field on some apps. The pagination envelope
// (@odata.context / @odata.count / @odata.nextLink) is dropped here and the
// elements re-wrapped via page(), matching every other single-page fixture in
// this package — GetAllValues' nextLink following is tested in the collectors
// package, not here.
const liveApps = `{
  "@odata.type": "#microsoft.graph.iosVppApp",
  "appStoreUrl": null,
  "applicableDeviceType": {
    "iPad": true,
    "iPhoneAndIPod": true
  },
  "bundleId": "com.khanov.BlockerX",
  "createdDateTime": "2025-09-25T17:11:18Z",
  "description": "1Blocker lets you block obtrusive ads, sneaky trackers, and annoying elements on sites. With 1Blocker, you\u2019re safe online and nothing will distract you from enjoying sites.\n\n1Blocker is very easy to use \u2014 just flip a couple of switches to start blocking ads and trackers. The app will automatically receive cloud updates to the built-in filters silently, so you don\u2019t need to do anything. It\u2019s as simple as setting and forgetting.\n\n1Blocker is a fully native app designed to extend Safari naturally. It\u2019s lightweight and doesn\u2019t drain your battery by taking up your device\u2019s resources.\n\nThe blocking itself is super fast because Safari does it itself. We only provide filters to Safari and don\u2019t modify webpages in any way. This vastly improves efficiency because Safari knows in advance what should be blocked. So, with 1Blocker, sites load on average 2-5x faster.\n\nIt\u2019s important to note that not all ads can be blocked though. Some sites use techniques that make it impossible for us to block their ads using currently available features for Safari content blockers.\n\nSECURE BY DESIGN\n\n1Blocker is secure and private. It doesn\u2019t have access to webpages and doesn\u2019t track you in any way.\n\nWe believe that privacy is not for sale. That's why we don't have an \"Acceptable Ads\" program. We stay independent, and the only way we make money is through direct sales of 1Blocker in the App Store to you.\n\nADVANCED CUSTOMIZATION\n\n1Blocker is a highly customizable content blocker, providing the possibility to create powerful custom rules. It allows you to create custom rules that block any URL by providing a regular expression or hide any element by CSS. It also lets you block cookies. (Available in Premium)\n\nAVAILABLE ON ALL DEVICES\n\n1Blocker is available for iPhone, iPad, and Mac. Your preferences and custom rules are always in sync through iCloud no matter which device you're using.\n\nFEATURED IN THE PRESS\n\n1Blocker has been featured in TechCrunch, Lifehacker, MacStories, Macworld, and many more.\n\nFEATURES AVAILABLE FOR FREE\n\n\u2022 The ability to enable one category (for example, Block Ads only)\n\u2022 Whitelisting sites right from the Safari extension\n\u2022 Whitelist synchronization between devices via iCloud\n\nFRIENDLY SUPPORT\n\nSend your feedback at @1BlockerApp on Twitter or via email. Your feedback is always very welcome and considered for the next release.\n\n\nWe have been making 1Blocker since 2015. We believe it\u2019s the best all-around package currently available in the App Store.\n\nPrivacy Policy: https://1blocker.com/privacy\nTerms of Use: https://1blocker.com/terms",
  "developer": null,
  "displayName": "1Blocker - Ad Blocker",
  "id": "5d694e0b-fcb3-4e0c-8b90-0efd0b68161e",
  "informationUrl": "https://apps.apple.com/gb/app/1blocker-ad-blocker/id1365531024",
  "isFeatured": false,
  "largeIcon": null,
  "lastModifiedDateTime": "2025-09-25T17:11:18Z",
  "licensingType": {
    "supportsDeviceLicensing": true,
    "supportsUserLicensing": true
  },
  "notes": null,
  "owner": null,
  "privacyInformationUrl": null,
  "publisher": "1Blocker LLC",
  "publishingState": "published",
  "releaseDateTime": "0001-01-01T00:00:00Z",
  "totalLicenseCount": 100,
  "usedLicenseCount": 2,
  "vppTokenAccountType": "business",
  "vppTokenAppleId": "rob@m7kni.io",
  "vppTokenOrganizationName": "FLICKTO LTD"
},
{
  "createdDateTime": "2025-09-25T17:11:18Z",
  "description": "1Blocker lets you block obtrusive ads, sneaky trackers, and annoying elements on sites. With 1Blocker, you\u2019re safe online and nothing will distract you from enjoying sites.\n\n1Blocker is very easy to use \u2014 just flip a couple of switches to start blocking ads and trackers. The app will automatically receive cloud updates to the built-in filters silently, so you don\u2019t need to do anything. It\u2019s as simple as setting and forgetting.\n\n1Blocker is a fully native app designed to extend Safari naturally. It\u2019s lightweight and doesn\u2019t drain your battery by taking up your device\u2019s resources.\n\nThe blocking itself is super fast because Safari does it itself. We only provide filters to Safari and don\u2019t modify webpages in any way. This vastly improves efficiency because Safari knows in advance what should be blocked. So, with 1Blocker, sites load on average 2-5x faster.\n\nIt\u2019s important to note that not all ads can be blocked though. Some sites use techniques that make it impossible for us to block their ads using currently available features for Safari content blockers.\n\nSECURE BY DESIGN\n\n1Blocker is secure and private. It doesn\u2019t have access to webpages and doesn\u2019t track you in any way.\n\nWe believe that privacy is not for sale. That's why we don't have an \"Acceptable Ads\" program. We stay independent, and the only way we make money is through direct sales of 1Blocker in the App Store to you.\n\nADVANCED CUSTOMIZATION\n\n1Blocker is a highly customizable content blocker, providing the possibility to create powerful custom rules. It allows you to create custom rules that block any URL by providing a regular expression or hide any element by CSS. It also lets you block cookies. (Available in Premium)\n\nAVAILABLE ON ALL DEVICES\n\n1Blocker is available for iPhone, iPad, and Mac. Your preferences and custom rules are always in sync through iCloud no matter which device you're using.\n\nFEATURED IN THE PRESS\n\n1Blocker has been featured in TechCrunch, Lifehacker, MacStories, Macworld, and many more.\n\nFEATURES AVAILABLE FOR FREE\n\n\u2022 The ability to enable one category (for example, Block Trackers only)\n\u2022 Whitelisting sites right from the Safari extension\n\u2022 Whitelist synchronization between devices via iCloud\n\u2022 The possibility to see blocked resources on a site\n\nFRIENDLY SUPPORT\n\nSend your feedback at @1BlockerApp on Twitter or via email. Your feedback is always very welcome and considered for the next release.\n\n\nWe have been making 1Blocker since 2015. We\u2019ve learned a lot from our customers and improved the app consistently for 5 years to suit all your needs. We believe it\u2019s the best all-around package currently available in the App Store.\n\nPrivacy Policy: https://1blocker.com/privacy\nTerms of Use: https://1blocker.com/terms",
  "developer": null,
  "displayName": "1Blocker - Ad Blocker",
  "id": "b37239bb-9879-49fc-b11b-c93c007f4b5a",
  "informationUrl": "https://apps.apple.com/gb/app/1blocker-ad-blocker/id1365531024",
  "isFeatured": false,
  "largeIcon": null,
  "lastModifiedDateTime": "2025-09-25T17:11:18Z",
  "notes": null,
  "owner": null,
  "privacyInformationUrl": null,
  "publisher": "1Blocker LLC",
  "publishingState": "published"
},
{
  "@odata.type": "#microsoft.graph.iosVppApp",
  "appStoreUrl": null,
  "applicableDeviceType": {
    "iPad": true,
    "iPhoneAndIPod": true
  },
  "bundleId": "com.3cx.3cxphone14",
  "createdDateTime": "2025-11-22T12:58:20Z",
  "description": "Stay connected and make remote work easier with 3CX. This app allows you to use your office extension from anywhere and not only for calls. Schedule conferences, chat with your colleagues and video call from your iOS device. \n\nGetting Started:\n\n1. Install the app.\n2. Open it, read and accept the license agreement and authorize the permissions the app needs (camera, microphone).\n3. Open your web client or desktop app and click on the QR code in the top right corner. Details on how to access your web client are in your 3CX email sent by your administrator.\n4. Open your camera on your iOS device and scan the QR code shown on your screen.\n5. Your extension is configured and you\u2019re now \u201cReady for calls\u201d!\n\nImportant: This app is only for use with 3CX V20 and is not a standalone app. \n\nMore information: https://www.3cx.com/user-manual/installation-iphone/",
  "developer": null,
  "displayName": "3CX",
  "id": "24649060-471a-4f63-a054-6114fa42f48e",
  "informationUrl": "https://apps.apple.com/gb/app/3cx/id992045982",
  "isFeatured": false,
  "largeIcon": null,
  "lastModifiedDateTime": "2025-11-22T12:58:20Z",
  "licensingType": {
    "supportsDeviceLicensing": true,
    "supportsUserLicensing": true
  },
  "notes": null,
  "owner": null,
  "privacyInformationUrl": null,
  "publisher": "3CX",
  "publishingState": "published",
  "releaseDateTime": "0001-01-01T00:00:00Z",
  "totalLicenseCount": 10,
  "usedLicenseCount": 0,
  "vppTokenAccountType": "business",
  "vppTokenAppleId": "rob@m7kni.io",
  "vppTokenOrganizationName": "FLICKTO LTD"
}`

// liveConfigs is a VERBATIM slice of
// GET /v1.0/deviceAppManagement/mobileAppConfigurations, same tenant and read
// `[live-measured 2026-07-17, #165]`.
//
// The live collection carried 3 iosMobileAppConfiguration policies; the
// "iOS Chrome" element was dropped as a whole element (it carried a live
// Chrome Cloud-Management enrollment token in settings[].appConfigKeyValue,
// which has no place in a committed fixture). The two kept elements are
// byte-verbatim, settings and encodedSettingXml included, so the collector is
// exercised against the real resource shape even though it reads only id and
// displayName off it.
const liveConfigs = `{
  "@odata.type": "#microsoft.graph.iosMobileAppConfiguration",
  "createdDateTime": "2026-06-02T17:10:28.6312173Z",
  "description": "Tailscale system policies for iOS (posture enforced). Applies via managed VPP app io.tailscale.ipn.ios.",
  "displayName": "iOS Tailscale System Policy",
  "encodedSettingXml": "PGRpY3Q+Cgk8a2V5PkFsbG93SW5jb21pbmdDb25uZWN0aW9uczwva2V5PgoJPHN0cmluZz51c2VyLWRlY2lkZXM8L3N0cmluZz4KCTxrZXk+RGV2aWNlU2VyaWFsTnVtYmVyPC9rZXk+Cgk8c3RyaW5nPnt7c2VyaWFsbnVtYmVyfX08L3N0cmluZz4KCTxrZXk+RXhpdE5vZGVBbGxvd0xBTkFjY2Vzczwva2V5PgoJPHN0cmluZz51c2VyLWRlY2lkZXM8L3N0cmluZz4KCTxrZXk+RXhpdE5vZGVzUGlja2VyPC9rZXk+Cgk8c3RyaW5nPnNob3c8L3N0cmluZz4KCTxrZXk+TWFuYWdlZEJ5T3JnYW5pemF0aW9uTmFtZTwva2V5PgoJPHN0cmluZz5tN2tuaTwvc3RyaW5nPgoJPGtleT5Qb3N0dXJlQ2hlY2tpbmc8L2tleT4KCTxzdHJpbmc+YWx3YXlzPC9zdHJpbmc+Cgk8a2V5PlRhaWxuZXQ8L2tleT4KCTxzdHJpbmc+bTdrbmkuaW88L3N0cmluZz4KCTxrZXk+VXBkYXRlTWVudTwva2V5PgoJPHN0cmluZz5zaG93PC9zdHJpbmc+Cgk8a2V5PlVzZVRhaWxzY2FsZUROU1NldHRpbmdzPC9rZXk+Cgk8c3RyaW5nPnVzZXItZGVjaWRlczwvc3RyaW5nPgoJPGtleT5Vc2VUYWlsc2NhbGVTdWJuZXRzPC9rZXk+Cgk8c3RyaW5nPnVzZXItZGVjaWRlczwvc3RyaW5nPgo8L2RpY3Q+",
  "id": "02e7c6b0-6139-49ea-8c15-7425ca571370",
  "lastModifiedDateTime": "2026-06-02T17:10:28.6312173Z",
  "settings": [],
  "targetedMobileApps": [
    "7112bf58-1f9a-4eea-8589-283d5bf52827"
  ],
  "version": 1
},
{
  "@odata.type": "#microsoft.graph.iosMobileAppConfiguration",
  "createdDateTime": "2025-09-25T18:08:47.1965944Z",
  "description": "",
  "displayName": "iOS Defender",
  "encodedSettingXml": null,
  "id": "f1358e77-31b3-4f76-940a-7bf5680a51c5",
  "lastModifiedDateTime": "2025-09-29T12:46:09.1014741Z",
  "settings": [
    {
      "appConfigKey": "issupervised",
      "appConfigKeyType": "stringType",
      "appConfigKeyValue": "{{issupervised}}"
    },
    {
      "appConfigKey": "DefenderDeviceTag",
      "appConfigKeyType": "stringType",
      "appConfigKeyValue": "ios"
    },
    {
      "appConfigKey": "DisableSignOut",
      "appConfigKeyType": "stringType",
      "appConfigKeyValue": "true"
    },
    {
      "appConfigKey": "DefenderFeedbackData",
      "appConfigKeyType": "booleanType",
      "appConfigKeyValue": "true"
    },
    {
      "appConfigKey": "DefenderOpenNetworkDetection",
      "appConfigKeyType": "integerType",
      "appConfigKeyValue": "1"
    },
    {
      "appConfigKey": "DefenderEndUserTrustFlowEnable",
      "appConfigKeyType": "stringType",
      "appConfigKeyValue": "true"
    },
    {
      "appConfigKey": "DefenderNetworkProtectionPrivacy",
      "appConfigKeyType": "stringType",
      "appConfigKeyValue": "false"
    },
    {
      "appConfigKey": "DefenderExcludeURLInReport",
      "appConfigKeyType": "stringType",
      "appConfigKeyValue": "false"
    },
    {
      "appConfigKey": "WebProtection",
      "appConfigKeyType": "stringType",
      "appConfigKeyValue": "false"
    },
    {
      "appConfigKey": "DefenderNetworkProtectionEnable",
      "appConfigKeyType": "stringType",
      "appConfigKeyValue": "true"
    }
  ],
  "targetedMobileApps": [
    "56cf47d5-34f7-4d44-a145-44bf2207462c"
  ],
  "version": 4
}`

// realTailscaleDeviceStatusSummary is the VERBATIM
// GET .../mobileAppConfigurations/{id}/deviceStatusSummary singleton for the
// iOS Tailscale policy `[live-measured 2026-07-17, #165]`.
//
// It settles the docs-only envelope question the collector was written to
// hedge: the real singleton GET returns a BARE object, NOT the {"value":{...}}
// envelope Microsoft's worked example showed. deviceStatusSummaryResponse's
// permissive decode still handles it (Value is nil -> the bare fields win),
// but the enveloped branch is now known to be a shape the v1.0 wire does not
// actually produce here — kept only as belt-and-braces, and covered below by a
// clearly-synthetic fixture rather than by anything ever seen live.
const realTailscaleDeviceStatusSummary = `{
  "@odata.context": "https://graph.microsoft.com/v1.0/$metadata#deviceAppManagement/mobileAppConfigurations('02e7c6b0-6139-49ea-8c15-7425ca571370')/deviceStatusSummary/$entity",
  "configurationVersion": 1,
  "errorCount": 0,
  "failedCount": 0,
  "id": "e933bb26-3dff-49f0-a41a-bd722a92f1fb_02e7c6b0-6139-49ea-8c15-7425ca571370",
  "lastUpdateDateTime": "2026-07-14T15:30:41.4166667Z",
  "notApplicableCount": 2,
  "pendingCount": 0,
  "successCount": 2
}`

// syntheticDefenderDeviceStatusSummary is SYNTHETIC (docs-derived), not a live
// capture: no enveloped deviceStatusSummary has ever been observed on the wire
// (see realTailscaleDeviceStatusSummary). It exists solely to keep the
// permissive decoder's {"value":{...}} branch under test, since dropping that
// coverage would let the branch rot unnoticed.
const syntheticDefenderDeviceStatusSummary = `{"value":{"pendingCount":1,"notApplicableCount":0,"successCount":5,"errorCount":0,"failedCount":0}}`

func fullFixture() map[string]string {
	return map[string]string{
		mobileAppsURL:                          page(liveApps),
		mobileConfigsURL:                       page(liveConfigs),
		deviceStatusSummaryURL(tailscaleCfgID): realTailscaleDeviceStatusSummary,
		deviceStatusSummaryURL(defenderCfgID):  syntheticDefenderDeviceStatusSummary,
	}
}

func TestCollectEmitsMobileAppsCountByTypeAndState(t *testing.T) {
	g := &fakeGraph{bodies: fullFixture()}
	rec := telemetrytest.New()

	if err := New(g, nil).Collect(context.Background(), rec.Emitter()); err != nil {
		t.Fatalf("Collect: %v", err)
	}

	pts := rec.MetricPoints(appsMetricName)
	type key struct{ appType, state string }
	got := map[key]float64{}
	for _, p := range pts {
		got[key{p.Attrs["app_type"], p.Attrs["publishing_state"]}] = p.Value
	}
	want := map[key]float64{
		// Two iosVppApp elements aggregate into a single count-2 series; the
		// third element has no @odata.type on the wire, so appTypeOf buckets it
		// to "unknown".
		{"iosVppApp", "published"}: 2,
		{"unknown", "published"}:   1,
	}
	if len(got) != len(want) {
		t.Fatalf("got %d series, want %d: %v", len(got), len(want), got)
	}
	for k, v := range want {
		if got[k] != v {
			t.Errorf("series app_type=%s publishing_state=%s = %v, want %v", k.appType, k.state, got[k], v)
		}
	}
}

func TestCollectEmitsConfigStatusFromDeviceStatusSummary(t *testing.T) {
	g := &fakeGraph{bodies: fullFixture()}
	rec := telemetrytest.New()

	if err := New(g, nil).Collect(context.Background(), rec.Emitter()); err != nil {
		t.Fatalf("Collect: %v", err)
	}

	pts := rec.MetricPoints(configStatusMetricName)
	type key struct{ policy, status string }
	got := map[key]float64{}
	for _, p := range pts {
		got[key{p.Attrs["policy_name"], p.Attrs["status"]}] = p.Value
	}
	want := map[key]float64{
		// iOS Tailscale: the real bare-object singleton (2 not-applicable, 2
		// success, everything else 0).
		{"iOS Tailscale System Policy", "pending"}:        0,
		{"iOS Tailscale System Policy", "not_applicable"}: 2,
		{"iOS Tailscale System Policy", "success"}:        2,
		{"iOS Tailscale System Policy", "error"}:          0,
		{"iOS Tailscale System Policy", "failed"}:         0,
		// iOS Defender: the synthetic {"value":{...}} envelope fixture, proving
		// the permissive decoder still reads the enveloped shape.
		{"iOS Defender", "pending"}:        1,
		{"iOS Defender", "not_applicable"}: 0,
		{"iOS Defender", "success"}:        5,
		{"iOS Defender", "error"}:          0,
		{"iOS Defender", "failed"}:         0,
	}
	if len(got) != len(want) {
		t.Fatalf("got %d series, want %d: %v", len(got), len(want), got)
	}
	for k, v := range want {
		if got[k] != v {
			t.Errorf("series policy=%s status=%s = %v, want %v", k.policy, k.status, got[k], v)
		}
	}
}

func TestCollectIsResilientToPerPolicyDeviceStatusSummaryError(t *testing.T) {
	g := &fakeGraph{
		bodies: fullFixture(),
		errs:   map[string]error{deviceStatusSummaryURL(defenderCfgID): errors.New("throttled")},
	}
	rec := telemetrytest.New()

	err := New(g, nil).Collect(context.Background(), rec.Emitter())
	if err == nil {
		t.Fatal("expected Collect to surface the per-policy deviceStatusSummary failure as an error")
	}

	pts := rec.MetricPoints(configStatusMetricName)
	for _, p := range pts {
		if p.Attrs["policy_name"] == "iOS Defender" {
			t.Errorf("iOS Defender series should be absent when its deviceStatusSummary fetch failed: %v", p)
		}
	}
	// The Tailscale policy and the mobile_apps.count metric must still emit
	// despite the Defender policy failing.
	var sawTailscale bool
	for _, p := range pts {
		if p.Attrs["policy_name"] == "iOS Tailscale System Policy" {
			sawTailscale = true
		}
	}
	if !sawTailscale {
		t.Error("iOS Tailscale series missing despite iOS Defender being the only failure")
	}
	if len(rec.MetricPoints(appsMetricName)) == 0 {
		t.Error("mobile_apps.count should still emit despite the config-status failure")
	}
}

func TestCollectSurfacesMobileAppsListFailure(t *testing.T) {
	g := &fakeGraph{
		bodies: fullFixture(),
		errs:   map[string]error{mobileAppsURL: errors.New("throttled")},
	}
	rec := telemetrytest.New()

	err := New(g, nil).Collect(context.Background(), rec.Emitter())
	if err == nil {
		t.Fatal("expected Collect to surface the mobileApps list failure as an error")
	}
	if pts := rec.MetricPoints(appsMetricName); len(pts) != 0 {
		t.Errorf("expected no mobile_apps.count series when the list fetch failed, got %v", pts)
	}
	// Config status is independent of the apps list and must still emit.
	if len(rec.MetricPoints(configStatusMetricName)) == 0 {
		t.Error("mobile_app_config.status should still emit despite the apps-list failure")
	}
}

func TestCollectSkipsGracefullyOn403(t *testing.T) {
	g := &fakeGraph{
		bodies: fullFixture(),
		errs: map[string]error{
			mobileAppsURL:    errors.New("graphclient: GET x: status 403: Forbidden"),
			mobileConfigsURL: errors.New("graphclient: GET x: status 403: Forbidden"),
		},
	}
	rec := telemetrytest.New()

	if err := New(g, nil).Collect(context.Background(), rec.Emitter()); err != nil {
		t.Fatalf("expected a 403 on both endpoints to be skipped, not surfaced as an error: %v", err)
	}
	if pts := rec.MetricPoints(appsMetricName); len(pts) != 0 {
		t.Errorf("expected no mobile_apps.count series on 403, got %v", pts)
	}
	if pts := rec.MetricPoints(configStatusMetricName); len(pts) != 0 {
		t.Errorf("expected no mobile_app_config.status series on 403, got %v", pts)
	}
}

func TestNoPerDeviceInstallStatusCalls(t *testing.T) {
	// Guards the M5-deferred scope: this collector must never call the
	// per-device install-status nav-props (deviceStatuses/userStatuses on
	// mobileApps/mobileAppConfigurations, or any per-app assignment install
	// detail) - those are deferred to the M5 export-job subsystem.
	g := &fakeGraph{bodies: fullFixture()}
	rec := telemetrytest.New()

	if err := New(g, nil).Collect(context.Background(), rec.Emitter()); err != nil {
		t.Fatalf("Collect: %v", err)
	}

	forbidden := []string{"deviceStatuses", "userStatuses", "installStates", "assignments"}
	for _, url := range g.requested {
		for _, f := range forbidden {
			if strings.Contains(url, f) {
				t.Errorf("collector requested %q, which touches the deferred per-device install-status surface (%s)", url, f)
			}
		}
	}
}

func TestNameIntervalAndPermissions(t *testing.T) {
	c := New(&fakeGraph{}, nil)
	if c.Name() != "intune.mobile_apps" {
		t.Errorf("Name = %q, want intune.mobile_apps", c.Name())
	}
	if c.DefaultInterval() <= 0 {
		t.Error("DefaultInterval must be positive")
	}
	perms := c.RequiredPermissions()
	if len(perms) != 1 || perms[0] != "DeviceManagementApps.Read.All" {
		t.Errorf("RequiredPermissions = %v, want [DeviceManagementApps.Read.All]", perms)
	}
}

// TestNoUnboundedLabels guards the cardinality rule: no series may carry a
// per-app or per-device identifier as an attribute — only the bounded
// app_type/publishing_state/policy_name/status dimensions.
func TestNoUnboundedLabels(t *testing.T) {
	g := &fakeGraph{bodies: fullFixture()}
	rec := telemetrytest.New()

	if err := New(g, nil).Collect(context.Background(), rec.Emitter()); err != nil {
		t.Fatalf("Collect: %v", err)
	}

	allowedAppAttrs := map[string]bool{"app_type": true, "publishing_state": true}
	for _, p := range rec.MetricPoints(appsMetricName) {
		for k := range p.Attrs {
			if !allowedAppAttrs[k] {
				t.Errorf("mobile_apps.count series has unexpected attribute %q: %v", k, p.Attrs)
			}
		}
	}

	allowedConfigAttrs := map[string]bool{"policy_name": true, "status": true}
	for _, p := range rec.MetricPoints(configStatusMetricName) {
		for k := range p.Attrs {
			if !allowedConfigAttrs[k] {
				t.Errorf("mobile_app_config.status series has unexpected attribute %q: %v", k, p.Attrs)
			}
		}
	}
}
