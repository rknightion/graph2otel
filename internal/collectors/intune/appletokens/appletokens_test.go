package appletokens

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/rknightion/graph2otel/internal/collectors"
	"github.com/rknightion/graph2otel/internal/telemetrytest"
)

// fakeGraph maps request URLs to canned bodies (or errors), mirroring the
// recommendations reference beta collector's test fake.
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
	apnsURL = "https://graph.microsoft.com/v1.0/deviceManagement/applePushNotificationCertificate"
	vppURL  = "https://graph.microsoft.com/v1.0/deviceAppManagement/vppTokens"
	depURL  = "https://graph.microsoft.com/beta/deviceManagement/depOnboardingSettings"
)

// fixedNow is the deterministic clock every test computes expiry offsets
// against, mirroring the devices reference collector's fixedClock. It predates
// the live captures below so their days-until-expiry come out positive.
var fixedNow = time.Date(2026, 7, 15, 12, 0, 0, 0, time.UTC)

func fixedClock() time.Time { return fixedNow }

// Verbatim GET captures read as graph2otel-poller against the m7kni tenant on
// 2026-07-17 `[live-measured 2026-07-17, #165]`, each from the exact endpoint
// this collector polls. Trimmed of nothing (each is a single-element source on
// this tenant), so they stay a faithful record of what the endpoints return.
//
//   - liveAPNSBody: GET /v1.0/deviceManagement/applePushNotificationCertificate,
//     the tenant-wide singleton. Note `certificateUploadStatus` is null on the
//     wire even though the certificate is configured (expirationDateTime,
//     certificateSerialNumber and topicIdentifier are all present) — so the
//     emitted state bucket resolves to "unknown", not the docs-implied "Valid".
//   - liveVPPBody: GET /v1.0/deviceAppManagement/vppTokens (1 token). The
//     appleId is a corporate email, kept verbatim per the #165 PII rule.
//   - liveDEPBody: GET /beta/deviceManagement/depOnboardingSettings (1 setting;
//     beta — no v1.0 equivalent exists). The appleIdentifier corporate email is
//     kept verbatim.
const (
	liveAPNSBody = `{
  "@odata.context": "https://graph.microsoft.com/v1.0/$metadata#deviceManagement/applePushNotificationCertificate/$entity",
  "appleIdentifier": "rob@rob-knight.com",
  "certificate": null,
  "certificateSerialNumber": "6DBBD018B25C7F76",
  "certificateUploadFailureReason": null,
  "certificateUploadStatus": null,
  "expirationDateTime": "2026-09-11T14:39:25Z",
  "id": "daa5f155-cc30-43d2-80d7-a38731207a3b",
  "lastModifiedDateTime": "2026-07-17T15:30:26Z",
  "topicIdentifier": "com.apple.mgmt.External.4d2db6f6-bec4-48d8-8f23-8e902e1276fb"
}`

	liveVPPBody = `{
  "@odata.context": "https://graph.microsoft.com/v1.0/$metadata#deviceAppManagement/vppTokens",
  "value": [
    {
      "appleId": "rob@m7kni.io",
      "automaticallyUpdateApps": true,
      "countryOrRegion": "gb",
      "expirationDateTime": "2026-09-25T17:09:22Z",
      "id": "bfc6fbf0-788f-47ba-86c2-0f784b986ef1",
      "lastModifiedDateTime": "2026-07-17T14:50:53.5002993Z",
      "lastSyncDateTime": "2026-07-17T14:50:53.4972449Z",
      "lastSyncStatus": "completed",
      "organizationName": "FLICKTO LTD",
      "state": "valid",
      "token": null,
      "vppTokenAccountType": "business"
    }
  ]
}`

	liveDEPBody = `{
  "@odata.context": "https://graph.microsoft.com/beta/$metadata#deviceManagement/depOnboardingSettings",
  "@odata.count": 1,
  "value": [
    {
      "appleIdentifier": "rob@rob-knight.co.uk",
      "dataSharingConsentGranted": true,
      "id": "e19cd98d-79c5-4be7-8bfa-93bd298ea801",
      "lastModifiedDateTime": "2025-09-19T16:50:51.5063355Z",
      "lastSuccessfulSyncDateTime": "2026-07-17T11:44:03.2967172Z",
      "lastSyncErrorCode": 0,
      "lastSyncTriggeredDateTime": "2026-07-17T11:44:00.3449091Z",
      "roleScopeTagIds": [
        "0"
      ],
      "shareTokenWithSchoolDataSyncService": false,
      "syncedDeviceCount": 7,
      "tokenExpirationDateTime": "2026-09-19T16:49:50Z",
      "tokenName": "intune",
      "tokenType": "dep"
    }
  ]
}`
)

// Absolute expiry timestamps on the live captures above, used to compute the
// expected days-until-expiry against fixedNow exactly as the mapper does.
const (
	liveAPNSExpiry = "2026-09-11T14:39:25Z"
	liveVPPExpiry  = "2026-09-25T17:09:22Z"
	liveDEPExpiry  = "2026-09-19T16:49:50Z"
)

// liveDays computes days-until-expiry the same way daysUntil does, so the
// assertions track the live timestamps rather than hard-coded offsets.
func liveDays(t *testing.T, expiry string) float64 {
	t.Helper()
	end, err := time.Parse(time.RFC3339, expiry)
	if err != nil {
		t.Fatalf("parse live expiry %q: %v", expiry, err)
	}
	return end.Sub(fixedNow).Hours() / 24
}

// fullFixture wires the three verbatim live captures to the URLs this collector
// polls: one APNS certificate, one VPP token, and one DEP onboarding setting.
func fullFixture() map[string]string {
	return map[string]string{
		apnsURL: liveAPNSBody,
		vppURL:  liveVPPBody,
		depURL:  liveDEPBody,
	}
}

func newTestCollector(g collectors.GraphClient) *Collector {
	c := New(g, nil)
	c.now = fixedClock
	return c
}

func TestCollectEmitsDaysUntilExpiryForAllThreeTypes(t *testing.T) {
	g := &fakeGraph{bodies: fullFixture()}
	rec := telemetrytest.New()

	if err := newTestCollector(g).Collect(context.Background(), rec.Emitter()); err != nil {
		t.Fatalf("Collect: %v", err)
	}

	type key struct{ typ, tokenName string }
	got := map[key]struct {
		days  float64
		state string
	}{}
	for _, p := range rec.MetricPoints(daysUntilExpiryMetric) {
		k := key{p.Attrs["type"], p.Attrs["token_name"]}
		got[k] = struct {
			days  float64
			state string
		}{p.Value, p.Attrs["state"]}
	}

	// The live APNS certificate ships certificateUploadStatus:null, so its
	// state bucket is "unknown" — a configured, non-expired cert whose upload
	// status the tenant simply does not report, not a "Valid" one.
	cases := []struct {
		k         key
		wantDays  float64
		wantState string
	}{
		{key{"apns", ""}, liveDays(t, liveAPNSExpiry), "unknown"},
		{key{"vpp", "FLICKTO LTD"}, liveDays(t, liveVPPExpiry), "valid"},
		{key{"dep", "intune"}, liveDays(t, liveDEPExpiry), "ok"},
	}
	for _, c := range cases {
		v, ok := got[c.k]
		if !ok {
			t.Errorf("missing point for %+v; got %+v", c.k, got)
			continue
		}
		if v.days != c.wantDays {
			t.Errorf("%+v: days = %v, want %v", c.k, v.days, c.wantDays)
		}
		if v.state != c.wantState {
			t.Errorf("%+v: state = %q, want %q", c.k, v.state, c.wantState)
		}
	}
}

func TestCollectEmitsDEPSyncedDeviceCount(t *testing.T) {
	g := &fakeGraph{bodies: fullFixture()}
	rec := telemetrytest.New()

	if err := newTestCollector(g).Collect(context.Background(), rec.Emitter()); err != nil {
		t.Fatalf("Collect: %v", err)
	}

	points := rec.MetricPoints(syncedDeviceCountMetric)
	if len(points) != 1 {
		t.Fatalf("synced_device_count points = %d, want 1: %+v", len(points), points)
	}
	if points[0].Value != 7 {
		t.Errorf("synced_device_count = %v, want 7", points[0].Value)
	}
	if points[0].Attrs["token_name"] != "intune" {
		t.Errorf("token_name = %q, want %q", points[0].Attrs["token_name"], "intune")
	}
}

func TestCollectDEPBetaFailureDoesNotDropAPNSOrVPP(t *testing.T) {
	bodies := fullFixture()
	delete(bodies, depURL)
	g := &fakeGraph{
		bodies: bodies,
		errs: map[string]error{
			depURL: errors.New("graphclient: GET " + depURL + ": status 500: server error"),
		},
	}
	rec := telemetrytest.New()

	err := newTestCollector(g).Collect(context.Background(), rec.Emitter())
	if err == nil {
		t.Error("a DEP 500 should surface as a Collect error")
	}

	var types []string
	for _, p := range rec.MetricPoints(daysUntilExpiryMetric) {
		types = append(types, p.Attrs["type"])
	}
	if !containsAll(types, "apns", "vpp") {
		t.Errorf("apns/vpp gauges must survive a DEP failure, got types %v", types)
	}
	for _, p := range rec.MetricPoints(daysUntilExpiryMetric) {
		if p.Attrs["type"] == "dep" {
			t.Errorf("dep point should not be present after a DEP fetch failure: %+v", p)
		}
	}
}

func TestCollectGracefulOn403ForOneSource(t *testing.T) {
	bodies := fullFixture()
	delete(bodies, apnsURL)
	g := &fakeGraph{
		bodies: bodies,
		errs: map[string]error{
			apnsURL: errors.New("graphclient: GET " + apnsURL + ": status 404: {\"error\":{\"code\":\"NotFound\"}}"),
		},
	}
	rec := telemetrytest.New()

	// A 404 (no APNS cert configured on this tenant) must be skipped-and-logged,
	// not surfaced as a collector error, and must not prevent vpp/dep from
	// emitting.
	if err := newTestCollector(g).Collect(context.Background(), rec.Emitter()); err != nil {
		t.Errorf("Collect should swallow a 404 as skip-and-log, got: %v", err)
	}

	for _, p := range rec.MetricPoints(daysUntilExpiryMetric) {
		if p.Attrs["type"] == "apns" {
			t.Errorf("apns point should be absent after a 404, got %+v", p)
		}
	}
	if len(rec.MetricPoints(syncedDeviceCountMetric)) != 1 {
		t.Error("dep synced_device_count should still emit after an unrelated apns 404")
	}
}

func TestCollectSkipsMissingExpirationWithoutError(t *testing.T) {
	g := &fakeGraph{bodies: map[string]string{
		apnsURL: `{"certificateUploadStatus":"Valid"}`, // no expirationDateTime
		vppURL:  `{"value":[]}`,
		depURL:  `{"value":[]}`,
	}}
	rec := telemetrytest.New()

	if err := newTestCollector(g).Collect(context.Background(), rec.Emitter()); err != nil {
		t.Fatalf("Collect: %v", err)
	}
	if points := rec.MetricPoints(daysUntilExpiryMetric); len(points) != 0 {
		t.Errorf("expected no points for a token with no expirationDateTime, got %+v", points)
	}
}

func TestNameIntervalAndPermissions(t *testing.T) {
	c := New(&fakeGraph{}, nil)
	if got := c.Name(); got != "intune.apple_tokens" {
		t.Errorf("Name = %q, want intune.apple_tokens", got)
	}
	if c.DefaultInterval() <= 0 {
		t.Error("DefaultInterval must be positive")
	}
	got := c.RequiredPermissions()
	if !containsAll(got, "DeviceManagementServiceConfig.Read.All", "DeviceManagementApps.Read.All") {
		t.Errorf("RequiredPermissions = %v, missing required scopes", got)
	}
}

func containsAll(have []string, want ...string) bool {
	set := map[string]bool{}
	for _, s := range have {
		set[s] = true
	}
	for _, w := range want {
		if !set[w] {
			return false
		}
	}
	return true
}
