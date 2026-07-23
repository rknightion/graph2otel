package connectors

import (
	"context"
	"errors"
	"sort"
	"testing"
	"time"

	"github.com/rknightion/graph2otel/internal/collectors"
	"github.com/rknightion/graph2otel/internal/telemetry"
	"github.com/rknightion/graph2otel/internal/telemetrytest"
)

// fakeGraph is an in-memory collectors.GraphClient: it maps request URLs to
// canned response bodies (or errors), mirroring the reference collectors'
// test fakes (entra/devices, entra/recommendations).
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
	body, ok := f.bodies[url]
	if !ok {
		return nil, errors.New("fakeGraph: no canned body for " + url)
	}
	return []byte(body), nil
}

var _ collectors.GraphClient = (*fakeGraph)(nil)

var (
	exchangeURL = defaultBaseURL + "/deviceManagement/exchangeConnectors"
	mtdURL      = defaultBaseURL + "/deviceManagement/mobileThreatDefenseConnectors"
	ndesURL     = betaBaseURL + "/deviceManagement/ndesConnectors"
	amsURL      = betaBaseURL + "/deviceManagement/androidManagedStoreAccountEnterpriseSettings"
)

// amsUnavailableErr is the graceful-skip (404) shape the beta Managed Google
// Play singleton returns on a tenant that has never bound one. Wired into the
// exchange/mtd/ndes-focused tests so their assertions stay exactly as they were
// before the #248 fold — the android_managed_store branch simply emits nothing.
func amsUnavailableErr() error {
	return errors.New(`graphclient: GET https://graph.microsoft.com/beta/deviceManagement/androidManagedStoreAccountEnterpriseSettings: status 404: {"error":{"code":"NotFound"}}`)
}

// liveAndroidManagedStore is a VERBATIM GET
// /beta/deviceManagement/androidManagedStoreAccountEnterpriseSettings read as
// graph2otel-poller against the m7kni tenant `[live-measured 2026-07-23, #248]`.
// It is a singleton (no {value:[]} envelope): boundAndValidated, last app sync
// succeeded. m7kni is Android-light so the VALUES are uninteresting, but every
// field the mapper reads is populated exactly as spelled here.
const liveAndroidManagedStore = `{
  "@odata.context": "https://graph.microsoft.com/beta/$metadata#deviceManagement/androidManagedStoreAccountEnterpriseSettings/$entity",
  "id": "androidManagedStoreAccountEnterpriseSettings",
  "bindStatus": "boundAndValidated",
  "managedGooglePlayEnterpriseType": "managedGoogleDomain",
  "lastAppSyncDateTime": "2026-07-23T16:59:33.792783Z",
  "lastAppSyncStatus": "success",
  "ownerUserPrincipalName": "rob@rob-knight.com",
  "ownerOrganizationName": "rob-knight",
  "lastModifiedDateTime": "2025-09-11T14:43:51.9783652Z",
  "enrollmentTarget": "targetedAsEnrollmentRestrictions",
  "targetGroupIds": [],
  "deviceOwnerManagementEnabled": true,
  "androidDeviceOwnerFullyManagedEnrollmentEnabled": false,
  "managedGooglePlayInitialScopeTagIds": ["0"],
  "companyCodes": []
}`

// liveAMSNow is one hour after lastAppSyncDateTime, so heartbeat_age is 3600s.
var liveAMSNow = time.Date(2026, 7, 23, 17, 59, 33, 792783000, time.UTC)

var fixedNow = time.Date(2026, 7, 15, 12, 0, 0, 0, time.UTC)

func fixedClock() time.Time { return fixedNow }

// liveMTDConnectors is a VERBATIM GET /deviceManagement/mobileThreatDefenseConnectors
// response read as graph2otel-poller against the m7kni tenant
// `[live-measured 2026-07-17, #165]`. Two real connector instances: one
// notSetUp with every platform disabled and a zero-value heartbeat (never
// connected), and one fully enabled with a real lastHeartbeatDateTime. Pinned
// with the full field set Graph returns — including the many *Enabled/*Blocked
// flags the collector ignores — so partnerState, lastHeartbeatDateTime, and the
// three androidEnabled/iosEnabled/windowsEnabled fields the mapper reads are
// proven present exactly as spelled on the wire.
const liveMTDConnectors = `{
  "@odata.context": "https://graph.microsoft.com/v1.0/$metadata#deviceManagement/mobileThreatDefenseConnectors",
  "value": [
    {
      "allowPartnerToCollectIOSApplicationMetadata": false,
      "allowPartnerToCollectIOSPersonalApplicationMetadata": false,
      "androidDeviceBlockedOnMissingPartnerData": false,
      "androidEnabled": false,
      "androidMobileApplicationManagementEnabled": false,
      "id": "c2b688fe-48c0-464b-a89c-67041aa8fcb2",
      "iosDeviceBlockedOnMissingPartnerData": false,
      "iosEnabled": false,
      "iosMobileApplicationManagementEnabled": false,
      "lastHeartbeatDateTime": "0001-01-01T00:00:00Z",
      "microsoftDefenderForEndpointAttachEnabled": false,
      "partnerState": "notSetUp",
      "partnerUnresponsivenessThresholdInDays": 7,
      "partnerUnsupportedOsVersionBlocked": false,
      "windowsDeviceBlockedOnMissingPartnerData": false,
      "windowsEnabled": false
    },
    {
      "allowPartnerToCollectIOSApplicationMetadata": true,
      "allowPartnerToCollectIOSPersonalApplicationMetadata": true,
      "androidDeviceBlockedOnMissingPartnerData": true,
      "androidEnabled": true,
      "androidMobileApplicationManagementEnabled": true,
      "id": "fc780465-2017-40d4-a0c5-307022471b92",
      "iosDeviceBlockedOnMissingPartnerData": true,
      "iosEnabled": true,
      "iosMobileApplicationManagementEnabled": true,
      "lastHeartbeatDateTime": "2026-07-17T10:45:28.2000756Z",
      "microsoftDefenderForEndpointAttachEnabled": true,
      "partnerState": "enabled",
      "partnerUnresponsivenessThresholdInDays": 7,
      "partnerUnsupportedOsVersionBlocked": false,
      "windowsDeviceBlockedOnMissingPartnerData": true,
      "windowsEnabled": true
    }
  ]
}`

// liveMTDNow is exactly one hour after the enabled connector's heartbeat, so
// the emitted heartbeat_age is a clean 3600s.
var liveMTDNow = time.Date(2026, 7, 17, 11, 45, 28, 200075600, time.UTC)

func newTestCollector(g collectors.GraphClient) *Collector {
	c := New(g, nil)
	c.now = fixedClock
	return c
}

// pointByAttr finds the single recorded point whose attribute key equals
// want, failing the test if there is not exactly one match.
func pointByAttr(t *testing.T, pts []telemetrytest.MetricPoint, key, want string) telemetrytest.MetricPoint {
	t.Helper()
	var matches []telemetrytest.MetricPoint
	for _, p := range pts {
		if p.Attrs[key] == want {
			matches = append(matches, p)
		}
	}
	if len(matches) != 1 {
		t.Fatalf("%d points with %s=%s, want exactly 1: %+v", len(matches), key, want, pts)
	}
	return matches[0]
}

func findPoint(pts []telemetrytest.MetricPoint, attrs map[string]string) (telemetrytest.MetricPoint, bool) {
	for _, p := range pts {
		match := true
		for k, v := range attrs {
			if p.Attrs[k] != v {
				match = false
				break
			}
		}
		if match {
			return p, true
		}
	}
	return telemetrytest.MetricPoint{}, false
}

func TestCollectEmitsStateAndHeartbeatAcrossAllThreeConnectorTypes(t *testing.T) {
	// Exchange and NDES bodies are docs-derived: on the live tenant
	// exchangeConnectors returns 501 NotSupported and ndesConnectors an empty
	// list (docs-derived, endpoint empty/501 on tenant 2026-07-17 (#165)), so
	// there is no capturable success body for either. They are synthesized here
	// only to exercise the multi-type aggregation the live single-type MTD
	// capture cannot. MTD's real success body is pinned in
	// TestCollectEmitsLiveMTDConnectorsEndToEnd.
	g := &fakeGraph{bodies: map[string]string{
		exchangeURL: `{"value":[
			{"status":"connected","lastSyncDateTime":"2026-07-15T11:59:00Z"},
			{"status":"disconnected","lastSyncDateTime":"2026-07-15T10:00:00Z"}
		]}`,
		mtdURL: `{"value":[
			{"partnerState":"enabled","lastHeartbeatDateTime":"2026-07-15T11:55:00Z","androidEnabled":true,"iosEnabled":false,"windowsEnabled":true}
		]}`,
		ndesURL: `{"value":[
			{"state":"active","lastConnectionDateTime":"2026-07-15T11:00:00Z"}
		]}`,
	}, errs: map[string]error{amsURL: amsUnavailableErr()}}
	rec := telemetrytest.New()

	if err := newTestCollector(g).Collect(context.Background(), rec.Emitter()); err != nil {
		t.Fatalf("Collect: %v", err)
	}

	states := rec.MetricPoints(stateMetric)
	if p, ok := findPoint(states, map[string]string{"connector_type": "exchange", "state": "connected"}); !ok || p.Value != 1 {
		t.Errorf("exchange connected state point = %+v, ok=%v", p, ok)
	}
	if p, ok := findPoint(states, map[string]string{"connector_type": "exchange", "state": "disconnected"}); !ok || p.Value != 1 {
		t.Errorf("exchange disconnected state point = %+v, ok=%v", p, ok)
	}
	if p, ok := findPoint(states, map[string]string{"connector_type": "mtd", "state": "enabled"}); !ok || p.Value != 1 {
		t.Errorf("mtd enabled state point = %+v, ok=%v", p, ok)
	}
	if p, ok := findPoint(states, map[string]string{"connector_type": "ndes", "state": "active"}); !ok || p.Value != 1 {
		t.Errorf("ndes active state point = %+v, ok=%v", p, ok)
	}

	ages := rec.MetricPoints(heartbeatAgeMetric)
	// Exchange has two instances; the oldest (most stale) sync is 2h old and
	// must win over the 1-minute-old one, since the metric surfaces the worst
	// case per connector type, not an average or the newest instance.
	exAge := pointByAttr(t, ages, "connector_type", "exchange")
	if exAge.Value != (2 * time.Hour).Seconds() {
		t.Errorf("exchange heartbeat age = %v, want %v (oldest instance)", exAge.Value, (2 * time.Hour).Seconds())
	}
	mtdAge := pointByAttr(t, ages, "connector_type", "mtd")
	if mtdAge.Value != (5 * time.Minute).Seconds() {
		t.Errorf("mtd heartbeat age = %v, want %v", mtdAge.Value, (5 * time.Minute).Seconds())
	}
	ndesAge := pointByAttr(t, ages, "connector_type", "ndes")
	if ndesAge.Value != (1 * time.Hour).Seconds() {
		t.Errorf("ndes heartbeat age = %v, want %v", ndesAge.Value, (1 * time.Hour).Seconds())
	}

	platforms := rec.MetricPoints(mtdPlatformMetric)
	if len(platforms) != 6 {
		t.Fatalf("mtd platform points = %d, want 6 (3 platforms x enabled/disabled)", len(platforms))
	}
	if p, ok := findPoint(platforms, map[string]string{"platform": "android", "enabled": "true"}); !ok || p.Value != 1 {
		t.Errorf("android enabled = %+v, ok=%v", p, ok)
	}
	if p, ok := findPoint(platforms, map[string]string{"platform": "ios", "enabled": "false"}); !ok || p.Value != 1 {
		t.Errorf("ios disabled = %+v, ok=%v", p, ok)
	}
	if p, ok := findPoint(platforms, map[string]string{"platform": "windows", "enabled": "true"}); !ok || p.Value != 1 {
		t.Errorf("windows enabled = %+v, ok=%v", p, ok)
	}
}

// TestCollectEmitsLiveMTDConnectorsEndToEnd drives the verbatim live MTD
// capture through the full Collect path into a Recorder. The tenant's other two
// connector endpoints return exactly what was captured on 2026-07-17 — Exchange
// 501 NotSupported (no connector configured) and NDES an empty beta list — so
// only the MTD metrics are emitted, which is the real steady state.
func TestCollectEmitsLiveMTDConnectorsEndToEnd(t *testing.T) {
	g := &fakeGraph{
		bodies: map[string]string{
			mtdURL:  liveMTDConnectors,
			ndesURL: `{"value":[]}`, // live: beta ndesConnectors returned an empty list
		},
		errs: map[string]error{
			// live: exchangeConnectors returned 501 NotSupported, not an empty list.
			exchangeURL: errors.New(`graphclient: GET https://graph.microsoft.com/v1.0/deviceManagement/exchangeConnectors: status 501: {"error":{"code":"NotSupported"}}`),
			amsURL:      amsUnavailableErr(),
		},
	}
	c := New(g, nil)
	c.now = func() time.Time { return liveMTDNow }
	rec := telemetrytest.New()

	if err := c.Collect(context.Background(), rec.Emitter()); err != nil {
		t.Fatalf("Collect: %v, want nil (exchange 501 + empty ndes are graceful)", err)
	}

	states := rec.MetricPoints(stateMetric)
	if p, ok := findPoint(states, map[string]string{"connector_type": "mtd", "state": "notSetUp"}); !ok || p.Value != 1 {
		t.Errorf("mtd notSetUp state point = %+v, ok=%v", p, ok)
	}
	if p, ok := findPoint(states, map[string]string{"connector_type": "mtd", "state": "enabled"}); !ok || p.Value != 1 {
		t.Errorf("mtd enabled state point = %+v, ok=%v", p, ok)
	}
	if _, ok := findPoint(states, map[string]string{"connector_type": "exchange"}); ok {
		t.Errorf("exchange state present despite live 501: %+v", states)
	}
	if _, ok := findPoint(states, map[string]string{"connector_type": "ndes"}); ok {
		t.Errorf("ndes state present despite live empty list: %+v", states)
	}

	// Only the enabled connector has a non-zero heartbeat; the notSetUp one's
	// 0001-01-01 timestamp is ignored, so the age is a clean 3600s.
	mtdAge := pointByAttr(t, rec.MetricPoints(heartbeatAgeMetric), "connector_type", "mtd")
	if mtdAge.Value != (1 * time.Hour).Seconds() {
		t.Errorf("mtd heartbeat age = %v, want %v", mtdAge.Value, (1 * time.Hour).Seconds())
	}

	// Two instances: one all-disabled, one all-enabled -> each platform is 1
	// enabled and 1 disabled.
	platforms := rec.MetricPoints(mtdPlatformMetric)
	if len(platforms) != 6 {
		t.Fatalf("mtd platform points = %d, want 6", len(platforms))
	}
	for _, platform := range []string{"android", "ios", "windows"} {
		if p, ok := findPoint(platforms, map[string]string{"platform": platform, "enabled": "true"}); !ok || p.Value != 1 {
			t.Errorf("%s enabled = %+v, ok=%v", platform, p, ok)
		}
		if p, ok := findPoint(platforms, map[string]string{"platform": platform, "enabled": "false"}); !ok || p.Value != 1 {
			t.Errorf("%s disabled = %+v, ok=%v", platform, p, ok)
		}
	}
}

func TestCollectSkipsExchangeGracefullyOn501AndStillEmitsMTDAndNDES(t *testing.T) {
	// Verified live: a tenant with no Exchange connector configured returns
	// HTTP 501 {"error":{"code":"NotSupported",...}} from
	// GET /deviceManagement/exchangeConnectors, not an empty list. That must
	// degrade like a 403/404 (graceful skip), not surface as a collector
	// failure on every scrape for every tenant lacking an Exchange connector.
	g := &fakeGraph{
		bodies: map[string]string{
			mtdURL:  `{"value":[{"partnerState":"enabled","lastHeartbeatDateTime":"2026-07-15T11:00:00Z","androidEnabled":true,"iosEnabled":true,"windowsEnabled":true}]}`,
			ndesURL: `{"value":[{"state":"active","lastConnectionDateTime":"2026-07-15T11:00:00Z"}]}`,
		},
		errs: map[string]error{
			exchangeURL: errors.New(`graphclient: GET https://graph.microsoft.com/v1.0/deviceManagement/exchangeConnectors: status 501: {"error":{"code":"NotSupported","message":"..."}}`),
			amsURL:      amsUnavailableErr(),
		},
	}
	rec := telemetrytest.New()

	if err := newTestCollector(g).Collect(context.Background(), rec.Emitter()); err != nil {
		t.Fatalf("Collect: %v, want nil (501/NotSupported on exchangeConnectors is a graceful skip, not a failure)", err)
	}

	states := rec.MetricPoints(stateMetric)
	if _, ok := findPoint(states, map[string]string{"connector_type": "exchange"}); ok {
		t.Errorf("exchange state point present despite the 501: %+v", states)
	}
	if p, ok := findPoint(states, map[string]string{"connector_type": "mtd", "state": "enabled"}); !ok || p.Value != 1 {
		t.Errorf("mtd state missing/wrong when exchange 501s: %+v, ok=%v", p, ok)
	}
	if p, ok := findPoint(states, map[string]string{"connector_type": "ndes", "state": "active"}); !ok || p.Value != 1 {
		t.Errorf("ndes state missing/wrong when exchange 501s: %+v, ok=%v", p, ok)
	}
}

func TestCollectSkipsNDESSilentlyOn403AndStillEmitsExchangeAndMTD(t *testing.T) {
	g := &fakeGraph{
		bodies: map[string]string{
			exchangeURL: `{"value":[{"status":"connected","lastSyncDateTime":"2026-07-15T11:00:00Z"}]}`,
			mtdURL:      `{"value":[]}`,
		},
		errs: map[string]error{
			ndesURL: errors.New("graphclient: GET https://graph.microsoft.com/beta/deviceManagement/ndesConnectors: status 403: forbidden"),
			amsURL:  amsUnavailableErr(),
		},
	}
	rec := telemetrytest.New()

	if err := newTestCollector(g).Collect(context.Background(), rec.Emitter()); err != nil {
		t.Fatalf("Collect: %v, want nil (403 on the beta NDES endpoint is skip-and-log, not a failure)", err)
	}

	states := rec.MetricPoints(stateMetric)
	if _, ok := findPoint(states, map[string]string{"connector_type": "exchange", "state": "connected"}); !ok {
		t.Errorf("exchange state missing when NDES 403s: %+v", states)
	}
	if _, ok := findPoint(states, map[string]string{"connector_type": "ndes"}); ok {
		t.Errorf("ndes state point present despite 403: %+v", states)
	}
	// mtd had zero connectors, so the optional platform metric must not be
	// emitted at all (not even as an empty snapshot with no series).
	if pts := rec.MetricPoints(mtdPlatformMetric); len(pts) != 0 {
		t.Errorf("mtd platform metric emitted with zero MTD connectors: %+v", pts)
	}
}

func TestCollectIsolatesNDESRealFailureFromExchangeAndMTD(t *testing.T) {
	g := &fakeGraph{
		bodies: map[string]string{
			exchangeURL: `{"value":[{"status":"connected","lastSyncDateTime":"2026-07-15T11:00:00Z"}]}`,
			mtdURL:      `{"value":[{"partnerState":"enabled","lastHeartbeatDateTime":"2026-07-15T11:00:00Z","androidEnabled":true,"iosEnabled":true,"windowsEnabled":true}]}`,
		},
		errs: map[string]error{
			ndesURL: errors.New("graphclient: GET https://graph.microsoft.com/beta/deviceManagement/ndesConnectors: status 500: boom"),
			amsURL:  amsUnavailableErr(),
		},
	}
	rec := telemetrytest.New()

	err := newTestCollector(g).Collect(context.Background(), rec.Emitter())
	if err == nil {
		t.Fatal("Collect: want a non-nil error surfacing the real (non-403/404) NDES failure")
	}

	states := rec.MetricPoints(stateMetric)
	if _, ok := findPoint(states, map[string]string{"connector_type": "exchange", "state": "connected"}); !ok {
		t.Errorf("exchange state missing when NDES fails with a real error: %+v", states)
	}
	if _, ok := findPoint(states, map[string]string{"connector_type": "mtd", "state": "enabled"}); !ok {
		t.Errorf("mtd state missing when NDES fails with a real error: %+v", states)
	}
}

func TestCollectHandlesExchangeFailureIndependentlyOfMTDAndNDES(t *testing.T) {
	g := &fakeGraph{
		bodies: map[string]string{
			mtdURL:  `{"value":[]}`,
			ndesURL: `{"value":[]}`,
		},
		errs: map[string]error{
			exchangeURL: errors.New("graphclient: GET .../exchangeConnectors: status 500: boom"),
			amsURL:      amsUnavailableErr(),
		},
	}
	rec := telemetrytest.New()

	err := newTestCollector(g).Collect(context.Background(), rec.Emitter())
	if err == nil {
		t.Fatal("Collect: want a non-nil error when the exchange connectors list fails")
	}
	// mtd/ndes both returned empty lists successfully; Collect must not have
	// aborted before reaching (or recording) their empty state.
	if _, ok := findPoint(rec.MetricPoints(stateMetric), map[string]string{"connector_type": "exchange"}); ok {
		t.Errorf("exchange state point present despite the list call failing")
	}
}

// TestCollectEmitsLiveAndroidManagedStoreEndToEnd drives the verbatim live
// Managed Google Play singleton (#248) through Collect: the binding folds onto
// the shared state/heartbeat metrics as connector_type=android_managed_store and
// emits one intune.connector log twin. Exchange 501s, MTD/NDES are empty — the
// real m7kni steady state — so only the android_managed_store connector points
// are present.
func TestCollectEmitsLiveAndroidManagedStoreEndToEnd(t *testing.T) {
	g := &fakeGraph{
		bodies: map[string]string{
			amsURL:  liveAndroidManagedStore,
			mtdURL:  `{"value":[]}`,
			ndesURL: `{"value":[]}`,
		},
		errs: map[string]error{
			exchangeURL: errors.New(`graphclient: GET https://graph.microsoft.com/v1.0/deviceManagement/exchangeConnectors: status 501: {"error":{"code":"NotSupported"}}`),
		},
	}
	c := New(g, nil)
	c.now = func() time.Time { return liveAMSNow }
	rec := telemetrytest.New()

	if err := c.Collect(context.Background(), rec.Emitter()); err != nil {
		t.Fatalf("Collect: %v, want nil (live steady state is graceful)", err)
	}

	states := rec.MetricPoints(stateMetric)
	if p, ok := findPoint(states, map[string]string{"connector_type": "android_managed_store", "state": "boundAndValidated"}); !ok || p.Value != 1 {
		t.Errorf("android_managed_store state point = %+v, ok=%v, want boundAndValidated value=1", p, ok)
	}

	amsAge := pointByAttr(t, rec.MetricPoints(heartbeatAgeMetric), "connector_type", "android_managed_store")
	if amsAge.Value != (1 * time.Hour).Seconds() {
		t.Errorf("android_managed_store heartbeat age = %v, want %v", amsAge.Value, (1 * time.Hour).Seconds())
	}

	// Exactly one intune.connector twin, carrying the per-connector detail the
	// metrics collapse away. Healthy binding → INFO.
	var twins []telemetrytest.LogRecord
	for _, r := range rec.LogRecords() {
		if r.EventName == eventConnector {
			twins = append(twins, r)
		}
	}
	if len(twins) != 1 {
		t.Fatalf("intune.connector twins = %d, want 1: %+v", len(twins), twins)
	}
	tw := twins[0]
	if tw.SeverityText != "INFO" {
		t.Errorf("twin severity = %q, want INFO (bound and validated, sync succeeded)", tw.SeverityText)
	}
	wantAttrs := map[string]string{
		"connector_type":       "android_managed_store",
		"bind_status":          "boundAndValidated",
		"last_app_sync_status": "success",
		"enrollment_target":    "targetedAsEnrollmentRestrictions",
		"owner_principal_name": "rob@rob-knight.com",
	}
	for k, v := range wantAttrs {
		if tw.Attrs[k] != v {
			t.Errorf("twin attr %s = %q, want %q", k, tw.Attrs[k], v)
		}
	}
}

// TestAndroidManagedStoreTwinSeverity pins the Warn condition directly on the
// mapper (the recorder idiom the LogRecord doc recommends): a broken bind or a
// failed last app sync escalates to Warn because it silently stops all Android
// app delivery; the fully-working state stays Info.
func TestAndroidManagedStoreTwinSeverity(t *testing.T) {
	cases := []struct {
		name string
		s    androidManagedStoreSettings
		want telemetry.Severity
	}{
		{"healthy", androidManagedStoreSettings{BindStatus: "boundAndValidated", LastAppSyncStatus: "success"}, telemetry.SeverityInfo},
		{"unbound", androidManagedStoreSettings{BindStatus: "notBound", LastAppSyncStatus: "success"}, telemetry.SeverityWarn},
		{"sync_failed", androidManagedStoreSettings{BindStatus: "boundAndValidated", LastAppSyncStatus: "failed"}, telemetry.SeverityWarn},
		{"sync_absent_still_info", androidManagedStoreSettings{BindStatus: "boundAndValidated"}, telemetry.SeverityInfo},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := androidManagedStoreTwin(tc.s).Severity; got != tc.want {
				t.Errorf("severity = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestNameIntervalAndPermissions(t *testing.T) {
	c := New(&fakeGraph{}, nil)
	if c.Name() != "intune.connectors" {
		t.Errorf("Name() = %q, want intune.connectors", c.Name())
	}
	if c.DefaultInterval() <= 0 {
		t.Errorf("DefaultInterval() = %v, want positive", c.DefaultInterval())
	}
	perms := c.RequiredPermissions()
	sort.Strings(perms)
	if len(perms) != 1 || perms[0] != "DeviceManagementServiceConfig.Read.All" {
		t.Errorf("RequiredPermissions() = %v, want [DeviceManagementServiceConfig.Read.All]", perms)
	}
}
