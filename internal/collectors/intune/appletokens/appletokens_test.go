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
// against, mirroring the devices reference collector's fixedClock.
var fixedNow = time.Date(2026, 7, 15, 12, 0, 0, 0, time.UTC)

func fixedClock() time.Time { return fixedNow }

func rfc3339(offsetDays int) string {
	return fixedNow.Add(time.Duration(offsetDays) * 24 * time.Hour).Format(time.RFC3339)
}

// fullFixture is a self-consistent set of canned bodies: one APNS
// certificate 45 days out, two VPP tokens (one healthy at 200 days, one
// assignedToExternalMDM at 10 days — non-functional even though not
// expired), and one DEP onboarding setting at 300 days with a clean sync.
func fullFixture() map[string]string {
	return map[string]string{
		apnsURL: `{"expirationDateTime":"` + rfc3339(45) + `","certificateUploadStatus":"Valid"}`,
		vppURL: `{"value":[
			{"organizationName":"Acme Corp","expirationDateTime":"` + rfc3339(200) + `","state":"valid"},
			{"organizationName":"Acme EDU","expirationDateTime":"` + rfc3339(10) + `","state":"assignedToExternalMDM"}
		]}`,
		depURL: `{"value":[
			{"tokenName":"Corp DEP","tokenExpirationDateTime":"` + rfc3339(300) + `","lastSyncErrorCode":0,"syncedDeviceCount":42}
		]}`,
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

	cases := []struct {
		k         key
		wantDays  float64
		wantState string
	}{
		{key{"apns", ""}, 45, "Valid"},
		{key{"vpp", "Acme Corp"}, 200, "valid"},
		{key{"vpp", "Acme EDU"}, 10, "assignedToExternalMDM"},
		{key{"dep", "Corp DEP"}, 300, "ok"},
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
	if points[0].Value != 42 {
		t.Errorf("synced_device_count = %v, want 42", points[0].Value)
	}
	if points[0].Attrs["token_name"] != "Corp DEP" {
		t.Errorf("token_name = %q, want %q", points[0].Attrs["token_name"], "Corp DEP")
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
