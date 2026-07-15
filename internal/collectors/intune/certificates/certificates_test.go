package certificates

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
// manageddevices/recommendations reference collectors' test fake.
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
	if body, ok := f.bodies[url]; ok {
		return []byte(body), nil
	}
	return nil, errors.New("unmapped url: " + url)
}

var _ collectors.GraphClient = (*fakeGraph)(nil)

const base = "https://graph.microsoft.com/beta"

var fixedNow = time.Date(2026, 7, 15, 12, 0, 0, 0, time.UTC)

func fixedClock() time.Time { return fixedNow }

func newTestCollector(g collectors.GraphClient) *Collector {
	c := New(g, nil)
	c.now = fixedClock
	return c
}

func deviceConfigsURL() string { return base + "/deviceManagement/deviceConfigurations" }
func userPfxURL() string       { return base + "/deviceManagement/userPfxCertificates" }
func certStatesURL(id, segment string) string {
	return base + "/deviceManagement/deviceConfigurations/" + id + "/microsoft.graph." + segment + "/managedDeviceCertificateStates"
}

func page(values ...map[string]any) string {
	b, err := json.Marshal(map[string]any{"value": values})
	if err != nil {
		panic(err)
	}
	return string(b)
}

func deviceConfig(id, displayName, odataType string) map[string]any {
	return map[string]any{
		"id":          id,
		"displayName": displayName,
		"@odata.type": odataType,
	}
}

func certState(profileName, issuanceState string, expiry *time.Time) map[string]any {
	s := map[string]any{
		"certificateProfileDisplayName": profileName,
		"certificateIssuanceState":      issuanceState,
	}
	if expiry != nil {
		s["certificateExpirationDateTime"] = expiry.Format(time.RFC3339)
	} else {
		s["certificateExpirationDateTime"] = nil
	}
	return s
}

func pfxCert(purpose string, expiry *time.Time) map[string]any {
	p := map[string]any{"intendedPurpose": purpose}
	if expiry != nil {
		p["expirationDateTime"] = expiry.Format(time.RFC3339)
	} else {
		p["expirationDateTime"] = nil
	}
	return p
}

func daysFromNow(d int) *time.Time {
	t := fixedNow.Add(time.Duration(d) * 24 * time.Hour)
	return &t
}

// baseFixture wires one deviceConfigurations page containing one iOS SCEP
// cert profile and one non-certificate profile (which must be skipped), plus
// canned certificate states for the matched profile and an empty pfx list.
func baseFixture() map[string]string {
	return map[string]string{
		deviceConfigsURL(): page(
			deviceConfig("profile-1", "Corp Wifi Certs", "#microsoft.graph.iosScepCertificateProfile"),
			deviceConfig("profile-2", "Password Policy", "#microsoft.graph.iosGeneralDeviceConfiguration"),
		),
		certStatesURL("profile-1", "iosScepCertificateProfile"): page(
			certState("Corp Wifi Certs", "issued", daysFromNow(120)),
			certState("Corp Wifi Certs", "issuePending", daysFromNow(5)),
			certState("Corp Wifi Certs", "revoked", daysFromNow(-1)),
		),
		userPfxURL(): page(),
	}
}

func TestCollectAggregatesManagedDeviceCertificateStatesByExpiryAndState(t *testing.T) {
	g := &fakeGraph{bodies: baseFixture()}
	rec := telemetrytest.New()

	if err := newTestCollector(g).Collect(context.Background(), rec.Emitter()); err != nil {
		t.Fatalf("Collect: %v", err)
	}

	pts := rec.MetricPoints(daysUntilExpiryMetricName)
	got := map[string]float64{}
	for _, p := range pts {
		key := p.Attrs["expiry_bucket"] + "/" + p.Attrs["state"] + "/" + p.Attrs["cert_profile_name"]
		got[key] = p.Value
	}
	want := map[string]float64{
		"over_90d/issued/Corp Wifi Certs": 1,
		"0d_7d/pending/Corp Wifi Certs":   1,
		"expired/revoked/Corp Wifi Certs": 1,
	}
	if len(got) != len(want) {
		t.Fatalf("got %d series, want %d: %v", len(got), len(want), got)
	}
	for k, v := range want {
		if got[k] != v {
			t.Errorf("%s = %v, want %v", k, got[k], v)
		}
	}
}

func TestCollectSkipsNonCertificateDeviceConfigurations(t *testing.T) {
	g := &fakeGraph{bodies: baseFixture()}
	rec := telemetrytest.New()

	// baseFixture maps ONLY profile-1's cast URL; if the collector ever tried
	// to fetch a managedDeviceCertificateStates sub-collection for profile-2
	// (the non-certificate profile), it would hit fakeGraph's "unmapped url"
	// error path and Collect would return an error.
	if err := newTestCollector(g).Collect(context.Background(), rec.Emitter()); err != nil {
		t.Fatalf("Collect: %v", err)
	}
}

func TestCollectCollapsesIssuanceStateEnumToBoundedBuckets(t *testing.T) {
	bodies := map[string]string{
		deviceConfigsURL(): page(
			deviceConfig("profile-1", "P", "#microsoft.graph.androidPkcsCertificateProfile"),
		),
		certStatesURL("profile-1", "androidPkcsCertificateProfile"): page(
			certState("P", "unknown", nil),
			certState("P", "challengeIssued", nil),
			certState("P", "challengeIssueFailed", nil),
			certState("P", "issued", nil),
			certState("P", "installed", nil),
			certState("P", "revoked", nil),
			certState("P", "deleted", nil),
			certState("P", "removedFromCollection", nil),
			certState("P", "someBrandNewFutureEnumValue", nil),
		),
		userPfxURL(): page(),
	}
	g := &fakeGraph{bodies: bodies}
	rec := telemetrytest.New()

	if err := newTestCollector(g).Collect(context.Background(), rec.Emitter()); err != nil {
		t.Fatalf("Collect: %v", err)
	}

	pts := rec.MetricPoints(stateCountMetricName)
	got := map[string]float64{}
	for _, p := range pts {
		got[p.Attrs["state"]] += p.Value
	}
	want := map[string]float64{
		"unknown": 2, // unknown + someBrandNewFutureEnumValue
		"pending": 1, // challengeIssued
		"failed":  1, // challengeIssueFailed
		"issued":  2, // issued + installed
		"revoked": 1,
		"deleted": 2, // deleted + removedFromCollection
	}
	if len(got) != len(want) {
		t.Fatalf("got %d bucket(s), want %d: %v", len(got), len(want), got)
	}
	for k, v := range want {
		if got[k] != v {
			t.Errorf("state=%s = %v, want %v", k, got[k], v)
		}
	}
}

func TestCollectAggregatesUserPfxCertificates(t *testing.T) {
	bodies := map[string]string{
		deviceConfigsURL(): page(),
		userPfxURL(): page(
			pfxCert("smimeEncryption", daysFromNow(45)),
			pfxCert("vpn", daysFromNow(-10)),
		),
	}
	g := &fakeGraph{bodies: bodies}
	rec := telemetrytest.New()

	if err := newTestCollector(g).Collect(context.Background(), rec.Emitter()); err != nil {
		t.Fatalf("Collect: %v", err)
	}

	statePts := rec.MetricPoints(stateCountMetricName)
	var imported float64
	for _, p := range statePts {
		if p.Attrs["state"] == "imported" {
			imported += p.Value
		}
	}
	if imported != 2 {
		t.Errorf("imported state count = %v, want 2", imported)
	}

	daysPts := rec.MetricPoints(daysUntilExpiryMetricName)
	got := map[string]float64{}
	for _, p := range daysPts {
		got[p.Attrs["expiry_bucket"]+"/"+p.Attrs["cert_profile_name"]] = p.Value
	}
	want := map[string]float64{
		"30d_90d/pfx:smimeEncryption": 1,
		"expired/pfx:vpn":             1,
	}
	for k, v := range want {
		if got[k] != v {
			t.Errorf("%s = %v, want %v (all: %v)", k, got[k], v, got)
		}
	}
}

func TestCollectCapsCertProfileNameCardinality(t *testing.T) {
	values := make([]map[string]any, 0, maxCertProfileNames+5)
	for i := 0; i < maxCertProfileNames+5; i++ {
		name := "profile-" + string(rune('A'+i))
		values = append(values, certState(name, "issued", nil))
	}
	bodies := map[string]string{
		deviceConfigsURL(): page(
			deviceConfig("profile-1", "P", "#microsoft.graph.androidPkcsCertificateProfile"),
		),
		certStatesURL("profile-1", "androidPkcsCertificateProfile"): page(values...),
		userPfxURL(): page(),
	}
	g := &fakeGraph{bodies: bodies}
	rec := telemetrytest.New()

	if err := newTestCollector(g).Collect(context.Background(), rec.Emitter()); err != nil {
		t.Fatalf("Collect: %v", err)
	}

	pts := rec.MetricPoints(daysUntilExpiryMetricName)
	names := map[string]bool{}
	for _, p := range pts {
		names[p.Attrs["cert_profile_name"]] = true
	}
	if len(names) > maxCertProfileNames+1 { // +1 for the "other" overflow bucket
		t.Errorf("got %d distinct cert_profile_name values, want <= %d (cap + overflow bucket): %v", len(names), maxCertProfileNames+1, names)
	}
	if !names["other"] {
		t.Errorf("expected overflow profile names to collapse into \"other\", got %v", names)
	}
}

func TestCollectIsResilientToDeviceConfigurationsFailure(t *testing.T) {
	bodies := map[string]string{
		userPfxURL(): page(pfxCert("vpn", daysFromNow(10))),
	}
	g := &fakeGraph{
		bodies: bodies,
		errs:   map[string]error{deviceConfigsURL(): errors.New("throttled")},
	}
	rec := telemetrytest.New()

	err := newTestCollector(g).Collect(context.Background(), rec.Emitter())
	if err == nil {
		t.Fatal("expected Collect to surface the deviceConfigurations failure as an error")
	}
	// The pfx-derived data must still emit despite the deviceConfigurations failure.
	if len(rec.MetricPoints(daysUntilExpiryMetricName)) == 0 {
		t.Error("days_until_expiry series should still emit from userPfxCertificates despite the deviceConfigurations failure")
	}
}

func TestCollectIsResilientToUserPfxCertificatesFailure(t *testing.T) {
	bodies := baseFixture()
	g := &fakeGraph{
		bodies: bodies,
		errs:   map[string]error{userPfxURL(): errors.New("throttled")},
	}
	rec := telemetrytest.New()

	err := newTestCollector(g).Collect(context.Background(), rec.Emitter())
	if err == nil {
		t.Fatal("expected Collect to surface the userPfxCertificates failure as an error")
	}
	if len(rec.MetricPoints(daysUntilExpiryMetricName)) == 0 {
		t.Error("days_until_expiry series should still emit from managedDeviceCertificateStates despite the userPfxCertificates failure")
	}
}

// TestCollectSkipsUnavailableBetaEndpointGracefully pins the acceptance
// criterion that a 403/404 from a beta-only endpoint (unlicensed tenant, or a
// cert-profile cast Graph doesn't recognize) is treated as "no data here", not
// a failure.
func TestCollectSkipsUnavailableBetaEndpointGracefully(t *testing.T) {
	g := &fakeGraph{
		bodies: map[string]string{
			userPfxURL(): page(),
		},
		errs: map[string]error{deviceConfigsURL(): errors.New("request failed: status 404 Not Found")},
	}
	rec := telemetrytest.New()

	if err := newTestCollector(g).Collect(context.Background(), rec.Emitter()); err != nil {
		t.Fatalf("Collect: %v, want nil (404 should be skipped, not surfaced)", err)
	}
}

func TestCollectSkipsUnavailableCertProfileCastGracefully(t *testing.T) {
	bodies := map[string]string{
		deviceConfigsURL(): page(
			deviceConfig("profile-1", "P", "#microsoft.graph.iosPkcsCertificateProfile"),
		),
		userPfxURL(): page(),
	}
	g := &fakeGraph{
		bodies: bodies,
		errs:   map[string]error{certStatesURL("profile-1", "iosPkcsCertificateProfile"): errors.New("request failed: status 403 Forbidden")},
	}
	rec := telemetrytest.New()

	if err := newTestCollector(g).Collect(context.Background(), rec.Emitter()); err != nil {
		t.Fatalf("Collect: %v, want nil (403 on one profile cast should be skipped, not surfaced)", err)
	}
}

func TestNoPerDeviceOrPerCertAttributes(t *testing.T) {
	g := &fakeGraph{bodies: baseFixture()}
	rec := telemetrytest.New()

	if err := newTestCollector(g).Collect(context.Background(), rec.Emitter()); err != nil {
		t.Fatalf("Collect: %v", err)
	}

	for _, metric := range []string{daysUntilExpiryMetricName, stateCountMetricName} {
		for _, p := range rec.MetricPoints(metric) {
			for k := range p.Attrs {
				switch k {
				case "id", "deviceId", "device_id", "thumbprint", "serialNumber", "serial_number",
					"userPrincipalName", "user_principal_name", "deviceDisplayName", "device_display_name":
					t.Errorf("metric %s has a per-entity attribute %q - cardinality violation", metric, k)
				}
			}
		}
	}
}

func TestNameIntervalPermissionsAndExperimental(t *testing.T) {
	c := New(&fakeGraph{}, nil)
	if c.Name() != "intune.certificates" {
		t.Errorf("Name = %q, want intune.certificates", c.Name())
	}
	if c.DefaultInterval() <= 0 {
		t.Errorf("DefaultInterval = %v, want positive", c.DefaultInterval())
	}
	perms := c.RequiredPermissions()
	if len(perms) != 1 || perms[0] != "DeviceManagementConfiguration.Read.All" {
		t.Errorf("RequiredPermissions = %v, want [DeviceManagementConfiguration.Read.All]", perms)
	}
	if !c.Experimental() {
		t.Error("Experimental() = false, want true (both endpoints are beta-only)")
	}
}
