package authmethodspolicy

import (
	"context"
	"errors"
	"testing"

	"github.com/rknightion/graph2otel/internal/collectors"
	"github.com/rknightion/graph2otel/internal/telemetrytest"
)

// fakeGraph returns a canned body (or error) for a single URL, mirroring the
// directorycounts test style but for a single-object endpoint rather than a
// $count segment.
type fakeGraph struct {
	body string
	err  error
}

func (f *fakeGraph) RawGet(_ context.Context, _ string) ([]byte, error) {
	if f.err != nil {
		return nil, f.err
	}
	return []byte(f.body), nil
}

func (f *fakeGraph) RawGetWithHeaders(ctx context.Context, url string, _ map[string]string) ([]byte, error) {
	return f.RawGet(ctx, url)
}

var _ collectors.GraphClient = (*fakeGraph)(nil)

// policyFixture mirrors the shape of the current Microsoft Graph v1.0
// authenticationMethodsPolicy response (verified against
// learn.microsoft.com/en-us/graph/api/authenticationmethodspolicy-get on
// 2026-07-15), trimmed to the fields this collector reads. It includes every
// known built-in method configuration plus one "external" custom method
// configuration (arbitrary GUID id) to exercise the cardinality guard.
const policyFixture = `{
	"id": "authenticationMethodsPolicy",
	"authenticationMethodConfigurations": [
		{"@odata.type": "#microsoft.graph.fido2AuthenticationMethodConfiguration", "id": "Fido2", "state": "enabled"},
		{"@odata.type": "#microsoft.graph.microsoftAuthenticatorAuthenticationMethodConfiguration", "id": "MicrosoftAuthenticator", "state": "enabled"},
		{"@odata.type": "#microsoft.graph.smsAuthenticationMethodConfiguration", "id": "Sms", "state": "disabled"},
		{"@odata.type": "#microsoft.graph.voiceAuthenticationMethodConfiguration", "id": "Voice", "state": "enabled"},
		{"@odata.type": "#microsoft.graph.temporaryAccessPassAuthenticationMethodConfiguration", "id": "TemporaryAccessPass", "state": "enabled"},
		{"@odata.type": "#microsoft.graph.hardwareOathAuthenticationMethodConfiguration", "id": "HardwareOath", "state": "disabled"},
		{"@odata.type": "#microsoft.graph.softwareOathAuthenticationMethodConfiguration", "id": "SoftwareOath", "state": "enabled"},
		{"@odata.type": "#microsoft.graph.emailAuthenticationMethodConfiguration", "id": "Email", "state": "disabled"},
		{"@odata.type": "#microsoft.graph.x509CertificateAuthenticationMethodConfiguration", "id": "X509Certificate", "state": "enabled"},
		{"@odata.type": "#microsoft.graph.externalAuthenticationMethodConfiguration", "id": "fda55161-0d73-48ec-b29f-d29689e3d1b6", "state": "enabled", "displayName": "Adatum - Broken"}
	]
}`

func TestCollectEmitsOneGaugePerKnownMethod(t *testing.T) {
	g := &fakeGraph{body: policyFixture}
	rec := telemetrytest.New()

	c := New(g, nil)
	if err := c.Collect(context.Background(), rec.Emitter()); err != nil {
		t.Fatalf("Collect: %v", err)
	}

	pts := rec.MetricPoints(methodEnabledMetric)
	got := map[string]float64{}
	for _, p := range pts {
		got[p.Attrs["method"]] = p.Value
	}
	want := map[string]float64{
		"fido2":                  1,
		"microsoftAuthenticator": 1,
		"sms":                    0,
		"voice":                  1,
		"temporaryAccessPass":    1,
		"hardwareOath":           0,
		"softwareOath":           1,
		"email":                  0,
		"x509Certificate":        1,
	}
	if len(got) != len(want) {
		t.Fatalf("got %d series, want %d: %v", len(got), len(want), got)
	}
	for method, v := range want {
		if got[method] != v {
			t.Errorf("series method=%s value = %v, want %v", method, got[method], v)
		}
	}
}

// TestCollectExcludesCustomExternalMethods pins the cardinality guard: a
// tenant-added "external" authentication method configuration has an
// arbitrary GUID id (not a fixed method type), so it must never become its
// own metric series — that would make cardinality grow with tenant
// configuration rather than stay bounded by the fixed method catalog.
func TestCollectExcludesCustomExternalMethods(t *testing.T) {
	g := &fakeGraph{body: policyFixture}
	rec := telemetrytest.New()

	if err := New(g, nil).Collect(context.Background(), rec.Emitter()); err != nil {
		t.Fatalf("Collect: %v", err)
	}

	pts := rec.MetricPoints(methodEnabledMetric)
	for _, p := range pts {
		if p.Attrs["method"] == "fda55161-0d73-48ec-b29f-d29689e3d1b6" {
			t.Fatalf("external method configuration leaked into metric attrs: %v", p.Attrs)
		}
	}
	const knownMethodCount = 9
	if len(pts) != knownMethodCount {
		t.Fatalf("got %d series, want exactly %d known method types", len(pts), knownMethodCount)
	}
}

// TestCollectEmitsLegacyEnabledCount pins the convenience count the issue
// calls out: enabled legacy methods (SMS, voice) as a single bounded gauge.
// The fixture has Sms disabled and Voice enabled, so the count is 1.
func TestCollectEmitsLegacyEnabledCount(t *testing.T) {
	g := &fakeGraph{body: policyFixture}
	rec := telemetrytest.New()

	if err := New(g, nil).Collect(context.Background(), rec.Emitter()); err != nil {
		t.Fatalf("Collect: %v", err)
	}

	pts := rec.MetricPoints(legacyEnabledMetric)
	if len(pts) != 1 {
		t.Fatalf("got %d series for %s, want exactly 1", len(pts), legacyEnabledMetric)
	}
	if pts[0].Value != 1 {
		t.Errorf("legacy enabled count = %v, want 1 (voice enabled, sms disabled)", pts[0].Value)
	}
}

func TestCollectSurfacesFetchError(t *testing.T) {
	g := &fakeGraph{err: errors.New("throttled")}
	rec := telemetrytest.New()

	err := New(g, nil).Collect(context.Background(), rec.Emitter())
	if err == nil {
		t.Fatal("expected Collect to surface the fetch error")
	}
	if pts := rec.MetricPoints(methodEnabledMetric); len(pts) != 0 {
		t.Errorf("got %d series after a fetch error, want 0", len(pts))
	}
}

func TestCollectSurfacesDecodeError(t *testing.T) {
	g := &fakeGraph{body: "not json"}
	rec := telemetrytest.New()

	if err := New(g, nil).Collect(context.Background(), rec.Emitter()); err == nil {
		t.Fatal("expected Collect to surface the decode error")
	}
}

func TestNameAndPermissions(t *testing.T) {
	c := New(&fakeGraph{}, nil)
	if c.Name() != "entra.auth_methods_policy" {
		t.Errorf("Name = %q", c.Name())
	}
	// Policy.Read.AuthenticationMethod is the least-privileged application
	// permission per current Microsoft Graph docs (verified 2026-07-15) —
	// Policy.Read.All is listed there as a higher-privileged alternative, not
	// the least-privilege scope the M2 guide asks for.
	perms := c.RequiredPermissions()
	if len(perms) != 1 || perms[0] != "Policy.Read.AuthenticationMethod" {
		t.Errorf("RequiredPermissions = %v, want [Policy.Read.AuthenticationMethod]", perms)
	}
}

func TestDefaultInterval(t *testing.T) {
	c := New(&fakeGraph{}, nil)
	if c.DefaultInterval() <= 0 {
		t.Errorf("DefaultInterval = %v, want positive", c.DefaultInterval())
	}
}
