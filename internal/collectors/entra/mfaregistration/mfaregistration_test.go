package mfaregistration

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/rknightion/graph2otel/internal/collectors"
	"github.com/rknightion/graph2otel/internal/license"
	"github.com/rknightion/graph2otel/internal/telemetry"
	"github.com/rknightion/graph2otel/internal/telemetrytest"
)

// fakeGraph maps request URLs to canned page bodies (or errors) and records
// the ConsistencyLevel header seen on each request.
type fakeGraph struct {
	bodies      map[string]string
	errs        map[string]error
	seenHeaders map[string]string // url -> ConsistencyLevel
}

func (f *fakeGraph) RawGet(ctx context.Context, url string) ([]byte, error) {
	return f.RawGetWithHeaders(ctx, url, nil)
}

func (f *fakeGraph) RawGetWithHeaders(_ context.Context, url string, headers map[string]string) ([]byte, error) {
	if f.seenHeaders == nil {
		f.seenHeaders = map[string]string{}
	}
	f.seenHeaders[url] = headers["ConsistencyLevel"]
	if err, ok := f.errs[url]; ok {
		return nil, err
	}
	return []byte(f.bodies[url]), nil
}

var _ collectors.GraphClient = (*fakeGraph)(nil)

// sampleUsers is five userRegistrationDetails records exercising every
// feature flag combination and a handful of registered methods, PLUS the
// per-entity identity fields (id/userPrincipalName/userDisplayName/
// lastUpdatedDateTime) that only the log twin reads — see
// TestCollectNoPerEntitySeries for the assertion that these never reach a
// metric attribute despite being decoded here. u4 (dave-admin) is the
// admin-without-MFA-capability case the log twin's severity mapping escalates.
const sampleUsers = `
{"id":"u1","userPrincipalName":"alice@example.com","userDisplayName":"Alice Example","lastUpdatedDateTime":"2026-07-15T10:00:00Z","isAdmin":true,"isMfaRegistered":true,"isMfaCapable":true,"isSsprRegistered":false,"isSsprEnabled":true,"isSsprCapable":false,"isPasswordlessCapable":false,"methodsRegistered":["microsoftAuthenticatorPush","sms"]},
{"id":"u2","userPrincipalName":"bob@example.com","userDisplayName":"Bob Example","lastUpdatedDateTime":"2026-07-15T10:05:00Z","isAdmin":false,"isMfaRegistered":true,"isMfaCapable":true,"isSsprRegistered":true,"isSsprEnabled":true,"isSsprCapable":true,"isPasswordlessCapable":true,"methodsRegistered":["fido2SecurityKey"]},
{"id":"u3","userPrincipalName":"carol@example.com","userDisplayName":"Carol Example","lastUpdatedDateTime":"2026-07-15T10:10:00Z","isAdmin":false,"isMfaRegistered":false,"isMfaCapable":false,"isSsprRegistered":false,"isSsprEnabled":false,"isSsprCapable":false,"isPasswordlessCapable":false,"methodsRegistered":[]},
{"id":"u4","userPrincipalName":"dave-admin@example.com","userDisplayName":"Dave Admin","lastUpdatedDateTime":"2026-07-15T10:15:00Z","isAdmin":true,"isMfaRegistered":false,"isMfaCapable":false,"isSsprRegistered":true,"isSsprEnabled":true,"isSsprCapable":true,"isPasswordlessCapable":false,"methodsRegistered":["sms"]},
{"id":"u5","userPrincipalName":"erin@example.com","userDisplayName":"Erin Example","lastUpdatedDateTime":"2026-07-15T10:20:00Z","isAdmin":false,"isMfaRegistered":true,"isMfaCapable":false,"isSsprRegistered":false,"isSsprEnabled":true,"isSsprCapable":false,"isPasswordlessCapable":false,"methodsRegistered":["microsoftAuthenticatorPush"]}
`

func page(usersJSON string) string {
	return `{"value":[` + usersJSON + `]}`
}

func fullFixture() map[string]string {
	return map[string]string{
		requestURL: page(sampleUsers),
	}
}

func TestCollectEmitsStatusCountsByFeature(t *testing.T) {
	g := &fakeGraph{bodies: fullFixture()}
	rec := telemetrytest.New()

	if err := New(g, nil).Collect(context.Background(), rec.Emitter()); err != nil {
		t.Fatalf("Collect: %v", err)
	}

	pts := rec.MetricPoints(statusMetricName)
	got := map[string]float64{}
	for _, p := range pts {
		got[p.Attrs["status"]] = p.Value
	}
	want := map[string]float64{
		"mfa_registered":       3,
		"mfa_capable":          2,
		"sspr_registered":      2,
		"sspr_enabled":         4,
		"sspr_capable":         2,
		"passwordless_capable": 1,
	}
	if len(got) != len(want) {
		t.Fatalf("got %d series, want %d: %v", len(got), len(want), got)
	}
	for status, v := range want {
		if got[status] != v {
			t.Errorf("series status=%s value = %v, want %v", status, got[status], v)
		}
	}
}

func TestCollectEmitsMethodCounts(t *testing.T) {
	g := &fakeGraph{bodies: fullFixture()}
	rec := telemetrytest.New()

	if err := New(g, nil).Collect(context.Background(), rec.Emitter()); err != nil {
		t.Fatalf("Collect: %v", err)
	}

	pts := rec.MetricPoints(methodMetricName)
	got := map[string]float64{}
	for _, p := range pts {
		got[p.Attrs["method"]] = p.Value
	}
	want := map[string]float64{
		"microsoftAuthenticatorPush": 2,
		"sms":                        2,
		"fido2SecurityKey":           1,
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

func TestCollectEmitsAdminMfaCapableSplit(t *testing.T) {
	g := &fakeGraph{bodies: fullFixture()}
	rec := telemetrytest.New()

	if err := New(g, nil).Collect(context.Background(), rec.Emitter()); err != nil {
		t.Fatalf("Collect: %v", err)
	}

	pts := rec.MetricPoints(adminMfaCapableMetricName)
	got := map[string]float64{}
	for _, p := range pts {
		got[p.Attrs["is_admin"]] = p.Value
	}
	want := map[string]float64{"true": 1, "false": 1}
	if len(got) != len(want) {
		t.Fatalf("got %d series, want %d: %v", len(got), len(want), got)
	}
	for isAdmin, v := range want {
		if got[isAdmin] != v {
			t.Errorf("series is_admin=%s value = %v, want %v", isAdmin, got[isAdmin], v)
		}
	}
}

func TestCollectFollowsPagination(t *testing.T) {
	page1 := `{"value":[{"isMfaRegistered":true,"isMfaCapable":true,"isSsprRegistered":false,"isSsprEnabled":false,"isSsprCapable":false,"isPasswordlessCapable":false,"isAdmin":false,"methodsRegistered":["sms"]}],"@odata.nextLink":"` + requestURL + `&$skiptoken=abc"}`
	page2 := `{"value":[{"isMfaRegistered":true,"isMfaCapable":true,"isSsprRegistered":false,"isSsprEnabled":false,"isSsprCapable":false,"isPasswordlessCapable":false,"isAdmin":false,"methodsRegistered":["sms"]}]}`
	g := &fakeGraph{bodies: map[string]string{
		requestURL:                     page1,
		requestURL + "&$skiptoken=abc": page2,
	}}
	rec := telemetrytest.New()

	if err := New(g, nil).Collect(context.Background(), rec.Emitter()); err != nil {
		t.Fatalf("Collect: %v", err)
	}

	pts := rec.MetricPoints(statusMetricName)
	for _, p := range pts {
		if p.Attrs["status"] == "mfa_registered" && p.Value != 2 {
			t.Errorf("mfa_registered = %v, want 2 (both pages counted)", p.Value)
		}
	}
}

func TestCollectSetsNoConsistencyLevelHeader(t *testing.T) {
	// userRegistrationDetails is read here with only a plain $select (no
	// advanced $filter/$search/$count), so ConsistencyLevel must NOT be set.
	g := &fakeGraph{bodies: fullFixture()}
	rec := telemetrytest.New()

	if err := New(g, nil).Collect(context.Background(), rec.Emitter()); err != nil {
		t.Fatalf("Collect: %v", err)
	}
	for url, cl := range g.seenHeaders {
		if cl != "" {
			t.Errorf("request %s had ConsistencyLevel=%q, want unset", url, cl)
		}
	}
}

func TestCollectIsResilientToFetchError(t *testing.T) {
	g := &fakeGraph{errs: map[string]error{requestURL: errors.New("throttled")}}
	rec := telemetrytest.New()

	err := New(g, nil).Collect(context.Background(), rec.Emitter())
	if err == nil {
		t.Error("expected Collect to surface the fetch failure as an error")
	}
	if names := rec.MetricNames(); len(names) != 0 {
		t.Errorf("expected no metrics emitted on fetch failure, got %v", names)
	}
}

func TestNameAndPermissions(t *testing.T) {
	c := New(&fakeGraph{}, nil)
	if c.Name() != "entra.mfa_registration" {
		t.Errorf("Name = %q", c.Name())
	}
	perms := c.RequiredPermissions()
	if len(perms) != 1 || perms[0] != "AuditLog.Read.All" {
		t.Errorf("RequiredPermissions = %v, want [AuditLog.Read.All]", perms)
	}
}

// TestRequiredCapabilityIsEntraP1 pins the WHOLE-collector license gate: the
// registration report (userRegistrationDetails) requires Entra ID P1 or P2 to
// return data, and a P2 tenant normally also holds the P1 capability, so
// gating on P1 alone covers both tiers. The composition root uses this to
// skip constructing/registering the collector entirely for a Free tenant —
// this collector itself never sees or checks caps (see license.ShouldRun).
func TestRequiredCapabilityIsEntraP1(t *testing.T) {
	c := New(&fakeGraph{}, nil)
	var requirer license.CapabilityRequirer = c
	if got := requirer.RequiredCapability(); got != license.CapEntraP1 {
		t.Errorf("RequiredCapability() = %q, want %q", got, license.CapEntraP1)
	}
}

// logsNamed returns the recorded log records carrying the given EventName.
func logsNamed(recs []telemetrytest.LogRecord, name string) []telemetrytest.LogRecord {
	var out []telemetrytest.LogRecord
	for _, r := range recs {
		if r.EventName == name {
			out = append(out, r)
		}
	}
	return out
}

// TestSelectRequestsIdentityFields pins the $select widening: without id,
// userPrincipalName, userDisplayName, and lastUpdatedDateTime on the wire,
// the log twin below would have nothing per-entity to emit. Asserting on the
// request URL itself means a future trim of $select cannot silently break
// the twin without a test failing here.
func TestSelectRequestsIdentityFields(t *testing.T) {
	for _, want := range []string{"id", "userPrincipalName", "userDisplayName", "lastUpdatedDateTime"} {
		if !strings.Contains(requestURL, want) {
			t.Errorf("requestURL %q missing $select field %q", requestURL, want)
		}
	}
}

// TestCollectEmitsUserRegistrationLogTwinForEveryUser is the maintainer
// decision from #114: EVERY user row is twinned, not just posture failures,
// because graph2otel's log pipeline is the surviving SIEM record and
// filtering to "problem rows only" would break "did this user have MFA last
// month" correlation.
func TestCollectEmitsUserRegistrationLogTwinForEveryUser(t *testing.T) {
	g := &fakeGraph{bodies: fullFixture()}
	rec := telemetrytest.New()

	if err := New(g, nil).Collect(context.Background(), rec.Emitter()); err != nil {
		t.Fatalf("Collect: %v", err)
	}

	got := logsNamed(rec.LogRecords(), eventUserRegistration)
	if len(got) != 5 {
		t.Fatalf("emitted %d %s logs, want 5 (one per user, including posture successes)", len(got), eventUserRegistration)
	}
}

// TestCollectEmitsUserRegistrationLogTwinAttrs checks the per-user detail
// (u1/alice) that the bounded metrics can never carry: identity, timestamp,
// and every posture flag as a string.
func TestCollectEmitsUserRegistrationLogTwinAttrs(t *testing.T) {
	g := &fakeGraph{bodies: fullFixture()}
	rec := telemetrytest.New()

	if err := New(g, nil).Collect(context.Background(), rec.Emitter()); err != nil {
		t.Fatalf("Collect: %v", err)
	}

	got := logsNamed(rec.LogRecords(), eventUserRegistration)
	var alice *telemetrytest.LogRecord
	for i := range got {
		if got[i].Attrs["id"] == "u1" {
			alice = &got[i]
		}
	}
	if alice == nil {
		t.Fatalf("no log for user u1; got %v", got)
	}

	want := map[string]string{
		"id":                   "u1",
		"user_principal_name":  "alice@example.com",
		"user_display_name":    "Alice Example",
		"last_updated":         "2026-07-15T10:00:00Z",
		"is_admin":             "true",
		"mfa_registered":       "true",
		"mfa_capable":          "true",
		"sspr_registered":      "false",
		"sspr_enabled":         "true",
		"sspr_capable":         "false",
		"passwordless_capable": "false",
		"methods_registered":   "microsoftAuthenticatorPush,sms",
	}
	for k, v := range want {
		if alice.Attrs[k] != v {
			t.Errorf("user registration log attr %q = %q, want %q", k, alice.Attrs[k], v)
		}
	}
}

// TestLogTwinOmitsAbsentAttrs drives logTwin directly with a zero-value
// record: identity/timestamp/methods fields must be omitted when empty
// (never emitted as ""), while the boolean posture flags always appear
// (they're never legitimately "absent" — a decoded bool is always true or
// false, so they're plain string assignments rather than setStr-omitted).
func TestLogTwinOmitsAbsentAttrs(t *testing.T) {
	ev := logTwin(userRegistrationDetail{})
	for _, k := range []string{"id", "user_principal_name", "user_display_name", "last_updated", "methods_registered"} {
		if v, ok := ev.Attrs[k]; ok {
			t.Errorf("zero-value record emitted absent attr %q = %q, want it omitted", k, v)
		}
	}
	for _, k := range []string{"is_admin", "mfa_registered", "mfa_capable", "sspr_registered", "sspr_enabled", "sspr_capable", "passwordless_capable"} {
		if _, ok := ev.Attrs[k]; !ok {
			t.Errorf("zero-value record missing boolean attr %q, want it present (as \"false\")", k)
		}
	}
}

// TestLogTwinSeverityAdminWithoutMfaCapableWarns pins the severity choice:
// an admin who cannot currently complete a policy-compliant MFA challenge
// (isMfaCapable false — the operationally meaningful "can't actually MFA"
// signal, a superset of isMfaRegistered false since a registered-but-
// policy-disallowed method registers true/false respectively) is the
// standout risk and escalates to Warn. Every other combination, including a
// non-admin with no MFA at all, stays Info — routine background posture on
// any real tenant, and warning on it would make the severity dimension
// useless for filtering (same reasoning as entra/risk's "only high
// escalates").
func TestLogTwinSeverityAdminWithoutMfaCapableWarns(t *testing.T) {
	for _, tc := range []struct {
		name       string
		isAdmin    bool
		mfaCapable bool
		want       telemetry.Severity
	}{
		{"admin not mfa-capable", true, false, telemetry.SeverityWarn},
		{"admin mfa-capable", true, true, telemetry.SeverityInfo},
		{"non-admin not mfa-capable", false, false, telemetry.SeverityInfo},
		{"non-admin mfa-capable", false, true, telemetry.SeverityInfo},
	} {
		ev := logTwin(userRegistrationDetail{IsAdmin: tc.isAdmin, IsMfaCapable: tc.mfaCapable})
		if ev.Severity != tc.want {
			t.Errorf("%s: severity = %v, want %v", tc.name, ev.Severity, tc.want)
		}
	}
}

// TestNoPerEntitySeries guards the cardinality rule: none of this
// collector's metrics may carry a per-user identifier (userPrincipalName,
// userDisplayName, id) as an attribute, even though those fields ARE now
// decoded (for the log twin above) — the per-user detail endpoint must
// still never be paged into anything but a bounded aggregate on the metric
// side.
func TestNoPerEntitySeries(t *testing.T) {
	g := &fakeGraph{bodies: fullFixture()}
	rec := telemetrytest.New()

	if err := New(g, nil).Collect(context.Background(), rec.Emitter()); err != nil {
		t.Fatalf("Collect: %v", err)
	}

	allowedStatusAttrs := map[string]bool{"status": true}
	for _, p := range rec.MetricPoints(statusMetricName) {
		for k := range p.Attrs {
			if !allowedStatusAttrs[k] {
				t.Errorf("status series has unexpected attribute %q (possible per-entity leak): %v", k, p.Attrs)
			}
		}
	}

	allowedMethodAttrs := map[string]bool{"method": true}
	for _, p := range rec.MetricPoints(methodMetricName) {
		for k := range p.Attrs {
			if !allowedMethodAttrs[k] {
				t.Errorf("method series has unexpected attribute %q (possible per-entity leak): %v", k, p.Attrs)
			}
		}
	}

	allowedAdminAttrs := map[string]bool{"is_admin": true}
	for _, p := range rec.MetricPoints(adminMfaCapableMetricName) {
		for k := range p.Attrs {
			if !allowedAdminAttrs[k] {
				t.Errorf("admin mfa-capable series has unexpected attribute %q (possible per-entity leak): %v", k, p.Attrs)
			}
		}
	}

	// Cardinality is bounded regardless of tenant size: 6 fixed statuses, the
	// small set of methods actually registered tenant-wide, and exactly 2
	// is_admin values.
	if n := len(rec.MetricPoints(statusMetricName)); n > 6 {
		t.Errorf("status series count = %d, want <= 6", n)
	}
	if n := len(rec.MetricPoints(adminMfaCapableMetricName)); n > 2 {
		t.Errorf("admin mfa-capable series count = %d, want <= 2", n)
	}
}
