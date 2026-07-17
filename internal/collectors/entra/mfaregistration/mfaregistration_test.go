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

// liveUsers is the four VERBATIM userRegistrationDetails records the m7kni
// tenant returned from GET /reports/authenticationMethods/userRegistrationDetails,
// read as graph2otel-poller on 2026-07-17 `[live-measured 2026-07-17, #165]`.
// Each record is exactly the field set the collector's own request returns:
// requestPath pins $select to the twelve fields below, so this fixture is what
// THIS collector sees on the wire, not an unfiltered dump. Nothing is trimmed,
// rounded, or scrubbed within that set — the real UPNs, display names and
// timestamps are pinned as the wire sent them, because a hand-written fixture is
// the bug #165 exists to remove: the previous version was Microsoft's own doc
// placeholders (alice@example.com / Alice Example / dave-admin@example.com),
// which can only confirm the author's belief and never fail — the same
// `"platform":"windows"` / invented-`riskType` failure as #142/#153.
//
// Spread: one non-admin member (juraj), one admin GUEST (peter), and two
// admin members with passwordless (rob, emergency). All four are MFA-capable
// and MFA-registered on this real tenant, so NO live row exercises the
// admin-without-MFA-capability warn path — that severity escalation is covered
// synthetically by TestLogTwinSeverityAdminWithoutMfaCapableWarns, which drives
// logTwin directly rather than through this fixture.
//
// FINDING (#173): the endpoint offers four fields the collector's $select does
// NOT request — isSystemPreferredAuthenticationMethodEnabled,
// systemPreferredAuthenticationMethods,
// userPreferredMethodForSecondaryAuthentication, and userType. They are absent
// here because a $select response never carries them; an unfiltered probe
// confirmed they exist and populate (userType being member/guest is the
// standout — it would let every MFA-posture question slice member vs guest).
// Adding them is a $select + struct change, filed as #173, not #165's
// fixture-provenance scope.
const liveUsers = `
{"id":"61851b42-fef7-4b43-ae43-4e335a60b306","isAdmin":false,"isMfaCapable":true,"isMfaRegistered":true,"isPasswordlessCapable":false,"isSsprCapable":true,"isSsprEnabled":true,"isSsprRegistered":true,"lastUpdatedDateTime":"2026-07-16T03:16:01.7292271Z","methodsRegistered":["email","microsoftAuthenticatorPush","softwareOneTimePasscode"],"userDisplayName":"Juraj Michalek (babe)","userPrincipalName":"juraj@m7kni.io"},
{"id":"e755e472-f2eb-4ea6-829d-5a908600fdb1","isAdmin":true,"isMfaCapable":true,"isMfaRegistered":true,"isPasswordlessCapable":false,"isSsprCapable":true,"isSsprEnabled":true,"isSsprRegistered":true,"lastUpdatedDateTime":"2026-07-16T03:16:01.7570479Z","methodsRegistered":["microsoftAuthenticatorPush","softwareOneTimePasscode"],"userDisplayName":"Peter Hewitt","userPrincipalName":"peter.hewitt_grafana.com#EXT#@m7knio.onmicrosoft.com"},
{"id":"bbcfc3c5-0b93-4135-9ef9-18477a9fb504","isAdmin":true,"isMfaCapable":true,"isMfaRegistered":true,"isPasswordlessCapable":true,"isSsprCapable":true,"isSsprEnabled":true,"isSsprRegistered":true,"lastUpdatedDateTime":"2026-07-17T12:33:37.9223339Z","methodsRegistered":["email","macOsSecureEnclaveKey","windowsHelloForBusiness","passKeySynced","microsoftAuthenticatorPasswordless","passKeyDeviceBoundAuthenticator","passKeyDeviceBound","microsoftAuthenticatorPush","softwareOneTimePasscode"],"userDisplayName":"Rob Knight","userPrincipalName":"rob@m7kni.io"},
{"id":"c55ddc8b-52ee-44c6-a0bc-b388be43cd2f","isAdmin":true,"isMfaCapable":true,"isMfaRegistered":true,"isPasswordlessCapable":true,"isSsprCapable":true,"isSsprEnabled":true,"isSsprRegistered":true,"lastUpdatedDateTime":"2026-07-16T03:16:01.7301508Z","methodsRegistered":["passKeyDeviceBound","microsoftAuthenticatorPasswordless","passKeyDeviceBoundAuthenticator","mobilePhone","microsoftAuthenticatorPush","softwareOneTimePasscode"],"userDisplayName":"emergency","userPrincipalName":"emergency@m7knio.onmicrosoft.com"}
`

func page(usersJSON string) string {
	return `{"value":[` + usersJSON + `]}`
}

func fullFixture() map[string]string {
	return map[string]string{
		requestURL: page(liveUsers),
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
	// Counts over the four live rows: every user is MFA-registered/capable
	// and fully SSPR-enrolled on this real tenant; only rob + emergency are
	// passwordless-capable.
	want := map[string]float64{
		"mfa_registered":       4,
		"mfa_capable":          4,
		"sspr_registered":      4,
		"sspr_enabled":         4,
		"sspr_capable":         4,
		"passwordless_capable": 2,
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
	// Method counts over the four live rows. A user counts toward each method
	// it registered, so these overlap; the passwordless/passkey spread comes
	// from rob + emergency.
	want := map[string]float64{
		"email":                              2,
		"microsoftAuthenticatorPush":         4,
		"softwareOneTimePasscode":            4,
		"macOsSecureEnclaveKey":              1,
		"windowsHelloForBusiness":            1,
		"passKeySynced":                      1,
		"microsoftAuthenticatorPasswordless": 2,
		"passKeyDeviceBoundAuthenticator":    2,
		"passKeyDeviceBound":                 2,
		"mobilePhone":                        1,
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
	// Of the MFA-capable users, three are admins (peter, rob, emergency) and
	// one is a non-admin member (juraj).
	want := map[string]float64{"true": 3, "false": 1}
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
	if len(got) != 4 {
		t.Fatalf("emitted %d %s logs, want 4 (one per user, including posture successes)", len(got), eventUserRegistration)
	}
}

// TestCollectEmitsUserRegistrationLogTwinAttrs drives the four LIVE
// userRegistrationDetails rows all the way through the collector into a
// Recorder — not just into the mapper — and pins the per-user detail the
// bounded metrics can never carry (identity, timestamp, every posture flag as
// a string) on the one non-admin member, juraj@m7kni.io. This is the
// end-to-end path that keeps testdata/signals.json honest: the golden is the
// union of what a package's tests EMIT, so the live record must reach the
// emitter, not stop at mapRow.
func TestCollectEmitsUserRegistrationLogTwinAttrs(t *testing.T) {
	g := &fakeGraph{bodies: fullFixture()}
	rec := telemetrytest.New()

	if err := New(g, nil).Collect(context.Background(), rec.Emitter()); err != nil {
		t.Fatalf("Collect: %v", err)
	}

	got := logsNamed(rec.LogRecords(), eventUserRegistration)
	const jurajID = "61851b42-fef7-4b43-ae43-4e335a60b306"
	var juraj *telemetrytest.LogRecord
	for i := range got {
		if got[i].Attrs["id"] == jurajID {
			juraj = &got[i]
		}
	}
	if juraj == nil {
		t.Fatalf("no log for user %s; got %v", jurajID, got)
	}

	want := map[string]string{
		"id":                   jurajID,
		"user_principal_name":  "juraj@m7kni.io",
		"user_display_name":    "Juraj Michalek (babe)",
		"last_updated":         "2026-07-16T03:16:01.7292271Z",
		"is_admin":             "false",
		"mfa_registered":       "true",
		"mfa_capable":          "true",
		"sspr_registered":      "true",
		"sspr_enabled":         "true",
		"sspr_capable":         "true",
		"passwordless_capable": "false",
		"methods_registered":   "email,microsoftAuthenticatorPush,softwareOneTimePasscode",
	}
	for k, v := range want {
		if juraj.Attrs[k] != v {
			t.Errorf("user registration log attr %q = %q, want %q", k, juraj.Attrs[k], v)
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
