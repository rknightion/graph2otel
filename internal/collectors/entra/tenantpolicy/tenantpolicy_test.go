package tenantpolicy

import (
	"context"
	"errors"
	"fmt"
	"testing"

	"github.com/rknightion/graph2otel/internal/collectors"
	"github.com/rknightion/graph2otel/internal/telemetrytest"
)

// fakeGraph maps request URLs to canned response bodies (or errors).
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
		return nil, fmt.Errorf("fakeGraph: no body stubbed for %s", url)
	}
	return []byte(body), nil
}

var _ collectors.GraphClient = (*fakeGraph)(nil)

const base = "https://graph.microsoft.com/v1.0"

// The three data-bearing bodies below are VERBATIM captures from the m7kni
// tenant, read as graph2otel-poller `[live-measured 2026-07-23, #245]`.
const liveAuthorizationPolicy = `{
  "id": "authorizationPolicy",
  "allowInvitesFrom": "adminsAndGuestInviters",
  "allowedToSignUpEmailBasedSubscriptions": true,
  "allowedToUseSSPR": true,
  "allowEmailVerifiedUsersToJoinOrganization": false,
  "allowUserConsentForRiskyApps": false,
  "blockMsolPowerShell": false,
  "guestUserRoleId": "10dae51f-b6af-4016-8d66-8c2a99b929b3",
  "defaultUserRolePermissions": {
    "allowedToCreateApps": false,
    "allowedToCreateSecurityGroups": false,
    "allowedToCreateTenants": true,
    "allowedToReadOtherUsers": true,
    "permissionGrantPoliciesAssigned": [
      "ManagePermissionGrantsForSelf.microsoft-user-default-recommended"
    ]
  }
}`

const liveAdminConsentRequestPolicy = `{
  "isEnabled": true,
  "notifyReviewers": true,
  "requestDurationInDays": 30,
  "reviewers": [
    {"query": "/v1.0/users/bbcfc3c5-0b93-4135-9ef9-18477a9fb504", "queryType": "MicrosoftGraph"}
  ]
}`

const liveDefaultAppManagementPolicy = `{
  "id": "00000000-0000-0000-0000-000000000000",
  "isEnabled": true,
  "applicationRestrictions": {
    "passwordCredentials": [],
    "keyCredentials": []
  }
}`

const emptyCollection = `{"value": []}`

func liveGraph() *fakeGraph {
	return &fakeGraph{bodies: map[string]string{
		base + "/policies/authorizationPolicy":        liveAuthorizationPolicy,
		base + "/policies/adminConsentRequestPolicy":  liveAdminConsentRequestPolicy,
		base + "/policies/defaultAppManagementPolicy": liveDefaultAppManagementPolicy,
		base + "/policies/appManagementPolicies":      emptyCollection,
		base + "/groupLifecyclePolicies":              emptyCollection,
		base + "/policies/featureRolloutPolicies":     emptyCollection,
	}}
}

func settingMap(t *testing.T, rec *telemetrytest.Recorder) map[string]float64 {
	t.Helper()
	out := map[string]float64{}
	for _, p := range rec.MetricPoints(metricSetting) {
		out[p.Attrs["setting"]] = p.Value
	}
	return out
}

// TestSettingsMapFromLiveWire pins each 0/1 setting against the verbatim wire.
func TestSettingsMapFromLiveWire(t *testing.T) {
	rec := telemetrytest.New()
	if err := New(liveGraph(), nil).Collect(context.Background(), rec.Emitter()); err != nil {
		t.Fatalf("Collect: %v", err)
	}
	got := settingMap(t, rec)
	want := map[string]float64{
		"users_can_create_apps":               0, // allowedToCreateApps false
		"users_can_create_security_groups":    0,
		"users_can_create_tenants":            1,
		"users_can_read_other_users":          1,
		"guest_invite_restricted":             1, // allowInvitesFrom != everyone
		"msol_powershell_blocked":             0,
		"user_consent_for_risky_apps_allowed": 0,
		"sspr_allowed":                        1,
		"email_verified_join_allowed":         0,
		"admin_consent_workflow_enabled":      1,
		"app_management_policy_enabled":       1,
		"app_password_credentials_restricted": 0, // empty passwordCredentials array
	}
	for k, v := range want {
		if got[k] != v {
			t.Errorf("setting %s = %v, want %v", k, got[k], v)
		}
	}
	if len(got) != len(want) {
		t.Errorf("emitted %d settings, want %d: %v", len(got), len(want), got)
	}
}

// TestGuestInviteRestrictedFlipsWhenEveryone pins the derived boolean: an
// everyone-can-invite tenant is unrestricted (0).
func TestGuestInviteRestrictedFlipsWhenEveryone(t *testing.T) {
	g := liveGraph()
	g.bodies[base+"/policies/authorizationPolicy"] = `{"allowInvitesFrom":"everyone","defaultUserRolePermissions":{}}`
	rec := telemetrytest.New()
	if err := New(g, nil).Collect(context.Background(), rec.Emitter()); err != nil {
		t.Fatalf("Collect: %v", err)
	}
	if settingMap(t, rec)["guest_invite_restricted"] != 0 {
		t.Error("guest_invite_restricted should be 0 when allowInvitesFrom=everyone")
	}
}

// TestTwinCarriesRawFields pins the twin: the guest role GUID and raw enum a 0/1
// gauge cannot express.
func TestTwinCarriesRawFields(t *testing.T) {
	rec := telemetrytest.New()
	if err := New(liveGraph(), nil).Collect(context.Background(), rec.Emitter()); err != nil {
		t.Fatalf("Collect: %v", err)
	}
	var twin *telemetrytest.LogRecord
	for _, r := range rec.LogRecords() {
		if r.EventName == eventTenantPolicy {
			rr := r
			twin = &rr
		}
	}
	if twin == nil {
		t.Fatal("no entra.tenant_policy twin emitted")
	}
	if twin.Attrs["guest_user_role_id"] != "10dae51f-b6af-4016-8d66-8c2a99b929b3" {
		t.Errorf("guest_user_role_id = %q", twin.Attrs["guest_user_role_id"])
	}
	if twin.Attrs["allow_invites_from"] != "adminsAndGuestInviters" {
		t.Errorf("allow_invites_from = %q", twin.Attrs["allow_invites_from"])
	}
	if twin.Attrs["admin_consent_reviewer_count"] != "1" {
		t.Errorf("admin_consent_reviewer_count = %q, want 1", twin.Attrs["admin_consent_reviewer_count"])
	}
	if twin.Attrs["admin_consent_request_duration_days"] != "30" {
		t.Errorf("admin_consent_request_duration_days = %q, want 30", twin.Attrs["admin_consent_request_duration_days"])
	}
}

// TestScopedPolicyCounts pins the count gauge over the three empty collections.
func TestScopedPolicyCounts(t *testing.T) {
	rec := telemetrytest.New()
	if err := New(liveGraph(), nil).Collect(context.Background(), rec.Emitter()); err != nil {
		t.Fatalf("Collect: %v", err)
	}
	got := map[string]float64{}
	for _, p := range rec.MetricPoints(metricScopedPolicies) {
		got[p.Attrs["kind"]] = p.Value
	}
	want := map[string]float64{"app_management": 0, "group_lifecycle": 0, "feature_rollout": 0}
	if len(got) != 3 {
		t.Fatalf("scoped policy kinds = %v, want 3", got)
	}
	for k, v := range want {
		if got[k] != v {
			t.Errorf("scoped %s = %v, want %v", k, got[k], v)
		}
	}
}

// TestResilientToOneSingletonFailure pins that a failure of one singleton does
// not prevent the others' settings from emitting.
func TestResilientToOneSingletonFailure(t *testing.T) {
	g := liveGraph()
	g.errs = map[string]error{base + "/policies/adminConsentRequestPolicy": errors.New("throttled")}
	rec := telemetrytest.New()
	err := New(g, nil).Collect(context.Background(), rec.Emitter())
	if err == nil {
		t.Fatal("expected the adminConsentRequestPolicy failure surfaced as an error")
	}
	got := settingMap(t, rec)
	if got["users_can_create_apps"] != 0 {
		t.Error("authorizationPolicy settings should still emit despite the consent-policy failure")
	}
	if _, ok := got["admin_consent_workflow_enabled"]; ok {
		t.Error("admin_consent_workflow_enabled must be absent when its fetch failed")
	}
}

func TestNameAndPermissions(t *testing.T) {
	c := New(&fakeGraph{}, nil)
	if c.Name() != "entra.tenant_policy" {
		t.Errorf("Name = %q", c.Name())
	}
	if perms := c.RequiredPermissions(); len(perms) != 1 || perms[0] != "Policy.Read.All" {
		t.Errorf("RequiredPermissions = %v", perms)
	}
}
