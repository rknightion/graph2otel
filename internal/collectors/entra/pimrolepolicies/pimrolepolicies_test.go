package pimrolepolicies

import (
	"context"
	"fmt"
	"testing"

	"github.com/rknightion/graph2otel/internal/collectors"
	"github.com/rknightion/graph2otel/internal/telemetrytest"
)

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

// policy0 is VERBATIM from the m7kni tenant `[live-measured 2026-07-23, #242]`:
// its end-user activation enabledRules are ["Justification"] ONLY — no MFA — and
// approval is not required, the exact worst-case misconfiguration this collector
// exists to surface. Only the rules this collector reads are retained.
const liveAndSyntheticPolicies = `{
  "value": [
    {
      "id": "Directory_4b8c18bd-2f9f-4227-af55-9f1061cf9c32_00a21845-f36e-44de-b57c-2c8f6abf5b64",
      "isOrganizationDefault": false,
      "lastModifiedDateTime": null,
      "rules": [
        {"id": "Enablement_EndUser_Assignment", "enabledRules": ["Justification"]},
        {"id": "Approval_EndUser_Assignment", "setting": {"isApprovalRequired": false, "approvalStages": [{"approvalStageTimeOutInDays": 1}]}},
        {"id": "Expiration_EndUser_Assignment", "isExpirationRequired": true, "maximumDuration": "PT8H"},
        {"id": "Expiration_Admin_Assignment", "isExpirationRequired": false, "maximumDuration": "P180D"},
        {"id": "Expiration_Admin_Eligibility", "isExpirationRequired": false, "maximumDuration": "P365D"},
        {"id": "AuthenticationContext_EndUser_Assignment", "isEnabled": false, "claimValue": null}
      ]
    },
    {
      "id": "policyB",
      "isOrganizationDefault": true,
      "lastModifiedDateTime": "2026-07-01T00:00:00Z",
      "rules": [
        {"id": "Enablement_EndUser_Assignment", "enabledRules": ["MultiFactorAuthentication", "Justification"]},
        {"id": "Approval_EndUser_Assignment", "setting": {"isApprovalRequired": true, "approvalStages": [{"approvalStageTimeOutInDays": 2}]}},
        {"id": "Expiration_EndUser_Assignment", "isExpirationRequired": true, "maximumDuration": "PT4H"},
        {"id": "Expiration_Admin_Assignment", "isExpirationRequired": true, "maximumDuration": "P90D"},
        {"id": "Expiration_Admin_Eligibility", "isExpirationRequired": true, "maximumDuration": "P180D"},
        {"id": "AuthenticationContext_EndUser_Assignment", "isEnabled": true, "claimValue": "c1"}
      ]
    }
  ]
}`

// liveAssignments is VERBATIM from the tenant: policyId -> roleDefinitionId.
const liveAssignments = `{
  "value": [
    {"policyId": "Directory_4b8c18bd-2f9f-4227-af55-9f1061cf9c32_00a21845-f36e-44de-b57c-2c8f6abf5b64", "roleDefinitionId": "92ed04bf-c94a-4b82-9729-b799a7a4c178", "scopeId": "/", "scopeType": "Directory"},
    {"policyId": "policyB", "roleDefinitionId": "role-B-guid", "scopeId": "/", "scopeType": "Directory"}
  ]
}`

func liveGraph() *fakeGraph {
	return &fakeGraph{bodies: map[string]string{
		base + policiesPath:    liveAndSyntheticPolicies,
		base + assignmentsPath: liveAssignments,
	}}
}

func twinFor(rec *telemetrytest.Recorder, roleDefID string) *telemetrytest.LogRecord {
	for _, r := range rec.LogRecords() {
		if r.EventName == eventPolicy && r.Attrs["role_definition_id"] == roleDefID {
			rr := r
			return &rr
		}
	}
	return nil
}

// TestWarnsWhenActivationNeedsNeitherMfaNorApproval pins the whole point: the
// live policy0 (Justification-only, no approval) escalates to WARN.
func TestWarnsWhenActivationNeedsNeitherMfaNorApproval(t *testing.T) {
	rec := telemetrytest.New()
	if err := New(liveGraph(), nil).Collect(context.Background(), rec.Emitter()); err != nil {
		t.Fatalf("Collect: %v", err)
	}
	w := twinFor(rec, "92ed04bf-c94a-4b82-9729-b799a7a4c178")
	if w == nil {
		t.Fatal("no twin for the live policy")
	}
	if w.SeverityText != "WARN" {
		t.Errorf("live policy severity = %q, want WARN (no MFA, no approval)", w.SeverityText)
	}
	b := twinFor(rec, "role-B-guid")
	if b == nil || b.SeverityText != "INFO" {
		t.Errorf("MFA-required policy severity = %v, want INFO", b)
	}
}

// TestTwinCarriesJoinedRoleAndActivationDetail pins the join + the per-policy
// detail the bounded gauge cannot carry.
func TestTwinCarriesJoinedRoleAndActivationDetail(t *testing.T) {
	rec := telemetrytest.New()
	if err := New(liveGraph(), nil).Collect(context.Background(), rec.Emitter()); err != nil {
		t.Fatalf("Collect: %v", err)
	}
	w := twinFor(rec, "92ed04bf-c94a-4b82-9729-b799a7a4c178")
	if w == nil {
		t.Fatal("no twin for the live policy")
	}
	if w.Attrs["activation_enabled_rules"] != "Justification" {
		t.Errorf("activation_enabled_rules = %q, want Justification", w.Attrs["activation_enabled_rules"])
	}
	if w.Attrs["activation_max_duration"] != "PT8H" {
		t.Errorf("activation_max_duration = %q, want PT8H", w.Attrs["activation_max_duration"])
	}
	if w.Attrs["approval_required"] != "false" {
		t.Errorf("approval_required = %q, want false", w.Attrs["approval_required"])
	}
	if w.Attrs["assignment_max_duration"] != "P180D" {
		t.Errorf("assignment_max_duration = %q, want P180D", w.Attrs["assignment_max_duration"])
	}
	if w.Attrs["assignment_expiry_required"] != "false" {
		t.Errorf("assignment_expiry_required = %q, want false", w.Attrs["assignment_expiry_required"])
	}
}

// TestRequirementGaugeCountsAreBounded pins the bounded requirement gauge and
// its cross-policy counts.
func TestRequirementGaugeCountsAreBounded(t *testing.T) {
	rec := telemetrytest.New()
	if err := New(liveGraph(), nil).Collect(context.Background(), rec.Emitter()); err != nil {
		t.Fatalf("Collect: %v", err)
	}
	// key: requirement|enabled|caller -> count
	got := map[string]float64{}
	for _, p := range rec.MetricPoints(metricRequirement) {
		got[p.Attrs["requirement"]+"|"+p.Attrs["enabled"]+"|"+p.Attrs["caller"]] = p.Value
	}
	// mfa_on_activation for end_user: policy0 false, policyB true.
	if got["mfa_on_activation|true|end_user"] != 1 || got["mfa_on_activation|false|end_user"] != 1 {
		t.Errorf("mfa_on_activation/end_user counts wrong: %v", got)
	}
	// approval_required for end_user: policy0 false, policyB true.
	if got["approval_required|true|end_user"] != 1 || got["approval_required|false|end_user"] != 1 {
		t.Errorf("approval_required/end_user counts wrong: %v", got)
	}
	// eligibility_expiry_required only exists for admin caller.
	if got["eligibility_expiry_required|false|admin"] != 1 || got["eligibility_expiry_required|true|admin"] != 1 {
		t.Errorf("eligibility_expiry_required/admin counts wrong: %v", got)
	}
}

func TestNameAndPermissions(t *testing.T) {
	c := New(&fakeGraph{}, nil)
	if c.Name() != "entra.pim_role_policies" {
		t.Errorf("Name = %q", c.Name())
	}
	perms := c.RequiredPermissions()
	if len(perms) != 2 {
		t.Errorf("RequiredPermissions = %v", perms)
	}
}
