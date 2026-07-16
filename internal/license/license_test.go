package license

import (
	"context"
	"errors"
	"testing"
)

// fakeLister is a test-only SkuLister returning a canned plan set or error.
type fakeLister struct {
	plans []ServicePlan
	err   error
}

func (f fakeLister) ListServicePlans(context.Context) ([]ServicePlan, error) {
	return f.plans, f.err
}

func plan(id, name, status string) ServicePlan {
	return ServicePlan{ServicePlanId: id, ServicePlanName: name, ProvisioningStatus: status}
}

// TestDetect covers representative service-plan sets across Free/P1/P2/
// Workload-ID-Premium/Intune and combinations thereof (issue #10 acceptance).
func TestDetect(t *testing.T) {
	tests := []struct {
		name  string
		plans []ServicePlan
		want  Capabilities
	}{
		{
			name:  "free tenant has no recognized service plans",
			plans: []ServicePlan{plan("11111111-1111-1111-1111-111111111111", "SOME_OTHER_PLAN", "Success")},
			want:  Capabilities{},
		},
		{
			name:  "no plans at all",
			plans: nil,
			want:  Capabilities{},
		},
		{
			name:  "entra P1 only",
			plans: []ServicePlan{plan(guidEntraP1, "AAD_PREMIUM", "Success")},
			want:  Capabilities{CapEntraP1: true},
		},
		{
			name:  "entra P2 only",
			plans: []ServicePlan{plan(guidEntraP2, "AAD_PREMIUM_P2", "Success")},
			want:  Capabilities{CapEntraP2: true},
		},
		{
			name:  "workload identities premium only",
			plans: []ServicePlan{plan(guidWorkloadIDPremium, "AAD_WRKLDID_P2", "Success")},
			want:  Capabilities{CapWorkloadIdentitiesPremium: true},
		},
		{
			name:  "intune only",
			plans: []ServicePlan{plan(guidIntune, "INTUNE_A", "Success")},
			want:  Capabilities{CapIntune: true},
		},
		{
			name:  "purview information protection via MIP content label P1 (E3 standard)",
			plans: []ServicePlan{plan(guidMIPContentLabelP1, "MIP_S_CLP1", "Success")},
			want:  Capabilities{CapPurviewInfoProtection: true},
		},
		{
			name:  "purview information protection via MIP content label P2 (E5 premium)",
			plans: []ServicePlan{plan(guidMIPContentLabelP2, "MIP_S_CLP2", "Success")},
			want:  Capabilities{CapPurviewInfoProtection: true},
		},
		{
			name:  "purview records management",
			plans: []ServicePlan{plan(guidRecordsManagement, "RECORDS_MANAGEMENT", "Success")},
			want:  Capabilities{CapPurviewRecordsMgmt: true},
		},
		{
			name: "purview info protection + records management together (E5 compliance shape)",
			plans: []ServicePlan{
				plan(guidMIPContentLabelP2, "MIP_S_CLP2", "Success"),
				plan(guidRecordsManagement, "RECORDS_MANAGEMENT", "Success"),
			},
			want: Capabilities{CapPurviewInfoProtection: true, CapPurviewRecordsMgmt: true},
		},
		{
			name: "P1 + Intune but not P2 (a real non-linear combination)",
			plans: []ServicePlan{
				plan(guidEntraP1, "AAD_PREMIUM", "Success"),
				plan(guidIntune, "INTUNE_A", "Success"),
			},
			want: Capabilities{CapEntraP1: true, CapIntune: true},
		},
		{
			name: "all four capabilities",
			plans: []ServicePlan{
				plan(guidEntraP1, "AAD_PREMIUM", "Success"),
				plan(guidEntraP2, "AAD_PREMIUM_P2", "Success"),
				plan(guidWorkloadIDPremium, "AAD_WRKLDID_P2", "Success"),
				plan(guidIntune, "INTUNE_A", "Success"),
			},
			want: Capabilities{CapEntraP1: true, CapEntraP2: true, CapWorkloadIdentitiesPremium: true, CapIntune: true},
		},
		{
			name:  "a recognized plan not yet provisioned does not count",
			plans: []ServicePlan{plan(guidEntraP2, "AAD_PREMIUM_P2", "PendingActivation")},
			want:  Capabilities{},
		},
		{
			name:  "disabled plan does not count",
			plans: []ServicePlan{plan(guidIntune, "INTUNE_A", "Disabled")},
			want:  Capabilities{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := Detect(context.Background(), fakeLister{plans: tt.plans})
			if err != nil {
				t.Fatalf("Detect: unexpected error: %v", err)
			}
			if len(got) != len(tt.want) {
				t.Fatalf("Detect() = %v, want %v", got, tt.want)
			}
			for c := range tt.want {
				if !got.Has(c) {
					t.Errorf("Detect() missing capability %v, got %v", c, got)
				}
			}
		})
	}
}

// TestDetectListerError verifies that a lister failure degrades gracefully:
// Detect returns an empty (Free) capability set plus a wrapped error, and
// never panics.
func TestDetectListerError(t *testing.T) {
	caps, err := Detect(context.Background(), fakeLister{err: errors.New("graph unavailable")})
	if err == nil {
		t.Fatal("expected an error from a failing lister")
	}
	if len(caps) != 0 {
		t.Errorf("Detect() on lister error = %v, want empty set", caps)
	}
}

// TestCapabilitiesHas exercises the Has method directly, including on a nil
// map (must not panic).
func TestCapabilitiesHas(t *testing.T) {
	var nilCaps Capabilities
	if nilCaps.Has(CapEntraP1) {
		t.Error("nil Capabilities.Has() = true, want false")
	}

	caps := Capabilities{CapEntraP1: true}
	if !caps.Has(CapEntraP1) {
		t.Error("Has(CapEntraP1) = false, want true")
	}
	if caps.Has(CapEntraP2) {
		t.Error("Has(CapEntraP2) = true, want false")
	}
}

// entraP2Collector is a fake collector declaring it needs CapEntraP2 (the
// shape of a real Identity-Protection collector like risky-users).
type entraP2Collector struct{}

func (entraP2Collector) RequiredCapability() Capability { return CapEntraP2 }

// entraP1Collector is a fake collector declaring it needs CapEntraP1 (the
// shape of a real sign-in-log collector).
type entraP1Collector struct{}

func (entraP1Collector) RequiredCapability() Capability { return CapEntraP1 }

// ungatedCollector implements no license requirement at all (e.g. directory
// objects, available on every tier).
type ungatedCollector struct{}

// TestShouldRunGatesOnMissingCapability: a collector requiring CapEntraP2 is
// gated OUT for a P1-only tenant and IN for a P2 tenant.
func TestShouldRunGatesOnMissingCapability(t *testing.T) {
	p1Only := Capabilities{CapEntraP1: true}
	if ok, cap, has := ShouldRun(entraP2Collector{}, p1Only); ok || has || cap != CapEntraP2 {
		t.Errorf("ShouldRun(P2-collector, P1-only) = (%v, %v, %v), want (false, %v, false)", ok, cap, has, CapEntraP2)
	}

	p2 := Capabilities{CapEntraP1: true, CapEntraP2: true}
	if ok, cap, has := ShouldRun(entraP2Collector{}, p2); !ok || !has || cap != CapEntraP2 {
		t.Errorf("ShouldRun(P2-collector, P2-tenant) = (%v, %v, %v), want (true, %v, true)", ok, cap, has, CapEntraP2)
	}
}

// TestShouldRunSkipsGatedCollectorOnFreeTenant: a sign-in-style collector
// requiring CapEntraP1 is skipped on a Free (empty caps) tenant.
func TestShouldRunSkipsGatedCollectorOnFreeTenant(t *testing.T) {
	free := Capabilities{}
	ok, cap, has := ShouldRun(entraP1Collector{}, free)
	if ok || has {
		t.Errorf("ShouldRun(P1-collector, free tenant) = (%v, _, %v), want ok=false has=false", ok, has)
	}
	if cap != CapEntraP1 {
		t.Errorf("ShouldRun requiredCap = %v, want %v", cap, CapEntraP1)
	}
}

// TestShouldRunUngatedCollectorAlwaysRuns: a collector that does not
// implement CapabilityRequirer has no license requirement.
func TestShouldRunUngatedCollectorAlwaysRuns(t *testing.T) {
	ok, _, has := ShouldRun(ungatedCollector{}, Capabilities{})
	if !ok {
		t.Error("ShouldRun(ungated collector, free tenant) ok = false, want true")
	}
	if has {
		t.Error("ShouldRun(ungated collector) has = true, want false (no requirement declared)")
	}
}

func TestIsInsufficientData(t *testing.T) {
	if IsInsufficientData(nil) {
		t.Error("IsInsufficientData(nil) = true, want false")
	}
	if IsInsufficientData(errors.New("boom")) {
		t.Error("IsInsufficientData(plain error) = true, want false")
	}
	if !IsInsufficientData(errors.New("Report is not ready. Reason: insufficientData")) {
		t.Error("IsInsufficientData(insufficientData error) = false, want true")
	}
	if !IsInsufficientData(errors.New("INSUFFICIENTDATA")) {
		t.Error("IsInsufficientData is expected to be case-insensitive")
	}
}
