package license

import (
	"testing"

	"github.com/google/uuid"
	"github.com/microsoftgraph/msgraph-sdk-go/models"
)

// buildSku constructs a *models.SubscribedSku with the given service plans,
// each as (servicePlanId, servicePlanName, provisioningStatus), mirroring the
// shape a real subscribedSkus response returns.
func buildSku(plans ...[3]string) models.SubscribedSkuable {
	sku := models.NewSubscribedSku()
	var infos []models.ServicePlanInfoable
	for _, p := range plans {
		sp := models.NewServicePlanInfo()
		id := uuid.MustParse(p[0])
		sp.SetServicePlanId(&id)
		name := p[1]
		sp.SetServicePlanName(&name)
		status := p[2]
		sp.SetProvisioningStatus(&status)
		infos = append(infos, sp)
	}
	sku.SetServicePlans(infos)
	return sku
}

// TestFlattenServicePlans verifies the real adapter's flattening logic
// against actual msgraph-sdk-go model types (constructed directly, no
// network) reproduces the exact ServicePlan values Detect expects, across
// multiple SKUs.
func TestFlattenServicePlans(t *testing.T) {
	skus := []models.SubscribedSkuable{
		buildSku(
			[3]string{guidEntraP1, "AAD_PREMIUM", "Success"},
			[3]string{guidIntune, "INTUNE_A", "PendingActivation"},
		),
		buildSku(
			[3]string{guidEntraP2, "AAD_PREMIUM_P2", "Success"},
		),
	}

	got := flattenServicePlans(skus)
	if len(got) != 3 {
		t.Fatalf("flattenServicePlans() returned %d plans, want 3: %+v", len(got), got)
	}

	byID := map[string]ServicePlan{}
	for _, p := range got {
		byID[p.ServicePlanId] = p
	}

	if p, ok := byID[guidEntraP1]; !ok || p.ServicePlanName != "AAD_PREMIUM" || p.ProvisioningStatus != "Success" {
		t.Errorf("flattened entra P1 plan = %+v", p)
	}
	if p, ok := byID[guidIntune]; !ok || p.ProvisioningStatus != "PendingActivation" {
		t.Errorf("flattened intune plan = %+v", p)
	}
	if p, ok := byID[guidEntraP2]; !ok || p.ServicePlanName != "AAD_PREMIUM_P2" {
		t.Errorf("flattened entra P2 plan = %+v", p)
	}
}

// TestFlattenServicePlansHandlesNilFields: a service plan missing its
// optional fields yields zero values, not a panic.
func TestFlattenServicePlansHandlesNilFields(t *testing.T) {
	sku := models.NewSubscribedSku()
	sku.SetServicePlans([]models.ServicePlanInfoable{models.NewServicePlanInfo()})

	got := flattenServicePlans([]models.SubscribedSkuable{sku})
	if len(got) != 1 {
		t.Fatalf("flattenServicePlans() returned %d plans, want 1", len(got))
	}
	if got[0] != (ServicePlan{}) {
		t.Errorf("flattenServicePlans() with all-nil fields = %+v, want zero value", got[0])
	}
}

// TestFlattenServicePlansSkipsNilEntries: nil SKU/service-plan entries in the
// slice (defensive against SDK edge cases) are skipped, not dereferenced.
func TestFlattenServicePlansSkipsNilEntries(t *testing.T) {
	sku := models.NewSubscribedSku()
	sku.SetServicePlans([]models.ServicePlanInfoable{nil})

	got := flattenServicePlans([]models.SubscribedSkuable{nil, sku})
	if len(got) != 0 {
		t.Fatalf("flattenServicePlans() = %+v, want empty", got)
	}
}

// TestNewGraphSkuListerImplementsSkuLister is a compile-time-flavored check
// that the constructor's return type satisfies SkuLister.
func TestNewGraphSkuListerImplementsSkuLister(t *testing.T) {
	_ = NewGraphSkuLister(nil)
}
