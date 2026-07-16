// Package license detects, per tenant, which premium Microsoft Entra ID and
// Intune licensing capabilities are active — and lets the composition root
// gracefully skip an optional collector that needs a capability the tenant
// doesn't hold, instead of hard-failing the whole process.
//
// # Why a set, not a tier
//
// Entra ID and Intune licenses do not compose into a single linear ladder: a
// tenant can hold Entra ID P1 plus Intune without P2, or P2 without Workload
// Identities Premium. Capabilities is therefore a SET (Capability -> bool),
// never an ordinal "tier N and below" comparison. "Free" is the empty set.
//
// # Wiring pattern for the composition root
//
// At startup, per tenant: build a SkuLister (NewGraphSkuLister, real Graph
// client) and call Detect once. Then, for each candidate collector before
// registering it with the collector.Registry, call ShouldRun(collector,
// caps). When it returns ok=false, do not register the collector for that
// tenant — log SkipReason(collector.Name(), tenantID, requiredCap) at info
// level and move on. A collector with no license requirement (ShouldRun's
// ok=true, has=false) always registers. Detection failure must never abort
// startup: Detect degrades to an empty (Free) capability set on error, which
// simply gates out every premium collector for that tenant until the next
// successful detection.
package license

import (
	"context"
	"fmt"
	"strings"
)

// Capability identifies one premium licensing capability that can gate an
// optional collector.
type Capability string

const (
	// CapEntraP1 is Microsoft Entra ID P1 (service plan AAD_PREMIUM).
	CapEntraP1 Capability = "entra_p1"
	// CapEntraP2 is Microsoft Entra ID P2 (service plan AAD_PREMIUM_P2) —
	// required for Identity Protection endpoints (risky users, risk
	// detections).
	CapEntraP2 Capability = "entra_p2"
	// CapWorkloadIdentitiesPremium is Microsoft Entra Workload ID Premium
	// (service plan AAD_WRKLDID_P2) — required for workload identity
	// sign-in/risk analytics.
	CapWorkloadIdentitiesPremium Capability = "workload_identities_premium"
	// CapIntune is Microsoft Intune (service plan INTUNE_A) — required for
	// device compliance and Intune reporting endpoints.
	CapIntune Capability = "intune"
	// CapPurviewInfoProtection is Microsoft Purview Information Protection
	// (sensitivity labels) — granted by the MIP content-label service plans
	// MIP_S_CLP1 ("Information Protection for Office 365 - Standard", E3-level)
	// or MIP_S_CLP2 ("... - Premium", E5-level). Required to read the tenant's
	// sensitivity-label catalog via
	// /security/dataSecurityAndGovernance/sensitivityLabels.
	CapPurviewInfoProtection Capability = "purview_information_protection"
	// CapPurviewRecordsMgmt is Microsoft Purview Records Management (service
	// plan RECORDS_MANAGEMENT) — required to read the tenant's retention-label
	// catalog via /security/labels/retentionLabels and the retention event
	// types via /security/triggerTypes/retentionEventTypes.
	CapPurviewRecordsMgmt Capability = "purview_records_management"
)

// The canonical service-plan GUIDs backing servicePlanCapability, exported as
// named constants so tests and callers can refer to them without repeating
// the raw strings. Values verified against Microsoft's "Product names and
// service plan identifiers for licensing" reference (see the doc comment on
// servicePlanCapability below for the source and fetch date).
const (
	guidEntraP1           = "41781fb2-bc02-4b7c-bd55-b576c07bb09d" // AAD_PREMIUM
	guidEntraP2           = "eec0eb4f-6444-4f95-aba0-50c24d67f998" // AAD_PREMIUM_P2
	guidWorkloadIDPremium = "7dc0e92d-bf15-401d-907e-0884efe7c760" // AAD_WRKLDID_P2
	guidIntune            = "c1ec4a95-1f05-45b3-a911-aa3fa01094f5" // INTUNE_A
	// guidMIPContentLabelP1/P2 are the two Microsoft Information Protection
	// content-label service plans; either one grants CapPurviewInfoProtection
	// (a tenant licensed at E5 holds both, at E3 only P1). Friendly names in
	// the licensing reference: "Information Protection for Office 365 -
	// Standard" (P1) / "- Premium" (P2).
	guidMIPContentLabelP1 = "5136a095-5cf0-4aff-bec3-e84448b38ea5" // MIP_S_CLP1
	guidMIPContentLabelP2 = "efb0351d-3b08-4503-993d-383af8de41e3" // MIP_S_CLP2
	guidRecordsManagement = "65cc641f-cccd-4643-97e0-a17e3045e541" // RECORDS_MANAGEMENT
)

// servicePlanCapability maps a Microsoft Graph service-plan GUID
// (subscribedSku.servicePlans[].servicePlanId) to the graph2otel Capability
// it grants. A package-level var, not a const map, so it is easy to extend or
// correct as Microsoft adds service plans.
//
// Source: Microsoft's "Product names and service plan identifiers for
// licensing" reference,
// https://learn.microsoft.com/en-us/entra/identity/users/licensing-service-plan-reference
// (fetched 2026-07-15), cross-checked against the raw reference markdown at
// https://raw.githubusercontent.com/MicrosoftDocs/entra-docs/main/docs/identity/users/licensing-service-plan-reference.md.
// The Workload Identities Premium GUID (AAD_WRKLDID_P2) was confirmed from
// two independent rows in that table: the "Microsoft Entra Workload ID" SKU
// and the "Workload Identities Premium" bundle SKU both list service plan
// AAD_WRKLDID_P2 = 7dc0e92d-bf15-401d-907e-0884efe7c760, friendly name
// "Microsoft Entra Workload ID P2". Service-plan GUIDs are stable identifiers
// Microsoft documents as safe to hardcode; they do not change when a SKU is
// renamed or repackaged around them.
var servicePlanCapability = map[string]Capability{
	guidEntraP1:           CapEntraP1,
	guidEntraP2:           CapEntraP2,
	guidWorkloadIDPremium: CapWorkloadIdentitiesPremium,
	guidIntune:            CapIntune,
	// Both MIP content-label plans map to the one InfoProtection capability:
	// reading the sensitivity-label catalog needs the entitlement, not a
	// specific P1-vs-P2 tier.
	guidMIPContentLabelP1: CapPurviewInfoProtection,
	guidMIPContentLabelP2: CapPurviewInfoProtection,
	guidRecordsManagement: CapPurviewRecordsMgmt,
}

// provisioningStatusEnabled is the subscribedSkus servicePlanInfo
// provisioningStatus value meaning the plan is actually active for the
// tenant. Per the Microsoft Graph servicePlanInfo resource docs
// (https://learn.microsoft.com/en-us/graph/api/resources/serviceplaninfo),
// this field's possible values include "Success" (active), "Disabled", and
// "PendingInput"/"PendingActivation"/"PendingProvisioning" (not yet active) —
// "Success" is the value that means enabled, not "Enabled". Only "Success"
// plans grant their Capability; a purchased-but-not-yet-provisioned plan must
// not unlock a collector prematurely.
const provisioningStatusEnabled = "Success"

// Capabilities is the SET of premium capabilities detected for a tenant. The
// empty set is "Free" tier: no premium capability is present, so every
// capability-gated collector is skipped, but ungated collectors still run.
type Capabilities map[Capability]bool

// Has reports whether cap is present in the set. Safe to call on a nil map.
func (c Capabilities) Has(cap Capability) bool {
	return c[cap]
}

// ServicePlan is one service-plan entry read from a tenant's subscribedSkus,
// the shape Detect consumes. Fields mirror
// models.ServicePlanInfoable (ServicePlanId, ServicePlanName,
// ProvisioningStatus) so the real adapter (see graphclient_adapter.go) can
// flatten Graph API responses into it, while tests construct fakes without
// depending on the Graph SDK.
type ServicePlan struct {
	ServicePlanId      string
	ServicePlanName    string
	ProvisioningStatus string
}

// SkuLister reads a tenant's licensed service plans. Implemented by the real
// Graph-backed adapter (NewGraphSkuLister) and, in tests, by a fake — this
// abstraction is what keeps Detect's mapping logic unit-testable without a
// live Graph client.
type SkuLister interface {
	ListServicePlans(ctx context.Context) ([]ServicePlan, error)
}

// Detect reads lister's service plans and returns the Capabilities they
// grant. Only plans with ProvisioningStatus == "Success" are considered (see
// provisioningStatusEnabled); an unrecognized service-plan GUID is silently
// ignored, since new SKUs graph2otel doesn't yet map should never break
// detection for the ones it does.
//
// A lister error degrades gracefully: Detect returns an empty (Free)
// Capabilities set alongside the wrapped error, rather than propagating a nil
// map. Callers should log the returned error but keep running with the empty
// set — a transient Graph failure (throttling, an expired token) must gate
// premium collectors off rather than block startup or panic.
func Detect(ctx context.Context, lister SkuLister) (Capabilities, error) {
	caps := Capabilities{}

	plans, err := lister.ListServicePlans(ctx)
	if err != nil {
		return caps, fmt.Errorf("license: list service plans: %w", err)
	}

	for _, p := range plans {
		if p.ProvisioningStatus != provisioningStatusEnabled {
			continue
		}
		if cap, ok := servicePlanCapability[p.ServicePlanId]; ok {
			caps[cap] = true
		}
	}
	return caps, nil
}

// CapabilityRequirer is optionally implemented by a collector to declare the
// single premium Capability it needs in order to run. A collector that does
// not implement this interface has no license requirement and always runs,
// on every tier.
type CapabilityRequirer interface {
	RequiredCapability() Capability
}

// ShouldRun reports whether collector c may run for a tenant holding caps.
//
//   - c does not implement CapabilityRequirer: no license requirement was
//     declared, so ok=true always; requiredCap is the zero Capability and
//     has=false (nothing was checked).
//   - c implements CapabilityRequirer: ok and has both report
//     caps.Has(requiredCap), where requiredCap is c.RequiredCapability().
//
// The composition root calls ShouldRun once per candidate collector per
// tenant at registration time and must never register a collector for which
// it returns ok=false — see the package doc for the full wiring pattern.
func ShouldRun(c any, caps Capabilities) (ok bool, requiredCap Capability, has bool) {
	req, gated := c.(CapabilityRequirer)
	if !gated {
		return true, "", false
	}
	requiredCap = req.RequiredCapability()
	has = caps.Has(requiredCap)
	return has, requiredCap, has
}

// SkipReason renders the log line the composition root should emit when
// ShouldRun reports ok=false for collectorName against tenantID, e.g.
// "skipping collector risky_users for tenant 11111111-...: requires
// entra_p2".
func SkipReason(collectorName, tenantID string, requiredCap Capability) string {
	return fmt.Sprintf("skipping collector %s for tenant %s: requires %s", collectorName, tenantID, requiredCap)
}

// IsInsufficientData reports whether err represents the Intune reporting
// workload's "insufficientData" response — returned for a fresh or very
// small tenant that has not yet accumulated enough device/compliance data for
// the requested report. This is expected, not a failure: a WindowCollector or
// SnapshotCollector hitting an Intune reports-export endpoint should treat a
// true result as "capability present but data not yet available" and defer
// (skip this tick's emission, keep its checkpoint unchanged) rather than
// count it as a collector error.
//
// The match is a case-insensitive substring check against err's message,
// since the SDK surfaces this condition as free-text inside the export job's
// status/error payload rather than as a distinct typed error.
func IsInsufficientData(err error) bool {
	if err == nil {
		return false
	}
	return strings.Contains(strings.ToLower(err.Error()), "insufficientdata")
}
