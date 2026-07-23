// Package pimrolepolicies is the Entra PIM role-activation policy collector
// (#242). entra.roles answers "who holds what"; this answers "what does it take
// to get it" — the single most consequential class of Entra misconfiguration
// (a Global Administrator eligible assignment that activates on justification
// alone, with no MFA and no approval) and one invisible in every other signal
// graph2otel ships.
//
// # Bounded gauge, one twin per policy
//
// From roleManagementPolicies?$expand=rules the collector reads each policy's
// activation rules and emits ONE bounded gauge, entra.pim.role_policy.requirement,
// counting policies by (requirement, enabled, caller) — a fixed ~24-series set,
// independent of the role catalog. The per-policy detail a bounded count
// cannot express — the role GUID, the exact enabled-rule list, the durations —
// rides one entra.pim_role_policy log twin (#114), which Warns when a policy
// allows activation with neither MFA nor approval.
//
// role_definition_id is joined from roleManagementPolicyAssignments (policyId ->
// roleDefinitionId). The human role display name is NOT resolved here: it needs
// a separate roleDefinitions fetch and the GUID is a stable join key; resolution
// is deferred, and the twin carries the GUID.
package pimrolepolicies

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"slices"
	"strings"
	"time"

	"github.com/rknightion/graph2otel/internal/collector"
	"github.com/rknightion/graph2otel/internal/collectors"
	"github.com/rknightion/graph2otel/internal/semconv"
	"github.com/rknightion/graph2otel/internal/telemetry"
)

const collectorName = "entra.pim_role_policies"

const metricRequirement = "entra.pim.role_policy.requirement"

const eventPolicy = "entra.pim_role_policy"

const defaultBaseURL = "https://graph.microsoft.com/v1.0"

// The directory-scope filter both endpoints share. $expand=rules inlines the
// activation rules on each policy (17 per policy live).
const (
	policiesPath    = "/policies/roleManagementPolicies?$filter=scopeId+eq+'/'+and+scopeType+eq+'Directory'&$expand=rules"
	assignmentsPath = "/policies/roleManagementPolicyAssignments?$filter=scopeId+eq+'/'+and+scopeType+eq+'Directory'"
)

// Rule id constants — the rules whose settings this collector reads. PIM names
// each rule deterministically by (kind, caller, operation).
const (
	ruleEnableEndUser   = "Enablement_EndUser_Assignment"
	ruleEnableAdmin     = "Enablement_Admin_Assignment"
	ruleApprovalEndUser = "Approval_EndUser_Assignment"
	ruleExpiryEndUser   = "Expiration_EndUser_Assignment"
	ruleExpiryAdmin     = "Expiration_Admin_Assignment"
	ruleExpiryAdminElig = "Expiration_Admin_Eligibility"
	ruleAuthCtxEndUser  = "AuthenticationContext_EndUser_Assignment"
)

const (
	callerEndUser = "end_user"
	callerAdmin   = "admin"
)

// Collector polls the directory-scope PIM role-management policies.
type Collector struct {
	g       collectors.GraphClient
	baseURL string
	logger  *slog.Logger
}

// New builds the PIM role-policy collector. A nil logger falls back to the slog
// default.
func New(g collectors.GraphClient, logger *slog.Logger) *Collector {
	if logger == nil {
		logger = slog.Default()
	}
	return &Collector{g: g, baseURL: defaultBaseURL, logger: logger}
}

// Name implements collector.Collector.
func (c *Collector) Name() string { return collectorName }

// DefaultInterval implements collector.Collector. Activation policy is
// configuration, not events — a long interval is ample.
func (c *Collector) DefaultInterval() time.Duration { return 6 * time.Hour }

// RequiredPermissions declares the read scopes both endpoints need; both are in
// the poller's token already.
func (c *Collector) RequiredPermissions() []string {
	return []string{"Policy.Read.All", "RoleManagement.Read.Directory"}
}

// roleManagementPolicy is the subset of a roleManagementPolicy this collector
// reads: identity plus the inline activation rules.
type roleManagementPolicy struct {
	ID                    string    `json:"id"`
	IsOrganizationDefault bool      `json:"isOrganizationDefault"`
	LastModifiedDateTime  string    `json:"lastModifiedDateTime"`
	Rules                 []ruleRaw `json:"rules"`
}

// ruleRaw is one policy rule, decoded loosely: the fields vary by rule type, so
// every field this collector reads across all rule types is optional here.
type ruleRaw struct {
	ID           string           `json:"id"`
	EnabledRules []string         `json:"enabledRules"`
	IsEnabled    *bool            `json:"isEnabled"`
	ClaimValue   string           `json:"claimValue"`
	IsExpiration *bool            `json:"isExpirationRequired"`
	MaxDuration  string           `json:"maximumDuration"`
	Setting      *approvalSetting `json:"setting"`
}

type approvalSetting struct {
	IsApprovalRequired bool `json:"isApprovalRequired"`
	ApprovalStages     []struct {
		ApprovalStageTimeOutInDays int `json:"approvalStageTimeOutInDays"`
	} `json:"approvalStages"`
}

// policyAssignment maps a policy to the role it governs.
type policyAssignment struct {
	PolicyID         string `json:"policyId"`
	RoleDefinitionID string `json:"roleDefinitionId"`
}

// Collect fetches the policies and their role assignments, emits the bounded
// requirement gauge, and one twin per policy.
func (c *Collector) Collect(ctx context.Context, e telemetry.Emitter) error {
	raws, err := collectors.GetAllValues(ctx, c.g, c.baseURL+policiesPath, nil)
	if err != nil {
		return fmt.Errorf("role management policies: %w", err)
	}

	roleByPolicy := c.fetchRoleAssignments(ctx)

	// counts[[3]string{requirement, enabled, caller}] = number of policies.
	counts := map[[3]string]int64{}
	var errs []error
	for _, raw := range raws {
		var p roleManagementPolicy
		if err := json.Unmarshal(raw, &p); err != nil {
			errs = append(errs, fmt.Errorf("decode policy: %w", err))
			continue
		}
		c.tally(p, counts)
		e.LogEvent(c.twin(p, roleByPolicy[p.ID]))
	}

	points := make([]telemetry.GaugePoint, 0, len(counts))
	for k, v := range counts {
		points = append(points, telemetry.GaugePoint{
			Value: float64(v),
			Attrs: telemetry.Attrs{
				semconv.AttrRequirement: k[0],
				semconv.AttrEnabled:     k[1],
				semconv.AttrCaller:      k[2],
			},
		})
	}
	e.GaugeSnapshot(metricRequirement, "{policy}", "PIM role-activation policies, by activation requirement, whether it is enabled, and caller.", points)

	return errors.Join(errs...)
}

// fetchRoleAssignments builds the policyId -> roleDefinitionId map, or nil when
// the fetch fails (the twin then omits role_definition_id rather than blocking
// the whole collection on a secondary fetch).
func (c *Collector) fetchRoleAssignments(ctx context.Context) map[string]string {
	raws, err := collectors.GetAllValues(ctx, c.g, c.baseURL+assignmentsPath, nil)
	if err != nil {
		c.logger.Warn("PIM policy->role assignment map unavailable this cycle; twins omit role_definition_id",
			"collector", collectorName, "error", err)
		return nil
	}
	out := make(map[string]string, len(raws))
	for _, raw := range raws {
		var a policyAssignment
		if err := json.Unmarshal(raw, &a); err == nil && a.PolicyID != "" {
			out[a.PolicyID] = a.RoleDefinitionID
		}
	}
	return out
}

// tally increments the requirement counts for one policy.
func (c *Collector) tally(p roleManagementPolicy, counts map[[3]string]int64) {
	by := rulesByID(p.Rules)
	add := func(requirement, caller string, enabled bool) {
		counts[[3]string{requirement, boolStr(enabled), caller}]++
	}

	eu := by[ruleEnableEndUser]
	add("mfa_on_activation", callerEndUser, hasRule(eu, "MultiFactorAuthentication"))
	add("justification_required", callerEndUser, hasRule(eu, "Justification"))

	ad := by[ruleEnableAdmin]
	add("mfa_on_activation", callerAdmin, hasRule(ad, "MultiFactorAuthentication"))
	add("justification_required", callerAdmin, hasRule(ad, "Justification"))

	add("approval_required", callerEndUser, approvalRequired(by[ruleApprovalEndUser]))
	add("auth_context_required", callerEndUser, boolp(by[ruleAuthCtxEndUser].IsEnabled))
	add("activation_expiry_required", callerEndUser, boolp(by[ruleExpiryEndUser].IsExpiration))
	add("activation_expiry_required", callerAdmin, boolp(by[ruleExpiryAdmin].IsExpiration))
	add("eligibility_expiry_required", callerAdmin, boolp(by[ruleExpiryAdminElig].IsExpiration))
}

// twin renders one policy as a log record. It Warns when an end-user can activate
// with neither MFA nor approval — the worst-case misconfiguration this collector
// exists to surface.
func (c *Collector) twin(p roleManagementPolicy, roleDefID string) telemetry.Event {
	by := rulesByID(p.Rules)
	eu := by[ruleEnableEndUser]
	approval := by[ruleApprovalEndUser]
	authCtx := by[ruleAuthCtxEndUser]
	expEndUser := by[ruleExpiryEndUser]
	expAdmin := by[ruleExpiryAdmin]
	expElig := by[ruleExpiryAdminElig]

	attrs := telemetry.Attrs{}
	telemetry.SetStr(attrs, semconv.AttrPolicyId, p.ID)
	telemetry.SetStr(attrs, semconv.AttrRoleDefinitionId, roleDefID)
	telemetry.SetBool(attrs, semconv.AttrIsOrganizationDefault, p.IsOrganizationDefault)
	telemetry.SetStr(attrs, semconv.AttrLastModifiedDateTime, p.LastModifiedDateTime)
	telemetry.SetStrs(attrs, semconv.AttrActivationEnabledRules, eu.EnabledRules)
	telemetry.SetStr(attrs, semconv.AttrActivationMaxDuration, expEndUser.MaxDuration)

	approvalReq := approvalRequired(approval)
	telemetry.SetBool(attrs, semconv.AttrApprovalRequired, approvalReq)
	if approval.Setting != nil && len(approval.Setting.ApprovalStages) > 0 {
		attrs[semconv.AttrApprovalStageTimeoutDays] = int64(approval.Setting.ApprovalStages[0].ApprovalStageTimeOutInDays)
	}
	if expAdmin.IsExpiration != nil {
		telemetry.SetBool(attrs, semconv.AttrAssignmentExpiryRequired, *expAdmin.IsExpiration)
	}
	telemetry.SetStr(attrs, semconv.AttrAssignmentMaxDuration, expAdmin.MaxDuration)
	if expElig.IsExpiration != nil {
		telemetry.SetBool(attrs, semconv.AttrEligibilityExpiryRequired, *expElig.IsExpiration)
	}
	telemetry.SetStr(attrs, semconv.AttrEligibilityMaxDuration, expElig.MaxDuration)
	if authCtx.IsEnabled != nil {
		telemetry.SetBool(attrs, semconv.AttrAuthContextEnabled, *authCtx.IsEnabled)
	}
	telemetry.SetStr(attrs, semconv.AttrAuthContextClaim, authCtx.ClaimValue)

	sev := telemetry.SeverityInfo
	noMFA := !hasRule(eu, "MultiFactorAuthentication")
	if noMFA && !approvalReq {
		sev = telemetry.SeverityWarn
	}

	label := roleDefID
	if label == "" {
		label = p.ID
	}
	return telemetry.Event{
		Name:     eventPolicy,
		Body:     fmt.Sprintf("pim role policy %s: activation_rules=%s approval=%t", label, strings.Join(eu.EnabledRules, ","), approvalReq),
		Severity: sev,
		Attrs:    attrs,
	}
}

func rulesByID(rules []ruleRaw) map[string]ruleRaw {
	out := make(map[string]ruleRaw, len(rules))
	for _, r := range rules {
		out[r.ID] = r
	}
	return out
}

func hasRule(r ruleRaw, name string) bool {
	return slices.Contains(r.EnabledRules, name)
}

func approvalRequired(r ruleRaw) bool {
	return r.Setting != nil && r.Setting.IsApprovalRequired
}

func boolp(b *bool) bool { return b != nil && *b }

func boolStr(b bool) string {
	if b {
		return "true"
	}
	return "false"
}

func init() {
	collectors.Register(func(d collectors.Deps) collector.SnapshotCollector {
		return New(d.Graph, d.Logger)
	})
}
