// Package tenantpolicy is the Entra tenant-policy-posture collector (#245): the
// CIS/benchmark tenant switches that get changed once during an incident and
// never changed back — can ordinary users register apps, create groups, read
// other users, invite guests; is legacy MSOL PowerShell blocked; is user
// consent for risky apps allowed; is the admin-consent workflow on; does the
// default app-management policy restrict long-lived secrets.
//
// # Bounded gauge, one twin
//
// Every switch is a 0/1 point on ONE bounded gauge, entra.tenant_policy.setting,
// labeled by a fixed enumerated `setting` name — never by anything that grows
// with tenant size. The three scoped-policy collections (app-management,
// group-lifecycle, feature-rollout) are counted on entra.tenant_policy.scoped_policies
// by a fixed `kind`. The raw detail a 0/1 gauge cannot express — the guest role
// GUID that distinguishes Guest from Restricted Guest, the raw allowInvitesFrom
// enum, the admin-consent reviewer count, the permission-grant policy list —
// rides one entra.tenant_policy log twin (#114).
//
// The three data-bearing endpoints are independent single objects; a failure in
// one is surfaced as a non-fatal aggregated error and does not stop the others.
// The three scoped-policy collections are empty on m7kni, so only their COUNT is
// emitted (no field mapper is written against data never seen — #142/#165).
package tenantpolicy

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/rknightion/graph2otel/internal/collector"
	"github.com/rknightion/graph2otel/internal/collectors"
	"github.com/rknightion/graph2otel/internal/semconv"
	"github.com/rknightion/graph2otel/internal/telemetry"
)

const collectorName = "entra.tenant_policy"

const (
	metricSetting        = "entra.tenant_policy.setting"
	metricScopedPolicies = "entra.tenant_policy.scoped_policies"
)

const eventTenantPolicy = "entra.tenant_policy"

const defaultBaseURL = "https://graph.microsoft.com/v1.0"

// Collector polls the tenant authorization / consent / app-management policies.
type Collector struct {
	g       collectors.GraphClient
	baseURL string
	logger  *slog.Logger
}

// New builds the tenant-policy collector. A nil logger falls back to the slog
// default.
func New(g collectors.GraphClient, logger *slog.Logger) *Collector {
	if logger == nil {
		logger = slog.Default()
	}
	return &Collector{g: g, baseURL: defaultBaseURL, logger: logger}
}

// Name implements collector.Collector.
func (c *Collector) Name() string { return collectorName }

// DefaultInterval implements collector.Collector. This is configuration, not an
// event stream — it changes rarely, so a long interval is ample.
func (c *Collector) DefaultInterval() time.Duration { return 6 * time.Hour }

// RequiredPermissions declares the single scope every endpoint here shares.
func (c *Collector) RequiredPermissions() []string { return []string{"Policy.Read.All"} }

// authorizationPolicy is the subset of policies/authorizationPolicy this
// collector reads. defaultUserRolePermissions is the CIS-shaped switch cluster.
type authorizationPolicy struct {
	AllowInvitesFrom                          string `json:"allowInvitesFrom"`
	AllowedToSignUpEmailBasedSubscriptions    bool   `json:"allowedToSignUpEmailBasedSubscriptions"`
	AllowedToUseSSPR                          bool   `json:"allowedToUseSSPR"`
	AllowEmailVerifiedUsersToJoinOrganization bool   `json:"allowEmailVerifiedUsersToJoinOrganization"`
	AllowUserConsentForRiskyApps              bool   `json:"allowUserConsentForRiskyApps"`
	BlockMsolPowerShell                       bool   `json:"blockMsolPowerShell"`
	GuestUserRoleID                           string `json:"guestUserRoleId"`
	DefaultUserRolePermissions                struct {
		AllowedToCreateApps             bool     `json:"allowedToCreateApps"`
		AllowedToCreateSecurityGroups   bool     `json:"allowedToCreateSecurityGroups"`
		AllowedToCreateTenants          bool     `json:"allowedToCreateTenants"`
		AllowedToReadOtherUsers         bool     `json:"allowedToReadOtherUsers"`
		PermissionGrantPoliciesAssigned []string `json:"permissionGrantPoliciesAssigned"`
	} `json:"defaultUserRolePermissions"`
}

// adminConsentRequestPolicy is the subset of policies/adminConsentRequestPolicy.
type adminConsentRequestPolicy struct {
	IsEnabled             bool `json:"isEnabled"`
	RequestDurationInDays int  `json:"requestDurationInDays"`
	Reviewers             []struct {
		Query string `json:"query"`
	} `json:"reviewers"`
}

// defaultAppManagementPolicy is the subset of policies/defaultAppManagementPolicy
// this collector reads. A non-empty passwordCredentials restriction array means
// long-lived app secrets are restricted tenant-wide.
type defaultAppManagementPolicy struct {
	IsEnabled               bool `json:"isEnabled"`
	ApplicationRestrictions struct {
		PasswordCredentials []json.RawMessage `json:"passwordCredentials"`
	} `json:"applicationRestrictions"`
}

// Collect fetches the three data-bearing singletons and the three scoped-policy
// collections, emitting the bounded setting gauge, the scoped-policy counts, and
// the raw twin. Each singleton fetch is independent.
func (c *Collector) Collect(ctx context.Context, e telemetry.Emitter) error {
	var errs []error

	settings := map[string]float64{}
	twin := telemetry.Attrs{}

	if ap, err := c.getObject(ctx, "/policies/authorizationPolicy"); err != nil {
		errs = append(errs, fmt.Errorf("authorizationPolicy: %w", err))
	} else {
		var p authorizationPolicy
		if err := json.Unmarshal(ap, &p); err != nil {
			errs = append(errs, fmt.Errorf("decode authorizationPolicy: %w", err))
		} else {
			c.applyAuthorizationPolicy(p, settings, twin)
		}
	}

	if acp, err := c.getObject(ctx, "/policies/adminConsentRequestPolicy"); err != nil {
		errs = append(errs, fmt.Errorf("adminConsentRequestPolicy: %w", err))
	} else {
		var p adminConsentRequestPolicy
		if err := json.Unmarshal(acp, &p); err != nil {
			errs = append(errs, fmt.Errorf("decode adminConsentRequestPolicy: %w", err))
		} else {
			settings["admin_consent_workflow_enabled"] = b2f(p.IsEnabled)
			twin[semconv.AttrAdminConsentReviewerCount] = int64(len(p.Reviewers))
			twin[semconv.AttrAdminConsentRequestDuration] = int64(p.RequestDurationInDays)
		}
	}

	if damp, err := c.getObject(ctx, "/policies/defaultAppManagementPolicy"); err != nil {
		errs = append(errs, fmt.Errorf("defaultAppManagementPolicy: %w", err))
	} else {
		var p defaultAppManagementPolicy
		if err := json.Unmarshal(damp, &p); err != nil {
			errs = append(errs, fmt.Errorf("decode defaultAppManagementPolicy: %w", err))
		} else {
			settings["app_management_policy_enabled"] = b2f(p.IsEnabled)
			restricted := len(p.ApplicationRestrictions.PasswordCredentials) > 0
			settings["app_password_credentials_restricted"] = b2f(restricted)
			telemetry.SetBool(twin, semconv.AttrAppPasswordCredsRestricted, restricted)
		}
	}

	// Emit the bounded setting gauge only if at least one setting resolved (a
	// total failure of all singletons emits nothing rather than a hollow zero).
	if len(settings) > 0 {
		points := make([]telemetry.GaugePoint, 0, len(settings))
		for name, v := range settings {
			points = append(points, telemetry.GaugePoint{
				Value: v,
				Attrs: telemetry.Attrs{semconv.AttrSetting: name},
			})
		}
		e.GaugeSnapshot(metricSetting, "{setting}", "Tenant policy posture switches, 0/1 by setting.", points)
		e.LogEvent(telemetry.Event{
			Name:     eventTenantPolicy,
			Body:     "tenant policy posture",
			Severity: telemetry.SeverityInfo,
			Attrs:    twin,
		})
	}

	c.collectScopedPolicies(ctx, e, &errs)

	return errors.Join(errs...)
}

// applyAuthorizationPolicy fans the authorizationPolicy fields into the bounded
// setting map and the raw twin.
func (c *Collector) applyAuthorizationPolicy(p authorizationPolicy, settings map[string]float64, twin telemetry.Attrs) {
	settings["users_can_create_apps"] = b2f(p.DefaultUserRolePermissions.AllowedToCreateApps)
	settings["users_can_create_security_groups"] = b2f(p.DefaultUserRolePermissions.AllowedToCreateSecurityGroups)
	settings["users_can_create_tenants"] = b2f(p.DefaultUserRolePermissions.AllowedToCreateTenants)
	settings["users_can_read_other_users"] = b2f(p.DefaultUserRolePermissions.AllowedToReadOtherUsers)
	// A derived boolean: guest invitations are unrestricted only when anyone may
	// invite. The raw enum rides the twin so the exact scope is not lost.
	settings["guest_invite_restricted"] = b2f(!strings.EqualFold(p.AllowInvitesFrom, "everyone"))
	settings["msol_powershell_blocked"] = b2f(p.BlockMsolPowerShell)
	settings["user_consent_for_risky_apps_allowed"] = b2f(p.AllowUserConsentForRiskyApps)
	settings["sspr_allowed"] = b2f(p.AllowedToUseSSPR)
	settings["email_verified_join_allowed"] = b2f(p.AllowEmailVerifiedUsersToJoinOrganization)

	telemetry.SetStr(twin, semconv.AttrAllowInvitesFrom, p.AllowInvitesFrom)
	telemetry.SetStr(twin, semconv.AttrGuestUserRoleId, p.GuestUserRoleID)
	telemetry.SetStrs(twin, semconv.AttrPermissionGrantPolicies, p.DefaultUserRolePermissions.PermissionGrantPoliciesAssigned)
}

// scopedPolicy names one of the three collection endpoints this collector counts
// but does not field-map (empty on m7kni — no mapper is written against unseen
// data).
type scopedPolicy struct {
	kind string
	path string
}

var scopedPolicies = []scopedPolicy{
	{kind: "app_management", path: "/policies/appManagementPolicies"},
	{kind: "group_lifecycle", path: "/groupLifecyclePolicies"},
	{kind: "feature_rollout", path: "/policies/featureRolloutPolicies"},
}

// collectScopedPolicies emits a bounded count per scoped-policy kind. These are
// empty on m7kni; the count makes "someone added a custom scoped policy" visible
// without a docs-written field mapper.
func (c *Collector) collectScopedPolicies(ctx context.Context, e telemetry.Emitter, errs *[]error) {
	points := make([]telemetry.GaugePoint, 0, len(scopedPolicies))
	for _, sp := range scopedPolicies {
		raws, err := collectors.GetAllValues(ctx, c.g, c.baseURL+sp.path, nil)
		if err != nil {
			*errs = append(*errs, fmt.Errorf("%s: %w", sp.kind, err))
			continue
		}
		points = append(points, telemetry.GaugePoint{
			Value: float64(len(raws)),
			Attrs: telemetry.Attrs{semconv.AttrKind: sp.kind},
		})
	}
	if len(points) > 0 {
		e.GaugeSnapshot(metricScopedPolicies, "{policy}", "Count of scoped tenant policies, by kind.", points)
	}
}

// getObject GETs a single-object (non-collection) policy endpoint.
func (c *Collector) getObject(ctx context.Context, path string) ([]byte, error) {
	return c.g.RawGet(ctx, c.baseURL+path)
}

// b2f maps a bool to a 0/1 gauge value.
func b2f(b bool) float64 {
	if b {
		return 1
	}
	return 0
}

func init() {
	collectors.Register(func(d collectors.Deps) collector.SnapshotCollector {
		return New(d.Graph, d.Logger)
	})
}
