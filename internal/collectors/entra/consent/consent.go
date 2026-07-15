// Package consent is the Entra OAuth consent-surface collector: aggregate
// counts of delegated permission grants (oauth2PermissionGrants) and
// application-permission (app role) assignments, classified by whether they
// grant a high-privilege scope/role from a bounded, hard-coded allowlist.
//
// Over-privileged consent -- a delegated grant of a high-privilege scope, or
// an application permission granting a sensitive Graph/Exchange app role -- is
// a key attack path in Entra tenants. This collector never emits a per-grant
// or per-service-principal series (oauth2PermissionGrants alone can run into
// the tens of thousands in a large tenant); it only emits the bounded
// privilege x consent-type classification counts.
package consent

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
	"github.com/rknightion/graph2otel/internal/telemetry"
)

// collectorName is the stable key used for config (enable/interval),
// self-observability, and the admin status page.
const collectorName = "entra.consent"

// metricName is the single gauge this collector emits, sliced by the bounded
// (consent_type, privilege) classification.
const metricName = "entra.consent.grants.total"

// defaultBaseURL is the Graph v1.0 root.
const defaultBaseURL = "https://graph.microsoft.com/v1.0"

// consentType values -- the source of the grant, not the OData
// oauth2PermissionGrant.consentType field (which distinguishes
// "AllPrincipals" vs "Principal" delegated grants; both roll up to
// "delegated" here since that distinction isn't a privilege signal).
const (
	consentTypeDelegated   = "delegated"
	consentTypeApplication = "application"
)

// privilege classification values.
const (
	privilegeHigh     = "privileged"
	privilegeStandard = "standard"
)

// highPrivilegeDelegatedScopes is the bounded, hard-coded allowlist of
// delegated OAuth2 permission scopes treated as high-privilege. A delegated
// grant is classified "privileged" if ANY space-delimited scope value in its
// `scope` field appears here. Extend deliberately -- this is the entire
// cardinality bound for the delegated side of entra.consent.grants.total.
var highPrivilegeDelegatedScopes = map[string]bool{
	"Directory.ReadWrite.All":            true,
	"Directory.AccessAsUser.All":         true,
	"RoleManagement.ReadWrite.Directory": true,
	"Application.ReadWrite.All":          true,
	"Mail.Read":                          true,
	"Mail.ReadWrite":                     true,
	"Mail.Send":                          true,
	"MailboxSettings.ReadWrite":          true,
	"User.ReadWrite.All":                 true,
	"Group.ReadWrite.All":                true,
	"Files.ReadWrite.All":                true,
	"Sites.FullControl.All":              true,
}

// highPrivilegeAppRoles is the bounded, hard-coded allowlist of application
// permission (app role) names treated as high-privilege, matched against the
// resolved appRole.value string (not its GUID, which is only stable per
// resource, not across tenants' JSON fixtures/tests).
var highPrivilegeAppRoles = map[string]bool{
	"Directory.ReadWrite.All":            true,
	"RoleManagement.ReadWrite.Directory": true,
	"Application.ReadWrite.All":          true,
	"Mail.Read":                          true,
	"Mail.ReadWrite":                     true,
	"Mail.Send":                          true,
	"User.ReadWrite.All":                 true,
	"Group.ReadWrite.All":                true,
	"Sites.FullControl.All":              true,
	// full_access_as_app is Exchange Online's app-only role granting full
	// access to every mailbox in the tenant; it lives on the Exchange
	// resource service principal, not Microsoft Graph's.
	"full_access_as_app": true,
}

// resourceApp is a well-known resource application whose app-role
// assignments (application permissions granted to it) are worth scanning.
// This bounds the "application" side of the collector to a fixed, small set
// of high-value resources instead of an unbounded fan-out over every service
// principal in the tenant (see resolveResourceServicePrincipal doc).
type resourceApp struct {
	label string // for logging only, never emitted as a metric attribute
	appID string
}

// resourceApps is the bounded set of resource applications scanned for
// over-privileged application-permission (app role) assignments.
var resourceApps = []resourceApp{
	{"microsoft_graph", "00000003-0000-0000-c000-000000000000"},
	{"office365_exchange_online", "00000002-0000-0ff1-ce00-000000000000"},
}

// oauth2Grant is the subset of the oauth2PermissionGrant resource this
// collector needs.
type oauth2Grant struct {
	Scope string `json:"scope"`
}

// servicePrincipalLookup is the subset of a servicePrincipal resource needed
// to resolve a resource app's object ID and its app-role GUID-to-name map.
type servicePrincipalLookup struct {
	ID       string    `json:"id"`
	AppRoles []appRole `json:"appRoles"`
}

// appRole pairs an app role's GUID with its stable string identifier (e.g.
// "Directory.ReadWrite.All").
type appRole struct {
	ID    string `json:"id"`
	Value string `json:"value"`
}

// appRoleAssignment is the subset of the appRoleAssignment resource this
// collector needs -- just enough to classify, never a per-principal
// identifier.
type appRoleAssignment struct {
	AppRoleID string `json:"appRoleId"`
}

// Collector polls the OAuth consent surface: delegated permission grants and
// application-permission (app role) assignments against a bounded set of
// high-value resource applications.
type Collector struct {
	g       collectors.GraphClient
	baseURL string
	logger  *slog.Logger
}

// New builds the consent collector. A nil logger falls back to the slog
// default.
func New(g collectors.GraphClient, logger *slog.Logger) *Collector {
	if logger == nil {
		logger = slog.Default()
	}
	return &Collector{g: g, baseURL: defaultBaseURL, logger: logger}
}

// Name implements collector.Collector.
func (c *Collector) Name() string { return collectorName }

// DefaultInterval implements collector.Collector. The consent surface
// changes rarely (new app registrations / admin consent events, not routine
// directory churn), and application-side scanning fans out across a couple
// of resource service principals each with a paged appRoleAssignedTo list, so
// a longer cadence than the cheap $count-based collectors is appropriate.
func (c *Collector) DefaultInterval() time.Duration { return 15 * time.Minute }

// RequiredPermissions implements the permissions-declaring optional
// interface. Directory.Read.All covers oauth2PermissionGrants and the
// servicePrincipals filter lookup; Application.Read.All is the
// least-privilege scope for appRoleAssignedTo.
func (c *Collector) RequiredPermissions() []string {
	return []string{"Directory.Read.All", "Application.Read.All"}
}

// Collect fetches delegated permission grants and application-permission
// assignments against the bounded resourceApps set, classifies each against
// the high-privilege allowlists, and emits only the resulting bounded
// (consent_type, privilege) counts as a single gauge snapshot. A failure on
// one source (grants, or one resource app's lookup/listing) is logged and
// joined into the returned error, but does not prevent the other sources'
// counts from being emitted.
func (c *Collector) Collect(ctx context.Context, e telemetry.Emitter) error {
	counts := map[string]map[string]int64{
		consentTypeDelegated:   {privilegeHigh: 0, privilegeStandard: 0},
		consentTypeApplication: {privilegeHigh: 0, privilegeStandard: 0},
	}
	var errs []error

	if err := c.collectDelegatedGrants(ctx, counts[consentTypeDelegated]); err != nil {
		c.logger.Warn("oauth2PermissionGrants collection failed", "collector", collectorName, "error", err)
		errs = append(errs, fmt.Errorf("oauth2PermissionGrants: %w", err))
	}

	for _, ra := range resourceApps {
		if err := c.collectResourceAppRoleAssignments(ctx, ra, counts[consentTypeApplication]); err != nil {
			c.logger.Warn("app role assignment collection failed", "collector", collectorName, "resource", ra.label, "error", err)
			errs = append(errs, fmt.Errorf("%s: %w", ra.label, err))
		}
	}

	points := make([]telemetry.GaugePoint, 0, 4)
	for _, consentType := range []string{consentTypeDelegated, consentTypeApplication} {
		for _, privilege := range []string{privilegeHigh, privilegeStandard} {
			points = append(points, telemetry.GaugePoint{
				Value: float64(counts[consentType][privilege]),
				Attrs: telemetry.Attrs{"consent_type": consentType, "privilege": privilege},
			})
		}
	}
	e.GaugeSnapshot(metricName, "{grant}",
		"Entra OAuth consent grants (delegated permission grants and application role assignments), by consent type and privilege classification.",
		points)
	return errors.Join(errs...)
}

// collectDelegatedGrants pages oauth2PermissionGrants and accumulates a
// running (privilege -> count) tally; it never retains per-grant data. This
// is a plain list (no advanced $filter/$search/$count), so no ConsistencyLevel
// header is required per the Graph docs.
//
// Scaling caution: oauth2PermissionGrants is not bounded by tenant policy
// count -- it grows with the number of distinct (user, client, resource)
// consent combinations, so a very large tenant could in principle exceed
// collectors.GetAllValues' 1000-page cap. Unlike the $count-based
// directorycounts collector, classifying by scope content requires reading
// every grant's `scope` field, so there is no cheaper aggregate-only Graph
// query available today.
func (c *Collector) collectDelegatedGrants(ctx context.Context, tally map[string]int64) error {
	grants, err := collectors.GetAllValues(ctx, c.g, c.baseURL+"/oauth2PermissionGrants", nil)
	if err != nil {
		return err
	}
	for _, raw := range grants {
		var g oauth2Grant
		if err := json.Unmarshal(raw, &g); err != nil {
			return fmt.Errorf("decode oauth2PermissionGrant: %w", err)
		}
		if grantHasHighPrivilegeScope(g.Scope) {
			tally[privilegeHigh]++
		} else {
			tally[privilegeStandard]++
		}
	}
	return nil
}

// collectResourceAppRoleAssignments resolves one well-known resource app's
// service principal (skipping silently if not provisioned in this tenant),
// then pages its appRoleAssignedTo list and accumulates a running
// (privilege -> count) tally classified against highPrivilegeAppRoles.
//
// Scanning the resource side (servicePrincipals/{resourceId}/appRoleAssignedTo)
// rather than enumerating every tenant service principal's own
// appRoleAssignments is a deliberate bound: the latter is an unbounded N+1
// fan-out (one call per service principal in the tenant), while this bounds
// the work to len(resourceApps) resolutions plus one paged list per resolved
// resource, scaling with the number of apps granted a role on that resource
// rather than with total tenant service principal count.
func (c *Collector) collectResourceAppRoleAssignments(ctx context.Context, ra resourceApp, tally map[string]int64) error {
	sp, err := c.resolveResourceServicePrincipal(ctx, ra.appID)
	if err != nil {
		return err
	}
	if sp == nil {
		return nil // resource not provisioned in this tenant
	}

	roleNames := make(map[string]string, len(sp.AppRoles))
	for _, role := range sp.AppRoles {
		roleNames[role.ID] = role.Value
	}

	assignments, err := collectors.GetAllValues(ctx, c.g, c.baseURL+"/servicePrincipals/"+sp.ID+"/appRoleAssignedTo", nil)
	if err != nil {
		return err
	}
	for _, raw := range assignments {
		var a appRoleAssignment
		if err := json.Unmarshal(raw, &a); err != nil {
			return fmt.Errorf("decode appRoleAssignment: %w", err)
		}
		if highPrivilegeAppRoles[roleNames[a.AppRoleID]] {
			tally[privilegeHigh]++
		} else {
			tally[privilegeStandard]++
		}
	}
	return nil
}

// resolveResourceServicePrincipal looks up a resource app's service principal
// by appId (`$filter=appId eq '...'`, a simple single-clause equality filter
// that Graph documents as supported without advanced-query headers) and
// returns its object ID plus app-role GUID-to-name map. A tenant where the
// resource isn't provisioned (e.g. no Exchange Online) returns (nil, nil),
// not an error.
func (c *Collector) resolveResourceServicePrincipal(ctx context.Context, appID string) (*servicePrincipalLookup, error) {
	url := c.baseURL + "/servicePrincipals?$filter=appId eq '" + appID + "'&$select=id,appRoles"
	values, err := collectors.GetAllValues(ctx, c.g, url, nil)
	if err != nil {
		return nil, err
	}
	if len(values) == 0 {
		return nil, nil
	}
	var sp servicePrincipalLookup
	if err := json.Unmarshal(values[0], &sp); err != nil {
		return nil, fmt.Errorf("decode service principal: %w", err)
	}
	return &sp, nil
}

// grantHasHighPrivilegeScope reports whether any space-delimited token in a
// delegated grant's `scope` field is in the high-privilege allowlist.
func grantHasHighPrivilegeScope(scope string) bool {
	for _, s := range strings.Fields(scope) {
		if highPrivilegeDelegatedScopes[s] {
			return true
		}
	}
	return false
}

func init() {
	collectors.Register(func(d collectors.Deps) collector.SnapshotCollector {
		return New(d.Graph, d.Logger)
	})
}
