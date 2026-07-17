// Package consent is the Entra OAuth consent-surface collector: aggregate
// counts of delegated permission grants (oauth2PermissionGrants) and
// application-permission (app role) assignments, classified by whether they
// grant a high-privilege scope/role from a bounded, hard-coded allowlist.
//
// Over-privileged consent -- a delegated grant of a high-privilege scope, or
// an application permission granting a sensitive Graph/Exchange app role -- is
// a key attack path in Entra tenants ("illicit consent grant"). Knowing "N
// high-privilege grants exist" is not enough to act on; an analyst needs to
// know WHICH client, principal, or app role holds one.
//
// # A twin scoped to the high-privilege slice only, never every grant
//
// This collector emits TWO things per cycle, from the SAME fetch:
//
//   - a bounded GAUGE counted by consent_type x privilege -- the aggregate;
//   - one LOG record (entra.consent_grant) per grant/assignment ALREADY
//     classified "privileged" -- the identifying detail the gauge cannot
//     carry: client/principal/resource ids, the scope or app role granted,
//     and (application side only) the display names Graph already returns
//     inline on appRoleAssignment, at no extra call.
//
// Deliberately NOT twinned: standard-privilege grants. oauth2PermissionGrants
// alone can run into the tens of thousands in a large tenant -- exactly the
// volume problem that ruled out a per-grant metric SERIES in the first place.
// Twinning every grant into logs would reimport that same problem into Loki
// instead of OTEL metrics. The high-privilege slice is the opposite shape:
// low volume (a handful of grants against a handful of allowlisted
// scopes/roles) and high signal (each one is worth an analyst's attention) --
// exactly what a log twin should carry. See entra/risk (#110) for the general
// rule this collector follows: per-entity identity is never a metric label,
// but "not a metric label" means "log twin", not "dropped".
//
// This is a STATE feed, not an event stream: a still-live high-privilege
// grant is re-emitted every cycle for as long as it exists (Timestamp is left
// zero, i.e. poll time), which is what makes "which high-privilege grants
// existed as of last Tuesday" answerable from the logs pipeline alone.
//
// Per-grant/per-principal identity never becomes a metric label regardless of
// privilege -- see SECURITY.md's cardinality boundary.
package consent

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	neturl "net/url"
	"strings"
	"time"

	"github.com/rknightion/graph2otel/internal/collector"
	"github.com/rknightion/graph2otel/internal/collectors"
	"github.com/rknightion/graph2otel/internal/semconv"
	"github.com/rknightion/graph2otel/internal/telemetry"
)

// collectorName is the stable key used for config (enable/interval),
// self-observability, and the admin status page.
const collectorName = "entra.consent"

// metricName is the single gauge this collector emits, sliced by the bounded
// (consent_type, privilege) classification.
const metricName = "entra.consent.grants.total"

// eventConsentGrant is the log EventName for the high-privilege consent-grant
// twin -- one record per grant/assignment already classified "privileged".
// See the package doc's "twin scoped to the high-privilege slice" section.
const eventConsentGrant = "entra.consent_grant"

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
// collector needs: Scope classifies to a (privilege) count; the rest
// (ID/ClientID/ConsentType/PrincipalID/ResourceID) are raw identifying fields
// that go ONLY to the high-privilege log twin, never to a metric attribute --
// see delegatedGrantLogTwin. Field names verified against
// learn.microsoft.com/graph/api/resources/oauth2permissiongrant. PrincipalID
// is empty whenever ConsentType is "AllPrincipals" (admin-consent-for-all
// grants have no single principal) -- setStr omits it in that case.
type oauth2Grant struct {
	ID          string `json:"id"`
	ClientID    string `json:"clientId"`
	ConsentType string `json:"consentType"`
	PrincipalID string `json:"principalId"`
	ResourceID  string `json:"resourceId"`
	Scope       string `json:"scope"`
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
// collector needs: AppRoleID classifies to a (privilege) count; the rest are
// raw identifying fields that go ONLY to the high-privilege log twin, never
// to a metric attribute -- see appRoleAssignmentLogTwin. Field names verified
// against learn.microsoft.com/graph/api/resources/approleassignment.
// PrincipalDisplayName/ResourceDisplayName are returned inline by Graph on
// this resource -- twinning them is free, no extra lookup call needed.
type appRoleAssignment struct {
	ID                   string `json:"id"`
	AppRoleID            string `json:"appRoleId"`
	PrincipalID          string `json:"principalId"`
	PrincipalDisplayName string `json:"principalDisplayName"`
	PrincipalType        string `json:"principalType"`
	ResourceID           string `json:"resourceId"`
	ResourceDisplayName  string `json:"resourceDisplayName"`
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

	if err := c.collectDelegatedGrants(ctx, e, counts[consentTypeDelegated]); err != nil {
		c.logger.Warn("oauth2PermissionGrants collection failed", "collector", collectorName, "error", err)
		errs = append(errs, fmt.Errorf("oauth2PermissionGrants: %w", err))
	}

	for _, ra := range resourceApps {
		if err := c.collectResourceAppRoleAssignments(ctx, e, ra, counts[consentTypeApplication]); err != nil {
			c.logger.Warn("app role assignment collection failed", "collector", collectorName, "resource", ra.label, "error", err)
			errs = append(errs, fmt.Errorf("%s: %w", ra.label, err))
		}
	}

	points := make([]telemetry.GaugePoint, 0, 4)
	for _, consentType := range []string{consentTypeDelegated, consentTypeApplication} {
		for _, privilege := range []string{privilegeHigh, privilegeStandard} {
			points = append(points, telemetry.GaugePoint{
				Value: float64(counts[consentType][privilege]),
				Attrs: telemetry.Attrs{semconv.AttrConsentType: consentType, semconv.AttrPrivilege: privilege},
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
func (c *Collector) collectDelegatedGrants(ctx context.Context, e telemetry.Emitter, tally map[string]int64) error {
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
			e.LogEvent(delegatedGrantLogTwin(g))
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
func (c *Collector) collectResourceAppRoleAssignments(ctx context.Context, e telemetry.Emitter, ra resourceApp, tally map[string]int64) error {
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
		roleValue := roleNames[a.AppRoleID]
		if highPrivilegeAppRoles[roleValue] {
			tally[privilegeHigh]++
			e.LogEvent(appRoleAssignmentLogTwin(a, ra, roleValue))
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
	// The $filter value ("appId eq '<guid>'") contains spaces and quotes, which
	// must be percent-encoded or Graph rejects the request as malformed (HTTP
	// 400) — verified live. Encode the query value, don't inline it raw.
	filter := fmt.Sprintf("appId eq '%s'", appID)
	url := c.baseURL + "/servicePrincipals?$filter=" + neturl.QueryEscape(filter) + "&$select=id,appRoles"
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
	for s := range strings.FieldsSeq(scope) {
		if highPrivilegeDelegatedScopes[s] {
			return true
		}
	}
	return false
}

// delegatedGrantLogTwin renders a high-privilege delegated permission grant as
// an OTLP log record. Only called for a grant already classified
// "privileged" (see collectDelegatedGrants) -- a standard-scope grant never
// reaches here, which is the whole point of scoping the twin (see the package
// doc).
//
// Timestamp is left zero ("now", i.e. poll time): this is a STATE feed, the
// same live grant is re-emitted every cycle for as long as it exists, and
// oauth2PermissionGrant carries no timestamp of its own to stamp it with
// instead -- see risk.logTwin for the fuller rationale behind this choice.
func delegatedGrantLogTwin(g oauth2Grant) telemetry.Event {
	attrs := telemetry.Attrs{}
	telemetry.SetStr(attrs, semconv.AttrId, g.ID)
	telemetry.SetStr(attrs, semconv.AttrConsentType, consentTypeDelegated)
	telemetry.SetStr(attrs, semconv.AttrPrivilege, privilegeHigh)
	telemetry.SetStr(attrs, semconv.AttrClientId, g.ClientID)
	telemetry.SetStr(attrs, semconv.AttrPrincipalId, g.PrincipalID)
	telemetry.SetStr(attrs, semconv.AttrResourceId, g.ResourceID)
	telemetry.SetStr(attrs, semconv.AttrScope, g.Scope)

	return telemetry.Event{
		Name:     eventConsentGrant,
		Body:     fmt.Sprintf("high-privilege delegated consent grant: client=%s scope=%q", g.ClientID, g.Scope),
		Severity: telemetry.SeverityWarn,
		Attrs:    attrs,
	}
}

// appRoleAssignmentLogTwin renders a high-privilege application-permission
// (app role) assignment as an OTLP log record. Only called for an assignment
// already classified "privileged" (see collectResourceAppRoleAssignments).
// ra is the bounded, hard-coded resourceApps entry being scanned (its label
// is a fixed string, never a per-tenant value); roleValue is the appRoleId
// already resolved against the resource service principal's appRoles during
// classification -- reused here, not looked up again.
func appRoleAssignmentLogTwin(a appRoleAssignment, ra resourceApp, roleValue string) telemetry.Event {
	attrs := telemetry.Attrs{}
	telemetry.SetStr(attrs, semconv.AttrId, a.ID)
	telemetry.SetStr(attrs, semconv.AttrConsentType, consentTypeApplication)
	telemetry.SetStr(attrs, semconv.AttrPrivilege, privilegeHigh)
	telemetry.SetStr(attrs, semconv.AttrResourceLabel, ra.label)
	telemetry.SetStr(attrs, semconv.AttrResourceId, a.ResourceID)
	telemetry.SetStr(attrs, semconv.AttrResourceDisplayName, a.ResourceDisplayName)
	telemetry.SetStr(attrs, semconv.AttrAppRoleId, a.AppRoleID)
	telemetry.SetStr(attrs, semconv.AttrAppRole, roleValue)
	telemetry.SetStr(attrs, semconv.AttrPrincipalId, a.PrincipalID)
	telemetry.SetStr(attrs, semconv.AttrPrincipalDisplayName, a.PrincipalDisplayName)
	telemetry.SetStr(attrs, semconv.AttrPrincipalType, a.PrincipalType)

	return telemetry.Event{
		Name:     eventConsentGrant,
		Body:     fmt.Sprintf("high-privilege application consent grant: resource=%s app_role=%s principal=%s", ra.label, roleValue, principalDisplayOrID(a)),
		Severity: telemetry.SeverityWarn,
		Attrs:    attrs,
	}
}

// principalDisplayOrID picks the most human-readable identifier an app role
// assignment carries for its principal, falling back to the raw principal id.
func principalDisplayOrID(a appRoleAssignment) string {
	if a.PrincipalDisplayName != "" {
		return a.PrincipalDisplayName
	}
	return a.PrincipalID
}

func init() {
	collectors.Register(func(d collectors.Deps) collector.SnapshotCollector {
		return New(d.Graph, d.Logger)
	})
}
