// Package rbac is the Intune RBAC collector: the role definitions Intune
// maintains in its OWN role store, the assignments that bind them to principals,
// and the link between the two.
//
// # Why this exists
//
// Intune's role store is entirely separate from Entra directory roles.
// entra.roles enumerates directory-role holders and sees none of it, so a
// principal granted sweeping device-management rights through an Intune custom
// role — wipe, retire, app assignment, script execution — was completely
// invisible to graph2otel, while a Global Reader showed up immediately (#257).
//
// # Sources (v1.0 — NOT Experimental)
//
// Both collections answer 200 on v1.0 and on beta (live-measured 2026-07-24 as
// graph2otel-poller), so this is a v1.0 collector and carries no Experimental
// gate; #183 reserves that for genuine beta surfaces.
//
//	GET /deviceManagement/roleDefinitions                     (10 rows on m7kni)
//	GET /deviceManagement/roleAssignments                     (1 row on m7kni)
//	GET /deviceManagement/roleDefinitions/{id}/roleAssignments (per definition)
//
// # The third fetch is not optional, and here is why
//
// The assignment row carries NO reference to the role it grants — no
// roleDefinitionId, no navigation value. Without the link, "MDE Endpoint
// Security Managers is assigned at allDevicesAndLicensedUsers" cannot be turned
// into "…and the role it grants is a hand-made one", which is the entire signal
// #257 asks for.
//
// Two ways to get the link were measured on 2026-07-24, and only one works:
//
//   - `GET /deviceManagement/roleAssignments?$expand=roleDefinition` answers 200
//     with `"roleDefinition": null`, AND silently drops `scopeType`,
//     `scopeMembers` and `roleScopeTagIds` from the response. It costs fields and
//     returns nothing.
//   - `GET /deviceManagement/roleDefinitions/{id}/roleAssignments` (the EDM's
//     ContainsTarget navigation) answers 200 with the assignment and its
//     `@odata.type`. Its rows are TRUNCATED — `members` comes back empty and
//     `scopeType` is absent — so the full assignment list is fetched separately
//     and joined on the assignment id.
//
// The fan-out is one request per role definition, bounded by the tenant's role
// CATALOG (built-ins plus however many custom roles an admin made), never by
// user or device count. That, plus the 6h interval, is why it is affordable.
//
// # Wire facts handled rather than assumed (live-measured 2026-07-24, n=1)
//
//   - `isBuiltIn` and `isBuiltInRoleDefinition` are BOTH present on the same
//     record and agree on every live row. Both are emitted, and both are gauge
//     dimensions, so a future disagreement appears as a new series instead of
//     being resolved by a mapper that assumed one was a rename of the other
//     (#142).
//   - `permissions` and `rolePermissions` are byte-identical on all ten live
//     rows. Rather than pick one and hope, the emitted action list is the sorted
//     UNION of both, so a divergence loses nothing.
//   - `permissions[].resourceActions[].allowedResourceActions` duplicates
//     `permissions[].actions` exactly on all ten rows, so it folds into the same
//     union. Its sibling `notAllowedResourceActions` is a different fact (the
//     explicit deny half) and gets its own attribute.
//   - The role definition carries an `@odata.type` discriminator
//     (`deviceAndAppManagementRoleDefinition` on every live row); the assignment
//     row does NOT, though the same assignment DOES carry one when read through
//     the per-definition navigation. The discriminator is read, not assumed.
//
// # members are emitted as bare guids, deliberately
//
// `roleAssignments.members` is a list of principal object ids with no names
// attached. They are emitted verbatim. Resolving them would mean a second
// lookup per assignment against a directory scope this collector does not
// otherwise need, and a name resolved out of a different store is a name that
// can be wrong — an unresolved guid is honest, a fabricated name is not. The
// guid joins to entra.groups / entra.users in the backend, which already carry
// the mapping. See semconv.AttrMembers.
//
// # Cardinality (#112/#114)
//
// The gauges carry only bounded dimensions: (is_built_in,
// is_built_in_role_definition, role_definition_type) and (scope_type,
// is_built_in). Every per-entity field — role ids and names, descriptions, the
// unbounded `Microsoft.Intune_*` action list, principal guids, scope members —
// rides a log twin, one per definition and one per assignment, every cycle.
// Guard test.
package rbac

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/rknightion/graph2otel/internal/collector"
	"github.com/rknightion/graph2otel/internal/collectors"
	"github.com/rknightion/graph2otel/internal/graphclient"
	"github.com/rknightion/graph2otel/internal/preflight"
	"github.com/rknightion/graph2otel/internal/semconv"
	"github.com/rknightion/graph2otel/internal/telemetry"
)

const (
	collectorName = "intune.rbac"
	// definitionsMetricName counts role definitions by the two built-in flags
	// and the @odata.type subtype — bounded by the role catalog's SHAPE, which
	// is a handful of combinations however many roles exist.
	definitionsMetricName = "intune.rbac.role_definitions"
	// assignmentsMetricName counts role assignments by scope type and whether
	// the role they grant is built-in.
	assignmentsMetricName = "intune.rbac.role_assignments"

	eventRoleDefinition = "intune.role_definition"
	eventRoleAssignment = "intune.role_assignment"

	// defaultBaseURL is the Graph v1.0 root — both collections are GA.
	defaultBaseURL = "https://graph.microsoft.com/v1.0"
	// roleDefinitionsPath / roleAssignmentsPath are the two top-level
	// collections; roleAssignmentsSegment is appended to a single definition to
	// walk its assignments navigation. No $top: GetAllValues already asks for
	// Graph's largest page via the Prefer header, and an unverified $top is how
	// a paged collector earns a 400 (docs/graph-api-gotchas.md).
	roleDefinitionsPath    = "/deviceManagement/roleDefinitions"
	roleAssignmentsPath    = "/deviceManagement/roleAssignments"
	roleAssignmentsSegment = "/roleAssignments"

	// odataTypePrefix is stripped off the @odata.type discriminator so the
	// emitted value is the bare subtype name.
	odataTypePrefix = "#microsoft.graph."
	// scopeTypeAllDevices is the widest assignment scope Intune offers: every
	// device and every licensed user in the tenant.
	scopeTypeAllDevices = "allDevicesAndLicensedUsers"
	// unknownValue keeps a bounded gauge dimension stable when a fact is not
	// available, rather than emitting an empty label or guessing one.
	unknownValue = "unknown"
)

// Collector polls the Intune role definitions and role assignments.
type Collector struct {
	g       collectors.GraphClient
	baseURL string
	logger  *slog.Logger
}

// New builds the collector. A nil logger falls back to slog.Default().
func New(g collectors.GraphClient, logger *slog.Logger) *Collector {
	if logger == nil {
		logger = slog.Default()
	}
	return &Collector{g: g, baseURL: defaultBaseURL, logger: logger}
}

func (c *Collector) Name() string { return collectorName }

// DefaultInterval is 6h. An RBAC catalog changes on a human timescale, and
// the fetch fans out one request per role definition — a shorter cadence would
// buy detection latency nobody needs at a cost that scales with the number of
// custom roles. intune.audit_events carries the change EVENT itself, so this
// collector's job is the standing STATE.
func (c *Collector) DefaultInterval() time.Duration { return 6 * time.Hour }

// RequiredPermissions declares the single read-only least-privilege scope.
func (c *Collector) RequiredPermissions() []string {
	return []string{"DeviceManagementRBAC.Read.All"}
}

// roleDefinition is one /deviceManagement/roleDefinitions row.
type roleDefinition struct {
	ODataType               string           `json:"@odata.type"`
	ID                      string           `json:"id"`
	DisplayName             string           `json:"displayName"`
	Description             string           `json:"description"`
	IsBuiltIn               bool             `json:"isBuiltIn"`
	IsBuiltInRoleDefinition bool             `json:"isBuiltInRoleDefinition"`
	RoleScopeTagIDs         []string         `json:"roleScopeTagIds"`
	Permissions             []rolePermission `json:"permissions"`
	RolePermissions         []rolePermission `json:"rolePermissions"`
}

// rolePermission is one entry of the permissions / rolePermissions collections.
// Both collections carry this identical shape, and are identical in content on
// every live row — see the package doc.
type rolePermission struct {
	Actions         []string         `json:"actions"`
	ResourceActions []resourceAction `json:"resourceActions"`
}

// resourceAction is the allow/deny pair inside a rolePermission.
type resourceAction struct {
	AllowedResourceActions    []string `json:"allowedResourceActions"`
	NotAllowedResourceActions []string `json:"notAllowedResourceActions"`
}

// roleAssignment is one /deviceManagement/roleAssignments row. It carries no
// reference to the role definition it grants — that link comes from the
// per-definition navigation. See the package doc.
type roleAssignment struct {
	ID              string   `json:"id"`
	DisplayName     string   `json:"displayName"`
	Description     string   `json:"description"`
	ScopeType       string   `json:"scopeType"`
	ScopeMembers    []string `json:"scopeMembers"`
	ResourceScopes  []string `json:"resourceScopes"`
	Members         []string `json:"members"`
	RoleScopeTagIDs []string `json:"roleScopeTagIds"`
}

// Collect fetches the role catalog, the assignment list, and the link between
// them, then emits both bounded gauges and a twin per definition and per
// assignment. A 403 on the catalog (missing scope, or Intune absent on this
// tenant) is a graceful info-level skip rather than a collection failure.
func (c *Collector) Collect(ctx context.Context, e telemetry.Emitter) error {
	defs, err := c.listDefinitions(ctx)
	if err != nil {
		if isForbidden(err) {
			c.logger.Info("rbac: roleDefinitions forbidden (missing scope?); skipping",
				"collector", collectorName, "error", graphclient.FormatODataError(err))
			return nil
		}
		return fmt.Errorf("%s: list role definitions: %w", collectorName, err)
	}

	assignments, err := c.listAssignments(ctx)
	if err != nil {
		return fmt.Errorf("%s: list role assignments: %w", collectorName, err)
	}

	// assignmentRole maps an assignment id to the definition that grants it.
	// A definition whose link fetch fails simply contributes nothing, leaving
	// its assignments unresolved rather than mislabeled.
	assignmentRole := map[string]*roleDefinition{}
	assignmentsPerDef := map[string]int{}
	for i := range defs {
		def := &defs[i]
		ids, lerr := c.listAssignmentIDs(ctx, def.ID)
		if lerr != nil {
			c.logger.Warn("rbac: role definition assignments navigation failed; its assignments stay unresolved",
				"collector", collectorName, "role_definition_id", def.ID, "error", lerr)
			continue
		}
		assignmentsPerDef[def.ID] = len(ids)
		for _, id := range ids {
			assignmentRole[id] = def
		}
	}

	defCounts := map[[3]string]int64{}
	for i := range defs {
		def := &defs[i]
		defCounts[[3]string{
			strconv.FormatBool(def.IsBuiltIn),
			strconv.FormatBool(def.IsBuiltInRoleDefinition),
			subtypeOf(def.ODataType),
		}]++
		e.LogEvent(definitionTwin(def, assignmentsPerDef[def.ID]))
	}

	assignCounts := map[[2]string]int64{}
	for i := range assignments {
		a := &assignments[i]
		def := assignmentRole[a.ID]
		assignCounts[[2]string{orUnknown(a.ScopeType), builtInLabel(def)}]++
		e.LogEvent(assignmentTwin(a, def))
	}

	e.GaugeSnapshot(definitionsMetricName, "{role}",
		"Intune role definitions by built-in flags and @odata.type subtype. Intune keeps its OWN role store, separate from Entra directory roles; both wire built-in flags are emitted because they are separate fields that happen to agree. Per-role detail — name, description, scope tags and the full Microsoft.Intune_* action list — on the intune.role_definition log twin.",
		gaugePoints3(defCounts, semconv.AttrIsBuiltIn, semconv.AttrIsBuiltInRoleDefinition, semconv.AttrRoleDefinitionType))
	e.GaugeSnapshot(assignmentsMetricName, "{assignment}",
		"Intune role assignments by scope type and whether the role they grant is built-in. scope_type=allDevicesAndLicensedUsers with is_built_in=false is a hand-made role holding tenant-wide device management; is_built_in=unknown means the assignment's role definition could not be resolved. Members and scopes on the intune.role_assignment log twin.",
		gaugePoints2(assignCounts, semconv.AttrScopeType, semconv.AttrIsBuiltIn))

	return nil
}

// listDefinitions pages the role-definition catalog.
func (c *Collector) listDefinitions(ctx context.Context) ([]roleDefinition, error) {
	raws, err := collectors.GetAllValues(ctx, c.g, c.baseURL+roleDefinitionsPath, nil)
	if err != nil {
		return nil, err
	}
	defs := make([]roleDefinition, 0, len(raws))
	for _, raw := range raws {
		var d roleDefinition
		if err := json.Unmarshal(raw, &d); err != nil {
			return nil, fmt.Errorf("decode role definition: %w", err)
		}
		defs = append(defs, d)
	}
	return defs, nil
}

// listAssignments pages the top-level assignment collection — the only form
// that carries members, scopeType and scopeMembers.
func (c *Collector) listAssignments(ctx context.Context) ([]roleAssignment, error) {
	raws, err := collectors.GetAllValues(ctx, c.g, c.baseURL+roleAssignmentsPath, nil)
	if err != nil {
		return nil, err
	}
	out := make([]roleAssignment, 0, len(raws))
	for _, raw := range raws {
		var a roleAssignment
		if err := json.Unmarshal(raw, &a); err != nil {
			return nil, fmt.Errorf("decode role assignment: %w", err)
		}
		out = append(out, a)
	}
	return out, nil
}

// listAssignmentIDs walks one definition's roleAssignments navigation and
// returns just the assignment ids. Only the ids are taken: the rows come back
// truncated (empty members, no scopeType), so anything else read here would be
// a worse copy of what the top-level list already has.
func (c *Collector) listAssignmentIDs(ctx context.Context, defID string) ([]string, error) {
	url := c.baseURL + roleDefinitionsPath + "/" + defID + roleAssignmentsSegment
	raws, err := collectors.GetAllValues(ctx, c.g, url, nil)
	if err != nil {
		return nil, err
	}
	ids := make([]string, 0, len(raws))
	for _, raw := range raws {
		var a struct {
			ID string `json:"id"`
		}
		if err := json.Unmarshal(raw, &a); err != nil {
			return nil, fmt.Errorf("decode linked role assignment: %w", err)
		}
		if a.ID != "" {
			ids = append(ids, a.ID)
		}
	}
	return ids, nil
}

// definitionTwin renders one role definition as a log record — the per-entity
// half the bounded gauge cannot carry. The timestamp is left zero ("now"): this
// is a re-emitted state snapshot, not an event stream, so "which roles existed
// at 14:00" stays answerable.
//
// Severity is always INFO, including for a custom role. A role definition grants
// nothing until something is assigned to it, so the actionable judgment lives on
// the ASSIGNMENT twin; warning here as well would fire twice for one fact and
// once for a custom role nobody holds.
func definitionTwin(d *roleDefinition, assignmentCount int) telemetry.Event {
	attrs := telemetry.Attrs{}
	telemetry.SetStr(attrs, semconv.AttrRoleId, d.ID)
	telemetry.SetStr(attrs, semconv.AttrRoleName, d.DisplayName)
	telemetry.SetStr(attrs, semconv.AttrDisplayName, d.DisplayName)
	telemetry.SetStr(attrs, semconv.AttrDescription, d.Description)
	telemetry.SetStr(attrs, semconv.AttrRoleDefinitionType, subtypeOf(d.ODataType))
	telemetry.SetBool(attrs, semconv.AttrIsBuiltIn, d.IsBuiltIn)
	telemetry.SetBool(attrs, semconv.AttrIsBuiltInRoleDefinition, d.IsBuiltInRoleDefinition)
	telemetry.SetStrs(attrs, semconv.AttrActions, allowedActions(d))
	telemetry.SetStrs(attrs, semconv.AttrNotAllowedActions, deniedActions(d))
	telemetry.SetStrs(attrs, semconv.AttrRoleScopeTagIds, d.RoleScopeTagIDs)
	attrs[semconv.AttrAssignmentCount] = assignmentCount

	return telemetry.Event{
		Name: eventRoleDefinition,
		Body: fmt.Sprintf("intune role definition %s: is_built_in=%t assignment_count=%d actions=%d",
			labelOf(d.DisplayName, d.ID), d.IsBuiltIn, assignmentCount, len(allowedActions(d))),
		Severity: telemetry.SeverityInfo,
		Attrs:    attrs,
	}
}

// assignmentTwin renders one role assignment as a log record. def is nil when
// the definition→assignment link could not be resolved, and in that case the
// role fields are OMITTED rather than filled with a placeholder: a missing link
// must read as missing, not as a role named "unknown".
//
// Severity is WARN when the assignment holds the tenant's widest scope
// (allDevicesAndLicensedUsers) and the role it grants is not a known built-in —
// that is, a hand-made role with tenant-wide device management, or one whose
// identity graph2otel could not establish. Both cases are "something can wipe
// the fleet and it is not a Microsoft-authored role". Everything else is INFO,
// including a built-in role at the widest scope, which is the ordinary way
// Intune is administered.
func assignmentTwin(a *roleAssignment, def *roleDefinition) telemetry.Event {
	attrs := telemetry.Attrs{}
	telemetry.SetStr(attrs, semconv.AttrRoleAssignmentId, a.ID)
	telemetry.SetStr(attrs, semconv.AttrDisplayName, a.DisplayName)
	telemetry.SetStr(attrs, semconv.AttrDescription, a.Description)
	telemetry.SetStr(attrs, semconv.AttrScopeType, a.ScopeType)
	telemetry.SetStrs(attrs, semconv.AttrScopeMembers, a.ScopeMembers)
	telemetry.SetStrs(attrs, semconv.AttrResourceScopes, a.ResourceScopes)
	telemetry.SetStrs(attrs, semconv.AttrMembers, a.Members)
	telemetry.SetStrs(attrs, semconv.AttrRoleScopeTagIds, a.RoleScopeTagIDs)
	attrs[semconv.AttrMembersCount] = len(a.Members)

	roleName := ""
	if def != nil {
		telemetry.SetStr(attrs, semconv.AttrRoleId, def.ID)
		telemetry.SetStr(attrs, semconv.AttrRoleName, def.DisplayName)
		telemetry.SetBool(attrs, semconv.AttrIsBuiltIn, def.IsBuiltIn)
		roleName = def.DisplayName
	}

	severity := telemetry.SeverityInfo
	if a.ScopeType == scopeTypeAllDevices && (def == nil || !def.IsBuiltIn) {
		severity = telemetry.SeverityWarn
	}

	return telemetry.Event{
		Name: eventRoleAssignment,
		Body: fmt.Sprintf("intune role assignment %s: role=%s scope_type=%s members=%d",
			labelOf(a.DisplayName, a.ID), labelOf(roleName, unknownValue), orUnknown(a.ScopeType), len(a.Members)),
		Severity: severity,
		Attrs:    attrs,
	}
}

// allowedActions is the sorted, deduplicated union of every action a role
// grants, drawn from BOTH permissions and rolePermissions and from both the
// bare `actions` list and `resourceActions[].allowedResourceActions`. The four
// are identical on every live row; taking the union means a future divergence
// costs nothing rather than silently dropping half a role's rights (#114).
func allowedActions(d *roleDefinition) []string {
	set := map[string]struct{}{}
	for _, p := range append(append([]rolePermission{}, d.Permissions...), d.RolePermissions...) {
		for _, a := range p.Actions {
			set[a] = struct{}{}
		}
		for _, ra := range p.ResourceActions {
			for _, a := range ra.AllowedResourceActions {
				set[a] = struct{}{}
			}
		}
	}
	return sortedKeys(set)
}

// deniedActions is the sorted union of every explicit deny entry. Empty on all
// live rows, in which case the attribute is omitted rather than emitted blank.
func deniedActions(d *roleDefinition) []string {
	set := map[string]struct{}{}
	for _, p := range append(append([]rolePermission{}, d.Permissions...), d.RolePermissions...) {
		for _, ra := range p.ResourceActions {
			for _, a := range ra.NotAllowedResourceActions {
				set[a] = struct{}{}
			}
		}
	}
	return sortedKeys(set)
}

func sortedKeys(set map[string]struct{}) []string {
	if len(set) == 0 {
		return nil
	}
	out := make([]string, 0, len(set))
	for k := range set {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// gaugePoints3 renders a three-dimensional count map as gauge points.
func gaugePoints3(counts map[[3]string]int64, k0, k1, k2 string) []telemetry.GaugePoint {
	points := make([]telemetry.GaugePoint, 0, len(counts))
	for k, v := range counts {
		points = append(points, telemetry.GaugePoint{
			Value: float64(v),
			Attrs: telemetry.Attrs{k0: k[0], k1: k[1], k2: k[2]},
		})
	}
	return points
}

// gaugePoints2 renders a two-dimensional count map as gauge points.
func gaugePoints2(counts map[[2]string]int64, k0, k1 string) []telemetry.GaugePoint {
	points := make([]telemetry.GaugePoint, 0, len(counts))
	for k, v := range counts {
		points = append(points, telemetry.GaugePoint{
			Value: float64(v),
			Attrs: telemetry.Attrs{k0: k[0], k1: k[1]},
		})
	}
	return points
}

// builtInLabel renders the assignment gauge's is_built_in dimension. An
// unresolved role definition yields "unknown" rather than defaulting to false,
// which would report a built-in assignment as a hand-made one.
func builtInLabel(def *roleDefinition) string {
	if def == nil {
		return unknownValue
	}
	return strconv.FormatBool(def.IsBuiltIn)
}

// subtypeOf strips the "#microsoft.graph." prefix off an @odata.type
// discriminator. A row without one (the top-level assignment shape) yields
// "unknown" rather than an empty gauge label.
func subtypeOf(odataType string) string {
	return orUnknown(strings.TrimPrefix(odataType, odataTypePrefix))
}

// labelOf picks the most human identifier available for a log body.
func labelOf(preferred, fallback string) string {
	if preferred != "" {
		return preferred
	}
	if fallback != "" {
		return fallback
	}
	return unknownValue
}

// orUnknown keeps a bounded gauge dimension from ever carrying an empty label.
func orUnknown(v string) string {
	if v == "" {
		return unknownValue
	}
	return v
}

// isForbidden reports whether err is a Graph 403 — a graceful skip (missing
// scope, or the surface absent on this tenant) rather than a collection failure.
func isForbidden(err error) bool {
	if err == nil {
		return false
	}
	if strings.Contains(err.Error(), "status 403") {
		return true
	}
	if code, _, ok := graphclient.UnwrapODataError(err); ok {
		return code == "Authorization_RequestDenied"
	}
	return false
}

var (
	_ collector.SnapshotCollector  = (*Collector)(nil)
	_ preflight.PermissionRequirer = (*Collector)(nil)
)

func init() {
	collectors.Register(func(d collectors.Deps) collector.SnapshotCollector {
		return New(d.Graph, d.Logger)
	})
}
