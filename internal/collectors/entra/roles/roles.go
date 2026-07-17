// Package roles is the Entra privileged-access-posture collector: standing
// directory-role membership (Free, every tier) plus PIM active/eligible/
// permanent assignments (P2-gated, partial degrade). Global Admin count and
// similar headline compliance figures are just one bounded role_name value
// within the standing-membership series, not a separate metric.
//
// # Both sides of the cardinality boundary, from one fetch
//
// Each half emits TWO things per cycle, from fetches it was already making:
//
//   - bounded GAUGES counted by role_name x assignment_type — the aggregate;
//   - one entra.role_member LOG per principal, carrying who actually holds the
//     role: object id, principal type, display name, UPN (users) or appId
//     (service principals), and for PIM the permanence/expiry.
//
// The log twin is the other half of the rule, not garnish. Per-principal
// identity must never become a metric label (a series per admin grows with
// tenant size), but "not a metric label" means "log twin", NOT "dropped".
// This collector previously paged every member object and then kept only
// len(members) — so the identity of every Global Admin was decoded into memory
// and thrown away, and "WHO is in Global Admin" was unanswerable. Same for the
// PIM half, which never decoded principalId at all despite it being right
// there in the response. That was a bug (#114), not a privacy control: the
// logs pipeline is where this belongs. See SECURITY.md.
//
// This is a STATE feed: every member is re-emitted each cycle for as long as
// they hold the role, which is what makes "who was Global Admin on the 3rd"
// answerable. Volume scales with the number of privileged principals (small by
// definition — a tenant with thousands of Global Admins has a bigger problem
// than log volume), not with tenant size.
//
// Severity is Info throughout, deliberately. Role membership is state, not an
// anomaly: warning on it would fire every cycle for every admin and make the
// severity dimension useless. The value here is queryability and change
// detection over time, not alerting.
package roles

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"strconv"
	"time"

	"github.com/rknightion/graph2otel/internal/collector"
	"github.com/rknightion/graph2otel/internal/collectors"
	"github.com/rknightion/graph2otel/internal/license"
	"github.com/rknightion/graph2otel/internal/semconv"
	"github.com/rknightion/graph2otel/internal/telemetry"
)

// collectorName is the stable key used for config (enable/interval),
// self-observability, and the admin status page.
const collectorName = "entra.roles"

// Metric names this collector emits.
const (
	// membersMetricName is the standing directory-role membership count, Free
	// tier, always emitted. role_name is bounded by the tenant's activated
	// directory-role catalog (a fixed, small set).
	membersMetricName = "entra.roles.members.total"
	// pimAssignmentsMetricName is the PIM active/eligible assignment count per
	// role, P2-gated. assignment_type is the only other dimension, so
	// cardinality is len(roles) * 2 at most.
	pimAssignmentsMetricName = "entra.pim.assignments.total"
	// pimPermanentMetricName is the count, per role, of ACTIVE PIM assignments
	// with no end time (i.e. not time-bound), P2-gated.
	pimPermanentMetricName = "entra.pim.permanent_assignments.total"
)

// defaultBaseURL is the Graph v1.0 root.
const defaultBaseURL = "https://graph.microsoft.com/v1.0"

// unknownRoleName is the bounded fallback bucket for a PIM schedule instance
// whose roleDefinition failed to expand (e.g. a dangling/deleted role
// definition). It keeps the series set bounded (one extra value) instead of
// falling back to the opaque, effectively-unbounded roleDefinitionId GUID.
const unknownRoleName = "unknown"

// expandRoleDefinitionQuery is appended to both PIM schedule-instance
// endpoints so the response carries a human-readable, catalog-bounded role
// name directly (roleDefinition.displayName) - no separate per-role lookup
// call is needed. "roleDefinition" has no characters requiring escaping, so
// this is a plain literal rather than built through net/url.
const expandRoleDefinitionQuery = "$expand=roleDefinition"

// directoryRole mirrors the Graph directoryRole resource fields this
// collector reads.
type directoryRole struct {
	ID          string `json:"id"`
	DisplayName string `json:"displayName"`
}

// eventRoleMember is the OTLP LogRecord EventName every role-membership twin
// carries — standing members and PIM assignments alike, discriminated by the
// assignment_type attribute ("standing" / "active" / "eligible", the same
// vocabulary the gauges use).
const eventRoleMember = "entra.role_member"

// roleMember is one element of the polymorphic directoryObject collection
// returned by GET /directoryRoles/{id}/members. The kind is discriminated by
// @odata.type: a user carries userPrincipalName, a service principal carries
// appId, and a group/device carries neither — so one struct decodes all of
// them and logTwin omits whatever is absent.
type roleMember struct {
	ODataType         string `json:"@odata.type"`
	ID                string `json:"id"`
	DisplayName       string `json:"displayName"`
	UserPrincipalName string `json:"userPrincipalName"`
	AppID             string `json:"appId"`
}

// principalTypes maps the @odata.type discriminator to graph2otel's bounded
// principal_type vocabulary. Anything unrecognized (or absent) collapses to
// "unknown" rather than leaking a raw OData type string.
var principalTypes = map[string]string{
	"#microsoft.graph.user":             "user",
	"#microsoft.graph.servicePrincipal": "service_principal",
	"#microsoft.graph.group":            "group",
	"#microsoft.graph.device":           "device",
	"#microsoft.graph.orgContact":       "org_contact",
}

// principalType normalizes a member's @odata.type.
func principalType(odataType string) string {
	if t, ok := principalTypes[odataType]; ok {
		return t
	}
	return "unknown"
}

// memberLogTwin renders one standing directory-role member as a log record.
//
// Severity is Info for every member, deliberately: standing role membership is
// STATE, not an anomaly. A tenant's Global Admins are re-emitted every cycle,
// so warning on them would fire constantly and make the severity dimension
// useless. The value here is queryability ("who holds this role, and when did
// that set change"), not alerting.
func memberLogTwin(m roleMember, role directoryRole) telemetry.Event {
	attrs := telemetry.Attrs{}
	telemetry.SetStr(attrs, semconv.AttrAssignmentType, "standing")
	telemetry.SetStr(attrs, semconv.AttrRoleName, role.DisplayName)
	telemetry.SetStr(attrs, semconv.AttrRoleId, role.ID)
	telemetry.SetStr(attrs, semconv.AttrPrincipalId, m.ID)
	telemetry.SetStr(attrs, semconv.AttrPrincipalType, principalType(m.ODataType))
	telemetry.SetStr(attrs, semconv.AttrPrincipalDisplayName, m.DisplayName)
	telemetry.SetStr(attrs, semconv.AttrPrincipalUserPrincipalName, m.UserPrincipalName)
	telemetry.SetStr(attrs, semconv.AttrPrincipalAppId, m.AppID)

	who := m.UserPrincipalName
	if who == "" {
		who = m.DisplayName
	}
	if who == "" {
		who = m.ID
	}
	return telemetry.Event{
		Name:     eventRoleMember,
		Body:     fmt.Sprintf("%s: standing member %s", role.DisplayName, who),
		Severity: telemetry.SeverityInfo,
		Attrs:    attrs,
	}
}

// pimLogTwin renders one PIM schedule instance (active or eligible) as a log
// record. Severity is Info for the same reason as memberLogTwin — this is
// state, not an event.
//
// principal_id is the only identifier available: these endpoints return a bare
// principalId and the collector requests $expand=roleDefinition but NOT
// $expand=principal, so no UPN/display name is on the wire. Resolving it would
// mean either widening the expand (unverified cost against the live tenant) or
// a per-principal fan-out (a Graph call per assignment). Left as-is
// deliberately; the id joins to entra.role_member's standing twins and to the
// sign-in logs, so it is not a dead end.
func pimLogTwin(inst scheduleInstance, assignmentType string) telemetry.Event {
	attrs := telemetry.Attrs{}
	telemetry.SetStr(attrs, semconv.AttrAssignmentType, assignmentType)
	telemetry.SetStr(attrs, semconv.AttrRoleName, inst.roleName())
	telemetry.SetStr(attrs, semconv.AttrPrincipalId, inst.PrincipalID)

	permanent := inst.EndDateTime == nil
	telemetry.SetStr(attrs, semconv.AttrPermanent, strconv.FormatBool(permanent))
	if !permanent {
		telemetry.SetStr(attrs, semconv.AttrEndDateTime, *inst.EndDateTime)
	}

	kind := "time-bound"
	if permanent {
		kind = "permanent"
	}
	return telemetry.Event{
		Name:     eventRoleMember,
		Body:     fmt.Sprintf("%s: %s PIM assignment for %s (%s)", inst.roleName(), assignmentType, inst.PrincipalID, kind),
		Severity: telemetry.SeverityInfo,
		Attrs:    attrs,
	}
}

// scheduleInstance mirrors the fields shared by unifiedRoleAssignmentScheduleInstance
// and unifiedRoleEligibilityScheduleInstance that this collector reads, with
// $expand=roleDefinition requested so RoleDefinition.DisplayName is populated.
type scheduleInstance struct {
	// PrincipalID identifies who holds (or is eligible for) the role. It is
	// dropped from the bounded gauge — a per-principal series would grow with
	// tenant size — and carried by the log twin instead.
	PrincipalID    string             `json:"principalId"`
	EndDateTime    *string            `json:"endDateTime"`
	RoleDefinition *roleDefinitionRef `json:"roleDefinition"`
}

// roleDefinitionRef is the $expand=roleDefinition payload shape this collector
// reads.
type roleDefinitionRef struct {
	DisplayName string `json:"displayName"`
}

// roleName returns the bounded role_name attribute value for a schedule
// instance: the expanded roleDefinition's display name, or unknownRoleName
// when the expansion is missing/empty.
func (s scheduleInstance) roleName() string {
	if s.RoleDefinition == nil || s.RoleDefinition.DisplayName == "" {
		return unknownRoleName
	}
	return s.RoleDefinition.DisplayName
}

// Collector polls standing directory-role membership (Free) and PIM
// active/eligible/permanent assignment counts (P2-gated).
type Collector struct {
	g       collectors.GraphClient
	caps    license.Capabilities
	baseURL string
	logger  *slog.Logger
}

// New builds the roles collector. A nil logger falls back to the slog
// default. caps gates only the PIM half of Collect - the standing-membership
// half always runs, on every tier, which is why this collector deliberately
// does NOT implement license.CapabilityRequirer.
func New(g collectors.GraphClient, caps license.Capabilities, logger *slog.Logger) *Collector {
	if logger == nil {
		logger = slog.Default()
	}
	return &Collector{g: g, caps: caps, baseURL: defaultBaseURL, logger: logger}
}

// Name implements collector.Collector.
func (c *Collector) Name() string { return collectorName }

// DefaultInterval implements collector.Collector. Privileged-role membership
// and PIM assignments change infrequently, and none of these endpoints
// support delta queries (a full read every cycle), so a longer interval than
// the cheap directory-counts collector is appropriate.
func (c *Collector) DefaultInterval() time.Duration { return 10 * time.Minute }

// RequiredPermissions declares the least-privilege Graph application scopes.
// RoleManagement.Read.Directory covers /directoryRoles and its members (the
// standing, Free-tier half, needed on every tenant regardless of license).
// RoleAssignmentSchedule.Read.Directory and RoleEligibilitySchedule.Read.Directory
// are the narrower, per-endpoint least-privileged scopes Microsoft's current
// docs list for the two roleManagement schedule-instance endpoints (verified
// 2026-07-15) - narrower than the single blanket RoleManagement.Read.Directory
// the issue's API table names for all three rows, per the authoring guide's
// "prefer the specific scope" rule. They are declared unconditionally (not
// only when P2 is detected) since Graph app-permission grants are static and a
// tenant's license tier can change without redeploying the app registration.
func (c *Collector) RequiredPermissions() []string {
	return []string{
		"RoleManagement.Read.Directory",
		"RoleAssignmentSchedule.Read.Directory",
		"RoleEligibilitySchedule.Read.Directory",
	}
}

// Collect emits standing directory-role membership counts unconditionally,
// then - only when the tenant holds CapEntraP2 - emits PIM active/eligible
// assignment counts and the permanent-assignment count. On a non-P2 tenant
// the PIM half is skipped entirely (not emitted as an empty snapshot) and
// logged at info level, matching license.SkipReason's spirit for a
// partially-degraded (not fully gated) collector.
func (c *Collector) Collect(ctx context.Context, e telemetry.Emitter) error {
	var errs []error

	if err := c.collectStandingMembers(ctx, e); err != nil {
		errs = append(errs, err)
	}

	if !c.caps.Has(license.CapEntraP2) {
		c.logger.Info("skipping PIM assignment counts: requires entra_p2", "collector", collectorName)
	} else if err := c.collectPIMAssignments(ctx, e); err != nil {
		errs = append(errs, err)
	}

	return errors.Join(errs...)
}

// collectStandingMembers fetches the activated directory-role catalog and,
// per role, its member count, emitting one bounded gauge snapshot. A failure
// fetching the catalog itself drops the whole snapshot (nothing to iterate);
// a failure on one role's member count is logged and that role is dropped
// from the snapshot, but the others still emit.
func (c *Collector) collectStandingMembers(ctx context.Context, e telemetry.Emitter) error {
	raw, err := collectors.GetAllValues(ctx, c.g, c.baseURL+"/directoryRoles", nil)
	if err != nil {
		c.logger.Warn("directoryRoles fetch failed", "collector", collectorName, "error", err)
		return fmt.Errorf("directoryRoles: %w", err)
	}

	var errs []error
	points := make([]telemetry.GaugePoint, 0, len(raw))
	for _, r := range raw {
		var role directoryRole
		if err := json.Unmarshal(r, &role); err != nil {
			c.logger.Warn("skipping unparseable directoryRole", "collector", collectorName, "error", err)
			errs = append(errs, fmt.Errorf("decode directoryRole: %w", err))
			continue
		}
		if role.ID == "" || role.DisplayName == "" {
			c.logger.Warn("skipping directoryRole with empty id/displayName", "collector", collectorName)
			continue
		}

		members, err := collectors.GetAllValues(ctx, c.g, c.baseURL+"/directoryRoles/"+role.ID+"/members", nil)
		if err != nil {
			c.logger.Warn("directoryRole members fetch failed", "collector", collectorName, "role", role.DisplayName, "error", err)
			errs = append(errs, fmt.Errorf("members(%s): %w", role.DisplayName, err))
			continue
		}

		// The member objects are already fully in hand here, so the twin costs
		// no extra Graph call. A member that fails to decode still counts
		// toward the gauge (it exists) but emits no twin.
		for _, m := range members {
			var member roleMember
			if err := json.Unmarshal(m, &member); err != nil {
				c.logger.Warn("skipping unparseable directoryRole member", "collector", collectorName, "role", role.DisplayName, "error", err)
				continue
			}
			e.LogEvent(memberLogTwin(member, role))
		}

		points = append(points, telemetry.GaugePoint{
			Value: float64(len(members)),
			Attrs: telemetry.Attrs{semconv.AttrRoleName: role.DisplayName},
		})
	}

	e.GaugeSnapshot(membersMetricName, "{member}", "Standing (non-PIM) Entra directory-role membership count, per role.", points)
	return errors.Join(errs...)
}

// collectPIMAssignments fetches active and eligible PIM role-assignment
// schedule instances and emits the per-role active/eligible counts plus the
// per-role permanent (no end time) active-assignment count. Neither endpoint
// supports delta queries, so this is a full read every cycle.
func (c *Collector) collectPIMAssignments(ctx context.Context, e telemetry.Emitter) error {
	var errs []error

	activeByRole := map[string]int64{}
	permanentByRole := map[string]int64{}
	active, err := collectors.GetAllValues(ctx, c.g, c.baseURL+"/roleManagement/directory/roleAssignmentScheduleInstances?"+expandRoleDefinitionQuery, nil)
	if err != nil {
		c.logger.Warn("roleAssignmentScheduleInstances fetch failed", "collector", collectorName, "error", err)
		errs = append(errs, fmt.Errorf("roleAssignmentScheduleInstances: %w", err))
	} else {
		for _, r := range active {
			var inst scheduleInstance
			if err := json.Unmarshal(r, &inst); err != nil {
				c.logger.Warn("skipping unparseable roleAssignmentScheduleInstance", "collector", collectorName, "error", err)
				continue
			}
			name := inst.roleName()
			activeByRole[name]++
			if inst.EndDateTime == nil {
				permanentByRole[name]++
			}
			e.LogEvent(pimLogTwin(inst, "active"))
		}
	}

	eligibleByRole := map[string]int64{}
	eligible, err := collectors.GetAllValues(ctx, c.g, c.baseURL+"/roleManagement/directory/roleEligibilityScheduleInstances?"+expandRoleDefinitionQuery, nil)
	if err != nil {
		c.logger.Warn("roleEligibilityScheduleInstances fetch failed", "collector", collectorName, "error", err)
		errs = append(errs, fmt.Errorf("roleEligibilityScheduleInstances: %w", err))
	} else {
		for _, r := range eligible {
			var inst scheduleInstance
			if err := json.Unmarshal(r, &inst); err != nil {
				c.logger.Warn("skipping unparseable roleEligibilityScheduleInstance", "collector", collectorName, "error", err)
				continue
			}
			eligibleByRole[inst.roleName()]++
			e.LogEvent(pimLogTwin(inst, "eligible"))
		}
	}

	assignmentPoints := make([]telemetry.GaugePoint, 0, len(activeByRole)+len(eligibleByRole))
	for role, n := range activeByRole {
		assignmentPoints = append(assignmentPoints, telemetry.GaugePoint{
			Value: float64(n),
			Attrs: telemetry.Attrs{semconv.AttrRoleName: role, semconv.AttrAssignmentType: "active"},
		})
	}
	for role, n := range eligibleByRole {
		assignmentPoints = append(assignmentPoints, telemetry.GaugePoint{
			Value: float64(n),
			Attrs: telemetry.Attrs{semconv.AttrRoleName: role, semconv.AttrAssignmentType: "eligible"},
		})
	}
	e.GaugeSnapshot(pimAssignmentsMetricName, "{assignment}", "PIM active/eligible directory-role assignment count, per role and assignment_type.", assignmentPoints)

	permanentPoints := make([]telemetry.GaugePoint, 0, len(permanentByRole))
	for role, n := range permanentByRole {
		permanentPoints = append(permanentPoints, telemetry.GaugePoint{
			Value: float64(n),
			Attrs: telemetry.Attrs{semconv.AttrRoleName: role},
		})
	}
	e.GaugeSnapshot(pimPermanentMetricName, "{assignment}", "Active PIM directory-role assignments with no end time (not time-bound), per role.", permanentPoints)

	return errors.Join(errs...)
}

func init() {
	collectors.Register(func(d collectors.Deps) collector.SnapshotCollector {
		return New(d.Graph, d.Caps, d.Logger)
	})
}
