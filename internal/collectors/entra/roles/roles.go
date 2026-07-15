// Package roles is the Entra privileged-access-posture collector: standing
// directory-role membership counts (Free, every tier) plus PIM active/
// eligible/permanent assignment counts (P2-gated, partial degrade). Global
// Admin count and similar headline compliance figures are just one bounded
// role_name value within the standing-membership series, not a separate
// metric.
package roles

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/rknightion/graph2otel/internal/collector"
	"github.com/rknightion/graph2otel/internal/collectors"
	"github.com/rknightion/graph2otel/internal/license"
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

// scheduleInstance mirrors the fields shared by unifiedRoleAssignmentScheduleInstance
// and unifiedRoleEligibilityScheduleInstance that this collector reads, with
// $expand=roleDefinition requested so RoleDefinition.DisplayName is populated.
type scheduleInstance struct {
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
		points = append(points, telemetry.GaugePoint{
			Value: float64(len(members)),
			Attrs: telemetry.Attrs{"role_name": role.DisplayName},
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
		}
	}

	assignmentPoints := make([]telemetry.GaugePoint, 0, len(activeByRole)+len(eligibleByRole))
	for role, n := range activeByRole {
		assignmentPoints = append(assignmentPoints, telemetry.GaugePoint{
			Value: float64(n),
			Attrs: telemetry.Attrs{"role_name": role, "assignment_type": "active"},
		})
	}
	for role, n := range eligibleByRole {
		assignmentPoints = append(assignmentPoints, telemetry.GaugePoint{
			Value: float64(n),
			Attrs: telemetry.Attrs{"role_name": role, "assignment_type": "eligible"},
		})
	}
	e.GaugeSnapshot(pimAssignmentsMetricName, "{assignment}", "PIM active/eligible directory-role assignment count, per role and assignment_type.", assignmentPoints)

	permanentPoints := make([]telemetry.GaugePoint, 0, len(permanentByRole))
	for role, n := range permanentByRole {
		permanentPoints = append(permanentPoints, telemetry.GaugePoint{
			Value: float64(n),
			Attrs: telemetry.Attrs{"role_name": role},
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
