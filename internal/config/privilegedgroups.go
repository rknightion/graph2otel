package config

import (
	"fmt"
	"strings"
)

// MaxPrivilegedGroupAllowlist bounds how many group ids a tenant may allowlist
// for the per-group member-count gauge (#337, the surviving residual of #43).
//
// The allowlist IS the cardinality bound — group_id becomes a metric label
// only for groups an operator explicitly named, unlike every other group
// signal in this project (entra.groups.total et al., which are strictly
// bounded population aggregates with no per-group dimension). 50 is chosen as
// a number an operator can assign and audit BY HAND in one sitting: it is
// generously above Entra ID's built-in privileged directory roles (a few
// dozen, per Microsoft's own role-assignable-groups guidance) plus realistic
// headroom for a handful of tenant-specific break-glass/PIM-eligible groups,
// while still being small enough that a config reviewer can read the whole
// list and vouch for every entry. It is deliberately NOT hundreds: an
// allowlist an operator cannot review by eye has stopped doing the job an
// allowlist is for.
const MaxPrivilegedGroupAllowlist = 50

// PrivilegedGroupsConfig is a per-tenant, explicitly configured allowlist of
// group ids to track member-count gauges for (#337). Member counts are
// emitted ONLY for groups on this list — no group outside it ever creates a
// series, so tenant size never determines this collector's cardinality.
type PrivilegedGroupsConfig struct {
	// GroupIDs is the allowlist: Entra group object ids (GUIDs) to track. Empty
	// (the default) registers no privileged-groups collector for this tenant,
	// exactly as an unset blob_ingest.account_url registers no blob collectors.
	GroupIDs []string `yaml:"group_ids"`
}

// Configured reports whether this tenant has opted into the privileged-groups
// collector. A non-empty GroupIDs is the whole opt-in.
func (p PrivilegedGroupsConfig) Configured() bool { return len(p.GroupIDs) > 0 }

// validate checks a privileged_groups block in isolation: an unset/empty
// allowlist is valid (opt-out); a set one must stay at or under
// MaxPrivilegedGroupAllowlist, and every entry must be non-empty and unique.
func (p PrivilegedGroupsConfig) validate() error {
	if len(p.GroupIDs) == 0 {
		return nil
	}
	if len(p.GroupIDs) > MaxPrivilegedGroupAllowlist {
		return fmt.Errorf("group_ids has %d entries, exceeds the maximum of %d allowlisted privileged groups", len(p.GroupIDs), MaxPrivilegedGroupAllowlist)
	}
	seen := make(map[string]bool, len(p.GroupIDs))
	for i, id := range p.GroupIDs {
		trimmed := strings.TrimSpace(id)
		if trimmed == "" {
			return fmt.Errorf("group_ids[%d] is empty", i)
		}
		if seen[trimmed] {
			return fmt.Errorf("group_ids[%d] %q is a duplicate", i, trimmed)
		}
		seen[trimmed] = true
	}
	return nil
}
