package semconv

// Attribute keys introduced by entra.privileged_groups (#337, the surviving
// residual of #43): the allowlisted privileged-group member-count gauge.
//
// group_id is REUSED from AttrGroupId (attrs_defender.go) rather than
// re-coined, and reason from AttrReason (attrs.go) — the registry's
// no-duplicate-values gate would fail a second constant carrying either
// string. Both are METRIC LABELS here, unlike their existing Defender/generic
// uses, but that is safe: group_id is bounded by the tenant's configured
// allowlist (validated to at most config.MaxPrivilegedGroupAllowlist entries),
// not by tenant population, so it never becomes the per-entity-label mistake
// #112 exists to prevent.
const (
	// AttrAccessible is whether this cycle's fetch for an allowlisted group
	// succeeded. It rides BOTH the entra.privileged_groups.accessible gauge
	// (as the value, 1/0 — not a label) and the log twin (as a bool attribute)
	// so "the group has zero members" and "graph2otel could not read the
	// group" are never conflated: a group missing from the member-count gauge
	// this cycle always has a companion accessible=0 point, never silence
	// alone.
	AttrAccessible = "accessible"

	// AttrMemberCount is the log twin's measured member count, mirroring the
	// entra.privileged_groups.members.total gauge value as a log attribute so
	// the twin is self-sufficient without joining back to the metric. Log-only
	// (never a metric label — the count itself IS the gauge's value already).
	AttrMemberCount = "member_count"
)
