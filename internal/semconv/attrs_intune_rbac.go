package semconv

// Attribute keys introduced by intune.rbac (#257) — the Intune RBAC store,
// which is a SEPARATE role store from Entra directory roles and is invisible to
// entra.roles.
//
// # What is reused rather than re-coined
//
// Most of the record already has a key in this package, and those are REUSED so
// an Intune role assignment and an Entra directory-role assignment answer the
// same LogQL filter without a translation table:
//
//	roleDefinition.id           -> AttrRoleId          ("role_id")
//	roleDefinition.displayName  -> AttrDisplayName / AttrRoleName
//	roleDefinition.description  -> AttrDescription
//	roleDefinition.isBuiltIn    -> AttrIsBuiltIn       ("is_built_in")
//	permissions[].actions       -> AttrActions         ("actions")
//	len(members)                -> AttrMembersCount    ("members_count")
//
// AttrRoleId/AttrRoleName carry an INTUNE role here and an Entra directory role
// in entra.roles. That is the same thing (the identity of a role a principal
// holds) attached to two different stores, not two different things sharing a
// key — the #225 failure. `event_name` separates them, which is exactly the
// separation #257 exists to make visible.
//
// Every key below is LOG-ONLY except the three noted as bounded gauge
// dimensions. `actions` in particular is an unbounded `Microsoft.Intune_*` list
// (121 entries on one live built-in role) and is the only field that says what a
// custom role can actually DO, so it must ride the twin and must never be
// dropped (#114).
const (
	// AttrRoleDefinitionType is the wire's `@odata.type` discriminator with the
	// `#microsoft.graph.` prefix stripped — `deviceAndAppManagementRoleDefinition`
	// on every live row. It is READ rather than assumed because a different
	// subtype may carry a different field set. Bounded (a handful of subtypes),
	// so it is a legitimate gauge dimension.
	AttrRoleDefinitionType = "role_definition_type"
	// AttrIsBuiltInRoleDefinition is the wire's `isBuiltInRoleDefinition`, which
	// is present ALONGSIDE `isBuiltIn` on the same record and agrees with it on
	// every live row. Both are emitted, and both are gauge dimensions, precisely
	// so a future disagreement is visible as a new series rather than silently
	// resolved by a mapper that assumed one was a rename of the other (#142).
	AttrIsBuiltInRoleDefinition = "is_built_in_role_definition"
	// AttrNotAllowedActions is the union of
	// `permissions[].resourceActions[].notAllowedResourceActions` — the explicit
	// deny half of a role's permission set. Empty on every live row; the
	// attribute is omitted rather than emitted blank.
	AttrNotAllowedActions = "not_allowed_actions"
	// AttrRoleScopeTagIds is the role's `roleScopeTagIds` collection: the scope
	// tags that bound which objects the role can see.
	AttrRoleScopeTagIds = "role_scope_tag_ids"
	// AttrAssignmentCount is how many role assignments reference this role
	// definition. A custom role with zero assignments grants nothing; the same
	// role with assignments is the thing worth looking at.
	AttrAssignmentCount = "assignment_count"

	// AttrRoleAssignmentId is the assignment's own id — distinct from
	// AttrRoleId, which is the id of the ROLE it grants.
	AttrRoleAssignmentId = "role_assignment_id"
	// AttrScopeType is the assignment's `scopeType` — a bounded wire enum whose
	// widest value, `allDevicesAndLicensedUsers`, means tenant-wide device
	// management. It is a gauge dimension and drives severity.
	AttrScopeType = "scope_type"
	// AttrScopeMembers is the assignment's `scopeMembers` collection: the group
	// object ids that bound WHICH devices/users the assignment covers. Empty on
	// an `allDevicesAndLicensedUsers` assignment, which is what makes that scope
	// type unbounded.
	AttrScopeMembers = "scope_members"
	// AttrResourceScopes is the assignment's `resourceScopes` collection.
	AttrResourceScopes = "resource_scopes"
	// AttrMembers is the assignment's `members` collection: the principal object
	// ids the role is granted to.
	//
	// These are emitted as BARE GUIDS, deliberately unresolved. Graph returns no
	// names here, so putting names on the record would mean a second lookup per
	// assignment against a directory scope this collector does not otherwise
	// need — and a name resolved from a different store is a name that can be
	// wrong. An unresolved guid is honest; a fabricated name is not. The guid
	// joins to entra.groups / entra.users in the backend, which already carry
	// the mapping.
	AttrMembers = "members"
)
