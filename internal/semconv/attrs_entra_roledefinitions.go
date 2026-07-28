package semconv

// Attribute keys introduced by entra.role_definitions (#320) — the Entra
// directory ROLE DEFINITION catalog (roleManagement/directory/roleDefinitions),
// distinct from entra.roles' standing/PIM ASSIGNMENTS: a definition can exist,
// be custom, or be disabled with zero current assignments, which is exactly
// the visibility gap this collector closes.
//
// # What is reused rather than re-coined
//
// AttrId, AttrDisplayName, AttrDescription (id/displayName/description),
// AttrTemplateId (templateId — same key conditionalaccess already coined for a
// policy's own templateId; here it is the definition's OWN template id, which
// equals AttrId on every built-in role observed live 2026-07-28 and would
// diverge only for a role created from a template and later modified),
// AttrIsBuiltIn / AttrIsEnabled (isBuiltIn / isEnabled — both already bounded
// gauge-dimension booleans from other collectors), AttrVersion (version),
// AttrResourceScopes (resourceScopes — intune.rbac coined this key for the
// identical "which scopes this grant applies to" shape).
//
// # What is new here
//
// rolePermissions is an ARRAY of {allowedResourceActions: [...]}. The true
// count crossing every element is what answers "how much can this role
// actually do", so it is a typed field of its own (AttrRolePermissionCount),
// separate from the flattened, capped action list.
const (
	// AttrAllowedActions is rolePermissions[].allowedResourceActions FLATTENED
	// across every element (order preserved), capped at maxAllowedActions. An
	// unrecognized action string rides the array as-is — this collector does
	// not validate the RBAC action namespace, only counts and lists it.
	AttrAllowedActions = "allowed_actions"
	// AttrAllowedActionCount is the TRUE, uncapped total of allowed actions
	// across every rolePermissions element — reported even when
	// AttrAllowedActions itself was capped, so the cap never hides the real
	// size of a role's grant.
	AttrAllowedActionCount = "allowed_action_count"
	// AttrAllowedActionsTruncated is true when AttrAllowedActions was capped
	// at maxAllowedActions.
	AttrAllowedActionsTruncated = "allowed_actions_truncated"
	// AttrRolePermissionCount is len(rolePermissions) — how many permission
	// blocks the definition carries (observed 0-3 live), independent of how
	// many actions each one lists.
	AttrRolePermissionCount = "role_permission_count"
	// AttrInheritsPermissionsFromIds is inheritsPermissionsFrom[].id, bounded
	// (a definition inherits from a small, fixed set of other definitions —
	// observed live as a single element, always the built-in "Directory
	// Readers"-shaped base role). Capped at maxResourceScopes: this array
	// shares resourceScopes' "admin-configured, not per-entity" shape rather
	// than allowed_actions' "can genuinely run into the hundreds" shape, so it
	// borrows that cap instead of defining a third one.
	AttrInheritsPermissionsFromIds = "inherits_permissions_from_ids"
	// AttrInheritsPermissionsFromTruncated is true when
	// AttrInheritsPermissionsFromIds was capped at maxResourceScopes. A
	// separate key from AttrResourceScopesTruncated below even though both
	// share one cap constant — they bound two different arrays on the same
	// record, and folding their truncation flags onto one key would make one
	// array's cap invisible whenever the other one fired.
	AttrInheritsPermissionsFromTruncated = "inherits_permissions_from_truncated"
	// AttrResourceScopesTruncated is true when AttrResourceScopes was capped
	// at maxResourceScopes. resourceScopes is "/" (tenant-wide) on every live
	// row, so this is a defensive backstop, not a path any current tenant
	// exercises.
	AttrResourceScopesTruncated = "resource_scopes_truncated"
)
