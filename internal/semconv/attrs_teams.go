package semconv

// Attribute keys used by the m365.teams collector (#121). Shared keys these
// records also emit (display_name via AttrDisplayName, description via
// AttrDescription, id via AttrId) are reused, never redeclared. Every key is a
// semconv.Attr* constant (Gate B); no value duplicates another constant (Gate A).
const (
	// AttrVisibility is a team's visibility: public / private / hiddenMembership.
	// A bounded closed set, so it is safe as a metric label.
	AttrVisibility = "visibility"
	// AttrRole buckets a membership count by role: owner / member / guest. Bounded.
	AttrRole = "role"
	// AttrOwnersCount / AttrMembersCount / AttrGuestsCount are a team's membership
	// counts from teams.summary. Per-entity on the LOG twin only — never a metric
	// label (they are the metric VALUES, bucketed by role).
	AttrOwnersCount  = "owners_count"
	AttrMembersCount = "members_count"
	AttrGuestsCount  = "guests_count"
	// AttrIsArchived marks an archived team — an archived team is the desired
	// end-state, not an orphan, so it is excluded from the ownerless count but
	// still carries a log twin.
	AttrIsArchived = "is_archived"

	// --- #247: installed apps (sideloaded + RSC grants) and channel census ---

	// AttrDistributionMethod is a Teams app's distributionMethod: a closed
	// 3-value enum store / organization / sideloaded. Bounded, safe as a metric
	// label. `sideloaded` is the actionable-bad state (an app installed outside
	// the tenant catalog / store).
	AttrDistributionMethod = "distribution_method"
	// AttrHasRscPermissions is the "true"/"false" flag for whether an installed
	// app holds any grantedResourceSpecificApplicationPermissions (RSC). Bounded
	// (two values), safe as a metric label; the grant LIST itself is per-entity
	// and lives only on the log twin.
	AttrHasRscPermissions = "has_rsc_permissions"
	// AttrRscPermissions is the list of resource-specific consent grants held by
	// an installed app (e.g. ChannelMessage.Read.Group). Per-entity → LOG twin
	// only, never a metric label. This is the entra.consent blind spot #247 is
	// about: RSC grants are consented per team, not tenant-wide, so an app-role
	// consent audit cannot see them.
	AttrRscPermissions = "rsc_permissions"
	// AttrTeamId is the parent team's id on an installed-app or channel twin, for
	// correlation back to the m365.team twin. Per-entity → LOG twin only.
	AttrTeamId = "team_id"
	// AttrTeamDisplayName is the parent team's display name on an installed-app or
	// channel twin. Per-entity → LOG twin only.
	AttrTeamDisplayName = "team_display_name"
	// AttrFilesFolderWebUrl is a channel's SharePoint files-folder URL. Per-entity
	// → LOG twin only.
	AttrFilesFolderWebUrl = "files_folder_web_url"
)
