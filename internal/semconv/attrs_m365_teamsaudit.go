package semconv

// Teams-specific log attributes from Management Activity API records in
// m365.audit. The audit GUID values are opaque, not Graph inventory IDs.
const (
	AttrTeamGuid    = "team_guid"
	AttrTeamName    = "team_name"
	AttrChannelGuid = "channel_guid"
	AttrChannelName = "channel_name"

	// AttrTeamsMembersJSON holds a bounded JSON array of observed member fields.
	AttrTeamsMembersJSON = "teams_members_json"
	// AttrTeamsMembersTruncated is set only if a member projection hit a limit.
	AttrTeamsMembersTruncated = "teams_members_truncated"
)
