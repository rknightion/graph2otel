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
	// AttrTeamsMembersCount is the number of Members entries on the wire.
	AttrTeamsMembersCount = "teams_members_count"

	// Meeting and call detail (#665). MeetingDetailId joins to the id of the
	// MeetingDetail record; CallParticipantDetail's CallId is emitted as
	// AttrCallId because it equals teams.call call_id (live-measured).
	AttrTeamsMeetingDetailId         = "teams_meeting_detail_id"
	AttrTeamsJoinTime                = "teams_join_time"
	AttrTeamsLeaveTime               = "teams_leave_time"
	AttrTeamsJoinedFromLobby         = "teams_joined_from_lobby"
	AttrTeamsMeetingStartTime        = "teams_meeting_start_time"
	AttrTeamsMeetingEndTime          = "teams_meeting_end_time"
	AttrTeamsMeetingUrl              = "teams_meeting_url"
	AttrTeamsCommunicationType       = "teams_communication_type"
	AttrTeamsCommunicationSubType    = "teams_communication_sub_type"
	AttrTeamsModalities              = "teams_modalities"
	AttrTeamsProviderTypes           = "teams_provider_types"
	AttrTeamsOrganizerObjectId       = "teams_organizer_object_id"
	AttrTeamsOrganizerOrganizationId = "teams_organizer_organization_id"
	// AttrTeamsAttendeesJSON holds a bounded JSON array of observed attendee
	// fields; AttrTeamsAttendeesCount is the wire count of Attendees entries.
	AttrTeamsAttendeesJSON             = "teams_attendees_json"
	AttrTeamsAttendeesTruncated        = "teams_attendees_truncated"
	AttrTeamsAttendeesCount            = "teams_attendees_count"
	AttrTeamsUsersInvitedDuringMeeting = "teams_users_invited_during_meeting"
	AttrTeamsRtmpInEnabled             = "teams_rtmp_in_enabled"
	AttrTeamsDeviceId                  = "teams_device_id"
	AttrTeamsDeviceInformation         = "teams_device_information"

	// App and tab detail. AddOnGuid is opaque: not validated against Graph.
	AttrTeamsAddonId     = "teams_addon_id"
	AttrTeamsAddonTypeId = "teams_addon_type_id"
	AttrTeamsAddonName   = "teams_addon_name"
	AttrTeamsTabType     = "teams_tab_type"

	// ParticipantInfo: who took part from outside the tenant.
	AttrTeamsHasForeignTenantUsers   = "teams_has_foreign_tenant_users"
	AttrTeamsHasGuestUsers           = "teams_has_guest_users"
	AttrTeamsHasOtherGuestUsers      = "teams_has_other_guest_users"
	AttrTeamsHasUnauthenticatedUsers = "teams_has_unauthenticated_users"
	AttrTeamsParticipatingTenantIds  = "teams_participating_tenant_ids"
)
