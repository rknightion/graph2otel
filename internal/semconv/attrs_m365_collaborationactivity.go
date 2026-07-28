package semconv

// m365.collaboration_activity attributes (#362). Reused where a key already
// exists: AttrWorkload (attrs_m365.go) labels every metric/twin with which
// workload — teams/sharepoint/onedrive — a row came from; AttrAction
// (attrs_defender.go, generic "action") labels the bounded per-workload action
// gauge; AttrUserId / AttrUserPrincipalName (attrs_shared.go), AttrIsDeleted /
// AttrLastActivityDate (attrs_m365.go), and AttrDeletedDate
// (attrs_m365_mailboxusage.go) all carry the same meaning here as in the other
// usage-report collectors.
//
// AttrActivityState is a metric-only dimension (derived active/inactive/
// never_active bucket from Last Activity Date vs the report window) — it never
// appears on the log twin, which instead carries the raw Last Activity Date a
// reader can derive the same bucket from.
//
// AttrAssignedProducts holds the CSV cell VERBATIM, including its embedded
// " + " (one license SKU name itself contains " + " — see
// collaborationactivity.go's package doc). It is deliberately not split into a
// list.
//
// The five *Count attributes below are per-workload numeric facets from the
// usage-report CSV; they ride the log twin only, never a metric label — the
// bounded action-sum gauge carries the SAME data aggregated across users under
// AttrAction's action names (team_chat_messages, files_synced, ...), which are
// plain string values, not separate semconv keys.
const (
	AttrReportRefreshDate = "report_refresh_date"
	AttrReportPeriod      = "report_period"
	AttrAssignedProducts  = "assigned_products"
	AttrActivityState     = "activity_state"

	AttrTeamChatMessageCount    = "team_chat_message_count"
	AttrPrivateChatMessageCount = "private_chat_message_count"
	AttrCallCount               = "call_count"
	AttrMeetingsOrganizedCount  = "meetings_organized_count"
	AttrMeetingsAttendedCount   = "meetings_attended_count"

	AttrFilesViewedOrEditedCount   = "files_viewed_or_edited_count"
	AttrFilesSyncedCount           = "files_synced_count"
	AttrFilesSharedInternallyCount = "files_shared_internally_count"
	AttrFilesSharedExternallyCount = "files_shared_externally_count"
	AttrPagesVisitedCount          = "pages_visited_count"
)
