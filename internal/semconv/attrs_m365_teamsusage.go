package semconv

// Teams usage report attributes. DaysAgo is the only new metric dimension:
// a bounded offset from the latest D30 report date, never an absolute date.
const (
	AttrDaysAgo                   = "days_ago"
	AttrTeamType                  = "team_type"
	AttrActiveUsersCount          = "active_users_count"
	AttrActiveChannelsCount       = "active_channels_count"
	AttrChannelMessagesCount      = "channel_messages_count"
	AttrReactionsCount            = "reactions_count"
	AttrPostMessagesCount         = "post_messages_count"
	AttrReplyMessagesCount        = "reply_messages_count"
	AttrUrgentMessagesCount       = "urgent_messages_count"
	AttrMentionsCount             = "mentions_count"
	AttrActiveSharedChannelsCount = "active_shared_channels_count"
	AttrActiveExternalUsersCount  = "active_external_users_count"
)
