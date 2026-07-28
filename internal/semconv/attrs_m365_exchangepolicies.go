package semconv

// Attributes for the Exchange Online outbound-spam (#357,
// m365.exchange_outbound_spam_policy) and connection-filter (#358,
// m365.exchange_connection_filter_policy) collectors, both read over the
// Exchange Online admin API's app-only cmdlet transport
// (internal/exoclient), the same shape as the sibling accepted-domains and
// org-config collectors.
//
// Reused where a key already exists: AttrName, AttrIdentity, AttrId,
// AttrGuid, AttrIsValid, AttrOrganizationId, AttrDistinguishedName,
// AttrAdminDisplayName, AttrWhenChangedUtc, AttrExchangeObjectId
// (attrs_m365.go / attrs_m365_auditbypass.go / attrs_purview.go),
// AttrIsDefault (attrs_entra.go — generic "is this the tenant's default
// object" flag, not domain-specific), AttrEnabled, AttrSetting
// (attrs_intune.go), AttrConfigType (attrs_intune.go — reused for the wire's
// ConfigurationType field: both name the kind of configuration object, and
// this project reuses aggressively per the semconv collision rule),
// AttrRecommendedPolicyType (attrs_defender.go — the same
// RecommendedPolicyType field the MDO policy collector already reads),
// AttrArraysTruncated (attrs_entra_conditionalaccess.go — the same
// "some bounded array on this record got capped" flag, reused rather than
// duplicated per collector).
//
// # Two fields deliberately NOT backed by a wirecheck enum watcher
//
// AutoForwardingMode and ActionWhenThresholdReached (outbound spam) and
// DirectoryBasedEdgeBlockMode (connection filter) were each observed with
// exactly ONE live value on the m7kni tenant (2026-07-28). Per this
// project's wirecheck rule (CLAUDE.md, #233/#234), one observed value is not
// a value set: a watchdog built off it would fire the moment a tenant's
// second, entirely legitimate value showed up. All three are carried as
// plain strings on their twins with no internal/wirecheck Enum declared —
// see the two package docs.
const (
	// AttrLimit is the bounded label on
	// m365.exchange.outbound_spam.recipient_limit{limit}: one of
	// external_per_hour, internal_per_hour, per_day — a fixed, small key
	// space (see the package doc), never per-entity.
	AttrLimit = "limit"

	// AttrAutoForwardingMode is the wire's AutoForwardingMode
	// (HostedOutboundSpamFilterPolicy) — whether Exchange Online allows
	// automatic external forwarding for mail matching this policy. See the
	// wirecheck note above.
	AttrAutoForwardingMode = "auto_forwarding_mode"
	// AttrActionWhenThresholdReached is the wire's ActionWhenThresholdReached
	// — what happens to a sender once it crosses the recipient-limit
	// thresholds below. See the wirecheck note above.
	AttrActionWhenThresholdReached = "action_when_threshold_reached"
	// AttrRecipientLimitExternalPerHour / AttrRecipientLimitInternalPerHour /
	// AttrRecipientLimitPerDay are the wire's three RecipientLimit* numeric
	// columns, carried verbatim on the twin and, for the tenant's DEFAULT
	// policy only, as the m365.exchange.outbound_spam.recipient_limit{limit}
	// gauge — see the package doc for why only the default policy's values
	// become a gauge.
	AttrRecipientLimitExternalPerHour = "recipient_limit_external_per_hour"
	AttrRecipientLimitInternalPerHour = "recipient_limit_internal_per_hour"
	AttrRecipientLimitPerDay          = "recipient_limit_per_day"
	// AttrBccSuspiciousOutboundMail / AttrNotifyOutboundSpam are the wire's
	// two outbound-spam notification toggles.
	AttrBccSuspiciousOutboundMail = "bcc_suspicious_outbound_mail"
	AttrNotifyOutboundSpam        = "notify_outbound_spam"
	// AttrBccSuspiciousOutboundAdditionalRecipients /
	// AttrNotifyOutboundSpamRecipients are the wire's two recipient-list
	// columns, capped like every other bounded array attribute in this
	// project (see the package doc's maxRecipientList).
	AttrBccSuspiciousOutboundAdditionalRecipients = "bcc_suspicious_outbound_additional_recipients"
	AttrNotifyOutboundSpamRecipients              = "notify_outbound_spam_recipients"

	// AttrEnableSafeList is the wire's EnableSafeList
	// (HostedConnectionFilterPolicy) — whether Microsoft's dynamic allow list
	// (the "safe list") is honored for this policy.
	AttrEnableSafeList = "enable_safe_list"
	// AttrDirectoryBasedEdgeBlockMode is the wire's
	// DirectoryBasedEdgeBlockMode. See the wirecheck note above.
	AttrDirectoryBasedEdgeBlockMode = "directory_based_edge_block_mode"
	// AttrIpAllowList / AttrIpBlockList are the wire's two IP posture arrays
	// (IPv4, IPv6 and CIDR-range entries preserved verbatim), capped like
	// every other bounded array attribute in this project — see the package
	// doc's maxIPListAttr. Never a metric label: an IP is per-entity data
	// (#112).
	AttrIpAllowList = "ip_allow_list"
	AttrIpBlockList = "ip_block_list"
	// AttrIpAllowListCount / AttrIpBlockListCount are the TRUE entry counts
	// for the two arrays above, stamped even when the array attribute itself
	// was capped (so a reader can tell a capped display apart from the real
	// count) and even when zero (a measured empty list is a real, alertable
	// finding — see the package doc).
	AttrIpAllowListCount = "ip_allow_list_count"
	AttrIpBlockListCount = "ip_block_list_count"
)
