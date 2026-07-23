package semconv

// Attribute keys used only by m365.* collectors.
const (
	AttrActionRequiredByDateTime     = "action_required_by_date_time"
	AttrActiveFileCount              = "active_file_count"
	AttrActorIds                     = "actor_ids"
	AttrAzureAdEventType             = "azure_ad_event_type"
	AttrClientIp                     = "client_ip"
	AttrDriveType                    = "drive_type"
	AttrExtendedPropertyNames        = "extended_property_names"
	AttrExtendedPropertyValues       = "extended_property_values"
	AttrExternalResharingEnabled     = "external_resharing_enabled"
	AttrFeature                      = "feature"
	AttrFeatureGroup                 = "feature_group"
	AttrFileCount                    = "file_count"
	AttrHasAttachments               = "has_attachments"
	AttrIdleSessionSignoutEnabled    = "idle_session_signout_enabled"
	AttrImpactDescription            = "impact_description"
	AttrIsDeleted                    = "is_deleted"
	AttrIsMajorChange                = "is_major_change"
	AttrIsResolved                   = "is_resolved"
	AttrLastActivityDate             = "last_activity_date"
	AttrLastModifiedDateTime         = "last_modified_date_time"
	AttrLegacyAuthEnabled            = "legacy_auth_enabled"
	AttrMessageBody                  = "message_body"
	AttrNamesConcealed               = "names_concealed"
	AttrObjectId                     = "object_id"
	AttrOperation                    = "operation"
	AttrOrganizationId               = "organization_id"
	AttrOrigin                       = "origin"
	AttrOwnerDisplayName             = "owner_display_name"
	AttrOwnerPrincipalName           = "owner_principal_name"
	AttrQuotaState                   = "quota_state"
	AttrRecordType                   = "record_type"
	AttrRecordTypeId                 = "record_type_id"
	AttrReleaseTo                    = "release_to"
	AttrRequestType                  = "request_type"
	AttrResultStatus                 = "result_status"
	AttrRootWebTemplate              = "root_web_template"
	AttrService                      = "service"
	AttrServices                     = "services"
	AttrSharingAllowedDomains        = "sharing_allowed_domains"
	AttrSharingBlockedDomains        = "sharing_blocked_domains"
	AttrSharingCapability            = "sharing_capability"
	AttrSharingDomainRestrictionMode = "sharing_domain_restriction_mode"
	AttrSiteId                       = "site_id"
	AttrSiteUrl                      = "site_url"
	AttrStorageAllocatedBytes        = "storage_allocated_bytes"
	AttrStorageRemainingBytes        = "storage_remaining_bytes"
	AttrStorageUsedBytes             = "storage_used_bytes"
	AttrUnmanagedSyncRestricted      = "unmanaged_sync_restricted"
	AttrUserKey                      = "user_key"
	AttrUserType                     = "user_type"
	AttrUserTypeId                   = "user_type_id"
	AttrVersion                      = "version"
	AttrWorkload                     = "workload"
)

// Exchange Online DKIM signing posture (#250, m365.exchange_dkim). Per-domain
// detail lives on the log twin (m365.exchange_dkim_config); the metric counts
// accepted domains by the bounded enabled x status tuple only, so none of these
// keys is ever a metric label.
const (
	AttrAdminAuditLogAgeLimit           = "admin_audit_log_age_limit"
	AttrAdminAuditLogEnabled            = "admin_audit_log_enabled"
	AttrLogLevel                        = "log_level"
	AttrTestCmdletLoggingEnabled        = "test_cmdlet_logging_enabled"
	AttrUnifiedAuditLogFirstOptInDate   = "unified_audit_log_first_opt_in_date"
	AttrUnifiedAuditLogIngestionEnabled = "unified_audit_log_ingestion_enabled"

	AttrAlgorithm              = "algorithm"
	AttrBodyCanonicalization   = "body_canonicalization"
	AttrDomain                 = "domain"
	AttrHeaderCanonicalization = "header_canonicalization"
	AttrIsValid                = "is_valid"
	AttrKeyCreationTime        = "key_creation_time"
	AttrLastChecked            = "last_checked"
	AttrRotateOnDate           = "rotate_on_date"
	AttrSelector1Cname         = "selector1_cname"
	AttrSelector1KeySize       = "selector1_key_size"
	AttrSelector2Cname         = "selector2_cname"
	AttrSelector2KeySize       = "selector2_key_size"
)

// Exchange Online transport-rule attributes (#250, m365.exchange_transport_rules).
// Reused where a key already exists: AttrName and AttrDescription and
// AttrPriority and AttrState and AttrId (shared), AttrIsValid (above). Only
// state and rule_mode are ever metric labels — both are bounded enums fixed by
// the API. Every other key is per-rule data and appears on the log twin only
// (#112). AttrRuleMode is "rule_mode" rather than "mode" because "mode" is
// already AttrClipMode.
const (
	AttrActionTypes                   = "action_types"
	AttrActivationDate                = "activation_date"
	AttrAddToRecipients               = "add_to_recipients"
	AttrApplyRightsProtectionTemplate = "apply_rights_protection_template"
	AttrBlindCopyTo                   = "blind_copy_to"
	AttrComments                      = "comments"
	AttrConditionTypes                = "condition_types"
	AttrCopyTo                        = "copy_to"
	AttrCreatedBy                     = "created_by"
	AttrDeleteMessage                 = "delete_message"
	AttrDlpPolicy                     = "dlp_policy"
	AttrExceptionTypes                = "exception_types"
	AttrExpiryDate                    = "expiry_date"
	AttrFromScope                     = "from_scope"
	AttrLastModifiedBy                = "last_modified_by"
	AttrManuallyModified              = "manually_modified"
	AttrPrependSubject                = "prepend_subject"
	AttrQuarantine                    = "quarantine"
	AttrRedirectMessageTo             = "redirect_message_to"
	AttrRedirectsMail                 = "redirects_mail"
	AttrRouteMessageOutboundConnector = "route_message_outbound_connector"
	AttrRuleErrorAction               = "rule_error_action"
	AttrRuleMode                      = "rule_mode"
	AttrSenderAddressLocation         = "sender_address_location"
	AttrSentToScope                   = "sent_to_scope"
	AttrSetAuditSeverity              = "set_audit_severity"
	AttrStopRuleProcessing            = "stop_rule_processing"
	AttrWhenChanged                   = "when_changed"
)

// Exchange Online remote-domain attributes (#250, m365.exchange_remote_domains).
// Reused where a key already exists: AttrDomain and AttrIsValid (above),
// AttrName and AttrId (shared), AttrWhenChanged (transport rules). Only
// auto_forward_enabled is ever a metric label. Several of these are TRI-STATE on
// the wire — null means "use the default", not "off" — so the mapper omits them
// rather than asserting false.
const (
	AttrAllowedOofType                    = "allowed_oof_type"
	AttrAutoForwardEnabled                = "auto_forward_enabled"
	AttrAutoReplyEnabled                  = "auto_reply_enabled"
	AttrCharacterSet                      = "character_set"
	AttrContentType                       = "content_type"
	AttrDeliveryReportEnabled             = "delivery_report_enabled"
	AttrDisplaySenderName                 = "display_sender_name"
	AttrIsInternal                        = "is_internal"
	AttrLineWrapSize                      = "line_wrap_size"
	AttrMeetingForwardNotificationEnabled = "meeting_forward_notification_enabled"
	AttrNdrDiagnosticInfoEnabled          = "ndr_diagnostic_info_enabled"
	AttrNdrEnabled                        = "ndr_enabled"
	AttrNonMimeCharacterSet               = "non_mime_character_set"
	AttrTargetDeliveryDomain              = "target_delivery_domain"
	AttrTnefEnabled                       = "tnef_enabled"
	AttrTrustedMailInboundEnabled         = "trusted_mail_inbound_enabled"
	AttrTrustedMailOutboundEnabled        = "trusted_mail_outbound_enabled"
	AttrUseSimpleDisplayName              = "use_simple_display_name"
	AttrWhenCreated                       = "when_created"
)

// Exchange Online mailbox attributes (#250, m365.exchange_mailboxes). Reused
// where a key already exists: AttrUserPrincipalName and AttrDisplayName and
// AttrId and AttrSetting (shared), AttrWhenCreated (remote domains). Only
// recipient_type_details, forwarding_configured and audit_enabled are ever
// metric labels — all three bounded — and setting on the protection gauge. Every
// other key is per-mailbox data and appears on the log twin only (#112): a label
// keyed by UPN would grow one series per user.
const (
	AttrAccountDisabled                   = "account_disabled"
	AttrArchiveGuid                       = "archive_guid"
	AttrArchiveState                      = "archive_state"
	AttrArchiveStatus                     = "archive_status"
	AttrAuditEnabled                      = "audit_enabled"
	AttrAuditLogAgeLimit                  = "audit_log_age_limit"
	AttrComplianceTagHoldApplied          = "compliance_tag_hold_applied"
	AttrDeliverToMailboxAndForward        = "deliver_to_mailbox_and_forward"
	AttrEmailAddresses                    = "email_addresses"
	AttrExchangeGuid                      = "exchange_guid"
	AttrExternalDirectoryObjectId         = "external_directory_object_id"
	AttrForwardingAddress                 = "forwarding_address"
	AttrForwardingConfigured              = "forwarding_configured"
	AttrForwardingSmtpAddress             = "forwarding_smtp_address"
	AttrGrantSendOnBehalfTo               = "grant_send_on_behalf_to"
	AttrHiddenFromAddressLists            = "hidden_from_address_lists"
	AttrInPlaceHolds                      = "in_place_holds"
	AttrIsDirSynced                       = "is_dir_synced"
	AttrIsInactiveMailbox                 = "is_inactive_mailbox"
	AttrIsMailboxEnabled                  = "is_mailbox_enabled"
	AttrIsResource                        = "is_resource"
	AttrIsShared                          = "is_shared"
	AttrIssueWarningQuota                 = "issue_warning_quota"
	AttrLitigationHoldDate                = "litigation_hold_date"
	AttrLitigationHoldDuration            = "litigation_hold_duration"
	AttrLitigationHoldEnabled             = "litigation_hold_enabled"
	AttrLitigationHoldOwner               = "litigation_hold_owner"
	AttrMailboxPlan                       = "mailbox_plan"
	AttrMessageCopyForSendOnBehalfEnabled = "message_copy_for_send_on_behalf_enabled"
	AttrMessageCopyForSentAsEnabled       = "message_copy_for_sent_as_enabled"
	AttrPrimarySmtpAddress                = "primary_smtp_address"
	AttrProhibitSendQuota                 = "prohibit_send_quota"
	AttrProhibitSendReceiveQuota          = "prohibit_send_receive_quota"
	AttrRecipientTypeDetails              = "recipient_type_details"
	AttrRetainDeletedItemsFor             = "retain_deleted_items_for"
	AttrRetentionHoldEnabled              = "retention_hold_enabled"
	AttrSingleItemRecoveryEnabled         = "single_item_recovery_enabled"
	AttrWhenMailboxCreated                = "when_mailbox_created"
)

// Exchange Online organization-configuration attributes (#250,
// m365.exchange_org_config — the Get-OrganizationConfig half; the
// Get-AdminAuditLogConfig half is m365.exchange_audit_config above). Reused
// where a key already exists: AttrName and AttrDisplayName and AttrId and
// AttrSetting (shared). The BOOLEAN posture settings deliberately have no
// constants here: they are metric label VALUES on the bounded setting_enabled
// gauge, named from the wire field's snake_case, so adding one costs no
// registry entry. Only the non-boolean config below lands as twin attributes.
const (
	AttrActivityBasedAuthTimeoutInterval = "activity_based_authentication_timeout_interval"
	AttrAuditDisabled                    = "audit_disabled"
	AttrCustomerLockboxEnabled           = "customer_lockbox_enabled"
	AttrDefaultAuthenticationPolicy      = "default_authentication_policy"
	AttrEwsAllowMacOutlook               = "ews_allow_mac_outlook"
	AttrEwsAllowOutlook                  = "ews_allow_outlook"
	AttrEwsApplicationAccessPolicy       = "ews_application_access_policy"
	AttrEwsEnabled                       = "ews_enabled"
	AttrFocusedInboxOn                   = "focused_inbox_on"
	AttrHierarchicalAddressBookRoot      = "hierarchical_address_book_root"
	AttrIpListBlocked                    = "ip_list_blocked"
	AttrIsDehydrated                     = "is_dehydrated"
	AttrIsMixedMode                      = "is_mixed_mode"
	AttrMessageRecallEnabled             = "message_recall_enabled"
	AttrOauth2ClientProfileEnabled       = "oauth2_client_profile_enabled"
	AttrPublicFoldersEnabled             = "public_folders_enabled"
)
