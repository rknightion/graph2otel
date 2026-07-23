package semconv

// Attribute keys used across two or more domains (entra/intune/m365/purview).
const (
	AttrActivity              = "activity"
	AttrAppId                 = "app_id"
	AttrCategory              = "category"
	AttrContainer             = "container"
	AttrCorrelationId         = "correlation_id"
	AttrDiagnosticCategory    = "diagnostic_category"
	AttrDisplayName           = "display_name"
	AttrIsMapped              = "is_mapped"
	AttrExpirationDateTime    = "expiration_date_time"
	AttrExpiryBucket          = "expiry_bucket"
	AttrId                    = "id"
	AttrKeyUsage              = "key_usage"
	AttrModifiedPropertyNames = "modified_property_names"
	AttrOperatingSystem       = "operating_system"
	AttrPriority              = "priority"
	AttrSeverity              = "severity"

	// AttrSource is a per-record provenance field carrying MICROSOFT's own
	// meanings, NOT graph2otel's transport. It holds different live values per
	// collector: which Graph endpoint a certificate came from (intune/certificates:
	// "managed_device" / "user_pfx") and Microsoft's verbatim `source` field
	// (entra/riskdetections). It is deliberately distinct from
	// AttrIngestTransport (which names graph2otel's ingest transport) and from the
	// `source: graph|blob` CONFIG key (#144). [#141]
	AttrSource          = "source"
	AttrStartDateTime   = "start_date_time"
	AttrState           = "state"
	AttrStatus          = "status"
	AttrType            = "type"
	AttrUserDisplayName = "user_display_name"

	// AttrUserId holds the classic Office 365 UserId (usually a UPN, sometimes a
	// sentinel) on both m365 transports. It is DELIBERATELY NOT
	// AttrUserPrincipalName: the value is a UPN only ~10 records in 11, so naming
	// it user_principal_name asserted something false ~9% of the time (#151). The
	// classic UserKey travels separately as AttrUserKey. Do not re-add a
	// user_principal_name alias alongside it. Also used by entra/intune collectors
	// as a generic user identifier.
	AttrUserId            = "user_id"
	AttrUserPrincipalName = "user_principal_name"
)
