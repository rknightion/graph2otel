package semconv

// Attribute keys introduced by the DLP.All branch of m365.activity (#370):
// the classification metadata of a DLP rule match, from the Office 365
// Management Activity API's ComplianceDLPSharePoint (RecordType 11) and
// ComplianceDLPExchange (RecordType 13) records.
//
// REUSED rather than re-coined (the registry's no-duplicate-values gate would
// fail a second constant carrying any of these strings): AttrIncidentId
// (attrs_entra.go), AttrSeverity (attrs_shared.go), AttrFileName,
// AttrRecipientCount, AttrSubject (attrs_defender.go).
//
// # THE ONE THING THIS FILE EXISTS TO KEEP OUT
//
// There is deliberately NO constant for `DetectedValues`, and there must never
// be one. Live-measured 2026-07-29 on a deliberate match, that array carries
// TWO fields and both are unsafe:
//
//   - `Name` is the matched value verbatim — an AWS secret access key, a
//     password, a card number.
//   - `Value` is NOT the match. It is a ~100-135 character WINDOW OF THE
//     SURROUNDING DOCUMENT, and on the live sample it leaked the tail of the
//     preceding access key ID and the start of the next section — content that
//     was never itself a match.
//
// So emitting `Value` exfiltrates arbitrary adjacent document text bounded only
// by a character window. #100's framing was "for a credential match the value
// IS the credential"; measured, it is that PLUS a slice of whatever sat next to
// it. The whole `SensitiveInformationDetections` object is dropped, which is
// clean because every field below sits outside it.
//
// Everything here is a LOG attribute. None of it may key a metric label: policy
// and rule names are tenant-defined and file paths, subjects and recipients are
// per-entity (#112).
const (
	// AttrDlpPolicyNames are the names of the DLP policies that matched, one
	// record can trip several. Tenant-defined strings, so log-only.
	AttrDlpPolicyNames = "dlp_policy_names"

	// AttrDlpPolicyIds are the matched policies' ids, index-aligned with
	// AttrDlpPolicyNames. Parallel slices rather than one attribute per policy
	// name: the names are tenant-defined and unbounded, so
	// attribute-per-name would mint unbounded attribute KEYS — the same
	// reasoning as ExtendedProperties' name/value pair.
	AttrDlpPolicyIds = "dlp_policy_ids"

	// AttrDlpRuleNames are the names of the individual rules that matched.
	AttrDlpRuleNames = "dlp_rule_names"

	// AttrDlpRuleModes are the matched rules' RuleMode values (e.g.
	// `TestWithNotifyUser`).
	//
	// Reported VERBATIM and deliberately not reconciled against the policy
	// definition: the compiled policy XML calls the same state
	// `mode="AuditAndNotify"` while the record says `TestWithNotifyUser`
	// (live-measured 2026-07-29). Two vocabularies for one state, and the
	// record's is what an operator sees in Purview.
	AttrDlpRuleModes = "dlp_rule_modes"

	// AttrDlpActions are the actions the matched rules took (e.g. NotifyUser,
	// GenerateIncidentReport). This is what separates an audit-only match from
	// one that actually blocked something.
	AttrDlpActions = "dlp_actions"

	// AttrDlpSensitiveTypeNames are the names of the sensitive information
	// types that matched (e.g. "Credit Card Number", "U.K. National Insurance
	// Number (NINO)").
	//
	// NOTE the names do not describe the jurisdiction of the MATCH: live, `EU
	// Passport Number` fired on a UK passport number and `EU Debit Card
	// Number` on a UK card. A dashboard grouping by this attribute to infer
	// geography will be wrong.
	AttrDlpSensitiveTypeNames = "dlp_sensitive_type_names"

	// AttrDlpSensitiveTypeIds are the matched SITs' GUIDs, index-aligned with
	// AttrDlpSensitiveTypeNames. Carried because the compiled DLP policy
	// identifies SITs by GUID ONLY, so the id is what joins a match back to
	// the policy that asked for it.
	AttrDlpSensitiveTypeIds = "dlp_sensitive_type_ids"

	// AttrDlpMatchConfidences are the confidence percentages of each match,
	// index-aligned with AttrDlpSensitiveTypeNames.
	AttrDlpMatchConfidences = "dlp_match_confidences"

	// AttrDlpMatchCounts are the instance counts of each match, index-aligned
	// with AttrDlpSensitiveTypeNames. This is the "how many card numbers were
	// in the file" number — the safe substitute for the values themselves.
	AttrDlpMatchCounts = "dlp_match_counts"

	// AttrDlpMatchLocation is where in the item the match was found (e.g.
	// `Message Body`). Present on the Exchange record and ABSENT on the
	// OneDrive one (live-measured 2026-07-29), so it is emitted only when sent.
	AttrDlpMatchLocation = "dlp_match_location"

	// AttrDlpResultsTruncated reports whether Microsoft truncated the match
	// list. It comes from inside SensitiveInformationDetections — the object
	// whose values are dropped — and is the one field there that is safe and
	// worth keeping: it says the counts above are a floor rather than a total.
	// False on every live match, so a true is the interesting case.
	AttrDlpResultsTruncated = "dlp_results_truncated"

	// AttrDlpDetectionIncluded is the record's SensitiveInfoDetectionIsIncluded
	// flag: whether Microsoft attached the matched values to this record at
	// all. Carried as the operator's own audit of what the tenant is shipping
	// through the feed — when it is true, the values WERE on the wire and this
	// collector dropped them.
	AttrDlpDetectionIncluded = "dlp_detection_included"

	// AttrDlpEvaluationSource is the record's EvaluationSource (e.g.
	// `DlpPolicyEventBasedAssistantOneDriveForBusiness`) — which evaluator
	// produced the match. Absent on the Exchange record.
	AttrDlpEvaluationSource = "dlp_evaluation_source"

	// AttrFilePathUrl is SharePointMetaData.FilePathUrl — the full path of the
	// matched file. Per-entity and log-only, and the single most actionable
	// field on a OneDrive match: it is what an operator needs to go and look.
	AttrFilePathUrl = "file_path_url"

	// AttrFileOwner is SharePointMetaData.FileOwner.
	AttrFileOwner = "file_owner"

	// AttrFileSizeBytes is the matched item's size, from either metadata block.
	AttrFileSizeBytes = "file_size_bytes"

	// AttrSiteCollectionUrl is SharePointMetaData.SiteCollectionUrl.
	AttrSiteCollectionUrl = "site_collection_url"

	// AttrIsViewableByExternalUsers is the metadata blocks' shared
	// IsViewableByExternalUsers flag. It is the field that turns a DLP match
	// into an incident: sensitive content in a private file is a hygiene
	// problem, the same content externally viewable is an exposure.
	AttrIsViewableByExternalUsers = "is_viewable_by_external_users"

	// AttrSensitivityLabelNames are the item's applied sensitivity labels, from
	// either metadata block.
	AttrSensitivityLabelNames = "sensitivity_label_names"

	// AttrMailFrom is the metadata blocks' From — the sender on an Exchange
	// match, or the sharer on a SharePoint one.
	AttrMailFrom = "mail_from"

	// AttrMailTo are ExchangeMetaData.To recipients.
	AttrMailTo = "mail_to"

	// AttrMailCc are ExchangeMetaData.CC recipients.
	AttrMailCc = "mail_cc"

	// AttrMailBcc are ExchangeMetaData.BCC recipients. Emitted for the same
	// reason as the others: a BCC is exactly the recipient a DLP investigation
	// cannot afford to be missing, and it is per-entity data on a log record,
	// which is where it belongs (#112/#114).
	AttrMailBcc = "mail_bcc"
)
