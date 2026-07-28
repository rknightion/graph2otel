package semconv

// Exchange mailbox usage attributes (#359, m365.mailbox_usage). Reused where a
// key already exists: AttrUserPrincipalName / AttrDisplayName (attrs_shared.go),
// AttrIsDeleted / AttrLastActivityDate / AttrNamesConcealed / AttrQuotaState
// (attrs_m365.go), AttrStorageUsedBytes (attrs_m365.go), AttrIssueWarningQuota /
// AttrProhibitSendQuota / AttrProhibitSendReceiveQuota (attrs_m365.go — there
// they carry the EXO cmdlet's formatted string quota; here they carry the same
// real-world quota threshold as a plain byte count from the usage report, same
// meaning, different source).
//
// AttrQuotaState on this package's bounded metric takes Microsoft's OWN
// mailbox-quota-status vocabulary (under_limit / warning_issued /
// send_prohibited / send_receive_prohibited / indeterminate) rather than the
// derived normal/nearing/critical/exceeded buckets internal/collectors/m365/
// storage computes — a different value set under the same key, because both
// describe "which quota bucket is this mailbox in" for their own report shape.
//
// AttrCreatedDate and AttrDeletedDate are plain calendar dates ("2026-07-25"),
// matching AttrLastActivityDate's existing convention for this report family —
// deliberately distinct from AttrCreatedDateTime/AttrDeletedDateTime elsewhere,
// which carry full Graph JSON ISO-8601 timestamps from a different wire shape.
const (
	AttrCreatedDate      = "created_date"
	AttrDaysInactive     = "days_inactive"
	AttrDeletedDate      = "deleted_date"
	AttrDeletedItemCount = "deleted_item_count"
	AttrDeletedItemQuota = "deleted_item_quota_bytes"
	AttrDeletedItemSize  = "deleted_item_size_bytes"
	AttrHasArchive       = "has_archive"
	AttrItemCount        = "item_count"
)
