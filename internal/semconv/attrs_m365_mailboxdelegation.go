package semconv

// Exchange Online mailbox delegation attributes (#355, m365.mailbox_delegation).
//
// Reused where a key already exists: AttrKind (attrs.go) — the generic bounded
// "kind" label, here valued "full_access"/"send_as" to say which cmdlet an
// assignment came from. Every attribute below is new to this collector.
//
// AttrMailbox, AttrTrustee and AttrTrusteeSid are LOG-ONLY: per-entity mailbox
// and trustee identity never becomes a metric label (#112) — see the package
// doc's cardinality section. AttrTrusteeKind and AttrIsInherited are the only
// two of these that also back a metric label, and both are bounded by
// construction (two/three values, never per-entity).
const (
	// AttrMailbox is the mailbox a delegation was read from (its
	// PrimarySmtpAddress). Log twin only.
	AttrMailbox = "mailbox"
	// AttrTrustee is the raw User/Trustee field from the wire: a display name,
	// UPN, or "NT AUTHORITY\SELF" — never PrimarySmtpAddress, which is empty on
	// every live row (#355 trap 2). Log twin only.
	AttrTrustee = "trustee"
	// AttrTrusteeSid is the trustee's SID (UserSid / TrusteeSidString). Log
	// twin only.
	AttrTrusteeSid = "trustee_sid"
	// AttrTrusteeKind buckets a delegation as "self" (the implicit
	// NT AUTHORITY\SELF permission present on every mailbox) or "delegated"
	// (an actual standing delegation). Bounded: exactly two values. Backs both
	// a metric label and a log attribute.
	AttrTrusteeKind = "trustee_kind"
	// AttrRights is the full set of AccessRights tokens carried by one row,
	// AFTER splitting each wire array element on ", " (#355 trap 1). Log twin
	// only — the metric only needs to know an entry qualified as
	// full_access/send_as, not its full right set.
	AttrRights = "rights"
	// AttrDeny is Get-MailboxPermission's Deny flag. A *bool in the mapper:
	// never observed true live, so it is read but never asserted against a
	// value set (see the package doc). Log twin only, omitted when the wire
	// key is absent.
	AttrDeny = "deny"
	// AttrIsInherited is IsInherited from Get-MailboxPermission. Bounded to
	// "true"/"false"/"unknown" (the field is absent on every
	// Get-RecipientPermission row observed live). Backs both a metric label
	// and a log attribute.
	AttrIsInherited = "is_inherited"
	// AttrAccessControlType is Get-RecipientPermission's AccessControlType
	// ("Allow" on every live row; "Deny" never observed — see the package
	// doc). Log twin only, and only ever set on send_as twins.
	AttrAccessControlType = "access_control_type"
)
