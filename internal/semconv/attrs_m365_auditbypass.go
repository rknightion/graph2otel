// Package semconv: attributes for the Exchange Online mailbox audit-bypass
// collector (#356), Get-MailboxAuditBypassAssociation over the Exchange Online
// admin API's app-only cmdlet transport.
//
// Reused where a key already exists: AttrName, AttrIdentity, AttrId,
// AttrIsValid, AttrOrganizationId (attrs_m365.go), AttrDistinguishedName
// (attrs_defender.go), AttrWhenChangedUtc (attrs_purview.go — the same
// WhenChangedUTC wire field the accepted-domains and mailbox collectors read
// as WhenChanged; this cmdlet's wire response carries the UTC-suffixed sibling
// instead, so the twin binds to the existing key rather than coining a
// duplicate). Only genuinely new attributes are declared below.
package semconv

const (
	// AttrGuid is the mailbox's Exchange GUID (the wire's "Guid" field).
	// ExchangeObjectId is observed identical to Guid on every live row
	// (live-measured 2026-07-28, #356), but both are carried since nothing in
	// the wire response documents that as guaranteed rather than incidental.
	AttrGuid = "guid"
	// AttrExchangeObjectId is the wire's "ExchangeObjectId" field.
	AttrExchangeObjectId = "exchange_object_id"
	// AttrObjectClass is the wire's "ObjectClass" array (e.g. "top",
	// "person", "organizationalPerson", "user") describing the directory
	// object's class hierarchy.
	AttrObjectClass = "object_class"
)
