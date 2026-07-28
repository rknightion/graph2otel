// Package semconv: attributes for the Exchange Online inbox-rules collector
// (#363, m365.inbox_rules — Get-InboxRule -IncludeHidden over the Exchange
// Online admin API's app-only cmdlet transport, one call per fanned-out
// mailbox via internal/exofanout).
//
// Reused where a key already exists: AttrName, AttrPriority, AttrIdentity,
// AttrIsValid, AttrPrimarySmtpAddress, AttrDeleteMessage (attrs_m365.go),
// AttrDescription (attrs_purview.go), AttrEnabled (attrs_intune.go),
// AttrObjectState (attrs_defender.go). Only genuinely new attributes are
// declared below.
package semconv

const (
	// AttrRuleIdentity is the wire's "RuleIdentity" — a BigInteger that
	// overflows int64 (live-measured 2026-07-28, #363: 15394007230974001153).
	// Carried as a STRING everywhere in this collector; it is an opaque
	// identity, never arithmetic. Never a metric label (per-rule identity).
	AttrRuleIdentity = "rule_identity"
	// AttrErrorType is the wire's "ErrorType" (e.g. "None") describing whether
	// the rule is in an error state.
	AttrErrorType = "error_type"
	// AttrSupportedByTask is the wire's "SupportedByTask" boolean.
	AttrSupportedByTask = "supported_by_task"
	// AttrMailboxOwnerId is the wire's "MailboxOwnerId" — the directory id of
	// the mailbox this rule belongs to. Twin-only, never a metric label.
	AttrMailboxOwnerId = "mailbox_owner_id"
	// AttrSubjectContainsWords is the wire's "SubjectContainsWords" array — the
	// condition words this rule matches on, when the rule uses that condition.
	AttrSubjectContainsWords = "subject_contains_words"
	// AttrForwardTo is the wire's "ForwardTo" array, carried VERBATIM. Each
	// element is a display name plus a legacyExchangeDN
	// (`"Rob Knight" [EX:/o=ExchangeLabs/...]`), NOT an SMTP address — there is
	// no SMTP address anywhere in a Get-InboxRule record, so this is emitted
	// honestly rather than half-parsed into something that looks like one.
	AttrForwardTo = "forward_to"
	// AttrForwardToDisplayNames is the DISPLAY-NAME portion extracted from each
	// AttrForwardTo entry, when the `"Name" [...]` shape parses. It is a
	// display name, not an address, and does not identify which mailbox (or
	// whether an external one) receives the mail — see the package doc.
	// Elements that do not parse are omitted from this list, never guessed.
	AttrForwardToDisplayNames = "forward_to_display_names"
	// AttrRedirectTo is the wire's "RedirectTo" array — same shape and same
	// display-name-only caveat as AttrForwardTo. UNOBSERVED on this tenant
	// (#363): mapped because it is a documented rule action, but its value set
	// has not been seen on the wire.
	AttrRedirectTo = "redirect_to"
	// AttrForwardAsAttachmentTo is the wire's "ForwardAsAttachmentTo" array —
	// same shape as AttrForwardTo. UNOBSERVED on this tenant (#363).
	AttrForwardAsAttachmentTo = "forward_as_attachment_to"
	// AttrHasForwarding is the bounded derived flag ("true"/"false") backing the
	// m365.inbox_rules.rules gauge's has_forwarding label: true when any of
	// ForwardTo, ForwardAsAttachmentTo or RedirectTo is non-empty. It answers
	// "does this rule forward or redirect mail", not WHERE — see AttrForwardTo.
	AttrHasForwarding = "has_forwarding"
)
