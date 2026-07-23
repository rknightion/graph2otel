package semconv

// Attribute keys introduced by m365.message_trace (#254), the per-message mail
// flow record read over Exchange Online's Get-MessageTraceV2.
//
// # Only three keys are new, and that is the point
//
// The record has twelve wire fields, and nine of them already have a constant
// in this package because defender.quarantine maps the SAME fields off the SAME
// transport. Those are REUSED rather than re-coined, which is what makes the
// two signals joinable in LogQL without a translation table — most importantly
// MessageId, which both collectors emit as AttrInternetMessageId, the same key
// defender.email* carries, so the join #254 exists for is one label name:
//
//	MessageId        -> AttrInternetMessageId  (the RFC 5322 Message-ID)
//	Received         -> AttrReceivedTime       (verbatim, also the event time)
//	SenderAddress    -> AttrSenderAddress
//	RecipientAddress -> AttrRecipientAddress
//	Subject          -> AttrSubject
//	Size             -> AttrSize
//	Status           -> AttrStatus
//
// The registry's no-duplicate-values gate enforces this from the other
// direction: a second constant carrying "sender_address" is a build failure, so
// re-coining is not merely discouraged, it is impossible.
//
// All three keys below are LOG-ONLY. Every one identifies a single message or a
// single network endpoint, so a metric labeled by any of them grows one series
// per message — the #112 failure this collector is most exposed to, since it
// sees one record per message per recipient.
const (
	// AttrMessageTraceId is the trace record's own identity — the dedupe key.
	// It is NOT the Message-ID: one internet message fans out to one trace
	// record per recipient, each with a distinct MessageTraceId.
	AttrMessageTraceId = "message_trace_id"
	// AttrFromIp is the wire's FromIP: the sending host's address. IPv6 in the
	// live capture, so it is carried as an opaque string, never parsed.
	AttrFromIp = "from_ip"
	// AttrToIp is the wire's ToIP, the receiving host's address. It is EMPTY on
	// inbound mail (live-measured 2026-07-23) and the empty value is omitted
	// rather than stamped, so its presence itself distinguishes the directions.
	AttrToIp = "to_ip"
)
