// Package exchangemailboxes is the Exchange Online mailbox census and posture
// collector (#250), read over the Exchange Online admin API's app-only cmdlet
// transport (internal/exoclient).
//
// # Why this matters
//
// Mailbox-level forwarding is the quietest exfiltration path in Microsoft 365:
// ForwardingSmtpAddress sends a copy of every message out of the tenant, it
// survives a password reset, and the mailbox owner never sees it. Alongside it
// sit the per-mailbox controls that decide whether anything is recoverable or
// even recorded — SingleItemRecoveryEnabled, LitigationHoldEnabled and
// AuditEnabled. None of it is on any Graph endpoint.
//
// The recipient-type census matters for a second reason: a SharedMailbox has no
// interactive sign-in of its own, so it is a standing delegation surface that a
// user census does not show.
//
// # Both sides of the cardinality boundary
//
// From one cmdlet call:
//
//   - a bounded census GAUGE m365.exchange.mailboxes{recipient_type_details,
//     forwarding_configured, audit_enabled} — recipient types are a value set
//     fixed by the API, so this grows with the VARIETY of mailbox types, never
//     with the number of mailboxes;
//   - a bounded posture GAUGE m365.exchange.mailboxes.setting_enabled{setting} —
//     one seeded series per named boolean setting, so "how many mailboxes have
//     single-item recovery off" is total minus this;
//   - one LOG twin per mailbox carrying the UPN, addresses, forwarding targets,
//     holds, quotas and archive state.
//
// A UPN is per-entity and is NEVER a metric label (#112): one series per user
// would grow with tenant size, cost real money, and answer nothing the twin does
// not answer better. "WHICH mailbox forwards externally" is a LogQL query over
// the twin.
//
// # No silent truncation
//
// The default page returns ONE mailbox plus an @odata.nextLink and an
// @adminapi.warnings string saying results were truncated. internal/exoclient
// neither follows the link nor surfaces the warning — it returns only the value
// array — so a collector that did not ask for everything would report a tenant
// of one and look perfectly healthy. ResultSize=Unlimited is therefore
// load-bearing, not a tuning knob (live-measured 2026-07-23: with it, both the
// nextLink and the warning disappear).
//
// # Wire shapes (live-measured 2026-07-23)
//
// Quotas are FORMATTED STRINGS, not numbers ("99 GB (106,300,440,576 bytes)");
// LitigationHoldDuration is the string "Unlimited"; RetainDeletedItemsFor and
// AuditLogAgeLimit are .NET TimeSpans ("14.00:00:00"). All of them are emitted
// verbatim — re-deriving a number from a formatted string would be inventing a
// value the API never sent (#142). EmailAddresses is a prefix-tagged list
// (smtp:/SMTP:/SIP:/SPO:), joined rather than dropped.
//
// A state snapshot, not an event stream: the twins are stamped at poll time.
package exchangemailboxes

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/rknightion/graph2otel/internal/collector"
	"github.com/rknightion/graph2otel/internal/collectors"
	"github.com/rknightion/graph2otel/internal/semconv"
	"github.com/rknightion/graph2otel/internal/telemetry"
)

const (
	// collectorName is the stable key for config, self-observability and the
	// admin status page.
	collectorName = "m365.exchange_mailboxes"
	// eventName is the OTLP LogRecord EventName each mailbox twin carries.
	eventName = "m365.exchange_mailbox"
	// metricMailboxes is the recipient-type census.
	metricMailboxes = "m365.exchange.mailboxes"
	// metricSetting counts mailboxes with each named boolean setting on.
	metricSetting = "m365.exchange.mailboxes.setting_enabled"
	// unitMailbox is the annotation unit for a countable mailbox.
	unitMailbox = "{mailbox}"
	// cmdlet is the single Exchange Online cmdlet this collector runs.
	cmdlet = "Get-Mailbox"
	// paramResultSize / resultSizeUnlimited defeat the default one-row page. See
	// the no-silent-truncation note in the package doc — this is load-bearing.
	paramResultSize     = "ResultSize"
	resultSizeUnlimited = "Unlimited"
	// interval: mailbox posture changes on the timescale of admin edits and user
	// provisioning. Hourly, and one call.
	interval = time.Hour
	// archiveNone is the ArchiveStatus value meaning no archive is provisioned.
	archiveNone = "None"
)

// Wire field names, read by exact name so the "<Name>@data.type" sidecars are
// ignored.
const (
	fieldUserPrincipalName             = "UserPrincipalName"
	fieldDisplayName                   = "DisplayName"
	fieldPrimarySmtpAddress            = "PrimarySmtpAddress"
	fieldRecipientTypeDetails          = "RecipientTypeDetails"
	fieldExchangeGuid                  = "ExchangeGuid"
	fieldExternalDirectoryObjectId     = "ExternalDirectoryObjectId"
	fieldLitigationHoldEnabled         = "LitigationHoldEnabled"
	fieldLitigationHoldDuration        = "LitigationHoldDuration"
	fieldLitigationHoldDate            = "LitigationHoldDate"
	fieldLitigationHoldOwner           = "LitigationHoldOwner"
	fieldInPlaceHolds                  = "InPlaceHolds"
	fieldRetentionHoldEnabled          = "RetentionHoldEnabled"
	fieldSingleItemRecoveryEnabled     = "SingleItemRecoveryEnabled"
	fieldRetainDeletedItemsFor         = "RetainDeletedItemsFor"
	fieldComplianceTagHoldApplied      = "ComplianceTagHoldApplied"
	fieldForwardingAddress             = "ForwardingAddress"
	fieldForwardingSmtpAddress         = "ForwardingSmtpAddress"
	fieldDeliverToMailboxAndForward    = "DeliverToMailboxAndForward"
	fieldHiddenFromAddressListsEnabled = "HiddenFromAddressListsEnabled"
	fieldAuditEnabled                  = "AuditEnabled"
	fieldAuditLogAgeLimit              = "AuditLogAgeLimit"
	fieldArchiveStatus                 = "ArchiveStatus"
	fieldArchiveState                  = "ArchiveState"
	fieldArchiveGuid                   = "ArchiveGuid"
	fieldIsMailboxEnabled              = "IsMailboxEnabled"
	fieldAccountDisabled               = "AccountDisabled"
	fieldWhenMailboxCreated            = "WhenMailboxCreated"
	fieldMessageCopyForSentAsEnabled   = "MessageCopyForSentAsEnabled"
	fieldMessageCopyForSendOnBehalf    = "MessageCopyForSendOnBehalfEnabled"
	fieldGrantSendOnBehalfTo           = "GrantSendOnBehalfTo"
	fieldProhibitSendQuota             = "ProhibitSendQuota"
	fieldProhibitSendReceiveQuota      = "ProhibitSendReceiveQuota"
	fieldIssueWarningQuota             = "IssueWarningQuota"
	fieldMailboxPlan                   = "MailboxPlan"
	fieldIsDirSynced                   = "IsDirSynced"
	fieldIsShared                      = "IsShared"
	fieldIsResource                    = "IsResource"
	fieldIsInactiveMailbox             = "IsInactiveMailbox"
	fieldEmailAddresses                = "EmailAddresses"
	fieldIdentity                      = "Identity"
)

// The named settings the posture gauge reports.
const (
	settingAuditEnabled       = "audit_enabled"
	settingSingleItemRecovery = "single_item_recovery"
	settingLitigationHold     = "litigation_hold"
	settingRetentionHold      = "retention_hold"
	settingComplianceTagHold  = "compliance_tag_hold"
	settingHiddenFromAddress  = "hidden_from_address_lists"
	settingForwarding         = "forwarding_configured"
	settingDeliverAndForward  = "deliver_and_forward"
	settingArchiveEnabled     = "archive_enabled"
	settingMessageCopySentAs  = "message_copy_sent_as"
	settingInactiveMailbox    = "inactive_mailbox"
	settingAccountDisabled    = "account_disabled"
)

// protectionSettings is the fixed, ordered key space of the posture gauge. Every
// entry is seeded at zero, so a setting nobody uses is a visible 0 rather than a
// missing series.
var protectionSettings = []struct {
	name string
	on   func(map[string]any) bool
}{
	{settingAuditEnabled, func(r map[string]any) bool { return boolVal(r, fieldAuditEnabled) }},
	{settingSingleItemRecovery, func(r map[string]any) bool { return boolVal(r, fieldSingleItemRecoveryEnabled) }},
	{settingLitigationHold, func(r map[string]any) bool { return boolVal(r, fieldLitigationHoldEnabled) }},
	{settingRetentionHold, func(r map[string]any) bool { return boolVal(r, fieldRetentionHoldEnabled) }},
	{settingComplianceTagHold, func(r map[string]any) bool { return boolVal(r, fieldComplianceTagHoldApplied) }},
	{settingHiddenFromAddress, func(r map[string]any) bool { return boolVal(r, fieldHiddenFromAddressListsEnabled) }},
	{settingForwarding, forwardingConfigured},
	{settingDeliverAndForward, func(r map[string]any) bool { return boolVal(r, fieldDeliverToMailboxAndForward) }},
	{settingArchiveEnabled, archiveEnabled},
	{settingMessageCopySentAs, func(r map[string]any) bool { return boolVal(r, fieldMessageCopyForSentAsEnabled) }},
	{settingInactiveMailbox, func(r map[string]any) bool { return boolVal(r, fieldIsInactiveMailbox) }},
	{settingAccountDisabled, func(r map[string]any) bool { return boolVal(r, fieldAccountDisabled) }},
}

// censusKey is the bounded tuple the census gauge is counted by.
type censusKey struct {
	recipientType string
	forwarding    string
	audit         string
}

// Collector reads the Exchange Online mailbox census and posture.
type Collector struct {
	c collectors.EXOClient
}

// New builds the mailbox collector.
func New(d collectors.EXODeps) *Collector { return &Collector{c: d.Client} }

// Name implements collector.Collector.
func (c *Collector) Name() string { return collectorName }

// DefaultInterval implements collector.Collector.
func (c *Collector) DefaultInterval() time.Duration { return interval }

// IngestTransport marks every record as coming from the Exchange Online admin
// API rather than Graph (#141).
func (c *Collector) IngestTransport() telemetry.Transport {
	return telemetry.TransportExchangeOnline
}

// RequiredPermissions is empty: access is the two grants outside the Graph-scope
// vocabulary (Exchange.ManageAsApp + a directory role). Get-Mailbox needs GLOBAL
// READER — it is 403 all-NUL at Security Reader alone (live-measured
// 2026-07-23, both before and after the grant).
func (c *Collector) RequiredPermissions() []string { return nil }

// Collect runs the cmdlet and emits the census, the posture gauge and a twin per
// mailbox.
func (c *Collector) Collect(ctx context.Context, e telemetry.Emitter) error {
	// Stamp the transport HERE: with no ingest engine on this path the Scheduler
	// baseline is TransportGraph.
	e = telemetry.WithTransport(e, telemetry.TransportExchangeOnline)

	// ResultSize is load-bearing — see the package doc.
	recs, err := c.c.Invoke(ctx, cmdlet, map[string]any{paramResultSize: resultSizeUnlimited})
	if err != nil {
		return fmt.Errorf("%s: %w", cmdlet, err)
	}

	census := map[censusKey]float64{}
	settings := make(map[string]float64, len(protectionSettings))
	for _, s := range protectionSettings {
		settings[s.name] = 0
	}

	for _, r := range recs {
		census[censusKey{
			recipientType: str(r, fieldRecipientTypeDetails),
			forwarding:    boolStr(forwardingConfigured(r)),
			audit:         boolStr(boolVal(r, fieldAuditEnabled)),
		}]++
		for _, s := range protectionSettings {
			if s.on(r) {
				settings[s.name]++
			}
		}
		e.LogEvent(mailboxTwin(r))
	}

	censusPts := make([]telemetry.GaugePoint, 0, len(census))
	for k, v := range census {
		censusPts = append(censusPts, telemetry.GaugePoint{Value: v, Attrs: telemetry.Attrs{
			semconv.AttrRecipientTypeDetails: k.recipientType,
			semconv.AttrForwardingConfigured: k.forwarding,
			semconv.AttrAuditEnabled:         k.audit,
		}})
	}
	e.GaugeSnapshot(metricMailboxes, unitMailbox,
		"Exchange Online mailboxes by recipient type, whether forwarding is configured and whether auditing is on. Keyed by mailbox TYPE, never by mailbox — which mailbox forwards where is on the m365.exchange_mailbox log twin.",
		censusPts)

	settingPts := make([]telemetry.GaugePoint, 0, len(protectionSettings))
	for _, s := range protectionSettings {
		settingPts = append(settingPts, telemetry.GaugePoint{Value: settings[s.name], Attrs: telemetry.Attrs{
			semconv.AttrSetting: s.name,
		}})
	}
	e.GaugeSnapshot(metricSetting, unitMailbox,
		"Mailboxes with each named boolean setting ON. Every setting is seeded, so \"how many mailboxes have single-item recovery OFF\" is the mailbox total minus this series rather than a missing one.",
		settingPts)

	return nil
}

// mailboxTwin renders one mailbox as a log record. SMTP forwarding off the
// tenant is the mailbox-level exfiltration path and rates Error; an unaudited
// mailbox is a blind spot rather than an active leak, so it rates Warn.
func mailboxTwin(r map[string]any) telemetry.Event {
	upn := str(r, fieldUserPrincipalName)
	smtpFwd := str(r, fieldForwardingSmtpAddress)
	internalFwd := str(r, fieldForwardingAddress)
	audited := boolVal(r, fieldAuditEnabled)

	attrs := telemetry.Attrs{}
	telemetry.SetStr(attrs, semconv.AttrUserPrincipalName, upn)
	telemetry.SetStr(attrs, semconv.AttrDisplayName, str(r, fieldDisplayName))
	telemetry.SetStr(attrs, semconv.AttrPrimarySmtpAddress, str(r, fieldPrimarySmtpAddress))
	telemetry.SetStr(attrs, semconv.AttrRecipientTypeDetails, str(r, fieldRecipientTypeDetails))
	telemetry.SetStr(attrs, semconv.AttrExchangeGuid, str(r, fieldExchangeGuid))
	telemetry.SetStr(attrs, semconv.AttrExternalDirectoryObjectId, str(r, fieldExternalDirectoryObjectId))
	telemetry.SetStr(attrs, semconv.AttrId, str(r, fieldIdentity))

	telemetry.SetStr(attrs, semconv.AttrForwardingSmtpAddress, smtpFwd)
	telemetry.SetStr(attrs, semconv.AttrForwardingAddress, internalFwd)
	telemetry.SetBool(attrs, semconv.AttrDeliverToMailboxAndForward, boolVal(r, fieldDeliverToMailboxAndForward))

	telemetry.SetBool(attrs, semconv.AttrAuditEnabled, audited)
	telemetry.SetStr(attrs, semconv.AttrAuditLogAgeLimit, str(r, fieldAuditLogAgeLimit))
	telemetry.SetBool(attrs, semconv.AttrSingleItemRecoveryEnabled, boolVal(r, fieldSingleItemRecoveryEnabled))
	telemetry.SetStr(attrs, semconv.AttrRetainDeletedItemsFor, str(r, fieldRetainDeletedItemsFor))
	telemetry.SetBool(attrs, semconv.AttrLitigationHoldEnabled, boolVal(r, fieldLitigationHoldEnabled))
	telemetry.SetStr(attrs, semconv.AttrLitigationHoldDuration, str(r, fieldLitigationHoldDuration))
	telemetry.SetStr(attrs, semconv.AttrLitigationHoldDate, str(r, fieldLitigationHoldDate))
	telemetry.SetStr(attrs, semconv.AttrLitigationHoldOwner, str(r, fieldLitigationHoldOwner))
	telemetry.SetBool(attrs, semconv.AttrRetentionHoldEnabled, boolVal(r, fieldRetentionHoldEnabled))
	telemetry.SetBool(attrs, semconv.AttrComplianceTagHoldApplied, boolVal(r, fieldComplianceTagHoldApplied))
	telemetry.SetStr(attrs, semconv.AttrInPlaceHolds, joinStrings(r, fieldInPlaceHolds))

	telemetry.SetStr(attrs, semconv.AttrArchiveStatus, str(r, fieldArchiveStatus))
	telemetry.SetStr(attrs, semconv.AttrArchiveState, str(r, fieldArchiveState))
	telemetry.SetStr(attrs, semconv.AttrArchiveGuid, str(r, fieldArchiveGuid))

	telemetry.SetBool(attrs, semconv.AttrHiddenFromAddressLists, boolVal(r, fieldHiddenFromAddressListsEnabled))
	telemetry.SetBool(attrs, semconv.AttrIsMailboxEnabled, boolVal(r, fieldIsMailboxEnabled))
	telemetry.SetBool(attrs, semconv.AttrAccountDisabled, boolVal(r, fieldAccountDisabled))
	telemetry.SetBool(attrs, semconv.AttrIsDirSynced, boolVal(r, fieldIsDirSynced))
	telemetry.SetBool(attrs, semconv.AttrIsShared, boolVal(r, fieldIsShared))
	telemetry.SetBool(attrs, semconv.AttrIsResource, boolVal(r, fieldIsResource))
	telemetry.SetBool(attrs, semconv.AttrIsInactiveMailbox, boolVal(r, fieldIsInactiveMailbox))
	telemetry.SetBool(attrs, semconv.AttrMessageCopyForSentAsEnabled, boolVal(r, fieldMessageCopyForSentAsEnabled))
	telemetry.SetBool(attrs, semconv.AttrMessageCopyForSendOnBehalfEnabled, boolVal(r, fieldMessageCopyForSendOnBehalf))
	telemetry.SetStr(attrs, semconv.AttrGrantSendOnBehalfTo, joinStrings(r, fieldGrantSendOnBehalfTo))
	telemetry.SetStr(attrs, semconv.AttrEmailAddresses, joinStrings(r, fieldEmailAddresses))

	// Quotas stay verbatim: the wire sends a formatted string and re-deriving a
	// byte count from it would emit a number the API never sent.
	telemetry.SetStr(attrs, semconv.AttrProhibitSendQuota, str(r, fieldProhibitSendQuota))
	telemetry.SetStr(attrs, semconv.AttrProhibitSendReceiveQuota, str(r, fieldProhibitSendReceiveQuota))
	telemetry.SetStr(attrs, semconv.AttrIssueWarningQuota, str(r, fieldIssueWarningQuota))
	telemetry.SetStr(attrs, semconv.AttrMailboxPlan, str(r, fieldMailboxPlan))
	telemetry.SetStr(attrs, semconv.AttrWhenMailboxCreated, str(r, fieldWhenMailboxCreated))

	sev := telemetry.SeverityInfo
	body := fmt.Sprintf("mailbox %s: type=%s audit=%t", upn, str(r, fieldRecipientTypeDetails), audited)
	switch {
	case smtpFwd != "":
		sev = telemetry.SeverityError
		body = fmt.Sprintf("mailbox %s forwards mail out of the tenant to %s", upn, smtpFwd)
	case internalFwd != "":
		sev = telemetry.SeverityWarn
		body = fmt.Sprintf("mailbox %s forwards mail to %s", upn, internalFwd)
	case !audited:
		sev = telemetry.SeverityWarn
		body = fmt.Sprintf("mailbox %s has auditing disabled — its activity is not recorded", upn)
	}
	return telemetry.Event{Name: eventName, Body: body, Severity: sev, Attrs: attrs}
}

// forwardingConfigured reports whether the mailbox sends copies anywhere, by
// either the internal recipient or the SMTP route.
func forwardingConfigured(r map[string]any) bool {
	return str(r, fieldForwardingSmtpAddress) != "" || str(r, fieldForwardingAddress) != ""
}

// archiveEnabled reports whether an archive mailbox is provisioned. "None" is
// the live value for no archive; an empty status is treated the same.
func archiveEnabled(r map[string]any) bool {
	s := str(r, fieldArchiveStatus)
	return s != "" && s != archiveNone
}

// joinStrings renders a JSON array of strings as a comma-separated list, "" when
// absent or empty.
func joinStrings(m map[string]any, key string) string {
	raw, ok := m[key].([]any)
	if !ok {
		return ""
	}
	out := make([]string, 0, len(raw))
	for _, e := range raw {
		if s, ok := e.(string); ok && s != "" {
			out = append(out, s)
		}
	}
	return strings.Join(out, ",")
}

// boolStr renders a bool as the metric-label string.
func boolStr(b bool) string {
	if b {
		return "true"
	}
	return "false"
}

// str reads a string column, "" when absent or non-string. Reading by exact name
// ignores the "<Name>@data.type" sidecars.
func str(m map[string]any, key string) string {
	s, _ := m[key].(string)
	return s
}

// boolVal reads a boolean column, false when absent or non-bool.
func boolVal(m map[string]any, key string) bool {
	b, _ := m[key].(bool)
	return b
}

func init() {
	collectors.RegisterEXO(func(d collectors.EXODeps) collector.SnapshotCollector { return New(d) })
}

var _ collector.SnapshotCollector = (*Collector)(nil)
