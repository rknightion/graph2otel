// Package exchangeorgconfig is the Exchange Online organization-configuration
// collector (#250) — the Get-OrganizationConfig half of the org-config pair,
// read over the Exchange Online admin API's app-only cmdlet transport
// (internal/exoclient). The Get-AdminAuditLogConfig half is
// m365.exchange_audit_config; the two are separate collectors because they are
// separate cmdlets with separate authorization (Get-AdminAuditLogConfig is
// authorized at Security Reader, Get-OrganizationConfig needs Global Reader —
// live-measured 2026-07-23).
//
// # Why this matters
//
// This one object holds the tenant-wide Exchange switches with no Graph
// equivalent. Two of them decide whether the rest of the security stack works at
// all:
//
//   - OAuth2ClientProfileEnabled false means MODERN AUTH IS OFF, so clients fall
//     back to legacy protocols that carry no conditional-access or MFA
//     evaluation. That is the Error condition.
//   - AuditDisabled true means org-wide mailbox auditing is off, so mailbox
//     activity is not recorded anywhere. That is the Warn condition.
//
// # Both sides of the cardinality boundary
//
// From one cmdlet call:
//
//   - a bounded GAUGE m365.exchange.org_config.setting_enabled{setting} — one
//     0/1 series per named boolean, keyed by the wire field's snake_case so the
//     POLARITY reads off the name (audit_disabled = 1 means auditing is off).
//     The key space is a fixed list in this file, never tenant data;
//   - one LOG twin carrying the non-boolean configuration the gauge cannot
//     express: the EWS access policy, the activity timeout interval, the
//     authentication policy and the blocked-IP list.
//
// # Two coercion traps this collector must not fall into (live-measured)
//
//  1. PublicFoldersEnabled is the STRING "Local", not a boolean. Coercing it
//     would publish a confident 0 for a setting that is switched on.
//  2. MessageRecallEnabled, FocusedInboxOn, DefaultAuthenticationPolicy and the
//     EwsAllow* family arrive as NULL, meaning "not configured" — NOT false. A 0
//     there asserts a decision the tenant never made, so a null setting is
//     omitted from the gauge entirely rather than defaulted.
//
// Both are why booleanSettings is read through a presence-checking accessor
// rather than a plain type assertion with a zero-value fallback.
//
// A state snapshot, not an event stream: the twin is stamped at poll time.
package exchangeorgconfig

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
	collectorName = "m365.exchange_org_config"
	// eventName is the OTLP LogRecord EventName the config twin carries.
	eventName = "m365.exchange_org_config"
	// metricSetting is the 0/1 posture gauge keyed by setting.
	metricSetting = "m365.exchange.org_config.setting_enabled"
	// unitSetting is the annotation unit for a bounded 0/1 posture flag.
	unitSetting = "{setting}"
	// cmdlet is the single Exchange Online cmdlet this collector runs.
	cmdlet = "Get-OrganizationConfig"
	// interval: organization configuration changes when an admin edits it.
	interval = time.Hour
)

// The two settings that drive severity, plus the wire fields the twin reads.
const (
	fieldOAuth2ClientProfileEnabled = "OAuth2ClientProfileEnabled"
	fieldAuditDisabled              = "AuditDisabled"

	fieldName                       = "Name"
	fieldGuid                       = "Guid"
	fieldDisplayName                = "DisplayName"
	fieldPublicFoldersEnabled       = "PublicFoldersEnabled"
	fieldActivityTimeoutInterval    = "ActivityBasedAuthenticationTimeoutInterval"
	fieldDefaultAuthenticationPolic = "DefaultAuthenticationPolicy"
	fieldHierarchicalAddressBook    = "HierarchicalAddressBookRoot"
	fieldFocusedInboxOn             = "FocusedInboxOn"
	fieldEwsApplicationAccessPolicy = "EwsApplicationAccessPolicy"
	fieldEwsAllowOutlook            = "EwsAllowOutlook"
	fieldEwsAllowMacOutlook         = "EwsAllowMacOutlook"
	fieldIPListBlocked              = "IPListBlocked"
	fieldCustomerLockboxEnabled     = "CustomerLockboxEnabled"
	fieldEwsEnabled                 = "EwsEnabled"
	fieldIsMixedMode                = "IsMixedMode"
	fieldIsDehydrated               = "IsDehydrated"
	fieldMessageRecallEnabled       = "MessageRecallEnabled"
)

// booleanSettings is the fixed candidate key space of the posture gauge: the
// wire field to read, and the setting label to publish it under. The label is
// the field's snake_case, so polarity is readable from the name — audit_disabled
// at 1 means auditing is OFF.
//
// A candidate whose wire value is absent or not a real boolean is SKIPPED, not
// defaulted (see the coercion traps in the package doc), so the emitted series
// are a subset of this list and never exceed it.
var booleanSettings = []struct {
	field   string
	setting string
}{
	{fieldOAuth2ClientProfileEnabled, "oauth2_client_profile_enabled"},
	{fieldAuditDisabled, "audit_disabled"},
	{fieldCustomerLockboxEnabled, "customer_lockbox_enabled"},
	{fieldEwsEnabled, "ews_enabled"},
	{fieldIsDehydrated, "is_dehydrated"},
	{fieldIsMixedMode, "is_mixed_mode"},
	{fieldMessageRecallEnabled, "message_recall_enabled"},
	{"AutoExpandingArchiveEnabled", "auto_expanding_archive_enabled"},
	{"MailTipsAllTipsEnabled", "mail_tips_all_tips_enabled"},
	{"MailTipsExternalRecipientsTipsEnabled", "mail_tips_external_recipients_tips_enabled"},
	{"ConnectorsEnabled", "connectors_enabled"},
	{"ConnectorsEnabledForOutlook", "connectors_enabled_for_outlook"},
	{"ConnectorsEnabledForTeams", "connectors_enabled_for_teams"},
	{"ConnectorsEnabledForYammer", "connectors_enabled_for_yammer"},
	{"PublicComputersDetectionEnabled", "public_computers_detection_enabled"},
	{"ActivityBasedAuthenticationTimeoutEnabled", "activity_based_authentication_timeout_enabled"},
	{"ActivityBasedAuthenticationTimeoutWithSingleSignOnEnabled", "activity_based_authentication_timeout_with_sso_enabled"},
	{"SendFromAliasEnabled", "send_from_alias_enabled"},
	{"AutodiscoverPartialDirSync", "autodiscover_partial_dir_sync"},
	{"BookingsEnabled", "bookings_enabled"},
	{"OutlookMobileGCCRestrictionsEnabled", "outlook_mobile_gcc_restrictions_enabled"},
	{"LinkPreviewEnabled", "link_preview_enabled"},
	{"MessageRemindersEnabled", "message_reminders_enabled"},
	{"SmtpActionableMessagesEnabled", "smtp_actionable_messages_enabled"},
	{"WorkspaceTenantEnabled", "workspace_tenant_enabled"},
	{"DirectReportsGroupAutoCreationEnabled", "direct_reports_group_auto_creation_enabled"},
	{"UnblockUnsafeSenderPromptEnabled", "unblock_unsafe_sender_prompt_enabled"},
	{"MaskClientIpInReceivedHeadersEnabled", "mask_client_ip_in_received_headers_enabled"},
	{"ElcProcessingDisabled", "elc_processing_disabled"},
}

// Collector reads the Exchange Online organization configuration.
type Collector struct {
	c collectors.EXOClient
}

// New builds the organization-configuration collector.
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
// vocabulary (Exchange.ManageAsApp + a directory role). Get-OrganizationConfig
// needs GLOBAL READER — it is 403 all-NUL at Security Reader alone, unlike
// Get-AdminAuditLogConfig (live-measured 2026-07-23, both before and after the
// grant).
func (c *Collector) RequiredPermissions() []string { return nil }

// Collect runs the cmdlet and emits the posture gauge plus the config twin.
func (c *Collector) Collect(ctx context.Context, e telemetry.Emitter) error {
	// Stamp the transport HERE: with no ingest engine on this path the Scheduler
	// baseline is TransportGraph.
	e = telemetry.WithTransport(e, telemetry.TransportExchangeOnline)

	recs, err := c.c.Invoke(ctx, cmdlet, nil)
	if err != nil {
		return fmt.Errorf("%s: %w", cmdlet, err)
	}
	if len(recs) == 0 {
		// No config object returned — emit nothing rather than a misleading zero.
		return nil
	}
	r := recs[0]

	pts := make([]telemetry.GaugePoint, 0, len(booleanSettings))
	for _, s := range booleanSettings {
		b, ok := r[s.field].(bool)
		if !ok {
			// Absent, null or a non-boolean (PublicFoldersEnabled is the string
			// "Local"). Skipping is the point — see the package doc.
			continue
		}
		pts = append(pts, telemetry.GaugePoint{Value: b2f(b), Attrs: telemetry.Attrs{
			semconv.AttrSetting: s.setting,
		}})
	}
	e.GaugeSnapshot(metricSetting, unitSetting,
		"Exchange Online organization settings as a 0/1 flag per setting, named from the wire field so the polarity reads off the name (audit_disabled=1 means org-wide mailbox auditing is OFF). A setting the tenant has not configured arrives null and is OMITTED rather than reported as 0.",
		pts)

	e.LogEvent(configTwin(r))
	return nil
}

// configTwin renders the organization config as a log record. Modern auth off is
// Error — clients fall back to legacy protocols that carry no conditional-access
// or MFA evaluation; org-wide mailbox auditing off is Warn.
func configTwin(r map[string]any) telemetry.Event {
	modernAuth, modernAuthKnown := r[fieldOAuth2ClientProfileEnabled].(bool)
	auditDisabled, _ := r[fieldAuditDisabled].(bool)

	attrs := telemetry.Attrs{}
	telemetry.SetStr(attrs, semconv.AttrName, str(r, fieldName))
	telemetry.SetStr(attrs, semconv.AttrId, str(r, fieldGuid))
	telemetry.SetStr(attrs, semconv.AttrDisplayName, str(r, fieldDisplayName))
	telemetry.SetBool(attrs, semconv.AttrOauth2ClientProfileEnabled, modernAuth)
	telemetry.SetBool(attrs, semconv.AttrAuditDisabled, auditDisabled)
	telemetry.SetBool(attrs, semconv.AttrCustomerLockboxEnabled, boolVal(r, fieldCustomerLockboxEnabled))
	telemetry.SetBool(attrs, semconv.AttrEwsEnabled, boolVal(r, fieldEwsEnabled))
	telemetry.SetBool(attrs, semconv.AttrIsMixedMode, boolVal(r, fieldIsMixedMode))
	telemetry.SetBool(attrs, semconv.AttrIsDehydrated, boolVal(r, fieldIsDehydrated))
	// Non-boolean and tri-state configuration: verbatim, and omitted when null.
	telemetry.SetStr(attrs, semconv.AttrPublicFoldersEnabled, str(r, fieldPublicFoldersEnabled))
	telemetry.SetStr(attrs, semconv.AttrActivityBasedAuthTimeoutInterval, str(r, fieldActivityTimeoutInterval))
	telemetry.SetStr(attrs, semconv.AttrDefaultAuthenticationPolicy, str(r, fieldDefaultAuthenticationPolic))
	telemetry.SetStr(attrs, semconv.AttrHierarchicalAddressBookRoot, str(r, fieldHierarchicalAddressBook))
	telemetry.SetStr(attrs, semconv.AttrFocusedInboxOn, str(r, fieldFocusedInboxOn))
	telemetry.SetStr(attrs, semconv.AttrEwsApplicationAccessPolicy, str(r, fieldEwsApplicationAccessPolicy))
	telemetry.SetStr(attrs, semconv.AttrEwsAllowOutlook, str(r, fieldEwsAllowOutlook))
	telemetry.SetStr(attrs, semconv.AttrEwsAllowMacOutlook, str(r, fieldEwsAllowMacOutlook))
	telemetry.SetStr(attrs, semconv.AttrIpListBlocked, joinStrings(r, fieldIPListBlocked))
	optBool(attrs, semconv.AttrMessageRecallEnabled, r, fieldMessageRecallEnabled)

	sev := telemetry.SeverityInfo
	body := fmt.Sprintf("exchange org config %s: modern_auth=%t audit_disabled=%t",
		str(r, fieldName), modernAuth, auditDisabled)
	switch {
	case modernAuthKnown && !modernAuth:
		sev = telemetry.SeverityError
		body = fmt.Sprintf("exchange org config %s: modern authentication is OFF — clients can fall back to legacy protocols that carry no conditional-access or MFA evaluation", str(r, fieldName))
	case auditDisabled:
		sev = telemetry.SeverityWarn
		body = fmt.Sprintf("exchange org config %s: org-wide mailbox auditing is disabled — mailbox activity is not recorded", str(r, fieldName))
	}
	return telemetry.Event{Name: eventName, Body: body, Severity: sev, Attrs: attrs}
}

// b2f is 1 for true, 0 for false — the 0/1 posture gauge value.
func b2f(b bool) float64 {
	if b {
		return 1
	}
	return 0
}

// str reads a string column, "" when absent, null or non-string. Reading by
// exact name ignores the "<Name>@data.type" sidecars.
func str(m map[string]any, key string) string {
	s, _ := m[key].(string)
	return s
}

// boolVal reads a boolean column, false when absent or non-bool. Only used for
// fields live-verified to be real booleans; tri-state fields go through optBool.
func boolVal(m map[string]any, key string) bool {
	b, _ := m[key].(bool)
	return b
}

// optBool stamps a boolean ONLY when the wire carried a real bool, so a
// tri-state null stays absent rather than being reported as false.
func optBool(attrs telemetry.Attrs, key string, m map[string]any, field string) {
	if b, ok := m[field].(bool); ok {
		telemetry.SetBool(attrs, key, b)
	}
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

func init() {
	collectors.RegisterEXO(func(d collectors.EXODeps) collector.SnapshotCollector { return New(d) })
}

var _ collector.SnapshotCollector = (*Collector)(nil)
