// Package exchangetransportrules is the Exchange Online mail-flow rule collector
// (#250), read over the Exchange Online admin API's app-only cmdlet transport
// (internal/exoclient).
//
// # Why this matters
//
// A transport rule runs on every message in the tenant, and one that blind-copies
// or redirects mail to an outside address is textbook business-email-compromise
// persistence: it survives a password reset, it is invisible to the mailbox
// owner, and nothing in the Graph API surface exposes it. The same mechanism
// also hides mail (DeleteMessage) and reroutes it through arbitrary
// infrastructure (RouteMessageOutboundConnector).
//
// # Both sides of the cardinality boundary
//
// From one cmdlet call:
//
//   - bounded GAUGEs — m365.exchange.transport_rules{state, rule_mode} (2x3,
//     both enums fixed by the API) and .redirecting{state}, the count of rules
//     that duplicate or divert mail;
//   - one LOG twin per rule carrying name, priority, who created and last
//     changed it, the condition/action class names, and every mail-diverting
//     target — the per-rule detail the gauges collapse (#112/#114).
//
// A DISABLED rule is deliberately counted and twinned rather than ignored: it is
// one toggle away from live, and an attacker staging a rule disabled is a real
// pattern. It is Warn where the same rule enabled would be Error.
//
// # Wire shapes (live-measured 2026-07-23)
//
// Conditions, Actions and Exceptions are #Collection(String) of fully-qualified
// .NET class names under one constant namespace, or null when the rule has none.
// State and Mode are verbatim enum strings. Booleans are real JSON bools.
//
// The multi-recipient properties (BlindCopyTo, CopyTo, RedirectMessageTo,
// AddToRecipients) are present on the wire but null on m7kni, so their NAMES are
// verified and their populated shape is not. recipientsOf therefore accepts both
// shapes the admin API uses for multi-valued properties — an array and a bare
// string — rather than betting on one.
//
// A state snapshot, not an event stream: the twins are stamped at poll time.
package exchangetransportrules

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
	collectorName = "m365.exchange_transport_rules"
	// eventName is the OTLP LogRecord EventName each rule twin carries.
	eventName = "m365.exchange_transport_rule"
	// metricRules counts rules by the bounded state x mode tuple.
	metricRules = "m365.exchange.transport_rules"
	// metricRedirecting counts rules that duplicate or divert mail.
	metricRedirecting = "m365.exchange.transport_rules.redirecting"
	// unitRule is the annotation unit for a countable rule.
	unitRule = "{rule}"
	// cmdlet is the single Exchange Online cmdlet this collector runs.
	cmdlet = "Get-TransportRule"
	// interval: rules change when an admin edits them, and one cmdlet call is
	// cheap.
	interval = time.Hour
	// rulesNamespace is the constant .NET namespace every condition/action class
	// name sits under. Stripped for readability; anything outside it is left
	// verbatim.
	rulesNamespace = "Microsoft.Exchange.MessagingPolicies.Rules.Tasks."
)

// The bounded enum values, seeded so an empty tenant still publishes its series.
const (
	stateEnabled  = "Enabled"
	stateDisabled = "Disabled"

	modeEnforce        = "Enforce"
	modeAudit          = "Audit"
	modeAuditAndNotify = "AuditAndNotify"
)

var (
	states = []string{stateEnabled, stateDisabled}
	modes  = []string{modeEnforce, modeAudit, modeAuditAndNotify}
)

// Wire field names, read by exact name so the "<Name>@data.type" sidecars are
// ignored.
const (
	fieldState                         = "State"
	fieldMode                          = "Mode"
	fieldName                          = "Name"
	fieldGuid                          = "Guid"
	fieldDescription                   = "Description"
	fieldComments                      = "Comments"
	fieldCreatedBy                     = "CreatedBy"
	fieldLastModifiedBy                = "LastModifiedBy"
	fieldManuallyModified              = "ManuallyModified"
	fieldActivationDate                = "ActivationDate"
	fieldExpiryDate                    = "ExpiryDate"
	fieldWhenChanged                   = "WhenChanged"
	fieldConditions                    = "Conditions"
	fieldActions                       = "Actions"
	fieldExceptions                    = "Exceptions"
	fieldRuleErrorAction               = "RuleErrorAction"
	fieldSenderAddressLocation         = "SenderAddressLocation"
	fieldFromScope                     = "FromScope"
	fieldSentToScope                   = "SentToScope"
	fieldDlpPolicy                     = "DlpPolicy"
	fieldPrependSubject                = "PrependSubject"
	fieldSetAuditSeverity              = "SetAuditSeverity"
	fieldApplyRightsProtectionTemplate = "ApplyRightsProtectionTemplate"
	fieldRouteMessageOutboundConnector = "RouteMessageOutboundConnector"
	fieldDeleteMessage                 = "DeleteMessage"
	fieldQuarantine                    = "Quarantine"
	fieldStopRuleProcessing            = "StopRuleProcessing"
	fieldPriority                      = "Priority"
	fieldIsValid                       = "IsValid"
)

// divertFields are the properties that cause a message to reach a recipient the
// sender did not address. Any one of them set means the rule duplicates or
// diverts mail — the BEC-persistence shape.
var divertFields = []struct {
	wire string
	attr string
}{
	{"BlindCopyTo", semconv.AttrBlindCopyTo},
	{"CopyTo", semconv.AttrCopyTo},
	{"RedirectMessageTo", semconv.AttrRedirectMessageTo},
	{"AddToRecipients", semconv.AttrAddToRecipients},
}

// Collector reads Exchange Online transport rules.
type Collector struct {
	c collectors.EXOClient
}

// New builds the transport-rule collector.
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
// vocabulary (Exchange.ManageAsApp + Security Reader). Get-TransportRule is
// authorized at Security Reader (live-measured 2026-07-23).
func (c *Collector) RequiredPermissions() []string { return nil }

// Collect runs the cmdlet and emits the two gauges plus a twin per rule.
func (c *Collector) Collect(ctx context.Context, e telemetry.Emitter) error {
	// Stamp the transport HERE: with no ingest engine on this path the Scheduler
	// baseline is TransportGraph.
	e = telemetry.WithTransport(e, telemetry.TransportExchangeOnline)

	recs, err := c.c.Invoke(ctx, cmdlet, nil)
	if err != nil {
		return fmt.Errorf("%s: %w", cmdlet, err)
	}

	counts := map[[2]string]float64{}
	for _, s := range states {
		for _, m := range modes {
			counts[[2]string{s, m}] = 0
		}
	}
	redirecting := map[string]float64{stateEnabled: 0, stateDisabled: 0}

	for _, r := range recs {
		state := str(r, fieldState)
		counts[[2]string{state, str(r, fieldMode)}]++
		if _, diverts := divertTargets(r); diverts {
			redirecting[state]++
		}
		e.LogEvent(ruleTwin(r))
	}

	rulePts := make([]telemetry.GaugePoint, 0, len(counts))
	seen := map[[2]string]bool{}
	addRule := func(k [2]string) {
		if seen[k] {
			return
		}
		seen[k] = true
		rulePts = append(rulePts, telemetry.GaugePoint{Value: counts[k], Attrs: telemetry.Attrs{
			semconv.AttrState:    k[0],
			semconv.AttrRuleMode: k[1],
		}})
	}
	for _, s := range states {
		for _, m := range modes {
			addRule([2]string{s, m})
		}
	}
	for k := range counts {
		addRule(k)
	}
	e.GaugeSnapshot(metricRules, unitRule,
		"Exchange Online transport rules by state and rule mode. Disabled rules are counted too: a staged rule is one toggle from live. Which rule, and what it does, is on the m365.exchange_transport_rule log twin.",
		rulePts)

	redirPts := make([]telemetry.GaugePoint, 0, len(states))
	for _, s := range states {
		redirPts = append(redirPts, telemetry.GaugePoint{Value: redirecting[s], Attrs: telemetry.Attrs{
			semconv.AttrState: s,
		}})
	}
	e.GaugeSnapshot(metricRedirecting, unitRule,
		"Transport rules that blind-copy, copy, redirect or add a recipient — a message reaching someone the sender did not address. An ENABLED one is the textbook business-email-compromise persistence shape and also emits an Error-severity log record naming the target.",
		redirPts)

	return nil
}

// ruleTwin renders one transport rule as a log record. An enabled rule that
// diverts mail is Error; the same rule disabled is Warn, because it is one
// toggle from live rather than harmless.
func ruleTwin(r map[string]any) telemetry.Event {
	state := str(r, fieldState)
	targets, diverts := divertTargets(r)

	attrs := telemetry.Attrs{}
	telemetry.SetStr(attrs, semconv.AttrName, str(r, fieldName))
	telemetry.SetStr(attrs, semconv.AttrId, str(r, fieldGuid))
	telemetry.SetStr(attrs, semconv.AttrState, state)
	telemetry.SetStr(attrs, semconv.AttrRuleMode, str(r, fieldMode))
	telemetry.SetNum(attrs, semconv.AttrPriority, r, fieldPriority)
	telemetry.SetStr(attrs, semconv.AttrDescription, str(r, fieldDescription))
	telemetry.SetStr(attrs, semconv.AttrComments, str(r, fieldComments))
	telemetry.SetStr(attrs, semconv.AttrCreatedBy, str(r, fieldCreatedBy))
	telemetry.SetStr(attrs, semconv.AttrLastModifiedBy, str(r, fieldLastModifiedBy))
	telemetry.SetBool(attrs, semconv.AttrManuallyModified, boolVal(r, fieldManuallyModified))
	telemetry.SetStr(attrs, semconv.AttrActivationDate, str(r, fieldActivationDate))
	telemetry.SetStr(attrs, semconv.AttrExpiryDate, str(r, fieldExpiryDate))
	telemetry.SetStr(attrs, semconv.AttrWhenChanged, str(r, fieldWhenChanged))
	telemetry.SetStr(attrs, semconv.AttrConditionTypes, classNames(r, fieldConditions))
	telemetry.SetStr(attrs, semconv.AttrActionTypes, classNames(r, fieldActions))
	telemetry.SetStr(attrs, semconv.AttrExceptionTypes, classNames(r, fieldExceptions))
	telemetry.SetStr(attrs, semconv.AttrRuleErrorAction, str(r, fieldRuleErrorAction))
	telemetry.SetStr(attrs, semconv.AttrSenderAddressLocation, str(r, fieldSenderAddressLocation))
	telemetry.SetStr(attrs, semconv.AttrFromScope, str(r, fieldFromScope))
	telemetry.SetStr(attrs, semconv.AttrSentToScope, str(r, fieldSentToScope))
	telemetry.SetStr(attrs, semconv.AttrDlpPolicy, str(r, fieldDlpPolicy))
	telemetry.SetStr(attrs, semconv.AttrPrependSubject, str(r, fieldPrependSubject))
	telemetry.SetStr(attrs, semconv.AttrSetAuditSeverity, str(r, fieldSetAuditSeverity))
	telemetry.SetStr(attrs, semconv.AttrApplyRightsProtectionTemplate, str(r, fieldApplyRightsProtectionTemplate))
	telemetry.SetStr(attrs, semconv.AttrRouteMessageOutboundConnector, str(r, fieldRouteMessageOutboundConnector))
	telemetry.SetBool(attrs, semconv.AttrDeleteMessage, boolVal(r, fieldDeleteMessage))
	telemetry.SetBool(attrs, semconv.AttrQuarantine, boolVal(r, fieldQuarantine))
	telemetry.SetBool(attrs, semconv.AttrStopRuleProcessing, boolVal(r, fieldStopRuleProcessing))
	telemetry.SetBool(attrs, semconv.AttrIsValid, boolVal(r, fieldIsValid))
	telemetry.SetBool(attrs, semconv.AttrRedirectsMail, diverts)
	// Each diverting target lands under its own key, so a query can tell a BCC
	// from a redirect without parsing a blob.
	for _, f := range divertFields {
		if v, ok := recipientsOf(r, f.wire); ok {
			telemetry.SetStr(attrs, f.attr, v)
		}
	}

	enabled := state == stateEnabled
	sev := telemetry.SeverityInfo
	switch {
	case diverts && enabled:
		sev = telemetry.SeverityError
	case diverts, enabled && boolVal(r, fieldDeleteMessage):
		sev = telemetry.SeverityWarn
	}

	body := fmt.Sprintf("transport rule %q: state=%s mode=%s", str(r, fieldName), state, str(r, fieldMode))
	if diverts {
		body = fmt.Sprintf("transport rule %q (%s) diverts mail to %s", str(r, fieldName), strings.ToLower(state), targets)
	}
	return telemetry.Event{Name: eventName, Body: body, Severity: sev, Attrs: attrs}
}

// divertTargets reports every recipient the rule sends mail to beyond the
// addressed ones, and whether there are any.
func divertTargets(r map[string]any) (string, bool) {
	var got []string
	for _, f := range divertFields {
		if v, ok := recipientsOf(r, f.wire); ok {
			got = append(got, v)
		}
	}
	return strings.Join(got, ","), len(got) > 0
}

// recipientsOf reads a multi-recipient property, tolerating both shapes the
// admin API uses for multi-valued properties: a JSON array of strings (as
// Conditions/Actions arrive) and a bare string. m7kni has no rule with one of
// these set, so the field NAMES are live-verified and the populated shape is
// not — hence the tolerance rather than a bet on one shape. Reports false for
// null, absent, or an empty value.
func recipientsOf(m map[string]any, key string) (string, bool) {
	switch v := m[key].(type) {
	case string:
		if v == "" {
			return "", false
		}
		return v, true
	case []any:
		out := make([]string, 0, len(v))
		for _, e := range v {
			if s, ok := e.(string); ok && s != "" {
				out = append(out, s)
			}
		}
		if len(out) == 0 {
			return "", false
		}
		return strings.Join(out, ","), true
	default:
		return "", false
	}
}

// classNames renders a #Collection(String) of .NET class names as a
// comma-separated list of short names. Null or absent yields "" (omitted).
func classNames(m map[string]any, key string) string {
	raw, ok := m[key].([]any)
	if !ok {
		return ""
	}
	out := make([]string, 0, len(raw))
	for _, e := range raw {
		if s, ok := e.(string); ok && s != "" {
			out = append(out, shortClassName(s))
		}
	}
	return strings.Join(out, ",")
}

// shortClassName strips the one constant namespace every rule predicate and
// action class sits under. A name outside that namespace passes through
// verbatim, so if Microsoft ever moves them the value degrades to the raw class
// name rather than being mangled.
func shortClassName(s string) string {
	return strings.TrimPrefix(s, rulesNamespace)
}

// str reads a string column, "" when absent or non-string. Reading by exact name
// ignores the "<Name>@data.type" sidecars.
func str(m map[string]any, key string) string {
	s, _ := m[key].(string)
	return s
}

// boolVal reads a boolean column. Booleans on THIS transport are real JSON
// bools, unlike the advanced-hunting API's SByte 0/1 encoding (#249).
func boolVal(m map[string]any, key string) bool {
	b, _ := m[key].(bool)
	return b
}

func init() {
	collectors.RegisterEXO(func(d collectors.EXODeps) collector.SnapshotCollector { return New(d) })
}

var _ collector.SnapshotCollector = (*Collector)(nil)
