// Package inboxrules is the Exchange Online mailbox inbox-rules collector
// (#363): current-state inventory of every mailbox's inbox rules, INCLUDING
// hidden ones, read over the Exchange Online admin API's app-only cmdlet
// transport (internal/exoclient), fanned out one call per mailbox via the
// shared internal/exofanout gate (#355/#363).
//
// # Why this matters
//
// A malicious inbox rule — auto-forward exfiltration, hide-and-delete a
// phishing reply chain, delete security alerts on arrival — is a classic
// post-compromise persistence and exfiltration mechanism, and the rules that
// matter most are exactly the ones an attacker tries to make invisible.
// Get-InboxRule without -IncludeHidden misses them: live-measured 2026-07-28
// against m7kni, a mailbox whose only rule was the system Junk E-mail Rule
// returned 1 rule WITH the flag and 0 WITHOUT it. -IncludeHidden is therefore
// non-optional on every call this collector makes.
//
// # Cost shape — why this is neither HighVolume nor Experimental
//
// This is a 1+N collector: one Get-Mailbox enumeration plus one Get-InboxRule
// call PER MAILBOX (995 ms/mailbox live-measured, #363's package doc on
// internal/exofanout has the full cost table). That is linear in TENANT SIZE,
// not in traffic (HighVolume) and not a Graph beta surface (Experimental) —
// see internal/exofanout's package doc for why this project treats per-mailbox
// fan-out as its own opt-in rather than overloading either flag. Enablement and
// the per-cycle mailbox cap are the composition root's job: this collector
// implements collectors.PerMailboxCollector (PerMailbox() true) so the
// composition root's exo_per_mailbox.enabled gate can find it without a
// hand-kept name list, and never branches on that config itself.
//
// # Both sides of the cardinality boundary, from one fan-out
//
// Every cycle emits, per mailbox, one Get-InboxRule(-IncludeHidden) call
// producing:
//
//   - a bounded GAUGE m365.inbox_rules.rules, counted by (enabled,
//     has_forwarding, deletes) — three booleans, 8 possible buckets, never by
//     mailbox or rule identity (#112);
//   - one LOG twin per rule (m365.inbox_rule) carrying the full per-rule
//     detail the gauge cannot: which mailbox, which rule, what it does.
//
// Plus, once per cycle regardless of mailbox count:
//
//   - m365.inbox_rules.mailboxes_covered / .mailboxes_total — the fan-out
//     coverage pair from internal/exofanout, emitted EVERY cycle so "zero
//     rules" and "the cap left most of the tenant unpolled" stay
//     distinguishable. Partial coverage is acceptable; partial coverage that
//     LOOKS complete is not.
//
// The log-twin population is bounded by rules-per-mailbox, not tenant size —
// and a forwarding rule IS the finding this collector exists to surface, so it
// is emitted for every rule, not gated behind a "found something" condition
// the way m365.exchange_audit_bypass's twin is.
//
// # RuleIdentity is a BigInteger — carried as a STRING, never arithmetic
//
// Live-measured 2026-07-28: RuleIdentity=15394007230974001153, which overflows
// int64 (max 9223372036854775807). Decoding that JSON number into a Go
// interface{}/float64 (the shape a plain json.Unmarshal into map[string]any
// produces) silently rounds it to 15394007230974001152 — a different, still
// plausible-looking id, off by one. This collector never performs that
// round-trip itself: RuleIdentity is read as whatever numeric-ish type the
// source map holds (json.Number when the caller's decoder preserved it,
// float64 otherwise) and rendered with strconv.FormatFloat's fixed-point 'f'
// verb (never the default %v, which would emit scientific notation and lose
// even the corrupted value's trailing digits). Identity embeds the same
// oversized integer (`<guid>\<RuleIdentity>`) and is native-string on the wire,
// so it needs no special handling. See ruleIdentityString.
//
// # ForwardTo is not an email address — emitted honestly, never half-parsed
//
// ForwardTo/ForwardAsAttachmentTo/RedirectTo are arrays whose elements are a
// display name plus a legacyExchangeDN
// (`"Rob Knight" [EX:/o=ExchangeLabs/.../cn=8450ce8c...]`). There is NO SMTP
// address anywhere in a Get-InboxRule record, so "which address does this rule
// forward to" cannot be answered from the rule alone. This collector emits the
// raw array verbatim (AttrForwardTo etc.) and additionally extracts the
// quoted display-name PREFIX into a clearly-named sibling attribute
// (AttrForwardToDisplayNames) — but never synthesizes anything that reads as
// an address, and the package doc says so: a partially-parsed value looks
// complete and would be wrong.
//
// # Unobserved fields — mapped, not watched
//
// RedirectTo, ForwardAsAttachmentTo, DeleteMessage=true, and any genuinely
// hidden NON-system rule are UNOBSERVED on this tenant (#363; only the
// forwarding rule and the system Junk E-mail Rule have been seen live). All
// are mapped — they are documented Get-InboxRule actions — but none is given a
// wirecheck.Enum watch: one observed value is not a value set (CLAUDE.md), and
// this package has observed at most one value for each.
//
// # Severity — Warn means "forwards or redirects", not "is malicious"
//
// Because externality cannot be determined from this cmdlet alone (see
// ForwardTo above), the twin's severity is Warn whenever has_forwarding is
// true and Info otherwise. It does NOT claim the forwarding target is
// external — only that the rule forwards or redirects mail at all, which is
// the fact this cmdlet can actually support.
//
// # Absent fields are never sentinels
//
// Optional booleans (Enabled, SupportedByTask, IsValid, DeleteMessage) are read
// as pointers for the log twin: an absent key omits the attribute rather than
// publishing a fabricated false. The bounded gauge's three boolean buckets
// still need a definite value every cycle, so it treats an absent optional
// boolean as false for BUCKETING purposes only — a decision documented here,
// not a claim that the wire said false.
package inboxrules

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"strconv"
	"time"

	"github.com/rknightion/graph2otel/internal/collector"
	"github.com/rknightion/graph2otel/internal/collectors"
	"github.com/rknightion/graph2otel/internal/exofanout"
	"github.com/rknightion/graph2otel/internal/recordoutcome"
	"github.com/rknightion/graph2otel/internal/semconv"
	"github.com/rknightion/graph2otel/internal/telemetry"
)

const (
	// collectorName is the stable key for config, self-observability and the
	// admin status page.
	collectorName = "m365.inbox_rules"
	// eventName is the OTLP LogRecord EventName each rule twin carries.
	eventName = "m365.inbox_rule"

	// metricRules is the bounded per-cycle inventory gauge, counted by
	// (enabled, has_forwarding, deletes).
	metricRules = "m365.inbox_rules.rules"
	// metricMailboxesCovered / metricMailboxesTotal are the fan-out coverage
	// pair, emitted every cycle regardless of metricRules — see the package
	// doc.
	metricMailboxesCovered = "m365.inbox_rules.mailboxes_covered"
	metricMailboxesTotal   = "m365.inbox_rules.mailboxes_total"

	unitRule    = "{rule}"
	unitMailbox = "{mailbox}"

	// cmdlet is the single per-mailbox Exchange Online cmdlet this collector
	// calls. Mailbox enumeration is internal/exofanout's Get-Mailbox call, not
	// this package's concern.
	cmdlet = "Get-InboxRule"

	// paramMailbox / paramIncludeHidden are this cmdlet's two parameters.
	// IncludeHidden=true is REQUIRED — see the package doc.
	paramMailbox       = "Mailbox"
	paramIncludeHidden = "IncludeHidden"

	// interval: inbox rules change when a user or attacker edits their mailbox
	// rules, an infrequent event relative to poll cadence, and the collector's
	// cost is linear in mailbox count (see internal/exofanout's cost table) —
	// a long interval keeps a large tenant's per-cycle cost bounded without
	// missing a persistence rule for long.
	interval = 6 * time.Hour
)

// Wire field names, read by exact name so any "<Name>@data.type" sidecar is
// ignored.
const (
	fieldDescription           = "Description"
	fieldEnabled               = "Enabled"
	fieldIdentity              = "Identity"
	fieldErrorType             = "ErrorType"
	fieldName                  = "Name"
	fieldPriority              = "Priority"
	fieldRuleIdentity          = "RuleIdentity"
	fieldSupportedByTask       = "SupportedByTask"
	fieldSubjectContainsWords  = "SubjectContainsWords"
	fieldForwardTo             = "ForwardTo"
	fieldForwardAsAttachmentTo = "ForwardAsAttachmentTo"
	fieldRedirectTo            = "RedirectTo"
	fieldDeleteMessage         = "DeleteMessage"
	fieldMailboxOwnerId        = "MailboxOwnerId"
	fieldIsValid               = "IsValid"
	fieldObjectState           = "ObjectState"
)

// Collector reads every mailbox's inbox rules, including hidden ones.
type Collector struct {
	c   collectors.EXOClient
	cap int
}

// New builds the inbox-rules collector. It is ALWAYS constructed — even from a
// completely zero-valued collectors.EXODeps (the composition root builds an
// availability candidate, and probes on its transport-init error path, from a
// zero-valued EXODeps and immediately calls Name() on the result) — so Name,
// DefaultInterval and RequiredPermissions must never dereference c. Enablement
// is the composition root's job via PerMailbox(), not this collector's.
func New(d collectors.EXODeps) *Collector {
	return &Collector{c: d.Client, cap: d.PerMailboxCap}
}

// Name implements collector.Collector.
func (c *Collector) Name() string { return collectorName }

// DefaultInterval implements collector.Collector.
func (c *Collector) DefaultInterval() time.Duration { return interval }

// IngestTransport marks every record as coming from the Exchange Online admin
// API rather than Graph (#141).
func (c *Collector) IngestTransport() telemetry.Transport {
	return telemetry.TransportExchangeOnline
}

// RequiredPermissions is empty: access is the two grants outside the
// Graph-scope vocabulary (Exchange.ManageAsApp + a directory role), the same
// boundary documented on the sibling EXO collectors.
func (c *Collector) RequiredPermissions() []string { return nil }

// PerMailbox implements collectors.PerMailboxCollector: this collector's cost
// is linear in mailbox count (one Get-InboxRule call per mailbox), so the
// composition root's exo_per_mailbox.enabled gate applies to it. The
// collector itself never reads that config — see the package doc.
func (c *Collector) PerMailbox() bool { return true }

// Collect enumerates the tenant's mailboxes (capped per internal/exofanout),
// polls Get-InboxRule -IncludeHidden for each, and emits both sides of the
// cardinality boundary described in the package doc.
func (c *Collector) Collect(ctx context.Context, e telemetry.Emitter, outcomes *recordoutcome.Recorder) error {
	// Stamp the transport HERE: with no ingest engine on this path the
	// Scheduler baseline is TransportGraph.
	e = telemetry.WithTransport(e, telemetry.TransportExchangeOnline)

	if c.c == nil {
		// A zero-valued EXODeps collector (see New's doc) is never actually
		// polled by the composition root, but Collect stays a safe no-op
		// rather than trusting that invariant to hold forever.
		return nil
	}

	res, err := exofanout.Enumerate(ctx, c.c, c.cap)
	if err != nil {
		outcomes.Cause(recordoutcome.CauseSourceError)
		return fmt.Errorf("enumerate mailboxes: %w", err)
	}

	// Emitted EVERY cycle, independent of what follows: this is the "did the
	// poll actually run, and how much of the tenant did it see" signal — see
	// the package doc.
	e.GaugeSnapshot(metricMailboxesCovered, unitMailbox,
		"Mailboxes this cycle actually polled for inbox rules. Compare against m365.inbox_rules.mailboxes_total: covered < total means the exo_per_mailbox cap left part of the tenant unpolled this cycle, not that the tenant is small.",
		[]telemetry.GaugePoint{{Value: float64(res.Covered)}})
	e.GaugeSnapshot(metricMailboxesTotal, unitMailbox,
		"Total mailboxes this tenant has, per Get-Mailbox. Always emitted alongside mailboxes_covered so partial coverage is never indistinguishable from a genuinely small tenant.",
		[]telemetry.GaugePoint{{Value: float64(res.Total)}})

	type bucket struct{ enabled, forwarding, deletes bool }
	counts := map[bucket]int64{}

	var errs []error
	for _, mb := range res.Mailboxes {
		rows, err := c.c.Invoke(ctx, cmdlet, map[string]any{
			paramMailbox:       mb.PrimarySmtpAddress,
			paramIncludeHidden: true,
		})
		if err != nil {
			outcomes.Cause(recordoutcome.CauseSourceError)
			errs = append(errs, fmt.Errorf("%s(%s): %w", cmdlet, mb.PrimarySmtpAddress, err))
			continue
		}
		outcomes.Add(recordoutcome.OutcomeFetched, uint64(len(rows)))

		for _, r := range rows {
			enabled := boolVal(r, fieldEnabled)
			forwardTo := strs(r, fieldForwardTo)
			forwardAsAttachmentTo := strs(r, fieldForwardAsAttachmentTo)
			redirectTo := strs(r, fieldRedirectTo)
			forwarding := len(forwardTo) > 0 || len(forwardAsAttachmentTo) > 0 || len(redirectTo) > 0
			deletes := boolVal(r, fieldDeleteMessage)

			counts[bucket{enabled: enabled, forwarding: forwarding, deletes: deletes}]++

			e.LogEvent(ruleTwin(mb.PrimarySmtpAddress, r, forwarding))
			outcomes.Add(recordoutcome.OutcomeMapped, 1)
			outcomes.Add(recordoutcome.OutcomeEmitted, 1)
		}
	}

	points := make([]telemetry.GaugePoint, 0, len(counts))
	for k, v := range counts {
		points = append(points, telemetry.GaugePoint{
			Value: float64(v),
			Attrs: telemetry.Attrs{
				semconv.AttrEnabled:       strconv.FormatBool(k.enabled),
				semconv.AttrHasForwarding: strconv.FormatBool(k.forwarding),
				semconv.AttrDeleteMessage: strconv.FormatBool(k.deletes),
			},
		})
	}
	e.GaugeSnapshot(metricRules, unitRule,
		"Inbox rules across every polled mailbox (Get-InboxRule -IncludeHidden), counted by enabled, has_forwarding (any of ForwardTo/ForwardAsAttachmentTo/RedirectTo non-empty) and deletes (DeleteMessage=true). Never labeled by mailbox or rule identity (#112) — see the m365.inbox_rule log twin for per-rule detail.",
		points)

	return errors.Join(errs...)
}

// forwardToNamePattern extracts the quoted display-name PREFIX from a
// ForwardTo/ForwardAsAttachmentTo/RedirectTo element
// (`"Rob Knight" [EX:/o=...]`). It never attempts to parse the
// legacyExchangeDN suffix into anything address-shaped — see the package doc.
var forwardToNamePattern = regexp.MustCompile(`^"([^"]*)"`)

// extractDisplayNames returns the quoted display-name prefix of every element
// that has one, skipping (never guessing at) elements that do not match.
func extractDisplayNames(vals []string) []string {
	var out []string
	for _, v := range vals {
		if m := forwardToNamePattern.FindStringSubmatch(v); m != nil {
			out = append(out, m[1])
		}
	}
	return out
}

// ruleTwin renders one inbox rule as a log record. mailbox is the
// PrimarySmtpAddress this rule was fetched under (Get-InboxRule's -Identity),
// which the rule object itself does not carry.
func ruleTwin(mailbox string, r map[string]any, forwarding bool) telemetry.Event {
	name := str(r, fieldName)
	ruleID := ruleIdentityString(r[fieldRuleIdentity])
	forwardTo := strs(r, fieldForwardTo)
	forwardAsAttachmentTo := strs(r, fieldForwardAsAttachmentTo)
	redirectTo := strs(r, fieldRedirectTo)

	attrs := telemetry.Attrs{}
	telemetry.SetStr(attrs, semconv.AttrPrimarySmtpAddress, mailbox)
	telemetry.SetStr(attrs, semconv.AttrName, name)
	telemetry.SetStr(attrs, semconv.AttrDescription, str(r, fieldDescription))
	telemetry.SetStr(attrs, semconv.AttrIdentity, str(r, fieldIdentity))
	telemetry.SetStr(attrs, semconv.AttrRuleIdentity, ruleID)
	telemetry.SetStr(attrs, semconv.AttrErrorType, str(r, fieldErrorType))
	telemetry.SetStr(attrs, semconv.AttrMailboxOwnerId, str(r, fieldMailboxOwnerId))
	telemetry.SetStr(attrs, semconv.AttrObjectState, str(r, fieldObjectState))
	telemetry.SetNum(attrs, semconv.AttrPriority, r, fieldPriority)
	telemetry.SetStrs(attrs, semconv.AttrSubjectContainsWords, strs(r, fieldSubjectContainsWords))
	telemetry.SetStrs(attrs, semconv.AttrForwardTo, forwardTo)
	telemetry.SetStrs(attrs, semconv.AttrForwardToDisplayNames, extractDisplayNames(forwardTo))
	telemetry.SetStrs(attrs, semconv.AttrForwardAsAttachmentTo, forwardAsAttachmentTo)
	telemetry.SetStrs(attrs, semconv.AttrRedirectTo, redirectTo)

	// Optional booleans: pointer-read, attribute omitted (never fabricated
	// false) when the wire key was absent — see the package doc.
	if v, ok := boolPtr(r, fieldEnabled); ok {
		attrs[semconv.AttrEnabled] = strconv.FormatBool(*v)
	}
	if v, ok := boolPtr(r, fieldSupportedByTask); ok {
		attrs[semconv.AttrSupportedByTask] = strconv.FormatBool(*v)
	}
	if v, ok := boolPtr(r, fieldIsValid); ok {
		attrs[semconv.AttrIsValid] = strconv.FormatBool(*v)
	}
	if v, ok := boolPtr(r, fieldDeleteMessage); ok {
		attrs[semconv.AttrDeleteMessage] = strconv.FormatBool(*v)
	}

	sev := telemetry.SeverityInfo
	if forwarding {
		// Warn means "forwards or redirects mail" — NOT "is malicious" and NOT
		// "forwards externally": externality cannot be determined from this
		// cmdlet alone. See the package doc.
		sev = telemetry.SeverityWarn
	}

	return telemetry.Event{
		Name:     eventName,
		Body:     fmt.Sprintf("inbox rule %q on %s (id=%s): forwarding=%v", name, mailbox, ruleID, forwarding),
		Severity: sev,
		Attrs:    attrs,
	}
}

// ruleIdentityString renders RuleIdentity as a decimal string without ever
// round-tripping it through an int64 (it overflows one) or through %v's
// default float formatting (which would emit scientific notation). It is an
// opaque identity, never arithmetic — see the package doc.
//
// v may be json.Number (a caller whose decoder preserved full precision),
// float64 (the shape a plain json.Unmarshal into map[string]any produces —
// already silently rounded by the time this function sees it, which this
// function does not and cannot repair), or string. Any other shape, including
// absence, yields "".
func ruleIdentityString(v any) string {
	switch n := v.(type) {
	case json.Number:
		return string(n)
	case float64:
		// Precision 0, NOT -1: RuleIdentity is always integer-valued, and -1
		// (shortest round-tripping representation) can print a DIFFERENT
		// decimal that still parses back to the same float64 (observed:
		// 15394007230974001153 -> float64 -> "15394007230974001000" with -1,
		// vs the float64's actual exact value "15394007230974001152" with 0).
		// Precision 0 prints the float64's real value, which is what the
		// package doc's documented off-by-one corruption refers to.
		return strconv.FormatFloat(n, 'f', 0, 64)
	case string:
		return n
	default:
		return ""
	}
}

// boolPtr reads a boolean column, returning (value, true) when present as a
// JSON bool and (nil, false) when the key is absent or non-bool.
func boolPtr(m map[string]any, key string) (*bool, bool) {
	v, present := m[key]
	if !present {
		return nil, false
	}
	b, ok := v.(bool)
	if !ok {
		return nil, false
	}
	return &b, true
}

// boolVal reads a boolean column, false when absent or non-bool. Used ONLY
// for the bounded gauge's bucket keys, which need a definite value every
// cycle — see the package doc. The log twin uses boolPtr instead, so an
// absent key is never asserted false there.
func boolVal(m map[string]any, key string) bool {
	b, _ := m[key].(bool)
	return b
}

// str reads a string column, "" when absent or non-string.
func str(m map[string]any, key string) string {
	s, _ := m[key].(string)
	return s
}

// strs reads a JSON array-of-string column (decoded as []any by
// encoding/json), skipping any non-string element rather than failing the
// whole row.
func strs(m map[string]any, key string) []string {
	raw, ok := m[key].([]any)
	if !ok {
		return nil
	}
	out := make([]string, 0, len(raw))
	for _, v := range raw {
		if s, ok := v.(string); ok {
			out = append(out, s)
		}
	}
	return out
}

func init() {
	collectors.RegisterEXO(func(d collectors.EXODeps) collector.SnapshotCollector { return New(d) })
}

var (
	_ collector.SnapshotCollector    = (*Collector)(nil)
	_ collectors.PerMailboxCollector = (*Collector)(nil)
)
