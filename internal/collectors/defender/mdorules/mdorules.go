// Package mdorules is the Defender for Office 365 / EOP protection-policy RULE
// layer (#354), read over the same Exchange Online admin API cmdlet transport
// as defender.mdo_policies (internal/exoclient, collectors.EXODeps).
//
// # A policy says WHAT; a rule says WHO and IN WHAT ORDER
//
// defender.mdo_policies already exports what each anti-spam/anti-malware/
// anti-phish/Safe Links/Safe Attachments/ATP/Teams-protection policy DOES. It
// has no view of who the policy actually reaches, what precedence it applies
// at relative to the tenant's other rules, or whether a policy is wired to
// anything at all. This package fetches the ten rule cmdlets that carry that
// half, plus the seven policy cmdlets defender.mdo_policies also reads, and
// joins the two: a rule twin naming which policies it turns on and the
// recipients it scopes to, and an "unreferenced policy" twin for a policy no
// enabled rule ever applies — a configured-but-inert control.
//
// # Ten cmdlets, one wire shape family
//
// Every rule family shares one flat record shape (State, Priority, Comments,
// Description, RuleVersion, the six recipient-condition fields, Conditions,
// Exceptions, Identity, DistinguishedName, Guid, ImmutableId, OrganizationId,
// Name, IsValid, WhenChanged), verified across the three non-empty live m7kni
// captures (Get-ATPProtectionPolicyRule, Get-EOPProtectionPolicyRule,
// Get-ATPBuiltInProtectionRule; 2026-07-28, graph2otel-poller, #354). The only
// thing that varies by family is WHICH policy-reference field(s) it carries:
// atp_protection/atp_built_in name SafeAttachmentPolicy + SafeLinksPolicy,
// eop_protection names all three of HostedContentFilterPolicy/AntiPhishPolicy/
// MalwareFilterPolicy, and the seven single-purpose families
// (hosted_content, malware, anti_phish, safe_links, safe_attachment,
// teams_protection, hosted_outbound_spam) each name exactly one. The seven
// single-purpose cmdlets returned ZERO rows on m7kni (the tenant uses preset
// security policies, which route through atp_protection/eop_protection
// instead), so their policy-reference FIELD NAME is doc-derived, not
// wire-verified. ruleFamily.policyFields lists a field per family and
// referencedPolicyNames attempts every one against every record — a wrong
// guess for an unverified family costs that family's rows one missing
// referenced-policy name, never a dropped rule, which is why this shape is
// safe to ship ahead of a live sample.
//
// # An empty result is authorized-and-empty, not denied
//
// All seventeen read-only Invokes (ten rule + seven policy cmdlets) returned
// HTTP 200 under the poller's EXISTING grants (Exchange.ManageAsApp + Security
// Reader) — no new scope. An Exchange cmdlet the app-only session is not
// authorized for is deleted from that session and fails
// CommandNotFoundException before touching a target; a 200 with an empty
// `value` array is the tenant genuinely having no rows, which is the case for
// seven of the ten rule cmdlets on m7kni. Never conflate the two: this
// collector's empty-result handling (TestEmptyFamilyIsNotAnError) treats it as
// the healthy steady state, not a fetch failure.
//
// # Absent is not false, NULL is not empty, zero is not absent
//
// Three separate absence traps, each guarded by its own test:
//
//   - A boolean/string/numeric column not present on the wire is OMITTED from
//     the twin, never stamped false/""/0 (str/SetNum/SetBool already do this).
//   - The six recipient-condition fields are NULL when the axis is unscoped,
//     and an unscoped axis means the rule reaches MORE traffic, not less — the
//     opposite of an empty list, which would read as "applies to nobody".
//     stringList treats a JSON null (fails the []any assertion) exactly the
//     same as an empty array: no attribute is set, so the mapper cannot
//     manufacture a false "applies to nobody" out of either shape.
//   - Priority is a real, load-bearing 0 for the highest-precedence rule
//     (lower number wins in Exchange's rule model). SetNum's presence check
//     (`f, ok := m[key].(float64)`) is independent of the value, so Priority=0
//     is emitted, never treated as "not set".
//
// # Recipient scoping is TWIN-ONLY, always (#112)
//
// SentTo, SentToMemberOf, RecipientDomainIs and the three ExceptIf* fields
// carry mailbox addresses, group names and domains — per-entity data that
// grows with the tenant, never metric labels. The bounded gauge instead counts
// rules PER CONDITION KIND, under AttrCondition, whose six values
// (sent_to, sent_to_member_of, recipient_domain_is, except_sent_to,
// except_sent_to_member_of, except_recipient_domain_is) are a closed set fixed
// by Exchange's rule model. signalgate_test.go enforces this mechanically.
//
// # The join, and why it costs two extra fetches rather than a shared cache
//
// metricUnrefPolicy answers "is this policy referenced by any ENABLED rule",
// which needs BOTH the rule side (this package) and the policy side
// (defender.mdo_policies) in the same Collect call. Sharing state between two
// independently-scheduled collectors would couple their intervals and their
// failure modes; re-reading the seven Get-*Policy cmdlets here instead costs
// seven cheap read-only round trips per hour and keeps this collector
// independently correct and independently testable. Seventeen Invokes per
// cycle in total, same hourly cadence defender.mdo_policies uses for the same
// reason (admin-timescale configuration, not a stream).
//
// Only an ENABLED rule counts as "referencing" a policy — a disabled rule is
// not currently applying it, so a policy reached only by disabled rules is
// still reported unreferenced. Matching is case-insensitive
// (strings.ToLower), because Exchange identities and display names are
// case-insensitive on the wire; this is exercised directly by
// TestUnreferencedPolicyMatchIsCaseInsensitive.
//
// A rule referencing a policy that no longer exists still gets its rule twin
// (referencedPolicyNames only reads what the rule record says, it never
// validates against the policy fetch), and a policy no rule references still
// gets its unreferenced-policy twin — #114's "not a metric label means log
// twin, never dropped" applies to BOTH directions of this join, not just the
// count.
//
// If ANY of the seven policy fetches fails, metricUnrefPolicy and
// defender.mdo_unreferenced_policy are suppressed ENTIRELY for that cycle —
// not partially computed from whatever succeeded. A partial answer here is not
// a smaller true answer, it is a false "no orphans found" built from an
// incomplete policy universe, which is worse than reporting nothing. The rule
// twins still emit regardless: they do not depend on the policy fetch at all.
//
// # metricUnrefPolicy is deliberately NOT under defender.mdo.policies.*
//
// defender.mdo_policies already owns the defender.mdo.policies metric name and
// its label set (policy_type only). Naming this collector's gauge
// defender.mdo.policies.unreferenced would put two collectors emitting under
// one metric-name prefix with two different label sets feeding the same
// series family — the kind of split identity that makes a query return
// whichever collector happened to run last. defender.mdo.unreferenced_policies
// is its own name precisely so it is its own series, owned by one collector.
//
// # Wirecheck: nothing declared, on purpose
//
// State has been observed at exactly one value ("Enabled") across the three
// live samples, and one observed value is not a value set (#234) — there is no
// evidence for what else Exchange might send. rule_family and condition are
// graph2otel-derived names for a cmdlet and a wire FIELD respectively, not
// Graph-supplied enum values, so neither is a wirecheck concern at all. No
// internal/wirecheck declaration exists in this package for exactly these
// reasons.
//
// # A STATE feed, not an event stream
//
// A rule is re-emitted every cycle for as long as it exists, so
// defender.mdo_rule and defender.mdo_unreferenced_policy both leave
// Event.Timestamp at zero (poll time) rather than stamping WhenChanged as the
// event time — the same reasoning defender.mdo_policies documents: stamping
// the wire's last-edit time would pile every repeat onto that one instant.
// WhenChanged is still carried, as an ATTRIBUTE.
package mdorules

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/rknightion/graph2otel/internal/collector"
	"github.com/rknightion/graph2otel/internal/collectors"
	"github.com/rknightion/graph2otel/internal/recordoutcome"
	"github.com/rknightion/graph2otel/internal/semconv"
	"github.com/rknightion/graph2otel/internal/telemetry"
)

const (
	// collectorName is the stable key for config, self-observability and the
	// admin status page.
	collectorName = "defender.mdo_rules"
	// eventRule is the OTLP LogRecord EventName every per-rule twin carries.
	eventRule = "defender.mdo_rule"
	// eventUnrefPolicy is the OTLP LogRecord EventName every unreferenced-policy
	// twin carries.
	eventUnrefPolicy = "defender.mdo_unreferenced_policy"
	// interval: rule configuration changes on the timescale of admin action,
	// same reasoning and same cadence as defender.mdo_policies.
	interval = time.Hour

	// metricRules counts rules by rule_family and state.
	metricRules = "defender.mdo.rules"
	// metricConditions counts rules by rule_family and which recipient
	// condition they carry.
	metricConditions = "defender.mdo.rules.conditions"
	// metricUnscoped counts, per rule_family, ENABLED rules with no recipient
	// condition on any of the three include axes — rules that apply org-wide.
	metricUnscoped = "defender.mdo.rules.unscoped"
	// metricUnrefPolicy counts, per policy_type, policies no enabled rule
	// references. Deliberately NOT under the defender.mdo.policies.* prefix —
	// see the package doc.
	metricUnrefPolicy = "defender.mdo.unreferenced_policies"

	// unitRule and unitPolicy are annotation count units; annotation units are
	// self-describing and need no internal/semconv/additive.go entry.
	unitRule   = "{rule}"
	unitPolicy = "{policy}"

	// stateEnabled and stateDisabled are the two seeded, recognized values of
	// the state label.
	stateEnabled  = "Enabled"
	stateDisabled = "Disabled"
	// stateUnknown is the bucket for a rule record whose State is empty or any
	// value other than stateEnabled/stateDisabled. An empty string is the
	// least debuggable value a metric label can carry, so a missing/unexpected
	// State is named rather than left blank — see ruleStateLabel.
	stateUnknown = "unknown"
)

// ruleFamily binds one rule cmdlet to its rule_family label and the wire
// field(s) that name the policy or policies it applies. Order is the fetch
// order; a failure in one cmdlet is aggregated and does not stop the rest.
type ruleFamily struct {
	name         string
	cmdlet       string
	policyFields []string
}

// ruleFamilies is the full set of ten MDO/EOP rule shapes this collector
// reads (#354). Only atp_protection, eop_protection and atp_built_in have a
// live-verified policyFields set (m7kni, 2026-07-28) — the remaining seven
// single-purpose families returned zero rows, so their single policy field
// name is taken from Microsoft's documented cmdlet parameters, not the wire.
var ruleFamilies = []ruleFamily{
	{name: "atp_protection", cmdlet: "Get-ATPProtectionPolicyRule", policyFields: []string{"SafeAttachmentPolicy", "SafeLinksPolicy"}},
	{name: "eop_protection", cmdlet: "Get-EOPProtectionPolicyRule", policyFields: []string{"HostedContentFilterPolicy", "AntiPhishPolicy", "MalwareFilterPolicy"}},
	{name: "atp_built_in", cmdlet: "Get-ATPBuiltInProtectionRule", policyFields: []string{"SafeAttachmentPolicy", "SafeLinksPolicy"}},
	{name: "hosted_content", cmdlet: "Get-HostedContentFilterRule", policyFields: []string{"HostedContentFilterPolicy"}},
	{name: "malware", cmdlet: "Get-MalwareFilterRule", policyFields: []string{"MalwareFilterPolicy"}},
	{name: "anti_phish", cmdlet: "Get-AntiPhishRule", policyFields: []string{"AntiPhishPolicy"}},
	{name: "safe_links", cmdlet: "Get-SafeLinksRule", policyFields: []string{"SafeLinksPolicy"}},
	{name: "safe_attachment", cmdlet: "Get-SafeAttachmentRule", policyFields: []string{"SafeAttachmentPolicy"}},
	{name: "teams_protection", cmdlet: "Get-TeamsProtectionPolicyRule", policyFields: []string{"TeamsProtectionPolicy"}},
	{name: "hosted_outbound_spam", cmdlet: "Get-HostedOutboundSpamFilterRule", policyFields: []string{"HostedOutboundSpamFilterPolicy"}},
}

// policyFetch binds one of the seven Get-*Policy cmdlets defender.mdo_policies
// also reads to the policy_type label this package reports orphans under.
// Kept as its own list (not imported from mdopolicies) so this collector's
// correctness does not depend on that package's internals — see the package
// doc on why the fetch is duplicated rather than shared.
type policyFetch struct {
	policyType string
	cmdlet     string
}

var policyFetches = []policyFetch{
	{policyType: "hosted_content", cmdlet: "Get-HostedContentFilterPolicy"},
	{policyType: "malware", cmdlet: "Get-MalwareFilterPolicy"},
	{policyType: "anti_phish", cmdlet: "Get-AntiPhishPolicy"},
	{policyType: "safe_links", cmdlet: "Get-SafeLinksPolicy"},
	{policyType: "safe_attachments", cmdlet: "Get-SafeAttachmentPolicy"},
	{policyType: "atp_o365", cmdlet: "Get-AtpPolicyForO365"},
	{policyType: "teams_protection", cmdlet: "Get-TeamsProtectionPolicy"},
}

// condition binds one of the six recipient-scoping wire fields to the bounded
// metric label value it counts under (metricLabel) and the twin attribute key
// it is carried under (attrKey, always twin-only per #112).
type condition struct {
	metricLabel string
	attrKey     string
	field       string
}

// conditions is the full closed set of recipient-scoping axes an MDO/EOP rule
// can carry, fixed by Exchange's rule model.
var conditions = []condition{
	{metricLabel: "sent_to", attrKey: semconv.AttrSentTo, field: "SentTo"},
	{metricLabel: "sent_to_member_of", attrKey: semconv.AttrSentToMemberOf, field: "SentToMemberOf"},
	{metricLabel: "recipient_domain_is", attrKey: semconv.AttrRecipientDomainIs, field: "RecipientDomainIs"},
	{metricLabel: "except_sent_to", attrKey: semconv.AttrExceptIfSentTo, field: "ExceptIfSentTo"},
	{metricLabel: "except_sent_to_member_of", attrKey: semconv.AttrExceptIfSentToMemberOf, field: "ExceptIfSentToMemberOf"},
	{metricLabel: "except_recipient_domain_is", attrKey: semconv.AttrExceptIfRecipientDomainIs, field: "ExceptIfRecipientDomainIs"},
}

// unscopedFields are the three INCLUDE axes that decide whether a rule is
// scoped to specific recipients at all. The three EXCEPT axes narrow an
// already-scoped or already-unscoped rule and do not participate in this
// test — an org-wide rule with an exclusion is still org-wide for everyone
// else.
var unscopedFields = []string{"SentTo", "SentToMemberOf", "RecipientDomainIs"}

// Collector reads the Defender for Office 365 / EOP rule layer plus the seven
// policy cmdlets needed to detect an unreferenced policy, over the Exchange
// Online admin API.
type Collector struct {
	c      collectors.EXOClient
	logger *slog.Logger
}

// New builds the MDO rule collector. A nil logger falls back to slog.Default().
func New(d collectors.EXODeps) *Collector {
	logger := d.Logger
	if logger == nil {
		logger = slog.Default()
	}
	return &Collector{c: d.Client, logger: logger}
}

// Name implements collector.Collector.
func (c *Collector) Name() string { return collectorName }

// DefaultInterval implements collector.Collector.
func (c *Collector) DefaultInterval() time.Duration { return interval }

// IngestTransport marks every record this collector emits as having come from
// the Exchange Online admin API rather than Graph (#141). Stamped here
// because there is no ingest engine on this path, the same position
// defender.mdo_policies is in.
func (c *Collector) IngestTransport() telemetry.Transport {
	return telemetry.TransportExchangeOnline
}

// RequiredPermissions is empty: this collector needs no GRAPH scope. Access is
// the same two grants defender.mdo_policies needs — Exchange.ManageAsApp
// (authentication) and the Security Reader directory role (authorization),
// both read-only and both required (live-measured 2026-07-23 on the sibling
// collector: 401 -> 403 -> 200).
func (c *Collector) RequiredPermissions() []string { return nil }

// Collect fetches all ten rule families plus the seven policy cmdlets and
// emits the bounded gauges, the per-rule twins, and the unreferenced-policy
// twins.
//
// Every one of the seventeen cmdlets degrades independently: a failure is
// logged, aggregated into the returned error, and does not stop the rest —
// the same resilience shape defender.mdo_policies uses. A rule-cmdlet failure
// only costs that family's rows. Unlike a genuinely empty family (which stays
// at its seeded zero), a FAILED family's seeded entries are deleted from
// metricRules and metricUnscoped entirely, so it emits NO point at all for
// this cycle — the same rule m365.collaboration_activity states outright
// (#240): "a failed report contributes NOTHING rather than zero, because zero
// would misreport 'unavailable' as 'measured empty'". The failure itself
// surfaces through the returned error and the outcome recorder's
// CauseSourceError, never as a confident zero on the metric. A policy-cmdlet
// failure suppresses metricUnrefPolicy and its twins entirely for the cycle —
// see the package doc.
func (c *Collector) Collect(ctx context.Context, e telemetry.Emitter, outcomes *recordoutcome.Recorder) error {
	// Stamp the transport HERE: there is no ingest engine on this path and the
	// Scheduler baseline is telemetry.TransportGraph.
	e = telemetry.WithTransport(e, telemetry.TransportExchangeOnline)

	stateCounts := map[[2]string]float64{}
	conditionCounts := map[[2]string]float64{}
	unscopedCounts := map[string]float64{}
	for _, rf := range ruleFamilies {
		stateCounts[[2]string{rf.name, stateEnabled}] = 0
		stateCounts[[2]string{rf.name, stateDisabled}] = 0
		unscopedCounts[rf.name] = 0
	}

	// referencedPolicies holds every policy name (lower-cased) referenced by
	// at least one ENABLED rule, across every family.
	referencedPolicies := map[string]bool{}

	var errs []error

	for _, rf := range ruleFamilies {
		recs, err := c.c.Invoke(ctx, rf.cmdlet, nil)
		if err != nil {
			outcomes.Cause(recordoutcome.CauseSourceError)
			c.logger.Warn("mdo rule fetch failed",
				"collector", collectorName, "cmdlet", rf.cmdlet, "error", err)
			errs = append(errs, fmt.Errorf("%s: %w", rf.cmdlet, err))
			// A failed fetch gets NO series, not a confident zero — delete the
			// seeded entries rather than leaving them at 0. See the Collect doc
			// comment and #240.
			delete(stateCounts, [2]string{rf.name, stateEnabled})
			delete(stateCounts, [2]string{rf.name, stateDisabled})
			delete(unscopedCounts, rf.name)
			continue
		}
		outcomes.Add(recordoutcome.OutcomeFetched, uint64(len(recs)))
		for _, r := range recs {
			stateCounts[[2]string{rf.name, ruleStateLabel(r)}]++

			// enabled is judged against the RAW wire value (case-insensitively),
			// never the bucketed metric label — ruleStateLabel already collapsed
			// anything unrecognized to "unknown", and re-comparing that against
			// stateEnabled would wrongly treat a real-but-differently-cased
			// "Enabled" variant as disabled.
			enabled := strings.EqualFold(str(r, "State"), stateEnabled)
			refs := referencedPolicyNames(rf, r)
			if enabled {
				for _, name := range refs {
					referencedPolicies[strings.ToLower(name)] = true
				}
			}

			for _, cond := range conditions {
				if _, ok := stringList(r, cond.field); ok {
					conditionCounts[[2]string{rf.name, cond.metricLabel}]++
				}
			}

			if enabled && isUnscoped(r) {
				unscopedCounts[rf.name]++
			}

			e.LogEvent(ruleTwin(rf.name, refs, r))
			outcomes.Add(recordoutcome.OutcomeMapped, 1)
			outcomes.Add(recordoutcome.OutcomeEmitted, 1)
		}
	}

	// The policy side of the join. Fetched fresh here rather than shared with
	// defender.mdo_policies — see the package doc.
	policiesByType := map[string][]map[string]any{}
	policyFetchFailed := false
	for _, pf := range policyFetches {
		recs, err := c.c.Invoke(ctx, pf.cmdlet, nil)
		if err != nil {
			outcomes.Cause(recordoutcome.CauseSourceError)
			c.logger.Warn("mdo policy fetch failed (for unreferenced-policy detection)",
				"collector", collectorName, "cmdlet", pf.cmdlet, "error", err)
			errs = append(errs, fmt.Errorf("%s: %w", pf.cmdlet, err))
			policyFetchFailed = true
			continue
		}
		outcomes.Add(recordoutcome.OutcomeFetched, uint64(len(recs)))
		policiesByType[pf.policyType] = recs
	}

	if !policyFetchFailed {
		unrefCounts := map[string]float64{}
		for _, pf := range policyFetches {
			unrefCounts[pf.policyType] = 0
			for _, r := range policiesByType[pf.policyType] {
				name := str(r, "Name")
				if name == "" || referencedPolicies[strings.ToLower(name)] {
					outcomes.Add(recordoutcome.OutcomeFiltered, 1)
					continue
				}
				unrefCounts[pf.policyType]++
				e.LogEvent(unrefPolicyTwin(pf.policyType, name))
				outcomes.Add(recordoutcome.OutcomeMapped, 1)
				outcomes.Add(recordoutcome.OutcomeEmitted, 1)
			}
		}

		unrefPoints := make([]telemetry.GaugePoint, 0, len(unrefCounts))
		for policyType, n := range unrefCounts {
			unrefPoints = append(unrefPoints, telemetry.GaugePoint{
				Value: n,
				Attrs: telemetry.Attrs{semconv.AttrPolicyType: policyType},
			})
		}
		e.GaugeSnapshot(metricUnrefPolicy, unitPolicy,
			"Microsoft Defender for Office 365 / EOP policies not referenced by any ENABLED rule, by policy type — a configured control nothing currently applies. Suppressed entirely (no points emitted) for a cycle where any of the seven policy fetches failed, rather than reporting a false zero.",
			unrefPoints)
	}

	statePoints := make([]telemetry.GaugePoint, 0, len(stateCounts))
	for k, v := range stateCounts {
		statePoints = append(statePoints, telemetry.GaugePoint{
			Value: v,
			Attrs: telemetry.Attrs{semconv.AttrRuleFamily: k[0], semconv.AttrState: k[1]},
		})
	}
	e.GaugeSnapshot(metricRules, unitRule,
		"Microsoft Defender for Office 365 / EOP protection rules, by rule family and state. Every (rule_family, state) pair is seeded to 0 for a family that was successfully read, so a rule appearing where none existed is a change from 0 rather than a series materializing from nothing. A family whose fetch FAILED this cycle emits no point at all — a failed fetch is a gap, not a measured zero.",
		statePoints)

	conditionPoints := make([]telemetry.GaugePoint, 0, len(conditionCounts))
	for k, v := range conditionCounts {
		conditionPoints = append(conditionPoints, telemetry.GaugePoint{
			Value: v,
			Attrs: telemetry.Attrs{semconv.AttrRuleFamily: k[0], semconv.AttrCondition: k[1]},
		})
	}
	e.GaugeSnapshot(metricConditions, unitRule,
		"MDO/EOP rules by rule family and which recipient condition they carry (sent_to, sent_to_member_of, recipient_domain_is, except_sent_to, except_sent_to_member_of, except_recipient_domain_is). The recipient VALUES are twin-only (#112); this counts only which condition KIND is present.",
		conditionPoints)

	unscopedPoints := make([]telemetry.GaugePoint, 0, len(unscopedCounts))
	for family, n := range unscopedCounts {
		unscopedPoints = append(unscopedPoints, telemetry.GaugePoint{
			Value: n,
			Attrs: telemetry.Attrs{semconv.AttrRuleFamily: family},
		})
	}
	e.GaugeSnapshot(metricUnscoped, unitRule,
		"ENABLED MDO/EOP rules per rule family with no recipient condition on any include axis (SentTo, SentToMemberOf, RecipientDomainIs) — rules that apply org-wide. Every successfully-read rule_family is seeded to 0; a family whose fetch failed this cycle emits no point.",
		unscopedPoints)

	return errors.Join(errs...)
}

// referencedPolicyNames reads every policy-reference field this rule's family
// carries and returns the non-empty ones, in the family's declared field
// order. A wrong or unverified field name for a single-purpose family simply
// contributes nothing here — it never affects whether the rule itself is
// emitted.
func referencedPolicyNames(rf ruleFamily, r map[string]any) []string {
	var out []string
	for _, field := range rf.policyFields {
		if name := str(r, field); name != "" {
			out = append(out, name)
		}
	}
	return out
}

// isUnscoped reports whether r carries no recipient condition on any of the
// three INCLUDE axes — SentTo, SentToMemberOf, RecipientDomainIs all
// absent/null/empty means the rule applies org-wide.
func isUnscoped(r map[string]any) bool {
	for _, field := range unscopedFields {
		if _, ok := stringList(r, field); ok {
			return false
		}
	}
	return true
}

// ruleTwin renders one rule as an OTLP log record. Timestamp is left zero
// (poll time) — see the package doc on why a state feed must not stamp its
// source time.
//
// Severity is Warn for any rule whose State is not Enabled: a configured rule
// that is not currently applying is worth an operator's attention, the same
// "one toggle from live" reasoning m365.exchange_connectors and
// m365.exchange_transport_rules apply to a disabled rule. An ENABLED unscoped
// rule stays Info — a preset security policy that reaches the whole tenant is
// the RECOMMENDED configuration, not a finding; only a disabled state escalates
// here, never the scope itself.
func ruleTwin(family string, refs []string, r map[string]any) telemetry.Event {
	state := str(r, "State")
	name := str(r, "Name")

	attrs := telemetry.Attrs{}
	telemetry.SetStr(attrs, semconv.AttrRuleFamily, family)
	telemetry.SetStr(attrs, semconv.AttrRuleName, name)
	telemetry.SetStr(attrs, semconv.AttrRuleIdentity, str(r, "Identity"))
	telemetry.SetStr(attrs, semconv.AttrGuid, str(r, "Guid"))
	telemetry.SetStr(attrs, semconv.AttrState, state)
	telemetry.SetNum(attrs, semconv.AttrPriority, r, "Priority")
	telemetry.SetStr(attrs, semconv.AttrRuleVersion, str(r, "RuleVersion"))
	if b, ok := r["IsValid"].(bool); ok {
		telemetry.SetBool(attrs, semconv.AttrIsValid, b)
	}
	telemetry.SetStr(attrs, semconv.AttrWhenChanged, str(r, "WhenChanged"))
	telemetry.SetStr(attrs, semconv.AttrDescription, str(r, "Description"))
	telemetry.SetStrs(attrs, semconv.AttrReferencedPolicies, refs)
	// policy_name carries the single referenced policy's name when the family
	// names exactly one — eop_protection/atp_protection/atp_built_in reference
	// two or three policies at once, so the single-policy key would be
	// ambiguous for them and is only set for the single-purpose families.
	if len(refs) == 1 {
		telemetry.SetStr(attrs, semconv.AttrPolicyName, refs[0])
	}
	for _, cond := range conditions {
		if vals, ok := stringList(r, cond.field); ok {
			telemetry.SetStrs(attrs, cond.attrKey, vals)
		}
	}

	sev := telemetry.SeverityInfo
	if !strings.EqualFold(state, stateEnabled) {
		sev = telemetry.SeverityWarn
	}

	displayName := name
	if displayName == "" {
		displayName = "unknown"
	}
	return telemetry.Event{
		Name:     eventRule,
		Body:     fmt.Sprintf("mdo %s rule %q: state=%s priority=%s", family, displayName, state, priorityString(r)),
		Severity: sev,
		Attrs:    attrs,
	}
}

// unrefPolicyTwin renders one unreferenced policy as an OTLP log record.
// Always Warn: a configured MDO/EOP policy no enabled rule applies is inert
// configuration, worth an operator's attention every cycle it persists.
func unrefPolicyTwin(policyType, name string) telemetry.Event {
	attrs := telemetry.Attrs{}
	telemetry.SetStr(attrs, semconv.AttrPolicyType, policyType)
	telemetry.SetStr(attrs, semconv.AttrPolicyName, name)
	return telemetry.Event{
		Name:     eventUnrefPolicy,
		Body:     fmt.Sprintf("mdo %s policy %q is not referenced by any enabled rule", policyType, name),
		Severity: telemetry.SeverityWarn,
		Attrs:    attrs,
	}
}

// priorityString renders Priority for the twin Body, "?" when absent.
func priorityString(r map[string]any) string {
	if f, ok := r["Priority"].(float64); ok {
		return fmt.Sprintf("%d", int64(f))
	}
	return "?"
}

// str reads a string column, "" when absent, null or non-string. The API
// decorates several columns with sidecar "<Name>@data.type"/"<Name>@odata.type"
// keys; reading by exact name ignores them.
func str(m map[string]any, key string) string {
	s, _ := m[key].(string)
	return s
}

// ruleStateLabel reads r's State and buckets it under the metricRules state
// label: the two recognized values verbatim, or stateUnknown for anything
// else — including a missing/empty State, which would otherwise mint a
// state="" series, the least debuggable value a label can carry. This only
// affects the METRIC bucket; the defender.mdo_rule twin's own state attribute
// (set in ruleTwin via telemetry.SetStr) still carries whatever the wire sent
// verbatim when it is a genuinely unrecognized non-empty value — SetStr's own
// empty-string rule only ever omits the attribute for a truly blank State, it
// never substitutes "unknown" there.
func ruleStateLabel(r map[string]any) string {
	switch s := str(r, "State"); s {
	case stateEnabled, stateDisabled:
		return s
	default:
		return stateUnknown
	}
}

// stringList reads a JSON array-of-strings column, returning (nil, false) when
// the key is absent, JSON null, or present but contains no non-empty string
// element. A NULL wire value and an empty/all-empty array are therefore
// INDISTINGUISHABLE here on purpose: both mean "this axis carries no
// restriction", which is the honest reading — see the package doc on why NULL
// must never be rendered as an empty (and therefore "applies to nobody") list.
func stringList(m map[string]any, key string) ([]string, bool) {
	raw, ok := m[key].([]any)
	if !ok {
		return nil, false
	}
	vals := make([]string, 0, len(raw))
	for _, v := range raw {
		if s, ok := v.(string); ok && s != "" {
			vals = append(vals, s)
		}
	}
	if len(vals) == 0 {
		return nil, false
	}
	return vals, true
}

func init() {
	collectors.RegisterEXO(func(d collectors.EXODeps) collector.SnapshotCollector { return New(d) })
}

var _ collector.SnapshotCollector = (*Collector)(nil)
