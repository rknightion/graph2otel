package semconv

// defender.mdo_rules attributes (#354) — the Defender for Office 365 / EOP
// protection-policy RULE layer: which recipients a policy actually reaches, in
// what priority order, and whether the policy is referenced by any rule at all.
//
// Reused where a key already exists: AttrRuleName / AttrRuleIdentity
// (attrs_purview.go and attrs_m365_*.go), AttrPolicyType / AttrPolicyName
// (attrs_intune.go), AttrState / AttrPriority / AttrDescription
// (attrs_shared.go), and AttrGuid / AttrIsValid / AttrWhenChanged
// (attrs_m365.go). The rule's `Identity` column maps to AttrRuleIdentity, not
// to the generic AttrIdentity — the two would be the same fact under two names,
// which is the drift this registry exists to stop.
//
// # Why a rule and its policy are different records
//
// An MDO policy says WHAT protection is applied; a rule says WHO it is applied
// to and in what precedence order. defender.mdo_policies already carries the
// first half. These keys carry the second, and the pair is joinable on
// AttrPolicyName — which is why the rule twin emits the referenced policy names
// under the SAME key that collector already uses, rather than inventing one.
//
// # Recipient lists are twin-only, always
//
// AttrSentTo, AttrSentToMemberOf, AttrRecipientDomainIs and the three
// AttrExceptIf* keys hold recipient addresses, group names and domains. Every
// one of them is per-entity and grows with the tenant, so none is ever a metric
// label (#112). The bounded gauge instead counts rules PER CONDITION KIND under
// AttrCondition, whose values are the six fixed condition names below — a closed
// set fixed by Exchange's rule model, not by tenant data.
const (
	// AttrRuleFamily is the bounded metric dimension naming which rule cmdlet a
	// record came from: atp_protection, eop_protection, atp_built_in,
	// hosted_content, malware, anti_phish, safe_links, safe_attachment,
	// teams_protection, hosted_outbound_spam. It is a graph2otel-derived name
	// for the cmdlet, not a Graph-supplied value, so it is not a wirecheck
	// concern.
	AttrRuleFamily = "rule_family"

	// AttrCondition is the bounded metric dimension naming WHICH recipient
	// condition a rule carries: sent_to, sent_to_member_of, recipient_domain_is,
	// except_sent_to, except_sent_to_member_of, except_recipient_domain_is.
	AttrCondition = "condition"

	// AttrRuleVersion is Exchange's own RuleVersion string ("14.0.0.0"), a
	// schema version for the rule object rather than anything tenant-specific.
	AttrRuleVersion = "rule_version"

	// AttrReferencedPolicies is the list of policy names this rule applies —
	// one rule can reference several (an EOP protection rule names a hosted
	// content filter policy, an anti-phish policy AND a malware filter policy).
	// The individual names also ride under AttrPolicyName-shaped per-kind keys
	// on the twin; this list is what makes "which policies does this rule turn
	// on" answerable without knowing the kinds in advance.
	AttrReferencedPolicies = "referenced_policies"

	// The six recipient-scoping fields, verbatim from the wire. All twin-only.
	// A NULL wire value means the condition is absent — the rule is unscoped on
	// that axis and therefore applies more broadly, which is the opposite of an
	// empty list meaning "nobody". The mapper omits the attribute rather than
	// emitting an empty list, so absence stays legible as absence.
	AttrSentTo                    = "sent_to"
	AttrSentToMemberOf            = "sent_to_member_of"
	AttrRecipientDomainIs         = "recipient_domain_is"
	AttrExceptIfSentTo            = "except_if_sent_to"
	AttrExceptIfSentToMemberOf    = "except_if_sent_to_member_of"
	AttrExceptIfRecipientDomainIs = "except_if_recipient_domain_is"
)
