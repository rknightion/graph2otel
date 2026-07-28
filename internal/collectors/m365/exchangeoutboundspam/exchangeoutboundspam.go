// Package exchangeoutboundspam is the Exchange Online outbound-spam and
// automatic-forwarding posture collector (#357), read over the Exchange
// Online admin API's app-only cmdlet transport (internal/exoclient), the
// same shape as the sibling accepted-domains and organization-config
// collectors (#250, #353).
//
// # Why this matters
//
// HostedOutboundSpamFilterPolicy is the control that decides what happens
// when a mailbox in this tenant starts sending spam, or forwards mail
// automatically to an external address — both classic signs of a compromised
// account. AutoForwardingMode governs whether Exchange Online allows
// automatic external forwarding at all; the three RecipientLimit* fields cap
// how many recipients a sender can mail before ActionWhenThresholdReached
// kicks in (e.g. BlockUserForToday). No Graph endpoint reports any of this.
//
// # Both sides of the cardinality boundary
//
// From one cmdlet call:
//
//   - a bounded GAUGE m365.exchange.outbound_spam.policies{is_default,
//     enabled} — is_default and enabled are both strict booleans, bounded by
//     the shape of the API rather than by tenant size;
//   - a bounded GAUGE m365.exchange.outbound_spam.recipient_limit{limit} —
//     the three RecipientLimit* fields from the tenant's DEFAULT policy
//     ONLY, keyed by a fixed 3-member "limit" label
//     (external_per_hour/internal_per_hour/per_day), following the
//     m365.exchange.org_config.setting_enabled{setting} idiom
//     (exchangeorgconfig) generalized from booleans to numerics;
//   - one LOG twin per policy (default AND every custom policy) carrying the
//     full configuration: mode strings, action, all three limits, and the
//     notify/BCC recipient lists.
//
// # Why the recipient_limit gauge is DEFAULT-policy-only
//
// A tenant can have multiple outbound spam policies — Microsoft's own
// reference documents a named custom policy example ("Contoso Executives")
// scoped to specific mailboxes. Unlike m365.exchange.org_config's singleton
// object, RecipientLimitExternalPerHour is genuinely per-policy, and a
// custom policy's identity is per-entity data that must never become a
// metric label (#112, same reasoning as exchangeaccepteddomains' domain
// name). Rather than either fabricate an aggregate across policies with
// different meanings, or label the gauge by policy identity, this collector
// emits the numeric-limit gauge from the tenant's DEFAULT policy only — the
// one policy guaranteed unique per tenant, and the effective fallback for
// every mailbox not covered by a custom policy. Every policy's individual
// limits, default or custom, are still fully captured on its own twin. If no
// returned policy has IsDefault=true (should not happen, but is not
// enforced by this collector), no recipient_limit points are emitted at all
// — fabricating them from an arbitrary non-default policy would misrepresent
// the tenant's actual fallback limits.
//
// # This tenant's default policy reads Enabled=false with all limits at zero
//
// Live measurement (2026-07-28, #357) against the m7kni tenant found the
// Default policy has Enabled=false and all three RecipientLimit* fields at
// 0. Zero is a real, present value on the wire (not absent), and Enabled is
// a fact to report, not a filter — every returned policy gets a twin
// regardless of Enabled, matching the acceptance criteria's disabled case.
//
// # Three fields deliberately NOT backed by a wirecheck enum watcher
//
// AutoForwardingMode ("Automatic") and ActionWhenThresholdReached
// ("BlockUserForToday") were each observed with exactly ONE live value.
// Per this project's wirecheck rule (CLAUDE.md, #233/#234), one observed
// value is not a value set: internal/semconv/attrs_m365_exchangepolicies.go
// declares no Enum watcher for either. Both are carried as plain strings on
// the twin.
//
// # No ResultSize parameter
//
// Unlike Get-AcceptedDomain/Get-Mailbox, Get-HostedOutboundSpamFilterPolicy
// has NO ResultSize parameter (Microsoft Learn reference, checked
// 2026-07-28) — its only parameter is an optional -Identity filter, and it
// is not a paged cmdlet. This collector therefore calls it with nil
// parameters; adding an unsupported parameter would itself be a source
// error on some EXO cmdlets, not a silent no-op.
//
// A state snapshot, not an event stream: the twins and gauges are stamped at
// poll time.
package exchangeoutboundspam

import (
	"context"
	"fmt"
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
	collectorName = "m365.exchange_outbound_spam"
	// eventName is the OTLP LogRecord EventName each policy twin carries.
	eventName = "m365.exchange_outbound_spam_policy"
	// metricPolicies counts outbound spam policies by default state and
	// enabled state.
	metricPolicies = "m365.exchange.outbound_spam.policies"
	// unitPolicy is the annotation unit for a countable policy.
	unitPolicy = "{policy}"
	// metricRecipientLimit is the tenant's DEFAULT policy's three recipient
	// limits, keyed by "limit" — see the package doc.
	metricRecipientLimit = "m365.exchange.outbound_spam.recipient_limit"
	// unitRecipient is the annotation unit for a bounded recipient-count
	// limit.
	unitRecipient = "{recipient}"
	// cmdlet is the single Exchange Online cmdlet this collector runs. It
	// accepts no ResultSize — see the package doc.
	cmdlet = "Get-HostedOutboundSpamFilterPolicy"
	// interval: outbound spam policy configuration changes when an admin
	// edits it.
	interval = time.Hour

	// limit label values for metricRecipientLimit — a fixed, small key
	// space, never per-entity.
	limitExternalPerHour = "external_per_hour"
	limitInternalPerHour = "internal_per_hour"
	limitPerDay          = "per_day"

	// maxRecipientList caps the two recipient-address log attributes, same
	// bound and rationale as entra/conditionalaccess's maxArrayAttr: a
	// record-size guard, not a business limit.
	maxRecipientList = 50
)

// Wire field names, read by exact name so any "<Name>@data.type" sidecars
// are ignored.
const (
	fieldAdminDisplayName                          = "AdminDisplayName"
	fieldIsDefault                                 = "IsDefault"
	fieldConfigurationType                         = "ConfigurationType"
	fieldEnabled                                   = "Enabled"
	fieldRecipientLimitExternalPerHour             = "RecipientLimitExternalPerHour"
	fieldRecipientLimitInternalPerHour             = "RecipientLimitInternalPerHour"
	fieldRecipientLimitPerDay                      = "RecipientLimitPerDay"
	fieldActionWhenThresholdReached                = "ActionWhenThresholdReached"
	fieldNotifyOutboundSpamRecipients              = "NotifyOutboundSpamRecipients"
	fieldBccSuspiciousOutboundAdditionalRecipients = "BccSuspiciousOutboundAdditionalRecipients"
	fieldBccSuspiciousOutboundMail                 = "BccSuspiciousOutboundMail"
	fieldNotifyOutboundSpam                        = "NotifyOutboundSpam"
	fieldRecommendedPolicyType                     = "RecommendedPolicyType"
	fieldAutoForwardingMode                        = "AutoForwardingMode"
	fieldName                                      = "Name"
	fieldDistinguishedName                         = "DistinguishedName"
	fieldIdentity                                  = "Identity"
	fieldId                                        = "Id"
	fieldGuid                                      = "Guid"
	fieldWhenChangedUTC                            = "WhenChangedUTC"
	fieldExchangeObjectId                          = "ExchangeObjectId"
	fieldOrganizationId                            = "OrganizationId"
	fieldIsValid                                   = "IsValid"
)

// Collector reads Exchange Online outbound spam filter policies.
type Collector struct {
	c collectors.EXOClient
}

// New builds the outbound-spam collector.
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

// RequiredPermissions is empty: access is the two grants outside the
// Graph-scope vocabulary (Exchange.ManageAsApp + a directory role), the same
// boundary documented on the sibling EXO collectors.
func (c *Collector) RequiredPermissions() []string { return nil }

// Collect runs the cmdlet, emits the policy-count gauge, the default
// policy's recipient-limit gauge, and a twin per policy.
func (c *Collector) Collect(ctx context.Context, e telemetry.Emitter, outcomes *recordoutcome.Recorder) error {
	// Stamp the transport HERE: with no ingest engine on this path the
	// Scheduler baseline is TransportGraph.
	e = telemetry.WithTransport(e, telemetry.TransportExchangeOnline)

	// No ResultSize — this cmdlet does not accept one, see the package doc.
	recs, err := c.c.Invoke(ctx, cmdlet, nil)
	if err != nil {
		outcomes.Cause(recordoutcome.CauseSourceError)
		return fmt.Errorf("%s: %w", cmdlet, err)
	}
	outcomes.Add(recordoutcome.OutcomeFetched, uint64(len(recs)))
	if len(recs) == 0 {
		return nil
	}

	type bucketKey struct {
		isDefault string
		enabled   string
	}
	counts := map[bucketKey]float64{}
	var defaultPolicy map[string]any

	for _, r := range recs {
		isDefault := boolVal(r, fieldIsDefault)
		enabled := boolVal(r, fieldEnabled)
		counts[bucketKey{boolStr(isDefault), boolStr(enabled)}]++
		if isDefault && defaultPolicy == nil {
			defaultPolicy = r
		}
		e.LogEvent(policyTwin(r))
		outcomes.Add(recordoutcome.OutcomeMapped, 1)
		outcomes.Add(recordoutcome.OutcomeEmitted, 1)
	}

	policyPoints := make([]telemetry.GaugePoint, 0, len(counts))
	for k, n := range counts {
		policyPoints = append(policyPoints, telemetry.GaugePoint{Value: n, Attrs: telemetry.Attrs{
			semconv.AttrIsDefault: k.isDefault,
			semconv.AttrEnabled:   k.enabled,
		}})
	}
	e.GaugeSnapshot(metricPolicies, unitPolicy,
		"Exchange Online outbound spam filter policies by whether each is the tenant's default policy and whether it is enabled. Both dimensions are strict booleans; the policy NAME/identity lives on the m365.exchange_outbound_spam_policy log twin only, never here (#112).",
		policyPoints)

	e.GaugeSnapshot(metricRecipientLimit, unitRecipient,
		"The tenant's DEFAULT outbound spam policy's three recipient-limit thresholds, keyed by limit (external_per_hour/internal_per_hour/per_day). Sourced from the default policy only, even when custom policies exist — see the package doc. Absent entirely when this poll returned no policy with is_default=true.",
		recipientLimitPoints(defaultPolicy))

	return nil
}

// recipientLimitPoints builds the recipient_limit gauge points from the
// tenant's default policy, when one was found this poll. A limit field
// present on the wire but not a JSON number (should not happen) is skipped
// rather than defaulted, same convention as exchangeorgconfig's boolean
// settings.
func recipientLimitPoints(defaultPolicy map[string]any) []telemetry.GaugePoint {
	if defaultPolicy == nil {
		return nil
	}
	fields := []struct {
		field string
		limit string
	}{
		{fieldRecipientLimitExternalPerHour, limitExternalPerHour},
		{fieldRecipientLimitInternalPerHour, limitInternalPerHour},
		{fieldRecipientLimitPerDay, limitPerDay},
	}
	points := make([]telemetry.GaugePoint, 0, len(fields))
	for _, f := range fields {
		v, ok := defaultPolicy[f.field].(float64)
		if !ok {
			continue
		}
		points = append(points, telemetry.GaugePoint{Value: v, Attrs: telemetry.Attrs{
			semconv.AttrLimit: f.limit,
		}})
	}
	return points
}

// policyTwin renders one outbound spam policy as a log record. Every field
// this collector classifies as "one observed value" (AutoForwardingMode,
// ActionWhenThresholdReached) is carried verbatim with no severity
// classification attached — see the package doc's wirecheck-restraint note.
func policyTwin(r map[string]any) telemetry.Event {
	name := str(r, fieldName)
	isDefault := boolVal(r, fieldIsDefault)
	enabled := boolVal(r, fieldEnabled)

	attrs := telemetry.Attrs{}
	telemetry.SetStr(attrs, semconv.AttrName, name)
	telemetry.SetStr(attrs, semconv.AttrIdentity, str(r, fieldIdentity))
	telemetry.SetStr(attrs, semconv.AttrId, str(r, fieldId))
	telemetry.SetStr(attrs, semconv.AttrGuid, str(r, fieldGuid))
	telemetry.SetStr(attrs, semconv.AttrAdminDisplayName, str(r, fieldAdminDisplayName))
	telemetry.SetStr(attrs, semconv.AttrDistinguishedName, str(r, fieldDistinguishedName))
	telemetry.SetStr(attrs, semconv.AttrExchangeObjectId, str(r, fieldExchangeObjectId))
	telemetry.SetStr(attrs, semconv.AttrOrganizationId, str(r, fieldOrganizationId))
	telemetry.SetStr(attrs, semconv.AttrWhenChangedUtc, str(r, fieldWhenChangedUTC))
	telemetry.SetBool(attrs, semconv.AttrIsValid, boolVal(r, fieldIsValid))

	telemetry.SetBool(attrs, semconv.AttrIsDefault, isDefault)
	telemetry.SetBool(attrs, semconv.AttrEnabled, enabled)
	telemetry.SetStr(attrs, semconv.AttrConfigType, str(r, fieldConfigurationType))
	telemetry.SetStr(attrs, semconv.AttrRecommendedPolicyType, str(r, fieldRecommendedPolicyType))
	telemetry.SetStr(attrs, semconv.AttrAutoForwardingMode, str(r, fieldAutoForwardingMode))
	telemetry.SetStr(attrs, semconv.AttrActionWhenThresholdReached, str(r, fieldActionWhenThresholdReached))

	// Present on the wire as a real number (including 0) — SetNum omits only
	// when the field is absent or not a JSON number, so a measured zero is
	// still stamped.
	telemetry.SetNum(attrs, semconv.AttrRecipientLimitExternalPerHour, r, fieldRecipientLimitExternalPerHour)
	telemetry.SetNum(attrs, semconv.AttrRecipientLimitInternalPerHour, r, fieldRecipientLimitInternalPerHour)
	telemetry.SetNum(attrs, semconv.AttrRecipientLimitPerDay, r, fieldRecipientLimitPerDay)

	telemetry.SetBool(attrs, semconv.AttrBccSuspiciousOutboundMail, boolVal(r, fieldBccSuspiciousOutboundMail))
	telemetry.SetBool(attrs, semconv.AttrNotifyOutboundSpam, boolVal(r, fieldNotifyOutboundSpam))

	truncated := setCappedStrs(attrs, semconv.AttrBccSuspiciousOutboundAdditionalRecipients, strs(r, fieldBccSuspiciousOutboundAdditionalRecipients))
	truncated = setCappedStrs(attrs, semconv.AttrNotifyOutboundSpamRecipients, strs(r, fieldNotifyOutboundSpamRecipients)) || truncated
	if truncated {
		attrs[semconv.AttrArraysTruncated] = true
	}

	body := fmt.Sprintf("outbound spam policy %q: default=%t enabled=%t auto_forwarding=%s", name, isDefault, enabled, str(r, fieldAutoForwardingMode))
	return telemetry.Event{Name: eventName, Body: body, Severity: telemetry.SeverityInfo, Attrs: attrs}
}

// str reads a string column, "" when absent or non-string. Reading by exact
// name ignores the "<Name>@data.type" sidecars.
func str(m map[string]any, key string) string {
	s, _ := m[key].(string)
	return s
}

// boolVal reads a boolean column, false when absent or non-bool.
func boolVal(m map[string]any, key string) bool {
	b, _ := m[key].(bool)
	return b
}

// boolStr renders a bool as the "true"/"false" string used for metric label
// values, matching telemetry.SetBool's convention.
func boolStr(b bool) string {
	if b {
		return "true"
	}
	return "false"
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

// capStrings returns at most max entries from items (the first max, in
// order) plus whether truncation happened, same helper and rationale as
// entra/conditionalaccess's capStrings.
func capStrings(items []string, max int) (capped []string, truncated bool) {
	if len(items) <= max {
		return items, false
	}
	return items[:max], true
}

// setCappedStrs sets attrs[key] to a maxRecipientList-bounded copy of items
// when non-empty (an empty slice omits the attribute, same convention as
// telemetry.SetStrs), and reports whether it had to truncate.
func setCappedStrs(attrs telemetry.Attrs, key string, items []string) (truncated bool) {
	if len(items) == 0 {
		return false
	}
	capped, truncated := capStrings(items, maxRecipientList)
	attrs[key] = capped
	return truncated
}

func init() {
	collectors.RegisterEXO(func(d collectors.EXODeps) collector.SnapshotCollector { return New(d) })
}

var _ collector.SnapshotCollector = (*Collector)(nil)
