// Package exchangeconnectionfilter is the Exchange Online connection-filter
// IP allow/block posture collector (#358), read over the Exchange Online
// admin API's app-only cmdlet transport (internal/exoclient), the same shape
// as the sibling accepted-domains and organization-config collectors (#250,
// #353).
//
// # Why this matters
//
// Get-HostedConnectionFilterPolicy controls IP addresses that bypass or are
// blocked from normal inbound spam filtering — a DIFFERENT mail-flow stage
// and a different control from the Tenant Allow/Block List this project
// already collects. A non-empty IPAllowList lets mail from those addresses
// skip content filtering entirely: it is the kind of control an attacker who
// gains admin access would want to abuse, so its state is worth alerting on
// even absent any other signal.
//
// # Both sides of the cardinality boundary
//
// From one cmdlet call:
//
//   - a bounded GAUGE m365.exchange.connection_filter.policies{is_default,
//     enable_safe_list} — both strict booleans, bounded by the shape of the
//     API rather than by tenant size;
//   - two bounded GAUGEs, m365.exchange.connection_filter.ip_allow_list_length
//     and .ip_block_list_length — the ENTRY COUNT of each list on the
//     tenant's DEFAULT policy only (see below), never the IPs themselves;
//   - one LOG twin per policy (default AND any custom policy) carrying the
//     full IP allow/block lists verbatim (capped, see maxIPListAttr) plus
//     the safe-list and directory-based-edge-block posture.
//
// An IP address is per-entity data and is NEVER a metric label (#112): it
// lives on the twin only. Microsoft's own reference notes that a tenant
// typically has exactly one connection filter policy (the Default one), but
// nothing prevents more, so this collector does not assume singularity.
//
// # Why the length gauges are DEFAULT-policy-only
//
// Same reasoning as exchangeoutboundspam's recipient_limit gauge: a length
// value is genuinely per-policy, and a non-default policy's identity is
// per-entity data that must never become a metric label. Rather than
// aggregate across policies with different scopes, or label by policy
// identity, the two length gauges are sourced from the tenant's DEFAULT
// policy only — the one policy guaranteed unique per tenant. Every policy's
// individual lists, default or custom, are still fully captured on its own
// twin. If no returned policy has IsDefault=true, no length-gauge points are
// emitted at all.
//
// # Measured zero is not an absent series
//
// Live measurement (2026-07-28, #358) against the m7kni tenant found both
// IPAllowList and IPBlockList EMPTY on the Default policy — the tenant's
// actual, healthy posture. Both length gauges are still emitted valued 0
// whenever a default policy is present this poll: a vanished series and a
// measured zero are different facts, and for this control zero is the
// finding an operator wants to be able to alert has NOT silently regressed
// into "unknown" rather than "empty".
//
// # DirectoryBasedEdgeBlockMode is NOT backed by a wirecheck enum watcher
//
// Observed with exactly ONE live value, "Default". Per this project's
// wirecheck rule (CLAUDE.md, #233/#234), one observed value is not a value
// set: internal/semconv/attrs_m365_exchangepolicies.go declares no Enum
// watcher for it. It is carried as a plain string on the twin.
//
// # No ResultSize parameter
//
// Unlike Get-AcceptedDomain/Get-Mailbox, Get-HostedConnectionFilterPolicy
// has NO ResultSize parameter (Microsoft Learn reference, checked
// 2026-07-28) — its only parameter is an optional -Identity filter, and it
// is not a paged cmdlet. This collector therefore calls it with nil
// parameters.
//
// A state snapshot, not an event stream: the twins and gauges are stamped at
// poll time.
package exchangeconnectionfilter

import (
	"context"
	"fmt"
	"strconv"
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
	collectorName = "m365.exchange_connection_filter"
	// eventName is the OTLP LogRecord EventName each policy twin carries.
	eventName = "m365.exchange_connection_filter_policy"
	// metricPolicies counts connection filter policies by default state and
	// safe-list state.
	metricPolicies = "m365.exchange.connection_filter.policies"
	// unitPolicy is the annotation unit for a countable policy.
	unitPolicy = "{policy}"
	// metricIPAllowListLength / metricIPBlockListLength are the tenant's
	// DEFAULT policy's IP list entry counts — see the package doc.
	metricIPAllowListLength = "m365.exchange.connection_filter.ip_allow_list_length"
	metricIPBlockListLength = "m365.exchange.connection_filter.ip_block_list_length"
	// unitIP is the annotation unit for a countable IP/CIDR entry.
	unitIP = "{ip}"
	// cmdlet is the single Exchange Online cmdlet this collector runs. It
	// accepts no ResultSize — see the package doc.
	cmdlet = "Get-HostedConnectionFilterPolicy"
	// interval: connection filter configuration changes when an admin edits
	// it.
	interval = time.Hour

	// maxIPListAttr caps the two IP-list log attributes. IP allow/block
	// lists can legitimately run larger than the named-location arrays
	// elsewhere in this project (entra/conditionalaccess's maxArrayAttr=50),
	// so this collector uses a larger bound — still a record-size guard, not
	// a business limit. The TRUE count is always stamped separately (see
	// semconv.AttrIpAllowListCount/AttrIpBlockListCount), so truncation never
	// hides how large the list actually is.
	maxIPListAttr = 100
)

// Wire field names, read by exact name so any "<Name>@data.type" sidecars
// are ignored.
const (
	fieldAdminDisplayName            = "AdminDisplayName"
	fieldIsDefault                   = "IsDefault"
	fieldIPAllowList                 = "IPAllowList"
	fieldIPBlockList                 = "IPBlockList"
	fieldEnableSafeList              = "EnableSafeList"
	fieldDirectoryBasedEdgeBlockMode = "DirectoryBasedEdgeBlockMode"
	fieldName                        = "Name"
	fieldDistinguishedName           = "DistinguishedName"
	fieldIdentity                    = "Identity"
	fieldId                          = "Id"
	fieldGuid                        = "Guid"
	fieldWhenChangedUTC              = "WhenChangedUTC"
	fieldExchangeObjectId            = "ExchangeObjectId"
	fieldOrganizationId              = "OrganizationId"
	fieldIsValid                     = "IsValid"
)

// Collector reads Exchange Online connection filter policies.
type Collector struct {
	c collectors.EXOClient
}

// New builds the connection-filter collector.
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
// policy's IP-list-length gauges, and a twin per policy.
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
		isDefault      string
		enableSafeList string
	}
	counts := map[bucketKey]float64{}
	var defaultPolicy map[string]any

	for _, r := range recs {
		isDefault := boolVal(r, fieldIsDefault)
		safeList := boolVal(r, fieldEnableSafeList)
		counts[bucketKey{boolStr(isDefault), boolStr(safeList)}]++
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
			semconv.AttrIsDefault:      k.isDefault,
			semconv.AttrEnableSafeList: k.enableSafeList,
		}})
	}
	e.GaugeSnapshot(metricPolicies, unitPolicy,
		"Exchange Online connection filter policies by whether each is the tenant's default policy and whether Microsoft's dynamic safe list is enabled. Both dimensions are strict booleans; the policy NAME/identity and its IP lists live on the m365.exchange_connection_filter_policy log twin only, never here (#112).",
		policyPoints)

	if defaultPolicy != nil {
		allowLen := float64(len(strs(defaultPolicy, fieldIPAllowList)))
		blockLen := float64(len(strs(defaultPolicy, fieldIPBlockList)))
		e.GaugeSnapshot(metricIPAllowListLength, unitIP,
			"The tenant's DEFAULT connection filter policy's IPAllowList entry count. Emitted as a measured 0 when empty (this project's healthy default), never omitted — a vanished series and a measured zero are different facts. Individual IPs are per-entity data and are never a label here (#112); see the m365.exchange_connection_filter_policy log twin.",
			[]telemetry.GaugePoint{{Value: allowLen}})
		e.GaugeSnapshot(metricIPBlockListLength, unitIP,
			"The tenant's DEFAULT connection filter policy's IPBlockList entry count. Emitted as a measured 0 when empty, never omitted. Individual IPs are per-entity data and are never a label here (#112); see the m365.exchange_connection_filter_policy log twin.",
			[]telemetry.GaugePoint{{Value: blockLen}})
	}

	return nil
}

// policyTwin renders one connection filter policy as a log record.
// DirectoryBasedEdgeBlockMode is carried verbatim with no severity
// classification attached — see the package doc's wirecheck-restraint note.
func policyTwin(r map[string]any) telemetry.Event {
	name := str(r, fieldName)
	isDefault := boolVal(r, fieldIsDefault)

	allow := strs(r, fieldIPAllowList)
	block := strs(r, fieldIPBlockList)

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
	telemetry.SetBool(attrs, semconv.AttrEnableSafeList, boolVal(r, fieldEnableSafeList))
	telemetry.SetStr(attrs, semconv.AttrDirectoryBasedEdgeBlockMode, str(r, fieldDirectoryBasedEdgeBlockMode))

	// The TRUE counts are always stamped, even zero and even when the list
	// attribute below gets capped — see the package doc.
	attrs[semconv.AttrIpAllowListCount] = strconv.Itoa(len(allow))
	attrs[semconv.AttrIpBlockListCount] = strconv.Itoa(len(block))

	truncated := setCappedStrs(attrs, semconv.AttrIpAllowList, allow)
	truncated = setCappedStrs(attrs, semconv.AttrIpBlockList, block) || truncated
	if truncated {
		attrs[semconv.AttrArraysTruncated] = true
	}

	body := fmt.Sprintf("connection filter policy %q: default=%t allow=%d block=%d safe_list=%t",
		name, isDefault, len(allow), len(block), boolVal(r, fieldEnableSafeList))
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
// whole row. A missing key or an empty array both yield a nil/empty slice —
// callers distinguish "measured empty" from "field absent" by stamping the
// COUNT unconditionally rather than relying on this return value alone.
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

// setCappedStrs sets attrs[key] to a maxIPListAttr-bounded copy of items
// when non-empty (an empty slice omits the attribute, same convention as
// telemetry.SetStrs), and reports whether it had to truncate.
func setCappedStrs(attrs telemetry.Attrs, key string, items []string) (truncated bool) {
	if len(items) == 0 {
		return false
	}
	capped, truncated := capStrings(items, maxIPListAttr)
	attrs[key] = capped
	return truncated
}

func init() {
	collectors.RegisterEXO(func(d collectors.EXODeps) collector.SnapshotCollector { return New(d) })
}

var _ collector.SnapshotCollector = (*Collector)(nil)
