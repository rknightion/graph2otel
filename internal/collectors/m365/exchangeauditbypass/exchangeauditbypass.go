// Package exchangeauditbypass is the Exchange Online mailbox audit-bypass
// collector (#356): which mailboxes have mailbox-audit logging turned OFF,
// read over the Exchange Online admin API's app-only cmdlet transport
// (internal/exoclient), the same shape as the sibling accepted-domains and
// admin-audit-log-config collectors (#250, #99).
//
// # Why this matters
//
// A mailbox with an audit-bypass association enabled produces NO mailbox
// audit records at all — Get-MailboxAuditBypassAssociation is the one cmdlet
// that reports it, and nothing else on this project's path (Graph or EXO)
// surfaces it. This is an audit-BLINDING control: enabling it for a mailbox
// makes every subsequent action on that mailbox invisible to mailbox audit
// logging, which is exactly the state an attacker (or a careless admin script)
// wants. The healthy tenant reads all-clear — zero mailboxes bypassed — so
// unlike most of this project's collectors, ANY non-zero finding here is
// itself the interesting signal, not a rate or a trend.
//
// # Live population, and why the twin departs from one-per-entity
//
// Live measurement (2026-07-28, #356) against the m7kni tenant returned 242
// associations, every one with AuditBypassEnabled=false, and the population
// is dominated by system objects (SystemMailbox{...}, TenantSetting_...,
// Asc-... service accounts) rather than one row per human mailbox.
// RecipientTypeDetails is absent on every row measured, so this collector does
// not build on it.
//
// Emitting a twin per association — the usual log-twin default this project
// otherwise follows — would mean 242 log records EVERY CYCLE on a healthy
// tenant, carrying zero findings. That is pure noise: it would train an
// operator to ignore the event name entirely. This collector deliberately
// inverts the usual rule: the twin population is bounded by "someone
// deliberately turned this on", not by tenant size, so ONLY associations with
// AuditBypassEnabled=true get a log twin, at Warn severity — the twin IS the
// finding, not the inventory. The bounded gauges below carry the inventory
// instead.
//
// # Both sides of the cardinality boundary
//
// From one cmdlet call:
//
//   - a bounded GAUGE m365.exchange.audit_bypass.enabled_count — the count of
//     associations with AuditBypassEnabled=true. Zero on a healthy tenant, not
//     absent — the point exists every cycle so "reads zero" and "the cmdlet
//     returned nothing" stay distinguishable via the sibling gauge below;
//   - a bounded GAUGE m365.exchange.audit_bypass.examined — the total count of
//     associations this poll actually classified true/false. Without this,
//     "0 bypassed" and "the tenant call came back empty" are indistinguishable,
//     and those are opposite facts (one is healthy, the other is a source
//     outage or a scope regression);
//   - one LOG twin per association with AuditBypassEnabled=true, carrying the
//     mailbox identity (name/identity/guid), when it was last changed, and
//     Warn severity — see above.
//
// Neither gauge carries a per-mailbox label: the population scales with
// mailbox count, so per-entity identity never becomes a metric label (#112).
// The mailbox identity lives on the twin only, and only for the mailboxes
// that matter.
//
// # AuditBypassEnabled is a pointer: absent is neither true nor false
//
// The decode struct reads AuditBypassEnabled as *bool, not bool. A bare bool
// cannot distinguish "the wire said false" from "the key was absent from this
// row", and defaulting an absent key to false would silently report a mailbox
// this project genuinely could not classify as healthy — the exact inversion
// this collector exists to catch. A row whose key is absent is counted as
// INDETERMINATE: excluded from both gauges (neither examined nor bypassed) and
// never given a log twin, because a twin implies a finding and "unknown" is
// not one. Live measurement observed the key present (as false) on all 242
// rows, so the indeterminate branch is untested by live data and is exercised
// only by a synthesized fixture — see the test file.
//
// # No silent truncation
//
// ResultSize=Unlimited is pinned on every call, for the same reason it is
// pinned on Get-AcceptedDomain and Get-Mailbox: the default page is
// undocumented and a truncated page for this cmdlet still returns HTTP 200,
// so without it a tenant with more mailboxes than the default page reports a
// fraction of them and looks perfectly healthy doing it.
//
// A state snapshot, not an event stream: the twins and gauges are stamped at
// poll time.
package exchangeauditbypass

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
	collectorName = "m365.exchange_audit_bypass"
	// eventName is the OTLP LogRecord EventName each bypassed-mailbox twin
	// carries.
	eventName = "m365.exchange_audit_bypass"
	// metricBypassed counts associations with AuditBypassEnabled=true. Zero on
	// a healthy tenant, emitted every cycle regardless.
	metricBypassed = "m365.exchange.audit_bypass.enabled_count"
	// metricExamined counts associations this poll classified true/false
	// (excludes indeterminate rows). Without this gauge, "0 bypassed" and "the
	// cmdlet returned nothing" are indistinguishable — see the package doc.
	metricExamined = "m365.exchange.audit_bypass.examined"
	// unitAssociation is the annotation unit for a countable audit-bypass
	// association.
	unitAssociation = "{association}"
	// cmdlet is the single Exchange Online cmdlet this collector runs.
	cmdlet = "Get-MailboxAuditBypassAssociation"
	// paramResultSize / resultSizeUnlimited defeat the default page. Load-
	// bearing — see the package doc's no-silent-truncation note.
	paramResultSize     = "ResultSize"
	resultSizeUnlimited = "Unlimited"
	// interval: audit-bypass associations change when an admin runs
	// Set-MailboxAuditBypassAssociation, an infrequent administrative action.
	interval = time.Hour
)

// Wire field names, read by exact name so the "<Name>@data.type" sidecars are
// ignored.
const (
	// #nosec G101 -- a wire COLUMN NAME, not a credential. gosec matches the
	// "Audit...Enabled" shape; the value read from this column is a boolean.
	fieldAuditBypassEnabled = "AuditBypassEnabled"
	fieldName               = "Name"
	fieldIdentity           = "Identity"
	fieldId                 = "Id"
	fieldGuid               = "Guid"
	fieldExchangeObjectId   = "ExchangeObjectId"
	fieldDistinguishedName  = "DistinguishedName"
	fieldObjectClass        = "ObjectClass"
	fieldWhenChangedUTC     = "WhenChangedUTC"
	fieldOrganizationId     = "OrganizationId"
	fieldIsValid            = "IsValid"
)

// Collector reads Exchange Online mailbox audit-bypass associations.
type Collector struct {
	c collectors.EXOClient
}

// New builds the audit-bypass collector.
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

// Collect runs the cmdlet, emits the examined/bypassed gauges, and emits a
// twin for every association with AuditBypassEnabled=true.
func (c *Collector) Collect(ctx context.Context, e telemetry.Emitter, outcomes *recordoutcome.Recorder) error {
	// Stamp the transport HERE: with no ingest engine on this path the
	// Scheduler baseline is TransportGraph.
	e = telemetry.WithTransport(e, telemetry.TransportExchangeOnline)

	// ResultSize is load-bearing — see the package doc.
	recs, err := c.c.Invoke(ctx, cmdlet, map[string]any{paramResultSize: resultSizeUnlimited})
	if err != nil {
		outcomes.Cause(recordoutcome.CauseSourceError)
		return fmt.Errorf("%s: %w", cmdlet, err)
	}
	outcomes.Add(recordoutcome.OutcomeFetched, uint64(len(recs)))
	if len(recs) == 0 {
		// No associations returned — nothing to emit rather than a misleading
		// zero on either gauge (see the package doc's examined/bypassed split).
		return nil
	}

	var examined, bypassed float64
	var indeterminate uint64
	for _, r := range recs {
		enabled, ok := boolPtr(r, fieldAuditBypassEnabled)
		if !ok {
			// The key was absent: neither healthy nor a finding. Excluded from
			// both gauges and never given a twin — see the package doc.
			indeterminate++
			continue
		}
		examined++
		if *enabled {
			bypassed++
			e.LogEvent(bypassTwin(r))
			// Mapped must reconcile as Emitted+Deduped (recordoutcome.Validate):
			// only rows that actually produce a twin count as Mapped/Emitted.
			outcomes.Add(recordoutcome.OutcomeMapped, 1)
			outcomes.Add(recordoutcome.OutcomeEmitted, 1)
		} else {
			// Examined (for the gauge) but not mapped into an emitted twin —
			// AuditBypassEnabled=false is the healthy case and gets no twin.
			outcomes.Add(recordoutcome.OutcomeFiltered, 1)
		}
	}
	if indeterminate > 0 {
		outcomes.Add(recordoutcome.OutcomeFiltered, indeterminate)
	}

	e.GaugeSnapshot(metricExamined, unitAssociation,
		"Exchange Online mailbox audit-bypass associations this poll classified true/false. Excludes rows where AuditBypassEnabled was absent from the wire (indeterminate, counted in neither gauge). Compare against m365.exchange.audit_bypass.enabled_count: a healthy tenant reads examined>0, enabled_count=0 — examined=0 means the source call returned nothing, not that the tenant is clean.",
		[]telemetry.GaugePoint{{Value: examined}})

	e.GaugeSnapshot(metricBypassed, unitAssociation,
		"Exchange Online mailbox audit-bypass associations with AuditBypassEnabled=true — mailboxes producing NO mailbox audit records. The healthy steady state is zero. Per-mailbox identity is never a label here (#112); see the m365.exchange_audit_bypass log twin, emitted only for associations counted in this gauge.",
		[]telemetry.GaugePoint{{Value: bypassed}})

	return nil
}

// bypassTwin renders one ENABLED audit-bypass association as a log record.
// Only called for associations already known to have AuditBypassEnabled=true
// — the twin population is the finding, not the inventory (see package doc),
// so every twin this collector emits carries Warn severity: an audit-bypassed
// mailbox is a security-relevant state by construction, not a graded one.
func bypassTwin(r map[string]any) telemetry.Event {
	name := str(r, fieldName)
	identity := str(r, fieldIdentity)

	attrs := telemetry.Attrs{}
	telemetry.SetStr(attrs, semconv.AttrName, name)
	telemetry.SetStr(attrs, semconv.AttrIdentity, identity)
	telemetry.SetStr(attrs, semconv.AttrId, str(r, fieldId))
	telemetry.SetStr(attrs, semconv.AttrGuid, str(r, fieldGuid))
	telemetry.SetStr(attrs, semconv.AttrExchangeObjectId, str(r, fieldExchangeObjectId))
	telemetry.SetStr(attrs, semconv.AttrDistinguishedName, str(r, fieldDistinguishedName))
	telemetry.SetStrs(attrs, semconv.AttrObjectClass, strs(r, fieldObjectClass))
	telemetry.SetStr(attrs, semconv.AttrWhenChangedUtc, str(r, fieldWhenChangedUTC))
	telemetry.SetStr(attrs, semconv.AttrOrganizationId, str(r, fieldOrganizationId))
	telemetry.SetBool(attrs, semconv.AttrIsValid, boolVal(r, fieldIsValid))

	body := fmt.Sprintf("mailbox audit bypass ENABLED for %q (identity=%s): this mailbox produces no mailbox audit records", name, identity)
	return telemetry.Event{Name: eventName, Body: body, Severity: telemetry.SeverityWarn, Attrs: attrs}
}

// boolPtr reads a boolean column, returning (value, true) when present as a
// JSON bool and (false, false) when the key is absent or non-bool — the
// distinction the package doc's indeterminate branch depends on.
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

// boolVal reads a boolean column, false when absent or non-bool.
func boolVal(m map[string]any, key string) bool {
	b, _ := m[key].(bool)
	return b
}

// str reads a string column, "" when absent or non-string. Reading by exact
// name ignores the "<Name>@data.type"/"@odata.type" sidecars.
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

var _ collector.SnapshotCollector = (*Collector)(nil)
