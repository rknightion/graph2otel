// Package exchangeaccepteddomains is the Exchange Online accepted-domain
// posture collector (#353), read over the Exchange Online admin API's
// app-only cmdlet transport (internal/exoclient), the same shape as the sibling
// remote-domain and mailbox collectors (#250).
//
// # Why this matters
//
// An accepted domain defines who Exchange Online believes IT IS for mail
// routing purposes — whether it delivers mail for a domain locally
// (Authoritative) or relays it elsewhere (InternalRelay, a legitimate hybrid
// on-prem/cloud configuration, not a misconfiguration). It is a separate
// mail-routing boundary from the remote-domain (#250, outbound posture toward
// external domains) and DKIM (#250, signing) collectors, and no Graph endpoint
// reports it.
//
// # Both sides of the cardinality boundary
//
// From one cmdlet call:
//
//   - a bounded GAUGE m365.exchange.accepted_domains{domain_type,
//     is_default_domain} — domain_type is a small, API-fixed enum and
//     is_default_domain a strict boolean, both bounded by the shape of the
//     API rather than by tenant size;
//   - one LOG twin per domain carrying the domain name, type, initial/default/
//     match-subdomains state, SMTP DANE and authentication posture.
//
// The domain NAME is per-entity and is NEVER a metric label (#112): a series
// keyed by domain name would grow with the number of domains a tenant owns and
// answer nothing the twin does not answer better via LogQL.
//
// # domain_type is watched, but not wirecheck-enforced
//
// Live measurement (2026-07-27, #353) against the m7kni tenant observed
// exactly ONE DomainType value, "Authoritative", across all 4 returned
// domains. Microsoft's own Get-AcceptedDomain reference additionally documents
// "InternalRelay" (and "Mixed"), but neither has been observed on the wire
// here — that is docs-only evidence, not live-measured. Per this project's
// wirecheck rule (CLAUDE.md, #233/#234), one observed value is not a value
// set: this collector deliberately declares NO internal/wirecheck enum watcher
// for DomainType. A watcher built off a single observed value would fire the
// moment a tenant's second, entirely legitimate domain type showed up — worse
// than no watcher at all. This is a recorded decision, not an oversight.
//
// # InternalRelay is not a finding
//
// Unlike the remote-domain collector's AutoForwardEnabled (a real security
// control this project rates Warn/Error), DomainType has no "bad" value: an
// InternalRelay domain is how hybrid Exchange deployments route mail for a
// domain whose mailboxes live on-premises, and Authoritative is the ordinary
// case for a domain wholly hosted in Exchange Online. Every domain twin this
// collector emits carries Info severity regardless of its DomainType — the
// mapper does not classify DomainType as good or bad at all.
//
// # No silent truncation
//
// ResultSize=Unlimited is pinned on every call, for the same reason it is
// pinned on Get-Mailbox (see exchangemailboxes's package doc): the default
// page is undocumented and a truncated page for this cmdlet still returns
// HTTP 200, so without it a tenant with more accepted domains than the default
// page reports a fraction of them and looks perfectly healthy doing it.
//
// A state snapshot, not an event stream: the twins are stamped at poll time.
package exchangeaccepteddomains

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
	collectorName = "m365.exchange_accepted_domains"
	// eventName is the OTLP LogRecord EventName each domain twin carries.
	eventName = "m365.exchange_accepted_domain"
	// metricDomains counts accepted domains by domain type and default state.
	metricDomains = "m365.exchange.accepted_domains"
	// unitDomain is the annotation unit for a countable domain.
	unitDomain = "{domain}"
	// cmdlet is the single Exchange Online cmdlet this collector runs.
	cmdlet = "Get-AcceptedDomain"
	// paramResultSize / resultSizeUnlimited defeat the default page. Load-
	// bearing — see the package doc's no-silent-truncation note.
	paramResultSize     = "ResultSize"
	resultSizeUnlimited = "Unlimited"
	// interval: accepted-domain configuration changes when an admin adds or
	// edits a domain.
	interval = time.Hour
)

// Wire field names, read by exact name so the "<Name>@data.type" sidecars are
// ignored.
const (
	fieldDomainName                = "DomainName"
	fieldDomainType                = "DomainType"
	fieldDefault                   = "Default"
	fieldInitialDomain             = "InitialDomain"
	fieldMatchSubDomains           = "MatchSubDomains"
	fieldSmtpDaneStatus            = "SmtpDaneStatus"
	fieldAuthenticationType        = "AuthenticationType"
	fieldExternallyManaged         = "ExternallyManaged"
	fieldPendingRemoval            = "PendingRemoval"
	fieldPendingCompletion         = "PendingCompletion"
	fieldOutboundOnly              = "OutboundOnly"
	fieldEmailOnly                 = "EmailOnly"
	fieldAddressBookEnabled        = "AddressBookEnabled"
	fieldSendingFromDomainDisabled = "SendingFromDomainDisabled"
	fieldSendingToDomainDisabled   = "SendingToDomainDisabled"
	fieldIsCoexistenceDomain       = "IsCoexistenceDomain"
	fieldCatchAllRecipientID       = "CatchAllRecipientID"
	fieldFederatedOrganizationLink = "FederatedOrganizationLink"
	fieldName                      = "Name"
	fieldDistinguishedName         = "DistinguishedName"
	fieldExchangeVersion           = "ExchangeVersion"
	fieldAdminDisplayName          = "AdminDisplayName"
	fieldMailFlowRegion            = "MailFlowRegion"
	fieldAzureProvisioningRegion   = "AzureProvisioningRegion"
)

// Collector reads Exchange Online accepted-domain configuration.
type Collector struct {
	c collectors.EXOClient
}

// New builds the accepted-domain collector.
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

// Collect runs the cmdlet and emits the gauge plus a twin per domain.
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

	// domain_type is an open-ish enum (see package doc): buckets are built
	// dynamically from whatever the wire sends, never pre-seeded from a
	// hardcoded value set — the same reasoning as exchangemailboxes' census.
	type bucketKey struct {
		domainType string
		isDefault  string
	}
	counts := map[bucketKey]float64{}
	for _, r := range recs {
		key := bucketKey{
			domainType: str(r, fieldDomainType),
			isDefault:  boolStr(boolVal(r, fieldDefault)),
		}
		counts[key]++
		e.LogEvent(domainTwin(r))
		outcomes.Add(recordoutcome.OutcomeMapped, 1)
		outcomes.Add(recordoutcome.OutcomeEmitted, 1)
	}

	points := make([]telemetry.GaugePoint, 0, len(counts))
	for k, v := range counts {
		points = append(points, telemetry.GaugePoint{Value: v, Attrs: telemetry.Attrs{
			semconv.AttrDomainType:      k.domainType,
			semconv.AttrIsDefaultDomain: k.isDefault,
		}})
	}

	e.GaugeSnapshot(metricDomains, unitDomain,
		"Exchange Online accepted domains by domain type and whether each is the tenant's default domain. domain_type and is_default_domain are both bounded by the API (a small enum and a strict boolean); the domain NAME itself lives on the m365.exchange_accepted_domain log twin only, never here (#112).",
		points)
	return nil
}

// domainTwin renders one accepted domain as a log record. DomainType has no
// "bad" value — InternalRelay is a legitimate hybrid configuration, not a
// misconfiguration — so every twin this collector emits carries Info
// severity regardless of DomainType. See the package doc.
func domainTwin(r map[string]any) telemetry.Event {
	domain := str(r, fieldDomainName)
	domainType := str(r, fieldDomainType)

	attrs := telemetry.Attrs{}
	telemetry.SetStr(attrs, semconv.AttrDomain, domain)
	telemetry.SetStr(attrs, semconv.AttrName, str(r, fieldName))
	telemetry.SetStr(attrs, semconv.AttrDomainType, domainType)
	telemetry.SetBool(attrs, semconv.AttrIsDefaultDomain, boolVal(r, fieldDefault))
	telemetry.SetBool(attrs, semconv.AttrIsInitialDomain, boolVal(r, fieldInitialDomain))
	telemetry.SetBool(attrs, semconv.AttrMatchSubdomains, boolVal(r, fieldMatchSubDomains))
	telemetry.SetStr(attrs, semconv.AttrSmtpDaneStatus, str(r, fieldSmtpDaneStatus))
	telemetry.SetStr(attrs, semconv.AttrAuthenticationType, str(r, fieldAuthenticationType))
	telemetry.SetBool(attrs, semconv.AttrExternallyManaged, boolVal(r, fieldExternallyManaged))
	telemetry.SetBool(attrs, semconv.AttrPendingRemoval, boolVal(r, fieldPendingRemoval))
	telemetry.SetBool(attrs, semconv.AttrPendingCompletion, boolVal(r, fieldPendingCompletion))
	telemetry.SetBool(attrs, semconv.AttrOutboundOnly, boolVal(r, fieldOutboundOnly))
	telemetry.SetBool(attrs, semconv.AttrEmailOnly, boolVal(r, fieldEmailOnly))
	telemetry.SetBool(attrs, semconv.AttrAddressBookEnabled, boolVal(r, fieldAddressBookEnabled))
	telemetry.SetBool(attrs, semconv.AttrSendingFromDomainDisabled, boolVal(r, fieldSendingFromDomainDisabled))
	telemetry.SetBool(attrs, semconv.AttrSendingToDomainDisabled, boolVal(r, fieldSendingToDomainDisabled))
	telemetry.SetBool(attrs, semconv.AttrIsCoexistenceDomain, boolVal(r, fieldIsCoexistenceDomain))
	telemetry.SetStr(attrs, semconv.AttrCatchAllRecipientId, str(r, fieldCatchAllRecipientID))
	telemetry.SetStr(attrs, semconv.AttrFederatedOrganizationLink, str(r, fieldFederatedOrganizationLink))
	telemetry.SetStr(attrs, semconv.AttrDistinguishedName, str(r, fieldDistinguishedName))
	telemetry.SetStr(attrs, semconv.AttrExchangeVersion, str(r, fieldExchangeVersion))
	telemetry.SetStr(attrs, semconv.AttrAdminDisplayName, str(r, fieldAdminDisplayName))
	telemetry.SetStr(attrs, semconv.AttrMailFlowRegion, str(r, fieldMailFlowRegion))
	telemetry.SetStr(attrs, semconv.AttrAzureProvisioningRegion, str(r, fieldAzureProvisioningRegion))

	body := fmt.Sprintf("accepted domain %q: type=%s default=%t initial=%t", domain, domainType, boolVal(r, fieldDefault), boolVal(r, fieldInitialDomain))
	return telemetry.Event{Name: eventName, Body: body, Severity: telemetry.SeverityInfo, Attrs: attrs}
}

// str reads a string column, "" when absent or non-string. Reading by exact
// name ignores the "<Name>@data.type" sidecars. A JSON null (e.g.
// CatchAllRecipientID when no catch-all is configured) also decodes to "" here
// and SetStr omits empty strings, so null is correctly never stamped.
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

func init() {
	collectors.RegisterEXO(func(d collectors.EXODeps) collector.SnapshotCollector { return New(d) })
}

var _ collector.SnapshotCollector = (*Collector)(nil)
