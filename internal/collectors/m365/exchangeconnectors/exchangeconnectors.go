// Package exchangeconnectors is the Exchange Online mail-flow connector
// collector (#253, carved out of #250), read over the Exchange Online admin
// API's app-only cmdlet transport (internal/exoclient).
//
// # Why this matters
//
// A connector is mail-flow ROUTING, and it is the one piece of Exchange
// configuration that can redirect a tenant's mail wholesale:
//
//   - a rogue OUTBOUND connector routes the tenant's mail through
//     attacker-controlled infrastructure;
//   - a rogue INBOUND connector lets attacker mail arrive pre-trusted, as if it
//     came from the organization's own on-premises servers.
//
// Both are known M365 compromise patterns, both are invisible to every Graph
// endpoint, and neither is covered by m365.exchange_transport_rules — a rule
// acts on a message, a connector decides where messages travel.
//
// # Both sides of the cardinality boundary
//
// From two cmdlet calls:
//
//   - a bounded GAUGE m365.exchange.connectors{direction, enabled} — four
//     series, ALL SEEDED. Seeding is the point: "a connector appeared on a
//     tenant that had none" is the alert this collector exists for, and an alert
//     on a series appearing from nothing is not a thing anyone writes. It has to
//     be a change from a live 0.
//   - a bounded GAUGE m365.exchange.connectors.without_tls{direction} — the
//     concrete posture number, the counterpart of allow_block_list's
//     non_expiring_allow.
//   - one LOG twin per connector carrying the name, sender domains and IPs, the
//     certificate name, the TLS and restriction flags and who created it. Every
//     one of those identifies an entity, so none of them is ever a metric label
//     (#112/#114).
//
// # ConnectorSource is the discriminator, not ConnectorType
//
// ConnectorSource says who created the connector: "Default" and "HybridWizard"
// are expected furniture on a hybrid tenant, while "AdminUI" means a human made
// it by hand — the interesting one. ConnectorType is a different axis entirely
// (OnPremises vs Partner) and, confusingly, has nothing to do with the
// inbound/outbound direction this collector labels as `direction`. They are kept
// apart deliberately; folding them would produce a label whose meaning changes
// per row.
//
// # The outbound half is DELIBERATELY THIN — live-measured 2026-07-23
//
// m7kni has two inbound connectors and ZERO outbound ones, so the outbound
// record's field shape has never been on the wire. This collector therefore maps
// only the fields proven present on a real connector record, and does NOT guess
// at the outbound-only ones (smart hosts, recipient domains, the MX-record and
// transport-rule-scoping flags). Writing those from Microsoft's documentation is
// exactly the mistake #142/#165 record — a wrong field name maps to nothing and
// looks healthy doing it.
//
// The consequence is honest and bounded: an outbound connector is COUNTED, rated
// and twinned the moment it exists, but its twin will not yet say where the mail
// goes. #253 stays open for that, and its unblock condition is one outbound
// connector existing on a tenant this poller can read.
//
// A state snapshot, not an event stream: the twins are stamped at poll time.
package exchangeconnectors

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
	collectorName = "m365.exchange_connectors"
	// eventName is the OTLP LogRecord EventName each connector twin carries.
	eventName = "m365.exchange_connector"
	// metricConnectors counts connectors by direction and enabled state.
	metricConnectors = "m365.exchange.connectors"
	// metricWithoutTLS counts connectors that do not require TLS.
	metricWithoutTLS = "m365.exchange.connectors.without_tls"
	// unitConnector is the annotation unit for a countable connector.
	unitConnector = "{connector}"
	// inboundCmdlet and outboundCmdlet are the two cmdlets this collector runs.
	// BOTH always run: a connector on the side that was not asked about is
	// invisible, and invisible is the failure this collector is meant to prevent.
	// Both need GLOBAL READER — 403 all-NUL at Security Reader alone
	// (live-measured 2026-07-23, before and after the grant).
	inboundCmdlet  = "Get-InboundConnector"
	outboundCmdlet = "Get-OutboundConnector"
	// interval: connector configuration changes when an admin edits it.
	interval = time.Hour
)

// direction values. This is graph2otel's own axis — which cmdlet the record came
// from — not a wire field, because the record itself does not say.
const (
	directionInbound  = "inbound"
	directionOutbound = "outbound"
)

// ConnectorSource values that mean "a tool created this as part of a supported
// topology", as opposed to sourceAdminUI, which means a human made it by hand.
const (
	sourceAdminUI      = "AdminUI"
	sourceHybridWizard = "HybridWizard"
)

// Wire field names, read by exact name so the "<Name>@data.type" sidecars are
// ignored.
const (
	fieldEnabled                      = "Enabled"
	fieldConnectorType                = "ConnectorType"
	fieldConnectorSource              = "ConnectorSource"
	fieldComment                      = "Comment"
	fieldSenderIPAddresses            = "SenderIPAddresses"
	fieldSenderDomains                = "SenderDomains"
	fieldTrustedOrganizations         = "TrustedOrganizations"
	fieldClientHostNames              = "ClientHostNames"
	fieldAssociatedAcceptedDomains    = "AssociatedAcceptedDomains"
	fieldRequireTLS                   = "RequireTls"
	fieldRestrictDomainsToIPAddresses = "RestrictDomainsToIPAddresses"
	fieldRestrictDomainsToCertificate = "RestrictDomainsToCertificate"
	fieldCloudServicesMailEnabled     = "CloudServicesMailEnabled"
	fieldTreatMessagesAsInternal      = "TreatMessagesAsInternal"
	fieldTLSSenderCertificateName     = "TlsSenderCertificateName"
	fieldEFTestMode                   = "EFTestMode"
	fieldEFSkipLastIP                 = "EFSkipLastIP"
	fieldEFSkipIPs                    = "EFSkipIPs"
	fieldEFSkipMailGateway            = "EFSkipMailGateway"
	fieldEFUsers                      = "EFUsers"
	fieldScanAndDropRecipients        = "ScanAndDropRecipients"
	fieldAdminDisplayName             = "AdminDisplayName"
	fieldName                         = "Name"
	fieldIdentity                     = "Identity"
	fieldGuid                         = "Guid"
	fieldIsValid                      = "IsValid"
	fieldWhenChangedUTC               = "WhenChangedUTC"
	fieldWhenCreatedUTC               = "WhenCreatedUTC"
)

// Collector reads Exchange Online inbound and outbound connectors.
type Collector struct {
	c collectors.EXOClient
}

// New builds the connector collector.
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
// vocabulary (Exchange.ManageAsApp + an Entra directory role).
func (c *Collector) RequiredPermissions() []string { return nil }

// Collect runs both cmdlets and emits the gauges plus a twin per connector.
func (c *Collector) Collect(ctx context.Context, e telemetry.Emitter) error {
	// Stamp the transport HERE: with no ingest engine on this path the Scheduler
	// baseline is TransportGraph.
	e = telemetry.WithTransport(e, telemetry.TransportExchangeOnline)

	// counts is seeded with every (direction, enabled) combination so all four
	// series exist even on a tenant with no connectors at all.
	counts := map[[2]string]float64{}
	noTLS := map[string]float64{directionInbound: 0, directionOutbound: 0}
	for _, dir := range []string{directionInbound, directionOutbound} {
		for _, en := range []string{"true", "false"} {
			counts[[2]string{dir, en}] = 0
		}
	}

	for _, side := range []struct {
		cmdlet    string
		direction string
	}{
		{inboundCmdlet, directionInbound},
		{outboundCmdlet, directionOutbound},
	} {
		recs, err := c.c.Invoke(ctx, side.cmdlet, nil)
		if err != nil {
			return fmt.Errorf("%s: %w", side.cmdlet, err)
		}
		for _, r := range recs {
			counts[[2]string{side.direction, boolStr(boolVal(r, fieldEnabled))}]++
			if !boolVal(r, fieldRequireTLS) {
				noTLS[side.direction]++
			}
			e.LogEvent(connectorTwin(r, side.direction))
		}
	}

	connectorPoints := make([]telemetry.GaugePoint, 0, len(counts))
	for k, v := range counts {
		connectorPoints = append(connectorPoints, telemetry.GaugePoint{
			Value: v,
			Attrs: telemetry.Attrs{semconv.AttrDirection: k[0], semconv.AttrEnabled: k[1]},
		})
	}
	e.GaugeSnapshot(metricConnectors, unitConnector,
		"Exchange Online mail-flow connectors by direction and enabled state. All four series are seeded, so a connector appearing on a tenant that had none is a change from 0 rather than a new series. A connector is mail ROUTING — an outbound one can send the tenant's mail through infrastructure Microsoft does not own, and an inbound one can let mail arrive pre-trusted. Which connector, where it points and whether it demands TLS live on the m365.exchange_connector log twin.",
		connectorPoints)

	e.GaugeSnapshot(metricWithoutTLS, unitConnector,
		"Exchange Online connectors that do not require TLS, by direction. Mail crossing such a connector is neither encrypted nor authenticated in transit, so an inbound one is a channel for mail to arrive pre-trusted over cleartext.",
		[]telemetry.GaugePoint{
			{Value: noTLS[directionInbound], Attrs: telemetry.Attrs{semconv.AttrDirection: directionInbound}},
			{Value: noTLS[directionOutbound], Attrs: telemetry.Attrs{semconv.AttrDirection: directionOutbound}},
		})
	return nil
}

// connectorTwin renders one connector as a log record.
//
// The severity ladder encodes the threat model. An ENABLED OUTBOUND connector is
// Error whatever else it says: it exists to send the tenant's mail somewhere
// Microsoft does not control, which is the relay/exfiltration shape, and TLS on
// that path protects the hop without making the destination legitimate. Inbound,
// the danger is mail arriving pre-trusted; without RequireTls that channel is
// unauthenticated too, so an enabled cleartext inbound connector is also Error.
// An enabled inbound connector that does demand TLS is a deliberate, common
// hybrid arrangement and rates Warn — worth seeing, not worth paging.
//
// A DISABLED connector is one toggle away from live, so a hand-created one still
// rates Warn, the same reasoning m365.exchange_transport_rules applies to a
// disabled redirecting rule. A disabled connector the hybrid wizard or the
// service itself created is expected furniture and rates Info.
func connectorTwin(r map[string]any, direction string) telemetry.Event {
	name := str(r, fieldName)
	enabled := boolVal(r, fieldEnabled)
	requireTLS := boolVal(r, fieldRequireTLS)
	handMade := str(r, fieldConnectorSource) == sourceAdminUI

	attrs := telemetry.Attrs{}
	telemetry.SetStr(attrs, semconv.AttrDirection, direction)
	telemetry.SetStr(attrs, semconv.AttrName, name)
	telemetry.SetStr(attrs, semconv.AttrIdentity, str(r, fieldIdentity))
	telemetry.SetStr(attrs, semconv.AttrId, str(r, fieldGuid))
	telemetry.SetBool(attrs, semconv.AttrEnabled, enabled)
	telemetry.SetStr(attrs, semconv.AttrConnectorType, str(r, fieldConnectorType))
	telemetry.SetStr(attrs, semconv.AttrConnectorSource, str(r, fieldConnectorSource))
	telemetry.SetStr(attrs, semconv.AttrComment, str(r, fieldComment))
	telemetry.SetStr(attrs, semconv.AttrAdminDisplayName, str(r, fieldAdminDisplayName))
	telemetry.SetBool(attrs, semconv.AttrRequireTls, requireTLS)
	telemetry.SetBool(attrs, semconv.AttrRestrictDomainsToIpAddresses, boolVal(r, fieldRestrictDomainsToIPAddresses))
	telemetry.SetBool(attrs, semconv.AttrRestrictDomainsToCertificate, boolVal(r, fieldRestrictDomainsToCertificate))
	telemetry.SetBool(attrs, semconv.AttrCloudServicesMailEnabled, boolVal(r, fieldCloudServicesMailEnabled))
	telemetry.SetBool(attrs, semconv.AttrTreatMessagesAsInternal, boolVal(r, fieldTreatMessagesAsInternal))
	telemetry.SetBool(attrs, semconv.AttrEnhancedFilteringTestMode, boolVal(r, fieldEFTestMode))
	telemetry.SetBool(attrs, semconv.AttrEnhancedFilteringSkipLastIp, boolVal(r, fieldEFSkipLastIP))
	telemetry.SetBool(attrs, semconv.AttrIsValid, boolVal(r, fieldIsValid))
	telemetry.SetStr(attrs, semconv.AttrWhenCreated, str(r, fieldWhenCreatedUTC))
	telemetry.SetStr(attrs, semconv.AttrWhenChanged, str(r, fieldWhenChangedUTC))
	// TlsSenderCertificateName is null when no certificate is pinned — omitted
	// rather than stamped empty, so "no certificate" and "" stay distinguishable.
	telemetry.SetStr(attrs, semconv.AttrTlsSenderCertificateName, str(r, fieldTLSSenderCertificateName))
	// The list fields are where a connector actually says what it trusts. Emitted
	// verbatim, priority suffixes and all (#142) — "smtp:*;1" is the wire value,
	// not something to parse into a domain and a number.
	setStrList(attrs, semconv.AttrSenderIpAddresses, r, fieldSenderIPAddresses)
	setStrList(attrs, semconv.AttrSenderDomains, r, fieldSenderDomains)
	setStrList(attrs, semconv.AttrTrustedOrganizations, r, fieldTrustedOrganizations)
	setStrList(attrs, semconv.AttrClientHostNames, r, fieldClientHostNames)
	setStrList(attrs, semconv.AttrAssociatedAcceptedDomains, r, fieldAssociatedAcceptedDomains)
	setStrList(attrs, semconv.AttrScanAndDropRecipients, r, fieldScanAndDropRecipients)
	setStrList(attrs, semconv.AttrEnhancedFilteringSkipIps, r, fieldEFSkipIPs)
	setStrList(attrs, semconv.AttrEnhancedFilteringSkipMailGateway, r, fieldEFSkipMailGateway)
	setStrList(attrs, semconv.AttrEnhancedFilteringUsers, r, fieldEFUsers)

	sev := telemetry.SeverityInfo
	body := fmt.Sprintf("%s connector %q: enabled=%t require_tls=%t source=%s",
		direction, name, enabled, requireTLS, str(r, fieldConnectorSource))
	switch {
	case enabled && direction == directionOutbound:
		sev = telemetry.SeverityError
		body = fmt.Sprintf("outbound connector %q is ENABLED — tenant mail is routed through infrastructure outside Exchange Online", name)
	case enabled && !requireTLS:
		sev = telemetry.SeverityError
		body = fmt.Sprintf("inbound connector %q is ENABLED and does not require TLS — mail can arrive pre-trusted over an unauthenticated channel", name)
	case enabled:
		sev = telemetry.SeverityWarn
		body = fmt.Sprintf("inbound connector %q is enabled (TLS required) — mail crossing it arrives pre-trusted", name)
	case handMade:
		sev = telemetry.SeverityWarn
		body = fmt.Sprintf("%s connector %q is hand-created and disabled — one toggle from live", direction, name)
	}
	return telemetry.Event{Name: eventName, Body: body, Severity: sev, Attrs: attrs}
}

// str reads a string column, "" when absent, null or non-string. Reading by
// exact name ignores the "<Name>@data.type" sidecars.
func str(m map[string]any, key string) string {
	s, _ := m[key].(string)
	return s
}

// boolVal reads a boolean column, false when absent or non-bool.
func boolVal(m map[string]any, key string) bool {
	b, _ := m[key].(bool)
	return b
}

// boolStr renders a bool as the metric label value.
func boolStr(b bool) string {
	if b {
		return "true"
	}
	return "false"
}

// setStrList stamps a JSON array of strings as one comma-joined attribute, and
// omits it entirely when the array is empty — an empty list means "nothing is
// trusted here", which an empty string would render indistinguishable from a
// field that was never sent. Same shape as exchangemailboxes' joinStrings.
//
// NOT telemetry.SetList, which splits its argument on WHITESPACE: a connector's
// values contain none, so every joined list would arrive as a single-element
// slice still holding the commas.
func setStrList(attrs telemetry.Attrs, key string, m map[string]any, field string) {
	raw, ok := m[field].([]any)
	if !ok || len(raw) == 0 {
		return
	}
	vals := make([]string, 0, len(raw))
	for _, v := range raw {
		if s, ok := v.(string); ok && s != "" {
			vals = append(vals, s)
		}
	}
	telemetry.SetStr(attrs, key, strings.Join(vals, ","))
}

func init() {
	collectors.RegisterEXO(func(d collectors.EXODeps) collector.SnapshotCollector { return New(d) })
}

var _ collector.SnapshotCollector = (*Collector)(nil)
