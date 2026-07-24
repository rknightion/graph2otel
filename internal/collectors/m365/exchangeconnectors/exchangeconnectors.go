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
// # The two directions are DIFFERENT RECORD SHAPES, not one shape with extras
//
// This is the fact the collector is built around, and it was only settled when an
// outbound connector first existed on m7kni (live-measured 2026-07-24, #253).
// The two cmdlets return overlapping but distinct field sets:
//
//   - INBOUND-only: RequireTls, SenderIPAddresses, SenderDomains,
//     TrustedOrganizations, ClientHostNames, AssociatedAcceptedDomains,
//     RestrictDomainsTo{IPAddresses,Certificate}, TreatMessagesAsInternal,
//     TlsSenderCertificateName, ScanAndDropRecipients, every EF* field.
//   - OUTBOUND-only: SmartHosts, RecipientDomains, UseMXRecord,
//     RouteAllMessagesViaOnPremises, IsTransportRuleScoped, AllAcceptedDomains,
//     SenderRewritingEnabled, TestMode, TlsSettings, TlsDomain, MtaStsMode,
//     SmtpDaneMode, ValidationRecipients, IsValidated,
//     LastValidationTimestamp.
//   - Shared: Enabled, ConnectorType, ConnectorSource, Comment,
//     CloudServicesMailEnabled, AdminDisplayName, Name, Identity, Guid, IsValid,
//     WhenCreatedUTC, WhenChangedUTC.
//
// Two consequences drive the code, and both were live DEFECTS in the first
// version rather than hypotheticals:
//
//  1. A boolean is stamped only when the wire carried one (setBoolIfPresent).
//     An unconditional stamp published six fabricated `false` values on every
//     outbound twin — each a positive claim that a mail-security control was off,
//     about a field Microsoft never sent.
//  2. TLS is read per direction (hasTLS). Inbound uses the boolean RequireTls;
//     outbound has no such field and uses the TlsSettings enum. Reading
//     RequireTls off an outbound record returned false every time, so the
//     without_tls gauge counted EVERY outbound connector as cleartext — a wrong
//     number on a security posture metric, not a missing attribute.
//
// TlsSettings' member names are deliberately NOT enumerated anywhere here: one
// value ("CertificateValidation") has ever been observed, and the rest would have
// to come from documentation (#142/#165). Presence of a non-empty setting is the
// honest test a single sample supports.
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

// OUTBOUND-only wire field names, read from the one verbatim
// Get-OutboundConnector record ever observed (m7kni, live-measured 2026-07-24).
// None of these appears on an inbound record, and none of the inbound-only
// fields above appears here.
const (
	fieldSmartHosts                = "SmartHosts"
	fieldRecipientDomains          = "RecipientDomains"
	fieldUseMXRecord               = "UseMXRecord"
	fieldRouteAllMessagesViaOnPrem = "RouteAllMessagesViaOnPremises"
	fieldIsTransportRuleScoped     = "IsTransportRuleScoped"
	fieldAllAcceptedDomains        = "AllAcceptedDomains"
	fieldSenderRewritingEnabled    = "SenderRewritingEnabled"
	fieldTestMode                  = "TestMode"
	fieldTLSSettings               = "TlsSettings"
	fieldTLSDomain                 = "TlsDomain"
	fieldMtaStsMode                = "MtaStsMode"
	fieldSmtpDaneMode              = "SmtpDaneMode"
	fieldValidationRecipients      = "ValidationRecipients"
	fieldIsValidated               = "IsValidated"
	fieldLastValidationTimestamp   = "LastValidationTimestamp"
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
			if !hasTLS(r, side.direction) {
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
	requireTLS := hasTLS(r, direction)
	handMade := str(r, fieldConnectorSource) == sourceAdminUI

	attrs := telemetry.Attrs{}
	// Fields present on BOTH record shapes.
	telemetry.SetStr(attrs, semconv.AttrDirection, direction)
	telemetry.SetStr(attrs, semconv.AttrName, name)
	telemetry.SetStr(attrs, semconv.AttrIdentity, str(r, fieldIdentity))
	telemetry.SetStr(attrs, semconv.AttrId, str(r, fieldGuid))
	telemetry.SetBool(attrs, semconv.AttrEnabled, enabled)
	telemetry.SetStr(attrs, semconv.AttrConnectorType, str(r, fieldConnectorType))
	telemetry.SetStr(attrs, semconv.AttrConnectorSource, str(r, fieldConnectorSource))
	telemetry.SetStr(attrs, semconv.AttrComment, str(r, fieldComment))
	telemetry.SetStr(attrs, semconv.AttrAdminDisplayName, str(r, fieldAdminDisplayName))
	setBoolIfPresent(attrs, semconv.AttrCloudServicesMailEnabled, r, fieldCloudServicesMailEnabled)
	setBoolIfPresent(attrs, semconv.AttrIsValid, r, fieldIsValid)
	telemetry.SetStr(attrs, semconv.AttrWhenCreated, str(r, fieldWhenCreatedUTC))
	telemetry.SetStr(attrs, semconv.AttrWhenChanged, str(r, fieldWhenChangedUTC))

	// INBOUND-only. Every one of these is ABSENT from an outbound record, so each
	// is stamped only when the wire actually carried it (live-measured
	// 2026-07-24). An unconditional bool stamp here published six fabricated
	// `false` values on every outbound twin — a positive claim that a security
	// control was off, about a field Microsoft never sent.
	setBoolIfPresent(attrs, semconv.AttrRequireTls, r, fieldRequireTLS)
	setBoolIfPresent(attrs, semconv.AttrRestrictDomainsToIpAddresses, r, fieldRestrictDomainsToIPAddresses)
	setBoolIfPresent(attrs, semconv.AttrRestrictDomainsToCertificate, r, fieldRestrictDomainsToCertificate)
	setBoolIfPresent(attrs, semconv.AttrTreatMessagesAsInternal, r, fieldTreatMessagesAsInternal)
	setBoolIfPresent(attrs, semconv.AttrEnhancedFilteringTestMode, r, fieldEFTestMode)
	setBoolIfPresent(attrs, semconv.AttrEnhancedFilteringSkipLastIp, r, fieldEFSkipLastIP)
	// TlsSenderCertificateName is null when no certificate is pinned — omitted
	// rather than stamped empty, so "no certificate" and "" stay distinguishable.
	telemetry.SetStr(attrs, semconv.AttrTlsSenderCertificateName, str(r, fieldTLSSenderCertificateName))
	// The list fields are where an INBOUND connector says what it trusts. Emitted
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

	// OUTBOUND-only. SmartHosts and RecipientDomains are the pair that answer
	// WHERE THE MAIL GOES — the single most useful fact about an outbound
	// connector, and the gap #253 stayed open for.
	setStrList(attrs, semconv.AttrSmartHosts, r, fieldSmartHosts)
	setStrList(attrs, semconv.AttrRecipientDomains, r, fieldRecipientDomains)
	setStrList(attrs, semconv.AttrValidationRecipients, r, fieldValidationRecipients)
	setBoolIfPresent(attrs, semconv.AttrUseMxRecord, r, fieldUseMXRecord)
	setBoolIfPresent(attrs, semconv.AttrRouteAllMessagesViaOnPremises, r, fieldRouteAllMessagesViaOnPrem)
	setBoolIfPresent(attrs, semconv.AttrIsTransportRuleScoped, r, fieldIsTransportRuleScoped)
	setBoolIfPresent(attrs, semconv.AttrAllAcceptedDomains, r, fieldAllAcceptedDomains)
	setBoolIfPresent(attrs, semconv.AttrSenderRewritingEnabled, r, fieldSenderRewritingEnabled)
	setBoolIfPresent(attrs, semconv.AttrTestMode, r, fieldTestMode)
	setBoolIfPresent(attrs, semconv.AttrIsValidated, r, fieldIsValidated)
	// TlsSettings / TlsDomain are outbound's TLS axis — an enum string plus an
	// optional pinned domain, NOT the inbound boolean. Emitted verbatim; the
	// member names are deliberately not enumerated anywhere in this collector,
	// because exactly one value has ever been observed on the wire.
	telemetry.SetStr(attrs, semconv.AttrTlsSettings, str(r, fieldTLSSettings))
	telemetry.SetStr(attrs, semconv.AttrTlsDomain, str(r, fieldTLSDomain))
	telemetry.SetStr(attrs, semconv.AttrMtaStsMode, str(r, fieldMtaStsMode))
	telemetry.SetStr(attrs, semconv.AttrSmtpDaneMode, str(r, fieldSmtpDaneMode))
	telemetry.SetStr(attrs, semconv.AttrLastValidationTimestamp, str(r, fieldLastValidationTimestamp))

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

// setBoolIfPresent stamps a boolean attribute ONLY when the wire actually
// carried a bool for it.
//
// The two connector record shapes overlap in only a handful of fields, so
// reading an inbound-only boolean off an outbound record yields "absent" — and
// an unconditional stamp renders that as a confident `false`. On a record
// describing mail-flow security controls, a fabricated `false` is a claim that a
// protection is switched off. Absent and off are different answers and this keeps
// them different (live-measured 2026-07-24, #253; same class as the
// zero-is-absent traps in intune.hardware_inventory).
func setBoolIfPresent(attrs telemetry.Attrs, key string, m map[string]any, field string) {
	if b, ok := m[field].(bool); ok {
		telemetry.SetBool(attrs, key, b)
	}
}

// hasTLS reports whether a connector demands TLS, reading whichever field its
// direction actually uses.
//
// The two directions express this DIFFERENTLY, and conflating them is a wrong
// number rather than a cosmetic slip: inbound carries the boolean RequireTls,
// while an outbound record has no such field and instead carries TlsSettings, an
// enum string (plus an optional TlsDomain). Reading RequireTls off an outbound
// record therefore returned false for every outbound connector ever, so the
// without_tls gauge counted them all as cleartext regardless of their real
// configuration.
//
// Outbound is judged by TlsSettings being NON-EMPTY rather than by matching
// member names. Exactly one value has been observed on the wire
// ("CertificateValidation", live-measured 2026-07-24); enumerating the others
// would mean taking them from documentation, which is how a mapper ends up
// matching nothing and looking healthy (#142/#165). Presence is the honest test
// the single sample supports.
func hasTLS(r map[string]any, direction string) bool {
	if direction == directionOutbound {
		return strings.TrimSpace(str(r, fieldTLSSettings)) != ""
	}
	return boolVal(r, fieldRequireTLS)
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
