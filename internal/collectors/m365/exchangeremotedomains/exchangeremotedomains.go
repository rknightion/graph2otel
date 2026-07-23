// Package exchangeremotedomains is the Exchange Online remote-domain collector
// (#250), read over the Exchange Online admin API's app-only cmdlet transport
// (internal/exoclient).
//
// # Why this matters
//
// A remote domain entry decides what Exchange Online will do with mail addressed
// OUTSIDE the tenant, and its AutoForwardEnabled flag is the tenant-wide switch
// for automatic external forwarding — the classic mailbox-rule exfiltration
// path. Microsoft's own hardening guidance is to turn it off, and no Graph
// endpoint reports it.
//
// The entry whose DomainName is "*" applies to EVERY remote domain, so forwarding
// enabled there is a tenant-wide hole; the same flag on a named partner domain is
// a narrower, usually deliberate decision. The severity rule separates the two —
// collapsing them would either cry wolf on every tenant with one partner
// exception, or stay quiet on a tenant that allows forwarding everywhere.
//
// # Both sides of the cardinality boundary
//
// From one cmdlet call:
//
//   - a bounded GAUGE m365.exchange.remote_domains{auto_forward_enabled} — two
//     series, both seeded, so "forwarding is off everywhere" is a visible 0 on
//     the true bucket rather than a missing series;
//   - one LOG twin per domain carrying the domain name, the OOF policy, the
//     reply/report/NDR flags and the trusted-mail toggles.
//
// # Tri-state booleans (live-measured 2026-07-23)
//
// TNEFEnabled and RequiredCharsetCoverage arrive as null, which means "use the
// default", NOT "disabled". Stamping false there would assert a setting the
// tenant never made, so optBool omits them instead. The flags this collector
// actually reasons about (AutoForwardEnabled and friends) are real JSON bools.
//
// A state snapshot, not an event stream: the twins are stamped at poll time.
package exchangeremotedomains

import (
	"context"
	"fmt"
	"time"

	"github.com/rknightion/graph2otel/internal/collector"
	"github.com/rknightion/graph2otel/internal/collectors"
	"github.com/rknightion/graph2otel/internal/semconv"
	"github.com/rknightion/graph2otel/internal/telemetry"
)

const (
	// collectorName is the stable key for config, self-observability and the
	// admin status page.
	collectorName = "m365.exchange_remote_domains"
	// eventName is the OTLP LogRecord EventName each domain twin carries.
	eventName = "m365.exchange_remote_domain"
	// metricDomains counts remote domains by whether they permit auto-forwarding.
	metricDomains = "m365.exchange.remote_domains"
	// unitDomain is the annotation unit for a countable domain.
	unitDomain = "{domain}"
	// cmdlet is the single Exchange Online cmdlet this collector runs.
	cmdlet = "Get-RemoteDomain"
	// interval: remote-domain policy changes when an admin edits it.
	interval = time.Hour
	// wildcardDomain is the DomainName that means "every remote domain".
	wildcardDomain = "*"
)

// Wire field names, read by exact name so the "<Name>@data.type" sidecars are
// ignored.
const (
	fieldDomainName                        = "DomainName"
	fieldName                              = "Name"
	fieldGuid                              = "Guid"
	fieldIsInternal                        = "IsInternal"
	fieldTargetDeliveryDomain              = "TargetDeliveryDomain"
	fieldAllowedOOFType                    = "AllowedOOFType"
	fieldAutoReplyEnabled                  = "AutoReplyEnabled"
	fieldAutoForwardEnabled                = "AutoForwardEnabled"
	fieldDeliveryReportEnabled             = "DeliveryReportEnabled"
	fieldNDREnabled                        = "NDREnabled"
	fieldNDRDiagnosticInfoEnabled          = "NDRDiagnosticInfoEnabled"
	fieldMeetingForwardNotificationEnabled = "MeetingForwardNotificationEnabled"
	fieldContentType                       = "ContentType"
	fieldDisplaySenderName                 = "DisplaySenderName"
	fieldCharacterSet                      = "CharacterSet"
	fieldNonMimeCharacterSet               = "NonMimeCharacterSet"
	fieldTNEFEnabled                       = "TNEFEnabled"
	fieldLineWrapSize                      = "LineWrapSize"
	fieldTrustedMailInboundEnabled         = "TrustedMailInboundEnabled"
	fieldTrustedMailOutboundEnabled        = "TrustedMailOutboundEnabled"
	fieldUseSimpleDisplayName              = "UseSimpleDisplayName"
	fieldIsValid                           = "IsValid"
	fieldWhenChanged                       = "WhenChanged"
	fieldWhenCreated                       = "WhenCreated"
)

// Collector reads Exchange Online remote-domain configuration.
type Collector struct {
	c collectors.EXOClient
}

// New builds the remote-domain collector.
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
// vocabulary (Exchange.ManageAsApp + a directory role). Get-RemoteDomain needs
// GLOBAL READER — it is 403 all-NUL at Security Reader alone (live-measured
// 2026-07-23, both before and after the grant).
func (c *Collector) RequiredPermissions() []string { return nil }

// Collect runs the cmdlet and emits the gauge plus a twin per domain.
func (c *Collector) Collect(ctx context.Context, e telemetry.Emitter) error {
	// Stamp the transport HERE: with no ingest engine on this path the Scheduler
	// baseline is TransportGraph.
	e = telemetry.WithTransport(e, telemetry.TransportExchangeOnline)

	recs, err := c.c.Invoke(ctx, cmdlet, nil)
	if err != nil {
		return fmt.Errorf("%s: %w", cmdlet, err)
	}

	counts := map[bool]float64{true: 0, false: 0}
	for _, r := range recs {
		counts[boolVal(r, fieldAutoForwardEnabled)]++
		e.LogEvent(domainTwin(r))
	}

	e.GaugeSnapshot(metricDomains, unitDomain,
		"Exchange Online remote domains by whether they permit automatic external forwarding. The entry whose domain is \"*\" covers EVERY remote domain, so a non-zero true bucket may be one tenant-wide hole rather than a narrow exception — which domain it is lives on the m365.exchange_remote_domain log twin.",
		[]telemetry.GaugePoint{
			{Value: counts[true], Attrs: telemetry.Attrs{semconv.AttrAutoForwardEnabled: "true"}},
			{Value: counts[false], Attrs: telemetry.Attrs{semconv.AttrAutoForwardEnabled: "false"}},
		})
	return nil
}

// domainTwin renders one remote domain as a log record. Auto-forwarding on the
// wildcard domain is a tenant-wide exfiltration path and rates Error; on a named
// domain it is a narrower decision and rates Warn.
func domainTwin(r map[string]any) telemetry.Event {
	domain := str(r, fieldDomainName)
	forwards := boolVal(r, fieldAutoForwardEnabled)
	wildcard := domain == wildcardDomain

	attrs := telemetry.Attrs{}
	telemetry.SetStr(attrs, semconv.AttrDomain, domain)
	telemetry.SetStr(attrs, semconv.AttrName, str(r, fieldName))
	telemetry.SetStr(attrs, semconv.AttrId, str(r, fieldGuid))
	telemetry.SetBool(attrs, semconv.AttrAutoForwardEnabled, forwards)
	telemetry.SetBool(attrs, semconv.AttrAutoReplyEnabled, boolVal(r, fieldAutoReplyEnabled))
	telemetry.SetStr(attrs, semconv.AttrAllowedOofType, str(r, fieldAllowedOOFType))
	telemetry.SetBool(attrs, semconv.AttrIsInternal, boolVal(r, fieldIsInternal))
	telemetry.SetBool(attrs, semconv.AttrTargetDeliveryDomain, boolVal(r, fieldTargetDeliveryDomain))
	telemetry.SetBool(attrs, semconv.AttrDeliveryReportEnabled, boolVal(r, fieldDeliveryReportEnabled))
	telemetry.SetBool(attrs, semconv.AttrNdrEnabled, boolVal(r, fieldNDREnabled))
	telemetry.SetBool(attrs, semconv.AttrNdrDiagnosticInfoEnabled, boolVal(r, fieldNDRDiagnosticInfoEnabled))
	telemetry.SetBool(attrs, semconv.AttrMeetingForwardNotificationEnabled, boolVal(r, fieldMeetingForwardNotificationEnabled))
	telemetry.SetBool(attrs, semconv.AttrTrustedMailInboundEnabled, boolVal(r, fieldTrustedMailInboundEnabled))
	telemetry.SetBool(attrs, semconv.AttrTrustedMailOutboundEnabled, boolVal(r, fieldTrustedMailOutboundEnabled))
	telemetry.SetBool(attrs, semconv.AttrDisplaySenderName, boolVal(r, fieldDisplaySenderName))
	telemetry.SetBool(attrs, semconv.AttrUseSimpleDisplayName, boolVal(r, fieldUseSimpleDisplayName))
	telemetry.SetStr(attrs, semconv.AttrContentType, str(r, fieldContentType))
	telemetry.SetStr(attrs, semconv.AttrCharacterSet, str(r, fieldCharacterSet))
	telemetry.SetStr(attrs, semconv.AttrNonMimeCharacterSet, str(r, fieldNonMimeCharacterSet))
	telemetry.SetStr(attrs, semconv.AttrLineWrapSize, str(r, fieldLineWrapSize))
	telemetry.SetStr(attrs, semconv.AttrWhenChanged, str(r, fieldWhenChanged))
	telemetry.SetStr(attrs, semconv.AttrWhenCreated, str(r, fieldWhenCreated))
	telemetry.SetBool(attrs, semconv.AttrIsValid, boolVal(r, fieldIsValid))
	// Tri-state: null means "use the default", so it is omitted rather than
	// asserted false.
	optBool(attrs, semconv.AttrTnefEnabled, r, fieldTNEFEnabled)

	sev := telemetry.SeverityInfo
	body := fmt.Sprintf("remote domain %q: auto_forward=%t oof=%s", domain, forwards, str(r, fieldAllowedOOFType))
	switch {
	case forwards && wildcard:
		sev = telemetry.SeverityError
		body = fmt.Sprintf("remote domain %q permits automatic external forwarding to EVERY remote domain — a tenant-wide exfiltration path", domain)
	case forwards:
		sev = telemetry.SeverityWarn
		body = fmt.Sprintf("remote domain %q permits automatic external forwarding", domain)
	}
	return telemetry.Event{Name: eventName, Body: body, Severity: sev, Attrs: attrs}
}

// str reads a string column, "" when absent or non-string. Reading by exact name
// ignores the "<Name>@data.type" sidecars.
func str(m map[string]any, key string) string {
	s, _ := m[key].(string)
	return s
}

// boolVal reads a boolean column, false when absent or non-bool.
func boolVal(m map[string]any, key string) bool {
	b, _ := m[key].(bool)
	return b
}

// optBool stamps a boolean ONLY when the wire carried a real bool. A tri-state
// field arriving as null means "use the default" and must not be reported as
// false.
func optBool(attrs telemetry.Attrs, key string, m map[string]any, field string) {
	if b, ok := m[field].(bool); ok {
		telemetry.SetBool(attrs, key, b)
	}
}

func init() {
	collectors.RegisterEXO(func(d collectors.EXODeps) collector.SnapshotCollector { return New(d) })
}

var _ collector.SnapshotCollector = (*Collector)(nil)
