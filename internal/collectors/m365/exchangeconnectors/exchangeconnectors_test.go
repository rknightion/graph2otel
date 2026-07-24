package exchangeconnectors

import (
	"context"
	"encoding/json"
	"errors"
	"testing"

	"github.com/rknightion/graph2otel/internal/collectors"
	"github.com/rknightion/graph2otel/internal/semconv"
	"github.com/rknightion/graph2otel/internal/telemetry"
	"github.com/rknightion/graph2otel/internal/telemetrytest"
)

// liveInboundTLS and liveInboundNoTLS are VERBATIM Get-InboundConnector records
// captured from the m7kni tenant as graph2otel-poller on 2026-07-23 over the
// Exchange Online admin API. Both connectors on that tenant are disabled and
// hand-created (ConnectorSource "AdminUI"); they differ in exactly the axis this
// collector reasons about — one requires TLS and pins a certificate, the other
// takes cleartext from a bare sender IP.
//
// Note "smtp:*;1" in SenderDomains: the ";1" suffix is a priority, part of the
// wire value, and is emitted verbatim rather than parsed (#142).
const liveInboundTLS = `{
  "Enabled": false,
  "ConnectorType": "OnPremises",
  "ConnectorSource": "AdminUI",
  "Comment": "test connector for poller",
  "SenderIPAddresses": [],
  "SenderDomains": ["smtp:*;1"],
  "TrustedOrganizations": [],
  "ClientHostNames": [],
  "AssociatedAcceptedDomains": [],
  "RequireTls": true,
  "RestrictDomainsToIPAddresses": false,
  "RestrictDomainsToCertificate": false,
  "CloudServicesMailEnabled": true,
  "TreatMessagesAsInternal": false,
  "TlsSenderCertificateName": "*.rob-knight.com",
  "EFTestMode": false,
  "ScanAndDropRecipients": [],
  "EFSkipLastIP": false,
  "EFSkipIPs": [],
  "EFSkipMailGateway": [],
  "EFUsers": [],
  "AdminDisplayName": "",
  "Name": "connectortest",
  "Identity": "connectortest",
  "WhenChangedUTC": "2026-07-23T22:55:13.0000000Z",
  "WhenCreatedUTC": "2026-07-23T22:55:04.0000000Z",
  "Guid": "ac4d5ab0-6637-4e91-8d47-f5c2e95c71d9",
  "IsValid": true
}`

const liveInboundNoTLS = `{
  "Enabled": false,
  "ConnectorType": "OnPremises",
  "ConnectorSource": "AdminUI",
  "Comment": "",
  "SenderIPAddresses": ["81.187.237.31"],
  "SenderDomains": ["smtp:*;1"],
  "TrustedOrganizations": [],
  "ClientHostNames": [],
  "AssociatedAcceptedDomains": [],
  "RequireTls": false,
  "RestrictDomainsToIPAddresses": false,
  "RestrictDomainsToCertificate": false,
  "CloudServicesMailEnabled": false,
  "TreatMessagesAsInternal": false,
  "TlsSenderCertificateName": null,
  "EFTestMode": false,
  "ScanAndDropRecipients": [],
  "EFSkipLastIP": false,
  "EFSkipIPs": [],
  "EFSkipMailGateway": [],
  "EFUsers": [],
  "AdminDisplayName": "",
  "Name": "myorgemail",
  "Identity": "myorgemail",
  "WhenChangedUTC": "2026-07-23T22:55:49.0000000Z",
  "WhenCreatedUTC": "2026-07-23T22:55:43.0000000Z",
  "Guid": "acc2eccd-550f-4efa-9905-46054a5f516a",
  "IsValid": true
}`

// liveOutbound is a VERBATIM Get-OutboundConnector record captured from m7kni as
// graph2otel-poller on 2026-07-24, the day an outbound connector first existed on
// this tenant (#253's unblock condition). It is the ONLY outbound record ever
// observed, and it settles the question the collector previously had to guess at.
//
// The outbound record is NOT the inbound record with extra fields — it is a
// DIFFERENT SHAPE. It carries none of RequireTls, SenderIPAddresses,
// SenderDomains, TrustedOrganizations, ClientHostNames,
// AssociatedAcceptedDomains, RestrictDomainsToIPAddresses,
// RestrictDomainsToCertificate, TreatMessagesAsInternal,
// TlsSenderCertificateName, ScanAndDropRecipients or any EF* field. Reading those
// off an outbound record does not return false — it returns "absent", which a
// bool decode silently renders as false.
//
// Outbound TLS is a different axis entirely: TlsSettings (an enum string) plus
// TlsDomain, not the inbound boolean RequireTls.
const liveOutbound = `{
  "Enabled": true,
  "UseMXRecord": false,
  "Comment": "for graph2otel test",
  "ConnectorType": "OnPremises",
  "ConnectorSource": "AdminUI",
  "RecipientDomains": [],
  "SmartHosts": ["smtp-relay.gmail.com"],
  "TlsDomain": null,
  "TlsSettings": "CertificateValidation",
  "IsTransportRuleScoped": true,
  "RouteAllMessagesViaOnPremises": false,
  "CloudServicesMailEnabled": true,
  "AllAcceptedDomains": false,
  "SenderRewritingEnabled": false,
  "MtaStsMode": "Opportunistic",
  "SmtpDaneMode": "Opportunistic",
  "TestMode": false,
  "ValidationRecipients": ["rob@m7kni.io"],
  "IsValidated": false,
  "LastValidationTimestamp": "2026-07-24T18:59:12.0000000",
  "AdminDisplayName": "",
  "Name": "outbourconnection",
  "Identity": "outbourconnection",
  "WhenChangedUTC": "2026-07-24T19:01:54.0000000Z",
  "WhenCreatedUTC": "2026-07-24T18:58:31.0000000Z",
  "Guid": "d0d71cb9-6105-410f-8193-3640e12852a5",
  "IsValid": true
}`

// fakeEXO answers each cmdlet from its own canned set, so a test can give
// inbound and outbound different populations — which is the whole point here,
// since the two cmdlets are separate calls.
type fakeEXO struct {
	byCmdlet map[string][]map[string]any
	err      error
	calls    []string
}

func (f *fakeEXO) Invoke(_ context.Context, cmdlet string, _ map[string]any) ([]map[string]any, error) {
	f.calls = append(f.calls, cmdlet)
	if f.err != nil {
		return nil, f.err
	}
	return f.byCmdlet[cmdlet], nil
}

func recordsFrom(t *testing.T, docs ...string) []map[string]any {
	t.Helper()
	out := make([]map[string]any, 0, len(docs))
	for _, d := range docs {
		var m map[string]any
		if err := json.Unmarshal([]byte(d), &m); err != nil {
			t.Fatalf("unmarshal fixture: %v", err)
		}
		out = append(out, m)
	}
	return out
}

func collectWith(t *testing.T, f *fakeEXO) *telemetrytest.Recorder {
	t.Helper()
	rec := telemetrytest.New()
	c := New(collectors.EXODeps{Client: f})
	if err := c.Collect(context.Background(), rec.Emitter()); err != nil {
		t.Fatalf("Collect: %v", err)
	}
	return rec
}

// liveTenant is m7kni exactly as it stands: two disabled inbound connectors and
// no outbound connector at all.
func liveTenant(t *testing.T) *fakeEXO {
	t.Helper()
	return &fakeEXO{byCmdlet: map[string][]map[string]any{
		inboundCmdlet: recordsFrom(t, liveInboundTLS, liveInboundNoTLS),
	}}
}

func TestCollect_RunsBothCmdlets(t *testing.T) {
	f := liveTenant(t)
	collectWith(t, f)
	want := map[string]bool{inboundCmdlet: false, outboundCmdlet: false}
	for _, c := range f.calls {
		if _, ok := want[c]; !ok {
			t.Errorf("unexpected cmdlet %q", c)
			continue
		}
		want[c] = true
	}
	for c, called := range want {
		if !called {
			t.Errorf("cmdlet %q was never run — a connector on that side would be invisible", c)
		}
	}
}

// TestCollect_EverySeriesIsSeeded: an outbound connector appearing on a tenant
// that had none is the alert this collector exists for. If the outbound series
// only materialized once a connector existed, that alert would have to fire on a
// series appearing from nothing, which no sane alert rule does.
func TestCollect_EverySeriesIsSeeded(t *testing.T) {
	rec := collectWith(t, &fakeEXO{})

	got := map[[2]string]float64{}
	for _, p := range rec.MetricPoints(metricConnectors) {
		got[[2]string{p.Attrs[semconv.AttrDirection], p.Attrs[semconv.AttrEnabled]}] = p.Value
	}
	for _, dir := range []string{directionInbound, directionOutbound} {
		for _, en := range []string{"true", "false"} {
			v, ok := got[[2]string{dir, en}]
			if !ok {
				t.Errorf("series {direction=%s,enabled=%s} missing on an empty tenant", dir, en)
				continue
			}
			if v != 0 {
				t.Errorf("series {direction=%s,enabled=%s} = %v on an empty tenant, want 0", dir, en, v)
			}
		}
	}
}

func TestCollect_CountsByDirectionAndEnabled(t *testing.T) {
	rec := collectWith(t, liveTenant(t))

	got := map[[2]string]float64{}
	for _, p := range rec.MetricPoints(metricConnectors) {
		got[[2]string{p.Attrs[semconv.AttrDirection], p.Attrs[semconv.AttrEnabled]}] = p.Value
	}
	if v := got[[2]string{directionInbound, "false"}]; v != 2 {
		t.Errorf("disabled inbound = %v, want 2", v)
	}
	if v := got[[2]string{directionInbound, "true"}]; v != 0 {
		t.Errorf("enabled inbound = %v, want 0", v)
	}
	if v := got[[2]string{directionOutbound, "false"}]; v != 0 {
		t.Errorf("disabled outbound = %v, want 0", v)
	}
}

// TestCollect_WithoutTLSGauge: accepting mail on a connector that does not
// require TLS is the concrete posture number, the counterpart of
// allow_block_list's non_expiring_allow gauge.
func TestCollect_WithoutTLSGauge(t *testing.T) {
	rec := collectWith(t, liveTenant(t))

	got := map[string]float64{}
	for _, p := range rec.MetricPoints(metricWithoutTLS) {
		got[p.Attrs[semconv.AttrDirection]] = p.Value
	}
	if v, ok := got[directionInbound]; !ok || v != 1 {
		t.Errorf("inbound without TLS = %v (present=%t), want 1", v, ok)
	}
	if v, ok := got[directionOutbound]; !ok || v != 0 {
		t.Errorf("outbound without TLS = %v (present=%t), want 0", v, ok)
	}
}

// tenantWithOutbound is m7kni on 2026-07-24: the two inbound connectors plus the
// one outbound connector whose shape this collector now maps.
func tenantWithOutbound(t *testing.T) *fakeEXO {
	t.Helper()
	return &fakeEXO{byCmdlet: map[string][]map[string]any{
		inboundCmdlet:  recordsFrom(t, liveInboundTLS, liveInboundNoTLS),
		outboundCmdlet: recordsFrom(t, liveOutbound),
	}}
}

// outboundTwin returns the twin for the one outbound connector.
func outboundTwin(t *testing.T, rec *telemetrytest.Recorder) map[string]string {
	t.Helper()
	for _, l := range rec.LogRecords() {
		if l.EventName == eventName && l.Attrs[semconv.AttrDirection] == directionOutbound {
			return l.Attrs
		}
	}
	t.Fatal("no outbound twin emitted")
	return nil
}

// TestConnectorTwin_OutboundOmitsFieldsAbsentFromTheWire is the guard against
// this collector's own worst failure mode, and it is not hypothetical: the first
// version read RequireTls, RestrictDomainsToIPAddresses,
// RestrictDomainsToCertificate, TreatMessagesAsInternal, EFTestMode and
// EFSkipLastIP off BOTH directions with an unconditional bool stamp. None of
// those fields exists on an outbound record, so every outbound twin carried six
// fabricated `false` values — each one a positive claim about a security control
// that Microsoft never made.
//
// An absent field is not a false one. This is the same class of defect as the
// zero-is-absent traps in intune.hardware_inventory: a decode that cannot tell
// "off" from "not reported" invents data and looks healthy doing it.
func TestConnectorTwin_OutboundOmitsFieldsAbsentFromTheWire(t *testing.T) {
	attrs := connectorTwin(recordsFrom(t, liveOutbound)[0], directionOutbound).Attrs

	// Every one of these is absent from the verbatim outbound record above.
	for _, k := range []string{
		semconv.AttrRequireTls,
		semconv.AttrRestrictDomainsToIpAddresses,
		semconv.AttrRestrictDomainsToCertificate,
		semconv.AttrTreatMessagesAsInternal,
		semconv.AttrEnhancedFilteringTestMode,
		semconv.AttrEnhancedFilteringSkipLastIp,
		semconv.AttrTlsSenderCertificateName,
		semconv.AttrSenderDomains,
		semconv.AttrSenderIpAddresses,
	} {
		if v, present := attrs[k]; present {
			t.Errorf("outbound twin carries %s=%q, but that field is not on an outbound record — an absent field must be omitted, never stamped", k, v)
		}
	}

	// CloudServicesMailEnabled IS on an outbound record, so it must still appear:
	// the fix is to omit what is absent, not to stop reading shared fields.
	if attrs[semconv.AttrCloudServicesMailEnabled] != "true" {
		t.Errorf("cloud_services_mail_enabled = %q, want %q — this field IS present on the wire", attrs[semconv.AttrCloudServicesMailEnabled], "true")
	}
}

// TestConnectorTwin_OutboundCarriesItsDestination: the single most useful thing
// about an outbound connector is WHERE THE MAIL GOES. Counting it and rating it
// Error while the twin stays silent on its destination was the gap #253 stayed
// open for.
func TestConnectorTwin_OutboundCarriesItsDestination(t *testing.T) {
	attrs := connectorTwin(recordsFrom(t, liveOutbound)[0], directionOutbound).Attrs

	want := map[string]string{
		semconv.AttrSmartHosts:                    "smtp-relay.gmail.com",
		semconv.AttrUseMxRecord:                   "false",
		semconv.AttrIsTransportRuleScoped:         "true",
		semconv.AttrRouteAllMessagesViaOnPremises: "false",
		semconv.AttrAllAcceptedDomains:            "false",
		semconv.AttrSenderRewritingEnabled:        "false",
		semconv.AttrTestMode:                      "false",
		semconv.AttrTlsSettings:                   "CertificateValidation",
		semconv.AttrMtaStsMode:                    "Opportunistic",
		semconv.AttrSmtpDaneMode:                  "Opportunistic",
		semconv.AttrIsValidated:                   "false",
		semconv.AttrValidationRecipients:          "rob@m7kni.io",
		semconv.AttrLastValidationTimestamp:       "2026-07-24T18:59:12.0000000",
	}
	for k, w := range want {
		if got := attrs[k]; got != w {
			t.Errorf("outbound twin %s = %q, want %q", k, got, w)
		}
	}

	// RecipientDomains is an empty list on this record, and TlsDomain is null:
	// both omitted rather than stamped empty, so "nothing configured" and "field
	// never sent" stay distinguishable from a configured empty value.
	for _, k := range []string{semconv.AttrRecipientDomains, semconv.AttrTlsDomain} {
		if v, present := attrs[k]; present {
			t.Errorf("empty/null field stamped as %s=%q", k, v)
		}
	}
}

// TestCollect_OutboundTwinSurvivesTheFullPath checks the destination reaches the
// emitter through Collect, not merely through connectorTwin in isolation: the
// outbound records come from a SECOND cmdlet call, so a twin can be correct and
// still never be emitted if that side is mis-wired.
func TestCollect_OutboundTwinSurvivesTheFullPath(t *testing.T) {
	attrs := outboundTwin(t, collectWith(t, tenantWithOutbound(t)))

	if attrs[semconv.AttrSmartHosts] != "smtp-relay.gmail.com" {
		t.Errorf("smart_hosts = %q, want the destination the connector routes to", attrs[semconv.AttrSmartHosts])
	}
	if attrs[semconv.AttrName] != "outbourconnection" {
		t.Errorf("name = %q", attrs[semconv.AttrName])
	}
	// The inbound twins must be unaffected by the outbound side existing.
	inbound := 0
	for _, l := range collectWith(t, tenantWithOutbound(t)).LogRecords() {
		if l.EventName == eventName && l.Attrs[semconv.AttrDirection] == directionInbound {
			inbound++
		}
	}
	if inbound != 2 {
		t.Errorf("inbound twins = %d, want 2", inbound)
	}
}

// TestCollect_WithoutTLSGauge_OutboundReadsTlsSettings: an outbound connector has
// no RequireTls field, so the shipped no-TLS test — which read exactly that —
// counted EVERY outbound connector as cleartext regardless of its real setting.
// That is a wrong NUMBER on a security posture gauge, not just a missing
// attribute.
//
// Outbound TLS is expressed by TlsSettings. This asserts only that a non-empty
// TlsSettings means TLS is configured and an absent/empty one means it is not —
// deliberately NOT an enumeration of the member names, because exactly one value
// ("CertificateValidation") has ever been observed on the wire and the rest would
// have to come from documentation.
func TestCollect_WithoutTLSGauge_OutboundReadsTlsSettings(t *testing.T) {
	rec := collectWith(t, tenantWithOutbound(t))

	got := map[string]float64{}
	for _, p := range rec.MetricPoints(metricWithoutTLS) {
		got[p.Attrs[semconv.AttrDirection]] = p.Value
	}
	if got[directionOutbound] != 0 {
		t.Errorf("outbound without_tls = %v, want 0: this connector sets TlsSettings=CertificateValidation", got[directionOutbound])
	}
	if got[directionInbound] != 1 {
		t.Errorf("inbound without_tls = %v, want 1", got[directionInbound])
	}

	// And a connector with no TLS setting at all must be counted.
	bare := recordsFrom(t, liveOutbound)[0]
	delete(bare, fieldTLSSettings)
	f := &fakeEXO{byCmdlet: map[string][]map[string]any{outboundCmdlet: {bare}}}
	rec2 := collectWith(t, f)
	for _, p := range rec2.MetricPoints(metricWithoutTLS) {
		if p.Attrs[semconv.AttrDirection] == directionOutbound && p.Value != 1 {
			t.Errorf("outbound without_tls = %v with no TlsSettings, want 1", p.Value)
		}
	}
}

// TestCollect_NoPerConnectorMetricLabels is the #112/#114 guard: connector
// names, sender IPs and certificate names identify an entity and must never key
// a series.
func TestCollect_NoPerConnectorMetricLabels(t *testing.T) {
	rec := collectWith(t, liveTenant(t))
	forbidden := []string{
		semconv.AttrName, semconv.AttrId, semconv.AttrSenderIpAddresses,
		semconv.AttrTlsSenderCertificateName, semconv.AttrSenderDomains,
	}
	for _, m := range []string{metricConnectors, metricWithoutTLS} {
		for _, p := range rec.MetricPoints(m) {
			for _, k := range forbidden {
				if v, present := p.Attrs[k]; present {
					t.Errorf("metric %s carries per-entity label %s=%q", m, k, v)
				}
			}
		}
	}
}

func TestCollect_TwinPerConnector(t *testing.T) {
	rec := collectWith(t, liveTenant(t))

	twins := map[string]map[string]string{}
	for _, l := range rec.LogRecords() {
		if l.EventName == eventName {
			twins[l.Attrs[semconv.AttrName]] = l.Attrs
		}
	}
	if len(twins) != 2 {
		t.Fatalf("twins = %d, want one per connector (2)", len(twins))
	}

	a, ok := twins["connectortest"]
	if !ok {
		t.Fatal("no twin for connectortest")
	}
	if a[semconv.AttrDirection] != directionInbound {
		t.Errorf("direction = %q", a[semconv.AttrDirection])
	}
	if a[semconv.AttrConnectorType] != "OnPremises" {
		t.Errorf("connector_type = %q, want the verbatim wire value", a[semconv.AttrConnectorType])
	}
	if a[semconv.AttrConnectorSource] != sourceAdminUI {
		t.Errorf("connector_source = %q", a[semconv.AttrConnectorSource])
	}
	if a[semconv.AttrRequireTls] != "true" {
		t.Errorf("require_tls = %q", a[semconv.AttrRequireTls])
	}
	if a[semconv.AttrTlsSenderCertificateName] != "*.rob-knight.com" {
		t.Errorf("tls_sender_certificate_name = %q", a[semconv.AttrTlsSenderCertificateName])
	}
	if a[semconv.AttrSenderDomains] != "smtp:*;1" {
		t.Errorf("sender_domains = %q, want the verbatim wire value including the priority suffix", a[semconv.AttrSenderDomains])
	}
	if a[semconv.AttrId] != "ac4d5ab0-6637-4e91-8d47-f5c2e95c71d9" {
		t.Errorf("id = %q", a[semconv.AttrId])
	}
	if a[semconv.AttrWhenCreated] != "2026-07-23T22:55:04.0000000Z" {
		t.Errorf("when_created = %q", a[semconv.AttrWhenCreated])
	}

	b := twins["myorgemail"]
	if b[semconv.AttrSenderIpAddresses] != "81.187.237.31" {
		t.Errorf("sender_ip_addresses = %q", b[semconv.AttrSenderIpAddresses])
	}
	// A multi-element list joins with commas into ONE attribute. telemetry.SetList
	// would be wrong here — it splits on whitespace, which these values never
	// contain, so every list would arrive as a one-element slice still holding the
	// commas.
	multi := recordsFrom(t, liveInboundNoTLS)[0]
	multi[fieldSenderIPAddresses] = []any{"81.187.237.31", "203.0.113.7"}
	if got := connectorTwin(multi, directionInbound).Attrs[semconv.AttrSenderIpAddresses]; got != "81.187.237.31,203.0.113.7" {
		t.Errorf("multi-element sender_ip_addresses = %#v, want one comma-joined string", got)
	}
	// TlsSenderCertificateName is null here: omitted, never stamped empty.
	if v, present := b[semconv.AttrTlsSenderCertificateName]; present {
		t.Errorf("null TlsSenderCertificateName stamped as %q", v)
	}
	// An empty list is omitted rather than stamped as an empty string.
	if v, present := b[semconv.AttrTrustedOrganizations]; present {
		t.Errorf("empty TrustedOrganizations stamped as %q", v)
	}
}

// TestConnectorTwin_Severity encodes the threat model. An enabled OUTBOUND
// connector routes tenant mail through infrastructure Microsoft does not own —
// the exfiltration/relay shape — so it is Error regardless of its TLS setting.
// Inbound, the danger is mail arriving pre-trusted: without TLS that channel is
// also unauthenticated, so an enabled cleartext inbound connector is Error too.
// Disabled connectors are one toggle from live and rate Warn when hand-created,
// matching m365.exchange_transport_rules' reasoning.
func TestConnectorTwin_Severity(t *testing.T) {
	rec := recordsFrom(t, liveInboundTLS, liveInboundNoTLS)
	tlsRec, noTLSRec := rec[0], rec[1]

	enabled := func(r map[string]any, on bool) map[string]any {
		out := map[string]any{}
		for k, v := range r {
			out[k] = v
		}
		out[fieldEnabled] = on
		return out
	}

	cases := []struct {
		name string
		rec  map[string]any
		dir  string
		want telemetry.Severity
	}{
		{"enabled outbound is always Error", enabled(tlsRec, true), directionOutbound, telemetry.SeverityError},
		{"enabled inbound without TLS is Error", enabled(noTLSRec, true), directionInbound, telemetry.SeverityError},
		{"enabled inbound with TLS is Warn", enabled(tlsRec, true), directionInbound, telemetry.SeverityWarn},
		{"disabled hand-created outbound is Warn", enabled(tlsRec, false), directionOutbound, telemetry.SeverityWarn},
		{"disabled hand-created inbound is Warn", noTLSRec, directionInbound, telemetry.SeverityWarn},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := connectorTwin(tc.rec, tc.dir).Severity; got != tc.want {
				t.Errorf("severity = %v, want %v", got, tc.want)
			}
		})
	}
}

// TestConnectorTwin_DefaultSourceIsQuieterThanHandCreated: a connector the
// hybrid wizard created is expected furniture on a hybrid tenant; a disabled one
// should not nag.
func TestConnectorTwin_DefaultSourceIsQuieterThanHandCreated(t *testing.T) {
	r := recordsFrom(t, liveInboundTLS)[0]
	r[fieldConnectorSource] = sourceHybridWizard
	if got := connectorTwin(r, directionInbound).Severity; got != telemetry.SeverityInfo {
		t.Errorf("disabled hybrid-wizard connector severity = %v, want Info", got)
	}
}

func TestCollect_EmptyTenantEmitsNoTwins(t *testing.T) {
	rec := collectWith(t, &fakeEXO{})
	for _, l := range rec.LogRecords() {
		if l.EventName == eventName {
			t.Errorf("a tenant with no connectors emitted a twin: %+v", l.Attrs)
		}
	}
}

func TestCollect_ErrorPropagates(t *testing.T) {
	rec := telemetrytest.New()
	c := New(collectors.EXODeps{Client: &fakeEXO{err: errors.New("403")}})
	if err := c.Collect(context.Background(), rec.Emitter()); err == nil {
		t.Fatal("want error when a cmdlet fails")
	}
}
