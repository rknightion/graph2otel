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
