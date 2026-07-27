package exchangeaccepteddomains

import (
	"context"
	"encoding/json"
	"errors"
	"testing"

	"github.com/rknightion/graph2otel/internal/collectors"
	"github.com/rknightion/graph2otel/internal/recordoutcome"
	"github.com/rknightion/graph2otel/internal/semconv"
	"github.com/rknightion/graph2otel/internal/telemetrytest"
)

// liveInitialDomain is a SANITIZED Get-AcceptedDomain record shape, derived
// verbatim from the m7kni tenant as graph2otel-poller on 2026-07-27 (#353) —
// the tenant's *.onmicrosoft.com initial domain, narrowed to the keys the
// mapper reads (the live records carry 56 fields each). Real tenant GUID and
// domain names are replaced with example values.
//
// DomainType is "Authoritative" on all 4 domains observed live — this is ONE
// observed value, not a value set (see package doc and
// internal/semconv/attrs_m365_accepteddomains.go): no wirecheck enum watcher
// is built off it.
const liveInitialDomain = `{
  "DomainName": "example.onmicrosoft.com",
  "DomainType": "Authoritative",
  "Default": false,
  "InitialDomain": true,
  "MatchSubDomains": false,
  "SmtpDaneStatus": "Disabled",
  "AuthenticationType": "Managed",
  "RawAuthenticationType": "Managed",
  "ExternallyManaged": false,
  "PendingRemoval": false,
  "PendingCompletion": false,
  "OutboundOnly": false,
  "EmailOnly": false,
  "AddressBookEnabled": true,
  "SendingFromDomainDisabled": false,
  "SendingToDomainDisabled": false,
  "IsCoexistenceDomain": false,
  "CatchAllRecipientID": null,
  "FederatedOrganizationLink": "Federation",
  "Name": "example.onmicrosoft.com",
  "DistinguishedName": "CN=example.onmicrosoft.com,CN=Accepted Domains",
  "ExchangeVersion": "0.20 (15.0.0.0)",
  "AdminDisplayName": "",
  "MailFlowRegion": "",
  "AzureProvisioningRegion": ""
}`

// liveDefaultCustomDomain is the tenant's custom vanity domain, marked Default.
// Same shape and same evidence class as liveInitialDomain.
const liveDefaultCustomDomain = `{
  "DomainName": "example.com",
  "DomainType": "Authoritative",
  "Default": true,
  "InitialDomain": false,
  "MatchSubDomains": false,
  "SmtpDaneStatus": "Disabled",
  "AuthenticationType": "Managed",
  "RawAuthenticationType": "Managed",
  "ExternallyManaged": false,
  "PendingRemoval": false,
  "PendingCompletion": false,
  "OutboundOnly": false,
  "EmailOnly": false,
  "AddressBookEnabled": true,
  "SendingFromDomainDisabled": false,
  "SendingToDomainDisabled": false,
  "IsCoexistenceDomain": false,
  "CatchAllRecipientID": null,
  "FederatedOrganizationLink": "Federation",
  "Name": "example.com",
  "DistinguishedName": "CN=example.com,CN=Accepted Domains",
  "ExchangeVersion": "0.20 (15.0.0.0)",
  "AdminDisplayName": "",
  "MailFlowRegion": "",
  "AzureProvisioningRegion": ""
}`

// namedSubdomain is a third, non-default, non-initial domain — same shape,
// same evidence class — used to exercise the "many non-default domains" path.
const namedSubdomain = `{
  "DomainName": "mail.example.com",
  "DomainType": "Authoritative",
  "Default": false,
  "InitialDomain": false,
  "MatchSubDomains": false,
  "SmtpDaneStatus": "Disabled",
  "AuthenticationType": "Managed",
  "RawAuthenticationType": "Managed",
  "ExternallyManaged": false,
  "PendingRemoval": false,
  "PendingCompletion": false,
  "OutboundOnly": false,
  "EmailOnly": false,
  "AddressBookEnabled": true,
  "SendingFromDomainDisabled": false,
  "SendingToDomainDisabled": false,
  "IsCoexistenceDomain": false,
  "CatchAllRecipientID": null,
  "FederatedOrganizationLink": "Federation",
  "Name": "mail.example.com",
  "DistinguishedName": "CN=mail.example.com,CN=Accepted Domains",
  "ExchangeVersion": "0.20 (15.0.0.0)",
  "AdminDisplayName": "",
  "MailFlowRegion": "",
  "AzureProvisioningRegion": ""
}`

// internalRelayDomain is DOCS-ONLY (not live-measured, see package doc):
// Microsoft's Get-AcceptedDomain reference documents InternalRelay as a
// DomainType value alongside Authoritative. It exists in this fixture set
// solely to prove InternalRelay is not auto-flagged as a finding — an
// internal-relay domain is a legitimate hybrid configuration, not a
// misconfiguration.
const internalRelayDomain = `{
  "DomainName": "relay.example.com",
  "DomainType": "InternalRelay",
  "Default": false,
  "InitialDomain": false,
  "MatchSubDomains": false,
  "SmtpDaneStatus": "Disabled",
  "AuthenticationType": "Managed",
  "RawAuthenticationType": "Managed",
  "ExternallyManaged": false,
  "PendingRemoval": false,
  "PendingCompletion": false,
  "OutboundOnly": false,
  "EmailOnly": false,
  "AddressBookEnabled": true,
  "SendingFromDomainDisabled": false,
  "SendingToDomainDisabled": false,
  "IsCoexistenceDomain": false,
  "CatchAllRecipientID": null,
  "FederatedOrganizationLink": "Federation",
  "Name": "relay.example.com",
  "DistinguishedName": "CN=relay.example.com,CN=Accepted Domains",
  "ExchangeVersion": "0.20 (15.0.0.0)",
  "AdminDisplayName": "",
  "MailFlowRegion": "",
  "AzureProvisioningRegion": ""
}`

type fakeEXO struct {
	recs   []map[string]any
	err    error
	params map[string]any
}

func (f *fakeEXO) Invoke(_ context.Context, _ string, params map[string]any) ([]map[string]any, error) {
	f.params = params
	if f.err != nil {
		return nil, f.err
	}
	return f.recs, nil
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

func collectWith(t *testing.T, exo *fakeEXO) *telemetrytest.Recorder {
	t.Helper()
	rec := telemetrytest.New()
	c := New(collectors.EXODeps{Client: exo})
	if err := c.Collect(context.Background(), rec.Emitter(), recordoutcome.NewRecorder()); err != nil {
		t.Fatalf("Collect: %v", err)
	}
	return rec
}

func collect(t *testing.T, recs []map[string]any) *telemetrytest.Recorder {
	t.Helper()
	return collectWith(t, &fakeEXO{recs: recs})
}

// TestCollect_ResultSizeUnlimitedIsPinned: the transport test the issue
// requires. Without ResultSize=Unlimited, a tenant larger than one default
// page would silently report a fraction of its accepted domains.
func TestCollect_ResultSizeUnlimitedIsPinned(t *testing.T) {
	exo := &fakeEXO{recs: recordsFrom(t, liveInitialDomain)}
	collectWith(t, exo)
	if got := exo.params[paramResultSize]; got != resultSizeUnlimited {
		t.Errorf("%s = %v, want %q", paramResultSize, got, resultSizeUnlimited)
	}
}

func TestCollect_TwinPerDomain(t *testing.T) {
	rec := collect(t, recordsFrom(t, liveInitialDomain, liveDefaultCustomDomain, namedSubdomain))
	n := 0
	for _, l := range rec.LogRecords() {
		if l.EventName == eventName {
			n++
		}
	}
	if n != 3 {
		t.Errorf("twins = %d, want 3 (all returned domains receive twins)", n)
	}
}

func TestCollect_AccountsEveryDomainOnce(t *testing.T) {
	outcomes := recordoutcome.NewRecorder()
	recs := recordsFrom(t, liveInitialDomain, liveDefaultCustomDomain, namedSubdomain)
	c := New(collectors.EXODeps{Client: &fakeEXO{recs: recs}})
	if err := c.Collect(context.Background(), telemetrytest.New().Emitter(), outcomes); err != nil {
		t.Fatalf("Collect: %v", err)
	}
	got := outcomes.Snapshot().Summarize(nil, false)
	want := recordoutcome.Counts{Fetched: 3, Mapped: 3, Emitted: 3}
	if got.Result != recordoutcome.ResultSuccess || got.Counts != want {
		t.Errorf("outcome = %#v, want success/%#v", got, want)
	}
}

func TestCollect_DomainTypeGauge(t *testing.T) {
	rec := collect(t, recordsFrom(t, liveInitialDomain, liveDefaultCustomDomain, internalRelayDomain))
	got := map[string]float64{}
	for _, p := range rec.MetricPoints(metricDomains) {
		got[p.Attrs[semconv.AttrDomainType]] += p.Value
	}
	if got["Authoritative"] != 2 {
		t.Errorf("Authoritative = %v, want 2", got["Authoritative"])
	}
	if got["InternalRelay"] != 1 {
		t.Errorf("InternalRelay = %v, want 1", got["InternalRelay"])
	}
}

func TestCollect_DefaultDomainGauge(t *testing.T) {
	rec := collect(t, recordsFrom(t, liveInitialDomain, liveDefaultCustomDomain, namedSubdomain))
	got := map[string]float64{}
	for _, p := range rec.MetricPoints(metricDomains) {
		got[p.Attrs[semconv.AttrIsDefaultDomain]] += p.Value
	}
	if got["true"] != 1 {
		t.Errorf("is_default_domain=true = %v, want 1", got["true"])
	}
	if got["false"] != 2 {
		t.Errorf("is_default_domain=false = %v, want 2", got["false"])
	}
}

// TestCollect_DomainNameNeverOnMetric: the domain name is per-entity and must
// never become a gauge label (#112) — it lives on the twin only.
func TestCollect_DomainNameNeverOnMetric(t *testing.T) {
	rec := collect(t, recordsFrom(t, liveInitialDomain))
	for _, p := range rec.MetricPoints(metricDomains) {
		if _, ok := p.Attrs[semconv.AttrDomain]; ok {
			t.Errorf("gauge point carries a domain label: %#v", p.Attrs)
		}
	}
}

func TestCollect_TwinAttributes(t *testing.T) {
	rec := collect(t, recordsFrom(t, liveDefaultCustomDomain))
	var a map[string]string
	for _, l := range rec.LogRecords() {
		if l.EventName == eventName {
			a = l.Attrs
		}
	}
	if a == nil {
		t.Fatal("no twin")
	}
	if a[semconv.AttrDomain] != "example.com" {
		t.Errorf("domain = %q", a[semconv.AttrDomain])
	}
	if a[semconv.AttrDomainType] != "Authoritative" {
		t.Errorf("domain_type = %q", a[semconv.AttrDomainType])
	}
	if a[semconv.AttrIsDefaultDomain] != "true" {
		t.Errorf("is_default_domain = %q", a[semconv.AttrIsDefaultDomain])
	}
	if a[semconv.AttrIsInitialDomain] != "false" {
		t.Errorf("is_initial_domain = %q", a[semconv.AttrIsInitialDomain])
	}
	if a[semconv.AttrMatchSubdomains] != "false" {
		t.Errorf("match_subdomains = %q", a[semconv.AttrMatchSubdomains])
	}
	if a[semconv.AttrSmtpDaneStatus] != "Disabled" {
		t.Errorf("smtp_dane_status = %q", a[semconv.AttrSmtpDaneStatus])
	}
	// CatchAllRecipientID is null on the wire and must be omitted, not stamped
	// as an empty string.
	if v, ok := a[semconv.AttrCatchAllRecipientId]; ok {
		t.Errorf("catch_all_recipient_id present as %q, want omitted (null on the wire)", v)
	}
}

// TestCollect_InternalRelayNotFlaggedAsFinding: the trap the issue is about.
// An InternalRelay domain is a legitimate hybrid configuration and must not
// rate a Warn/Error severity purely for being InternalRelay.
func TestCollect_InternalRelayNotFlaggedAsFinding(t *testing.T) {
	rec := collect(t, recordsFrom(t, internalRelayDomain))
	found := false
	for _, l := range rec.LogRecords() {
		if l.EventName != eventName {
			continue
		}
		found = true
		if l.SeverityText != "INFO" {
			t.Errorf("InternalRelay domain twin severity = %q, want INFO — InternalRelay must not be auto-flagged as a finding", l.SeverityText)
		}
	}
	if !found {
		t.Fatal("no twin emitted for InternalRelay domain")
	}
}

func TestCollect_NoDomainsStillSeeds(t *testing.T) {
	rec := collect(t, nil)
	if got := len(rec.MetricPoints(metricDomains)); got != 0 {
		t.Errorf("series with no domains = %d, want 0 (domain_type/is_default_domain are open dimensions, not pre-seeded booleans)", got)
	}
}

func TestCollect_ErrorPropagates(t *testing.T) {
	rec := telemetrytest.New()
	c := New(collectors.EXODeps{Client: &fakeEXO{err: errors.New("403")}})
	if err := c.Collect(context.Background(), rec.Emitter(), recordoutcome.NewRecorder()); err == nil {
		t.Fatal("want error when the cmdlet fails")
	}
}
