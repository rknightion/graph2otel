package exchangedkim

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"testing"

	"github.com/rknightion/graph2otel/internal/collectors"
	"github.com/rknightion/graph2otel/internal/semconv"
	"github.com/rknightion/graph2otel/internal/telemetry"
	"github.com/rknightion/graph2otel/internal/telemetrytest"
)

// liveRecords are the two real Get-DkimSigningConfig rows captured from the
// m7kni tenant as graph2otel-poller on 2026-07-23, over the Exchange Online
// admin API. The "@data.type"/"@odata.type" sidecar keys are on the wire
// verbatim and kept here deliberately: the mapper must ignore them by reading
// each field by exact name, and a hand-trimmed fixture would not prove that.
// The public keys are trimmed to a short placeholder — they are large and this
// collector deliberately does not emit them.
const liveRecords = `[
  {
    "Domain": "m7kni.io",
    "AdminDisplayName": "",
    "Selector1KeySize@data.type": "System.UInt16",
    "Selector1KeySize@odata.type": "#Decimal",
    "Selector1KeySize": 2048,
    "Selector1CNAME": "selector1-m7kni-io._domainkey.m7knio.y-v1.dkim.mail.microsoft",
    "Selector1PublicKey": "v=DKIM1; k=rsa; p=PLACEHOLDER;",
    "Selector2KeySize@data.type": "System.UInt16",
    "Selector2KeySize@odata.type": "#Decimal",
    "Selector2KeySize": 2048,
    "Selector2CNAME": "selector2-m7kni-io._domainkey.m7knio.y-v1.dkim.mail.microsoft",
    "Selector2PublicKey": "v=DKIM1; k=rsa; p=PLACEHOLDER;",
    "Enabled": true,
    "IsDefault": false,
    "HeaderCanonicalization": "Relaxed",
    "BodyCanonicalization": "Relaxed",
    "Algorithm": "RsaSHA256",
    "NumberOfBytesToSign": "All",
    "IncludeSignatureCreationTime": true,
    "IncludeKeyExpiration": false,
    "KeyCreationTime@data.type": "System.DateTime",
    "KeyCreationTime": "2026-07-14T18:54:40.7066975Z",
    "LastChecked@data.type": "System.DateTime",
    "LastChecked": "2026-07-14T18:54:40.7066975Z",
    "RotateOnDate@data.type": "System.DateTime",
    "RotateOnDate": "2026-07-14T18:54:40.7066975Z",
    "SelectorBeforeRotateOnDate": "selector2",
    "SelectorAfterRotateOnDate": "selector1",
    "Status": "Valid",
    "Identity": "m7kni.io",
    "Id": "m7kni.io",
    "IsValid": true,
    "ExchangeVersion": "0.20 (15.0.0.0)",
    "Name": "m7kni.io"
  },
  {
    "Domain": "m7kni.com",
    "AdminDisplayName": "",
    "Selector1KeySize@data.type": "System.UInt16",
    "Selector1KeySize@odata.type": "#Decimal",
    "Selector1KeySize": 2048,
    "Selector1CNAME": "selector1-m7kni-com._domainkey.m7knio.a-v1.dkim.mail.microsoft",
    "Selector1PublicKey": "v=DKIM1; k=rsa; p=PLACEHOLDER;",
    "Selector2KeySize@data.type": "System.UInt16",
    "Selector2KeySize@odata.type": "#Decimal",
    "Selector2KeySize": 2048,
    "Selector2CNAME": "selector2-m7kni-com._domainkey.m7knio.a-v1.dkim.mail.microsoft",
    "Selector2PublicKey": "v=DKIM1; k=rsa; p=PLACEHOLDER;",
    "Enabled": true,
    "IsDefault": false,
    "HeaderCanonicalization": "Relaxed",
    "BodyCanonicalization": "Relaxed",
    "Algorithm": "RsaSHA256",
    "NumberOfBytesToSign": "All",
    "IncludeSignatureCreationTime": true,
    "IncludeKeyExpiration": false,
    "KeyCreationTime@data.type": "System.DateTime",
    "KeyCreationTime": "2026-07-14T18:59:08.6546544Z",
    "LastChecked@data.type": "System.DateTime",
    "LastChecked": "2026-07-14T18:59:08.6546544Z",
    "RotateOnDate@data.type": "System.DateTime",
    "RotateOnDate": "2026-07-14T18:59:08.6546544Z",
    "SelectorBeforeRotateOnDate": "selector2",
    "SelectorAfterRotateOnDate": "selector1",
    "Status": "Valid",
    "Identity": "m7kni.com",
    "Id": "m7kni.com",
    "IsValid": true,
    "ExchangeVersion": "0.20 (15.0.0.0)",
    "Name": "m7kni.com"
  }
]`

func decodeRecords(t *testing.T, raw string) []map[string]any {
	t.Helper()
	var recs []map[string]any
	if err := json.Unmarshal([]byte(raw), &recs); err != nil {
		t.Fatalf("decode fixture: %v", err)
	}
	return recs
}

// fakeEXO serves canned records and records every Invoke call, so the tests can
// assert the request shape as well as the mapping. It needs no HTTP and no
// Exchange grants.
type fakeEXO struct {
	recs    []map[string]any
	err     error
	cmdlets []string
	params  []map[string]any
}

func (f *fakeEXO) Invoke(_ context.Context, cmdlet string, params map[string]any) ([]map[string]any, error) {
	f.cmdlets = append(f.cmdlets, cmdlet)
	f.params = append(f.params, params)
	if f.err != nil {
		return nil, f.err
	}
	return f.recs, nil
}

func newCollector(t *testing.T, f *fakeEXO) *Collector {
	t.Helper()
	return New(collectors.EXODeps{
		Client:   f,
		TenantID: "4b8c18bd-2f9f-4227-af55-9f1061cf9c32",
		Logger:   slog.New(slog.DiscardHandler),
	})
}

// TestCollectRunsTheCmdletOnce pins the request shape: exactly one call to
// Get-DkimSigningConfig, with no parameters (it takes none).
func TestCollectRunsTheCmdletOnce(t *testing.T) {
	f := &fakeEXO{recs: decodeRecords(t, liveRecords)}
	rec := telemetrytest.New()
	if err := newCollector(t, f).Collect(context.Background(), rec.Emitter()); err != nil {
		t.Fatalf("Collect: %v", err)
	}
	if len(f.cmdlets) != 1 {
		t.Fatalf("invoked %d times, want 1", len(f.cmdlets))
	}
	if f.cmdlets[0] != cmdlet {
		t.Errorf("cmdlet = %q, want %q", f.cmdlets[0], cmdlet)
	}
	if f.params[0] != nil {
		t.Errorf("params = %v, want nil — Get-DkimSigningConfig takes none", f.params[0])
	}
}

// TestCollectEmitsBoundedGauge checks the gauge counts domains by the enabled x
// status tuple, and carries ONLY those two bounded labels.
func TestCollectEmitsBoundedGauge(t *testing.T) {
	f := &fakeEXO{recs: decodeRecords(t, liveRecords)}
	rec := telemetrytest.New()
	if err := newCollector(t, f).Collect(context.Background(), rec.Emitter()); err != nil {
		t.Fatalf("Collect: %v", err)
	}
	pts := rec.MetricPoints(metricSigning)
	// Both live domains share (enabled=true, status=Valid), so they fold into a
	// single series valued 2 — proof the gauge is bounded, not per-domain.
	if len(pts) != 1 {
		t.Fatalf("gauge points = %d, want 1 (both domains share one enabled x status series)", len(pts))
	}
	if pts[0].Value != 2 {
		t.Errorf("domain count = %v, want 2", pts[0].Value)
	}
	want := map[string]string{
		semconv.AttrEnabled: "true",
		semconv.AttrStatus:  "Valid",
	}
	for k, v := range want {
		if got := pts[0].Attrs[k]; got != v {
			t.Errorf("gauge label %q = %q, want %q", k, got, v)
		}
	}
	// The gauge must carry ONLY the bounded enum labels. A per-domain field here
	// (the domain name) is a series per accepted domain — the #112 bug.
	for _, banned := range []string{semconv.AttrDomain, semconv.AttrSelector1Cname} {
		if _, present := pts[0].Attrs[banned]; present {
			t.Errorf("gauge carries per-entity label %q — that is a series per domain", banned)
		}
	}
}

// TestCollectEmitsPerDomainTwin drives the richest live record end-to-end and
// asserts the twin carries the per-domain detail the gauge collapses away.
func TestCollectEmitsPerDomainTwin(t *testing.T) {
	f := &fakeEXO{recs: decodeRecords(t, liveRecords)}
	rec := telemetrytest.New()
	if err := newCollector(t, f).Collect(context.Background(), rec.Emitter()); err != nil {
		t.Fatalf("Collect: %v", err)
	}
	logs := rec.LogRecords()
	if len(logs) != 2 {
		t.Fatalf("emitted %d log records, want 2 (one per domain)", len(logs))
	}
	// Records preserve input order, so logs[0] is m7kni.io.
	l := logs[0]
	if l.EventName != eventName {
		t.Errorf("event name = %q, want %q", l.EventName, eventName)
	}
	want := map[string]string{
		semconv.AttrDomain:                 "m7kni.io",
		semconv.AttrStatus:                 "Valid",
		semconv.AttrAlgorithm:              "RsaSHA256",
		semconv.AttrSelector1Cname:         "selector1-m7kni-io._domainkey.m7knio.y-v1.dkim.mail.microsoft",
		semconv.AttrSelector2Cname:         "selector2-m7kni-io._domainkey.m7knio.y-v1.dkim.mail.microsoft",
		semconv.AttrHeaderCanonicalization: "Relaxed",
		semconv.AttrBodyCanonicalization:   "Relaxed",
		semconv.AttrKeyCreationTime:        "2026-07-14T18:54:40.7066975Z",
		semconv.AttrLastChecked:            "2026-07-14T18:54:40.7066975Z",
		semconv.AttrRotateOnDate:           "2026-07-14T18:54:40.7066975Z",
		// Bools are stamped as queryable strings.
		semconv.AttrEnabled:   "true",
		semconv.AttrIsDefault: "false",
		semconv.AttrIsValid:   "true",
	}
	for k, v := range want {
		if got := l.Attrs[k]; got != v {
			t.Errorf("attr %q = %q, want %q", k, got, v)
		}
	}
	// Selector key sizes arrive as JSON numbers, emitted as float64 and flattened
	// to a plain integer-looking string by the recorder.
	if got := l.Attrs[semconv.AttrSelector1KeySize]; got != "2048" {
		t.Errorf("selector1_key_size = %q, want 2048", got)
	}
	if got := l.Attrs[semconv.AttrSelector2KeySize]; got != "2048" {
		t.Errorf("selector2_key_size = %q, want 2048", got)
	}
	// A healthy live record (enabled + Valid) is Info, not Warn.
	if l.SeverityText != "INFO" {
		t.Errorf("severity = %q, want INFO for an enabled+Valid domain", l.SeverityText)
	}
}

// TestEnabledButInvalidIsWarn is the actionable case: signing is on but the
// configuration is not Valid, so mail is going out unsigned or with a failing
// selector. The record here is a CONSTRUCTED edge — the live tenant had no such
// domain — built by flipping a live record's Status to a broken value.
func TestEnabledButInvalidIsWarn(t *testing.T) {
	r := decodeRecords(t, liveRecords)[0]
	r["Enabled"] = true
	r["Status"] = "CnameError" // constructed: broken selector CNAME
	r["IsValid"] = false
	f := &fakeEXO{recs: []map[string]any{r}}
	rec := telemetrytest.New()
	if err := newCollector(t, f).Collect(context.Background(), rec.Emitter()); err != nil {
		t.Fatalf("Collect: %v", err)
	}
	logs := rec.LogRecords()
	if len(logs) != 1 {
		t.Fatalf("emitted %d log records, want 1", len(logs))
	}
	if logs[0].SeverityText != "WARN" {
		t.Errorf("severity = %q, want WARN (enabled but Status != Valid)", logs[0].SeverityText)
	}
	// The gauge series for this domain is (enabled=true, status=CnameError).
	pts := rec.MetricPoints(metricSigning)
	if len(pts) != 1 || pts[0].Attrs[semconv.AttrStatus] != "CnameError" {
		t.Errorf("gauge = %v, want one point with status=CnameError", pts)
	}
}

// TestDisabledDomainIsInfo pins that a domain with signing simply turned off is
// a posture fact, not an alert — Info even though it is not Valid.
func TestDisabledDomainIsInfo(t *testing.T) {
	r := decodeRecords(t, liveRecords)[0]
	r["Enabled"] = false
	r["Status"] = "CnameError" // not Valid, but disabled — so not actionable
	f := &fakeEXO{recs: []map[string]any{r}}
	rec := telemetrytest.New()
	if err := newCollector(t, f).Collect(context.Background(), rec.Emitter()); err != nil {
		t.Fatalf("Collect: %v", err)
	}
	logs := rec.LogRecords()
	if len(logs) != 1 {
		t.Fatalf("emitted %d log records, want 1", len(logs))
	}
	if logs[0].SeverityText != "INFO" {
		t.Errorf("severity = %q, want INFO (signing disabled is a posture fact, not an alert)", logs[0].SeverityText)
	}
	if got := logs[0].Attrs[semconv.AttrEnabled]; got != "false" {
		t.Errorf("enabled = %q, want false — a disabled domain must still emit the flag", got)
	}
}

// TestEmptyResultIsNotAnError covers a tenant with no accepted domains: a clean
// zero, no twins, and an empty snapshot (no ghost series).
func TestEmptyResultIsNotAnError(t *testing.T) {
	f := &fakeEXO{recs: nil}
	rec := telemetrytest.New()
	if err := newCollector(t, f).Collect(context.Background(), rec.Emitter()); err != nil {
		t.Fatalf("Collect over an empty result: %v", err)
	}
	if got := len(rec.LogRecords()); got != 0 {
		t.Errorf("emitted %d twins over an empty result, want 0", got)
	}
	if pts := rec.MetricPoints(metricSigning); len(pts) != 0 {
		t.Errorf("gauge points = %d, want 0 — an empty snapshot drops stale series", len(pts))
	}
}

func TestCollectPropagatesClientError(t *testing.T) {
	sentinel := errors.New("403: missing directory role")
	f := &fakeEXO{err: sentinel}
	rec := telemetrytest.New()
	err := newCollector(t, f).Collect(context.Background(), rec.Emitter())
	if !errors.Is(err, sentinel) {
		t.Fatalf("Collect error = %v, want it to wrap %v", err, sentinel)
	}
}

// TestRecordsAreStampedWithTheExchangeOnlineTransport guards the #141 stamp: the
// Scheduler baseline is graph, so a collector that only declares
// IngestTransport() and forgets telemetry.WithTransport ships records labeled
// `graph` that came from Exchange Online. It must also NOT be a metric label.
func TestRecordsAreStampedWithTheExchangeOnlineTransport(t *testing.T) {
	f := &fakeEXO{recs: decodeRecords(t, liveRecords)}
	rec := telemetrytest.New()
	c := newCollector(t, f)
	if err := c.Collect(context.Background(), rec.Emitter()); err != nil {
		t.Fatalf("Collect: %v", err)
	}
	if got := rec.LogRecords()[0].Attrs[semconv.AttrIngestTransport]; got != string(telemetry.TransportExchangeOnline) {
		t.Errorf("%s = %q, want %q", semconv.AttrIngestTransport, got, telemetry.TransportExchangeOnline)
	}
	if got := c.IngestTransport(); got != telemetry.TransportExchangeOnline {
		t.Errorf("IngestTransport() = %q, want %q", got, telemetry.TransportExchangeOnline)
	}
	if _, present := rec.MetricPoints(metricSigning)[0].Attrs[semconv.AttrIngestTransport]; present {
		t.Error("ingest_transport must not be a metric label — it would change series identity")
	}
}

// TestLogTwinIsStampedAtPollTime pins the STATE-feed timestamp rule: the same
// config is re-emitted every cycle, so the record carries no source timestamp
// (poll time), and the wire times are preserved as attributes instead.
func TestLogTwinIsStampedAtPollTime(t *testing.T) {
	f := &fakeEXO{recs: decodeRecords(t, liveRecords)}
	rec := telemetrytest.New()
	if err := newCollector(t, f).Collect(context.Background(), rec.Emitter()); err != nil {
		t.Fatalf("Collect: %v", err)
	}
	if ts := rec.LogRecords()[0].Timestamp; !ts.IsZero() {
		t.Errorf("timestamp = %s, want zero (poll time) — this is a state feed", ts)
	}
	if got := rec.LogRecords()[0].Attrs[semconv.AttrKeyCreationTime]; got == "" {
		t.Error("key_creation_time must carry the wire time the record timestamp deliberately does not")
	}
}
