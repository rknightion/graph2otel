package exchangeremotedomains

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

// liveDefaultDomain is the VERBATIM Get-RemoteDomain record captured from the
// m7kni tenant as graph2otel-poller on 2026-07-23 over the Exchange Online admin
// API — the "Default" entry, whose DomainName is the wildcard "*" meaning EVERY
// remote domain.
//
// It carries AutoForwardEnabled: true, which is a real finding on a real tenant:
// external auto-forwarding is permitted to anywhere. That is why the wildcard
// case is separated from a named domain in the severity rule.
//
// Note TNEFEnabled and RequiredCharsetCoverage are null, NOT false — they are
// tri-state "use the default" fields, so the mapper must omit them rather than
// assert false.
const liveDefaultDomain = `{
  "DomainName": "*",
  "IsInternal": false,
  "TargetDeliveryDomain": false,
  "ByteEncoderTypeFor7BitCharsets": "Undefined",
  "CharacterSet": "iso-8859-1",
  "NonMimeCharacterSet": "iso-8859-1",
  "AllowedOOFType": "External",
  "AutoReplyEnabled": true,
  "AutoForwardEnabled": true,
  "DeliveryReportEnabled": true,
  "NDREnabled": true,
  "MeetingForwardNotificationEnabled": false,
  "ContentType": "MimeHtmlText",
  "DisplaySenderName": true,
  "RequiredCharsetCoverage": null,
  "TNEFEnabled": null,
  "LineWrapSize": "Unlimited",
  "TrustedMailOutboundEnabled": false,
  "TrustedMailInboundEnabled": false,
  "UseSimpleDisplayName": false,
  "NDRDiagnosticInfoEnabled": true,
  "AdminDisplayName": "",
  "Name": "Default",
  "Identity": "Default",
  "WhenChanged@data.type": "System.DateTime",
  "WhenChanged": "2026-06-14T17:23:32.0000000+00:00",
  "WhenCreated@data.type": "System.DateTime",
  "WhenCreated": "2025-08-08T18:38:40.0000000Z",
  "Guid@data.type": "System.Guid",
  "Guid": "04cd38fd-ca71-4e98-bcf5-0190e520f8a0",
  "IsValid": true
}`

// namedForwarding is the same record shape narrowed to a NAMED domain, to prove
// the wildcard and the named case take different severities. Every key is one
// live-verified above.
const namedForwarding = `{
  "DomainName": "partner.example",
  "Name": "partner", "Identity": "partner",
  "IsInternal": false, "TargetDeliveryDomain": false,
  "AllowedOOFType": "External",
  "AutoReplyEnabled": true, "AutoForwardEnabled": true,
  "DeliveryReportEnabled": true, "NDREnabled": true,
  "TNEFEnabled": null, "IsValid": true
}`

const noForwarding = `{
  "DomainName": "locked.example",
  "Name": "locked", "Identity": "locked",
  "IsInternal": false, "TargetDeliveryDomain": false,
  "AllowedOOFType": "None",
  "AutoReplyEnabled": false, "AutoForwardEnabled": false,
  "DeliveryReportEnabled": false, "NDREnabled": true,
  "TNEFEnabled": true, "IsValid": true
}`

type fakeEXO struct {
	recs []map[string]any
	err  error
}

func (f *fakeEXO) Invoke(_ context.Context, _ string, _ map[string]any) ([]map[string]any, error) {
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

func collect(t *testing.T, recs []map[string]any) *telemetrytest.Recorder {
	t.Helper()
	rec := telemetrytest.New()
	c := New(collectors.EXODeps{Client: &fakeEXO{recs: recs}})
	if err := c.Collect(context.Background(), rec.Emitter()); err != nil {
		t.Fatalf("Collect: %v", err)
	}
	return rec
}

func gaugeBy(rec *telemetrytest.Recorder, metric, key string) map[string]float64 {
	out := map[string]float64{}
	for _, p := range rec.MetricPoints(metric) {
		out[p.Attrs[key]] = p.Value
	}
	return out
}

func TestCollect_DomainsGauge(t *testing.T) {
	rec := collect(t, recordsFrom(t, liveDefaultDomain, namedForwarding, noForwarding))
	got := gaugeBy(rec, metricDomains, semconv.AttrAutoForwardEnabled)

	if got["true"] != 2 {
		t.Errorf("auto_forward_enabled=true = %v, want 2", got["true"])
	}
	if got["false"] != 1 {
		t.Errorf("auto_forward_enabled=false = %v, want 1", got["false"])
	}
	if len(got) != 2 {
		t.Errorf("domains series = %d, want 2", len(got))
	}
}

func TestCollect_SeedsBothBucketsOnTheLiveTenant(t *testing.T) {
	// m7kni has exactly one remote domain, and it permits forwarding — so the
	// "false" bucket only exists because it is seeded.
	rec := collect(t, recordsFrom(t, liveDefaultDomain))
	got := gaugeBy(rec, metricDomains, semconv.AttrAutoForwardEnabled)
	if got["true"] != 1 {
		t.Errorf("true = %v, want 1", got["true"])
	}
	if v, ok := got["false"]; !ok || v != 0 {
		t.Errorf("false = %v (present=%t), want a seeded 0", v, ok)
	}
}

func TestCollect_TwinPerDomain(t *testing.T) {
	rec := collect(t, recordsFrom(t, liveDefaultDomain, namedForwarding))
	n := 0
	for _, l := range rec.LogRecords() {
		if l.EventName == eventName {
			n++
		}
	}
	if n != 2 {
		t.Errorf("twins = %d, want 2", n)
	}
}

func TestCollect_TwinAttributes(t *testing.T) {
	rec := collect(t, recordsFrom(t, liveDefaultDomain))
	var a map[string]string
	for _, l := range rec.LogRecords() {
		if l.EventName == eventName {
			a = l.Attrs
		}
	}
	if a == nil {
		t.Fatal("no twin")
	}
	if a[semconv.AttrDomain] != "*" {
		t.Errorf("domain = %q, want the wildcard", a[semconv.AttrDomain])
	}
	if a[semconv.AttrAutoForwardEnabled] != "true" {
		t.Errorf("auto_forward_enabled = %q", a[semconv.AttrAutoForwardEnabled])
	}
	if a[semconv.AttrAllowedOofType] != "External" {
		t.Errorf("allowed_oof_type = %q", a[semconv.AttrAllowedOofType])
	}
	if a[semconv.AttrNdrEnabled] != "true" {
		t.Errorf("ndr_enabled = %q", a[semconv.AttrNdrEnabled])
	}
	if a[semconv.AttrTrustedMailInboundEnabled] != "false" {
		t.Errorf("trusted_mail_inbound_enabled = %q", a[semconv.AttrTrustedMailInboundEnabled])
	}
	if a[semconv.AttrName] != "Default" {
		t.Errorf("name = %q", a[semconv.AttrName])
	}
}

// TestCollect_TriStateNullIsOmittedNotFalse: TNEFEnabled arrives as null, which
// means "use the default", NOT "disabled". Stamping false would assert a setting
// the tenant never made.
func TestCollect_TriStateNullIsOmittedNotFalse(t *testing.T) {
	rec := collect(t, recordsFrom(t, liveDefaultDomain))
	for _, l := range rec.LogRecords() {
		if l.EventName != eventName {
			continue
		}
		if v, present := l.Attrs[semconv.AttrTnefEnabled]; present {
			t.Errorf("null TNEFEnabled stamped as %q — it must be omitted", v)
		}
	}
	// A real bool still lands.
	rec2 := collect(t, recordsFrom(t, noForwarding))
	for _, l := range rec2.LogRecords() {
		if l.EventName == eventName && l.Attrs[semconv.AttrTnefEnabled] != "true" {
			t.Errorf("tnef_enabled = %q, want true", l.Attrs[semconv.AttrTnefEnabled])
		}
	}
}

// TestDomainTwin_Severity: auto-forwarding to EVERY remote domain (the wildcard)
// is a tenant-wide exfil path and rates Error; the same setting scoped to one
// named domain is a deliberate, narrower decision and rates Warn.
func TestDomainTwin_Severity(t *testing.T) {
	wildcard := domainTwin(recordsFrom(t, liveDefaultDomain)[0])
	if wildcard.Severity != telemetry.SeverityError {
		t.Errorf("wildcard forwarding severity = %v, want Error", wildcard.Severity)
	}
	named := domainTwin(recordsFrom(t, namedForwarding)[0])
	if named.Severity != telemetry.SeverityWarn {
		t.Errorf("named-domain forwarding severity = %v, want Warn", named.Severity)
	}
	locked := domainTwin(recordsFrom(t, noForwarding)[0])
	if locked.Severity != telemetry.SeverityInfo {
		t.Errorf("no-forwarding severity = %v, want Info", locked.Severity)
	}
}

func TestCollect_NoDomainsStillSeeds(t *testing.T) {
	rec := collect(t, nil)
	if got := len(rec.MetricPoints(metricDomains)); got != 2 {
		t.Errorf("series with no domains = %d, want 2 seeded zeros", got)
	}
}

func TestCollect_ErrorPropagates(t *testing.T) {
	rec := telemetrytest.New()
	c := New(collectors.EXODeps{Client: &fakeEXO{err: errors.New("403")}})
	if err := c.Collect(context.Background(), rec.Emitter()); err == nil {
		t.Fatal("want error when the cmdlet fails")
	}
}
