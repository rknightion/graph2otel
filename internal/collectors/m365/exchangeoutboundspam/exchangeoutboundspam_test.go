package exchangeoutboundspam

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

// liveDefaultPolicy is the (sanitized) Get-HostedOutboundSpamFilterPolicy
// record captured from the m7kni tenant as graph2otel-poller on 2026-07-28
// (#357), narrowed to the keys the mapper reads. Real tenant GUIDs and the
// tenant domain are replaced with example values; every field VALUE is
// otherwise verbatim, including the zero recipient limits and
// Enabled=false — this tenant's default outbound spam policy is disabled and
// unlimited, which is itself a real, capturable posture.
const liveDefaultPolicy = `{
  "AdminDisplayName": "",
  "IsDefault": true,
  "ConfigurationType": "HostedOutboundSpamFilterPolicy",
  "Enabled": false,
  "RecipientLimitExternalPerHour": 0,
  "RecipientLimitInternalPerHour": 0,
  "RecipientLimitPerDay": 0,
  "ActionWhenThresholdReached": "BlockUserForToday",
  "NotifyOutboundSpamRecipients": [],
  "BccSuspiciousOutboundAdditionalRecipients": [],
  "BccSuspiciousOutboundMail": false,
  "NotifyOutboundSpam": false,
  "RecommendedPolicyType": "Custom",
  "AutoForwardingMode": "Automatic",
  "Name": "Default",
  "DistinguishedName": "CN=Default,CN=Outbound Spam Filter,CN=Transport Settings,CN=Configuration,CN=example.onmicrosoft.com,CN=ConfigurationUnits,DC=example,DC=prod,DC=outlook,DC=com",
  "Identity": "Default",
  "WhenChangedUTC": "2026-07-15T19:29:15.0000000Z",
  "ExchangeObjectId": "24bc71e7-3c70-4b04-9230-34159eb5109a",
  "OrganizationId": "example.prod.outlook.com/Microsoft Exchange Hosted Organizations/example.onmicrosoft.com",
  "Id": "Default",
  "Guid": "24bc71e7-3c70-4b04-9230-34159eb5109a",
  "IsValid": true
}`

// customEnabledPolicy is a SYNTHESIZED custom outbound spam policy (no such
// row exists on the m7kni tenant — it has no custom policies) exercising the
// "custom, enabled, with real limits and recipients" branch the acceptance
// criteria calls out.
const customEnabledPolicy = `{
  "AdminDisplayName": "Contoso Executives",
  "IsDefault": false,
  "ConfigurationType": "HostedOutboundSpamFilterPolicy",
  "Enabled": true,
  "RecipientLimitExternalPerHour": 500,
  "RecipientLimitInternalPerHour": 1000,
  "RecipientLimitPerDay": 2000,
  "ActionWhenThresholdReached": "Alert",
  "NotifyOutboundSpamRecipients": ["secops@example.com"],
  "BccSuspiciousOutboundAdditionalRecipients": ["archive@example.com"],
  "BccSuspiciousOutboundMail": true,
  "NotifyOutboundSpam": true,
  "RecommendedPolicyType": "Custom",
  "AutoForwardingMode": "Off",
  "Name": "Contoso Executives",
  "DistinguishedName": "CN=Contoso Executives,CN=Outbound Spam Filter,CN=Transport Settings,CN=Configuration,CN=example.onmicrosoft.com,CN=ConfigurationUnits,DC=example,DC=prod,DC=outlook,DC=com",
  "Identity": "Contoso Executives",
  "WhenChangedUTC": "2026-07-20T09:00:00.0000000Z",
  "ExchangeObjectId": "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
  "OrganizationId": "example.prod.outlook.com/Microsoft Exchange Hosted Organizations/example.onmicrosoft.com",
  "Id": "Contoso Executives",
  "Guid": "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
  "IsValid": true
}`

// customDisabledPolicy is a SYNTHESIZED custom policy with Enabled=false, to
// prove a disabled custom policy still gets a twin (Enabled is not a filter,
// only a fact) and is counted correctly in the policies gauge.
const customDisabledPolicy = `{
  "AdminDisplayName": "Legacy Exclusion",
  "IsDefault": false,
  "ConfigurationType": "HostedOutboundSpamFilterPolicy",
  "Enabled": false,
  "RecipientLimitExternalPerHour": 400,
  "RecipientLimitInternalPerHour": 800,
  "RecipientLimitPerDay": 1600,
  "ActionWhenThresholdReached": "BlockUser",
  "NotifyOutboundSpamRecipients": [],
  "BccSuspiciousOutboundAdditionalRecipients": [],
  "BccSuspiciousOutboundMail": false,
  "NotifyOutboundSpam": false,
  "RecommendedPolicyType": "Custom",
  "AutoForwardingMode": "Automatic",
  "Name": "Legacy Exclusion",
  "DistinguishedName": "CN=Legacy Exclusion,CN=Outbound Spam Filter,CN=Transport Settings,CN=Configuration,CN=example.onmicrosoft.com,CN=ConfigurationUnits,DC=example,DC=prod,DC=outlook,DC=com",
  "Identity": "Legacy Exclusion",
  "WhenChangedUTC": "2026-06-01T09:00:00.0000000Z",
  "ExchangeObjectId": "11111111-2222-3333-4444-555555555555",
  "OrganizationId": "example.prod.outlook.com/Microsoft Exchange Hosted Organizations/example.onmicrosoft.com",
  "Id": "Legacy Exclusion",
  "Guid": "11111111-2222-3333-4444-555555555555",
  "IsValid": true
}`

type fakeEXO struct {
	recs   []map[string]any
	err    error
	params map[string]any
	called bool
}

func (f *fakeEXO) Invoke(_ context.Context, _ string, params map[string]any) ([]map[string]any, error) {
	f.called = true
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

// TestCollect_NoResultSizeParam: Get-HostedOutboundSpamFilterPolicy has no
// ResultSize parameter (live docs, learn.microsoft.com, checked 2026-07-28)
// — unlike Get-AcceptedDomain/Get-Mailbox, so this collector must NOT pass
// one; passing an unsupported parameter to an EXO cmdlet is itself an error
// on some cmdlets.
func TestCollect_NoResultSizeParam(t *testing.T) {
	exo := &fakeEXO{recs: recordsFrom(t, liveDefaultPolicy)}
	collectWith(t, exo)
	if exo.params != nil {
		t.Errorf("params = %#v, want nil (this cmdlet accepts no ResultSize)", exo.params)
	}
}

func TestCollect_TwinPerPolicy(t *testing.T) {
	rec := collect(t, recordsFrom(t, liveDefaultPolicy, customEnabledPolicy, customDisabledPolicy))
	n := 0
	for _, l := range rec.LogRecords() {
		if l.EventName == eventName {
			n++
		}
	}
	if n != 3 {
		t.Errorf("twins = %d, want 3 (all returned policies receive twins)", n)
	}
}

func TestCollect_AccountsEveryPolicyOnce(t *testing.T) {
	outcomes := recordoutcome.NewRecorder()
	recs := recordsFrom(t, liveDefaultPolicy, customEnabledPolicy, customDisabledPolicy)
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

func TestCollect_PolicyCountGauge(t *testing.T) {
	rec := collect(t, recordsFrom(t, liveDefaultPolicy, customEnabledPolicy, customDisabledPolicy))
	type key struct{ isDefault, enabled string }
	got := map[key]float64{}
	for _, p := range rec.MetricPoints(metricPolicies) {
		got[key{p.Attrs[semconv.AttrIsDefault], p.Attrs[semconv.AttrEnabled]}] += p.Value
	}
	if got[key{"true", "false"}] != 1 {
		t.Errorf("default+disabled = %v, want 1", got[key{"true", "false"}])
	}
	if got[key{"false", "true"}] != 1 {
		t.Errorf("custom+enabled = %v, want 1", got[key{"false", "true"}])
	}
	if got[key{"false", "false"}] != 1 {
		t.Errorf("custom+disabled = %v, want 1", got[key{"false", "false"}])
	}
}

// TestCollect_PolicyIdentityNeverOnMetric: policy name/identity is per-entity
// and must never become a gauge label (#112) — it lives on the twin only.
func TestCollect_PolicyIdentityNeverOnMetric(t *testing.T) {
	rec := collect(t, recordsFrom(t, liveDefaultPolicy, customEnabledPolicy))
	for _, p := range rec.MetricPoints(metricPolicies) {
		if _, ok := p.Attrs[semconv.AttrName]; ok {
			t.Errorf("policies gauge point carries a name label: %#v", p.Attrs)
		}
		if _, ok := p.Attrs[semconv.AttrIdentity]; ok {
			t.Errorf("policies gauge point carries an identity label: %#v", p.Attrs)
		}
	}
	for _, p := range rec.MetricPoints(metricRecipientLimit) {
		if _, ok := p.Attrs[semconv.AttrName]; ok {
			t.Errorf("recipient_limit gauge point carries a name label: %#v", p.Attrs)
		}
	}
}

// TestCollect_DefaultPolicyRecipientLimitGauge: the recipient_limit{limit}
// gauge is sourced ONLY from the tenant's default policy — see the package
// doc for why a per-custom-policy series is not emitted.
func TestCollect_DefaultPolicyRecipientLimitGauge(t *testing.T) {
	rec := collect(t, recordsFrom(t, liveDefaultPolicy, customEnabledPolicy))
	got := map[string]float64{}
	for _, p := range rec.MetricPoints(metricRecipientLimit) {
		got[p.Attrs[semconv.AttrLimit]] = p.Value
	}
	// The DEFAULT policy's limits are all zero on this tenant — a measured
	// zero, not an absent series (RecipientLimitExternalPerHour is present
	// on the wire as the JSON number 0).
	if v, ok := got["external_per_hour"]; !ok || v != 0 {
		t.Errorf("external_per_hour = %v, ok=%v, want 0, true", v, ok)
	}
	if v, ok := got["internal_per_hour"]; !ok || v != 0 {
		t.Errorf("internal_per_hour = %v, ok=%v, want 0, true", v, ok)
	}
	if v, ok := got["per_day"]; !ok || v != 0 {
		t.Errorf("per_day = %v, ok=%v, want 0, true", v, ok)
	}
	// The custom policy's non-zero limits (500/1000/2000) must NOT leak into
	// this gauge.
	for _, v := range got {
		if v == 500 || v == 1000 || v == 2000 {
			t.Errorf("recipient_limit gauge leaked a non-default policy's value: %v", got)
		}
	}
}

// TestCollect_NoDefaultPolicy_NoRecipientLimitGauge: without a policy whose
// IsDefault is true, fabricating a recipient_limit gauge from an arbitrary
// policy would misrepresent the tenant's actual fallback limits, so no
// points are emitted at all.
func TestCollect_NoDefaultPolicy_NoRecipientLimitGauge(t *testing.T) {
	rec := collect(t, recordsFrom(t, customEnabledPolicy))
	if pts := rec.MetricPoints(metricRecipientLimit); len(pts) != 0 {
		t.Errorf("recipient_limit points = %d, want 0 (no default policy in this poll)", len(pts))
	}
}

func TestCollect_DefaultTwinAttributes(t *testing.T) {
	rec := collect(t, recordsFrom(t, liveDefaultPolicy))
	var a map[string]string
	for _, l := range rec.LogRecords() {
		if l.EventName == eventName {
			a = l.Attrs
		}
	}
	if a == nil {
		t.Fatal("no twin")
	}
	if a[semconv.AttrName] != "Default" {
		t.Errorf("name = %q", a[semconv.AttrName])
	}
	if a[semconv.AttrIsDefault] != "true" {
		t.Errorf("is_default = %q", a[semconv.AttrIsDefault])
	}
	if a[semconv.AttrEnabled] != "false" {
		t.Errorf("enabled = %q", a[semconv.AttrEnabled])
	}
	if a[semconv.AttrAutoForwardingMode] != "Automatic" {
		t.Errorf("auto_forwarding_mode = %q", a[semconv.AttrAutoForwardingMode])
	}
	if a[semconv.AttrActionWhenThresholdReached] != "BlockUserForToday" {
		t.Errorf("action_when_threshold_reached = %q", a[semconv.AttrActionWhenThresholdReached])
	}
	if a[semconv.AttrRecommendedPolicyType] != "Custom" {
		t.Errorf("recommended_policy_type = %q", a[semconv.AttrRecommendedPolicyType])
	}
	if a[semconv.AttrConfigType] != "HostedOutboundSpamFilterPolicy" {
		t.Errorf("config_type = %q", a[semconv.AttrConfigType])
	}
	if a[semconv.AttrGuid] != "24bc71e7-3c70-4b04-9230-34159eb5109a" {
		t.Errorf("guid = %q", a[semconv.AttrGuid])
	}
	if a[semconv.AttrWhenChangedUtc] == "" {
		t.Error("when_changed_utc should be present")
	}
	// RecipientLimit* are present on the wire as 0, a measured fact, so they
	// must be STAMPED, not omitted.
	if v, ok := a[semconv.AttrRecipientLimitExternalPerHour]; !ok || v != "0" {
		t.Errorf("recipient_limit_external_per_hour = %q, ok=%v, want \"0\", true", v, ok)
	}
	// Empty recipient-list arrays on the wire must be OMITTED (SetStrs/the
	// capped-array helper both omit empty slices), never stamped as an empty
	// list.
	if v, ok := a[semconv.AttrNotifyOutboundSpamRecipients]; ok {
		t.Errorf("notify_outbound_spam_recipients present as %v, want omitted (empty on the wire)", v)
	}
	if v, ok := a[semconv.AttrBccSuspiciousOutboundAdditionalRecipients]; ok {
		t.Errorf("bcc_suspicious_outbound_additional_recipients present as %v, want omitted (empty on the wire)", v)
	}
}

func TestCollect_CustomPolicyRecipientListsCaptured(t *testing.T) {
	rec := collect(t, recordsFrom(t, customEnabledPolicy))
	var a map[string]string
	for _, l := range rec.LogRecords() {
		if l.EventName == eventName {
			a = l.Attrs
		}
	}
	if a == nil {
		t.Fatal("no twin")
	}
	if a[semconv.AttrBccSuspiciousOutboundMail] != "true" {
		t.Errorf("bcc_suspicious_outbound_mail = %q", a[semconv.AttrBccSuspiciousOutboundMail])
	}
	if a[semconv.AttrNotifyOutboundSpam] != "true" {
		t.Errorf("notify_outbound_spam = %q", a[semconv.AttrNotifyOutboundSpam])
	}
	if a[semconv.AttrRecipientLimitExternalPerHour] != "500" {
		t.Errorf("recipient_limit_external_per_hour = %q, want 500", a[semconv.AttrRecipientLimitExternalPerHour])
	}
}

// TestCollect_DisabledCustomPolicyStillTwinned: Enabled=false is a fact to
// report, not a filter — the acceptance criteria explicitly call out the
// disabled case.
func TestCollect_DisabledCustomPolicyStillTwinned(t *testing.T) {
	rec := collect(t, recordsFrom(t, customDisabledPolicy))
	found := false
	for _, l := range rec.LogRecords() {
		if l.EventName == eventName {
			found = true
			if l.Attrs[semconv.AttrEnabled] != "false" {
				t.Errorf("enabled = %q, want false", l.Attrs[semconv.AttrEnabled])
			}
		}
	}
	if !found {
		t.Fatal("disabled custom policy should still emit a twin")
	}
}

func TestCollect_EmptyResult_NoEmit(t *testing.T) {
	rec := collect(t, nil)
	if logs := rec.LogRecords(); len(logs) != 0 {
		t.Errorf("empty result should emit no twins, got %d", len(logs))
	}
	if pts := rec.MetricPoints(metricPolicies); len(pts) != 0 {
		t.Errorf("empty result should emit no policies gauge points, got %d", len(pts))
	}
	if pts := rec.MetricPoints(metricRecipientLimit); len(pts) != 0 {
		t.Errorf("empty result should emit no recipient_limit points, got %d", len(pts))
	}
}

func TestCollect_ErrorPropagates(t *testing.T) {
	rec := telemetrytest.New()
	c := New(collectors.EXODeps{Client: &fakeEXO{err: errors.New("403")}})
	if err := c.Collect(context.Background(), rec.Emitter(), recordoutcome.NewRecorder()); err == nil {
		t.Fatal("want error when the cmdlet fails")
	}
}
