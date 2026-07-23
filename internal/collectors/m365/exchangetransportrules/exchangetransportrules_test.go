package exchangetransportrules

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

// liveEnabledRule and liveDisabledRule are VERBATIM Get-TransportRule records
// captured from the m7kni tenant as graph2otel-poller on 2026-07-23 over the
// Exchange Online admin API, trimmed to the keys the mapper reads plus the ones
// that prove its parsing rules. Every key below is on the wire; the null-valued
// recipient fields are kept precisely because they are how the field NAMES are
// verified.
//
// Two shapes worth noting, both live:
//   - Conditions/Actions/Exceptions are #Collection(String) of fully-qualified
//     .NET class names, or null when the rule has none.
//   - State/Mode are verbatim enum strings.
const liveEnabledRule = `{
  "Priority@data.type": "System.Int32",
  "Priority": 0,
  "DlpPolicy": null,
  "Comments": null,
  "CreatedBy": "Rob Knight",
  "LastModifiedBy": "Rob Knight",
  "ManuallyModified": false,
  "ActivationDate": null,
  "ExpiryDate": null,
  "Description": "If the message:\r\n\tIs received from 'Outside the organization'\r\nTake the following actions:\r\n\tPrepend the subject with 'EXTERNAL: '\r\n\tand Set audit severity level to 'Medium'\r\n",
  "Conditions@odata.type": "#Collection(String)",
  "Conditions": ["Microsoft.Exchange.MessagingPolicies.Rules.Tasks.FromScopePredicate"],
  "Exceptions": null,
  "Actions@odata.type": "#Collection(String)",
  "Actions": [
    "Microsoft.Exchange.MessagingPolicies.Rules.Tasks.PrependSubjectAction",
    "Microsoft.Exchange.MessagingPolicies.Rules.Tasks.SetAuditSeverityAction"
  ],
  "State": "Enabled",
  "Mode": "Enforce",
  "RuleErrorAction": "Ignore",
  "SenderAddressLocation": "HeaderOrEnvelope",
  "FromScope": "NotInOrganization",
  "SentToScope": null,
  "BlindCopyTo": null,
  "CopyTo": null,
  "RedirectMessageTo": null,
  "AddToRecipients": null,
  "RouteMessageOutboundConnector": null,
  "DeleteMessage": false,
  "Quarantine": false,
  "StopRuleProcessing": false,
  "PrependSubject": "EXTERNAL: ",
  "SetAuditSeverity": "Medium",
  "ApplyRightsProtectionTemplate": null,
  "Identity": "g2o-test",
  "Guid": "0ab1e768-08b0-4768-81e2-64d6f990c552",
  "Name": "g2o-test",
  "IsValid": true,
  "WhenChanged@data.type": "System.DateTime",
  "WhenChanged": "2026-07-23T21:51:45.0000000+00:00"
}`

const liveDisabledRule = `{
  "Priority@data.type": "System.Int32",
  "Priority": 1,
  "DlpPolicy": null,
  "Comments": null,
  "CreatedBy": "Rob Knight",
  "LastModifiedBy": "Rob Knight",
  "ManuallyModified": false,
  "Description": "Take the following actions:\r\n\tSet audit severity level to 'High'\r\n\tand rights protect message with RMS template:  'Encrypt' \r\n",
  "Conditions": null,
  "Exceptions": null,
  "Actions@odata.type": "#Collection(String)",
  "Actions": [
    "Microsoft.Exchange.MessagingPolicies.Rules.Tasks.SetAuditSeverityAction",
    "Microsoft.Exchange.MessagingPolicies.Rules.Tasks.RightsProtectMessageAction"
  ],
  "State": "Disabled",
  "Mode": "Enforce",
  "RuleErrorAction": "Ignore",
  "SenderAddressLocation": "Header",
  "FromScope": null,
  "BlindCopyTo": null,
  "CopyTo": null,
  "RedirectMessageTo": null,
  "AddToRecipients": null,
  "DeleteMessage": false,
  "Quarantine": false,
  "StopRuleProcessing": false,
  "PrependSubject": null,
  "SetAuditSeverity": "High",
  "ApplyRightsProtectionTemplate": "Encrypt",
  "Identity": "encrypt",
  "Guid": "4bfe3d5f-7ce5-480d-bb07-bd9f3e44c0c2",
  "Name": "encrypt",
  "IsValid": true,
  "WhenChanged": "2026-07-23T21:52:39.0000000+00:00"
}`

// m7kni has no mail-duplicating rule, so the POPULATED shape of the recipient
// fields is not verified on the wire — only their names are (they are present as
// null above). The mapper therefore tolerates BOTH shapes the admin API uses for
// multi-valued properties, and these two fixtures pin that tolerance: an array
// (as Conditions/Actions arrive) and a bare string.
const bccArrayRule = `{
  "Name": "exfil-array", "Identity": "exfil-array", "State": "Enabled", "Mode": "Enforce",
  "Priority": 2, "Conditions": null, "Actions": null, "Exceptions": null,
  "BlindCopyTo": ["attacker@evil.test"], "CopyTo": null, "RedirectMessageTo": null,
  "AddToRecipients": null, "DeleteMessage": false, "Quarantine": false
}`

const redirectStringRule = `{
  "Name": "exfil-string", "Identity": "exfil-string", "State": "Disabled", "Mode": "Enforce",
  "Priority": 3, "Conditions": null, "Actions": null, "Exceptions": null,
  "BlindCopyTo": null, "CopyTo": null, "RedirectMessageTo": "attacker@evil.test",
  "AddToRecipients": null, "DeleteMessage": false, "Quarantine": false
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

func gaugeBy(rec *telemetrytest.Recorder, metric string, keys ...string) map[string]float64 {
	out := map[string]float64{}
	for _, p := range rec.MetricPoints(metric) {
		k := ""
		for i, key := range keys {
			if i > 0 {
				k += "/"
			}
			k += p.Attrs[key]
		}
		out[k] = p.Value
	}
	return out
}

func TestCollect_RulesGauge(t *testing.T) {
	rec := collect(t, recordsFrom(t, liveEnabledRule, liveDisabledRule))
	got := gaugeBy(rec, metricRules, semconv.AttrState, semconv.AttrRuleMode)

	if got[stateEnabled+"/"+modeEnforce] != 1 {
		t.Errorf("Enabled/Enforce = %v, want 1", got[stateEnabled+"/"+modeEnforce])
	}
	if got[stateDisabled+"/"+modeEnforce] != 1 {
		t.Errorf("Disabled/Enforce = %v, want 1", got[stateDisabled+"/"+modeEnforce])
	}
	// A disabled rule is not a dormant nothing — it is one toggle from live, so
	// the audit modes are seeded too.
	if v, ok := got[stateEnabled+"/"+modeAudit]; !ok || v != 0 {
		t.Errorf("Enabled/Audit = %v (present=%t), want a seeded 0", v, ok)
	}
	if len(got) != 6 {
		t.Errorf("rules series = %d, want 2 states x 3 modes", len(got))
	}
}

// TestCollect_RedirectingGauge is the BEC-persistence signal: a rule that
// duplicates or diverts mail to another recipient.
func TestCollect_RedirectingGauge(t *testing.T) {
	rec := collect(t, recordsFrom(t, liveEnabledRule, liveDisabledRule, bccArrayRule, redirectStringRule))
	got := gaugeBy(rec, metricRedirecting, semconv.AttrState)

	if got[stateEnabled] != 1 {
		t.Errorf("Enabled redirecting = %v, want 1 (the BCC rule)", got[stateEnabled])
	}
	if got[stateDisabled] != 1 {
		t.Errorf("Disabled redirecting = %v, want 1 (the redirect rule)", got[stateDisabled])
	}
	if len(got) != 2 {
		t.Errorf("redirecting series = %d, want one per state", len(got))
	}
}

func TestCollect_NoRedirectingRulesStillSeedsZero(t *testing.T) {
	rec := collect(t, recordsFrom(t, liveEnabledRule, liveDisabledRule))
	got := gaugeBy(rec, metricRedirecting, semconv.AttrState)
	if got[stateEnabled] != 0 || got[stateDisabled] != 0 {
		t.Errorf("redirecting = %v, want all zero on the live tenant", got)
	}
	if len(got) != 2 {
		t.Errorf("redirecting series = %d, want a seeded 0 per state", len(got))
	}
}

// TestCollect_TwinPerRule enforces #114: every rule fetched gets a twin.
func TestCollect_TwinPerRule(t *testing.T) {
	rec := collect(t, recordsFrom(t, liveEnabledRule, liveDisabledRule))
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
	rec := collect(t, recordsFrom(t, liveEnabledRule))
	var a map[string]string
	for _, l := range rec.LogRecords() {
		if l.EventName == eventName {
			a = l.Attrs
		}
	}
	if a == nil {
		t.Fatal("no twin")
	}
	if a[semconv.AttrName] != "g2o-test" {
		t.Errorf("name = %q", a[semconv.AttrName])
	}
	if a[semconv.AttrState] != stateEnabled {
		t.Errorf("state = %q", a[semconv.AttrState])
	}
	if a[semconv.AttrRuleMode] != modeEnforce {
		t.Errorf("rule_mode = %q", a[semconv.AttrRuleMode])
	}
	if a[semconv.AttrPriority] != "0" {
		t.Errorf("priority = %q, want 0", a[semconv.AttrPriority])
	}
	if a[semconv.AttrCreatedBy] != "Rob Knight" {
		t.Errorf("created_by = %q", a[semconv.AttrCreatedBy])
	}
	if a[semconv.AttrFromScope] != "NotInOrganization" {
		t.Errorf("from_scope = %q", a[semconv.AttrFromScope])
	}
	if a[semconv.AttrPrependSubject] != "EXTERNAL: " {
		t.Errorf("prepend_subject = %q", a[semconv.AttrPrependSubject])
	}
	if a[semconv.AttrRedirectsMail] != "false" {
		t.Errorf("redirects_mail = %q, want false", a[semconv.AttrRedirectsMail])
	}
	// Null recipient fields are omitted, never stamped empty.
	if _, present := a[semconv.AttrBlindCopyTo]; present {
		t.Error("null BlindCopyTo should be omitted")
	}
}

// TestCollect_TwinStripsTheConstantNamespace: the .NET class names carry a
// 53-character constant namespace prefix. It is stripped so the values are
// readable as structured metadata; anything NOT under that exact prefix passes
// through verbatim, so a namespace change degrades to the raw value rather than
// being mangled.
func TestCollect_TwinStripsTheConstantNamespace(t *testing.T) {
	rec := collect(t, recordsFrom(t, liveEnabledRule))
	var a map[string]string
	for _, l := range rec.LogRecords() {
		if l.EventName == eventName {
			a = l.Attrs
		}
	}
	if a[semconv.AttrConditionTypes] != "FromScopePredicate" {
		t.Errorf("condition_types = %q, want FromScopePredicate", a[semconv.AttrConditionTypes])
	}
	want := "PrependSubjectAction,SetAuditSeverityAction"
	if a[semconv.AttrActionTypes] != want {
		t.Errorf("action_types = %q, want %q", a[semconv.AttrActionTypes], want)
	}
}

func TestShortClassName(t *testing.T) {
	if got := shortClassName(rulesNamespace + "FromScopePredicate"); got != "FromScopePredicate" {
		t.Errorf("prefixed = %q", got)
	}
	// Not under the known namespace: verbatim, not mangled.
	const other = "Some.Other.Namespace.Thing"
	if got := shortClassName(other); got != other {
		t.Errorf("foreign namespace = %q, want it verbatim", got)
	}
}

// TestRuleTwin_Severity: an ENABLED rule that duplicates or diverts mail is the
// textbook BEC persistence shape, so it is Error. The same rule disabled is one
// toggle away, so it is Warn rather than Info.
func TestRuleTwin_Severity(t *testing.T) {
	enabledBCC := ruleTwin(recordsFrom(t, bccArrayRule)[0])
	if enabledBCC.Severity != telemetry.SeverityError {
		t.Errorf("enabled BCC rule severity = %v, want Error", enabledBCC.Severity)
	}
	disabledRedirect := ruleTwin(recordsFrom(t, redirectStringRule)[0])
	if disabledRedirect.Severity != telemetry.SeverityWarn {
		t.Errorf("disabled redirect rule severity = %v, want Warn", disabledRedirect.Severity)
	}
	ordinary := ruleTwin(recordsFrom(t, liveEnabledRule)[0])
	if ordinary.Severity != telemetry.SeverityInfo {
		t.Errorf("ordinary rule severity = %v, want Info", ordinary.Severity)
	}
}

// TestRecipientsOf pins the shape tolerance directly.
func TestRecipientsOf(t *testing.T) {
	arr := recordsFrom(t, bccArrayRule)[0]
	if got, ok := recipientsOf(arr, "BlindCopyTo"); !ok || got != "attacker@evil.test" {
		t.Errorf("array shape = %q (ok=%t)", got, ok)
	}
	strv := recordsFrom(t, redirectStringRule)[0]
	if got, ok := recipientsOf(strv, "RedirectMessageTo"); !ok || got != "attacker@evil.test" {
		t.Errorf("string shape = %q (ok=%t)", got, ok)
	}
	if _, ok := recipientsOf(arr, "CopyTo"); ok {
		t.Error("null field should report absent")
	}
}

func TestCollect_NoRulesStillSeeds(t *testing.T) {
	rec := collect(t, nil)
	if got := len(rec.MetricPoints(metricRules)); got != 6 {
		t.Errorf("rules series with no rules = %d, want 6 seeded zeros", got)
	}
	for _, l := range rec.LogRecords() {
		if l.EventName == eventName {
			t.Error("no rules should emit no twins")
		}
	}
}

func TestCollect_ErrorPropagates(t *testing.T) {
	rec := telemetrytest.New()
	c := New(collectors.EXODeps{Client: &fakeEXO{err: errors.New("403")}})
	if err := c.Collect(context.Background(), rec.Emitter()); err == nil {
		t.Fatal("want error when the cmdlet fails")
	}
}
