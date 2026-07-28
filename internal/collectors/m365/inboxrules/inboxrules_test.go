package inboxrules

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/rknightion/graph2otel/internal/collectors"
	"github.com/rknightion/graph2otel/internal/recordoutcome"
	"github.com/rknightion/graph2otel/internal/semconv"
	"github.com/rknightion/graph2otel/internal/telemetrytest"
)

// forwardRuleFixture is the real forwarding rule captured live from m7kni
// (live-measured 2026-07-28, #363), full non-default property set. RuleIdentity
// is written WITHOUT quotes, i.e. as a JSON number, matching the wire shape.
const forwardRuleFixture = `{
  "Description": "If the message: the message includes specific words in the subject 'g2o-test-forward' Take the following actions: forward the message to 'Rob Knight'",
  "Enabled": true,
  "Identity": "7957928c-3cd2-4bbb-98c8-cfc8466f490a\\15394007230974001153",
  "ErrorType": "None",
  "Name": "g2o-test-forward",
  "Priority": 1,
  "RuleIdentity": 15394007230974001153,
  "SupportedByTask": true,
  "SubjectContainsWords": ["g2o-test-forward"],
  "ForwardTo": ["\"Rob Knight\" [EX:/o=ExchangeLabs/ou=Exchange Administrative Group (FYDIBOHF23SPDLT)/cn=Recipients/cn=8450ce8cf45b4ee88feb21c3cacff073-bbcfc3c5-0b]"],
  "MailboxOwnerId": "7957928c-3cd2-4bbb-98c8-cfc8466f490a",
  "IsValid": true,
  "ObjectState": "Unchanged"
}`

// junkRuleFixture is the system Junk E-mail Rule: hidden, only returned with
// -IncludeHidden, no forwarding fields.
const junkRuleFixture = `{
  "Name": "Junk E-mail Rule",
  "Priority": 0,
  "Enabled": true,
  "RuleIdentity": 721857812023476225,
  "Identity": "7957928c-3cd2-4bbb-98c8-cfc8466f490a\\721857812023476225",
  "IsValid": true,
  "ObjectState": "Unchanged"
}`

// recordsFrom decodes fixtures with a PLAIN json.Unmarshal into map[string]any
// — the shape internal/exoclient actually produces (no UseNumber), so any
// BigInteger-valued field is ALREADY a float64 by the time this collector
// sees it. This is deliberately the "corrupted" decode path used to prove
// ruleIdentityString does not make that corruption any worse (see the
// package doc and TestRuleIdentity*).
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

// recordsFromPreservingNumbers decodes with json.Number preserved (UseNumber),
// simulating a decoder that keeps full precision for a BigInteger field. Real
// exoclient does not do this today; this helper exists to prove
// ruleIdentityString round-trips a json.Number exactly WHEN one is handed to
// it, rather than assuming every caller hands it a float64.
func recordsFromPreservingNumbers(t *testing.T, docs ...string) []map[string]any {
	t.Helper()
	out := make([]map[string]any, 0, len(docs))
	for _, d := range docs {
		var m map[string]any
		dec := json.NewDecoder(bytes.NewReader([]byte(d)))
		dec.UseNumber()
		if err := dec.Decode(&m); err != nil {
			t.Fatalf("unmarshal fixture (UseNumber): %v", err)
		}
		out = append(out, m)
	}
	return out
}

// fakeEXO is a canned EXOClient serving both Get-Mailbox (enumeration) and
// Get-InboxRule (per-mailbox), keyed by cmdlet name.
type fakeEXO struct {
	mailboxRows []map[string]any
	mailboxErr  error

	// rulesByMailbox / ruleErrByMailbox key on the Mailbox param
	// (PrimarySmtpAddress) Get-InboxRule was called with.
	rulesByMailbox   map[string][]map[string]any
	ruleErrByMailbox map[string]error

	calls []fakeCall
}

type fakeCall struct {
	cmdlet string
	params map[string]any
}

func (f *fakeEXO) Invoke(_ context.Context, cmdlet string, params map[string]any) ([]map[string]any, error) {
	f.calls = append(f.calls, fakeCall{cmdlet: cmdlet, params: params})
	switch cmdlet {
	case "Get-Mailbox":
		if f.mailboxErr != nil {
			return nil, f.mailboxErr
		}
		return f.mailboxRows, nil
	case "Get-InboxRule":
		addr, _ := params["Mailbox"].(string)
		if err, ok := f.ruleErrByMailbox[addr]; ok {
			return nil, err
		}
		return f.rulesByMailbox[addr], nil
	default:
		return nil, fmt.Errorf("unexpected cmdlet %q", cmdlet)
	}
}

func mailboxRow(addr string) map[string]any {
	return map[string]any{
		"PrimarySmtpAddress":   addr,
		"DisplayName":          "dn-" + addr,
		"Identity":             "id-" + addr,
		"RecipientTypeDetails": "UserMailbox",
	}
}

func collect(t *testing.T, exo *fakeEXO, capN int) (*telemetrytest.Recorder, error) {
	t.Helper()
	rec := telemetrytest.New()
	c := New(collectors.EXODeps{Client: exo, PerMailboxCap: capN})
	err := c.Collect(context.Background(), rec.Emitter(), recordoutcome.NewRecorder())
	return rec, err
}

// TestNewFromZeroValuedEXODepsIsSafe pins the composition-root contract: the
// factory is called with a completely zero-valued EXODeps to build an
// availability candidate (and on the transport-init error path), and
// immediately has Name() called on the result. It must never panic, and
// Collect() must be a safe no-op too (defensive: the collector has no client
// to poll).
func TestNewFromZeroValuedEXODepsIsSafe(t *testing.T) {
	c := New(collectors.EXODeps{})
	if got := c.Name(); got != collectorName {
		t.Errorf("Name() = %q, want %q", got, collectorName)
	}
	if c.DefaultInterval() <= 0 {
		t.Error("DefaultInterval() must be positive")
	}
	if c.RequiredPermissions() != nil {
		t.Errorf("RequiredPermissions() = %v, want nil", c.RequiredPermissions())
	}
	rec := telemetrytest.New()
	if err := c.Collect(context.Background(), rec.Emitter(), recordoutcome.NewRecorder()); err != nil {
		t.Errorf("Collect() on a zero-valued collector must be a safe no-op, got error: %v", err)
	}
}

// TestPerMailboxIsAlwaysTrue pins that this collector self-identifies to the
// composition root's exo_per_mailbox.enabled gate via
// collectors.PerMailboxCollector, and never reads PerMailboxEnabled itself —
// enablement is the composition root's job.
func TestPerMailboxIsAlwaysTrue(t *testing.T) {
	c := New(collectors.EXODeps{})
	if !c.PerMailbox() {
		t.Error("PerMailbox() = false, want true")
	}
	if !collectors.IsPerMailbox(c) {
		t.Error("collectors.IsPerMailbox(c) = false, want true")
	}
}

// TestCollectPollsIncludeHiddenPerMailbox pins the one non-optional cmdlet
// parameter: without -IncludeHidden, a mailbox whose only rule is the system
// Junk E-mail Rule live-measures 0 rows instead of 1 (#363's package doc).
func TestCollectPollsIncludeHiddenPerMailbox(t *testing.T) {
	exo := &fakeEXO{
		mailboxRows: []map[string]any{mailboxRow("a@x.com")},
		rulesByMailbox: map[string][]map[string]any{
			"a@x.com": recordsFrom(t, junkRuleFixture),
		},
	}
	if _, err := collect(t, exo, 0); err != nil {
		t.Fatalf("Collect: %v", err)
	}

	var ruleCall *fakeCall
	for i := range exo.calls {
		if exo.calls[i].cmdlet == "Get-InboxRule" {
			ruleCall = &exo.calls[i]
		}
	}
	if ruleCall == nil {
		t.Fatal("Get-InboxRule was never called")
	}
	if got := ruleCall.params["Mailbox"]; got != "a@x.com" {
		t.Errorf("Mailbox param = %v, want a@x.com", got)
	}
	if got, ok := ruleCall.params["IncludeHidden"].(bool); !ok || !got {
		t.Errorf("IncludeHidden param = %v (ok=%v), want true", ruleCall.params["IncludeHidden"], ok)
	}
}

// TestCollectEmitsMailboxCoverageEveryCycle pins that mailboxes_covered /
// mailboxes_total are emitted every cycle, and that a cap smaller than the
// tenant leaves Covered < Total visible rather than looking like a small
// tenant.
func TestCollectEmitsMailboxCoverageEveryCycle(t *testing.T) {
	exo := &fakeEXO{
		mailboxRows: []map[string]any{mailboxRow("a@x.com"), mailboxRow("b@x.com"), mailboxRow("c@x.com")},
		rulesByMailbox: map[string][]map[string]any{
			"a@x.com": nil,
			"b@x.com": nil,
		},
	}
	rec, err := collect(t, exo, 2)
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	if got := gaugeValue(t, rec, metricMailboxesCovered); got != 2 {
		t.Errorf("mailboxes_covered = %v, want 2", got)
	}
	if got := gaugeValue(t, rec, metricMailboxesTotal); got != 3 {
		t.Errorf("mailboxes_total = %v, want 3", got)
	}
}

// TestCollectEmitsCoverageGaugesEvenWithZeroMailboxes proves the "empty
// tenant" case is not silently indistinguishable from "the poll never ran":
// both coverage gauges still emit a zero-valued point.
func TestCollectEmitsCoverageGaugesEvenWithZeroMailboxes(t *testing.T) {
	exo := &fakeEXO{mailboxRows: nil}
	rec, err := collect(t, exo, 0)
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	if got := gaugeValue(t, rec, metricMailboxesCovered); got != 0 {
		t.Errorf("mailboxes_covered = %v, want 0", got)
	}
	if got := gaugeValue(t, rec, metricMailboxesTotal); got != 0 {
		t.Errorf("mailboxes_total = %v, want 0", got)
	}
	if pts := rec.MetricPoints(metricRules); len(pts) != 0 {
		t.Errorf("rules gauge should have no points with no mailboxes, got %d", len(pts))
	}
}

// TestCollectEnumerateErrorPropagates pins that a Get-Mailbox failure is
// returned as an error rather than silently reporting an empty tenant.
func TestCollectEnumerateErrorPropagates(t *testing.T) {
	sentinel := errors.New("throttled")
	exo := &fakeEXO{mailboxErr: sentinel}
	_, err := collect(t, exo, 0)
	if !errors.Is(err, sentinel) {
		t.Fatalf("err = %v, want wrapped %v", err, sentinel)
	}
}

// TestCollectPerMailboxErrorIsPartial pins that one mailbox's Get-InboxRule
// failure does not prevent the others from being collected and emitted — the
// same partial-success shape as internal/collectors/entra/risk's two halves.
func TestCollectPerMailboxErrorIsPartial(t *testing.T) {
	exo := &fakeEXO{
		mailboxRows: []map[string]any{mailboxRow("a@x.com"), mailboxRow("b@x.com")},
		rulesByMailbox: map[string][]map[string]any{
			"b@x.com": recordsFrom(t, junkRuleFixture),
		},
		ruleErrByMailbox: map[string]error{
			"a@x.com": errors.New("access denied"),
		},
	}
	rec, err := collect(t, exo, 0)
	if err == nil {
		t.Fatal("want a non-nil error surfacing the a@x.com failure")
	}
	logs := rec.LogRecords()
	if len(logs) != 1 {
		t.Fatalf("want 1 twin (from b@x.com), got %d", len(logs))
	}
}

// TestRuleIdentityPreservesFullPrecisionViaJSONNumber pins that when the
// source map holds a json.Number for RuleIdentity, the twin's rule_identity
// attribute is the EXACT wire value, not a float64 round-trip.
func TestRuleIdentityPreservesFullPrecisionViaJSONNumber(t *testing.T) {
	exo := &fakeEXO{
		mailboxRows: []map[string]any{mailboxRow("a@x.com")},
		rulesByMailbox: map[string][]map[string]any{
			"a@x.com": recordsFromPreservingNumbers(t, forwardRuleFixture),
		},
	}
	rec, err := collect(t, exo, 0)
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	twin := onlyLog(t, rec)
	got := twin.Attrs[semconv.AttrRuleIdentity]
	if got != "15394007230974001153" {
		t.Errorf("rule_identity = %q, want exact wire value 15394007230974001153", got)
	}
}

// TestRuleIdentityFloat64DecodeIsDocumentedNotWorsened pins the SILENT
// CORRUPTION trap itself: a plain json.Unmarshal into map[string]any (the
// shape internal/exoclient actually produces today) already rounds
// 15394007230974001153 to 15394007230974001152 by the time this collector's
// code runs — a fact this package cannot repair, only refuse to make worse.
// This test proves ruleIdentityString renders that already-corrupted value as
// a plain fixed-point decimal (never scientific notation, never truncated),
// so the corruption is visible and stable rather than compounding.
func TestRuleIdentityFloat64DecodeIsDocumentedNotWorsened(t *testing.T) {
	exo := &fakeEXO{
		mailboxRows: []map[string]any{mailboxRow("a@x.com")},
		rulesByMailbox: map[string][]map[string]any{
			"a@x.com": recordsFrom(t, forwardRuleFixture), // plain Unmarshal: float64
		},
	}
	rec, err := collect(t, exo, 0)
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	twin := onlyLog(t, rec)
	got := twin.Attrs[semconv.AttrRuleIdentity]
	if strings.ContainsAny(got, "eE") {
		t.Errorf("rule_identity = %q must never be scientific notation", got)
	}
	// The documented off-by-one from the package doc: 15394007230974001153
	// rounds to the nearest float64, 15394007230974001152.
	if got != "15394007230974001152" {
		t.Errorf("rule_identity = %q, want the documented float64 rounding 15394007230974001152", got)
	}
}

// TestForwardToEmittedVerbatimNeverSynthesizedIntoAnAddress pins the SECOND
// trap: ForwardTo carries no SMTP address, and this collector must not
// fabricate one. The raw value is preserved exactly, and the extracted
// display-name sibling attribute contains only the quoted name portion.
func TestForwardToEmittedVerbatimNeverSynthesizedIntoAnAddress(t *testing.T) {
	exo := &fakeEXO{
		mailboxRows: []map[string]any{mailboxRow("a@x.com")},
		rulesByMailbox: map[string][]map[string]any{
			"a@x.com": recordsFrom(t, forwardRuleFixture),
		},
	}
	rec, err := collect(t, exo, 0)
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	twin := onlyLog(t, rec)

	// LogRecord.Attrs is map[string]string: telemetry.toLogKV joins a []string
	// attribute value with "," (see internal/telemetry/emitter.go). With one
	// element the joined form equals the element itself.
	wantRaw := `"Rob Knight" [EX:/o=ExchangeLabs/ou=Exchange Administrative Group (FYDIBOHF23SPDLT)/cn=Recipients/cn=8450ce8cf45b4ee88feb21c3cacff073-bbcfc3c5-0b]`
	if got := twin.Attrs[semconv.AttrForwardTo]; got != wantRaw {
		t.Errorf("forward_to = %q, want the verbatim wire value %q", got, wantRaw)
	}

	if got := twin.Attrs[semconv.AttrForwardToDisplayNames]; got != "Rob Knight" {
		t.Errorf("forward_to_display_names = %q, want %q", got, "Rob Knight")
	}

	// No attribute anywhere on the twin may look like a synthesized address.
	for k, v := range twin.Attrs {
		if strings.Contains(strings.ToLower(v), "@") && k != semconv.AttrPrimarySmtpAddress {
			t.Errorf("attribute %q = %q looks like a synthesized address", k, v)
		}
	}
}

// TestSubjectContainsWordsDecodedAsSlice pins the THIRD trap: array-shaped
// fields decode as []string, not a single joined string.
func TestSubjectContainsWordsDecodedAsSlice(t *testing.T) {
	exo := &fakeEXO{
		mailboxRows: []map[string]any{mailboxRow("a@x.com")},
		rulesByMailbox: map[string][]map[string]any{
			"a@x.com": recordsFrom(t, forwardRuleFixture),
		},
	}
	rec, err := collect(t, exo, 0)
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	twin := onlyLog(t, rec)
	if got := twin.Attrs[semconv.AttrSubjectContainsWords]; got != "g2o-test-forward" {
		t.Errorf("subject_contains_words = %q, want %q", got, "g2o-test-forward")
	}
}

// TestCollectBucketsBoundedGaugeByThreeBooleansOnly pins the cardinality
// contract: the rules gauge's only labels are enabled/has_forwarding/deletes,
// never mailbox or rule identity, and a forwarding rule buckets
// has_forwarding=true.
func TestCollectBucketsBoundedGaugeByThreeBooleansOnly(t *testing.T) {
	exo := &fakeEXO{
		mailboxRows: []map[string]any{mailboxRow("a@x.com")},
		rulesByMailbox: map[string][]map[string]any{
			"a@x.com": recordsFrom(t, forwardRuleFixture, junkRuleFixture),
		},
	}
	rec, err := collect(t, exo, 0)
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	pts := rec.MetricPoints(metricRules)
	if len(pts) != 2 {
		t.Fatalf("want 2 buckets (forwarding rule + junk rule), got %d: %#v", len(pts), pts)
	}
	for _, p := range pts {
		wantKeys := map[string]bool{
			semconv.AttrEnabled:       true,
			semconv.AttrHasForwarding: true,
			semconv.AttrDeleteMessage: true,
		}
		if len(p.Attrs) != len(wantKeys) {
			t.Errorf("bucket attrs = %#v, want exactly enabled/has_forwarding/deletes", p.Attrs)
		}
		for k := range p.Attrs {
			if !wantKeys[k] {
				t.Errorf("unexpected bucket label %q — never mailbox or rule identity (#112)", k)
			}
		}
	}
	var sawForwarding bool
	for _, p := range pts {
		if p.Attrs[semconv.AttrHasForwarding] == "true" {
			sawForwarding = true
			if p.Value != 1 {
				t.Errorf("has_forwarding=true bucket value = %v, want 1", p.Value)
			}
		}
	}
	if !sawForwarding {
		t.Error("no bucket had has_forwarding=true")
	}
}

// TestCollectTwinSeverityWarnOnlyWhenForwarding pins the severity rule: Warn
// means "forwards or redirects", nothing stronger.
func TestCollectTwinSeverityWarnOnlyWhenForwarding(t *testing.T) {
	exo := &fakeEXO{
		mailboxRows: []map[string]any{mailboxRow("a@x.com")},
		rulesByMailbox: map[string][]map[string]any{
			"a@x.com": recordsFrom(t, forwardRuleFixture, junkRuleFixture),
		},
	}
	rec, err := collect(t, exo, 0)
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	logs := rec.LogRecords()
	if len(logs) != 2 {
		t.Fatalf("want 2 twins, got %d", len(logs))
	}
	for _, l := range logs {
		name := l.Attrs[semconv.AttrName]
		switch name {
		case "g2o-test-forward":
			if l.SeverityText != "WARN" {
				t.Errorf("forwarding rule severity = %q, want WARN", l.SeverityText)
			}
		case "Junk E-mail Rule":
			if l.SeverityText != "INFO" {
				t.Errorf("junk rule severity = %q, want INFO", l.SeverityText)
			}
		default:
			t.Errorf("unexpected rule name %q", name)
		}
	}
}

// TestCollectOutcomesReconcile pins the fetched/mapped/emitted bookkeeping:
// every fetched row is mapped and emitted (this collector never filters or
// drops a row it fetched).
func TestCollectOutcomesReconcile(t *testing.T) {
	outcomes := recordoutcome.NewRecorder()
	exo := &fakeEXO{
		mailboxRows: []map[string]any{mailboxRow("a@x.com")},
		rulesByMailbox: map[string][]map[string]any{
			"a@x.com": recordsFrom(t, forwardRuleFixture, junkRuleFixture),
		},
	}
	c := New(collectors.EXODeps{Client: exo})
	if err := c.Collect(context.Background(), telemetrytest.New().Emitter(), outcomes); err != nil {
		t.Fatalf("Collect: %v", err)
	}
	snap := outcomes.Snapshot()
	if err := snap.Validate(); err != nil {
		t.Errorf("outcome reconciliation failed: %v", err)
	}
	want := recordoutcome.Counts{Fetched: 2, Mapped: 2, Emitted: 2}
	if snap.Counts != want {
		t.Errorf("counts = %#v, want %#v", snap.Counts, want)
	}
}

func gaugeValue(t *testing.T, rec *telemetrytest.Recorder, metric string) float64 {
	t.Helper()
	pts := rec.MetricPoints(metric)
	if len(pts) != 1 {
		t.Fatalf("want exactly 1 point for %s, got %d", metric, len(pts))
	}
	return pts[0].Value
}

func onlyLog(t *testing.T, rec *telemetrytest.Recorder) telemetrytest.LogRecord {
	t.Helper()
	logs := rec.LogRecords()
	if len(logs) != 1 {
		t.Fatalf("want exactly 1 log record, got %d", len(logs))
	}
	return logs[0]
}
