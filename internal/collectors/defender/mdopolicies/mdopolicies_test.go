package mdopolicies

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"os"
	"testing"

	"github.com/rknightion/graph2otel/internal/collectors"
	"github.com/rknightion/graph2otel/internal/semconv"
	"github.com/rknightion/graph2otel/internal/telemetry"
	"github.com/rknightion/graph2otel/internal/telemetrytest"
)

// cmdletSample maps each Get-*Policy cmdlet to the verbatim live capture that
// drives it. The files are real m7kni tenant responses read as graph2otel-poller
// over the Exchange Online admin API on 2026-07-23 (#250); they are the shape
// authority for every field this collector maps.
var cmdletSample = map[string]string{
	"Get-HostedContentFilterPolicy": "testdata/hostedcontent.json",
	"Get-MalwareFilterPolicy":       "testdata/malwarefilter.json",
	"Get-AntiPhishPolicy":           "testdata/antiphish.json",
	"Get-SafeLinksPolicy":           "testdata/safelinks.json",
	"Get-SafeAttachmentPolicy":      "testdata/safeattachment.json",
	"Get-AtpPolicyForO365":          "testdata/atppolicy.json",
	"Get-TeamsProtectionPolicy":     "testdata/teamsprotection.json",
}

// loadValue reads a live sample file and returns its "value" array as the decoded
// records the EXOClient.Invoke seam yields (the envelope's @odata.context /
// warnings are dropped by the transport before a collector ever sees them).
func loadValue(t *testing.T, path string) []map[string]any {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	var env struct {
		Value []map[string]any `json:"value"`
	}
	if err := json.Unmarshal(b, &env); err != nil {
		t.Fatalf("decode %s: %v", path, err)
	}
	return env.Value
}

// fakeEXO serves canned records per cmdlet and records every Invoke, so the tests
// assert the request shape as well as the mapping. No HTTP, no Exchange grants.
type fakeEXO struct {
	byCmdlet map[string][]map[string]any
	errs     map[string]error
	calls    []string
}

func (f *fakeEXO) Invoke(_ context.Context, cmdlet string, _ map[string]any) ([]map[string]any, error) {
	f.calls = append(f.calls, cmdlet)
	if err := f.errs[cmdlet]; err != nil {
		return nil, err
	}
	return f.byCmdlet[cmdlet], nil
}

var _ collectors.EXOClient = (*fakeEXO)(nil)

// liveFake loads all seven live samples into a fake so a single Collect drives the
// RICHEST fixtures end-to-end (the #164 fat-golden requirement).
func liveFake(t *testing.T) *fakeEXO {
	t.Helper()
	by := map[string][]map[string]any{}
	for cmdlet, path := range cmdletSample {
		by[cmdlet] = loadValue(t, path)
	}
	return &fakeEXO{byCmdlet: by}
}

func newCollector(t *testing.T, f *fakeEXO) *Collector {
	t.Helper()
	return New(collectors.EXODeps{
		Client:   f,
		TenantID: "4b8c18bd-2f9f-4227-af55-9f1061cf9c32",
		Logger:   slog.New(slog.DiscardHandler),
	})
}

func collectLive(t *testing.T) *telemetrytest.Recorder {
	t.Helper()
	f := liveFake(t)
	rec := telemetrytest.New()
	if err := newCollector(t, f).Collect(context.Background(), rec.Emitter()); err != nil {
		t.Fatalf("Collect over the live samples: %v", err)
	}
	return rec
}

// TestCollectInvokesEveryCmdletWithNoParams pins the request shape: one Invoke per
// policy cmdlet, no parameters (these Get-*Policy cmdlets take none).
func TestCollectInvokesEveryCmdletWithNoParams(t *testing.T) {
	f := liveFake(t)
	rec := telemetrytest.New()
	if err := newCollector(t, f).Collect(context.Background(), rec.Emitter()); err != nil {
		t.Fatalf("Collect: %v", err)
	}
	if len(f.calls) != len(cmdletSample) {
		t.Fatalf("invoked %d cmdlets, want %d", len(f.calls), len(cmdletSample))
	}
	for _, cmdlet := range f.calls {
		if _, ok := cmdletSample[cmdlet]; !ok {
			t.Errorf("unexpected cmdlet invoked: %q", cmdlet)
		}
	}
}

// TestPoliciesGaugeCountsByType pins metricPolicies against the live sample
// cardinalities: two of each preset-bearing type, one ATP and one Teams policy.
func TestPoliciesGaugeCountsByType(t *testing.T) {
	rec := collectLive(t)
	got := map[string]float64{}
	for _, p := range rec.MetricPoints(metricPolicies) {
		got[p.Attrs[semconv.AttrPolicyType]] = p.Value
	}
	want := map[string]float64{
		"hosted_content":   2,
		"malware":          2,
		"anti_phish":       2,
		"safe_links":       2,
		"safe_attachments": 2,
		"atp_o365":         1,
		"teams_protection": 1,
	}
	if len(got) != len(want) {
		t.Fatalf("got %d policy_type series, want %d: %v", len(got), len(want), got)
	}
	for k, v := range want {
		if got[k] != v {
			t.Errorf("policies{%s} = %v, want %v", k, got[k], v)
		}
	}
}

// TestProtectionEnabledGauge pins metricProtection: a count of ON policies keyed
// by (policy_type, protection). Every live toggle is on, so the count equals the
// policy count of the type.
func TestProtectionEnabledGauge(t *testing.T) {
	rec := collectLive(t)
	got := map[protKey]float64{}
	for _, p := range rec.MetricPoints(metricProtection) {
		got[protKey{p.Attrs[semconv.AttrPolicyType], p.Attrs[semconv.AttrProtection]}] = p.Value
	}
	want := map[protKey]float64{
		{"hosted_content", "zap"}:                2,
		{"hosted_content", "spam_zap"}:           2,
		{"hosted_content", "phish_zap"}:          2,
		{"malware", "file_filter"}:               2,
		{"malware", "zap"}:                       2,
		{"anti_phish", "spoof_intelligence"}:     2,
		{"anti_phish", "mailbox_intelligence"}:   2,
		{"safe_links", "safe_links_email"}:       2,
		{"safe_links", "safe_links_teams"}:       2,
		{"safe_links", "scan_urls"}:              2,
		{"safe_attachments", "safe_attachments"}: 2,
		{"atp_o365", "safe_docs"}:                1,
		{"teams_protection", "zap"}:              1,
	}
	if len(got) != len(want) {
		t.Fatalf("got %d protection series, want %d: %v", len(got), len(want), got)
	}
	for k, v := range want {
		if got[k] != v {
			t.Errorf("protection_enabled{%s,%s} = %v, want %v", k.policyType, k.protection, got[k], v)
		}
	}
}

// TestProtectionCountsDisabledToggle proves a present-but-off toggle counts 0
// (the series stays, since the type still SUPPORTS the protection), while an
// absent toggle emits no series at all for that (type, protection).
func TestProtectionCountsDisabledToggle(t *testing.T) {
	f := liveFake(t)
	// Flip ZapEnabled off on both hosted-content policies.
	for _, r := range f.byCmdlet["Get-HostedContentFilterPolicy"] {
		r["ZapEnabled"] = false
	}
	rec := telemetrytest.New()
	if err := newCollector(t, f).Collect(context.Background(), rec.Emitter()); err != nil {
		t.Fatalf("Collect: %v", err)
	}
	got := map[protKey]float64{}
	present := map[protKey]bool{}
	for _, p := range rec.MetricPoints(metricProtection) {
		k := protKey{p.Attrs[semconv.AttrPolicyType], p.Attrs[semconv.AttrProtection]}
		got[k] = p.Value
		present[k] = true
	}
	if v, ok := got[protKey{"hosted_content", "zap"}]; !ok || v != 0 {
		t.Errorf("hosted_content zap = %v present=%v, want a 0-valued series (capable but off)", v, ok)
	}
	// anti_phish has no ZAP toggle at all, so there must be no (anti_phish, zap).
	if present[protKey{"anti_phish", "zap"}] {
		t.Error("anti_phish has no ZAP toggle on the wire; it must emit no (anti_phish, zap) series")
	}
}

// TestPerPolicyTwins pins the twin: one defender.mdo_policy per policy across all
// seven fetches, carrying the per-policy action/toggle detail.
func TestPerPolicyTwins(t *testing.T) {
	rec := collectLive(t)
	logs := rec.LogRecords()
	if len(logs) != 12 {
		t.Fatalf("emitted %d twins, want 12 (2+2+2+2+2+1+1 policies)", len(logs))
	}

	var std *telemetrytest.LogRecord
	for i := range logs {
		if logs[i].EventName == eventName &&
			logs[i].Attrs[semconv.AttrPolicyType] == "hosted_content" &&
			logs[i].Attrs[semconv.AttrPolicyName] == "Standard Preset Security Policy1784144691483" {
			std = &logs[i]
		}
	}
	if std == nil {
		t.Fatal("no twin for the Standard Preset hosted-content policy")
	}
	want := map[string]string{
		semconv.AttrPolicyType:                "hosted_content",
		semconv.AttrRecommendedPolicyType:     "Standard",
		semconv.AttrSpamAction:                "MoveToJmf",
		semconv.AttrHighConfidenceSpamAction:  "Quarantine",
		semconv.AttrPhishSpamAction:           "Quarantine",
		semconv.AttrHighConfidencePhishAction: "Quarantine",
		semconv.AttrBulkSpamAction:            "MoveToJmf",
		semconv.AttrBulkThreshold:             "6",
		semconv.AttrQuarantineRetentionPeriod: "30",
		semconv.AttrZapEnabled:                "true",
		semconv.AttrSpamZapEnabled:            "true",
		semconv.AttrPhishZapEnabled:           "true",
		semconv.AttrIsDefault:                 "false",
	}
	for k, v := range want {
		if got := std.Attrs[k]; got != v {
			t.Errorf("twin attr %q = %q, want %q", k, got, v)
		}
	}
	if std.SeverityText != "INFO" {
		t.Errorf("severity = %q, want INFO (ZapEnabled is true)", std.SeverityText)
	}
}

// TestAntiPhishTwinCarriesDmarcAndThreshold covers the fields unique to the
// AntiPhish shape, which the hosted-content twin cannot exercise.
func TestAntiPhishTwinCarriesDmarcAndThreshold(t *testing.T) {
	rec := collectLive(t)
	var ap *telemetrytest.LogRecord
	for _, r := range rec.LogRecords() {
		if r.Attrs[semconv.AttrPolicyType] == "anti_phish" &&
			r.Attrs[semconv.AttrPolicyName] == "Standard Preset Security Policy1784144689723" {
			rr := r
			ap = &rr
		}
	}
	if ap == nil {
		t.Fatal("no twin for the Standard Preset anti-phish policy")
	}
	want := map[string]string{
		semconv.AttrAuthenticationFailAction:            "MoveToJmf",
		semconv.AttrDmarcRejectAction:                   "Reject",
		semconv.AttrDmarcQuarantineAction:               "Quarantine",
		semconv.AttrHonorDmarcPolicy:                    "true",
		semconv.AttrPhishThresholdLevel:                 "3",
		semconv.AttrMailboxIntelligenceProtectionAction: "MoveToJmf",
		semconv.AttrTargetedUserProtectionAction:        "Quarantine",
		semconv.AttrEnableTargetedUserProtection:        "true",
		semconv.AttrSpoofIntelligenceEnabled:            "true",
		semconv.AttrEnabled:                             "true",
	}
	for k, v := range want {
		if got := ap.Attrs[k]; got != v {
			t.Errorf("anti_phish twin attr %q = %q, want %q", k, got, v)
		}
	}
}

// TestTwinWarnsWhenZapOff pins the Warn rule: a policy that supports ZAP with it
// switched off escalates to WARN; the live all-ZAP-on tenant stays INFO.
func TestTwinWarnsWhenZapOff(t *testing.T) {
	f := liveFake(t)
	// Turn ZAP off on the malware Default policy only.
	for _, r := range f.byCmdlet["Get-MalwareFilterPolicy"] {
		if r["Name"] == "Default" {
			r["ZapEnabled"] = false
		}
	}
	rec := telemetrytest.New()
	if err := newCollector(t, f).Collect(context.Background(), rec.Emitter()); err != nil {
		t.Fatalf("Collect: %v", err)
	}
	sev := map[string]string{}
	for _, r := range rec.LogRecords() {
		if r.Attrs[semconv.AttrPolicyType] == "malware" {
			sev[r.Attrs[semconv.AttrPolicyName]] = r.SeverityText
		}
	}
	if sev["Default"] != "WARN" {
		t.Errorf("malware Default (ZAP off) severity = %q, want WARN", sev["Default"])
	}
	// The other malware policy still has ZAP on -> INFO.
	if sev["Standard Preset Security Policy1784144693315"] != "INFO" {
		t.Errorf("malware preset (ZAP on) severity = %q, want INFO", sev["Standard Preset Security Policy1784144693315"])
	}
}

// TestPolicyWithoutZapFieldStaysInfo proves the Warn rule keys on the field being
// PRESENT-and-false, not merely absent: an anti-phish policy carries no ZapEnabled
// field, so it must not warn.
func TestPolicyWithoutZapFieldStaysInfo(t *testing.T) {
	rec := collectLive(t)
	for _, r := range rec.LogRecords() {
		if r.Attrs[semconv.AttrPolicyType] == "anti_phish" && r.SeverityText != "INFO" {
			t.Errorf("anti_phish twin severity = %q, want INFO (no ZapEnabled field to warn on)", r.SeverityText)
		}
	}
}

// TestMetricsCarryNoPerPolicyLabel guards #112: the gauges must carry ONLY the
// bounded (policy_type, protection) labels, never a policy name.
func TestMetricsCarryNoPerPolicyLabel(t *testing.T) {
	rec := collectLive(t)
	for _, name := range []string{metricPolicies, metricProtection} {
		for _, p := range rec.MetricPoints(name) {
			for _, banned := range []string{semconv.AttrPolicyName, semconv.AttrName} {
				if _, present := p.Attrs[banned]; present {
					t.Errorf("metric %q carries per-policy label %q — a series per policy", name, banned)
				}
			}
		}
	}
}

// TestRecordsAreStampedWithTheExchangeOnlineTransport guards the #141 stamp: the
// EXO path has no ingest engine and the Scheduler baseline is graph, so Collect
// must stamp exchange_online itself, and it must never be a metric label.
func TestRecordsAreStampedWithTheExchangeOnlineTransport(t *testing.T) {
	f := liveFake(t)
	rec := telemetrytest.New()
	c := newCollector(t, f)
	if err := c.Collect(context.Background(), rec.Emitter()); err != nil {
		t.Fatalf("Collect: %v", err)
	}
	for _, r := range rec.LogRecords() {
		if got := r.Attrs[semconv.AttrIngestTransport]; got != string(telemetry.TransportExchangeOnline) {
			t.Fatalf("%s = %q, want %q", semconv.AttrIngestTransport, got, telemetry.TransportExchangeOnline)
		}
	}
	if got := c.IngestTransport(); got != telemetry.TransportExchangeOnline {
		t.Errorf("IngestTransport() = %q, want %q", got, telemetry.TransportExchangeOnline)
	}
	for _, p := range rec.MetricPoints(metricPolicies) {
		if _, present := p.Attrs[semconv.AttrIngestTransport]; present {
			t.Error("ingest_transport must not be a metric label — it would change series identity")
		}
	}
}

// TestCollectAggregatesCmdletFailures pins the securescore-shaped resilience: a
// failing cmdlet is surfaced as a non-fatal aggregated error while the other six
// still emit.
func TestCollectAggregatesCmdletFailures(t *testing.T) {
	f := liveFake(t)
	sentinel := errors.New("403: missing directory role")
	f.errs = map[string]error{"Get-AntiPhishPolicy": sentinel}
	rec := telemetrytest.New()
	err := newCollector(t, f).Collect(context.Background(), rec.Emitter())
	if !errors.Is(err, sentinel) {
		t.Fatalf("Collect error = %v, want it to wrap %v", err, sentinel)
	}
	// anti_phish dropped out; the other six types still counted.
	got := map[string]float64{}
	for _, p := range rec.MetricPoints(metricPolicies) {
		got[p.Attrs[semconv.AttrPolicyType]] = p.Value
	}
	if _, present := got["anti_phish"]; present {
		t.Error("anti_phish must be absent when its cmdlet failed")
	}
	if got["hosted_content"] != 2 {
		t.Errorf("hosted_content = %v despite an unrelated cmdlet failing, want 2", got["hosted_content"])
	}
}

// TestEmptyResultIsNotAnError covers the healthy steady state — a tenant with no
// policies of some type returns an empty array, not an error, and emits no series.
func TestEmptyResultIsNotAnError(t *testing.T) {
	f := &fakeEXO{byCmdlet: map[string][]map[string]any{}}
	rec := telemetrytest.New()
	if err := newCollector(t, f).Collect(context.Background(), rec.Emitter()); err != nil {
		t.Fatalf("Collect over empty results: %v", err)
	}
	if pts := rec.MetricPoints(metricPolicies); len(pts) != 0 {
		t.Errorf("got %d policy series over empty results, want 0", len(pts))
	}
	if logs := rec.LogRecords(); len(logs) != 0 {
		t.Errorf("got %d twins over empty results, want 0", len(logs))
	}
}

func TestNameAndPermissions(t *testing.T) {
	c := New(collectors.EXODeps{})
	if c.Name() != "defender.mdo_policies" {
		t.Errorf("Name = %q", c.Name())
	}
	if perms := c.RequiredPermissions(); perms != nil {
		t.Errorf("RequiredPermissions = %v, want nil (EXO access is outside the Graph-scope vocabulary)", perms)
	}
	if c.DefaultInterval() != interval {
		t.Errorf("DefaultInterval = %v, want %v", c.DefaultInterval(), interval)
	}
}
