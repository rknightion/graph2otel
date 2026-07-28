package exchangeconnectionfilter

import (
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

// liveDefaultPolicy is the (sanitized) Get-HostedConnectionFilterPolicy
// record captured from the m7kni tenant as graph2otel-poller on 2026-07-28
// (#358), narrowed to the keys the mapper reads. Real tenant GUIDs and the
// tenant domain are replaced with example values; every field VALUE is
// otherwise verbatim — including the two EMPTY IP lists, which is this
// tenant's actual, measured, healthy posture.
const liveDefaultPolicy = `{
  "AdminDisplayName": "",
  "IsDefault": true,
  "IPAllowList": [],
  "IPBlockList": [],
  "EnableSafeList": false,
  "DirectoryBasedEdgeBlockMode": "Default",
  "Identity": "Default",
  "Id": "Default",
  "IsValid": true,
  "Name": "Default",
  "DistinguishedName": "CN=Default,CN=Hosted Connection Filter,CN=Transport Settings,CN=Configuration,CN=example.onmicrosoft.com,CN=ConfigurationUnits,DC=example,DC=prod,DC=outlook,DC=com",
  "WhenChangedUTC": "2026-07-23T22:52:13.0000000Z",
  "ExchangeObjectId": "e2c54833-64c3-4943-a5e0-2fbd940673fc",
  "OrganizationId": "example.prod.outlook.com/Microsoft Exchange Hosted Organizations/example.onmicrosoft.com",
  "Guid": "e2c54833-64c3-4943-a5e0-2fbd940673fc"
}`

// customPolicyWithIPs is a SYNTHESIZED custom connection filter policy (no
// such row exists on the m7kni tenant — Microsoft's own docs say tenants
// typically have only the Default policy) exercising the populated
// allow/block list branch the acceptance criteria calls out, including IPv4,
// IPv6, and CIDR-range forms that must be preserved verbatim.
const customPolicyWithIPs = `{
  "AdminDisplayName": "Partner Relay",
  "IsDefault": false,
  "IPAllowList": ["203.0.113.5", "2001:db8::1", "198.51.100.0/24"],
  "IPBlockList": ["192.0.2.10"],
  "EnableSafeList": true,
  "DirectoryBasedEdgeBlockMode": "Default",
  "Identity": "Partner Relay",
  "Id": "Partner Relay",
  "IsValid": true,
  "Name": "Partner Relay",
  "DistinguishedName": "CN=Partner Relay,CN=Hosted Connection Filter,CN=Transport Settings,CN=Configuration,CN=example.onmicrosoft.com,CN=ConfigurationUnits,DC=example,DC=prod,DC=outlook,DC=com",
  "WhenChangedUTC": "2026-07-20T09:00:00.0000000Z",
  "ExchangeObjectId": "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
  "OrganizationId": "example.prod.outlook.com/Microsoft Exchange Hosted Organizations/example.onmicrosoft.com",
  "Guid": "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
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

// bigIPList builds a policy fixture whose IPAllowList has n entries, to
// exercise the array-cap/truncation path.
func bigIPListPolicy(t *testing.T, n int) map[string]any {
	t.Helper()
	ips := make([]string, n)
	for i := range ips {
		ips[i] = fmt.Sprintf("203.0.%d.%d/32", i/256, i%256)
	}
	doc := fmt.Sprintf(`{
  "AdminDisplayName": "Big Allow List",
  "IsDefault": false,
  "IPAllowList": ["%s"],
  "IPBlockList": [],
  "EnableSafeList": false,
  "DirectoryBasedEdgeBlockMode": "Default",
  "Identity": "Big Allow List",
  "Id": "Big Allow List",
  "IsValid": true,
  "Name": "Big Allow List",
  "Guid": "bbbbbbbb-cccc-dddd-eeee-ffffffffffff"
}`, strings.Join(ips, `","`))
	var m map[string]any
	if err := json.Unmarshal([]byte(doc), &m); err != nil {
		t.Fatalf("unmarshal fixture: %v", err)
	}
	return m
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

// TestCollect_NoResultSizeParam: Get-HostedConnectionFilterPolicy has no
// ResultSize parameter (live docs, learn.microsoft.com, checked 2026-07-28).
func TestCollect_NoResultSizeParam(t *testing.T) {
	exo := &fakeEXO{recs: recordsFrom(t, liveDefaultPolicy)}
	collectWith(t, exo)
	if exo.params != nil {
		t.Errorf("params = %#v, want nil (this cmdlet accepts no ResultSize)", exo.params)
	}
}

func TestCollect_TwinPerPolicy(t *testing.T) {
	rec := collect(t, recordsFrom(t, liveDefaultPolicy, customPolicyWithIPs))
	n := 0
	for _, l := range rec.LogRecords() {
		if l.EventName == eventName {
			n++
		}
	}
	if n != 2 {
		t.Errorf("twins = %d, want 2 (all returned policies receive twins)", n)
	}
}

func TestCollect_AccountsEveryPolicyOnce(t *testing.T) {
	outcomes := recordoutcome.NewRecorder()
	recs := recordsFrom(t, liveDefaultPolicy, customPolicyWithIPs)
	c := New(collectors.EXODeps{Client: &fakeEXO{recs: recs}})
	if err := c.Collect(context.Background(), telemetrytest.New().Emitter(), outcomes); err != nil {
		t.Fatalf("Collect: %v", err)
	}
	got := outcomes.Snapshot().Summarize(nil, false)
	want := recordoutcome.Counts{Fetched: 2, Mapped: 2, Emitted: 2}
	if got.Result != recordoutcome.ResultSuccess || got.Counts != want {
		t.Errorf("outcome = %#v, want success/%#v", got, want)
	}
}

func TestCollect_PolicyCountGauge(t *testing.T) {
	rec := collect(t, recordsFrom(t, liveDefaultPolicy, customPolicyWithIPs))
	type key struct{ isDefault, enableSafeList string }
	got := map[key]float64{}
	for _, p := range rec.MetricPoints(metricPolicies) {
		got[key{p.Attrs[semconv.AttrIsDefault], p.Attrs[semconv.AttrEnableSafeList]}] += p.Value
	}
	if got[key{"true", "false"}] != 1 {
		t.Errorf("default+safelist_off = %v, want 1", got[key{"true", "false"}])
	}
	if got[key{"false", "true"}] != 1 {
		t.Errorf("custom+safelist_on = %v, want 1", got[key{"false", "true"}])
	}
}

// TestCollect_PolicyIdentityNeverOnMetric: policy name/identity and IPs are
// per-entity and must never become a gauge label (#112).
func TestCollect_PolicyIdentityNeverOnMetric(t *testing.T) {
	rec := collect(t, recordsFrom(t, liveDefaultPolicy, customPolicyWithIPs))
	for _, name := range []string{metricPolicies, metricIPAllowListLength, metricIPBlockListLength} {
		for _, p := range rec.MetricPoints(name) {
			if _, ok := p.Attrs[semconv.AttrName]; ok {
				t.Errorf("%s point carries a name label: %#v", name, p.Attrs)
			}
			if _, ok := p.Attrs[semconv.AttrIpAllowList]; ok {
				t.Errorf("%s point carries an ip_allow_list label: %#v", name, p.Attrs)
			}
		}
	}
}

// TestCollect_DefaultPolicyEmptyListsReadAsMeasuredZero: an empty
// IPAllowList/IPBlockList on the wire must produce a gauge point valued 0,
// not an absent series — a vanished series and a measured zero are
// different facts, and zero is the healthy reading for this security
// control.
func TestCollect_DefaultPolicyEmptyListsReadAsMeasuredZero(t *testing.T) {
	rec := collect(t, recordsFrom(t, liveDefaultPolicy))

	allowPts := rec.MetricPoints(metricIPAllowListLength)
	if len(allowPts) != 1 {
		t.Fatalf("ip_allow_list_length points = %d, want 1 (measured, not absent)", len(allowPts))
	}
	if allowPts[0].Value != 0 {
		t.Errorf("ip_allow_list_length = %v, want 0", allowPts[0].Value)
	}

	blockPts := rec.MetricPoints(metricIPBlockListLength)
	if len(blockPts) != 1 {
		t.Fatalf("ip_block_list_length points = %d, want 1 (measured, not absent)", len(blockPts))
	}
	if blockPts[0].Value != 0 {
		t.Errorf("ip_block_list_length = %v, want 0", blockPts[0].Value)
	}
}

// TestCollect_DefaultPolicyLengthGaugesSourceDefaultOnly: the length gauges
// come from the tenant's DEFAULT policy only, mirroring the outbound-spam
// collector's recipient_limit design — a custom policy's populated lists
// must not leak into these gauges.
func TestCollect_DefaultPolicyLengthGaugesSourceDefaultOnly(t *testing.T) {
	rec := collect(t, recordsFrom(t, liveDefaultPolicy, customPolicyWithIPs))
	if v := rec.MetricPoints(metricIPAllowListLength)[0].Value; v != 0 {
		t.Errorf("ip_allow_list_length = %v, want 0 (from the Default policy, not the custom one)", v)
	}
	if v := rec.MetricPoints(metricIPBlockListLength)[0].Value; v != 0 {
		t.Errorf("ip_block_list_length = %v, want 0 (from the Default policy, not the custom one)", v)
	}
}

// TestCollect_NoDefaultPolicy_NoLengthGauges: without a policy whose
// IsDefault is true, no length gauge points are emitted at all.
func TestCollect_NoDefaultPolicy_NoLengthGauges(t *testing.T) {
	rec := collect(t, recordsFrom(t, customPolicyWithIPs))
	if pts := rec.MetricPoints(metricIPAllowListLength); len(pts) != 0 {
		t.Errorf("ip_allow_list_length points = %d, want 0 (no default policy in this poll)", len(pts))
	}
	if pts := rec.MetricPoints(metricIPBlockListLength); len(pts) != 0 {
		t.Errorf("ip_block_list_length points = %d, want 0 (no default policy in this poll)", len(pts))
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
	if a[semconv.AttrEnableSafeList] != "false" {
		t.Errorf("enable_safe_list = %q", a[semconv.AttrEnableSafeList])
	}
	if a[semconv.AttrDirectoryBasedEdgeBlockMode] != "Default" {
		t.Errorf("directory_based_edge_block_mode = %q", a[semconv.AttrDirectoryBasedEdgeBlockMode])
	}
	if a[semconv.AttrGuid] != "e2c54833-64c3-4943-a5e0-2fbd940673fc" {
		t.Errorf("guid = %q", a[semconv.AttrGuid])
	}
	if a[semconv.AttrWhenChangedUtc] == "" {
		t.Error("when_changed_utc should be present")
	}
	// A measured, empty list must be a stamped COUNT of "0", never an absent
	// count attribute — the same measured-zero-vs-absent distinction as the
	// gauges.
	if v, ok := a[semconv.AttrIpAllowListCount]; !ok || v != "0" {
		t.Errorf("ip_allow_list_count = %q, ok=%v, want \"0\", true", v, ok)
	}
	if v, ok := a[semconv.AttrIpBlockListCount]; !ok || v != "0" {
		t.Errorf("ip_block_list_count = %q, ok=%v, want \"0\", true", v, ok)
	}
	// The list attribute itself is OMITTED when empty (same convention as
	// telemetry.SetStrs), distinct from the count attribute above which is
	// always stamped.
	if v, ok := a[semconv.AttrIpAllowList]; ok {
		t.Errorf("ip_allow_list present as %v, want omitted (empty on the wire)", v)
	}
}

func TestCollect_CustomPolicyIPListsPreservedVerbatim(t *testing.T) {
	rec := collect(t, recordsFrom(t, customPolicyWithIPs))
	var l telemetrytest.LogRecord
	for _, r := range rec.LogRecords() {
		if r.EventName == eventName {
			l = r
		}
	}
	allow, ok := l.Attrs[semconv.AttrIpAllowList]
	if !ok {
		t.Fatal("ip_allow_list should be present")
	}
	for _, want := range []string{"203.0.113.5", "2001:db8::1", "198.51.100.0/24"} {
		if !strings.Contains(allow, want) {
			t.Errorf("ip_allow_list %q missing entry %q", allow, want)
		}
	}
	if l.Attrs[semconv.AttrIpAllowListCount] != "3" {
		t.Errorf("ip_allow_list_count = %q, want 3", l.Attrs[semconv.AttrIpAllowListCount])
	}
	if l.Attrs[semconv.AttrIpBlockListCount] != "1" {
		t.Errorf("ip_block_list_count = %q, want 1", l.Attrs[semconv.AttrIpBlockListCount])
	}
	if l.Attrs[semconv.AttrEnableSafeList] != "true" {
		t.Errorf("enable_safe_list = %q, want true", l.Attrs[semconv.AttrEnableSafeList])
	}
}

// TestCollect_IPListTruncation: an allow list past maxIPListAttr entries is
// capped on the twin, the true count is still stamped in full, and
// arrays_truncated records the loss.
func TestCollect_IPListTruncation(t *testing.T) {
	big := bigIPListPolicy(t, maxIPListAttr+10)
	rec := collect(t, []map[string]any{big})

	var l telemetrytest.LogRecord
	for _, r := range rec.LogRecords() {
		if r.EventName == eventName {
			l = r
		}
	}
	if l.Attrs[semconv.AttrIpAllowListCount] != fmt.Sprintf("%d", maxIPListAttr+10) {
		t.Errorf("ip_allow_list_count = %q, want %d (true count, not the capped display length)", l.Attrs[semconv.AttrIpAllowListCount], maxIPListAttr+10)
	}
	if l.Attrs[semconv.AttrArraysTruncated] != "true" {
		t.Errorf("arrays_truncated = %q, want true", l.Attrs[semconv.AttrArraysTruncated])
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
	if pts := rec.MetricPoints(metricIPAllowListLength); len(pts) != 0 {
		t.Errorf("empty result should emit no ip_allow_list_length points, got %d", len(pts))
	}
}

func TestCollect_ErrorPropagates(t *testing.T) {
	rec := telemetrytest.New()
	c := New(collectors.EXODeps{Client: &fakeEXO{err: errors.New("403")}})
	if err := c.Collect(context.Background(), rec.Emitter(), recordoutcome.NewRecorder()); err == nil {
		t.Fatal("want error when the cmdlet fails")
	}
}
