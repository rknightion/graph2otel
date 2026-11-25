package pstngateways

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"reflect"
	"strconv"
	"strings"
	"testing"

	"github.com/rknightion/graph2otel/internal/collectors"
	"github.com/rknightion/graph2otel/internal/recordoutcome"
	"github.com/rknightion/graph2otel/internal/semconv"
	"github.com/rknightion/graph2otel/internal/teams/adminmap"
	"github.com/rknightion/graph2otel/internal/teamsadminclient"
	"github.com/rknightion/graph2otel/internal/telemetry"
	"github.com/rknightion/graph2otel/internal/telemetrytest"
	"github.com/rknightion/graph2otel/internal/wirecheck"
)

type fakeClient struct {
	recs []map[string]any
	err  error
	got  []string
}

func (f *fakeClient) Configurations(_ context.Context, name string) ([]map[string]any, error) {
	f.got = append(f.got, name)
	return f.recs, f.err
}

func (f *fakeClient) VoiceApps(context.Context, teamsadminclient.VoiceAppKind) (teamsadminclient.VoiceAppsResult, error) {
	return teamsadminclient.VoiceAppsResult{}, errors.New("not used by pstn_gateways")
}

// fixture decodes the committed lab capture afresh on every call.
func fixture(t *testing.T) []map[string]any {
	t.Helper()
	raw, err := os.ReadFile("testdata/OnlinePSTNGateway.json")
	if err != nil {
		t.Fatal(err)
	}
	var recs []map[string]any
	if err := json.Unmarshal(raw, &recs); err != nil {
		t.Fatal(err)
	}
	return recs
}

func run(t *testing.T, recs []map[string]any) (*telemetrytest.Recorder, *recordoutcome.Recorder) {
	t.Helper()
	rec := telemetrytest.New()
	out := recordoutcome.NewRecorder()
	c := New(collectors.Deps{TeamsAdmin: &fakeClient{recs: recs}})
	if err := c.Collect(context.Background(), rec.Emitter(), out); err != nil {
		t.Fatalf("Collect: %v", err)
	}
	return rec, out
}

func twins(rec *telemetrytest.Recorder) []map[string]string {
	var out []map[string]string
	for _, l := range rec.LogRecords() {
		if l.EventName == eventName {
			out = append(out, l.Attrs)
		}
	}
	return out
}

func gauge(rec *telemetrytest.Recorder) map[string]float64 {
	out := map[string]float64{}
	for _, p := range rec.MetricPoints(metricCount) {
		out[p.Attrs[semconv.AttrEnabled]] = p.Value
	}
	return out
}

// TestMapGateway_FixtureAttributes pins every exported attribute of the lab
// gateway: nulls omitted, the four empty rule lists exported as _count=0 with no
// list, integers as integers and booleans as strings.
func TestMapGateway_FixtureAttributes(t *testing.T) {
	got := mapGateway(wirecheck.New("t", nil), nil, fixture(t)[0])
	want := telemetry.Attrs{
		semconv.AttrPstnGatewayIdentity:                                "sbc.example.com",
		semconv.AttrPstnGatewayFqdn:                                    "sbc.example.com",
		semconv.AttrPstnGatewaySipSignalingPort:                        5061,
		semconv.AttrPstnGatewayFailoverTimeSeconds:                     10,
		semconv.AttrPstnGatewayForwardCallHistory:                      "true",
		semconv.AttrPstnGatewayForwardPai:                              "true",
		semconv.AttrPstnGatewaySendSipOptions:                          "true",
		semconv.AttrPstnGatewayMaxConcurrentSessions:                   10,
		semconv.AttrPstnGatewayEnabled:                                 "true",
		semconv.AttrPstnGatewayMediaBypass:                             "false",
		semconv.AttrPstnGatewayGatewaySiteLbrEnabled:                   "false",
		semconv.AttrPstnGatewayGatewayLbrEnabledUserOverride:           "false",
		semconv.AttrPstnGatewayFailoverResponseCodes:                   "408,503,504",
		semconv.AttrPstnGatewayPidfLoSupported:                         "false",
		semconv.AttrPstnGatewayBypassMode:                              "None",
		semconv.AttrPstnGatewayIpAddressVersion:                        "IPv4",
		semconv.AttrPstnGatewayInviteWithReplaces:                      "OptimisticallySupported",
		semconv.AttrPstnGatewayAuthority:                               "Tenant",
		semconv.AttrPstnGatewayInboundTeamsNumberTranslationRulesCount: 0,
		semconv.AttrPstnGatewayInboundPstnNumberTranslationRulesCount:  0,
		semconv.AttrPstnGatewayOutbundTeamsNumberTranslationRulesCount: 0,
		semconv.AttrPstnGatewayOutboundPstnNumberTranslationRulesCount: 0,
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("attributes differ\n got: %#v\nwant: %#v", got, want)
	}
}

// TestMapGateway_MisspeltRuleKey: Microsoft's OutbundTeamsNumberTranslationRules
// is read under its own spelling and exported under it. The correctly spelt
// field is a different (unmeasured) wire name and must not be read.
func TestMapGateway_MisspeltRuleKey(t *testing.T) {
	r := fixture(t)[0]
	r["OutbundTeamsNumberTranslationRules"] = []any{"rule-a", "rule-b"}
	r["OutboundTeamsNumberTranslationRules"] = []any{"must-not-be-read"}
	got := mapGateway(wirecheck.New("t", nil), nil, r)

	if v := got["pstn_gateway_outbund_teams_number_translation_rules"]; !reflect.DeepEqual(v, []string{"rule-a", "rule-b"}) {
		t.Errorf("misspelled key = %#v, want [rule-a rule-b]", v)
	}
	if v := got["pstn_gateway_outbund_teams_number_translation_rules_count"]; v != 2 {
		t.Errorf("misspelled key count = %#v, want 2", v)
	}
	for k := range got {
		if strings.Contains(k, "outbound_teams") {
			t.Errorf("attribute %q derived from the correctly spelt field", k)
		}
	}
}

func TestMapGateway_RuleListCap(t *testing.T) {
	ids := make([]any, 101)
	for i := range ids {
		ids[i] = "rule-" + strconv.Itoa(i)
	}
	r := fixture(t)[0]
	r["InboundPstnNumberTranslationRules"] = ids
	got := mapGateway(wirecheck.New("t", nil), nil, r)

	list, _ := got["pstn_gateway_inbound_pstn_number_translation_rules"].([]string)
	if len(list) != 100 || list[99] != "rule-99" {
		t.Errorf("list len=%d, want the first 100 entries", len(list))
	}
	if got["pstn_gateway_inbound_pstn_number_translation_rules_count"] != 101 {
		t.Errorf("count = %#v, want the full length 101", got["pstn_gateway_inbound_pstn_number_translation_rules_count"])
	}
	if got["pstn_gateway_inbound_pstn_number_translation_rules_truncated"] != "true" {
		t.Errorf("truncated = %#v, want the string \"true\"", got["pstn_gateway_inbound_pstn_number_translation_rules_truncated"])
	}
}

// TestCollect_IPv6AndDisabled: a gateway the fixture does not show. IPv6 is
// exported verbatim; a disabled gateway counts under enabled=false.
func TestCollect_IPv6AndDisabled(t *testing.T) {
	r := fixture(t)[0]
	r["IPAddressVersion"] = "IPv6"
	r["Enabled"] = false
	r["MediaRelayRoutingLocationOverride"] = "EUR1"
	rec, _ := run(t, []map[string]any{r})

	tw := twins(rec)
	if len(tw) != 1 {
		t.Fatalf("twins = %d, want 1", len(tw))
	}
	if tw[0][semconv.AttrPstnGatewayIpAddressVersion] != "IPv6" {
		t.Errorf("ip_address_version = %q, want IPv6", tw[0][semconv.AttrPstnGatewayIpAddressVersion])
	}
	if tw[0][semconv.AttrPstnGatewayMediaRelayRoutingLocationOverride] != "EUR1" {
		t.Errorf("media relay override = %q", tw[0][semconv.AttrPstnGatewayMediaRelayRoutingLocationOverride])
	}
	if got := gauge(rec); !reflect.DeepEqual(got, map[string]float64{"false": 1}) {
		t.Errorf("gauge = %v, want only enabled=false:1", got)
	}
}

func TestCollect_FixtureEndToEnd(t *testing.T) {
	rec, out := run(t, fixture(t))
	tw := twins(rec)
	if len(tw) != 1 {
		t.Fatalf("twins = %d, want 1", len(tw))
	}
	if got := gauge(rec); !reflect.DeepEqual(got, map[string]float64{"true": 1}) {
		t.Errorf("gauge = %v, want enabled=true:1", got)
	}
	if tw[0][semconv.AttrConfigHashVersion] != "1" || len(tw[0][semconv.AttrConfigSHA256]) != 64 {
		t.Errorf("hash attrs = %q / %q", tw[0][semconv.AttrConfigHashVersion], tw[0][semconv.AttrConfigSHA256])
	}
	if tw[0][semconv.AttrIngestTransport] != "teams_admin" {
		t.Errorf("ingest_transport = %q, want teams_admin", tw[0][semconv.AttrIngestTransport])
	}
	logs := rec.LogRecords()
	if logs[0].Body != "PSTN gateway sbc.example.com" {
		t.Errorf("body = %q", logs[0].Body)
	}
	want := recordoutcome.Counts{Fetched: 1, Mapped: 1, Emitted: 1}
	if got := out.Snapshot().Summarize(nil, false); got.Result != recordoutcome.ResultSuccess || got.Counts != want {
		t.Errorf("outcome = %#v, want success/%#v", got, want)
	}
}

// TestCollect_GaugeTotalsEveryGateway: a gateway with no boolean Enabled is
// counted under unknown, so the total always equals the number of gateways; no
// gateway at all publishes an empty snapshot (which clears the series).
func TestCollect_GaugeTotalsEveryGateway(t *testing.T) {
	on, off, absent, nonBool := fixture(t)[0], fixture(t)[0], fixture(t)[0], fixture(t)[0]
	off["Enabled"] = false
	delete(absent, "Enabled")
	nonBool["Enabled"] = "yes"
	rec, _ := run(t, []map[string]any{on, on, off, absent, nonBool})
	want := map[string]float64{"true": 2, "false": 1, "unknown": 2}
	if got := gauge(rec); !reflect.DeepEqual(got, want) {
		t.Errorf("gauge = %v, want %v", got, want)
	}

	empty, _ := run(t, []map[string]any{})
	if got := gauge(empty); len(got) != 0 {
		t.Errorf("no gateways: gauge = %v, want no series", got)
	}
	if len(twins(empty)) != 0 {
		t.Error("no gateways: want no twins")
	}
}

func TestCollect_HashStableAndSensitive(t *testing.T) {
	hash := func(recs []map[string]any) string {
		rec, _ := run(t, recs)
		return twins(rec)[0][semconv.AttrConfigSHA256]
	}
	a, b := hash(fixture(t)), hash(fixture(t))
	if a != b {
		t.Errorf("two decodes of the fixture hash differently: %s vs %s", a, b)
	}
	for name, mutate := range map[string]func(map[string]any){
		"scalar":    func(r map[string]any) { r["MaxConcurrentSessions"] = 11.0 },
		"bool":      func(r map[string]any) { r["Enabled"] = false },
		"list":      func(r map[string]any) { r["OutbundTeamsNumberTranslationRules"] = []any{"x"} },
		"null→set":  func(r map[string]any) { r["ProxySbc"] = "proxy.example.com" },
		"authority": func(r map[string]any) { r["ConfigMetadata"] = map[string]any{"Authority": "Host"} },
	} {
		recs := fixture(t)
		mutate(recs[0])
		if got := hash(recs); got == a {
			t.Errorf("%s change left the hash unchanged", name)
		}
	}
	// A field the twin does not export must not move the hash.
	recs := fixture(t)
	recs[0]["SomeFutureField"] = "x"
	if got := hash(recs); got != a {
		t.Error("an unexported wire field changed the hash")
	}
}

func TestCollect_NilClientErrors(t *testing.T) {
	c := New(collectors.Deps{})
	if err := c.Collect(context.Background(), telemetrytest.New().Emitter(), recordoutcome.NewRecorder()); err == nil {
		t.Fatal("want an error from a nil client")
	}
}

func TestCollect_FetchErrors(t *testing.T) {
	for _, tc := range []struct {
		name  string
		err   error
		cause recordoutcome.Cause
	}{
		{"403 is permission denied", &teamsadminclient.APIError{StatusCode: 403, Path: "/Skype.Policy/configurations/OnlinePSTNGateway"}, recordoutcome.CausePermissionDenied},
		{"wrapped 403 is permission denied", fmt.Errorf("wrapped: %w", &teamsadminclient.APIError{StatusCode: 403}), recordoutcome.CausePermissionDenied},
		{"500 is a source error", &teamsadminclient.APIError{StatusCode: 500}, recordoutcome.CauseSourceError},
		{"401 is a source error", &teamsadminclient.APIError{StatusCode: 401}, recordoutcome.CauseSourceError},
		{"transport failure is a source error", errors.New("dial tcp"), recordoutcome.CauseSourceError},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rec := telemetrytest.New()
			out := recordoutcome.NewRecorder()
			c := New(collectors.Deps{TeamsAdmin: &fakeClient{err: tc.err}})
			err := c.Collect(context.Background(), rec.Emitter(), out)
			if err == nil {
				t.Fatal("want a non-nil error")
			}
			if !errors.Is(err, tc.err) {
				t.Errorf("error %v does not wrap %v", err, tc.err)
			}
			causes := out.Snapshot().Causes
			if len(causes) != 1 || causes[0] != tc.cause {
				t.Errorf("causes = %v, want [%s]", causes, tc.cause)
			}
			if len(twins(rec)) != 0 {
				t.Error("a failed fetch must emit no twin")
			}
		})
	}
}

func TestCollect_ReadsTheGatewayResource(t *testing.T) {
	f := &fakeClient{recs: fixture(t)}
	c := New(collectors.Deps{TeamsAdmin: f})
	if err := c.Collect(context.Background(), telemetrytest.New().Emitter(), recordoutcome.NewRecorder()); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(f.got, []string{"OnlinePSTNGateway"}) {
		t.Errorf("resources read = %v, want [OnlinePSTNGateway]", f.got)
	}
}

// TestKeysFollowTheNamingRule: every key that maps one wire field directly is
// prefix + snake_case(wire). The authority key comes from ConfigMetadata and is
// the one exception. A _count key is the list key plus _count.
func TestKeysFollowTheNamingRule(t *testing.T) {
	for _, f := range gatewayFields {
		if want := adminmap.SnakeKey("pstn_gateway_", f.wire); f.key != want {
			t.Errorf("wire %s exported as %q, naming rule gives %q", f.wire, f.key, want)
		}
	}
	// Every constant in the lane's file is covered: a field key, a derived _count
	// key or the authority exception.
	known := map[string]bool{semconv.AttrPstnGatewayAuthority: true}
	for _, f := range gatewayFields {
		known[f.key] = true
		if f.kind == kindList {
			known[f.key+"_count"] = true
		}
	}
	for _, k := range []string{
		semconv.AttrPstnGatewayInboundTeamsNumberTranslationRulesCount,
		semconv.AttrPstnGatewayInboundPstnNumberTranslationRulesCount,
		semconv.AttrPstnGatewayOutbundTeamsNumberTranslationRulesCount,
		semconv.AttrPstnGatewayOutboundPstnNumberTranslationRulesCount,
	} {
		if !known[k] {
			t.Errorf("count key %q has no list field", k)
		}
	}
}

// TestFixtureFieldsAreAllAccountedFor: every top-level wire field of the lab
// fixture is exported or listed here as deliberately not exported, so a field a
// capture shows can never be silently skipped.
func TestFixtureFieldsAreAllAccountedFor(t *testing.T) {
	exported := map[string]bool{fieldMetadata: true}
	for _, f := range gatewayFields {
		exported[f.wire] = true
	}
	for wire := range fixture(t)[0] {
		if !exported[wire] {
			t.Errorf("fixture field %s is neither exported nor listed as dropped", wire)
		}
	}
}
