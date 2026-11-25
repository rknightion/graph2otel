package sipdevicepolicy

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"reflect"
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

// fakeClient serves decoded fixtures by resource name; errs fails one resource.
type fakeClient struct {
	byName map[string][]map[string]any
	errs   map[string]error
	got    []string
}

func (f *fakeClient) Configurations(_ context.Context, name string) ([]map[string]any, error) {
	f.got = append(f.got, name)
	if err := f.errs[name]; err != nil {
		return nil, err
	}
	return f.byName[name], nil
}

func (f *fakeClient) VoiceApps(context.Context, teamsadminclient.VoiceAppKind) (teamsadminclient.VoiceAppsResult, error) {
	return teamsadminclient.VoiceAppsResult{}, errors.New("not used by sip_device_policy")
}

func load(t *testing.T, name string) []map[string]any {
	t.Helper()
	raw, err := os.ReadFile("testdata/" + name + ".json")
	if err != nil {
		t.Fatal(err)
	}
	var recs []map[string]any
	if err := json.Unmarshal(raw, &recs); err != nil {
		t.Fatal(err)
	}
	return recs
}

// fixtures decodes both committed lab captures afresh.
func fixtures(t *testing.T) *fakeClient {
	return &fakeClient{byName: map[string][]map[string]any{
		resourceSipDev:  load(t, resourceSipDev),
		resourceIPPhone: load(t, resourceIPPhone),
	}}
}

func run(t *testing.T, f *fakeClient) (*telemetrytest.Recorder, *recordoutcome.Recorder, error) {
	t.Helper()
	rec := telemetrytest.New()
	out := recordoutcome.NewRecorder()
	err := New(collectors.Deps{TeamsAdmin: f}).Collect(context.Background(), rec.Emitter(), out)
	return rec, out, err
}

func twinsOf(rec *telemetrytest.Recorder, event string) []telemetrytest.LogRecord {
	var out []telemetrytest.LogRecord
	for _, l := range rec.LogRecords() {
		if l.EventName == event {
			out = append(out, l)
		}
	}
	return out
}

func TestMapObject_SipDevicesFixture(t *testing.T) {
	got := mapObject(wirecheck.New("t", nil), nil, specs[0], load(t, resourceSipDev)[0])
	want := telemetry.Attrs{
		semconv.AttrSipDevicesIdentity:   "Global",
		semconv.AttrSipDevicesBulkSignIn: "Disabled",
		semconv.AttrSipDevicesAuthority:  "Host",
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("attributes differ\n got: %#v\nwant: %#v", got, want)
	}
}

// TestMapObject_IPPhoneFixture: the null Description is omitted, the Key and
// ConfigId blocks are not exported, the idle timeout is an integer and the
// hot-desking flag a "true"/"false" string.
func TestMapObject_IPPhoneFixture(t *testing.T) {
	got := mapObject(wirecheck.New("t", nil), nil, specs[1], load(t, resourceIPPhone)[0])
	want := telemetry.Attrs{
		semconv.AttrIpPhonePolicyIdentity:                       "Global",
		semconv.AttrIpPhonePolicySignInMode:                     "UserSignIn",
		semconv.AttrIpPhonePolicySearchOnCommonAreaPhoneMode:    "Enabled",
		semconv.AttrIpPhonePolicyAllowHomeScreen:                "EnabledUserOverride",
		semconv.AttrIpPhonePolicyAllowBetterTogether:            "Enabled",
		semconv.AttrIpPhonePolicyAllowHotDesking:                "true",
		semconv.AttrIpPhonePolicyHotDeskingIdleTimeoutInMinutes: 120,
		semconv.AttrIpPhonePolicyAuthority:                      "Host",
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("attributes differ\n got: %#v\nwant: %#v", got, want)
	}
}

func TestCollect_FixtureEndToEnd(t *testing.T) {
	f := fixtures(t)
	rec, out, err := run(t, f)
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	if !reflect.DeepEqual(f.got, []string{"TeamsSipDevicesConfiguration", "TeamsIPPhonePolicy"}) {
		t.Errorf("resources read = %v", f.got)
	}
	sip, ip := twinsOf(rec, eventSipDev), twinsOf(rec, eventIPPhone)
	if len(sip) != 1 || len(ip) != 1 {
		t.Fatalf("twins sip=%d ip=%d, want 1 and 1", len(sip), len(ip))
	}
	if sip[0].Body != "SIP devices configuration Global" || ip[0].Body != "IP phone policy Global" {
		t.Errorf("bodies = %q / %q", sip[0].Body, ip[0].Body)
	}
	for _, l := range append(sip, ip...) {
		if l.Attrs[semconv.AttrConfigHashVersion] != "1" || len(l.Attrs[semconv.AttrConfigSHA256]) != 64 {
			t.Errorf("%s hash attrs = %q / %q", l.EventName, l.Attrs[semconv.AttrConfigHashVersion], l.Attrs[semconv.AttrConfigSHA256])
		}
		if l.Attrs[semconv.AttrIngestTransport] != "teams_admin" {
			t.Errorf("%s ingest_transport = %q", l.EventName, l.Attrs[semconv.AttrIngestTransport])
		}
	}
	if sip[0].Attrs[semconv.AttrConfigSHA256] == ip[0].Attrs[semconv.AttrConfigSHA256] {
		t.Error("two different twins share a hash")
	}
	if names := rec.MetricNames(); len(names) != 0 {
		t.Errorf("metrics emitted = %v, want none", names)
	}
	want := recordoutcome.Counts{Fetched: 2, Mapped: 2, Emitted: 2}
	if got := out.Snapshot().Summarize(nil, false); got.Result != recordoutcome.ResultSuccess || got.Counts != want {
		t.Errorf("outcome = %#v, want success/%#v", got, want)
	}
}

// TestCollect_OneTwinPerPolicyInstance: the IP phone policy resource is a list;
// each instance is its own twin with its own hash.
func TestCollect_OneTwinPerPolicyInstance(t *testing.T) {
	f := fixtures(t)
	second := load(t, resourceIPPhone)[0]
	second["Identity"] = "Tag:CommonAreaPhones"
	second["SignInMode"] = "CommonAreaPhoneSignIn"
	f.byName[resourceIPPhone] = append(f.byName[resourceIPPhone], second)
	rec, _, err := run(t, f)
	if err != nil {
		t.Fatal(err)
	}
	ip := twinsOf(rec, eventIPPhone)
	if len(ip) != 2 {
		t.Fatalf("ip phone twins = %d, want 2", len(ip))
	}
	if ip[1].Attrs[semconv.AttrIpPhonePolicyIdentity] != "Tag:CommonAreaPhones" || ip[0].Attrs[semconv.AttrConfigSHA256] == ip[1].Attrs[semconv.AttrConfigSHA256] {
		t.Errorf("instances not distinct: %v / %v", ip[0].Attrs, ip[1].Attrs)
	}
}

func TestCollect_HashStableAndSensitive(t *testing.T) {
	hashes := func(f *fakeClient) (string, string) {
		rec, _, err := run(t, f)
		if err != nil {
			t.Fatal(err)
		}
		return twinsOf(rec, eventSipDev)[0].Attrs[semconv.AttrConfigSHA256], twinsOf(rec, eventIPPhone)[0].Attrs[semconv.AttrConfigSHA256]
	}
	sip, ip := hashes(fixtures(t))
	if sip2, ip2 := hashes(fixtures(t)); sip != sip2 || ip != ip2 {
		t.Error("two decodes of the fixtures hash differently")
	}

	f := fixtures(t)
	f.byName[resourceSipDev][0]["BulkSignIn"] = "Enabled"
	if s, i := hashes(f); s == sip || i != ip {
		t.Errorf("sip change: sip hash changed=%v, ip hash changed=%v, want true/false", s != sip, i != ip)
	}
	f = fixtures(t)
	f.byName[resourceIPPhone][0]["HotDeskingIdleTimeoutInMinutes"] = 60.0
	if s, i := hashes(f); i == ip || s != sip {
		t.Errorf("ip change: ip hash changed=%v, sip hash changed=%v, want true/false", i != ip, s != sip)
	}
	f = fixtures(t)
	f.byName[resourceIPPhone][0]["Description"] = "Lab phones"
	if _, i := hashes(f); i == ip {
		t.Error("a null Description becoming a value left the hash unchanged")
	}
	// The Key block is not exported, so it cannot move the hash.
	f = fixtures(t)
	f.byName[resourceIPPhone][0]["ConfigId"] = "Other"
	if _, i := hashes(f); i != ip {
		t.Error("an unexported wire field changed the hash")
	}
}

func TestCollect_NilClientErrors(t *testing.T) {
	if err := New(collectors.Deps{}).Collect(context.Background(), telemetrytest.New().Emitter(), recordoutcome.NewRecorder()); err == nil {
		t.Fatal("want an error from a nil client")
	}
}

func TestCollect_PermissionDenied(t *testing.T) {
	denied := &teamsadminclient.APIError{StatusCode: 403}
	f := fixtures(t)
	f.errs = map[string]error{resourceSipDev: denied, resourceIPPhone: denied}
	rec, out, err := run(t, f)
	if err == nil || !errors.Is(err, denied) {
		t.Fatalf("err = %v, want one wrapping the 403", err)
	}
	if causes := out.Snapshot().Causes; !reflect.DeepEqual(causes, []recordoutcome.Cause{recordoutcome.CausePermissionDenied}) {
		t.Errorf("causes = %v, want [permission_denied]", causes)
	}
	if len(rec.LogRecords()) != 0 {
		t.Error("a failed fetch must emit no twin")
	}
}

// TestCollect_OneResourceFailing: the healthy resource is still emitted, the
// error is returned so the tick counts as failed, and the cause is the failing
// one's.
func TestCollect_OneResourceFailing(t *testing.T) {
	f := fixtures(t)
	f.errs = map[string]error{resourceSipDev: errors.New("boom")}
	rec, out, err := run(t, f)
	if err == nil {
		t.Fatal("want an error when one resource fails")
	}
	if len(twinsOf(rec, eventSipDev)) != 0 || len(twinsOf(rec, eventIPPhone)) != 1 {
		t.Errorf("twins sip=%d ip=%d, want 0 and 1", len(twinsOf(rec, eventSipDev)), len(twinsOf(rec, eventIPPhone)))
	}
	if causes := out.Snapshot().Causes; !reflect.DeepEqual(causes, []recordoutcome.Cause{recordoutcome.CauseSourceError}) {
		t.Errorf("causes = %v, want [source_error]", causes)
	}
}

// TestEmptyLists: an empty resource emits nothing and is not an error.
func TestEmptyListEmitsNothing(t *testing.T) {
	f := &fakeClient{byName: map[string][]map[string]any{resourceSipDev: {}, resourceIPPhone: {}}}
	rec, _, err := run(t, f)
	if err != nil || len(rec.LogRecords()) != 0 {
		t.Errorf("err=%v logs=%d, want nil and 0", err, len(rec.LogRecords()))
	}
}

func TestKeysFollowTheNamingRule(t *testing.T) {
	for prefix, fields := range map[string][]field{"sip_devices_": sipDevicesFields, "ip_phone_policy_": ipPhoneFields} {
		for _, f := range fields {
			if want := adminmap.SnakeKey(prefix, f.wire); f.key != want {
				t.Errorf("wire %s exported as %q, naming rule gives %q", f.wire, f.key, want)
			}
		}
	}
	if adminmap.SnakeKey("ip_phone_policy_", "HotDeskingIdleTimeoutInMinutes") != semconv.AttrIpPhonePolicyHotDeskingIdleTimeoutInMinutes {
		t.Error("hot desking key does not follow the rule")
	}
	if semconv.AttrSipDevicesAuthority != "sip_devices_authority" || semconv.AttrIpPhonePolicyAuthority != "ip_phone_policy_authority" {
		t.Error("authority keys are prefix + authority")
	}
}

// TestFixtureFieldsAreAllAccountedFor: every top-level wire field of both
// fixtures is exported or deliberately dropped (the Key and ConfigId blocks
// repeat Identity and the schema), so a capture field is never silently skipped.
func TestFixtureFieldsAreAllAccountedFor(t *testing.T) {
	dropped := map[string]bool{"Key": true, "ConfigId": true, fieldMetadata: true}
	for _, s := range specs {
		exported := map[string]bool{}
		for _, f := range s.fields {
			exported[f.wire] = true
		}
		for wire := range load(t, s.resource)[0] {
			if !exported[wire] && !dropped[wire] {
				t.Errorf("%s fixture field %s is neither exported nor listed as dropped", s.resource, wire)
			}
		}
	}
}

// TestUnexpectedTypeIsReportedNotDropped: a wire type the fixture does not show
// reaches the wirecheck counter and the field is omitted rather than guessed.
func TestUnexpectedTypeIsReported(t *testing.T) {
	f := fixtures(t)
	f.byName[resourceIPPhone][0]["AllowHotDesking"] = "yes"
	rec, _, err := run(t, f)
	if err != nil {
		t.Fatal(err)
	}
	if _, present := twinsOf(rec, eventIPPhone)[0].Attrs[semconv.AttrIpPhonePolicyAllowHotDesking]; present {
		t.Error("a non-boolean AllowHotDesking must be omitted")
	}
	pts := rec.MetricPoints(wirecheck.MetricUnexpected)
	if len(pts) != 1 || pts[0].Attrs[semconv.AttrKind] != wirecheck.KindInvariant {
		t.Errorf("unexpected-type reports = %v, want one invariant", pts)
	}
}
