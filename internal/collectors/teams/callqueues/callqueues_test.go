package callqueues

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"reflect"
	"slices"
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
	res  teamsadminclient.VoiceAppsResult
	err  error
	kind teamsadminclient.VoiceAppKind
}

func (f *fakeClient) Configurations(context.Context, string) ([]map[string]any, error) {
	return nil, errors.New("unexpected Configurations call")
}

func (f *fakeClient) VoiceApps(_ context.Context, kind teamsadminclient.VoiceAppKind) (teamsadminclient.VoiceAppsResult, error) {
	f.kind = kind
	return f.res, f.err
}

// fixtureResult decodes the committed scrubbed lab capture afresh.
func fixtureResult(t *testing.T) teamsadminclient.VoiceAppsResult {
	t.Helper()
	raw, err := os.ReadFile("testdata/callqueues.json")
	if err != nil {
		t.Fatal(err)
	}
	var env struct {
		CallQueues  []map[string]any
		Diagnostics []struct{ Level, Message string }
	}
	if err := json.Unmarshal(raw, &env); err != nil {
		t.Fatal(err)
	}
	if len(env.CallQueues) != 2 {
		t.Fatalf("fixture has %d queues, want 2", len(env.CallQueues))
	}
	res := teamsadminclient.VoiceAppsResult{Records: env.CallQueues}
	for _, d := range env.Diagnostics {
		res.Diagnostics = append(res.Diagnostics, teamsadminclient.Diagnostic{Level: d.Level, Message: d.Message})
	}
	return res
}

func g(n int) string { return fmt.Sprintf("00000000-0000-4000-8000-0000000000%02d", n) }

func mapOne(t *testing.T, r map[string]any) (telemetry.Event, string, *telemetrytest.Recorder) {
	t.Helper()
	rec := telemetrytest.New()
	ev, method := New(collectors.Deps{}).twin(rec.Emitter(), r)
	return ev, method, rec
}

func TestTwin_FixtureAttributes(t *testing.T) {
	ev, method, _ := mapOne(t, fixtureResult(t).Records[0])
	if ev.Name != "teams.call_queue" || ev.Body != "call queue Teams Lab Sales" || ev.Severity != telemetry.SeverityInfo || method != "LongestIdle" {
		t.Errorf("event = %q / %q / %v / %q", ev.Name, ev.Body, ev.Severity, method)
	}
	got := ev.Attrs
	delete(got, semconv.AttrConfigSHA256)
	delete(got, semconv.AttrConfigHashVersion)
	want := telemetry.Attrs{
		"call_queue_id":                                     g(11),
		"call_queue_name":                                   "Teams Lab Sales",
		"call_queue_language_id":                            "en-GB",
		"call_queue_agent_alert_time_seconds":               20,
		"call_queue_enable_wrap_time":                       "false",
		"call_queue_wrap_time_duration_seconds":             0,
		"call_queue_allow_opt_out":                          "true",
		"call_queue_conference_mode":                        "true",
		"call_queue_presence_aware_routing":                 "false",
		"call_queue_agents_capped":                          "false",
		"call_queue_agents_in_sync_with_distribution_lists": "true",
		"call_queue_use_default_music_on_hold":              "true",
		"call_queue_overflow_threshold":                     5,
		"call_queue_timeout_threshold_seconds":              60,
		"call_queue_routing_method":                         "LongestIdle",
		"call_queue_routing_method_raw":                     3,
		"call_queue_overflow_action":                        "DisconnectWithBusy",
		"call_queue_overflow_action_raw":                    0,
		"call_queue_timeout_action":                         "Disconnect",
		"call_queue_timeout_action_raw":                     0,
		"call_queue_no_agent_action":                        "Queue",
		"call_queue_no_agent_action_raw":                    0,
		"call_queue_no_agent_apply_to":                      "NewCalls",
		"call_queue_no_agent_apply_to_raw":                  0,
		"call_queue_application_instances":                  []string{g(4)},
		"call_queue_application_instances_count":            1,
		"call_queue_obo_resource_account_ids_count":         0,
		"call_queue_distribution_lists_count":               0,
		"call_queue_authorized_users":                       []string{g(10)},
		"call_queue_authorized_users_count":                 1,
		"call_queue_agent_ids":                              []string{g(12), g(13), g(6)},
		"call_queue_agent_ids_count":                        3,
		"call_queue_agent_opt_in_count":                     3,
		"call_queue_overflow_prompt_texts_count":            0,
		"call_queue_overflow_prompt_file_names_count":       0,
		"call_queue_timeout_prompt_texts_count":             0,
		"call_queue_timeout_prompt_file_names_count":        0,
		"call_queue_no_agent_prompt_texts_count":            0,
		"call_queue_no_agent_prompt_file_names_count":       0,
	}
	if !reflect.DeepEqual(got, want) {
		for k, w := range want {
			if !reflect.DeepEqual(got[k], w) {
				t.Errorf("%s = %#v, want %#v", k, got[k], w)
			}
		}
		for k := range got {
			if _, ok := want[k]; !ok {
				t.Errorf("unexpected attribute %s = %#v", k, got[k])
			}
		}
	}

	// The second queue is RoundRobin with presence routing on.
	ev2, method2, _ := mapOne(t, fixtureResult(t).Records[1])
	if method2 != "RoundRobin" || ev2.Attrs["call_queue_presence_aware_routing"] != "true" || ev2.Attrs["call_queue_overflow_threshold"] != 50 {
		t.Errorf("second queue: %q %v %v", method2, ev2.Attrs["call_queue_presence_aware_routing"], ev2.Attrs["call_queue_overflow_threshold"])
	}
}

// TestEnumTables pins every table entry of the five integer enumerations
// (MicrosoftTeams 8.1.0, ...HuntGroup.Models) independently of the production
// maps.
func TestEnumTables(t *testing.T) {
	tables := map[string][]string{
		"RoutingMethod":  {"Attendant", "Serial", "RoundRobin", "LongestIdle"},
		"OverflowAction": {"DisconnectWithBusy", "Forward", "Voicemail", "SharedVoicemail"},
		"TimeoutAction":  {"Disconnect", "Forward", "Voicemail", "SharedVoicemail"},
		"NoAgentAction":  {"Queue", "Disconnect", "Forward", "Voicemail", "SharedVoicemail"},
		"NoAgentApplyTo": {"NewCalls", "AllCalls"},
	}
	for _, f := range enumFields {
		names, ok := tables[f.field]
		if !ok {
			t.Fatalf("unexpected enum field %s", f.field)
		}
		if len(f.table) != len(names) {
			t.Errorf("%s: table has %d entries, want %d", f.field, len(f.table), len(names))
		}
		for n, name := range names {
			r := fixtureResult(t).Records[0]
			r[f.field] = float64(n)
			a := mapAttrs(t, r)
			if a[f.key] != name || a[f.rawKey] != n {
				t.Errorf("%s=%d: got %v/%v, want %s/%d", f.field, n, a[f.key], a[f.rawKey], name, n)
			}
		}
		if _, ok := f.table[0]; !ok {
			t.Errorf("%s table has no 0 entry; the raw-export test in twin() relies on one", f.field)
		}
	}
}

func mapAttrs(t *testing.T, r map[string]any) telemetry.Attrs {
	t.Helper()
	ev, _, _ := mapOne(t, r)
	return ev.Attrs
}

func TestEnum_UnknownMissingAndNonInteger(t *testing.T) {
	for _, f := range enumFields {
		// An unknown integer: name "unknown", the integer under _raw, reported.
		r := fixtureResult(t).Records[0]
		r[f.field] = float64(99)
		ev, method, rec := mapOne(t, r)
		if ev.Attrs[f.key] != "unknown" || ev.Attrs[f.rawKey] != 99 {
			t.Errorf("%s=99: %v / %v", f.field, ev.Attrs[f.key], ev.Attrs[f.rawKey])
		}
		if f.field == "RoutingMethod" && method != "unknown" {
			t.Errorf("gauge label for RoutingMethod=99 = %q", method)
		}
		if !slices.Contains(rec.MetricNames(), wirecheck.MetricUnexpected) {
			t.Errorf("%s=99 was not reported through wirecheck", f.field)
		}

		// Missing and null, and a fractional value: "unknown", no _raw.
		for name, v := range map[string]any{"missing": nil, "fraction": 1.5, "string": "RoundRobin"} {
			r := fixtureResult(t).Records[0]
			if name == "missing" {
				delete(r, f.field)
			} else {
				r[f.field] = v
			}
			ev, _, _ := mapOne(t, r)
			if ev.Attrs[f.key] != "unknown" {
				t.Errorf("%s %s: key = %v, want unknown", f.field, name, ev.Attrs[f.key])
			}
			if raw, ok := ev.Attrs[f.rawKey]; ok {
				t.Errorf("%s %s: exported _raw %v for a value that is not an integer", f.field, name, raw)
			}
		}
	}
}

// TestCollect_GaugeCountsEveryQueue: a missing, fractional or unmapped
// RoutingMethod counts under unknown, so the series sum to the number of queues.
func TestCollect_GaugeCountsEveryQueue(t *testing.T) {
	res := fixtureResult(t) // LongestIdle + RoundRobin
	mk := func(v any, drop bool) map[string]any {
		r := map[string]any{"Identity": "x", "Name": "q"}
		if !drop {
			r["RoutingMethod"] = v
		}
		return r
	}
	res.Records = append(res.Records, mk(nil, true), mk(7.0, false), mk(1.5, false), mk(0.0, false), mk(1.0, false))
	rec := telemetrytest.New()
	if err := New(collectors.Deps{TeamsAdmin: &fakeClient{res: res}}).Collect(context.Background(), rec.Emitter(), nil); err != nil {
		t.Fatal(err)
	}
	got := map[string]float64{}
	var total float64
	for _, p := range rec.MetricPoints("teams.call_queue.count") {
		got[p.Attrs[semconv.AttrRoutingMethod]] = p.Value
		total += p.Value
		if p.Unit != "{call_queue}" {
			t.Errorf("unit = %q", p.Unit)
		}
	}
	want := map[string]float64{"LongestIdle": 1, "RoundRobin": 1, "Attendant": 1, "Serial": 1, "unknown": 3}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("gauge = %v, want %v", got, want)
	}
	if total != float64(len(res.Records)) {
		t.Errorf("gauge total %v != %d queues", total, len(res.Records))
	}
}

func TestCollect_DiagnosticsDedupedPerPoll(t *testing.T) {
	res := fixtureResult(t) // the same Warning twice
	res.Diagnostics = append(res.Diagnostics,
		teamsadminclient.Diagnostic{Level: "Information", Message: "other"},
		res.Diagnostics[0])
	rec := telemetrytest.New()
	fc := &fakeClient{res: res}
	if err := New(collectors.Deps{TeamsAdmin: fc}).Collect(context.Background(), rec.Emitter(), nil); err != nil {
		t.Fatal(err)
	}
	if fc.kind != teamsadminclient.CallQueues {
		t.Errorf("read kind %v", fc.kind)
	}
	var diags []telemetrytest.LogRecord
	twins := 0
	for _, l := range rec.LogRecords() {
		switch l.EventName {
		case "teams.call_queue_diagnostic":
			diags = append(diags, l)
		case "teams.call_queue":
			twins++
			if l.Attrs[semconv.AttrIngestTransport] != "teams_admin" || len(l.Attrs[semconv.AttrConfigSHA256]) != 64 {
				t.Errorf("twin stamps: %v / %v", l.Attrs[semconv.AttrIngestTransport], l.Attrs[semconv.AttrConfigSHA256])
			}
		}
	}
	if twins != 2 || len(diags) != 2 {
		t.Fatalf("twins=%d diagnostics=%d, want 2 and 2", twins, len(diags))
	}
	warn, info := diags[0], diags[1]
	if warn.Attrs[semconv.AttrCallQueueDiagnosticCount] != "3" || warn.Attrs[semconv.AttrCallQueueDiagnosticLevel] != "Warning" ||
		warn.SeverityText != "WARN" || warn.Body != res.Diagnostics[0].Message || warn.Attrs[semconv.AttrCallQueueDiagnosticMessage] != warn.Body {
		t.Errorf("warning record = %+v", warn)
	}
	if info.Attrs[semconv.AttrCallQueueDiagnosticCount] != "1" || info.SeverityText != "INFO" || info.Body != "other" {
		t.Errorf("info record = %+v", info)
	}
	for _, d := range diags {
		if _, ok := d.Attrs[semconv.AttrConfigSHA256]; ok {
			t.Error("a diagnostic carries a hash; it is not a twin")
		}
	}
}

// TestCollect_DiagnosticErrorLevelIsError: a diagnostic Microsoft marks as an
// error must not sit at INFO, where a severity filter at WARN or above hides it.
// The lab only produced Warning; Error is the level name the module's
// diagnostics use for failures.
func TestCollect_DiagnosticErrorLevelIsError(t *testing.T) {
	res := fixtureResult(t)
	res.Diagnostics = []teamsadminclient.Diagnostic{{Level: "Error", Message: "broken"}}
	rec := telemetrytest.New()
	if err := New(collectors.Deps{TeamsAdmin: &fakeClient{res: res}}).Collect(context.Background(), rec.Emitter(), nil); err != nil {
		t.Fatal(err)
	}
	for _, l := range rec.LogRecords() {
		if l.EventName == "teams.call_queue_diagnostic" && l.SeverityText != "ERROR" {
			t.Errorf("Error diagnostic severity = %q, want ERROR", l.SeverityText)
		}
	}
}

func TestTwin_ActionFamilies(t *testing.T) {
	r := fixtureResult(t).Records[0]
	r["OverflowAction"] = 1.0
	r["OverflowActionTarget"] = map[string]any{"Id": "tgt-1", "Type": "Phone"}
	r["OverflowRedirectVoicemailTextToSpeechPrompt"] = "voicemail text"
	r["OverflowDisconnectTextToSpeechPrompt"] = "disconnect text"
	r["OverflowRedirectPersonAudioFilePromptFileName"] = "person.wav"
	r["OverflowSharedVoicemailAudioFilePromptFileName"] = "shared.wav"
	r["OverflowRedirectPersonAudioFilePrompt"] = "opaque-handle" // content, never exported
	r["NoAgentSharedVoicemailTextToSpeechPrompt"] = "no agents"
	r["TimeoutRedirectPhoneNumberTextToSpeechPrompt"] = ""
	a := mapAttrs(t, r)

	if a[semconv.AttrCallQueueOverflowActionTargetId] != "tgt-1" || a[semconv.AttrCallQueueOverflowActionTargetType] != "Phone" {
		t.Errorf("overflow target = %v / %v", a[semconv.AttrCallQueueOverflowActionTargetId], a[semconv.AttrCallQueueOverflowActionTargetType])
	}
	if want := []string{"disconnect text", "voicemail text"}; !reflect.DeepEqual(a[semconv.AttrCallQueueOverflowPromptTexts], want) {
		t.Errorf("overflow texts = %v, want %v (field-name order)", a[semconv.AttrCallQueueOverflowPromptTexts], want)
	}
	if want := []string{"person.wav", "shared.wav"}; !reflect.DeepEqual(a[semconv.AttrCallQueueOverflowPromptFileNames], want) {
		t.Errorf("overflow files = %v, want %v", a[semconv.AttrCallQueueOverflowPromptFileNames], want)
	}
	if want := []string{"no agents"}; !reflect.DeepEqual(a[semconv.AttrCallQueueNoAgentPromptTexts], want) {
		t.Errorf("no agent texts = %v", a[semconv.AttrCallQueueNoAgentPromptTexts])
	}
	if a[semconv.AttrCallQueueTimeoutPromptTexts+"_count"] != 0 {
		t.Error("an empty prompt string was counted")
	}
	for k, v := range a {
		if s, ok := v.(string); ok && s == "opaque-handle" {
			t.Errorf("audio file prompt content leaked under %s", k)
		}
	}
}

// TestTwin_ActionTargetNotAnObject: the lab has no sample of a non-null target,
// so one that is not an object with an Id is reported, not guessed at.
func TestTwin_ActionTargetNotAnObject(t *testing.T) {
	r := fixtureResult(t).Records[0]
	r["TimeoutActionTarget"] = "sip:someone@example.com"
	ev, _, rec := mapOne(t, r)
	if _, ok := ev.Attrs[semconv.AttrCallQueueTimeoutActionTargetId]; ok {
		t.Error("exported a target id from a non-object target")
	}
	if !slices.Contains(rec.MetricNames(), wirecheck.MetricUnexpected) {
		t.Error("non-object target not reported through wirecheck")
	}
	// An absent or null target is the normal case and is not reported.
	if _, _, rec := mapOne(t, fixtureResult(t).Records[0]); slices.Contains(rec.MetricNames(), wirecheck.MetricUnexpected) {
		t.Error("the fixture's null targets were reported")
	}
}

func TestTwin_NullAbsentEmptyListsAndCap(t *testing.T) {
	r := fixtureResult(t).Records[0]
	r["Description"] = ""
	delete(r, "ShiftsTeamId")
	delete(r, "Agents")
	many := make([]any, 101)
	agents := make([]any, 101)
	for i := range many {
		many[i] = fmt.Sprintf("dl-%03d", i)
		agents[i] = map[string]any{"ObjectId": fmt.Sprintf("agent-%03d", i), "OptIn": i%2 == 0}
	}
	r["DistributionLists"] = many
	r["Agents"] = agents
	a := mapAttrs(t, r)
	for _, k := range []string{semconv.AttrCallQueueDescription, semconv.AttrCallQueueShiftsTeamId, semconv.AttrCallQueueIsCallbackEnabled,
		semconv.AttrCallQueueThreadId, semconv.AttrCallQueueComplianceRecordingForCallQueueIds, semconv.AttrCallQueueServiceLevelThresholdResponseTimeInSecond} {
		if v, ok := a[k]; ok {
			t.Errorf("%s = %#v, want omitted", k, v)
		}
	}
	if _, ok := a[semconv.AttrCallQueueComplianceRecordingForCallQueueIds+"_count"]; ok {
		t.Error("a null list exported a count")
	}
	if a[semconv.AttrCallQueueOboResourceAccountIds+"_count"] != 0 {
		t.Error("an empty list did not export count 0")
	}
	k := semconv.AttrCallQueueDistributionLists
	if len(a[k].([]string)) != 100 || a[k+"_count"] != 101 || a[k+"_truncated"] != "true" {
		t.Errorf("101 ids: len=%d count=%v truncated=%v", len(a[k].([]string)), a[k+"_count"], a[k+"_truncated"])
	}
	k = semconv.AttrCallQueueAgentIds
	if len(a[k].([]string)) != 100 || a[k+"_count"] != 101 || a[semconv.AttrCallQueueAgentOptInCount] != 51 {
		t.Errorf("101 agents: len=%d count=%v optin=%v", len(a[k].([]string)), a[k+"_count"], a[semconv.AttrCallQueueAgentOptInCount])
	}
}

func TestTwin_HashStableAndSensitive(t *testing.T) {
	h1 := mapAttrs(t, fixtureResult(t).Records[0])
	h2 := mapAttrs(t, fixtureResult(t).Records[0])
	if h1[semconv.AttrConfigSHA256] == "" || h1[semconv.AttrConfigSHA256] != h2[semconv.AttrConfigSHA256] {
		t.Errorf("hash not stable across two decodes")
	}
	if h1[semconv.AttrConfigHashVersion] != adminmap.HashVersion {
		t.Errorf("version = %v", h1[semconv.AttrConfigHashVersion])
	}
	for field, v := range map[string]any{"TimeoutThreshold": 90.0, "RoutingMethod": 1.0, "Name": "renamed"} {
		r := fixtureResult(t).Records[0]
		r[field] = v
		if mapAttrs(t, r)[semconv.AttrConfigSHA256] == h1[semconv.AttrConfigSHA256] {
			t.Errorf("hash did not change when %s changed", field)
		}
	}
	// A wire field that is not exported must not move the hash (ETag is volatile).
	r := fixtureResult(t).Records[0]
	r["ETag"] = "different"
	if mapAttrs(t, r)[semconv.AttrConfigSHA256] != h1[semconv.AttrConfigSHA256] {
		t.Error("hash changed on an unexported field")
	}
}

func TestCollect_NilClientErrors(t *testing.T) {
	if err := New(collectors.Deps{}).Collect(context.Background(), telemetrytest.New().Emitter(), recordoutcome.NewRecorder()); err == nil {
		t.Fatal("nil client returned no error")
	}
}

func TestCollect_PermissionDenied(t *testing.T) {
	apiErr := &teamsadminclient.APIError{StatusCode: 403, Path: "/Teams.VoiceApps/callqueues"}
	outcomes := recordoutcome.NewRecorder()
	err := New(collectors.Deps{TeamsAdmin: &fakeClient{err: apiErr}}).Collect(context.Background(), telemetrytest.New().Emitter(), outcomes)
	if err == nil || !errors.Is(err, apiErr) {
		t.Fatalf("err = %v, want it to wrap the 403", err)
	}
	if !slices.Contains(outcomes.Snapshot().Causes, recordoutcome.CausePermissionDenied) {
		t.Errorf("causes = %v", outcomes.Snapshot().Causes)
	}
	outcomes = recordoutcome.NewRecorder()
	err = New(collectors.Deps{TeamsAdmin: &fakeClient{err: errors.New("boom")}}).Collect(context.Background(), telemetrytest.New().Emitter(), outcomes)
	if err == nil || !slices.Contains(outcomes.Snapshot().Causes, recordoutcome.CauseSourceError) {
		t.Errorf("non-403: err=%v causes=%v", err, outcomes.Snapshot().Causes)
	}
}

func TestCollect_Outcomes(t *testing.T) {
	outcomes := recordoutcome.NewRecorder()
	if err := New(collectors.Deps{TeamsAdmin: &fakeClient{res: fixtureResult(t)}}).Collect(context.Background(), telemetrytest.New().Emitter(), outcomes); err != nil {
		t.Fatal(err)
	}
	if got := outcomes.Snapshot().Counts; got != (recordoutcome.Counts{Fetched: 2, Mapped: 2, Emitted: 2}) {
		t.Errorf("outcomes = %+v", got)
	}
}

// TestAttributeNaming: every key mapping one wire field directly is the event
// prefix plus the snake_case of the field (the #712 rule), plus _seconds where
// the field holds seconds with no unit in its name. Derived keys are exceptions.
func TestAttributeNaming(t *testing.T) {
	const prefix = "call_queue_"
	check := func(rows []struct{ field, key string }, suffix map[string]string) {
		for _, f := range rows {
			if want := adminmap.SnakeKey(prefix, f.field) + suffix[f.field]; f.key != want {
				t.Errorf("%s: key %q, want %q", f.field, f.key, want)
			}
		}
	}
	check(stringFields, nil)
	check(boolFields, nil)
	check(listFields, nil)
	check(numFields, map[string]string{"AgentAlertTime": "_seconds", "WrapTimeDuration": "_seconds", "TimeoutThreshold": "_seconds"})
	for _, f := range enumFields {
		if f.key != adminmap.SnakeKey(prefix, f.field) || f.rawKey != f.key+"_raw" {
			t.Errorf("%s: keys %q / %q", f.field, f.key, f.rawKey)
		}
	}
	// Exceptions: Identity is call_queue_id because call_queue_identity already
	// holds a resource account UPN in teams.voice_apps; the opt-in count is the one
	// reused constant.
	if semconv.AttrCallQueueId != "call_queue_id" || semconv.AttrCallQueueAgentOptInCount != "call_queue_agent_opt_in_count" {
		t.Error("id or reused opt-in count key changed")
	}
	for _, f := range families {
		for _, k := range []string{f.targetID, f.targetType, f.texts, f.fileNms} {
			if len(k) <= len(prefix) || k[:len(prefix)] != prefix {
				t.Errorf("derived key %q lacks prefix", k)
			}
		}
	}
}
