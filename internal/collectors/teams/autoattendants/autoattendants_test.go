package autoattendants

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/rknightion/graph2otel/internal/collectors"
	"github.com/rknightion/graph2otel/internal/recordoutcome"
	"github.com/rknightion/graph2otel/internal/semconv"
	"github.com/rknightion/graph2otel/internal/teams/adminmap"
	"github.com/rknightion/graph2otel/internal/teamsadminclient"
	"github.com/rknightion/graph2otel/internal/telemetry"
	"github.com/rknightion/graph2otel/internal/telemetrytest"
)

// fakeClient returns canned VoiceApps results; Configurations is unused here.
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

// fixture decodes the committed scrubbed lab capture; each call is a fresh decode.
func fixture(t *testing.T) []map[string]any {
	t.Helper()
	raw, err := os.ReadFile("testdata/auto-attendants.json")
	if err != nil {
		t.Fatal(err)
	}
	var env struct {
		AutoAttendants []map[string]any
	}
	if err := json.Unmarshal(raw, &env); err != nil {
		t.Fatal(err)
	}
	if len(env.AutoAttendants) != 1 {
		t.Fatalf("fixture has %d auto attendants, want 1", len(env.AutoAttendants))
	}
	return env.AutoAttendants
}

func g(n int) string { return fmt.Sprintf("00000000-0000-4000-8000-0000000000%02d", n) }

func TestTwin_FixtureAttributes(t *testing.T) {
	ev := twin(fixture(t)[0])
	if ev.Name != "teams.auto_attendant" || ev.Body != "auto attendant Teams Lab Attendant" || ev.Severity != telemetry.SeverityInfo {
		t.Errorf("event = %q / %q / %v", ev.Name, ev.Body, ev.Severity)
	}
	got := ev.Attrs
	delete(got, semconv.AttrConfigSHA256)
	delete(got, semconv.AttrConfigHashVersion)
	want := telemetry.Attrs{
		"auto_attendant_id":                             g(1),
		"auto_attendant_name":                           "Teams Lab Attendant",
		"auto_attendant_language_id":                    "en-GB",
		"auto_attendant_voice_id":                       "Male",
		"auto_attendant_time_zone_id":                   "GMT Standard Time",
		"auto_attendant_user_name_extension":            "None",
		"auto_attendant_voice_response_enabled":         "true",
		"auto_attendant_mainline_attendant_enabled":     "false",
		"auto_attendant_application_instances":          []string{g(9)},
		"auto_attendant_application_instances_count":    1,
		"auto_attendant_authorized_users":               []string{g(10)},
		"auto_attendant_authorized_users_count":         1,
		"auto_attendant_hide_authorized_users_count":    0,
		"auto_attendant_operator_type":                  "User",
		"auto_attendant_operator_id":                    g(6),
		"auto_attendant_schedule_count":                 1,
		"auto_attendant_call_flow_count":                2,
		"auto_attendant_call_handling_types":            []string{"AfterHours"},
		"auto_attendant_call_handling_types_count":      1,
		"auto_attendant_menu_option_actions":            []string{"TransferCallToTarget", "TransferCallToTarget", "TransferCallToTarget", "DisconnectCall"},
		"auto_attendant_menu_option_actions_count":      4,
		"auto_attendant_menu_option_target_types":       []string{"ApplicationEndpoint", "ApplicationEndpoint", "User", "none"},
		"auto_attendant_menu_option_target_types_count": 4,
		"auto_attendant_menu_target_ids":                []string{g(4), g(5), g(6)},
		"auto_attendant_menu_target_ids_count":          3,
		"auto_attendant_greeting_texts": []string{
			"Thank you for calling the Teams lab.",
			"The Teams lab is closed. Our hours are eight until eight, Monday to Saturday. Goodbye.",
		},
		"auto_attendant_greeting_texts_count": 2,
		"auto_attendant_menu_prompt_texts": []string{
			"For sales, press 1. For support, press 2. To speak to the operator, press 0.",
		},
		"auto_attendant_menu_prompt_texts_count": 1,
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
}

// TestTwin_NullAndAbsentOmitted: Status is null on the wire, so there must be no
// status key; removing a field outright must also leave no trace.
func TestTwin_NullAndAbsentOmitted(t *testing.T) {
	r := fixture(t)[0]
	delete(r, "VoiceId")
	delete(r, "Operator")
	delete(r, "Schedules")
	r["LanguageId"] = ""
	a := twin(r).Attrs
	for _, k := range []string{
		semconv.AttrAutoAttendantStatus, semconv.AttrAutoAttendantVoiceId, semconv.AttrAutoAttendantOperatorType,
		semconv.AttrAutoAttendantOperatorId, semconv.AttrAutoAttendantScheduleCount, semconv.AttrAutoAttendantLanguageId,
	} {
		if v, ok := a[k]; ok {
			t.Errorf("%s = %#v, want omitted", k, v)
		}
	}
}

// TestTwin_MenuListsStayAligned: the after-hours DisconnectCall option has a null
// CallTarget. Its target type must be a "none" placeholder at the same index as
// its action, and the ID list must hold only the real targets.
func TestTwin_MenuListsStayAligned(t *testing.T) {
	a := twin(fixture(t)[0]).Attrs
	actions := a[semconv.AttrAutoAttendantMenuOptionActions].([]string)
	types := a[semconv.AttrAutoAttendantMenuOptionTargetTypes].([]string)
	if len(actions) != len(types) {
		t.Fatalf("misaligned: %d actions, %d target types", len(actions), len(types))
	}
	i := slices.Index(actions, "DisconnectCall")
	if i < 0 || types[i] != "none" {
		t.Errorf("DisconnectCall at %d has target type %q, want none", i, types[i])
	}
	if ids := a[semconv.AttrAutoAttendantMenuTargetIds].([]string); len(ids) != len(types)-1 {
		t.Errorf("target ids = %d, want one fewer than the %d options", len(ids), len(types))
	}

	// A null target in the MIDDLE of the default flow shifts nothing after it.
	r := fixture(t)[0]
	opts := r["DefaultCallFlow"].(map[string]any)["Menu"].(map[string]any)["MenuOptions"].([]any)
	opts[1].(map[string]any)["CallTarget"] = nil
	a = twin(r).Attrs
	types = a[semconv.AttrAutoAttendantMenuOptionTargetTypes].([]string)
	if want := []string{"ApplicationEndpoint", "none", "User", "none"}; !reflect.DeepEqual(types, want) {
		t.Errorf("target types = %v, want %v", types, want)
	}
}

func TestTwin_EmptyListsAndCap(t *testing.T) {
	r := fixture(t)[0]
	r["ApplicationInstances"] = []any{}
	delete(r, "AuthorizedUsers")
	many := make([]any, 101)
	for i := range many {
		many[i] = fmt.Sprintf("user-%03d", i)
	}
	r["HideAuthorizedUsers"] = many
	a := twin(r).Attrs

	if n := a[semconv.AttrAutoAttendantApplicationInstances+"_count"]; n != 0 {
		t.Errorf("empty list count = %v, want 0", n)
	}
	if _, ok := a[semconv.AttrAutoAttendantApplicationInstances]; ok {
		t.Error("empty list exported a list value")
	}
	if _, ok := a[semconv.AttrAutoAttendantAuthorizedUsers+"_count"]; ok {
		t.Error("absent list exported a count")
	}
	k := semconv.AttrAutoAttendantHideAuthorizedUsers
	if got := len(a[k].([]string)); got != 100 {
		t.Errorf("capped list length = %d, want 100", got)
	}
	if a[k+"_count"] != 101 || a[k+"_truncated"] != true {
		t.Errorf("count/truncated = %v/%v, want 101/true", a[k+"_count"], a[k+"_truncated"])
	}
}

func TestTwin_HashStableAndSensitive(t *testing.T) {
	h1 := twin(fixture(t)[0]).Attrs
	h2 := twin(fixture(t)[0]).Attrs
	if h1[semconv.AttrConfigSHA256] == "" || h1[semconv.AttrConfigSHA256] != h2[semconv.AttrConfigSHA256] {
		t.Errorf("hash not stable across two decodes: %v vs %v", h1[semconv.AttrConfigSHA256], h2[semconv.AttrConfigSHA256])
	}
	if h1[semconv.AttrConfigHashVersion] != adminmap.HashVersion {
		t.Errorf("hash version = %v", h1[semconv.AttrConfigHashVersion])
	}
	changed := fixture(t)[0]
	changed["TimeZoneId"] = "UTC"
	if twin(changed).Attrs[semconv.AttrConfigSHA256] == h1[semconv.AttrConfigSHA256] {
		t.Error("hash did not change when TimeZoneId changed")
	}
	// A change inside the call flow tree that shows only in a derived list.
	flow := fixture(t)[0]
	flow["CallFlows"].([]any)[0].(map[string]any)["Menu"].(map[string]any)["MenuOptions"].([]any)[0].(map[string]any)["Action"] = "TransferCallToOperator"
	if twin(flow).Attrs[semconv.AttrConfigSHA256] == h1[semconv.AttrConfigSHA256] {
		t.Error("hash did not change when a menu option action changed")
	}
}

func TestCollect_EmitsTwinThroughEmitter(t *testing.T) {
	rec := telemetrytest.New()
	fc := &fakeClient{res: teamsadminclient.VoiceAppsResult{Records: fixture(t)}}
	outcomes := recordoutcome.NewRecorder()
	if err := New(collectors.Deps{TeamsAdmin: fc}).Collect(context.Background(), rec.Emitter(), outcomes); err != nil {
		t.Fatal(err)
	}
	if fc.kind != teamsadminclient.AutoAttendants {
		t.Errorf("read kind %v, want AutoAttendants", fc.kind)
	}
	logs := rec.LogRecords()
	if len(logs) != 1 || logs[0].EventName != "teams.auto_attendant" {
		t.Fatalf("logs = %+v", logs)
	}
	a := logs[0].Attrs
	if a[semconv.AttrIngestTransport] != "teams_admin" {
		t.Errorf("ingest_transport = %q, want teams_admin", a[semconv.AttrIngestTransport])
	}
	if a[semconv.AttrAutoAttendantMenuOptionTargetTypes] != "ApplicationEndpoint,ApplicationEndpoint,User,none" {
		t.Errorf("target types on the wire = %q", a[semconv.AttrAutoAttendantMenuOptionTargetTypes])
	}
	if len(a[semconv.AttrConfigSHA256]) != 64 {
		t.Errorf("config_sha256 = %q", a[semconv.AttrConfigSHA256])
	}
	if got := outcomes.Snapshot().Counts; got != (recordoutcome.Counts{Fetched: 1, Mapped: 1, Emitted: 1}) {
		t.Errorf("outcomes = %+v", got)
	}
	if names := rec.MetricNames(); len(names) != 0 {
		t.Errorf("auto attendants emit no metrics, got %v", names)
	}
}

func TestCollect_NilClientErrors(t *testing.T) {
	err := New(collectors.Deps{}).Collect(context.Background(), telemetrytest.New().Emitter(), recordoutcome.NewRecorder())
	if err == nil {
		t.Fatal("nil client returned no error")
	}
}

func TestCollect_PermissionDenied(t *testing.T) {
	apiErr := &teamsadminclient.APIError{StatusCode: 403, Path: "/Teams.VoiceApps/auto-attendants"}
	outcomes := recordoutcome.NewRecorder()
	err := New(collectors.Deps{TeamsAdmin: &fakeClient{err: apiErr}}).Collect(context.Background(), telemetrytest.New().Emitter(), outcomes)
	if err == nil || !errors.Is(err, apiErr) {
		t.Fatalf("err = %v, want it to wrap the 403", err)
	}
	if !slices.Contains(outcomes.Snapshot().Causes, recordoutcome.CausePermissionDenied) {
		t.Errorf("causes = %v, want permission_denied", outcomes.Snapshot().Causes)
	}

	outcomes = recordoutcome.NewRecorder()
	err = New(collectors.Deps{TeamsAdmin: &fakeClient{err: errors.New("boom")}}).Collect(context.Background(), telemetrytest.New().Emitter(), outcomes)
	if err == nil || !slices.Contains(outcomes.Snapshot().Causes, recordoutcome.CauseSourceError) {
		t.Errorf("non-403 error: err=%v causes=%v", err, outcomes.Snapshot().Causes)
	}
}

// TestAttributeNaming: every key that maps one wire field directly is the
// event prefix plus the snake_case of the field (the #712 rule); derived keys are
// listed as exceptions.
func TestAttributeNaming(t *testing.T) {
	const prefix = "auto_attendant_"
	check := func(rows []struct{ field, key string }) {
		for _, f := range rows {
			if want := adminmap.SnakeKey(prefix, f.field); f.key != want {
				t.Errorf("%s: key %q, want %q", f.field, f.key, want)
			}
		}
	}
	check(stringFields)
	check(boolFields)
	check(listFields)
	if semconv.AttrAutoAttendantId != "auto_attendant_id" {
		t.Errorf("object id key = %q (the exception: Id maps to auto_attendant_id)", semconv.AttrAutoAttendantId)
	}
	derived := []string{
		semconv.AttrAutoAttendantOperatorType, semconv.AttrAutoAttendantOperatorId, semconv.AttrAutoAttendantScheduleCount,
		semconv.AttrAutoAttendantCallFlowCount, semconv.AttrAutoAttendantCallHandlingTypes, semconv.AttrAutoAttendantMenuOptionActions,
		semconv.AttrAutoAttendantMenuOptionTargetTypes, semconv.AttrAutoAttendantMenuTargetIds, semconv.AttrAutoAttendantGreetingTexts,
		semconv.AttrAutoAttendantMenuPromptTexts,
	}
	for _, k := range derived {
		if !strings.HasPrefix(k, prefix) {
			t.Errorf("derived key %q lacks prefix %q", k, prefix)
		}
	}
}
