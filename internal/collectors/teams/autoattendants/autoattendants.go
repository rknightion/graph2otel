// Package autoattendants is the Teams auto attendant configuration collector
// (#720), read over the Teams admin API (internal/teamsadminclient,
// teams_admin transport, #712). One twin per auto attendant per poll carries the
// attendant's current configuration plus a config_sha256 over the exported
// attributes, so a query can see that a configuration changed between polls with
// no state held here.
//
// A snapshot, not an event stream: twins are stamped at poll time. There are no
// gauges: object counts are LogQL over the twins.
//
// # Menu option lists stay aligned
//
// auto_attendant_menu_option_actions and auto_attendant_menu_option_target_types
// get one entry per menu option, over the default call flow and then each call
// flow in wire order. An option with a null CallTarget (a DisconnectCall option)
// contributes "none" to the target type list, so index i of one list describes
// the same option as index i of the other. auto_attendant_menu_target_ids holds
// only the non-null target IDs and is therefore NOT positional.
//
// # Wire fields not exported
//
// Exported text includes greeting and menu prompt text (the telemetry model's one
// content exclusion is secrets, and prompts are not). Not exported:
//
//   - TenantId: the emitter stamps tenant_id.
//   - Every audio file prompt and *FileDownloadUri handle: the fetch handle for a
//     file whose id and name are the reference; whether they are signed is
//     unmeasured.
//   - DefaultCallFlow/CallFlows ids, names, Greetings and Menu fields other than
//     those above (DtmfResponse, VoiceResponses, DialByNameEnabled,
//     DirectorySearchMethod, timeout and AI disclaimer fields): the shape of the
//     tree is summarized by the counts and lists; the full tree is not a flat
//     attribute set.
//   - Schedules and CallHandlingAssociations bodies beyond their count and types.
//   - DialByNameResourceId, DirectoryLookupScope, OperatorSharedVoicemail,
//     GreetingsSettingAuthorizedUsers, MainlineAttendantAgentVoiceId,
//     SpamDetectionTemplateId and the AutoRecording*, SharedVoicemailTriageSettingsId
//     fields: null on the lab and unmeasured.
//
// Auto attendant enumerations are strings on the wire and are exported
// unchanged and unwatched.
package autoattendants

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/rknightion/graph2otel/internal/collector"
	"github.com/rknightion/graph2otel/internal/collectors"
	"github.com/rknightion/graph2otel/internal/recordoutcome"
	"github.com/rknightion/graph2otel/internal/semconv"
	"github.com/rknightion/graph2otel/internal/teams/adminmap"
	"github.com/rknightion/graph2otel/internal/teamsadminclient"
	"github.com/rknightion/graph2otel/internal/telemetry"
)

const (
	// collectorName is the stable key for config, self-observability and the
	// admin status page.
	collectorName = "teams.auto_attendants"
	// eventName is the OTLP LogRecord EventName of the twin.
	eventName = "teams.auto_attendant"
	// interval: auto attendant configuration changes when an admin edits it.
	interval = time.Hour
	// noTarget fills the target type list for an option with no CallTarget.
	noTarget = "none"
)

// Wire field names read by the mapper.
const (
	fieldID                       = "Id"
	fieldName                     = "Name"
	fieldDefaultCallFlow          = "DefaultCallFlow"
	fieldCallFlows                = "CallFlows"
	fieldSchedules                = "Schedules"
	fieldCallHandlingAssociations = "CallHandlingAssociations"
	fieldOperator                 = "Operator"
	fieldMenu                     = "Menu"
	fieldMenuOptions              = "MenuOptions"
	fieldPrompts                  = "Prompts"
	fieldGreetings                = "Greetings"
	fieldAction                   = "Action"
	fieldCallTarget               = "CallTarget"
	fieldType                     = "Type"
	fieldTTS                      = "TextToSpeechPrompt"
)

// stringFields are scalar string fields exported verbatim under their key.
var stringFields = []struct{ field, key string }{
	{"Name", semconv.AttrAutoAttendantName},
	{"LanguageId", semconv.AttrAutoAttendantLanguageId},
	{"VoiceId", semconv.AttrAutoAttendantVoiceId},
	{"TimeZoneId", semconv.AttrAutoAttendantTimeZoneId},
	{"UserNameExtension", semconv.AttrAutoAttendantUserNameExtension},
	{"Status", semconv.AttrAutoAttendantStatus},
}

// boolFields are exported only when the wire carried a real boolean.
var boolFields = []struct{ field, key string }{
	{"VoiceResponseEnabled", semconv.AttrAutoAttendantVoiceResponseEnabled},
	{"MainlineAttendantEnabled", semconv.AttrAutoAttendantMainlineAttendantEnabled},
}

// listFields are ID lists: exported capped, with _count (0 for an empty array).
var listFields = []struct{ field, key string }{
	{"ApplicationInstances", semconv.AttrAutoAttendantApplicationInstances},
	{"AuthorizedUsers", semconv.AttrAutoAttendantAuthorizedUsers},
	{"HideAuthorizedUsers", semconv.AttrAutoAttendantHideAuthorizedUsers},
}

// Collector reads auto attendant configuration.
type Collector struct {
	client collectors.TeamsAdminClient
}

// New builds the collector. A zero Deps (the census) leaves the client nil;
// Collect then errors.
func New(d collectors.Deps) *Collector { return &Collector{client: d.TeamsAdmin} }

// Name implements collector.Collector.
func (*Collector) Name() string { return collectorName }

// Profiles declares this collector's profile membership.
func (*Collector) Profiles() collector.ProfileSet { return collector.ProfileTeams }

// DefaultInterval implements collector.Collector.
func (*Collector) DefaultInterval() time.Duration { return interval }

// IngestTransport marks every record as coming from the Teams admin API.
func (*Collector) IngestTransport() telemetry.Transport { return telemetry.TransportTeamsAdmin }

// RequiredPermissions is empty: access is an Entra directory role on the
// poller, not a Graph scope.
func (*Collector) RequiredPermissions() []string { return nil }

// Collect reads every auto attendant and emits one twin each.
func (c *Collector) Collect(ctx context.Context, e telemetry.Emitter, outcomes *recordoutcome.Recorder) error {
	if c.client == nil {
		return errors.New(collectorName + ": no Teams admin API client (teams.admin_api.enabled is not set)")
	}
	e = telemetry.WithTransport(e, telemetry.TransportTeamsAdmin)

	res, err := c.client.VoiceApps(ctx, teamsadminclient.AutoAttendants)
	if err != nil {
		if teamsadminclient.IsPermission(err) {
			outcomes.Cause(recordoutcome.CausePermissionDenied)
		} else {
			outcomes.Cause(recordoutcome.CauseSourceError)
		}
		return fmt.Errorf("%s: read auto attendants: %w", collectorName, err)
	}
	outcomes.Add(recordoutcome.OutcomeFetched, uint64(len(res.Records)))
	for _, r := range res.Records {
		e.LogEvent(twin(r))
		outcomes.Add(recordoutcome.OutcomeMapped, 1)
		outcomes.Add(recordoutcome.OutcomeEmitted, 1)
	}
	return nil
}

// twin maps one auto attendant to its log record.
func twin(r map[string]any) telemetry.Event {
	attrs := telemetry.Attrs{}
	telemetry.SetStr(attrs, semconv.AttrAutoAttendantId, str(r, fieldID))
	for _, f := range stringFields {
		telemetry.SetStr(attrs, f.key, str(r, f.field))
	}
	for _, f := range boolFields {
		if b, ok := r[f.field].(bool); ok {
			telemetry.SetBool(attrs, f.key, b)
		}
	}
	for _, f := range listFields {
		adminmap.SetIDs(attrs, f.key, strList(r, f.field))
	}

	if op, ok := r[fieldOperator].(map[string]any); ok {
		telemetry.SetStr(attrs, semconv.AttrAutoAttendantOperatorType, str(op, fieldType))
		telemetry.SetStr(attrs, semconv.AttrAutoAttendantOperatorId, str(op, fieldID))
	}
	if s, ok := r[fieldSchedules].([]any); ok {
		attrs[semconv.AttrAutoAttendantScheduleCount] = len(s)
	}

	flows := callFlows(r)
	attrs[semconv.AttrAutoAttendantCallFlowCount] = len(flows)

	handling := []string{}
	if assoc, ok := r[fieldCallHandlingAssociations].([]any); ok {
		for _, a := range assoc {
			if m, ok := a.(map[string]any); ok {
				if t := str(m, fieldType); t != "" {
					handling = append(handling, t)
				}
			}
		}
	}
	adminmap.SetIDs(attrs, semconv.AttrAutoAttendantCallHandlingTypes, handling)

	actions, targetTypes, targetIDs := []string{}, []string{}, []string{}
	greetings, prompts := []string{}, []string{}
	for _, flow := range flows {
		greetings = append(greetings, promptTexts(flow[fieldGreetings])...)
		menu, _ := flow[fieldMenu].(map[string]any)
		if menu == nil {
			continue
		}
		prompts = append(prompts, promptTexts(menu[fieldPrompts])...)
		opts, _ := menu[fieldMenuOptions].([]any)
		for _, o := range opts {
			opt, _ := o.(map[string]any)
			actions = append(actions, orNone(str(opt, fieldAction)))
			target, _ := opt[fieldCallTarget].(map[string]any)
			targetTypes = append(targetTypes, orNone(str(target, fieldType)))
			if id := str(target, fieldID); id != "" {
				targetIDs = append(targetIDs, id)
			}
		}
	}
	adminmap.SetIDs(attrs, semconv.AttrAutoAttendantMenuOptionActions, actions)
	adminmap.SetIDs(attrs, semconv.AttrAutoAttendantMenuOptionTargetTypes, targetTypes)
	adminmap.SetIDs(attrs, semconv.AttrAutoAttendantMenuTargetIds, targetIDs)
	adminmap.SetIDs(attrs, semconv.AttrAutoAttendantGreetingTexts, greetings)
	adminmap.SetIDs(attrs, semconv.AttrAutoAttendantMenuPromptTexts, prompts)

	attrs[semconv.AttrConfigSHA256] = adminmap.Hash(attrs)
	attrs[semconv.AttrConfigHashVersion] = adminmap.HashVersion

	return telemetry.Event{
		Name:     eventName,
		Body:     "auto attendant " + str(r, fieldName),
		Severity: telemetry.SeverityInfo,
		Attrs:    attrs,
	}
}

// callFlows is the default call flow (when present) followed by every entry of
// CallFlows, in wire order.
func callFlows(r map[string]any) []map[string]any {
	var out []map[string]any
	if d, ok := r[fieldDefaultCallFlow].(map[string]any); ok {
		out = append(out, d)
	}
	if arr, ok := r[fieldCallFlows].([]any); ok {
		for _, f := range arr {
			if m, ok := f.(map[string]any); ok {
				out = append(out, m)
			}
		}
	}
	return out
}

// promptTexts returns the non-empty TextToSpeechPrompt of each prompt object.
func promptTexts(v any) []string {
	arr, _ := v.([]any)
	var out []string
	for _, p := range arr {
		if m, ok := p.(map[string]any); ok {
			if s := str(m, fieldTTS); s != "" {
				out = append(out, s)
			}
		}
	}
	return out
}

func orNone(s string) string {
	if s == "" {
		return noTarget
	}
	return s
}

// str reads a string field, "" when absent, null or not a string.
func str(m map[string]any, key string) string {
	s, _ := m[key].(string)
	return s
}

// strList returns the strings of a JSON array: nil when the field is absent or
// not an array (omitted), a non-nil empty slice for an empty array (_count 0).
func strList(m map[string]any, key string) []string {
	arr, ok := m[key].([]any)
	if !ok {
		return nil
	}
	out := make([]string, 0, len(arr))
	for _, v := range arr {
		if s, ok := v.(string); ok && s != "" {
			out = append(out, s)
		}
	}
	return out
}

func init() {
	collectors.Register(func(d collectors.Deps) collector.SnapshotCollector { return New(d) })
}

var _ collector.SnapshotCollector = (*Collector)(nil)
