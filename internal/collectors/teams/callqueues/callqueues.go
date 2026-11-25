// Package callqueues is the Teams call queue configuration collector (#720),
// read over the Teams admin API (internal/teamsadminclient, teams_admin
// transport, #712). One twin per call queue per poll carries the queue's current
// configuration plus a config_sha256 over the exported attributes, so a query can
// see that a configuration changed between polls with no state held here.
//
// # Gauge
//
// teams.call_queue.count{routing_method} counts queues by routing method. A queue
// whose RoutingMethod is missing, null, non-integer or an integer outside the
// table counts under "unknown", so the total always equals the number of queues.
//
// # Integer enumerations
//
// RoutingMethod, OverflowAction, TimeoutAction, NoAgentAction and NoAgentApplyTo
// are integers on the wire. The names come from the MicrosoftTeams module's .NET
// enum types, not from Microsoft's wire docs, and only RoutingMethod 2 and 3 are
// confirmed against live configuration. An unknown integer is exported as
// "unknown" plus <key>_raw and reported through wirecheck; nothing is dropped.
//
// # Diagnostics
//
// The Diagnostics envelope array carries no reference to a queue, and the client
// appends it from every page, so the same entry repeats. One
// teams.call_queue_diagnostic record is emitted per distinct (Level, Message) in a
// poll, with the number of entries that carried the pair. It is not a twin and has
// no hash.
//
// # Wire fields not exported
//
//   - TenantId: the emitter stamps tenant_id.
//   - Users (repeats Agents) and Agents[].OptIn beyond the opt-in count.
//   - ETag, DistributionListsLastExpanded, Statistics (deprecated text) and
//     StatusRecords: volatile or empty, and not configuration.
//   - Every *FileDownloadUri and audio file prompt body (*AudioFilePrompt): a fetch
//     handle for a file whose resource id and name are exported where the wire has
//     them. Whether the URLs are signed is unmeasured.
//   - OboResourceAccounts (repeats OboResourceAccountIds), ShiftsSchedulingGroupId,
//     the Callback* settings other than IsCallbackEnabled and
//     ServiceLevelThresholdResponseTimeInSecond, compliance recording
//     announcements, thread and history ids other than ThreadId, the
//     AutoRecording* and SharePoint fields, HideAuthorizedUsers and the
//     Enable*SharedVoicemail* flags: null on the lab and unmeasured.
package callqueues

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/rknightion/graph2otel/internal/collector"
	"github.com/rknightion/graph2otel/internal/collectors"
	"github.com/rknightion/graph2otel/internal/recordoutcome"
	"github.com/rknightion/graph2otel/internal/semconv"
	"github.com/rknightion/graph2otel/internal/teams/adminmap"
	"github.com/rknightion/graph2otel/internal/teamsadminclient"
	"github.com/rknightion/graph2otel/internal/telemetry"
	"github.com/rknightion/graph2otel/internal/wirecheck"
)

const (
	// collectorName is the stable key for config, self-observability and the
	// admin status page.
	collectorName = "teams.call_queues"
	// eventName is the OTLP LogRecord EventName of the queue twin.
	eventName = "teams.call_queue"
	// eventDiagnostic is the EventName of a deduplicated diagnostic record.
	eventDiagnostic = "teams.call_queue_diagnostic"
	// metricCount is the queue count gauge, by routing method.
	metricCount = "teams.call_queue.count"
	// unitCount is the annotation unit for the queue count.
	unitCount = "{call_queue}"
	// interval: call queue configuration changes when an admin edits it.
	interval = time.Hour
	// unknown is the routing_method label for a missing or unmapped value.
	unknown = "unknown"
)

// Enum tables: MicrosoftTeams 8.1.0 Microsoft.Rtc.Management.Hosted.HuntGroup.Models.
var (
	routingMethods  = map[int]string{0: "Attendant", 1: "Serial", 2: "RoundRobin", 3: "LongestIdle"}
	overflowActions = map[int]string{0: "DisconnectWithBusy", 1: "Forward", 2: "Voicemail", 3: "SharedVoicemail"}
	timeoutActions  = map[int]string{0: "Disconnect", 1: "Forward", 2: "Voicemail", 3: "SharedVoicemail"}
	noAgentActions  = map[int]string{0: "Queue", 1: "Disconnect", 2: "Forward", 3: "Voicemail", 4: "SharedVoicemail"}
	noAgentApplyTos = map[int]string{0: "NewCalls", 1: "AllCalls"}
)

// enumFields are the five integer enumerations: wire field, key, table.
var enumFields = []struct {
	field, key, rawKey string
	table              map[int]string
}{
	{"RoutingMethod", semconv.AttrCallQueueRoutingMethod, semconv.AttrCallQueueRoutingMethodRaw, routingMethods},
	{"OverflowAction", semconv.AttrCallQueueOverflowAction, semconv.AttrCallQueueOverflowActionRaw, overflowActions},
	{"TimeoutAction", semconv.AttrCallQueueTimeoutAction, semconv.AttrCallQueueTimeoutActionRaw, timeoutActions},
	{"NoAgentAction", semconv.AttrCallQueueNoAgentAction, semconv.AttrCallQueueNoAgentActionRaw, noAgentActions},
	{"NoAgentApplyTo", semconv.AttrCallQueueNoAgentApplyTo, semconv.AttrCallQueueNoAgentApplyToRaw, noAgentApplyTos},
}

var stringFields = []struct{ field, key string }{
	{"Name", semconv.AttrCallQueueName},
	{"LanguageId", semconv.AttrCallQueueLanguageId},
	{"Description", semconv.AttrCallQueueDescription},
	{"ShiftsTeamId", semconv.AttrCallQueueShiftsTeamId},
	{"ThreadId", semconv.AttrCallQueueThreadId},
	{"WelcomeMusicResourceId", semconv.AttrCallQueueWelcomeMusicResourceId},
	{"WelcomeMusicFileName", semconv.AttrCallQueueWelcomeMusicFileName},
	{"WelcomeTextToSpeechPrompt", semconv.AttrCallQueueWelcomeTextToSpeechPrompt},
	{"MusicOnHoldResourceId", semconv.AttrCallQueueMusicOnHoldResourceId},
	{"MusicOnHoldFileName", semconv.AttrCallQueueMusicOnHoldFileName},
}

var boolFields = []struct{ field, key string }{
	{"EnableWrapTime", semconv.AttrCallQueueEnableWrapTime},
	{"AllowOptOut", semconv.AttrCallQueueAllowOptOut},
	{"ConferenceMode", semconv.AttrCallQueueConferenceMode},
	{"PresenceAwareRouting", semconv.AttrCallQueuePresenceAwareRouting},
	{"AgentsCapped", semconv.AttrCallQueueAgentsCapped},
	{"AgentsInSyncWithDistributionLists", semconv.AttrCallQueueAgentsInSyncWithDistributionLists},
	{"UseDefaultMusicOnHold", semconv.AttrCallQueueUseDefaultMusicOnHold},
	{"IsCallbackEnabled", semconv.AttrCallQueueIsCallbackEnabled},
}

// numFields: a field holding seconds without a unit in its name has _seconds
// appended to its key (the #712 naming rule).
var numFields = []struct{ field, key string }{
	{"AgentAlertTime", semconv.AttrCallQueueAgentAlertTimeSeconds},
	{"WrapTimeDuration", semconv.AttrCallQueueWrapTimeDurationSeconds},
	{"OverflowThreshold", semconv.AttrCallQueueOverflowThreshold},
	{"TimeoutThreshold", semconv.AttrCallQueueTimeoutThresholdSeconds},
	{"ServiceLevelThresholdResponseTimeInSecond", semconv.AttrCallQueueServiceLevelThresholdResponseTimeInSecond},
}

var listFields = []struct{ field, key string }{
	{"ApplicationInstances", semconv.AttrCallQueueApplicationInstances},
	{"OboResourceAccountIds", semconv.AttrCallQueueOboResourceAccountIds},
	{"DistributionLists", semconv.AttrCallQueueDistributionLists},
	{"AuthorizedUsers", semconv.AttrCallQueueAuthorizedUsers},
	{"ComplianceRecordingForCallQueueIds", semconv.AttrCallQueueComplianceRecordingForCallQueueIds},
}

// families are the three action families: wire prefix and the keys they feed.
var families = []struct {
	prefix                               string
	targetID, targetType, texts, fileNms string
}{
	{"Overflow", semconv.AttrCallQueueOverflowActionTargetId, semconv.AttrCallQueueOverflowActionTargetType,
		semconv.AttrCallQueueOverflowPromptTexts, semconv.AttrCallQueueOverflowPromptFileNames},
	{"Timeout", semconv.AttrCallQueueTimeoutActionTargetId, semconv.AttrCallQueueTimeoutActionTargetType,
		semconv.AttrCallQueueTimeoutPromptTexts, semconv.AttrCallQueueTimeoutPromptFileNames},
	{"NoAgent", semconv.AttrCallQueueNoAgentActionTargetId, semconv.AttrCallQueueNoAgentActionTargetType,
		semconv.AttrCallQueueNoAgentPromptTexts, semconv.AttrCallQueueNoAgentPromptFileNames},
}

const (
	suffixTTS      = "TextToSpeechPrompt"
	suffixFileName = "AudioFilePromptFileName"
)

// Collector reads call queue configuration.
type Collector struct {
	client collectors.TeamsAdminClient
	watch  *wirecheck.Reporter
}

// New builds the collector. A zero Deps (the census) leaves the client nil;
// Collect then errors.
func New(d collectors.Deps) *Collector {
	return &Collector{client: d.TeamsAdmin, watch: wirecheck.New(collectorName, d.Logger)}
}

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

// Collect reads every call queue and emits the gauge, one twin per queue and one
// record per distinct diagnostic.
func (c *Collector) Collect(ctx context.Context, e telemetry.Emitter, outcomes *recordoutcome.Recorder) error {
	if c.client == nil {
		return errors.New(collectorName + ": no Teams admin API client (teams.admin_api.enabled is not set)")
	}
	e = telemetry.WithTransport(e, telemetry.TransportTeamsAdmin)

	res, err := c.client.VoiceApps(ctx, teamsadminclient.CallQueues)
	if err != nil {
		if teamsadminclient.IsPermission(err) {
			outcomes.Cause(recordoutcome.CausePermissionDenied)
		} else {
			outcomes.Cause(recordoutcome.CauseSourceError)
		}
		return fmt.Errorf("%s: read call queues: %w", collectorName, err)
	}
	outcomes.Add(recordoutcome.OutcomeFetched, uint64(len(res.Records)))

	byMethod := map[string]int{}
	for _, r := range res.Records {
		ev, method := c.twin(e, r)
		byMethod[method]++
		e.LogEvent(ev)
		outcomes.Add(recordoutcome.OutcomeMapped, 1)
		outcomes.Add(recordoutcome.OutcomeEmitted, 1)
	}

	methods := make([]string, 0, len(byMethod))
	for m := range byMethod {
		methods = append(methods, m)
	}
	sort.Strings(methods)
	pts := make([]telemetry.GaugePoint, 0, len(methods))
	for _, m := range methods {
		pts = append(pts, telemetry.GaugePoint{Value: float64(byMethod[m]), Attrs: telemetry.Attrs{semconv.AttrRoutingMethod: m}})
	}
	e.GaugeSnapshot(metricCount, unitCount,
		"Teams call queues by routing method. A queue whose routing method is missing or not a known integer counts under unknown, so the total equals the number of queues.", pts)

	for _, ev := range diagnostics(res.Diagnostics) {
		e.LogEvent(ev)
	}
	return nil
}

// diagnostics returns one record per distinct (Level, Message), in first-seen
// order, with the number of entries that carried the pair.
func diagnostics(in []teamsadminclient.Diagnostic) []telemetry.Event {
	type key struct{ level, message string }
	counts := map[key]int{}
	var order []key
	for _, d := range in {
		k := key{d.Level, d.Message}
		if counts[k] == 0 {
			order = append(order, k)
		}
		counts[k]++
	}
	out := make([]telemetry.Event, 0, len(order))
	for _, k := range order {
		sev := telemetry.SeverityInfo
		if strings.EqualFold(k.level, "warning") {
			sev = telemetry.SeverityWarn
		}
		attrs := telemetry.Attrs{semconv.AttrCallQueueDiagnosticCount: counts[k]}
		telemetry.SetStr(attrs, semconv.AttrCallQueueDiagnosticLevel, k.level)
		telemetry.SetStr(attrs, semconv.AttrCallQueueDiagnosticMessage, k.message)
		out = append(out, telemetry.Event{Name: eventDiagnostic, Body: k.message, Severity: sev, Attrs: attrs})
	}
	return out
}

// twin maps one call queue to its log record and returns its routing_method
// gauge label.
func (c *Collector) twin(e telemetry.Emitter, r map[string]any) (telemetry.Event, string) {
	attrs := telemetry.Attrs{}
	telemetry.SetStr(attrs, semconv.AttrCallQueueId, str(r, "Identity"))
	for _, f := range stringFields {
		telemetry.SetStr(attrs, f.key, str(r, f.field))
	}
	for _, f := range boolFields {
		if b, ok := r[f.field].(bool); ok {
			telemetry.SetBool(attrs, f.key, b)
		}
	}
	for _, f := range numFields {
		if n, ok := r[f.field].(float64); ok {
			attrs[f.key] = number(n)
		}
	}
	for _, f := range listFields {
		adminmap.SetIDs(attrs, f.key, strList(r, f.field))
	}

	method := unknown
	for i, f := range enumFields {
		name, raw, ok := adminmap.MapEnum(c.watch, e, f.field, r[f.field], f.table)
		attrs[f.key] = name
		// Every table has a 0 entry, so a non-zero raw with !ok is an unknown
		// integer; a missing or non-integer value comes back as 0 with !ok.
		if ok || raw != 0 {
			attrs[f.rawKey] = raw
		}
		if i == 0 {
			method = name
		}
	}

	if agents, ok := r["Agents"].([]any); ok {
		ids, optIn := make([]string, 0, len(agents)), 0
		for _, a := range agents {
			m, _ := a.(map[string]any)
			if id := str(m, "ObjectId"); id != "" {
				ids = append(ids, id)
			}
			if b, _ := m["OptIn"].(bool); b {
				optIn++
			}
		}
		adminmap.SetIDs(attrs, semconv.AttrCallQueueAgentIds, ids)
		attrs[semconv.AttrCallQueueAgentOptInCount] = optIn
	}

	for _, f := range families {
		c.family(e, attrs, r, f.prefix, f.targetID, f.targetType, f.texts, f.fileNms)
	}

	attrs[semconv.AttrConfigSHA256] = adminmap.Hash(attrs)
	attrs[semconv.AttrConfigHashVersion] = adminmap.HashVersion

	return telemetry.Event{
		Name:     eventName,
		Body:     "call queue " + str(r, "Name"),
		Severity: telemetry.SeverityInfo,
		Attrs:    attrs,
	}, method
}

// family exports one action family's target and prompt lists. The prompt lists
// hold every non-null field of the family with the matching suffix, in field-name
// order.
func (c *Collector) family(e telemetry.Emitter, attrs telemetry.Attrs, r map[string]any, prefix, targetIDKey, targetTypeKey, textsKey, filesKey string) {
	if raw, present := r[prefix+"ActionTarget"]; present && raw != nil {
		target, isObj := raw.(map[string]any)
		id := str(target, "Id")
		if !isObj || id == "" {
			c.watch.MissingField(e, prefix+"ActionTarget.Id")
		} else {
			telemetry.SetStr(attrs, targetIDKey, id)
			telemetry.SetStr(attrs, targetTypeKey, str(target, "Type"))
		}
	}
	names := make([]string, 0, len(r))
	for k := range r {
		if strings.HasPrefix(k, prefix) {
			names = append(names, k)
		}
	}
	sort.Strings(names)
	texts, files := []string{}, []string{}
	for _, k := range names {
		switch {
		case strings.HasSuffix(k, suffixTTS):
			if s := str(r, k); s != "" {
				texts = append(texts, s)
			}
		case strings.HasSuffix(k, suffixFileName):
			if s := str(r, k); s != "" {
				files = append(files, s)
			}
		}
	}
	adminmap.SetIDs(attrs, textsKey, texts)
	adminmap.SetIDs(attrs, filesKey, files)
}

// number returns an int for a whole JSON number and the float otherwise.
func number(f float64) any {
	if f == float64(int64(f)) {
		return int(f)
	}
	return f
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
