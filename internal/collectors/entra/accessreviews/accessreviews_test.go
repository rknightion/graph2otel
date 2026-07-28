package accessreviews

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/rknightion/graph2otel/internal/collectors"
	"github.com/rknightion/graph2otel/internal/recordoutcome"
	"github.com/rknightion/graph2otel/internal/semconv"
	"github.com/rknightion/graph2otel/internal/telemetry"
	"github.com/rknightion/graph2otel/internal/telemetrytest"
	"github.com/rknightion/graph2otel/internal/wirecheck"
)

type fakeGraph struct {
	bodies map[string]string
	errs   map[string]error
	// calls records every URL requested, in order, INCLUDING duplicates. Only
	// the fan-out-cap tests read it (to prove a cap actually bounded the
	// number of child requests fired, not merely the number of twins kept).
	calls []string
}

func (f *fakeGraph) RawGet(ctx context.Context, url string) ([]byte, error) {
	return f.RawGetWithHeaders(ctx, url, nil)
}

// RawGetWithHeaders serves a stubbed body/error for the exact URL, or — for
// any `/instances`-shaped child fetch nobody explicitly stubbed (the
// instances-list URL itself, or a `.../instances/{id}/decisions` URL) —
// degrades to an empty page. This lets every test written before #319 (which
// stubs only the definitions list) keep passing without also having to stub
// an instances fetch per definition: the fan-out this collector now performs
// is opt-in-to-test, not something every unrelated test must model. A test
// that DOES care about instances/decisions behavior stubs those URLs (or
// their errors) explicitly, which always takes priority.
func (f *fakeGraph) RawGetWithHeaders(_ context.Context, url string, _ map[string]string) ([]byte, error) {
	f.calls = append(f.calls, url)
	if err, ok := f.errs[url]; ok {
		return nil, err
	}
	if body, ok := f.bodies[url]; ok {
		return []byte(body), nil
	}
	if strings.Contains(url, "/instances") {
		return []byte(`{"value":[]}`), nil
	}
	return nil, fmt.Errorf("fakeGraph: no body stubbed for %s", url)
}

var _ collectors.GraphClient = (*fakeGraph)(nil)

const listURL = defaultBaseURL + definitionsPath

// liveDefinitions is VERBATIM from the m7kni tenant's v1.0 endpoint
// `[live-measured 2026-07-24, #260]` — the single access review that exists
// there, unedited. Every trap this collector handles is visible in it:
//
//   - createdBy.displayName and createdBy.userPrincipalName are EMPTY STRINGS
//     while createdBy.id is set, and createdBy.type is null;
//   - scope is polymorphic, discriminated by @odata.type;
//   - settings.applyActions is a second polymorphic member;
//   - instances arrives as an expanded nav property with its own
//     @odata.context and is EMPTY for a review whose status is InProgress;
//   - range.endDate is the sentinel "9999-12-31", not a real deadline.
//
// The BETA endpoint additionally returns backupReviewers, customData and
// customDataProvider. This collector reads v1.0, and those keys are absent
// here — which is why nothing maps them.
const liveDefinitions = `{
  "@odata.context": "https://graph.microsoft.com/v1.0/$metadata#identityGovernance/accessReviews/definitions",
  "@odata.count": 1,
  "value": [
    {
      "id": "fef06240-0798-4e51-aa95-ac4fb55404ce",
      "displayName": "Quarterly Global Administrator review",
      "createdDateTime": "2026-07-19T18:14:10.2862528Z",
      "lastModifiedDateTime": "2026-07-19T18:19:48.2990832Z",
      "status": "InProgress",
      "descriptionForAdmins": "Review all Global Administrator role holders",
      "descriptionForReviewers": "",
      "instanceEnumerationScope": null,
      "createdBy": {
        "id": "8f35f4e9-5c91-42db-a1f7-d77ada4cc0a2",
        "displayName": "",
        "type": null,
        "userPrincipalName": ""
      },
      "scope": {
        "@odata.type": "#microsoft.graph.principalResourceMembershipsScope",
        "principalScopes": [
          {
            "@odata.type": "#microsoft.graph.accessReviewQueryScope",
            "query": "/v1.0/users",
            "queryType": "MicrosoftGraph",
            "queryRoot": null
          }
        ],
        "resourceScopes": [
          {
            "@odata.type": "#microsoft.graph.accessReviewQueryScope",
            "query": "/beta/roleManagement/directory/roleDefinitions/62e90394-69f5-4237-9190-012177145e10",
            "queryType": "MicrosoftGraph",
            "queryRoot": null
          }
        ]
      },
      "reviewers": [
        {
          "query": "/v1.0/users/bbcfc3c5-0b93-4135-9ef9-18477a9fb504",
          "queryType": "MicrosoftGraph",
          "queryRoot": null
        }
      ],
      "fallbackReviewers": [],
      "settings": {
        "mailNotificationsEnabled": true,
        "reminderNotificationsEnabled": true,
        "justificationRequiredOnApproval": true,
        "defaultDecisionEnabled": false,
        "defaultDecision": "None",
        "instanceDurationInDays": 14,
        "autoApplyDecisionsEnabled": false,
        "recommendationsEnabled": true,
        "recommendationLookBackDuration": null,
        "decisionHistoriesForReviewersEnabled": false,
        "recurrence": {
          "pattern": {
            "type": "absoluteMonthly",
            "interval": 3,
            "month": 0,
            "dayOfMonth": 0,
            "daysOfWeek": [],
            "firstDayOfWeek": "sunday",
            "index": "first"
          },
          "range": {
            "type": "noEnd",
            "numberOfOccurrences": 0,
            "recurrenceTimeZone": null,
            "startDate": "2026-07-20",
            "endDate": "9999-12-31"
          }
        },
        "applyActions": [
          {
            "@odata.type": "#microsoft.graph.removeAccessApplyAction"
          }
        ],
        "recommendationInsightSettings": [
          {
            "@odata.type": "#microsoft.graph.userLastSignInRecommendationInsightSetting",
            "recommendationLookBackDuration": "P30D",
            "signInScope": "tenant"
          }
        ]
      },
      "stageSettings": [],
      "additionalNotificationRecipients": [],
      "instances@odata.context": "https://graph.microsoft.com/v1.0/$metadata#identityGovernance/accessReviews/definitions('fef06240-0798-4e51-aa95-ac4fb55404ce')/instances",
      "instances": []
    }
  ]
}`

func graphWith(body string) *fakeGraph {
	return &fakeGraph{bodies: map[string]string{listURL: body}}
}

func collect(t *testing.T, body string) *telemetrytest.Recorder {
	t.Helper()
	rec := telemetrytest.New()
	if err := New(graphWith(body), nil).Collect(context.Background(), rec.Emitter(), nil); err != nil {
		t.Fatalf("Collect: %v", err)
	}
	return rec
}

func twin(t *testing.T, rec *telemetrytest.Recorder, id string) telemetrytest.LogRecord {
	t.Helper()
	for _, r := range rec.LogRecords() {
		if r.EventName == eventReview && r.Attrs[semconv.AttrId] == id {
			return r
		}
	}
	t.Fatalf("no %s twin for id %q; got %+v", eventReview, id, rec.LogRecords())
	return telemetrytest.LogRecord{}
}

const liveID = "fef06240-0798-4e51-aa95-ac4fb55404ce"

// TestLiveSampleTwinCarriesTheDefinition maps the verbatim capture and pins
// every attribute the twin is supposed to carry.
func TestLiveSampleTwinCarriesTheDefinition(t *testing.T) {
	got := twin(t, collect(t, liveDefinitions), liveID).Attrs

	want := map[string]string{
		semconv.AttrDisplayName:                          "Quarterly Global Administrator review",
		semconv.AttrStatus:                               "InProgress",
		semconv.AttrCreatedDateTime:                      "2026-07-19T18:14:10.2862528Z",
		semconv.AttrLastModifiedDateTime:                 "2026-07-19T18:19:48.2990832Z",
		semconv.AttrDescriptionForAdmins:                 "Review all Global Administrator role holders",
		semconv.AttrCreatedById:                          "8f35f4e9-5c91-42db-a1f7-d77ada4cc0a2",
		semconv.AttrScopeODataType:                       "principalResourceMembershipsScope",
		semconv.AttrScopePrincipalQueries:                "/v1.0/users",
		semconv.AttrScopeResourceQueries:                 "/beta/roleManagement/directory/roleDefinitions/62e90394-69f5-4237-9190-012177145e10",
		semconv.AttrReviewerQueries:                      "/v1.0/users/bbcfc3c5-0b93-4135-9ef9-18477a9fb504",
		semconv.AttrReviewerCount:                        "1",
		semconv.AttrFallbackReviewerCount:                "0",
		semconv.AttrAdditionalNotificationRecipientCount: "0",
		semconv.AttrStageCount:                           "0",
		semconv.AttrRecurrencePatternType:                "absoluteMonthly",
		semconv.AttrRecurrenceInterval:                   "3",
		semconv.AttrRecurrenceRangeType:                  "noEnd",
		semconv.AttrRecurrenceStartDate:                  "2026-07-20",
		semconv.AttrInstanceDurationDays:                 "14",
		semconv.AttrMailNotificationsEnabled:             "true",
		semconv.AttrReminderNotificationsEnabled:         "true",
		semconv.AttrAutoApplyDecisionsEnabled:            "false",
		semconv.AttrDefaultDecisionEnabled:               "false",
		semconv.AttrDefaultDecision:                      "None",
		semconv.AttrJustificationRequiredOnApproval:      "true",
		semconv.AttrRecommendationsEnabled:               "true",
		semconv.AttrApplyActionTypes:                     "removeAccessApplyAction",
	}
	for k, v := range want {
		if got[k] != v {
			t.Errorf("attr %q = %q, want %q", k, got[k], v)
		}
	}
}

// TestEmptyIdentityFieldsAreOmittedNotBlank is the headline trap (#260): Graph
// returns createdBy with an id but with displayName and userPrincipalName as
// EMPTY STRINGS and type null. Stamping those would put blank identity fields
// on the twin that read as "this review has no creator" rather than "Graph did
// not resolve one".
func TestEmptyIdentityFieldsAreOmittedNotBlank(t *testing.T) {
	got := twin(t, collect(t, liveDefinitions), liveID).Attrs

	for _, key := range []string{
		semconv.AttrCreatedBy,
		semconv.AttrCreatedByUserPrincipalName,
		semconv.AttrCreatedByType,
		semconv.AttrDescriptionForReviewers,
	} {
		if v, ok := got[key]; ok {
			t.Errorf("attr %q was emitted as %q — an empty wire value must be omitted, not stamped blank", key, v)
		}
	}
	if got[semconv.AttrCreatedById] == "" {
		t.Error("created_by_id must survive: it is the one populated part of createdBy")
	}
}

// TestResolvedIdentityIsEmitted is the other half of the omission rule: when
// Graph DOES populate these fields, they must be carried.
func TestResolvedIdentityIsEmitted(t *testing.T) {
	body := strings.Replace(liveDefinitions,
		`"displayName": "",
        "type": null,
        "userPrincipalName": ""`,
		`"displayName": "Rob Knight",
        "type": "user",
        "userPrincipalName": "rob@m7kni.io"`, 1)
	body = strings.Replace(body,
		`"descriptionForReviewers": "",`,
		`"descriptionForReviewers": "Confirm each admin still needs the role",`, 1)

	got := twin(t, collect(t, body), liveID).Attrs
	if got[semconv.AttrDescriptionForReviewers] != "Confirm each admin still needs the role" {
		t.Errorf("description_for_reviewers = %q", got[semconv.AttrDescriptionForReviewers])
	}
	if got[semconv.AttrCreatedBy] != "Rob Knight" {
		t.Errorf("created_by = %q, want Rob Knight", got[semconv.AttrCreatedBy])
	}
	if got[semconv.AttrCreatedByUserPrincipalName] != "rob@m7kni.io" {
		t.Errorf("created_by_user_principal_name = %q", got[semconv.AttrCreatedByUserPrincipalName])
	}
	if got[semconv.AttrCreatedByType] != "user" {
		t.Errorf("created_by_type = %q", got[semconv.AttrCreatedByType])
	}
}

// TestBoundedGaugeCountsByStatusOnly pins the metric's whole label set. Anything
// per-review on it would be #112; signalgate_test.go enforces that too, but this
// states the intent locally.
func TestBoundedGaugeCountsByStatusOnly(t *testing.T) {
	rec := collect(t, liveDefinitions)

	pts := rec.MetricPoints(metricReviews)
	if len(pts) != 1 {
		t.Fatalf("gauge points = %d, want 1: %+v", len(pts), pts)
	}
	if pts[0].Value != 1 {
		t.Errorf("value = %v, want 1", pts[0].Value)
	}
	if len(pts[0].Attrs) != 1 || pts[0].Attrs[semconv.AttrStatus] != "InProgress" {
		t.Errorf("label set = %v, want exactly {status: InProgress}", pts[0].Attrs)
	}
}

// TestGaugeAggregatesAcrossReviews — two reviews sharing a status are one
// series with a count of two, which is the bounded-aggregate half of #112.
func TestGaugeAggregatesAcrossReviews(t *testing.T) {
	body := `{"value":[
      {"id":"a","status":"InProgress","scope":{"@odata.type":"#microsoft.graph.accessReviewQueryScope","query":"/v1.0/groups"}},
      {"id":"b","status":"InProgress","scope":{"@odata.type":"#microsoft.graph.accessReviewQueryScope","query":"/v1.0/groups"}},
      {"id":"c","status":"Completed","scope":{"@odata.type":"#microsoft.graph.accessReviewQueryScope","query":"/v1.0/groups"}}
    ]}`
	rec := collect(t, body)

	got := map[string]float64{}
	for _, p := range rec.MetricPoints(metricReviews) {
		got[p.Attrs[semconv.AttrStatus]] = p.Value
	}
	if got["InProgress"] != 2 || got["Completed"] != 1 {
		t.Errorf("counts = %v, want InProgress=2 Completed=1", got)
	}
	if n := len(rec.LogRecords()); n != 3 {
		t.Errorf("twins = %d, want 3 — every definition gets one (#114)", n)
	}
}

// TestPolymorphicQueryScopeIsReadByDiscriminator: a top-level
// accessReviewQueryScope carries a single `query` and no principal/resource
// arrays. The collector must switch on @odata.type, not probe for whichever
// field happens to be present.
func TestPolymorphicQueryScopeIsReadByDiscriminator(t *testing.T) {
	body := `{"value":[{"id":"a","status":"NotStarted","scope":{
      "@odata.type":"#microsoft.graph.accessReviewQueryScope",
      "query":"/v1.0/groups/11111111-1111-1111-1111-111111111111/transitiveMembers",
      "queryType":"MicrosoftGraph"}}]}`

	got := twin(t, collect(t, body), "a").Attrs
	if got[semconv.AttrScopeODataType] != "accessReviewQueryScope" {
		t.Errorf("scope_type = %q", got[semconv.AttrScopeODataType])
	}
	if got[semconv.AttrScopeQuery] != "/v1.0/groups/11111111-1111-1111-1111-111111111111/transitiveMembers" {
		t.Errorf("scope_query = %q", got[semconv.AttrScopeQuery])
	}
	for _, k := range []string{semconv.AttrScopePrincipalQueries, semconv.AttrScopeResourceQueries} {
		if v, ok := got[k]; ok {
			t.Errorf("attr %q = %q — a query scope has no principal/resource arrays", k, v)
		}
	}
}

// TestUnknownScopeTypeIsAnnouncedAndTheRecordSurvives: an unmapped scope shape
// must fire the wirecheck counter (a hole in THIS collector's mapping) and must
// NOT drop the review — a cosmetic surprise may not become a missing row.
func TestUnknownScopeTypeIsAnnouncedAndTheRecordSurvives(t *testing.T) {
	body := `{"value":[{"id":"a","status":"InProgress","scope":{
      "@odata.type":"#microsoft.graph.accessReviewInactiveUsersQueryScope","query":"/v1.0/users"}}]}`
	rec := collect(t, body)

	got := twin(t, rec, "a").Attrs
	if got[semconv.AttrScopeODataType] != "accessReviewInactiveUsersQueryScope" {
		t.Errorf("scope_type = %q — the discriminator is carried even when unmapped", got[semconv.AttrScopeODataType])
	}

	var found int
	for _, p := range rec.MetricPoints(wirecheck.MetricUnexpected) {
		if p.Attrs[semconv.AttrField] == semconv.AttrScopeODataType &&
			p.Attrs[semconv.AttrKind] == wirecheck.KindUnmappedValue {
			found++
		}
	}
	if found != 1 {
		t.Errorf("unmapped_value findings on scope_type = %d, want 1: %+v", found, rec.MetricPoints(wirecheck.MetricUnexpected))
	}
	if pts := rec.MetricPoints(metricReviews); len(pts) != 1 || pts[0].Value != 1 {
		t.Errorf("the review must still be counted; got %+v", pts)
	}
}

// TestStatusIsDeliberatelyUnwatched is the #234 evidence rule made executable.
// Exactly ONE status value ("InProgress") has ever been observed on the wire, and
// one observed value is not a value set — a wirecheck.Enum declared from
// Microsoft's documentation would fire on correct data, which is worse than no
// watchdog at all. A novel status must therefore pass silently.
func TestStatusIsDeliberatelyUnwatched(t *testing.T) {
	body := `{"value":[{"id":"a","status":"SomeStatusNobodyHasSeen","scope":{"@odata.type":"#microsoft.graph.accessReviewQueryScope","query":"/v1.0/users"}}]}`
	rec := collect(t, body)

	for _, p := range rec.MetricPoints(wirecheck.MetricUnexpected) {
		if p.Attrs[semconv.AttrField] == semconv.AttrStatus {
			t.Errorf("status must stay unwatched until a second value is observed (#234); got finding %v", p.Attrs)
		}
	}
	if got := twin(t, rec, "a").Attrs[semconv.AttrStatus]; got != "SomeStatusNobodyHasSeen" {
		t.Errorf("status = %q — an unknown status is passed through verbatim, never bucketed", got)
	}
}

// TestInstancesAreNeverReportedAsACount pins the instances decision. The inline
// `instances` array is EMPTY on both v1.0 and beta for a review whose status is
// InProgress (live-measured 2026-07-24), so its length says nothing about the
// review. Emitting instance_count: 0 would publish a fabricated fact.
func TestInstancesAreNeverReportedAsACount(t *testing.T) {
	rec := collect(t, liveDefinitions)
	for k, v := range twin(t, rec, liveID).Attrs {
		if strings.Contains(k, "instance") && k != semconv.AttrInstanceDurationDays {
			t.Errorf("attr %q = %q — instances are out of scope; see the package doc", k, v)
		}
	}
	for _, p := range rec.MetricPoints(metricReviews) {
		for k := range p.Attrs {
			if strings.Contains(k, "instance") {
				t.Errorf("metric label %q — instances are out of scope", k)
			}
		}
	}
}

// TestNotificationsAndRemindersBothDisabledWarns is the collector's only WARN
// rung: a review whose reviewers are never mailed and never reminded is a
// control that depends on someone remembering. It is definition-visible, so it
// needs no instance data.
func TestNotificationsAndRemindersBothDisabledWarns(t *testing.T) {
	body := strings.Replace(liveDefinitions,
		`"mailNotificationsEnabled": true,
        "reminderNotificationsEnabled": true,`,
		`"mailNotificationsEnabled": false,
        "reminderNotificationsEnabled": false,`, 1)

	rec := collect(t, body)
	got := twin(t, rec, liveID)
	if got.SeverityText != "WARN" {
		t.Errorf("severity = %q, want WARN when neither notifications nor reminders are enabled", got.SeverityText)
	}
	if !strings.Contains(got.Body, "notifications") {
		t.Errorf("body = %q, want it to name the reason", got.Body)
	}
	if twin(t, collect(t, liveDefinitions), liveID).SeverityText != "INFO" {
		t.Error("the live review notifies and reminds; it must stay INFO")
	}
}

// TestOnlyOneNotificationChannelDisabledStaysInfo keeps the WARN honest — a
// reminder-less review that still mails its reviewers is not the failure shape.
func TestOnlyOneNotificationChannelDisabledStaysInfo(t *testing.T) {
	body := strings.Replace(liveDefinitions,
		`"reminderNotificationsEnabled": true,`,
		`"reminderNotificationsEnabled": false,`, 1)
	if got := twin(t, collect(t, body), liveID).SeverityText; got != "INFO" {
		t.Errorf("severity = %q, want INFO", got)
	}
}

// TestAbsentSettingsOmitsTheFamilyAndIsAnnounced: with no settings block the
// eight governance attributes must be absent rather than a row of fabricated
// falses (which would also silently satisfy the WARN condition forever), and the
// absence must announce itself.
func TestAbsentSettingsOmitsTheFamilyAndIsAnnounced(t *testing.T) {
	body := `{"value":[{"id":"a","status":"InProgress","scope":{"@odata.type":"#microsoft.graph.accessReviewQueryScope","query":"/v1.0/users"}}]}`
	rec := collect(t, body)

	got := twin(t, rec, "a")
	for _, k := range []string{
		semconv.AttrMailNotificationsEnabled, semconv.AttrReminderNotificationsEnabled,
		semconv.AttrAutoApplyDecisionsEnabled, semconv.AttrDefaultDecisionEnabled,
		semconv.AttrJustificationRequiredOnApproval, semconv.AttrRecommendationsEnabled,
		semconv.AttrInstanceDurationDays, semconv.AttrRecurrencePatternType,
	} {
		if v, ok := got.Attrs[k]; ok {
			t.Errorf("attr %q = %q — an absent settings block must omit the family, not fabricate it", k, v)
		}
	}
	if got.SeverityText != "INFO" {
		t.Errorf("severity = %q, want INFO — a missing settings block is not evidence of a broken control", got.SeverityText)
	}

	var found bool
	for _, p := range rec.MetricPoints(wirecheck.MetricUnexpected) {
		if p.Attrs[semconv.AttrKind] == wirecheck.KindMissingField && p.Attrs[semconv.AttrField] == fieldSettings {
			found = true
		}
	}
	if !found {
		t.Error("an absent settings block must announce itself through wirecheck — otherwise the WARN rung silently stops working")
	}
}

// TestForbiddenIsAGracefulSkip — a tenant without the governance feature (or
// without the scope) 403s; that is a skip, not a collection failure.
func TestForbiddenIsAGracefulSkip(t *testing.T) {
	g := &fakeGraph{errs: map[string]error{listURL: errors.New("graph: GET failed with status 403")}}
	rec := telemetrytest.New()
	outcomes := recordoutcome.NewRecorder()
	if err := New(g, nil).Collect(context.Background(), rec.Emitter(), outcomes); err != nil {
		t.Fatalf("Collect = %v, want nil for a 403", err)
	}
	if n := len(rec.LogRecords()); n != 0 {
		t.Errorf("emitted %d records on a 403, want 0", n)
	}
	got := outcomes.Snapshot()
	summary := got.Summarize(nil, false)
	if summary.Result != recordoutcome.ResultFailure || summary.Cause != recordoutcome.CausePermissionDenied {
		t.Errorf("summary = %+v, want failure/%s", summary, recordoutcome.CausePermissionDenied)
	}
}

// TestOtherErrorsFail — everything that is not a 403 must surface.
func TestOtherErrorsFail(t *testing.T) {
	g := &fakeGraph{errs: map[string]error{listURL: errors.New("graph: GET failed with status 500")}}
	outcomes := recordoutcome.NewRecorder()
	if err := New(g, nil).Collect(context.Background(), telemetrytest.New().Emitter(), outcomes); err == nil {
		t.Fatal("Collect = nil, want an error for a 500")
	}
	got := outcomes.Snapshot().Summarize(errors.New("fetch failed"), false)
	if got.Result != recordoutcome.ResultFailure || got.Cause != recordoutcome.CauseSourceError {
		t.Fatalf("outcome = %+v, want failure/source_error", got)
	}
}

// TestUnparseableDefinitionIsSkippedNotFatal — one bad row must not take the
// whole poll with it, and the error must still be visible.
func TestUnparseableDefinitionIsSkippedNotFatal(t *testing.T) {
	body := `{"value":[
      "not-an-object",
      {"id":"b","status":"InProgress","scope":{"@odata.type":"#microsoft.graph.accessReviewQueryScope","query":"/v1.0/users"}}
    ]}`
	rec := telemetrytest.New()
	outcomes := recordoutcome.NewRecorder()
	err := New(graphWith(body), nil).Collect(context.Background(), rec.Emitter(), outcomes)
	if err == nil {
		t.Error("Collect = nil, want the decode failure aggregated")
	}
	if n := len(rec.LogRecords()); n != 1 {
		t.Errorf("twins = %d, want the good row still emitted", n)
	}
	snapshot := outcomes.Snapshot()
	want := recordoutcome.Counts{Fetched: 2, Mapped: 1, Emitted: 1, Errored: 1}
	if snapshot.Counts != want {
		t.Fatalf("counts = %+v, want %+v", snapshot.Counts, want)
	}
	if err := snapshot.Validate(); err != nil {
		t.Fatalf("Validate = %v", err)
	}
	summary := snapshot.Summarize(err, false)
	if summary.Result != recordoutcome.ResultPartial || summary.Cause != recordoutcome.CauseDecodeError {
		t.Fatalf("summary = %+v, want partial/decode_error", summary)
	}
}

// TestDefinitionWithoutAnIdIsSkipped — the id is the twin's join key.
func TestDefinitionWithoutAnIdIsSkipped(t *testing.T) {
	rec := collect(t, `{"value":[{"status":"InProgress"}]}`)
	if n := len(rec.LogRecords()); n != 0 {
		t.Errorf("twins = %d, want 0 for a definition with no id", n)
	}
}

// TestEmptyTenantClearsTheSnapshot — a tenant with no reviews must publish an
// empty snapshot so a previously-seen series drops out rather than lingering.
func TestEmptyTenantClearsTheSnapshot(t *testing.T) {
	rec := collect(t, `{"value":[]}`)
	if pts := rec.MetricPoints(metricReviews); len(pts) != 0 {
		t.Errorf("points = %+v, want none", pts)
	}
}

// --- #319: instances + decisions ---------------------------------------

const liveInstanceID = "ca2cd5a6-dadb-4bf9-9de2-49b445bbab71"

func instancesURL(definitionID string) string {
	return defaultBaseURL + definitionsPath + "/" + definitionID + "/instances"
}

func decisionsURL(definitionID, instanceID string) string {
	return defaultBaseURL + definitionsPath + "/" + definitionID + "/instances/" + instanceID + "/decisions"
}

// liveInstances is VERBATIM from the m7kni tenant
// [live-measured 2026-07-28, #319], `GET .../definitions/{id}/instances`.
const liveInstances = `{
  "@odata.context": "https://graph.microsoft.com/v1.0/$metadata#identityGovernance/accessReviews/definitions('fef06240-0798-4e51-aa95-ac4fb55404ce')/instances",
  "@odata.count": 1,
  "value": [
    {
      "id": "ca2cd5a6-dadb-4bf9-9de2-49b445bbab71",
      "startDateTime": "2026-07-19T18:14:10.287Z",
      "endDateTime": "2026-08-02T18:14:10.287Z",
      "status": "InProgress",
      "scope": {
        "@odata.type": "#microsoft.graph.principalResourceMembershipsScope",
        "principalScopes": [
          {"@odata.type": "#microsoft.graph.accessReviewQueryScope", "query": "/v1.0/users", "queryType": "MicrosoftGraph", "queryRoot": null}
        ],
        "resourceScopes": [
          {"@odata.type": "#microsoft.graph.accessReviewQueryScope", "query": "/beta/roleManagement/directory/roleDefinitions/62e90394-69f5-4237-9190-012177145e10", "queryType": "MicrosoftGraph", "queryRoot": null}
        ]
      },
      "reviewers": [
        {"query": "/v1.0/users/bbcfc3c5-0b93-4135-9ef9-18477a9fb504", "queryType": "MicrosoftGraph", "queryRoot": null}
      ],
      "fallbackReviewers": []
    }
  ]
}`

// liveDecisions is VERBATIM from the m7kni tenant
// [live-measured 2026-07-28, #319],
// `GET .../instances/ca2cd5a6.../decisions` — all three decisions on the one
// live instance. Every trap this collector handles is visible here:
//
//   - reviewedBy/appliedBy are FULLY POPULATED objects with the zero-GUID id
//     on every row (none of these three decisions has been reviewed yet);
//   - reviewedDateTime/appliedDateTime are JSON null;
//   - justification is an empty string;
//   - principal.lastUserSignInDateTime is an EMPTY STRING on the first row
//     (never signed in) and a real value on the other two.
const liveDecisions = `{
  "@odata.context": "https://graph.microsoft.com/v1.0/$metadata#identityGovernance/accessReviews/definitions('fef06240-0798-4e51-aa95-ac4fb55404ce')/instances('ca2cd5a6-dadb-4bf9-9de2-49b445bbab71')/decisions",
  "@odata.count": 3,
  "value": [
    {
      "id": "5a07a10a-9ecc-41b4-a58a-0a101ca9007c",
      "accessReviewId": "ca2cd5a6-dadb-4bf9-9de2-49b445bbab71",
      "reviewedDateTime": null,
      "decision": "NotReviewed",
      "justification": "",
      "appliedDateTime": null,
      "applyResult": "New",
      "recommendation": "Deny",
      "principalLink": "https://graph.microsoft.com/v1.0/users/163e6710-5145-4654-9bda-6d849136106b",
      "resourceLink": "https://graph.microsoft.com/beta/roleManagement/directory/roleDefinitions/62e90394-69f5-4237-9190-012177145e10",
      "reviewedBy": {"id": "00000000-0000-0000-0000-000000000000", "displayName": "", "type": "user", "userPrincipalName": ""},
      "appliedBy": {"id": "00000000-0000-0000-0000-000000000000", "displayName": "", "type": null, "userPrincipalName": ""},
      "resource": {"id": "62e90394-69f5-4237-9190-012177145e10", "displayName": "Global Administrator", "type": "directoryRole"},
      "principal": {
        "@odata.type": "#microsoft.graph.userIdentity",
        "id": "163e6710-5145-4654-9bda-6d849136106b",
        "displayName": "Emergency Access 2",
        "type": "user",
        "userPrincipalName": "emergency2@m7knio.onmicrosoft.com",
        "lastUserSignInDateTime": ""
      }
    },
    {
      "id": "3bd34300-8d04-4f3f-905e-303add294605",
      "accessReviewId": "ca2cd5a6-dadb-4bf9-9de2-49b445bbab71",
      "reviewedDateTime": null,
      "decision": "NotReviewed",
      "justification": "",
      "appliedDateTime": null,
      "applyResult": "New",
      "recommendation": "Approve",
      "principalLink": "https://graph.microsoft.com/v1.0/users/c55ddc8b-52ee-44c6-a0bc-b388be43cd2f",
      "resourceLink": "https://graph.microsoft.com/beta/roleManagement/directory/roleDefinitions/62e90394-69f5-4237-9190-012177145e10",
      "reviewedBy": {"id": "00000000-0000-0000-0000-000000000000", "displayName": "", "type": "user", "userPrincipalName": ""},
      "appliedBy": {"id": "00000000-0000-0000-0000-000000000000", "displayName": "", "type": null, "userPrincipalName": ""},
      "resource": {"id": "62e90394-69f5-4237-9190-012177145e10", "displayName": "Global Administrator", "type": "directoryRole"},
      "principal": {
        "@odata.type": "#microsoft.graph.userIdentity",
        "id": "c55ddc8b-52ee-44c6-a0bc-b388be43cd2f",
        "displayName": "emergency",
        "type": "user",
        "userPrincipalName": "emergency@m7knio.onmicrosoft.com",
        "lastUserSignInDateTime": "7/19/2026 3:43:13 AM +00:00"
      }
    },
    {
      "id": "8d533e90-5c4b-491e-99f2-ecbe35eb4d2a",
      "accessReviewId": "ca2cd5a6-dadb-4bf9-9de2-49b445bbab71",
      "reviewedDateTime": null,
      "decision": "NotReviewed",
      "justification": "",
      "appliedDateTime": null,
      "applyResult": "New",
      "recommendation": "Approve",
      "principalLink": "https://graph.microsoft.com/v1.0/users/bbcfc3c5-0b93-4135-9ef9-18477a9fb504",
      "resourceLink": "https://graph.microsoft.com/beta/roleManagement/directory/roleDefinitions/62e90394-69f5-4237-9190-012177145e10",
      "reviewedBy": {"id": "00000000-0000-0000-0000-000000000000", "displayName": "", "type": "user", "userPrincipalName": ""},
      "appliedBy": {"id": "00000000-0000-0000-0000-000000000000", "displayName": "", "type": null, "userPrincipalName": ""},
      "resource": {"id": "62e90394-69f5-4237-9190-012177145e10", "displayName": "Global Administrator", "type": "directoryRole"},
      "principal": {
        "@odata.type": "#microsoft.graph.userIdentity",
        "id": "bbcfc3c5-0b93-4135-9ef9-18477a9fb504",
        "displayName": "Rob Knight",
        "type": "user",
        "userPrincipalName": "rob@m7kni.io",
        "lastUserSignInDateTime": "7/19/2026 5:00:26 AM +00:00"
      }
    }
  ]
}`

// graphWithInstancesAndDecisions is the standard live-shaped stub: the
// definitions list (one review), its instances (one), and that instance's
// decisions (three).
func graphWithInstancesAndDecisions() *fakeGraph {
	return &fakeGraph{bodies: map[string]string{
		listURL:                              liveDefinitions,
		instancesURL(liveID):                 liveInstances,
		decisionsURL(liveID, liveInstanceID): liveDecisions,
	}}
}

func collectWith(t *testing.T, g *fakeGraph, now func() time.Time) *telemetrytest.Recorder {
	t.Helper()
	rec := telemetrytest.New()
	c := New(g, nil)
	if now != nil {
		c.now = now
	}
	if err := c.Collect(context.Background(), rec.Emitter(), nil); err != nil {
		t.Fatalf("Collect: %v", err)
	}
	return rec
}

func instanceTwinByID(t *testing.T, rec *telemetrytest.Recorder, id string) telemetrytest.LogRecord {
	t.Helper()
	for _, r := range rec.LogRecords() {
		if r.EventName == eventInstance && r.Attrs[semconv.AttrId] == id {
			return r
		}
	}
	t.Fatalf("no %s twin for id %q; got %+v", eventInstance, id, rec.LogRecords())
	return telemetrytest.LogRecord{}
}

func decisionTwinByID(t *testing.T, rec *telemetrytest.Recorder, id string) telemetrytest.LogRecord {
	t.Helper()
	for _, r := range rec.LogRecords() {
		if r.EventName == eventDecision && r.Attrs[semconv.AttrDecisionId] == id {
			return r
		}
	}
	t.Fatalf("no %s twin for id %q; got %+v", eventDecision, id, rec.LogRecords())
	return telemetrytest.LogRecord{}
}

// fixedClock returns a clock function pinned to t — used so severity tests
// never depend on the wall clock (a fixture with an absolute date has turned
// this repo's main branch red on a calendar date before).
func fixedClock(t time.Time) func() time.Time {
	return func() time.Time { return t }
}

// afterLiveInstance is well after the live instance's endDateTime
// (2026-08-02T18:14:10.287Z), so a clock pinned here judges it expired.
var afterLiveInstance = fixedClock(time.Date(2026, 8, 10, 0, 0, 0, 0, time.UTC))

// beforeLiveInstance is well before the live instance's endDateTime, so a
// clock pinned here judges it NOT expired.
var beforeLiveInstance = fixedClock(time.Date(2026, 7, 20, 0, 0, 0, 0, time.UTC))

// TestLiveInstanceAndDecisionMapInFull pins every attribute the instance and
// decision twins carry from the verbatim live captures.
func TestLiveInstanceAndDecisionMapInFull(t *testing.T) {
	rec := collectWith(t, graphWithInstancesAndDecisions(), beforeLiveInstance)

	inst := instanceTwinByID(t, rec, liveInstanceID)
	wantInst := map[string]string{
		semconv.AttrDefinitionId:          liveID,
		semconv.AttrStatus:                "InProgress",
		semconv.AttrStartDateTime:         "2026-07-19T18:14:10.287Z",
		semconv.AttrEndDateTime:           "2026-08-02T18:14:10.287Z",
		semconv.AttrScopeODataType:        "principalResourceMembershipsScope",
		semconv.AttrScopePrincipalQueries: "/v1.0/users",
		semconv.AttrScopeResourceQueries:  "/beta/roleManagement/directory/roleDefinitions/62e90394-69f5-4237-9190-012177145e10",
		semconv.AttrReviewerQueries:       "/v1.0/users/bbcfc3c5-0b93-4135-9ef9-18477a9fb504",
		semconv.AttrReviewerCount:         "1",
		semconv.AttrFallbackReviewerCount: "0",
	}
	for k, v := range wantInst {
		if inst.Attrs[k] != v {
			t.Errorf("instance attr %q = %q, want %q", k, inst.Attrs[k], v)
		}
	}
	if inst.SeverityText != "INFO" {
		t.Errorf("instance severity = %q, want INFO (not yet expired)", inst.SeverityText)
	}

	dec := decisionTwinByID(t, rec, "8d533e90-5c4b-491e-99f2-ecbe35eb4d2a")
	wantDec := map[string]string{
		semconv.AttrInstanceId:             liveInstanceID,
		semconv.AttrDefinitionId:           liveID,
		semconv.AttrDecision:               "NotReviewed",
		semconv.AttrAppliedResult:          "New",
		semconv.AttrRecommendation:         "Approve",
		semconv.AttrPrincipalLink:          "https://graph.microsoft.com/v1.0/users/bbcfc3c5-0b93-4135-9ef9-18477a9fb504",
		semconv.AttrResourceLink:           "https://graph.microsoft.com/beta/roleManagement/directory/roleDefinitions/62e90394-69f5-4237-9190-012177145e10",
		semconv.AttrResourceId:             "62e90394-69f5-4237-9190-012177145e10",
		semconv.AttrResourceDisplayName:    "Global Administrator",
		semconv.AttrResourceType:           "directoryRole",
		semconv.AttrPrincipalId:            "bbcfc3c5-0b93-4135-9ef9-18477a9fb504",
		semconv.AttrDisplayName:            "Rob Knight",
		semconv.AttrPrincipalType:          "user",
		semconv.AttrUserPrincipalName:      "rob@m7kni.io",
		semconv.AttrLastUserSignInDateTime: "7/19/2026 5:00:26 AM +00:00",
	}
	for k, v := range wantDec {
		if dec.Attrs[k] != v {
			t.Errorf("decision attr %q = %q, want %q", k, dec.Attrs[k], v)
		}
	}
	for _, k := range []string{
		semconv.AttrJustification, semconv.AttrReviewedDateTime, semconv.AttrAppliedDateTime,
		semconv.AttrReviewedById, semconv.AttrReviewedByDisplayName, semconv.AttrAppliedById,
	} {
		if v, ok := dec.Attrs[k]; ok {
			t.Errorf("decision attr %q = %q, want omitted (empty/null/zero-GUID on this row)", k, v)
		}
	}

	instancePts := rec.MetricPoints(metricInstances)
	if len(instancePts) != 1 || instancePts[0].Attrs[semconv.AttrStatus] != "InProgress" || instancePts[0].Value != 1 {
		t.Errorf("instances gauge = %+v, want one InProgress point of 1", instancePts)
	}
	decisionPts := rec.MetricPoints(metricDecisions)
	if len(decisionPts) != 1 {
		t.Fatalf("decisions gauge points = %+v, want 1 (all three decisions share decision=NotReviewed/applied_result=New)", decisionPts)
	}
	if decisionPts[0].Value != 3 || decisionPts[0].Attrs[semconv.AttrDecision] != "NotReviewed" || decisionPts[0].Attrs[semconv.AttrAppliedResult] != "New" {
		t.Errorf("decisions gauge = %+v, want {decision:NotReviewed,applied_result:New}=3", decisionPts[0])
	}
}

// TestZeroGUIDReviewerIsOmittedNotMappedThrough covers the headline sentinel
// at BOTH layers per the brief: the mapper's own return value (so a bug that
// only shows up before telemetry.Attrs's own filtering can't hide), and the
// full pipeline's Attrs (so the emitter chain doesn't reintroduce it).
func TestZeroGUIDReviewerIsOmittedNotMappedThrough(t *testing.T) {
	zeroIdentity := &userIdentity{ID: zeroGUID, DisplayName: "", Type: "user", UserPrincipalName: ""}
	dec := accessReviewDecision{ID: "d1", Decision: "NotReviewed", ApplyResult: "New", ReviewedBy: zeroIdentity, AppliedBy: zeroIdentity}

	// Layer 1: the mapper's own return value.
	ev := decisionTwin(liveID, liveInstanceID, dec, false)
	for _, k := range []string{semconv.AttrReviewedById, semconv.AttrReviewedByDisplayName, semconv.AttrAppliedById} {
		if v, ok := ev.Attrs[k]; ok {
			t.Errorf("mapper output attr %q = %v, want absent for a zero-GUID identity", k, v)
		}
	}

	// Layer 2: through the full pipeline.
	rec := collectWith(t, graphWithInstancesAndDecisions(), beforeLiveInstance)
	got := decisionTwinByID(t, rec, "5a07a10a-9ecc-41b4-a58a-0a101ca9007c").Attrs // row 1 of liveDecisions: zero-GUID reviewedBy/appliedBy
	for _, k := range []string{semconv.AttrReviewedById, semconv.AttrReviewedByDisplayName, semconv.AttrAppliedById} {
		if v, ok := got[k]; ok {
			t.Errorf("pipeline attr %q = %q, want absent", k, v)
		}
	}
}

// TestResolvedReviewerIsEmitted is the other half of the omission rule: a
// REAL (non-zero-GUID) reviewedBy/appliedBy must be carried.
func TestResolvedReviewerIsEmitted(t *testing.T) {
	real := &userIdentity{ID: "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee", DisplayName: "Alice Admin", Type: "user"}
	dec := accessReviewDecision{ID: "d1", Decision: "Approve", ApplyResult: "AppliedSuccessfully", ReviewedBy: real, AppliedBy: real}

	ev := decisionTwin(liveID, liveInstanceID, dec, false)
	if ev.Attrs[semconv.AttrReviewedById] != real.ID {
		t.Errorf("reviewed_by_id = %v, want %q", ev.Attrs[semconv.AttrReviewedById], real.ID)
	}
	if ev.Attrs[semconv.AttrReviewedByDisplayName] != "Alice Admin" {
		t.Errorf("reviewed_by_display_name = %v, want Alice Admin", ev.Attrs[semconv.AttrReviewedByDisplayName])
	}
	if ev.Attrs[semconv.AttrAppliedById] != real.ID {
		t.Errorf("applied_by_id = %v, want %q", ev.Attrs[semconv.AttrAppliedById], real.ID)
	}
}

// TestNullTimestampsAreOmitted covers reviewedDateTime/appliedDateTime being
// JSON null at both layers.
func TestNullTimestampsAreOmitted(t *testing.T) {
	dec := accessReviewDecision{ID: "d1", Decision: "NotReviewed", ApplyResult: "New"} // both pointers nil

	ev := decisionTwin(liveID, liveInstanceID, dec, false)
	for _, k := range []string{semconv.AttrReviewedDateTime, semconv.AttrAppliedDateTime} {
		if v, ok := ev.Attrs[k]; ok {
			t.Errorf("mapper output attr %q = %v, want absent for a null timestamp", k, v)
		}
	}

	rec := collectWith(t, graphWithInstancesAndDecisions(), beforeLiveInstance)
	got := decisionTwinByID(t, rec, "5a07a10a-9ecc-41b4-a58a-0a101ca9007c").Attrs
	for _, k := range []string{semconv.AttrReviewedDateTime, semconv.AttrAppliedDateTime} {
		if v, ok := got[k]; ok {
			t.Errorf("pipeline attr %q = %q, want absent", k, v)
		}
	}
}

// TestResolvedTimestampsAreEmitted is the other half: a non-null timestamp
// must be carried verbatim.
func TestResolvedTimestampsAreEmitted(t *testing.T) {
	reviewed := "2026-07-25T10:00:00Z"
	applied := "2026-07-25T11:00:00Z"
	dec := accessReviewDecision{ID: "d1", Decision: "Approve", ApplyResult: "AppliedSuccessfully", ReviewedDateTime: &reviewed, AppliedDateTime: &applied}

	ev := decisionTwin(liveID, liveInstanceID, dec, false)
	if ev.Attrs[semconv.AttrReviewedDateTime] != reviewed {
		t.Errorf("reviewed_date_time = %v, want %q", ev.Attrs[semconv.AttrReviewedDateTime], reviewed)
	}
	if ev.Attrs[semconv.AttrAppliedDateTime] != applied {
		t.Errorf("applied_date_time = %v, want %q", ev.Attrs[semconv.AttrAppliedDateTime], applied)
	}
}

// TestEmptyLastSignInIsOmittedNotBlank covers the third sentinel: an empty
// STRING (never null) must be omitted, not stamped blank, at both layers.
func TestEmptyLastSignInIsOmittedNotBlank(t *testing.T) {
	dec := accessReviewDecision{
		ID: "d1", Decision: "NotReviewed", ApplyResult: "New",
		Principal: &decisionPrincipal{ID: "p1", DisplayName: "Never Signed In", LastUserSignInDateTime: ""},
	}

	ev := decisionTwin(liveID, liveInstanceID, dec, false)
	if v, ok := ev.Attrs[semconv.AttrLastUserSignInDateTime]; ok {
		t.Errorf("mapper output attr last_user_sign_in_date_time = %v, want absent for an empty string", v)
	}

	rec := collectWith(t, graphWithInstancesAndDecisions(), beforeLiveInstance)
	got := decisionTwinByID(t, rec, "5a07a10a-9ecc-41b4-a58a-0a101ca9007c").Attrs // row 1: lastUserSignInDateTime is ""
	if v, ok := got[semconv.AttrLastUserSignInDateTime]; ok {
		t.Errorf("pipeline attr last_user_sign_in_date_time = %q, want absent", v)
	}
}

// TestResolvedLastSignInIsEmitted is the other half: a real value must be
// carried, both from a direct mapper call and through the full pipeline.
func TestResolvedLastSignInIsEmitted(t *testing.T) {
	dec := accessReviewDecision{
		ID: "d1", Decision: "NotReviewed", ApplyResult: "New",
		Principal: &decisionPrincipal{ID: "p1", DisplayName: "Someone", LastUserSignInDateTime: "7/19/2026 5:00:26 AM +00:00"},
	}
	ev := decisionTwin(liveID, liveInstanceID, dec, false)
	if ev.Attrs[semconv.AttrLastUserSignInDateTime] != "7/19/2026 5:00:26 AM +00:00" {
		t.Errorf("last_user_sign_in_date_time = %v", ev.Attrs[semconv.AttrLastUserSignInDateTime])
	}

	// Through the full pipeline: row 3 of liveDecisions (Rob Knight) carries a
	// real lastUserSignInDateTime.
	rec := collectWith(t, graphWithInstancesAndDecisions(), beforeLiveInstance)
	got := decisionTwinByID(t, rec, "8d533e90-5c4b-491e-99f2-ecbe35eb4d2a").Attrs
	if got[semconv.AttrLastUserSignInDateTime] != "7/19/2026 5:00:26 AM +00:00" {
		t.Errorf("pipeline last_user_sign_in_date_time = %q", got[semconv.AttrLastUserSignInDateTime])
	}
}

// TestExpiredUnreviewedDecisionWarns pins the decision severity rung: the
// owning instance's endDateTime is in the past AND decision is still
// NotReviewed.
func TestExpiredUnreviewedDecisionWarns(t *testing.T) {
	rec := collectWith(t, graphWithInstancesAndDecisions(), afterLiveInstance)
	dec := decisionTwinByID(t, rec, "8d533e90-5c4b-491e-99f2-ecbe35eb4d2a")
	if dec.SeverityText != "WARN" {
		t.Errorf("severity = %q, want WARN (instance expired, decision still NotReviewed)", dec.SeverityText)
	}
}

// TestFreshDecisionStaysInfo — the same decision, before the instance's
// endDateTime, must stay INFO.
func TestFreshDecisionStaysInfo(t *testing.T) {
	rec := collectWith(t, graphWithInstancesAndDecisions(), beforeLiveInstance)
	dec := decisionTwinByID(t, rec, "8d533e90-5c4b-491e-99f2-ecbe35eb4d2a")
	if dec.SeverityText != "INFO" {
		t.Errorf("severity = %q, want INFO (instance not yet expired)", dec.SeverityText)
	}
}

// TestReviewedDecisionNeverWarnsEvenIfExpired: a decision that WAS reviewed
// must never warn just because the instance later expired.
func TestReviewedDecisionNeverWarnsEvenIfExpired(t *testing.T) {
	reviewed := "2026-07-25T10:00:00Z"
	dec := accessReviewDecision{ID: "d1", Decision: "Approve", ApplyResult: "AppliedSuccessfully", ReviewedDateTime: &reviewed}
	ev := decisionTwin(liveID, liveInstanceID, dec, true) // instanceExpired=true
	if ev.Severity != telemetry.SeverityInfo {
		t.Errorf("severity = %v, want INFO — a reviewed decision never warns", ev.Severity)
	}
}

// TestExpiredInProgressInstanceWarns / TestFreshInstanceStaysInfo pin the
// instance severity rung under a pinned clock.
func TestExpiredInProgressInstanceWarns(t *testing.T) {
	rec := collectWith(t, graphWithInstancesAndDecisions(), afterLiveInstance)
	inst := instanceTwinByID(t, rec, liveInstanceID)
	if inst.SeverityText != "WARN" {
		t.Errorf("severity = %q, want WARN (InProgress and endDateTime in the past)", inst.SeverityText)
	}
}

func TestFreshInstanceStaysInfo(t *testing.T) {
	rec := collectWith(t, graphWithInstancesAndDecisions(), beforeLiveInstance)
	inst := instanceTwinByID(t, rec, liveInstanceID)
	if inst.SeverityText != "INFO" {
		t.Errorf("severity = %q, want INFO (not yet expired)", inst.SeverityText)
	}
}

// TestCompletedInstanceNeverWarnsEvenIfExpired: a Completed instance must not
// warn just because time has passed its window.
func TestCompletedInstanceNeverWarnsEvenIfExpired(t *testing.T) {
	body := strings.Replace(liveInstances, `"status": "InProgress",`, `"status": "Completed",`, 1)
	g := &fakeGraph{bodies: map[string]string{
		listURL:                              liveDefinitions,
		instancesURL(liveID):                 body,
		decisionsURL(liveID, liveInstanceID): `{"value":[]}`,
	}}
	rec := collectWith(t, g, afterLiveInstance)
	inst := instanceTwinByID(t, rec, liveInstanceID)
	if inst.SeverityText != "INFO" {
		t.Errorf("severity = %q, want INFO — a Completed instance never warns on expiry alone", inst.SeverityText)
	}
}

// TestDefinitionWithZeroInstancesIsSuccessNotAGap: an empty instances page is
// success, not an error, and must not fabricate any twin or gauge point.
func TestDefinitionWithZeroInstancesIsSuccessNotAGap(t *testing.T) {
	g := &fakeGraph{bodies: map[string]string{
		listURL:              liveDefinitions,
		instancesURL(liveID): `{"value":[]}`,
	}}
	rec := collectWith(t, g, beforeLiveInstance)
	for _, r := range rec.LogRecords() {
		if r.EventName == eventInstance || r.EventName == eventDecision {
			t.Errorf("unexpected %s twin for a definition with zero instances: %+v", r.EventName, r)
		}
	}
	if pts := rec.MetricPoints(metricInstances); len(pts) != 0 {
		t.Errorf("instances gauge = %+v, want none", pts)
	}
	if pts := rec.MetricPoints(metricDecisions); len(pts) != 0 {
		t.Errorf("decisions gauge = %+v, want none", pts)
	}
	// The definition twin itself is untouched by any of this.
	twin(t, rec, liveID)
}

// TestInstancesFetchFailureOmitsDefinitionAndDoesNotAbortRest is the #240
// test: one definition's instances fetch fails, another's succeeds. The
// failed one must be OMITTED from the gauge (never a fabricated zero), the
// working one must still be fully collected, and Collect must report the
// failure without losing the good data.
func TestInstancesFetchFailureOmitsDefinitionAndDoesNotAbortRest(t *testing.T) {
	twoDefs := `{"value":[
      {"id":"a","status":"InProgress","scope":{"@odata.type":"#microsoft.graph.accessReviewQueryScope","query":"/v1.0/users"}},
      {"id":"b","status":"InProgress","scope":{"@odata.type":"#microsoft.graph.accessReviewQueryScope","query":"/v1.0/users"}}
    ]}`
	bInstance := `{"value":[{"id":"bi1","startDateTime":"2026-07-01T00:00:00Z","endDateTime":"2026-09-01T00:00:00Z","status":"InProgress"}]}`
	g := &fakeGraph{
		bodies: map[string]string{listURL: twoDefs, instancesURL("b"): bInstance, decisionsURL("b", "bi1"): `{"value":[]}`},
		errs:   map[string]error{instancesURL("a"): errors.New("graph: GET failed with status 500")},
	}
	rec := telemetrytest.New()
	c := New(g, nil)
	c.now = beforeLiveInstance
	err := c.Collect(context.Background(), rec.Emitter(), nil)
	if err == nil {
		t.Fatal("Collect = nil, want the instances-fetch failure surfaced")
	}

	pts := rec.MetricPoints(metricInstances)
	if len(pts) != 1 || pts[0].Value != 1 {
		t.Fatalf("instances gauge = %+v, want exactly b's one instance (a omitted, never zero)", pts)
	}
	instanceTwinByID(t, rec, "bi1")
	for _, r := range rec.LogRecords() {
		if r.EventName == eventInstance && r.Attrs[semconv.AttrDefinitionId] == "a" {
			t.Errorf("definition a's instances fetch failed; it must have no instance twin, got %+v", r)
		}
	}
	// Both definition twins (a and b) are still present — the definition
	// layer itself never touches the instances fetch.
	twin(t, rec, "a")
	twin(t, rec, "b")
}

// TestMaxDefinitionsCapsTheInstancesFanOut: with more definitions than
// maxDefinitions, only maxDefinitions of them get an instances fetch at all —
// verified by counting actual HTTP calls, not just twins (a twin count alone
// cannot distinguish "capped" from "every definition simply had zero
// instances"). The cap is logged; there is no single twin to mark (see the
// package doc).
func TestMaxDefinitionsCapsTheInstancesFanOut(t *testing.T) {
	var defs strings.Builder
	defs.WriteString(`{"value":[`)
	for i := 0; i < maxDefinitions+1; i++ {
		if i > 0 {
			defs.WriteByte(',')
		}
		fmt.Fprintf(&defs, `{"id":"d%d","status":"InProgress","scope":{"@odata.type":"#microsoft.graph.accessReviewQueryScope","query":"/v1.0/users"}}`, i)
	}
	defs.WriteString(`]}`)

	var buf bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&buf, nil))
	g := &fakeGraph{bodies: map[string]string{listURL: defs.String()}}
	rec := telemetrytest.New()
	c := New(g, logger)
	if err := c.Collect(context.Background(), rec.Emitter(), nil); err != nil {
		t.Fatalf("Collect: %v", err)
	}

	instanceFetches := 0
	for _, u := range g.calls {
		if strings.HasSuffix(u, "/instances") {
			instanceFetches++
		}
	}
	if instanceFetches != maxDefinitions {
		t.Errorf("instances fetches = %d, want exactly maxDefinitions (%d)", instanceFetches, maxDefinitions)
	}
	if !strings.Contains(buf.String(), "capped") {
		t.Error("expected a log line announcing the maxDefinitions cap")
	}
}

// TestMaxInstancesPerDefinitionTruncatesLogsAndMarks: one definition with
// more instances than maxInstancesPerDefinition. Only the cap's worth survive
// as twins, the cap is logged, and every surviving instance twin is marked
// arrays_truncated (there is no single "this definition's instance list"
// twin to carry it instead — see the package doc).
func TestMaxInstancesPerDefinitionTruncatesLogsAndMarks(t *testing.T) {
	var insts strings.Builder
	insts.WriteString(`{"value":[`)
	for i := 0; i < maxInstancesPerDefinition+1; i++ {
		if i > 0 {
			insts.WriteByte(',')
		}
		fmt.Fprintf(&insts, `{"id":"i%d","status":"InProgress","startDateTime":"2026-07-01T00:00:00Z","endDateTime":"2026-09-01T00:00:00Z"}`, i)
	}
	insts.WriteString(`]}`)

	var buf bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&buf, nil))
	g := &fakeGraph{bodies: map[string]string{listURL: liveDefinitions, instancesURL(liveID): insts.String()}}
	rec := telemetrytest.New()
	c := New(g, logger)
	c.now = beforeLiveInstance
	if err := c.Collect(context.Background(), rec.Emitter(), nil); err != nil {
		t.Fatalf("Collect: %v", err)
	}

	got := 0
	for _, r := range rec.LogRecords() {
		if r.EventName == eventInstance {
			got++
			if r.Attrs[semconv.AttrArraysTruncated] != "true" {
				t.Errorf("instance %s: arrays_truncated = %q, want true", r.Attrs[semconv.AttrId], r.Attrs[semconv.AttrArraysTruncated])
			}
		}
	}
	if got != maxInstancesPerDefinition {
		t.Errorf("instance twins = %d, want exactly maxInstancesPerDefinition (%d)", got, maxInstancesPerDefinition)
	}
	if !strings.Contains(buf.String(), "truncated") {
		t.Error("expected a log line announcing the maxInstancesPerDefinition truncation")
	}
}

// TestMaxDecisionsPerInstanceTruncatesLogsAndMarks: one instance with more
// decisions than maxDecisionsPerInstance. Only the cap's worth survive as
// twins, the cap is logged, and the OWNING instance twin is marked
// arrays_truncated.
func TestMaxDecisionsPerInstanceTruncatesLogsAndMarks(t *testing.T) {
	var decs strings.Builder
	decs.WriteString(`{"value":[`)
	for i := 0; i < maxDecisionsPerInstance+1; i++ {
		if i > 0 {
			decs.WriteByte(',')
		}
		fmt.Fprintf(&decs, `{"id":"dec%d","decision":"NotReviewed","applyResult":"New"}`, i)
	}
	decs.WriteString(`]}`)

	oneInstance := `{"value":[{"id":"i1","status":"InProgress","startDateTime":"2026-07-01T00:00:00Z","endDateTime":"2026-09-01T00:00:00Z"}]}`

	var buf bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&buf, nil))
	g := &fakeGraph{bodies: map[string]string{
		listURL:                    liveDefinitions,
		instancesURL(liveID):       oneInstance,
		decisionsURL(liveID, "i1"): decs.String(),
	}}
	rec := telemetrytest.New()
	c := New(g, logger)
	c.now = beforeLiveInstance
	if err := c.Collect(context.Background(), rec.Emitter(), nil); err != nil {
		t.Fatalf("Collect: %v", err)
	}

	got := 0
	for _, r := range rec.LogRecords() {
		if r.EventName == eventDecision {
			got++
		}
	}
	if got != maxDecisionsPerInstance {
		t.Errorf("decision twins = %d, want exactly maxDecisionsPerInstance (%d)", got, maxDecisionsPerInstance)
	}
	inst := instanceTwinByID(t, rec, "i1")
	if inst.Attrs[semconv.AttrArraysTruncated] != "true" {
		t.Errorf("instance arrays_truncated = %q, want true", inst.Attrs[semconv.AttrArraysTruncated])
	}
	if !strings.Contains(buf.String(), "truncated") {
		t.Error("expected a log line announcing the maxDecisionsPerInstance truncation")
	}
}

// TestInstanceScopeIsPolymorphicByDiscriminator: the instance's scope reuses
// the exact same polymorphic reading code as the definition's — pinned here
// so a regression in that shared code is caught from either caller.
func TestInstanceScopeIsPolymorphicByDiscriminator(t *testing.T) {
	body := `{"value":[{"id":"i1","status":"InProgress","startDateTime":"2026-07-01T00:00:00Z","endDateTime":"2026-09-01T00:00:00Z",
      "scope":{"@odata.type":"#microsoft.graph.accessReviewQueryScope","query":"/v1.0/groups/x/transitiveMembers"}}]}`
	g := &fakeGraph{bodies: map[string]string{listURL: liveDefinitions, instancesURL(liveID): body}}
	rec := collectWith(t, g, beforeLiveInstance)
	inst := instanceTwinByID(t, rec, "i1")
	if inst.Attrs[semconv.AttrScopeODataType] != "accessReviewQueryScope" {
		t.Errorf("scope_odata_type = %q", inst.Attrs[semconv.AttrScopeODataType])
	}
	if inst.Attrs[semconv.AttrScopeQuery] != "/v1.0/groups/x/transitiveMembers" {
		t.Errorf("scope_query = %q", inst.Attrs[semconv.AttrScopeQuery])
	}
}

// TestInstanceUnknownScopeTypeStillProducesATwin: an unmapped @odata.type
// must still carry the discriminator and emit the instance twin — never drop
// it — matching the definition-level guarantee.
func TestInstanceUnknownScopeTypeStillProducesATwin(t *testing.T) {
	body := `{"value":[{"id":"i1","status":"InProgress","startDateTime":"2026-07-01T00:00:00Z","endDateTime":"2026-09-01T00:00:00Z",
      "scope":{"@odata.type":"#microsoft.graph.accessReviewInactiveUsersQueryScope","query":"/v1.0/users"}}]}`
	g := &fakeGraph{bodies: map[string]string{listURL: liveDefinitions, instancesURL(liveID): body}}
	rec := collectWith(t, g, beforeLiveInstance)

	inst := instanceTwinByID(t, rec, "i1")
	if inst.Attrs[semconv.AttrScopeODataType] != "accessReviewInactiveUsersQueryScope" {
		t.Errorf("scope_odata_type = %q — the discriminator must be carried even when unmapped", inst.Attrs[semconv.AttrScopeODataType])
	}

	var found int
	for _, p := range rec.MetricPoints(wirecheck.MetricUnexpected) {
		if p.Attrs[semconv.AttrField] == semconv.AttrScopeODataType && p.Attrs[semconv.AttrKind] == wirecheck.KindUnmappedValue {
			found++
		}
	}
	if found != 1 {
		t.Errorf("unmapped_value findings on scope_odata_type = %d, want 1", found)
	}
}

func TestNameIntervalAndPermissions(t *testing.T) {
	c := New(&fakeGraph{}, nil)
	if c.Name() != "entra.access_reviews" {
		t.Errorf("Name = %q", c.Name())
	}
	if c.DefaultInterval() <= 0 {
		t.Errorf("DefaultInterval = %v", c.DefaultInterval())
	}
	if got := c.RequiredPermissions(); len(got) != 1 || got[0] != "AccessReview.Read.All" {
		t.Errorf("RequiredPermissions = %v", got)
	}
	if !strings.HasPrefix(c.baseURL, "https://graph.microsoft.com/v1.0") {
		t.Errorf("baseURL = %q — this collector is v1.0, so it carries no Experimental gate", c.baseURL)
	}
}
