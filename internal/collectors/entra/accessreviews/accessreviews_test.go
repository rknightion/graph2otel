package accessreviews

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/rknightion/graph2otel/internal/collectors"
	"github.com/rknightion/graph2otel/internal/semconv"
	"github.com/rknightion/graph2otel/internal/telemetrytest"
	"github.com/rknightion/graph2otel/internal/wirecheck"
)

type fakeGraph struct {
	bodies map[string]string
	errs   map[string]error
}

func (f *fakeGraph) RawGet(ctx context.Context, url string) ([]byte, error) {
	return f.RawGetWithHeaders(ctx, url, nil)
}

func (f *fakeGraph) RawGetWithHeaders(_ context.Context, url string, _ map[string]string) ([]byte, error) {
	if err, ok := f.errs[url]; ok {
		return nil, err
	}
	body, ok := f.bodies[url]
	if !ok {
		return nil, fmt.Errorf("fakeGraph: no body stubbed for %s", url)
	}
	return []byte(body), nil
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
	if err := New(graphWith(body), nil).Collect(context.Background(), rec.Emitter()); err != nil {
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
	if err := New(g, nil).Collect(context.Background(), rec.Emitter()); err != nil {
		t.Fatalf("Collect = %v, want nil for a 403", err)
	}
	if n := len(rec.LogRecords()); n != 0 {
		t.Errorf("emitted %d records on a 403, want 0", n)
	}
}

// TestOtherErrorsFail — everything that is not a 403 must surface.
func TestOtherErrorsFail(t *testing.T) {
	g := &fakeGraph{errs: map[string]error{listURL: errors.New("graph: GET failed with status 500")}}
	if err := New(g, nil).Collect(context.Background(), telemetrytest.New().Emitter()); err == nil {
		t.Fatal("Collect = nil, want an error for a 500")
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
	err := New(graphWith(body), nil).Collect(context.Background(), rec.Emitter())
	if err == nil {
		t.Error("Collect = nil, want the decode failure aggregated")
	}
	if n := len(rec.LogRecords()); n != 1 {
		t.Errorf("twins = %d, want the good row still emitted", n)
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
