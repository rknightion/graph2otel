package windowsupdates

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/rknightion/graph2otel/internal/collectors"
	"github.com/rknightion/graph2otel/internal/semconv"
	"github.com/rknightion/graph2otel/internal/telemetrytest"
)

// fakeGraph maps request URLs to canned page bodies (or errors), satisfying
// collectors.GraphClient so Collector runs through collectors.GetAllValues with
// no live Graph call.
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
		return nil, fmt.Errorf("fakeGraph: no body for %q", url)
	}
	return []byte(body), nil
}

var _ collectors.GraphClient = (*fakeGraph)(nil)

func policiesURL() string    { return defaultBaseURL + updatePoliciesPath }
func deploymentsURL() string { return defaultBaseURL + deploymentsPath }

// livePolicies is the tenant's FULL updatePolicies collection, copied verbatim
// off the beta wire (probed as graph2otel-poller on m7kni 2026-07-24, #259).
// BOTH rows matter and neither is a simplification of the other: row 1 is a
// QUALITY policy whose contentApprovalRule filters on
// `qualityUpdateFilter{classification,cadence}`; row 2 is a DRIVER policy whose
// rule filters on `driverUpdateFilter`, which carries NEITHER field. Decoding
// the filter structurally would map row 2 as a quality filter with two empty
// strings, which is precisely what the @odata.type discriminator exists to stop.
const livePolicies = `{
  "@odata.context": "https://graph.microsoft.com/beta/$metadata#admin/windows/updates/updatePolicies",
  "value": [
    {
      "id": "0fa55cf5-4598-4fe3-b6c1-a724e5035f9d",
      "createdDateTime": "2025-10-09T12:35:44.5615718Z",
      "autoEnrollmentUpdateCategories": ["quality"],
      "complianceChangeRules": [
        {
          "@odata.type": "#microsoft.graph.windowsUpdates.contentApprovalRule",
          "createdDateTime": "2026-07-21T21:16:03.9736656Z",
          "lastEvaluatedDateTime": "0001-01-01T00:00:00Z",
          "lastModifiedDateTime": "2026-07-21T21:16:03.9736656Z",
          "durationBeforeDeploymentStart": "PT0S",
          "contentFilter": {
            "@odata.type": "#microsoft.graph.windowsUpdates.qualityUpdateFilter",
            "classification": "security",
            "cadence": "monthly"
          }
        }
      ],
      "deploymentSettings": {
        "schedule": null,
        "monitoring": null,
        "contentApplicability": null,
        "expedite": null,
        "userExperience": {
          "daysUntilForcedReboot": null,
          "offerAsOptional": false,
          "isHotpatchEnabled": true
        }
      },
      "audience": {"id": "9c6c8e6b-e85b-4cd5-8b96-73cbc4aac678"}
    },
    {
      "id": "a59bda37-7cdd-4683-84a2-ed46dd81a388",
      "createdDateTime": "2026-07-21T22:28:17.8790458Z",
      "autoEnrollmentUpdateCategories": ["driver"],
      "complianceChangeRules": [
        {
          "@odata.type": "#microsoft.graph.windowsUpdates.contentApprovalRule",
          "createdDateTime": "2026-07-21T22:28:18.2122453Z",
          "lastEvaluatedDateTime": "0001-01-01T00:00:00Z",
          "lastModifiedDateTime": "2026-07-21T22:28:18.2122453Z",
          "durationBeforeDeploymentStart": "PT0S",
          "contentFilter": {
            "@odata.type": "#microsoft.graph.windowsUpdates.driverUpdateFilter"
          }
        }
      ],
      "deploymentSettings": {
        "schedule": null,
        "monitoring": null,
        "userExperience": null,
        "expedite": null,
        "contentApplicability": {
          "offerWhileRecommendedBy": ["microsoft"],
          "safeguard": null
        }
      },
      "audience": {"id": "4a8f403a-ed7e-494f-ad56-4206a11d71d4"}
    }
  ]
}`

// liveDeployments is the tenant's FULL deployments collection, verbatim
// (2026-07-24). One row, and it is the interesting one: state.effectiveValue
// ("offering") DISAGREES with state.requestedValue ("none"), the nested
// catalogEntry has an EMPTY id and a null displayName, and the whole thing is
// polymorphic through two levels of @odata.type.
const liveDeployments = `{
  "@odata.context": "https://graph.microsoft.com/beta/$metadata#admin/windows/updates/deployments",
  "value": [
    {
      "id": "a964123e-df58-4910-a0cb-483ebfb2f2d6",
      "createdDateTime": "2026-07-21T22:26:29.2238015Z",
      "lastModifiedDateTime": "2026-07-24T18:02:31.0492953Z",
      "state": {
        "effectiveValue": "offering",
        "requestedValue": "none",
        "reasons": []
      },
      "content": {
        "@odata.type": "#microsoft.graph.windowsUpdates.catalogContent",
        "catalogEntry": {
          "@odata.type": "#microsoft.graph.windowsUpdates.qualityUpdateCatalogEntry",
          "id": "",
          "displayName": null,
          "deployableUntilDateTime": null,
          "releaseDateTime": "2026-07-14T00:00:00Z",
          "isExpeditable": false,
          "qualityUpdateClassification": "security",
          "catalogName": null,
          "shortName": null,
          "qualityUpdateCadence": "monthly",
          "cveSeverityInformation": null
        }
      },
      "settings": {
        "schedule": null,
        "monitoring": null,
        "contentApplicability": null,
        "userExperience": {
          "daysUntilForcedReboot": 0,
          "offerAsOptional": null,
          "isHotpatchEnabled": null
        },
        "expedite": {
          "isExpedited": true,
          "isReadinessTest": false
        }
      },
      "audience": {"id": "7f48457d-4be7-48b6-98b2-a6c760305eda"}
    }
  ]
}`

func liveGraph() *fakeGraph {
	return &fakeGraph{bodies: map[string]string{
		policiesURL():    livePolicies,
		deploymentsURL(): liveDeployments,
	}}
}

func collect(t *testing.T, g *fakeGraph) *telemetrytest.Recorder {
	t.Helper()
	rec := telemetrytest.New()
	if err := New(g, nil).Collect(context.Background(), rec.Emitter()); err != nil {
		t.Fatalf("Collect: %v", err)
	}
	return rec
}

// twinFor finds the single emitted twin with the given event name.
func twinFor(t *testing.T, rec *telemetrytest.Recorder, event string) telemetrytest.LogRecord {
	t.Helper()
	var found []telemetrytest.LogRecord
	for _, l := range rec.LogRecords() {
		if l.EventName == event {
			found = append(found, l)
		}
	}
	if len(found) != 1 {
		t.Fatalf("got %d %s twins, want exactly 1", len(found), event)
	}
	return found[0]
}

// twinWithAttr finds the twin whose attribute key holds val.
func twinWithAttr(t *testing.T, rec *telemetrytest.Recorder, event, key, val string) telemetrytest.LogRecord {
	t.Helper()
	for _, l := range rec.LogRecords() {
		if l.EventName == event && l.Attrs[key] == val {
			return l
		}
	}
	t.Fatalf("no %s twin with %s=%q", event, key, val)
	return telemetrytest.LogRecord{}
}

func TestDeploymentGaugeIsBoundedAndSplitsTheTwoStates(t *testing.T) {
	rec := collect(t, liveGraph())

	points := rec.MetricPoints(deploymentsMetricName)
	if len(points) != 1 {
		t.Fatalf("got %d deployment series, want 1: %+v", len(points), points)
	}
	p := points[0]
	if p.Kind != "gauge" {
		t.Errorf("metric kind = %q, want gauge", p.Kind)
	}
	if p.Value != 1 {
		t.Errorf("series value = %v, want 1", p.Value)
	}
	want := map[string]string{
		semconv.AttrDeploymentEffectiveState: "offering",
		semconv.AttrDeploymentRequestedState: "none",
		semconv.AttrCatalogEntryType:         "qualityUpdateCatalogEntry",
	}
	if len(p.Attrs) != len(want) {
		t.Errorf("deployment series carries %d labels %+v, want exactly %d", len(p.Attrs), p.Attrs, len(want))
	}
	for k, v := range want {
		if p.Attrs[k] != v {
			t.Errorf("deployment series label %s = %q, want %q", k, p.Attrs[k], v)
		}
	}
}

func TestPolicyGaugeCountsByAutoEnrollmentCategory(t *testing.T) {
	rec := collect(t, liveGraph())

	points := rec.MetricPoints(policiesMetricName)
	if len(points) != 2 {
		t.Fatalf("got %d policy series, want 2 (quality + driver): %+v", len(points), points)
	}
	got := map[string]float64{}
	for _, p := range points {
		if len(p.Attrs) != 1 {
			t.Errorf("policy series carries extra labels %+v, want only %s", p.Attrs, semconv.AttrUpdateCategory)
		}
		got[p.Attrs[semconv.AttrUpdateCategory]] = p.Value
	}
	for _, cat := range []string{"quality", "driver"} {
		if got[cat] != 1 {
			t.Errorf("policy series %s = %v, want 1", cat, got[cat])
		}
	}
}

// A policy with no autoEnrollmentUpdateCategories must still be counted — the
// gauge is the policy census, and dropping the un-enrolled ones would make a
// naive sum() disagree with the number of policies the tenant has.
func TestPolicyWithNoCategoriesCountsAsNone(t *testing.T) {
	g := &fakeGraph{bodies: map[string]string{
		policiesURL():    `{"value":[{"id":"p1","autoEnrollmentUpdateCategories":[]}]}`,
		deploymentsURL(): `{"value":[]}`,
	}}
	rec := collect(t, g)
	points := rec.MetricPoints(policiesMetricName)
	if len(points) != 1 || points[0].Attrs[semconv.AttrUpdateCategory] != noneValue || points[0].Value != 1 {
		t.Fatalf("policy series = %+v, want a single %s=%s series of 1", points, semconv.AttrUpdateCategory, noneValue)
	}
}

// A policy enrolled in several categories contributes to each, so the gauge is
// deliberately NOT a policy count. This pins that behavior so the description's
// warning and the code cannot drift apart.
func TestPolicyInSeveralCategoriesCountsInEach(t *testing.T) {
	g := &fakeGraph{bodies: map[string]string{
		policiesURL():    `{"value":[{"id":"p1","autoEnrollmentUpdateCategories":["quality","driver","feature"]}]}`,
		deploymentsURL(): `{"value":[]}`,
	}}
	rec := collect(t, g)
	if n := len(rec.MetricPoints(policiesMetricName)); n != 3 {
		t.Fatalf("got %d policy series, want 3 (one per enrolled category)", n)
	}
	if n := len(rec.LogRecords()); n != 1 {
		t.Fatalf("got %d twins, want 1 — the policy is one entity however many categories it enrolls in", n)
	}
}

// TestPerEntityFieldsNeverBecomeMetricLabels is the #112/#114 guard: policy and
// deployment identity, audience ids and the rule/filter detail ride the twins,
// never a metric label. signalcapture.Main covers a fixed banned list; this pins
// THIS collector's own per-entity keys, which are not on that list.
func TestPerEntityFieldsNeverBecomeMetricLabels(t *testing.T) {
	rec := collect(t, liveGraph())

	banned := []string{
		semconv.AttrPolicyId,
		semconv.AttrDeploymentId,
		semconv.AttrAudienceId,
		semconv.AttrCatalogEntryId,
		semconv.AttrCreatedDateTime,
		semconv.AttrLastModifiedDateTime,
		semconv.AttrDeploymentStateReasons,
		semconv.AttrRuleLastEvaluatedDateTimes,
		semconv.AttrComplianceChangeRuleTypes,
		semconv.AttrDeploymentStartDelays,
	}
	allowed := map[string]bool{
		semconv.AttrUpdateCategory:           true,
		semconv.AttrDeploymentEffectiveState: true,
		semconv.AttrDeploymentRequestedState: true,
		semconv.AttrCatalogEntryType:         true,
	}
	for _, name := range []string{deploymentsMetricName, policiesMetricName} {
		for _, p := range rec.MetricPoints(name) {
			for k := range p.Attrs {
				for _, b := range banned {
					if k == b {
						t.Errorf("%s carries per-entity metric label %q — it belongs on the twin (#112/#114)", name, k)
					}
				}
				if !allowed[k] {
					t.Errorf("%s carries unexpected metric label %q", name, k)
				}
			}
		}
	}
}

// The whole point of the collector: the live deployment's effective state does
// not match what was requested, and that must be WARN and directly queryable.
func TestStateMismatchDrivesSeverity(t *testing.T) {
	rec := collect(t, liveGraph())

	tw := twinFor(t, rec, deploymentEventName)
	if tw.SeverityText != "WARN" {
		t.Errorf("severity = %q, want WARN — effectiveValue offering != requestedValue none", tw.SeverityText)
	}
	if tw.Attrs[semconv.AttrDeploymentEffectiveState] != "offering" {
		t.Errorf("effective state = %q, want offering", tw.Attrs[semconv.AttrDeploymentEffectiveState])
	}
	if tw.Attrs[semconv.AttrDeploymentRequestedState] != "none" {
		t.Errorf("requested state = %q, want none", tw.Attrs[semconv.AttrDeploymentRequestedState])
	}
	if tw.Attrs[semconv.AttrDeploymentStateMatchesRequest] != "false" {
		t.Errorf("matches_request = %q, want false", tw.Attrs[semconv.AttrDeploymentStateMatchesRequest])
	}
	if !tw.Timestamp.IsZero() {
		t.Errorf("twin timestamp = %v, want zero (state snapshot, not an event)", tw.Timestamp)
	}
}

func TestStateSeverityLadder(t *testing.T) {
	tests := []struct {
		name         string
		state        string
		wantSeverity string
		wantMatches  string // "" means the attribute must be absent
	}{
		{
			name:         "agreement is INFO",
			state:        `{"effectiveValue":"offering","requestedValue":"offering","reasons":[]}`,
			wantSeverity: "INFO",
			wantMatches:  "true",
		},
		{
			name:         "disagreement is WARN",
			state:        `{"effectiveValue":"paused","requestedValue":"offering","reasons":[]}`,
			wantSeverity: "WARN",
			wantMatches:  "false",
		},
		{
			// An absent requestedValue cannot prove agreement OR disagreement.
			// Claiming either would be inventing a verdict from a missing field
			// — absent is not a sentinel.
			name:         "missing requested value claims nothing",
			state:        `{"effectiveValue":"offering","reasons":[]}`,
			wantSeverity: "INFO",
			wantMatches:  "",
		},
		{
			name:         "missing effective value claims nothing",
			state:        `{"requestedValue":"offering","reasons":[]}`,
			wantSeverity: "INFO",
			wantMatches:  "",
		},
		{
			// A state object absent altogether must not synthesize one.
			name:         "no state object at all",
			state:        `null`,
			wantSeverity: "INFO",
			wantMatches:  "",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			g := &fakeGraph{bodies: map[string]string{
				policiesURL():    `{"value":[]}`,
				deploymentsURL(): `{"value":[{"id":"d1","state":` + tc.state + `}]}`,
			}}
			rec := collect(t, g)
			tw := twinFor(t, rec, deploymentEventName)
			if tw.SeverityText != tc.wantSeverity {
				t.Errorf("severity = %q, want %q", tw.SeverityText, tc.wantSeverity)
			}
			got, ok := tw.Attrs[semconv.AttrDeploymentStateMatchesRequest]
			if tc.wantMatches == "" {
				if ok {
					t.Errorf("matches_request = %q, want the attribute omitted", got)
				}
				return
			}
			if got != tc.wantMatches {
				t.Errorf("matches_request = %q, want %q", got, tc.wantMatches)
			}
		})
	}
}

// state.reasons is EMPTY on every live row, so its populated shape is unverified.
// Graph beta returns such collections as bare enum strings or as objects with a
// `value` property, and neither may fail the row's decode and take the whole
// collection down with it (the deviceencryption fileVaultStates precedent).
func TestStateReasonsDecodeDefensively(t *testing.T) {
	tests := []struct {
		name string
		raw  string
		want []string
	}{
		{"empty", `[]`, nil},
		{"objects with value", `[{"value":"offerPaused"},{"value":"safeguardHold"}]`, []string{"offerPaused", "safeguardHold"}},
		{"bare strings", `["offerPaused"]`, []string{"offerPaused"}},
		{"unexpected shape", `{"value":"offerPaused"}`, nil},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			g := &fakeGraph{bodies: map[string]string{
				policiesURL(): `{"value":[]}`,
				deploymentsURL(): `{"value":[{"id":"d1","state":{"effectiveValue":"paused","requestedValue":"paused",
					"reasons":` + tc.raw + `}}]}`,
			}}
			rec := collect(t, g)
			tw := twinFor(t, rec, deploymentEventName)
			got, ok := tw.Attrs[semconv.AttrDeploymentStateReasons]
			if len(tc.want) == 0 {
				if ok {
					t.Errorf("state_reasons = %q, want the attribute omitted", got)
				}
				return
			}
			want := strings.Join(tc.want, ",")
			if got != want {
				t.Errorf("state_reasons = %q, want %q", got, want)
			}
		})
	}
}

// Two levels of @odata.type on one record, both read as discriminators.
func TestDeploymentTwinReadsBothDiscriminators(t *testing.T) {
	rec := collect(t, liveGraph())
	tw := twinFor(t, rec, deploymentEventName)

	if got := tw.Attrs[semconv.AttrUpdateContentType]; got != "catalogContent" {
		t.Errorf("update_content_type = %q, want the short-formed content discriminator catalogContent", got)
	}
	if got := tw.Attrs[semconv.AttrCatalogEntryType]; got != "qualityUpdateCatalogEntry" {
		t.Errorf("catalog_entry_type = %q, want qualityUpdateCatalogEntry", got)
	}
}

// The quality-variant fields are read ONLY when the discriminator says quality.
// A featureUpdateCatalogEntry carries a different field set, so a structural
// decode would map whatever happened to be present under a quality key.
func TestCatalogEntryVariantFieldsFollowTheDiscriminator(t *testing.T) {
	tests := []struct {
		name            string
		entry           string
		wantType        string
		wantClassified  bool
		wantClassString string
	}{
		{
			name: "quality entry maps classification and cadence",
			entry: `{"@odata.type":"#microsoft.graph.windowsUpdates.qualityUpdateCatalogEntry",
				"qualityUpdateClassification":"security","qualityUpdateCadence":"monthly"}`,
			wantType:        "qualityUpdateCatalogEntry",
			wantClassified:  true,
			wantClassString: "security",
		},
		{
			// The trap: a feature entry with a stray quality-shaped field must
			// not be read as a quality entry.
			name: "feature entry maps neither, even when the fields are present",
			entry: `{"@odata.type":"#microsoft.graph.windowsUpdates.featureUpdateCatalogEntry",
				"version":"25H2","qualityUpdateClassification":"security","qualityUpdateCadence":"monthly"}`,
			wantType:       "featureUpdateCatalogEntry",
			wantClassified: false,
		},
		{
			name:           "driver entry maps neither",
			entry:          `{"@odata.type":"#microsoft.graph.windowsUpdates.driverUpdateCatalogEntry"}`,
			wantType:       "driverUpdateCatalogEntry",
			wantClassified: false,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			g := &fakeGraph{bodies: map[string]string{
				policiesURL(): `{"value":[]}`,
				deploymentsURL(): `{"value":[{"id":"d1","content":{
					"@odata.type":"#microsoft.graph.windowsUpdates.catalogContent",
					"catalogEntry":` + tc.entry + `}}]}`,
			}}
			rec := collect(t, g)
			tw := twinFor(t, rec, deploymentEventName)
			if got := tw.Attrs[semconv.AttrCatalogEntryType]; got != tc.wantType {
				t.Errorf("catalog_entry_type = %q, want %q", got, tc.wantType)
			}
			cls, ok := tw.Attrs[semconv.AttrUpdateClassification]
			if !tc.wantClassified {
				if ok {
					t.Errorf("update_classification = %q on a %s — quality-only fields must follow the discriminator", cls, tc.wantType)
				}
				if cad, ok := tw.Attrs[semconv.AttrUpdateCadence]; ok {
					t.Errorf("update_cadence = %q on a %s", cad, tc.wantType)
				}
				return
			}
			if cls != tc.wantClassString {
				t.Errorf("update_classification = %q, want %q", cls, tc.wantClassString)
			}
		})
	}
}

// The empty catalogEntry id and the null displayName on the live row: an empty
// id is not an identifier, so it is omitted rather than emitted as "".
func TestEmptyCatalogEntryIdAndNullNameAreOmitted(t *testing.T) {
	rec := collect(t, liveGraph())
	tw := twinFor(t, rec, deploymentEventName)

	if got, ok := tw.Attrs[semconv.AttrCatalogEntryId]; ok {
		t.Errorf("catalog_entry_id = %q, want the attribute omitted (live wire sends \"\")", got)
	}
	if got, ok := tw.Attrs[semconv.AttrDisplayName]; ok {
		t.Errorf("display_name = %q, want the attribute omitted (live wire sends null)", got)
	}
	// A REAL id must still come through — the omission is about "" only.
	g := &fakeGraph{bodies: map[string]string{
		policiesURL(): `{"value":[]}`,
		deploymentsURL(): `{"value":[{"id":"d1","content":{
			"@odata.type":"#microsoft.graph.windowsUpdates.catalogContent",
			"catalogEntry":{"@odata.type":"#microsoft.graph.windowsUpdates.qualityUpdateCatalogEntry",
			"id":"10.0.26100.4770","displayName":"2026-07 Cumulative Update"}}}]}`,
	}}
	tw2 := twinFor(t, collect(t, g), deploymentEventName)
	if got := tw2.Attrs[semconv.AttrCatalogEntryId]; got != "10.0.26100.4770" {
		t.Errorf("catalog_entry_id = %q, want the real id", got)
	}
	if got := tw2.Attrs[semconv.AttrDisplayName]; got != "2026-07 Cumulative Update" {
		t.Errorf("display_name = %q, want the real name", got)
	}
}

// 0001-01-01T00:00:00Z is the .NET zero date meaning "never evaluated". It must
// never reach the twin as a timestamp; the FACT it encodes survives as a count.
func TestDotNetZeroDateIsNeverEmittedAsATimestamp(t *testing.T) {
	rec := collect(t, liveGraph())

	tw := twinWithAttr(t, rec, policyEventName, semconv.AttrPolicyId, "0fa55cf5-4598-4fe3-b6c1-a724e5035f9d")
	if got, ok := tw.Attrs[semconv.AttrRuleLastEvaluatedDateTimes]; ok {
		t.Errorf("rule_last_evaluated_date_times = %q, want omitted — the only rule has never been evaluated", got)
	}
	if got := tw.Attrs[semconv.AttrRulesNeverEvaluated]; got != "1" {
		t.Errorf("rules_never_evaluated = %q, want 1", got)
	}
}

func TestZeroDateVariantsAreAllRejected(t *testing.T) {
	tests := []struct {
		name string
		raw  string
		want string // "" means omitted
	}{
		{"the live zero date", `"0001-01-01T00:00:00Z"`, ""},
		{"the .NET seven-digit zero date", `"0001-01-01T00:00:00.0000000Z"`, ""},
		{"an offset zero date", `"0001-01-01T00:00:00+00:00"`, ""},
		{"unparseable", `"not a date"`, ""},
		{"empty", `""`, ""},
		{"a real evaluation", `"2026-07-22T03:00:00Z"`, "2026-07-22T03:00:00Z"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			g := &fakeGraph{bodies: map[string]string{
				policiesURL(): `{"value":[{"id":"p1","complianceChangeRules":[
					{"@odata.type":"#microsoft.graph.windowsUpdates.contentApprovalRule",
					 "lastEvaluatedDateTime":` + tc.raw + `}]}]}`,
				deploymentsURL(): `{"value":[]}`,
			}}
			rec := collect(t, g)
			tw := twinFor(t, rec, policyEventName)
			got, ok := tw.Attrs[semconv.AttrRuleLastEvaluatedDateTimes]
			if tc.want == "" {
				if ok {
					t.Errorf("rule_last_evaluated_date_times = %q, want omitted", got)
				}
				if n := tw.Attrs[semconv.AttrRulesNeverEvaluated]; n != "1" {
					t.Errorf("rules_never_evaluated = %q, want 1", n)
				}
				return
			}
			if got != tc.want {
				t.Errorf("rule_last_evaluated_date_times = %q, want %q", got, tc.want)
			}
			if n, ok := tw.Attrs[semconv.AttrRulesNeverEvaluated]; ok && n != "0" {
				t.Errorf("rules_never_evaluated = %q, want 0 or omitted", n)
			}
		})
	}
}

// The zero-date rule applies to EVERY timestamp on these records, not just the
// one the issue happened to observe it on — the same .NET serializer produces
// all of them.
func TestZeroDateIsRejectedOnEveryTimestampField(t *testing.T) {
	g := &fakeGraph{bodies: map[string]string{
		policiesURL(): `{"value":[{"id":"p1","createdDateTime":"0001-01-01T00:00:00Z"}]}`,
		deploymentsURL(): `{"value":[{"id":"d1","createdDateTime":"0001-01-01T00:00:00Z",
			"lastModifiedDateTime":"0001-01-01T00:00:00Z","content":{
			"@odata.type":"#microsoft.graph.windowsUpdates.catalogContent",
			"catalogEntry":{"@odata.type":"#microsoft.graph.windowsUpdates.qualityUpdateCatalogEntry",
			"releaseDateTime":"0001-01-01T00:00:00Z"}}}]}`,
	}}
	rec := collect(t, g)

	pol := twinFor(t, rec, policyEventName)
	if got, ok := pol.Attrs[semconv.AttrCreatedDateTime]; ok {
		t.Errorf("policy created_date_time = %q, want omitted", got)
	}
	dep := twinFor(t, rec, deploymentEventName)
	for _, k := range []string{semconv.AttrCreatedDateTime, semconv.AttrLastModifiedDateTime, semconv.AttrUpdateReleaseDateTime} {
		if got, ok := dep.Attrs[k]; ok {
			t.Errorf("deployment %s = %q, want omitted", k, got)
		}
	}
}

// durationBeforeDeploymentStart is an ISO-8601 duration STRING. It is emitted
// verbatim, one entry per rule, and never converted to a number.
func TestDeploymentStartDelayIsCarriedVerbatim(t *testing.T) {
	rec := collect(t, liveGraph())
	tw := twinWithAttr(t, rec, policyEventName, semconv.AttrPolicyId, "0fa55cf5-4598-4fe3-b6c1-a724e5035f9d")
	if got := tw.Attrs[semconv.AttrDeploymentStartDelays]; got != "PT0S" {
		t.Errorf("deployment_start_delays = %q, want PT0S verbatim", got)
	}
}

// The quality policy and the driver policy differ ONLY in their content filter
// variant, which is exactly the case a structural decode gets wrong.
func TestPolicyTwinsFollowTheContentFilterDiscriminator(t *testing.T) {
	rec := collect(t, liveGraph())

	quality := twinWithAttr(t, rec, policyEventName, semconv.AttrPolicyId, "0fa55cf5-4598-4fe3-b6c1-a724e5035f9d")
	if got := quality.Attrs[semconv.AttrContentFilterTypes]; got != "qualityUpdateFilter" {
		t.Errorf("quality policy content_filter_types = %q", got)
	}
	if got := quality.Attrs[semconv.AttrContentFilterClassifications]; got != "security" {
		t.Errorf("quality policy content_filter_classifications = %q, want security", got)
	}
	if got := quality.Attrs[semconv.AttrContentFilterCadences]; got != "monthly" {
		t.Errorf("quality policy content_filter_cadences = %q, want monthly", got)
	}

	driver := twinWithAttr(t, rec, policyEventName, semconv.AttrPolicyId, "a59bda37-7cdd-4683-84a2-ed46dd81a388")
	if got := driver.Attrs[semconv.AttrContentFilterTypes]; got != "driverUpdateFilter" {
		t.Errorf("driver policy content_filter_types = %q", got)
	}
	for _, k := range []string{semconv.AttrContentFilterClassifications, semconv.AttrContentFilterCadences} {
		if got, ok := driver.Attrs[k]; ok {
			t.Errorf("driver policy %s = %q — driverUpdateFilter carries neither field on the live wire", k, got)
		}
	}
	if got := driver.Attrs[semconv.AttrComplianceChangeRuleTypes]; got != "contentApprovalRule" {
		t.Errorf("driver policy compliance_change_rule_types = %q", got)
	}
}

func TestPolicyTwinCarriesDeploymentSettings(t *testing.T) {
	rec := collect(t, liveGraph())

	quality := twinWithAttr(t, rec, policyEventName, semconv.AttrPolicyId, "0fa55cf5-4598-4fe3-b6c1-a724e5035f9d")
	if got := quality.Attrs[semconv.AttrIsHotpatchEnabled]; got != "true" {
		t.Errorf("is_hotpatch_enabled = %q, want true", got)
	}
	if got := quality.Attrs[semconv.AttrOfferAsOptional]; got != "false" {
		t.Errorf("offer_as_optional = %q, want false", got)
	}
	// daysUntilForcedReboot is null on this row: absent, not zero.
	if got, ok := quality.Attrs[semconv.AttrDaysUntilForcedReboot]; ok {
		t.Errorf("days_until_forced_reboot = %q, want omitted for a null wire value", got)
	}
	if got := quality.Attrs[semconv.AttrAudienceId]; got != "9c6c8e6b-e85b-4cd5-8b96-73cbc4aac678" {
		t.Errorf("audience_id = %q", got)
	}
	if got := quality.Attrs[semconv.AttrAutoEnrollmentUpdateCategories]; got != "quality" {
		t.Errorf("auto_enrollment_update_categories = %q", got)
	}

	driver := twinWithAttr(t, rec, policyEventName, semconv.AttrPolicyId, "a59bda37-7cdd-4683-84a2-ed46dd81a388")
	if got := driver.Attrs[semconv.AttrOfferWhileRecommendedBy]; got != "microsoft" {
		t.Errorf("offer_while_recommended_by = %q, want microsoft", got)
	}
	// userExperience is null on this row — none of its fields may appear.
	for _, k := range []string{semconv.AttrIsHotpatchEnabled, semconv.AttrOfferAsOptional, semconv.AttrDaysUntilForcedReboot} {
		if got, ok := driver.Attrs[k]; ok {
			t.Errorf("driver policy %s = %q, want omitted (userExperience is null)", k, got)
		}
	}
}

// daysUntilForcedReboot is 0 on the live deployment and null on the live policy.
// Absent field != sentinel: a bare int would publish a fabricated 0 for the null.
func TestZeroDaysUntilForcedRebootIsARealValue(t *testing.T) {
	rec := collect(t, liveGraph())
	tw := twinFor(t, rec, deploymentEventName)
	if got := tw.Attrs[semconv.AttrDaysUntilForcedReboot]; got != "0" {
		t.Errorf("days_until_forced_reboot = %q, want a real 0 — the wire sent 0, not null", got)
	}
}

func TestDeploymentTwinCarriesExpediteAndIdentity(t *testing.T) {
	rec := collect(t, liveGraph())
	tw := twinFor(t, rec, deploymentEventName)

	want := map[string]string{
		semconv.AttrDeploymentId:          "a964123e-df58-4910-a0cb-483ebfb2f2d6",
		semconv.AttrCreatedDateTime:       "2026-07-21T22:26:29.2238015Z",
		semconv.AttrLastModifiedDateTime:  "2026-07-24T18:02:31.0492953Z",
		semconv.AttrAudienceId:            "7f48457d-4be7-48b6-98b2-a6c760305eda",
		semconv.AttrUpdateReleaseDateTime: "2026-07-14T00:00:00Z",
		semconv.AttrUpdateClassification:  "security",
		semconv.AttrUpdateCadence:         "monthly",
		semconv.AttrIsExpeditable:         "false",
		semconv.AttrIsExpedited:           "true",
		semconv.AttrIsReadinessTest:       "false",
	}
	for k, v := range want {
		if got := tw.Attrs[k]; got != v {
			t.Errorf("twin attr %s = %q, want %q", k, got, v)
		}
	}
}

// products is deliberately NOT collected (#259). This pins the decision: the
// collector must never issue that request, so a later "while we're here" change
// fails a test instead of quietly adding 17 constant rows per poll.
func TestProductsCatalogueIsNeverFetched(t *testing.T) {
	g := liveGraph()
	rec := telemetrytest.New()
	if err := New(g, nil).Collect(context.Background(), rec.Emitter()); err != nil {
		t.Fatalf("Collect: %v", err)
	}
	// fakeGraph errors on any URL it has no body for, and it was given only the
	// two collected paths — so a products fetch would already have failed the
	// Collect above. Pin the intent explicitly too.
	for _, l := range rec.LogRecords() {
		if l.EventName != policyEventName && l.EventName != deploymentEventName {
			t.Errorf("unexpected event %q — products is not collected", l.EventName)
		}
	}
	for _, name := range rec.MetricNames() {
		if name != policiesMetricName && name != deploymentsMetricName {
			t.Errorf("unexpected metric %q — products is not collected", name)
		}
	}
}

func TestCollectFollowsNextLink(t *testing.T) {
	page2 := defaultBaseURL + updatePoliciesPath + "?$skiptoken=abc"
	g := &fakeGraph{bodies: map[string]string{
		policiesURL():    `{"@odata.nextLink":"` + page2 + `","value":[{"id":"p1","autoEnrollmentUpdateCategories":["quality"]}]}`,
		page2:            `{"value":[{"id":"p2","autoEnrollmentUpdateCategories":["quality"]}]}`,
		deploymentsURL(): `{"value":[]}`,
	}}
	rec := collect(t, g)
	if n := len(rec.LogRecords()); n != 2 {
		t.Fatalf("got %d twins, want 2 (both pages consumed)", n)
	}
	points := rec.MetricPoints(policiesMetricName)
	if len(points) != 1 || points[0].Value != 2 {
		t.Fatalf("policy gauge = %+v, want a single series of 2", points)
	}
}

func TestForbiddenSkipsGracefully(t *testing.T) {
	forbidden := errors.New("graphclient: GET ...: status 403: forbidden")
	g := &fakeGraph{errs: map[string]error{policiesURL(): forbidden, deploymentsURL(): forbidden}}
	rec := telemetrytest.New()
	if err := New(g, nil).Collect(context.Background(), rec.Emitter()); err != nil {
		t.Fatalf("403 should be a graceful skip, got: %v", err)
	}
	if len(rec.LogRecords()) != 0 || len(rec.MetricNames()) != 0 {
		t.Error("expected no emissions on 403")
	}
}

// A failure on one segment must not clear the other's gauge: GaugeSnapshot
// replaces the whole series set, so snapshotting an empty slice for a segment
// that was never read would claim the tenant has zero of them.
func TestOneSegmentFailingLeavesTheOtherAlone(t *testing.T) {
	g := &fakeGraph{
		bodies: map[string]string{policiesURL(): livePolicies},
		errs:   map[string]error{deploymentsURL(): errors.New("boom")},
	}
	rec := telemetrytest.New()
	err := New(g, nil).Collect(context.Background(), rec.Emitter())
	if err == nil {
		t.Fatal("a non-403 error on one segment must be surfaced")
	}
	if n := len(rec.MetricPoints(policiesMetricName)); n != 2 {
		t.Errorf("policy gauge has %d series, want 2 — the segment that succeeded must still emit", n)
	}
	for _, name := range rec.MetricNames() {
		if name == deploymentsMetricName {
			t.Errorf("%s was snapshotted despite its fetch failing — an empty snapshot claims zero deployments", name)
		}
	}
}

func TestEmptyCollectionsEmitNoTwins(t *testing.T) {
	g := &fakeGraph{bodies: map[string]string{
		policiesURL():    `{"value":[]}`,
		deploymentsURL(): `{"value":[]}`,
	}}
	rec := collect(t, g)
	if len(rec.LogRecords()) != 0 {
		t.Error("no rows => no twins")
	}
}

func TestCollectorContract(t *testing.T) {
	c := New(nil, nil)
	if c.Name() != collectorName || collectorName != "intune.windows_updates" {
		t.Errorf("Name() = %q, want intune.windows_updates", c.Name())
	}
	// v1.0 rejects the segment outright — 400 "Resource not found for the
	// segment 'windows'", live-measured 2026-07-24 — so this is beta-only and
	// therefore Experimental (#183).
	if defaultBaseURL != "https://graph.microsoft.com/beta" {
		t.Errorf("defaultBaseURL = %q, want the beta root", defaultBaseURL)
	}
	if !c.Experimental() {
		t.Error("Experimental() = false, want true (beta-only endpoint)")
	}
	perms := c.RequiredPermissions()
	if len(perms) != 1 || perms[0] != "WindowsUpdates.Read.All" {
		t.Errorf("RequiredPermissions = %v, want the single read-only WindowsUpdates scope", perms)
	}
	if c.DefaultInterval() != time.Hour {
		t.Errorf("DefaultInterval = %v, want 1h", c.DefaultInterval())
	}
}
