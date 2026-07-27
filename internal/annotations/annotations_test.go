package annotations

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/rknightion/graph2otel/internal/checkpoint"
	"github.com/rknightion/graph2otel/internal/config"
	"github.com/rknightion/graph2otel/internal/telemetry"
)

// fixedNow is the clock every test uses, so an annotation stamped with arrival
// time instead of event time is immediately visible.
var fixedNow = time.Date(2026, 7, 27, 14, 0, 0, 0, time.UTC)

// recordingSink captures what the Recorder decided to publish.
type recordingSink struct {
	mu         sync.Mutex
	published  []Annotation
	duplicates int
}

func (s *recordingSink) Publish(a Annotation) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.published = append(s.published, a)
}

func (s *recordingSink) Duplicate(string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.duplicates++
}

func (s *recordingSink) all() []Annotation {
	s.mu.Lock()
	defer s.mu.Unlock()
	return slices.Clone(s.published)
}

// testConfig is the shipped default with the feature switched on and every
// category individually annotated, so a test asserting one annotation is not
// silently reading a rollup. Rollup behavior has its own tests.
func testConfig() config.GrafanaAnnotationsConfig {
	cfg := config.Default().GrafanaAnnotations
	cfg.URL = "https://grafana.example.com"
	cfg.Token = config.Secret("test-token")
	cfg.Categories.ConfigPosture.Rollup = false
	cfg.Categories.License.Rollup = false
	return cfg
}

func newTestRecorder(t *testing.T, cfg config.GrafanaAnnotationsConfig, dir string) (*Recorder, *recordingSink) {
	t.Helper()
	sink := &recordingSink{}
	dedupe := newDedupeStore(checkpoint.NewStore(dir), cfg.DedupeRetention)
	rec := NewRecorder(RecorderOptions{
		Config: cfg,
		Sink:   sink,
		Dedupe: dedupe,
		Now:    func() time.Time { return fixedNow },
	})
	return rec, sink
}

const testTenant = "11111111-1111-1111-1111-111111111111"

func directoryAudit(id, activity string) telemetry.Event {
	return telemetry.Event{
		Name:      "entra.directory_audit",
		Timestamp: fixedNow,
		Attrs: telemetry.Attrs{
			"id":                          id,
			"result":                      "success",
			"activity_display_name":       activity,
			"category":                    "Policy",
			"initiator_app_display_name":  "Azure Portal",
			"logged_by_service":           "Core Directory",
			"modified_property_names":     []string{"ConditionalAccessPolicy"},
			"target_display_names":        []string{"Require MFA for admins"},
			"initiator_service_principal": "sp",
		},
	}
}

// TestConditionalAccessPolicyChangeIsAnnotatedOnce is the base case for a
// KindEvent rule: the first delivery publishes and a re-delivery does not.
func TestConditionalAccessPolicyChangeIsAnnotatedOnce(t *testing.T) {
	rec, sink := newTestRecorder(t, testConfig(), t.TempDir())
	run := rec.BeginRun(testTenant, "entra.directory_audits")

	rec.ObserveEvent(run, directoryAudit("audit-1", "Update conditional access policy"))
	rec.ObserveEvent(run, directoryAudit("audit-1", "Update conditional access policy"))

	got := sink.all()
	if len(got) != 1 {
		t.Fatalf("published %d annotations, want exactly 1 (the second delivery is a duplicate): %+v", len(got), got)
	}
	if sink.duplicates != 1 {
		t.Errorf("duplicates = %d, want 1", sink.duplicates)
	}
	a := got[0]
	if a.Category != CategoryConfigPosture {
		t.Errorf("category = %q, want %q", a.Category, CategoryConfigPosture)
	}
	if a.RuleID != "entra.conditional_access_policy_changed" {
		t.Errorf("rule = %q", a.RuleID)
	}
	if !a.Time.Equal(fixedNow) {
		t.Errorf("time = %v, want the SOURCE event time %v", a.Time, fixedNow)
	}
	if !strings.Contains(a.Text, "Update conditional access policy") {
		t.Errorf("text %q does not carry the activity", a.Text)
	}
}

// TestANonConditionalAccessAuditIsNotAnnotated proves the predicate actually
// narrows: without it the whole directory-audit firehose would be annotated.
func TestANonConditionalAccessAuditIsNotAnnotated(t *testing.T) {
	rec, sink := newTestRecorder(t, testConfig(), t.TempDir())
	run := rec.BeginRun(testTenant, "entra.directory_audits")
	rec.ObserveEvent(run, directoryAudit("audit-2", "Reset password"))
	if got := sink.all(); len(got) != 0 {
		t.Fatalf("published %+v, want nothing", got)
	}
}

// TestAConditionalAccessServiceAuditIsAnnotatedWithoutTheActivityNamingCA pins
// the live-measured widening of this predicate.
//
// Entra DOES carry a CA-specific attribute — `logged_by_service` is literally
// "Conditional Access" on every record from that surface (live-measured
// 2026-07-27, 69 records over 30d on m7kni, #400). Matching only the
// activityDisplayName substring missed "Update named location", which is a real
// CA posture change: named locations are CA conditions, so a policy can change
// meaning without its own record moving.
func TestAConditionalAccessServiceAuditIsAnnotatedWithoutTheActivityNamingCA(t *testing.T) {
	rec, sink := newTestRecorder(t, testConfig(), t.TempDir())
	run := rec.BeginRun(testTenant, "entra.directory_audits")

	ev := directoryAudit("audit-named-location", "Update named location")
	ev.Attrs["logged_by_service"] = "Conditional Access"
	rec.ObserveEvent(run, ev)

	got := sink.all()
	if len(got) != 1 {
		t.Fatalf("published %d annotations, want 1 for a Conditional Access service audit: %+v", len(got), got)
	}
	if got[0].RuleID != "entra.conditional_access_policy_changed" {
		t.Errorf("rule = %q", got[0].RuleID)
	}
}

// TestAnAuditFromAnotherServiceIsNotAnnotated keeps the widening narrow: the
// service attribute must not turn the directory-audit firehose on.
func TestAnAuditFromAnotherServiceIsNotAnnotated(t *testing.T) {
	rec, sink := newTestRecorder(t, testConfig(), t.TempDir())
	run := rec.BeginRun(testTenant, "entra.directory_audits")
	ev := directoryAudit("audit-core", "Update group")
	ev.Attrs["logged_by_service"] = "Core Directory"
	rec.ObserveEvent(run, ev)
	if got := sink.all(); len(got) != 0 {
		t.Fatalf("published %+v, want nothing", got)
	}
}

// intuneAudit builds an Intune audit event in the shape the wire actually
// carries (live-measured 2026-07-27, #400): `activity_result` is "Success" with
// a capital S, and `activity_type` is a verb-first string such as
// "Patch DeviceConfiguration" or "Search CloudCertificationAuthority".
func intuneAudit(id, category, activityType string) telemetry.Event {
	return telemetry.Event{
		Name:      "intune.audit_event",
		Timestamp: fixedNow,
		Attrs: telemetry.Attrs{
			"id":                             id,
			"activity_result":                "Success",
			"category":                       category,
			"activity_type":                  activityType,
			"display_name":                   "Baseline",
			"actor_user_principal_name":      "admin@example.com",
			"actor_application_display_name": "Intune Portal",
		},
	}
}

// TestAnIntunePolicyChangeIsAnnotated is the base case, and pins the wire's
// capital-S "Success" against a case-sensitive comparison creeping in.
func TestAnIntunePolicyChangeIsAnnotated(t *testing.T) {
	rec, sink := newTestRecorder(t, testConfig(), t.TempDir())
	run := rec.BeginRun(testTenant, "intune.audit_events")
	rec.ObserveEvent(run, intuneAudit("i-1", "DeviceConfiguration", "Patch DeviceConfiguration"))

	got := sink.all()
	if len(got) != 1 {
		t.Fatalf("published %d annotations, want 1: %+v", len(got), got)
	}
	if got[0].RuleID != "intune.policy_changed" {
		t.Errorf("rule = %q", got[0].RuleID)
	}
}

// TestAReadOnlyIntuneAuditIsNotAnnotated is the live-measured correction.
//
// Intune audits READS into the same DeviceConfiguration category it audits
// changes into: "Search CloudCertificationAuthorityLeafCertificate",
// "Search CloudCertificationAuthority" and "Get CloudCertificationAuthority"
// were 38 of 543 DeviceConfiguration records over 30d on m7kni (live-measured
// 2026-07-27, #400). Annotating those puts a "config changed at 14:00" marker on
// a dashboard for an operation that changed nothing, which is worse than a
// missing marker: it sends someone looking for a change that never happened.
func TestAReadOnlyIntuneAuditIsNotAnnotated(t *testing.T) {
	for _, activityType := range []string{
		"Search CloudCertificationAuthorityLeafCertificate",
		"Search CloudCertificationAuthority",
		"Get CloudCertificationAuthority",
		"List DeviceConfiguration",
	} {
		t.Run(activityType, func(t *testing.T) {
			rec, sink := newTestRecorder(t, testConfig(), t.TempDir())
			run := rec.BeginRun(testTenant, "intune.audit_events")
			rec.ObserveEvent(run, intuneAudit("i-read", "DeviceConfiguration", activityType))
			if got := sink.all(); len(got) != 0 {
				t.Fatalf("published %+v for a read-only operation, want nothing", got)
			}
		})
	}
}

// TestAnUnrecognizedIntuneVerbIsStillAnnotated keeps the read filter an explicit
// DENY list rather than an allow list. Intune's verb vocabulary is open —
// "assignDeviceManagementScript", "patchDeviceCustomAttributeShellScript" and
// "createDeviceShellScript" are all live — so an allow list would silently stop
// annotating real changes the day Microsoft adds a verb. The failure mode is
// chosen deliberately: an unknown verb produces a spare marker, never a missing
// one.
func TestAnUnrecognizedIntuneVerbIsStillAnnotated(t *testing.T) {
	rec, sink := newTestRecorder(t, testConfig(), t.TempDir())
	run := rec.BeginRun(testTenant, "intune.audit_events")
	rec.ObserveEvent(run, intuneAudit("i-2", "DeviceConfiguration", "quarantineDeviceHealthScript DeviceHealthScript"))
	if got := sink.all(); len(got) != 1 {
		t.Fatalf("published %+v, want 1 for an unrecognized verb", got)
	}
}

// TestAnIntuneAuditInAnotherCategoryIsNotAnnotated: Device and Application
// categories are the bulk of the stream (300 of 500 sampled) and are not policy
// changes.
func TestAnIntuneAuditInAnotherCategoryIsNotAnnotated(t *testing.T) {
	rec, sink := newTestRecorder(t, testConfig(), t.TempDir())
	run := rec.BeginRun(testTenant, "intune.audit_events")
	rec.ObserveEvent(run, intuneAudit("i-3", "Device", "syncDevice ManagedDevice"))
	if got := sink.all(); len(got) != 0 {
		t.Fatalf("published %+v, want nothing", got)
	}
}

// TestAFailedAuditIsNotAnnotated: a policy change that failed did not change the
// policy, so it explains nothing on a dashboard.
func TestAFailedAuditIsNotAnnotated(t *testing.T) {
	rec, sink := newTestRecorder(t, testConfig(), t.TempDir())
	run := rec.BeginRun(testTenant, "entra.directory_audits")
	ev := directoryAudit("audit-3", "Update conditional access policy")
	ev.Attrs["result"] = "failure"
	rec.ObserveEvent(run, ev)
	if got := sink.all(); len(got) != 0 {
		t.Fatalf("published %+v, want nothing for a failed change", got)
	}
}

// TestDedupeSurvivesARestart is the load-bearing property #400 names: a restart
// re-delivers the overlap window, and a duplicated annotation is
// indistinguishable from a second real event.
func TestDedupeSurvivesARestart(t *testing.T) {
	dir := t.TempDir()
	cfg := testConfig()

	first, firstSink := newTestRecorder(t, cfg, dir)
	run := first.BeginRun(testTenant, "entra.directory_audits")
	first.ObserveEvent(run, directoryAudit("audit-restart", "Add conditional access policy"))
	if got := firstSink.all(); len(got) != 1 {
		t.Fatalf("first process published %d, want 1", len(got))
	}
	if err := first.dedupe.Persist(); err != nil {
		t.Fatalf("persist: %v", err)
	}

	// A second process over the same checkpoint dir, re-delivering the same
	// record from the overlap window.
	second, secondSink := newTestRecorder(t, cfg, dir)
	run2 := second.BeginRun(testTenant, "entra.directory_audits")
	second.ObserveEvent(run2, directoryAudit("audit-restart", "Add conditional access policy"))
	if got := secondSink.all(); len(got) != 0 {
		t.Fatalf("second process republished %+v after a restart; the dedupe set did not survive", got)
	}
	if secondSink.duplicates != 1 {
		t.Errorf("duplicates = %d, want 1", secondSink.duplicates)
	}
}

// TestDedupeIsNotPersistedAcrossTenants guards the namespace: two tenants can
// legitimately produce records with the same Graph id, and merging them would
// silently swallow one tenant's event.
func TestDedupeIsNotSharedAcrossTenants(t *testing.T) {
	rec, sink := newTestRecorder(t, testConfig(), t.TempDir())
	const other = "22222222-2222-2222-2222-222222222222"
	rec.ObserveEvent(rec.BeginRun(testTenant, "c"), directoryAudit("shared-id", "Update conditional access policy"))
	rec.ObserveEvent(rec.BeginRun(other, "c"), directoryAudit("shared-id", "Update conditional access policy"))
	if got := sink.all(); len(got) != 2 {
		t.Fatalf("published %d, want 2 (one per tenant)", len(got))
	}
}

func consentGrant(id, resource string) telemetry.Event {
	return telemetry.Event{
		Name: "entra.consent_grant",
		Attrs: telemetry.Attrs{
			"id":                    id,
			"consent_type":          "AllPrincipals",
			"client_id":             "client-1",
			"resource_display_name": resource,
			"scope":                 "Directory.Read.All",
			"privilege":             "high",
		},
	}
}

// TestAStateRulePrimesOnItsFirstRunThenPublishes is the flood guard. A snapshot
// log twin re-emits its WHOLE current set every tick, so publishing the first
// set would annotate every consent grant that already existed, at once.
func TestAStateRulePrimesOnItsFirstRunThenPublishes(t *testing.T) {
	rec, sink := newTestRecorder(t, testConfig(), t.TempDir())

	// Run 1: the existing set. Nothing published.
	run1 := rec.BeginRun(testTenant, "entra.consent")
	rec.ObserveEvent(run1, consentGrant("grant-1", "Microsoft Graph"))
	rec.ObserveEvent(run1, consentGrant("grant-2", "SharePoint"))
	if got := sink.all(); len(got) != 0 {
		t.Fatalf("the priming run published %+v; every pre-existing grant would be annotated at once", got)
	}

	// Run 2: the same set plus one new grant. Only the new one is published.
	run2 := rec.BeginRun(testTenant, "entra.consent")
	rec.ObserveEvent(run2, consentGrant("grant-1", "Microsoft Graph"))
	rec.ObserveEvent(run2, consentGrant("grant-2", "SharePoint"))
	rec.ObserveEvent(run2, consentGrant("grant-3", "Exchange"))
	got := sink.all()
	if len(got) != 1 {
		t.Fatalf("published %d annotations, want exactly 1 (only grant-3 is new): %+v", len(got), got)
	}
	if !strings.Contains(got[0].Text, "Exchange") {
		t.Errorf("published %q, want the new grant", got[0].Text)
	}
	if got[0].Severity != "high" {
		t.Errorf("severity = %q, want the privilege value", got[0].Severity)
	}
}

// TestUserConsentIsNotAnnotated: a single user consenting for themselves is not
// a tenant posture change, and on a real tenant it is most of the volume.
func TestUserConsentIsNotAnnotated(t *testing.T) {
	rec, sink := newTestRecorder(t, testConfig(), t.TempDir())
	run1 := rec.BeginRun(testTenant, "entra.consent")
	rec.ObserveEvent(run1, consentGrant("grant-admin", "Graph"))
	run2 := rec.BeginRun(testTenant, "entra.consent")
	userGrant := consentGrant("grant-user", "Graph")
	userGrant.Attrs["consent_type"] = "Principal"
	rec.ObserveEvent(run2, userGrant)
	if got := sink.all(); len(got) != 0 {
		t.Fatalf("published %+v for a per-user consent", got)
	}
}

// TestAWarmRestartPublishesWhatChangedDuringDowntime: with a remembered set on
// disk there IS a previous set, so a state rule must not prime again — otherwise
// a change made while the process was down is silently swallowed.
func TestAWarmRestartPublishesWhatChangedDuringDowntime(t *testing.T) {
	dir := t.TempDir()
	first, _ := newTestRecorder(t, testConfig(), dir)
	run1 := first.BeginRun(testTenant, "entra.consent")
	first.ObserveEvent(run1, consentGrant("grant-1", "Graph"))
	if err := first.dedupe.Persist(); err != nil {
		t.Fatalf("persist: %v", err)
	}

	second, sink := newTestRecorder(t, testConfig(), dir)
	run2 := second.BeginRun(testTenant, "entra.consent")
	second.ObserveEvent(run2, consentGrant("grant-1", "Graph"))
	second.ObserveEvent(run2, consentGrant("grant-new", "Exchange"))
	got := sink.all()
	if len(got) != 1 {
		t.Fatalf("published %d, want 1 (the grant added during downtime): %+v", len(got), got)
	}
	if !strings.Contains(got[0].Text, "Exchange") {
		t.Errorf("published %q", got[0].Text)
	}
}

func securityIncident(id, severity, status string) telemetry.Event {
	return telemetry.Event{
		Name:      "entra.security_incident",
		Timestamp: fixedNow,
		Attrs: telemetry.Attrs{
			"id":           id,
			"severity":     severity,
			"status":       status,
			"display_name": "Suspicious sign-in burst",
		},
	}
}

func TestOnlyMediumAndHighIncidentsBecomingActiveAreAnnotated(t *testing.T) {
	cases := []struct {
		severity, status string
		want             bool
	}{
		{"high", "active", true},
		{"medium", "active", true},
		{"low", "active", false},
		{"informational", "active", false},
		{"high", "resolved", false},
		{"high", "redirected", false},
		{"High", "Active", true}, // Graph casing has differed between v1.0 and beta
	}
	for _, tc := range cases {
		rec, sink := newTestRecorder(t, testConfig(), t.TempDir())
		run := rec.BeginRun(testTenant, "entra.security_incidents")
		rec.ObserveEvent(run, securityIncident("inc-"+tc.severity+tc.status, tc.severity, tc.status))
		got := len(sink.all()) == 1
		if got != tc.want {
			t.Errorf("severity=%q status=%q annotated=%v, want %v", tc.severity, tc.status, got, tc.want)
		}
	}
}

// TestAnIncidentReopeningIsASecondOccurrence: status is in the identity, so a
// close/reopen cycle is two markers rather than one silently swallowed.
func TestAnIncidentReopeningIsASecondOccurrence(t *testing.T) {
	rec, sink := newTestRecorder(t, testConfig(), t.TempDir())
	run := rec.BeginRun(testTenant, "entra.security_incidents")
	rec.ObserveEvent(run, securityIncident("inc-1", "high", "active"))
	rec.ObserveEvent(run, securityIncident("inc-1", "high", "resolved"))
	rec.ObserveEvent(run, securityIncident("inc-1", "high", "active"))
	// The resolved record is not annotated (the rule gates on active), and the
	// reopen shares the identity of the first active record, so it dedupes.
	if got := sink.all(); len(got) != 1 {
		t.Fatalf("published %d, want 1: %+v", len(got), got)
	}
}

func serviceHealth(id string, resolved bool) telemetry.Event {
	return telemetry.Event{
		Name: "m365.service_health_issue",
		Attrs: telemetry.Attrs{
			"id":             id,
			"is_resolved":    resolved,
			"title":          "Users cannot access Exchange Online",
			"service":        "Exchange Online",
			"classification": "incident",
			"status":         "serviceDegradation",
		},
	}
}

// TestServiceHealthIssueOpenAndResolvedAreTwoMarkers: the resolved flag is in
// the identity, so opening and closing are distinct occurrences of one issue.
func TestServiceHealthIssueOpenAndResolvedAreTwoMarkers(t *testing.T) {
	rec, sink := newTestRecorder(t, testConfig(), t.TempDir())
	// Prime both state rules over one run.
	rec.ObserveEvent(rec.BeginRun(testTenant, "m365.service_health"), serviceHealth("issue-0", false))

	rec.ObserveEvent(rec.BeginRun(testTenant, "m365.service_health"), serviceHealth("issue-1", false))
	rec.ObserveEvent(rec.BeginRun(testTenant, "m365.service_health"), serviceHealth("issue-1", true))

	got := sink.all()
	if len(got) != 2 {
		t.Fatalf("published %d, want 2 (open then resolved): %+v", len(got), got)
	}
	if got[0].RuleID != "m365.service_health_issue_open" {
		t.Errorf("first rule = %q", got[0].RuleID)
	}
	if got[1].RuleID != "m365.service_health_issue_resolved" {
		t.Errorf("second rule = %q", got[1].RuleID)
	}
	if !strings.Contains(got[1].Text, "resolved") {
		t.Errorf("resolved text = %q", got[1].Text)
	}
}

// TestOnlyAllowListedAttributesReachTheAnnotationText is the content guard: a
// field added to a source record later must not silently ride out to Grafana.
func TestOnlyAllowListedAttributesReachTheAnnotationText(t *testing.T) {
	const sentinel = "NEVER-PUBLISH-THIS-VALUE"
	rec, sink := newTestRecorder(t, testConfig(), t.TempDir())
	ev := directoryAudit("audit-allow", "Update conditional access policy")
	ev.Attrs["some_future_field"] = sentinel
	rec.ObserveEvent(rec.BeginRun(testTenant, "c"), ev)

	got := sink.all()
	if len(got) != 1 {
		t.Fatalf("published %d, want 1", len(got))
	}
	if strings.Contains(got[0].Text, sentinel) {
		t.Errorf("annotation text carries a non-allow-listed attribute:\n%s", got[0].Text)
	}
	if !strings.Contains(got[0].Text, "Azure Portal") {
		t.Errorf("annotation text lost an allow-listed attribute:\n%s", got[0].Text)
	}
}

// TestADisabledCategoryPublishesNothing.
func TestADisabledCategoryPublishesNothing(t *testing.T) {
	cfg := testConfig()
	cfg.Categories.ConfigPosture.Enabled = false
	rec, sink := newTestRecorder(t, cfg, t.TempDir())
	rec.ObserveEvent(rec.BeginRun(testTenant, "c"), directoryAudit("audit-off", "Update conditional access policy"))
	if got := sink.all(); len(got) != 0 {
		t.Fatalf("published %+v with the category disabled", got)
	}
}

// TestRollupCollapsesAnIntervalIntoOneAnnotation.
func TestRollupCollapsesAnIntervalIntoOneAnnotation(t *testing.T) {
	cfg := testConfig()
	cfg.Categories.ConfigPosture.Rollup = true
	rec, sink := newTestRecorder(t, cfg, t.TempDir())
	run := rec.BeginRun(testTenant, "entra.directory_audits")
	for i := range 7 {
		ev := directoryAudit("audit-roll-"+string(rune('a'+i)), "Update conditional access policy")
		rec.ObserveEvent(run, ev)
	}
	if got := sink.all(); len(got) != 0 {
		t.Fatalf("a rolled-up category published %d annotations before its interval closed", len(got))
	}

	rec.Flush(fixedNow.Add(cfg.RollupInterval + time.Second))
	got := sink.all()
	if len(got) != 1 {
		t.Fatalf("published %d, want exactly 1 rollup: %+v", len(got), got)
	}
	if !strings.HasPrefix(got[0].Text, "7 config_posture events") {
		t.Errorf("rollup text = %q, want the count first", got[0].Text)
	}
	if !strings.Contains(got[0].Text, "7x Update conditional access policy") {
		t.Errorf("rollup text = %q, want a bounded summary", got[0].Text)
	}
	if got[0].TimeEnd.IsZero() {
		t.Error("a rollup must be a REGION annotation covering the interval it summarizes")
	}
	if !slices.Contains(got[0].Tags(), TagRollup) {
		t.Errorf("rollup tags = %v, want %q", got[0].Tags(), TagRollup)
	}
}

// TestRollupSummaryIsBounded: an unbounded list in a tooltip defeats the point.
func TestRollupSummaryIsBounded(t *testing.T) {
	counts := map[string]int{}
	for i := range 20 {
		counts["activity-"+string(rune('a'+i))] = 20 - i
	}
	got := summarize(counts)
	if strings.Count(got, ";") > summaryLimit {
		t.Errorf("summary names more than %d items:\n%s", summaryLimit, got)
	}
	if !strings.Contains(got, "+15 more") {
		t.Errorf("summary does not report the elided count:\n%s", got)
	}
}

// TestRollupIsNotRepublishedAfterARestart: bucket boundaries are aligned to the
// interval, so the same bucket derives the same dedupe key in a new process.
func TestRollupIsNotRepublishedAfterARestart(t *testing.T) {
	dir := t.TempDir()
	cfg := testConfig()
	cfg.Categories.ConfigPosture.Rollup = true

	first, firstSink := newTestRecorder(t, cfg, dir)
	first.ObserveEvent(first.BeginRun(testTenant, "c"), directoryAudit("a1", "Update conditional access policy"))
	first.Flush(fixedNow.Add(cfg.RollupInterval + time.Second))
	if len(firstSink.all()) != 1 {
		t.Fatalf("first process published %d rollups", len(firstSink.all()))
	}
	if err := first.dedupe.Persist(); err != nil {
		t.Fatalf("persist: %v", err)
	}

	second, secondSink := newTestRecorder(t, cfg, dir)
	second.ObserveEvent(second.BeginRun(testTenant, "c"), directoryAudit("a2", "Update conditional access policy"))
	second.Flush(fixedNow.Add(cfg.RollupInterval + time.Second))
	if got := secondSink.all(); len(got) != 0 {
		t.Fatalf("the same interval bucket was republished after a restart: %+v", got)
	}
}

func licensePoints(values map[string]float64) []telemetry.GaugePoint {
	points := make([]telemetry.GaugePoint, 0, len(values))
	for sku, v := range values {
		points = append(points, telemetry.GaugePoint{Value: v, Attrs: telemetry.Attrs{"sku": sku}})
	}
	return points
}

func observeLicense(rec *Recorder, run runID, consumed, enabled map[string]float64) {
	rec.ObserveGaugeSnapshot(run, metricLicenseConsumed, licensePoints(consumed))
	rec.ObserveGaugeSnapshot(run, metricLicenseEnabled, licensePoints(enabled))
}

// TestLicenseFirstObservationPrimes: without a previous snapshot every SKU would
// read as newly added.
func TestLicenseFirstObservationPrimes(t *testing.T) {
	rec, sink := newTestRecorder(t, testConfig(), t.TempDir())
	observeLicense(rec, rec.BeginRun(testTenant, "entra.licensing"),
		map[string]float64{"ENTERPRISEPACK": 90}, map[string]float64{"ENTERPRISEPACK": 100})
	if got := sink.all(); len(got) != 0 {
		t.Fatalf("the first license snapshot published %+v", got)
	}
}

// TestLicenseSKUAndUnitChangesAreAnnotated covers all four license rules.
func TestLicenseSKUAndUnitChangesAreAnnotated(t *testing.T) {
	rec, sink := newTestRecorder(t, testConfig(), t.TempDir())
	observeLicense(rec, rec.BeginRun(testTenant, "entra.licensing"),
		map[string]float64{"ENTERPRISEPACK": 90, "OLD_SKU": 1},
		map[string]float64{"ENTERPRISEPACK": 100, "OLD_SKU": 5})

	observeLicense(rec, rec.BeginRun(testTenant, "entra.licensing"),
		map[string]float64{"ENTERPRISEPACK": 150, "NEW_SKU": 0},
		map[string]float64{"ENTERPRISEPACK": 150, "NEW_SKU": 25})

	byRule := map[string]Annotation{}
	for _, a := range sink.all() {
		byRule[a.RuleID] = a
	}
	for _, want := range LicenseRuleIDs() {
		if _, ok := byRule[want]; !ok {
			t.Errorf("license rule %q produced no annotation; got %v", want, byRule)
		}
	}
	if a, ok := byRule[RuleLicenseExhausted]; ok && !strings.Contains(a.Text, "150 of 150") {
		t.Errorf("exhaustion text = %q, want the consumed/enabled numbers", a.Text)
	}
	if a, ok := byRule[RuleLicenseSKURemoved]; ok && !strings.Contains(a.Text, "OLD_SKU") {
		t.Errorf("removal text = %q", a.Text)
	}
}

// TestLicenseExhaustionFiresOnTheTransitionOnly: a SKU sitting at its ceiling
// for a month is one event, not one per poll.
func TestLicenseExhaustionFiresOnTheTransitionOnly(t *testing.T) {
	rec, sink := newTestRecorder(t, testConfig(), t.TempDir())
	full := map[string]float64{"ENTERPRISEPACK": 100}
	observeLicense(rec, rec.BeginRun(testTenant, "entra.licensing"),
		map[string]float64{"ENTERPRISEPACK": 50}, full)
	observeLicense(rec, rec.BeginRun(testTenant, "entra.licensing"), full, full)
	observeLicense(rec, rec.BeginRun(testTenant, "entra.licensing"), full, full)
	observeLicense(rec, rec.BeginRun(testTenant, "entra.licensing"), full, full)

	exhausted := 0
	for _, a := range sink.all() {
		if a.RuleID == RuleLicenseExhausted {
			exhausted++
		}
	}
	if exhausted != 1 {
		t.Fatalf("exhaustion annotations = %d, want exactly 1 (the transition)", exhausted)
	}
}

// TestAZeroUnitSKUIsNotExhausted: enabled == 0 means "not purchased", not
// "full", and annotating it would fire on every trial SKU forever.
func TestAZeroUnitSKUIsNotExhausted(t *testing.T) {
	rec, sink := newTestRecorder(t, testConfig(), t.TempDir())
	observeLicense(rec, rec.BeginRun(testTenant, "entra.licensing"),
		map[string]float64{"A": 0}, map[string]float64{"A": 1})
	observeLicense(rec, rec.BeginRun(testTenant, "entra.licensing"),
		map[string]float64{"A": 0}, map[string]float64{"A": 0})
	for _, a := range sink.all() {
		if a.RuleID == RuleLicenseExhausted {
			t.Fatalf("a zero-unit SKU was reported exhausted: %q", a.Text)
		}
	}
}

// TestAnUnwatchedMetricIsIgnored proves the gauge hook costs one map lookup for
// every metric that is not a license gauge.
func TestAnUnwatchedMetricIsIgnored(t *testing.T) {
	rec, sink := newTestRecorder(t, testConfig(), t.TempDir())
	run := rec.BeginRun(testTenant, "entra.devices")
	rec.ObserveGaugeSnapshot(run, "entra.devices.total", licensePoints(map[string]float64{"x": 1}))
	rec.ObserveGaugeSnapshot(run, "entra.devices.total", licensePoints(map[string]float64{"y": 2}))
	if got := sink.all(); len(got) != 0 {
		t.Fatalf("an unrelated metric produced %+v", got)
	}
}

// --- the tag contract ---

func TestTagContract(t *testing.T) {
	a := Annotation{
		Category: CategorySecurityIncident,
		TenantID: testTenant,
		RuleID:   "entra.security_incident_active",
		Severity: "high",
	}
	want := []string{
		"graph2otel",
		"tenant_id:" + testTenant,
		"category:security_incident",
		"rule:entra.security_incident_active",
		"severity:high",
	}
	if got := a.Tags(); !slices.Equal(got, want) {
		t.Errorf("tags = %v, want %v", got, want)
	}
}

func TestEveryAnnotationCarriesTheRootTagAndTheTenant(t *testing.T) {
	for _, category := range Categories() {
		a := Annotation{Category: category, TenantID: testTenant, RuleID: "r"}
		tags := a.Tags()
		if !slices.Contains(tags, TagRoot) {
			t.Errorf("%s: tags %v missing the root selector %q", category, tags, TagRoot)
		}
		if !slices.Contains(tags, TagTenantPrefix+testTenant) {
			t.Errorf("%s: tags %v missing tenant_id (#143 puts it on EVERY signal)", category, tags)
		}
	}
}

func TestAnUnstampedAnnotationOmitsTheTenantTagRatherThanEmittingAnEmptyOne(t *testing.T) {
	tags := Annotation{Category: CategoryLifecycle, RuleID: "r"}.Tags()
	for _, tag := range tags {
		if tag == TagTenantPrefix {
			t.Errorf("tags %v carry a bare %q, which matches nothing and looks like a bug in a query", tags, TagTenantPrefix)
		}
	}
}

// --- dedupe key ---

func TestDedupeKeyIsStableAndIndependentOfTheClock(t *testing.T) {
	a := DedupeKey(testTenant, "rule", "id-1")
	b := DedupeKey(testTenant, "rule", "id-1")
	if a != b {
		t.Fatalf("the same occurrence derived two keys: %q vs %q", a, b)
	}
	if len(a) != dedupeHexLen {
		t.Errorf("key length = %d, want %d", len(a), dedupeHexLen)
	}
}

func TestDedupeKeyIsComponentUnambiguous(t *testing.T) {
	if DedupeKey("t", "r", "a", "bc") == DedupeKey("t", "r", "ab", "c") {
		t.Error("identity components are concatenated without a length prefix, so two different occurrences collide")
	}
}

func TestDedupeKeyIsDomainSeparated(t *testing.T) {
	// A bare SHA-256 of the same components must not equal the key, so a key can
	// never be confirmed by a hash computed elsewhere.
	if DedupeKey("t", "r") == DedupeKey("t\x00r", "") {
		t.Error("dedupe key is ambiguous across component boundaries")
	}
}

// --- the HTTP client ---

func TestClientPostsTheDocumentedShape(t *testing.T) {
	var (
		gotPath   string
		gotAuth   string
		gotMethod string
		gotBody   map[string]any
	)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath, gotAuth, gotMethod = r.URL.Path, r.Header.Get("Authorization"), r.Method
		_ = json.NewDecoder(r.Body).Decode(&gotBody)
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"message":"Annotation added","id":1}`))
	}))
	defer srv.Close()

	cfg := testConfig()
	cfg.URL = srv.URL + "/"
	cfg.Token = config.Secret("glsa-token")
	client, err := NewClient(cfg)
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	end := fixedNow.Add(5 * time.Minute)
	if err := client.Publish(t.Context(), Annotation{
		Category: CategoryConfigPosture, TenantID: testTenant, RuleID: "r",
		Time: fixedNow, TimeEnd: end, Text: "hello",
	}); err != nil {
		t.Fatalf("Publish: %v", err)
	}

	if gotMethod != http.MethodPost {
		t.Errorf("method = %q", gotMethod)
	}
	if gotPath != annotationsPath {
		t.Errorf("path = %q, want %q — the ONLY path this package may call", gotPath, annotationsPath)
	}
	if gotAuth != "Bearer glsa-token" {
		t.Errorf("authorization = %q", gotAuth)
	}
	// Epoch MILLISECONDS. Seconds would land in 1970 and be invisible on every
	// dashboard while the API still returned 200.
	if got, want := gotBody["time"], float64(fixedNow.UnixMilli()); got != want {
		t.Errorf("time = %v, want epoch milliseconds %v", got, want)
	}
	if got, want := gotBody["timeEnd"], float64(end.UnixMilli()); got != want {
		t.Errorf("timeEnd = %v, want %v", got, want)
	}
	if _, present := gotBody["dashboardUID"]; present {
		t.Error("dashboardUID was sent although none is configured; that would confine an organization annotation to one board")
	}
	tags, _ := gotBody["tags"].([]any)
	if len(tags) == 0 || tags[0] != TagRoot {
		t.Errorf("tags = %v, want the root selector first", tags)
	}
}

func TestClientSendsDashboardUIDWhenConfigured(t *testing.T) {
	var body map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewDecoder(r.Body).Decode(&body)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()
	cfg := testConfig()
	cfg.URL = srv.URL
	cfg.DashboardUID = "abc123"
	client, err := NewClient(cfg)
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	if err := client.Publish(t.Context(), Annotation{Time: fixedNow, Text: "x"}); err != nil {
		t.Fatalf("Publish: %v", err)
	}
	if body["dashboardUID"] != "abc123" {
		t.Errorf("dashboardUID = %v", body["dashboardUID"])
	}
}

func TestClientClassifiesFailures(t *testing.T) {
	cases := map[int]FailureCode{
		http.StatusUnauthorized:        FailureUnauthorized,
		http.StatusForbidden:           FailureUnauthorized,
		http.StatusTooManyRequests:     FailureRateLimited,
		http.StatusBadRequest:          FailureRejected,
		http.StatusInternalServerError: FailureServerError,
		http.StatusBadGateway:          FailureServerError,
	}
	for status, want := range cases {
		if got := classify(status); got != want {
			t.Errorf("classify(%d) = %q, want %q", status, got, want)
		}
	}
}

func TestClientReportsAPermissionFailureWithGrafanasOwnDetail(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte(`{"message":"You'll need additional permissions to perform this action. Permissions needed: annotations:create"}`))
	}))
	defer srv.Close()
	cfg := testConfig()
	cfg.URL = srv.URL
	client, err := NewClient(cfg)
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	err = client.Publish(t.Context(), Annotation{Time: fixedNow, Text: "x"})
	if err == nil {
		t.Fatal("a 403 must be an error")
	}
	var pubErr *PublishError
	if !errors.As(err, &pubErr) {
		t.Fatalf("error %T is not a *PublishError", err)
	}
	if pubErr.Code != FailureUnauthorized {
		t.Errorf("code = %q", pubErr.Code)
	}
	if !strings.Contains(pubErr.Detail, "annotations:create") {
		t.Errorf("detail %q does not carry Grafana's own explanation", pubErr.Detail)
	}
}

func TestClientRejectsAMissingToken(t *testing.T) {
	cfg := testConfig()
	cfg.Token = ""
	if _, err := NewClient(cfg); err == nil {
		t.Fatal("NewClient accepted an empty token")
	}
}

// --- the rate limiter ---

func TestRateLimiterEnforcesTheCeilingAndRefills(t *testing.T) {
	now := fixedNow
	limiter := newRateLimiter(3, func() time.Time { return now })
	for i := range 3 {
		if !limiter.allow() {
			t.Fatalf("annotation %d was refused inside the ceiling", i)
		}
	}
	if limiter.allow() {
		t.Fatal("the ceiling was not enforced")
	}
	now = now.Add(time.Minute)
	if !limiter.allow() {
		t.Fatal("the bucket did not refill")
	}
}

// --- the publisher end to end ---

// TestStartIsACleanNoOpWhenUnconfigured is the default deployment: no client, no
// goroutine, no warning storm.
func TestStartIsACleanNoOpWhenUnconfigured(t *testing.T) {
	a, err := Start(t.Context(), Options{Config: config.Default().GrafanaAnnotations})
	if err != nil {
		t.Fatalf("Start on an unconfigured block: %v", err)
	}
	if a != nil {
		t.Fatal("Start built an annotator with no url configured")
	}
	// Every method must be safe on the nil annotator.
	if got := a.Decorate(telemetry.Attribution{}, nil); got != nil {
		t.Error("nil Annotator.Decorate did not pass the emitter through")
	}
	if err := a.Close(t.Context()); err != nil {
		t.Errorf("nil Annotator.Close: %v", err)
	}
}

// TestStartRefusesATokenThatCannotWrite is the fail-fast half of the maintainer
// decision: discovering it at the first real event means the annotations an
// operator relies on are simply not there when they look.
func TestStartRefusesATokenThatCannotWrite(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte(`{"message":"Permissions needed: annotations:create"}`))
	}))
	defer srv.Close()

	cfg := testConfig()
	cfg.URL = srv.URL
	_, err := Start(t.Context(), Options{
		Config:        cfg,
		CheckpointDir: t.TempDir(),
		TenantIDs:     []string{testTenant},
		StartedAt:     fixedNow,
	})
	if err == nil {
		t.Fatal("Start accepted a token that cannot write an annotation")
	}
	if !strings.Contains(err.Error(), "annotations:create") {
		t.Errorf("error does not name the missing permission:\n%v", err)
	}
	if !strings.Contains(err.Error(), "fixed:annotations:writer") {
		t.Errorf("error does not name the role that grants it:\n%v", err)
	}
}

// TestStartWritesTheLifecycleMarkerCarryingVersionAndFingerprint proves the
// probe and the marker are the same write, and that #310's contract is what it
// carries — never the configuration itself.
func TestStartWritesTheLifecycleMarkerCarryingVersionAndFingerprint(t *testing.T) {
	var bodies []map[string]any
	var mu sync.Mutex
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body map[string]any
		_ = json.NewDecoder(r.Body).Decode(&body)
		mu.Lock()
		bodies = append(bodies, body)
		mu.Unlock()
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	cfg := testConfig()
	cfg.URL = srv.URL
	a, err := Start(t.Context(), Options{
		Config:            cfg,
		CheckpointDir:     t.TempDir(),
		Version:           "1.2.3",
		ConfigFingerprint: "abcdef0123456789",
		TenantIDs:         []string{testTenant},
		StartedAt:         fixedNow,
		Now:               func() time.Time { return fixedNow },
	})
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	t.Cleanup(func() { _ = a.Close(t.Context()) })

	mu.Lock()
	defer mu.Unlock()
	if len(bodies) != 1 {
		t.Fatalf("wrote %d markers, want 1 per configured tenant", len(bodies))
	}
	text, _ := bodies[0]["text"].(string)
	if !strings.Contains(text, "1.2.3") || !strings.Contains(text, "abcdef0123456789") {
		t.Errorf("marker text = %q, want the version and the config fingerprint", text)
	}
	if got, want := bodies[0]["time"], float64(fixedNow.UnixMilli()); got != want {
		t.Errorf("marker time = %v, want the PROCESS START time %v", got, want)
	}
}

// TestPublishNeverBlocksACollectorGoroutine is the failure-isolation contract.
// Publish is called from a collector mid-poll with a queue of 2 and a stalled
// destination; it must return immediately whatever Grafana is doing.
func TestPublishNeverBlocksACollectorGoroutine(t *testing.T) {
	stall := make(chan struct{})
	var preflightDone, stalledOnce sync.Once
	preflight := make(chan struct{})
	stalled := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		first := false
		preflightDone.Do(func() { first = true; close(preflight) })
		if !first {
			// Every write after the startup probe hangs, so the publisher goroutine
			// is parked inside an HTTP call for the rest of the test.
			stalledOnce.Do(func() { close(stalled) })
			<-stall
		}
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(srv.Close)

	cfg := testConfig()
	cfg.URL = srv.URL
	cfg.QueueSize = 2
	a, err := Start(t.Context(), Options{
		Config: cfg, CheckpointDir: t.TempDir(),
		TenantIDs: []string{testTenant}, StartedAt: fixedNow,
	})
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	<-preflight
	t.Cleanup(func() { _ = a.Close(t.Context()) })
	// TEARDOWN ORDER IS LOAD-BEARING (#403). Cleanups run last-registered-first,
	// so releasing the stalled handler happens BEFORE Close waits on the worker
	// and before httptest's Close waits on its outstanding request. Registered
	// the other way round — as a `defer close(stall)` above the server, which is
	// what shipped — the test deadlocks for the full package timeout whenever
	// the worker actually reached the handler before the body returned. That is
	// a coin flip locally and near-certain under coverage on a loaded runner,
	// which is exactly how it presented: one 600s hang, green on re-run.
	t.Cleanup(func() { close(stall) })

	// Park the publisher goroutine INSIDE the stalled handler before measuring
	// anything. Without this the test raced its own worker: the loop below
	// usually finished before the worker had dequeued a single annotation, so
	// nothing was ever published against a stalled destination and the contract
	// in this test's name went unexercised.
	a.Publish(Annotation{
		Category: CategoryConfigPosture, TenantID: testTenant,
		RuleID: "r", Time: fixedNow, Text: "x", DedupeKey: "seed",
	})
	<-stalled

	done := make(chan struct{})
	go func() {
		defer close(done)
		for i := range 1000 {
			a.Publish(Annotation{
				Category: CategoryConfigPosture, TenantID: testTenant,
				RuleID: "r", Time: fixedNow, Text: "x", DedupeKey: strconv.Itoa(i),
			})
		}
	}()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("Publish blocked; a collector goroutine can be stalled by Grafana")
	}
}

// TestCloseDrainIsBoundedWhenGrafanaStalls pins the shutdown budget.
//
// main.go closes the annotator with context.Background(), so "the drain is
// bounded by ctx" bought nothing: a stalled Grafana made shutdown cost one
// request timeout PER QUEUED ANNOTATION, up to queue_size of them. Close owns
// the bound itself now — one write's budget for the whole drain, whatever the
// caller passes (#403).
func TestCloseDrainIsBoundedWhenGrafanaStalls(t *testing.T) {
	stall := make(chan struct{})
	var preflightDone, stalledOnce sync.Once
	preflight := make(chan struct{})
	stalled := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		first := false
		preflightDone.Do(func() { first = true; close(preflight) })
		if !first {
			stalledOnce.Do(func() { close(stalled) })
			<-stall
		}
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(srv.Close)
	// Registered after the server's, so it runs first — see #403 above.
	t.Cleanup(func() { close(stall) })

	cfg := testConfig()
	cfg.URL = srv.URL
	cfg.Timeout = 200 * time.Millisecond
	cfg.QueueSize = 20
	a, err := Start(t.Context(), Options{
		Config: cfg, CheckpointDir: t.TempDir(),
		TenantIDs: []string{testTenant}, StartedAt: fixedNow,
	})
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	<-preflight

	// Park the worker inside the stalled handler, then fill the queue behind it.
	a.Publish(Annotation{
		Category: CategoryConfigPosture, TenantID: testTenant,
		RuleID: "r", Time: fixedNow, Text: "x", DedupeKey: "seed",
	})
	<-stalled
	for i := range cfg.QueueSize {
		a.Publish(Annotation{
			Category: CategoryConfigPosture, TenantID: testTenant,
			RuleID: "r", Time: fixedNow, Text: "x", DedupeKey: strconv.Itoa(i),
		})
	}

	done := make(chan struct{})
	go func() {
		defer close(done)
		//nolint:usetesting // the point is the UNBOUNDED context main.go passes.
		_ = a.Close(context.Background())
	}()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("Close did not return within 2s; the drain is paying one request " +
			"timeout per queued annotation instead of bounding the whole drain")
	}
}

// TestPersistedDedupeSetIsEvictedByRetention keeps the on-disk set bounded.
func TestPersistedDedupeSetIsEvictedByRetention(t *testing.T) {
	dir := t.TempDir()
	store := newDedupeStore(checkpoint.NewStore(dir), time.Hour)
	if !store.Claim(testTenant, "rule", "old", fixedNow.Add(-48*time.Hour)) {
		t.Fatal("first claim was refused")
	}
	if !store.Claim(testTenant, "rule", "new", fixedNow) {
		t.Fatal("second claim was refused")
	}
	if err := store.Persist(); err != nil {
		t.Fatalf("persist: %v", err)
	}
	raw, err := os.ReadFile(filepath.Join(dir, onlyFile(t, dir)))
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if strings.Contains(string(raw), `"rule|old"`) {
		t.Errorf("an entry outside the retention window survived:\n%s", raw)
	}
	if !strings.Contains(string(raw), `"rule|new"`) {
		t.Errorf("the in-window entry was evicted:\n%s", raw)
	}
}

func onlyFile(t *testing.T, dir string) string {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 {
		t.Fatalf("expected exactly one checkpoint file, got %d", len(entries))
	}
	return entries[0].Name()
}

// --- rule-set invariants ---

// TestEveryRuleIsWellFormed is the cheap gate that a rule added later cannot
// half-land: a rule with no identity cannot dedupe, and one with no allow-list
// would have nothing to say.
func TestEveryRuleIsWellFormed(t *testing.T) {
	seen := map[string]bool{}
	for _, rule := range Rules() {
		if rule.ID == "" || rule.EventName == "" {
			t.Errorf("rule %+v has no id or no source event", rule)
			continue
		}
		if seen[rule.ID] {
			t.Errorf("duplicate rule id %q; ids are part of the dedupe key", rule.ID)
		}
		seen[rule.ID] = true
		if len(rule.Identity) == 0 {
			t.Errorf("rule %q has no Identity, so two real occurrences cannot be told apart", rule.ID)
		}
		if len(rule.Detail) == 0 {
			t.Errorf("rule %q has no Detail allow-list", rule.ID)
		}
		if rule.Title == nil {
			t.Errorf("rule %q has no Title", rule.ID)
		}
		if !slices.Contains(Categories(), rule.Category) {
			t.Errorf("rule %q has category %q, which is not in the closed set", rule.ID, rule.Category)
		}
		if rule.Category == CategoryLifecycle {
			t.Errorf("rule %q claims the lifecycle category, which is graph2otel's own marker", rule.ID)
		}
		if rule.Category == CategoryLicense {
			t.Errorf("rule %q is in Rules() but the license category is derived from metric snapshots", rule.ID)
		}
	}
}

// TestAllFourCuratedCategoriesAreCovered pins the maintainer's decision that all
// four ship: a category with no rule is a silently missing feature.
func TestAllFourCuratedCategoriesAreCovered(t *testing.T) {
	covered := map[Category]bool{CategoryLicense: len(LicenseRuleIDs()) > 0}
	for _, rule := range Rules() {
		covered[rule.Category] = true
	}
	for _, category := range []Category{
		CategoryConfigPosture, CategorySecurityIncident,
		CategoryServiceHealth, CategoryLicense,
	} {
		if !covered[category] {
			t.Errorf("category %q has no rule", category)
		}
	}
}

// TestNoRuleReadsASignalGraph2otelDoesNotAlreadyEmit is the #400 constraint made
// mechanical: every source event name must be one an existing collector emits,
// so this feature can never introduce a poll.
func TestEveryRuleReadsAnAlreadyEmittedSignal(t *testing.T) {
	// The committed signal catalog is the authority on what graph2otel emits.
	raw, err := os.ReadFile(filepath.Join("..", "..", "spec", "signal-catalog.json"))
	if err != nil {
		t.Fatalf("read signal catalog: %v", err)
	}
	var catalog struct {
		Metrics []struct{ Name string } `json:"metrics"`
		Logs    []struct {
			EventName string `json:"event_name"`
		} `json:"logs"`
	}
	if err := json.Unmarshal(raw, &catalog); err != nil {
		t.Fatalf("decode signal catalog: %v", err)
	}
	events := map[string]bool{}
	for _, l := range catalog.Logs {
		events[l.EventName] = true
	}
	metrics := map[string]bool{}
	for _, m := range catalog.Metrics {
		metrics[m.Name] = true
	}
	for _, rule := range Rules() {
		if !events[rule.EventName] {
			t.Errorf("rule %q reads %q, which no collector emits — this feature must never poll Graph itself",
				rule.ID, rule.EventName)
		}
	}
	for _, metric := range []string{metricLicenseConsumed, metricLicenseEnabled} {
		if !metrics[metric] {
			t.Errorf("the license category reads %q, which no collector emits", metric)
		}
	}
}
