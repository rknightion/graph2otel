package labels

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/rknightion/graph2otel/internal/collectors"
	"github.com/rknightion/graph2otel/internal/license"
	"github.com/rknightion/graph2otel/internal/telemetrytest"
)

// fakeGraph is a canned-response GraphClient: bodies keyed by exact URL, or an
// error keyed by exact URL.
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
	b, ok := f.bodies[url]
	if !ok {
		return nil, errors.New("no canned body for " + url)
	}
	return []byte(b), nil
}

var _ collectors.GraphClient = (*fakeGraph)(nil)

const (
	sensitivityURL   = "https://graph.microsoft.com/v1.0/security/dataSecurityAndGovernance/sensitivityLabels"
	retentionURL     = "https://graph.microsoft.com/v1.0/security/labels/retentionLabels"
	eventTypesURL    = "https://graph.microsoft.com/v1.0/security/triggerTypes/retentionEventTypes"
	piiLabelName     = "Confidential Finance-Payroll"
	piiEventTypeName = "Employee Termination - Jane Doe"
)

// --- sensitivity labels ---

func TestSensitivityCollectBucketsByApplicableTo(t *testing.T) {
	// A label applicable to multiple targets contributes to each bucket; an
	// empty applicableTo lands in "none"; an unrecognized target in "unknown".
	body := `{"value":[
	  {"applicableTo":"email,file","name":"` + piiLabelName + `","priority":5,"isEnabled":true},
	  {"applicableTo":"file","name":"Secret","priority":6},
	  {"applicableTo":"teamwork,site","name":"Team"},
	  {"applicableTo":"","name":"NoTarget"},
	  {"applicableTo":"martian","name":"Weird"}
	]}`
	g := &fakeGraph{bodies: map[string]string{sensitivityURL: body}}
	rec := telemetrytest.New()

	if err := NewSensitivity(g, nil).Collect(context.Background(), rec.Emitter()); err != nil {
		t.Fatalf("Collect: %v", err)
	}

	got := map[string]float64{}
	for _, p := range rec.MetricPoints(sensitivityMetric) {
		got[p.Attrs["applicable_to"]] = p.Value
	}
	want := map[string]float64{
		"email": 1, "file": 2, "teamwork": 1, "site": 1, "none": 1, "unknown": 1,
	}
	for k, v := range want {
		if got[k] != v {
			t.Errorf("applicable_to=%s count = %v, want %v (all: %v)", k, got[k], v, got)
		}
	}
}

// TestSensitivityNoPIIInLabels is the cardinality/PII guard: no metric point
// may carry a label display name (or any attr key beyond the bounded set).
func TestSensitivityNoPIIInLabels(t *testing.T) {
	body := `{"value":[{"applicableTo":"file","name":"` + piiLabelName + `","priority":9,"tooltip":"secret finance"}]}`
	g := &fakeGraph{bodies: map[string]string{sensitivityURL: body}}
	rec := telemetrytest.New()
	if err := NewSensitivity(g, nil).Collect(context.Background(), rec.Emitter()); err != nil {
		t.Fatalf("Collect: %v", err)
	}

	allowedKeys := map[string]bool{"applicable_to": true}
	pts := rec.MetricPoints(sensitivityMetric)
	if len(pts) == 0 {
		t.Fatal("expected at least one metric point")
	}
	for _, p := range pts {
		for k, v := range p.Attrs {
			if !allowedKeys[k] {
				t.Errorf("unexpected metric label key %q (value %q) — only bounded dims allowed", k, v)
			}
			if v == piiLabelName {
				t.Errorf("PII label display name leaked into metric label %q=%q", k, v)
			}
		}
	}
}

// --- #126 guard: the sensitivity/retention skip asymmetry ---
//
// The two collectors in this package must treat a refusal in OPPOSITE ways, and
// the difference is the whole of #126:
//
//   - Retention labels are app-only-blocked for real. Microsoft documents
//     /security/labels/retentionLabels as "Application: Not supported", and the
//     Exchange compliance data-plane refuses the app-only identity with a 500
//     wrapping DataInsightsRequestError "...FAILED - Forbidden" even with
//     RecordsManagement.Read.All in the token (live 2026-07-16). No grant a
//     maintainer can make fixes it, so it skips.
//   - Sensitivity labels are NOT blocked. The endpoint is GA and returns 200
//     app-only with SensitivityLabel.Read (live 2026-07-16, #126). A 403 there
//     means missing admin consent — an operator-fixable misconfiguration that
//     must fail LOUDLY. Swallowing it is precisely how #109 mistook a missing
//     scope for a permanent product gap: the collector reported success over
//     zero data and nothing ever contradicted it.
//
// A change that re-broadens the skip back across both collectors — e.g. wiring
// the retention predicate into the sensitivity path "for symmetry" — must break
// these tests rather than silently restore the bug.

// dataInsightsForbidden is the live retention-label refusal signature, in
// graphclient's error format (live 2026-07-16, #109/#126). Shared by the
// retention skip test and the sensitivity failure test on purpose: the guard is
// that the SAME string means "skip" for one collector and "fail" for the other.
const dataInsightsForbidden = `status 500: {"error":{"code":"UnknownError","message":"{\"ErrorCode\":\"DataInsightsRequestError\",\"Message\":\"DataInsights command(GET) FAILED - Forbidden. TargetServer = X.PROD.OUTLOOK.COM\"}"}}`

// TestSensitivityErrorsAlwaysFail pins that the sensitivity collector has NO
// skip path: every error class fails, emitting neither metrics nor logs.
func TestSensitivityErrorsAlwaysFail(t *testing.T) {
	cases := []struct {
		name string
		err  string
	}{
		{
			// #126: the live signature of missing admin consent for
			// SensitivityLabel.Read. THE case this issue exists for.
			name: "forbidden_403",
			err:  `status 403: {"error":{"code":"InsufficientGraphPermissions","message":"Insufficient privileges to complete the operation."}}`,
		},
		{
			// The endpoint is GA and live-verified 200 — a 404 means it moved or
			// was withdrawn, which is real news, not a tenant condition.
			name: "not_found_404",
			err:  "status 404: not found",
		},
		{
			// #102's shape: a non-Graph data plane refusing the principal with the
			// scope in-token. A different diagnosis, still a failure.
			name: "unauthorized_401",
			err:  "status 401: unauthorized",
		},
		{
			// Retention's real, permanent gap — NOT sensitivity's. The retention
			// collector skips this exact string; this one must not.
			name: "data_insights_forbidden",
			err:  dataInsightsForbidden,
		},
		{
			name: "generic_500",
			err:  "status 500: boom",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			g := &fakeGraph{errs: map[string]error{
				sensitivityURL: errors.New("graphclient: GET " + sensitivityURL + ": " + tc.err),
			}}
			rec := telemetrytest.New()
			err := NewSensitivity(g, nil).Collect(context.Background(), rec.Emitter())
			if err == nil {
				t.Fatalf("Collect returned nil: a sensitivity-label fetch failure must never be swallowed (#126); error was %q", tc.err)
			}
			if len(rec.MetricPoints(sensitivityMetric)) != 0 {
				t.Error("expected no metric points on a failed fetch")
			}
			if len(rec.LogRecords()) != 0 {
				t.Error("expected no log twin records on a failed fetch")
			}
		})
	}
}

// TestSensitivityForbiddenErrorNamesTheMissingScope pins that the 403 failure is
// self-diagnosing. #109 spent days concluding "permanent app-only gap" from a
// bare 403; the error must name the grant that fixes it so the next reader does
// not re-run that investigation.
func TestSensitivityForbiddenErrorNamesTheMissingScope(t *testing.T) {
	g := &fakeGraph{errs: map[string]error{
		sensitivityURL: errors.New("graphclient: GET " + sensitivityURL +
			`: status 403: {"error":{"code":"InsufficientGraphPermissions"}}`),
	}}
	err := NewSensitivity(g, nil).Collect(context.Background(), telemetrytest.New().Emitter())
	if err == nil {
		t.Fatal("expected a 403 to fail the collector")
	}
	if !strings.Contains(err.Error(), "SensitivityLabel.Read") {
		t.Errorf("a 403 error must name the missing scope, got: %v", err)
	}
	if !strings.Contains(err.Error(), "status 403") {
		t.Errorf("a 403 error must preserve the underlying graphclient error, got: %v", err)
	}
}

// TestIsRetentionUnavailable pins the retention skip predicate's EXACT
// signature set. It is deliberately a whitelist, not a "4xx-ish" heuristic:
// widening it is how a real failure becomes a silent green tick, and this
// package has already paid for that once (#126).
func TestIsRetentionUnavailable(t *testing.T) {
	cases := []struct {
		name string
		err  string
		want bool
	}{
		{"forbidden_403", "graphclient: GET x: status 403: forbidden", true},
		{"not_found_404", "graphclient: GET x: status 404: not found", true},
		{"data_insights_forbidden_500", dataInsightsForbidden, true},
		// A generic 500 is a real failure and must still surface — the skip is
		// keyed on the DataInsights+Forbidden PAIR, never on the status alone.
		{"generic_500", "graphclient: GET x: status 500: boom", false},
		// DataInsights failing for some other reason is not the app-only refusal.
		{"data_insights_non_forbidden", `status 500: {"ErrorCode":"DataInsightsRequestError","Message":"DataInsights command(GET) FAILED - Timeout"}`, false},
		// "Forbidden" from somewhere other than the DataInsights data plane.
		{"forbidden_without_data_insights", "graphclient: GET x: status 500: Forbidden", false},
		// #102's shape: a data-plane 401 with the scope in-token. Real failure.
		{"unauthorized_401", "graphclient: GET x: status 401: unauthorized", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := isRetentionUnavailable(errors.New(tc.err)); got != tc.want {
				t.Errorf("isRetentionUnavailable(%q) = %v, want %v", tc.err, got, tc.want)
			}
		})
	}
}

// TestForbiddenSkipIsRetentionOnly pins the asymmetry head-on: the SAME
// DataInsights-Forbidden string skips for retention and fails for sensitivity.
// Any change that re-unifies the two error predicates breaks this.
func TestForbiddenSkipIsRetentionOnly(t *testing.T) {
	wrap := func(url string) error {
		return errors.New("graphclient: GET " + url + ": " + dataInsightsForbidden)
	}

	retG := &fakeGraph{errs: map[string]error{
		retentionURL:  wrap(retentionURL),
		eventTypesURL: wrap(eventTypesURL),
	}}
	if err := NewRetention(retG, nil).Collect(context.Background(), telemetrytest.New().Emitter()); err != nil {
		t.Errorf("retention: DataInsights-Forbidden is a documented permanent app-only gap (Application: Not supported) and must still skip, got: %v", err)
	}

	senG := &fakeGraph{errs: map[string]error{sensitivityURL: wrap(sensitivityURL)}}
	if err := NewSensitivity(senG, nil).Collect(context.Background(), telemetrytest.New().Emitter()); err == nil {
		t.Error("sensitivity: the retention data-plane's skip signature must NOT be honored here — this endpoint is GA and app-only-capable with SensitivityLabel.Read (#126)")
	}
}

// TestSensitivityCollectEmitsLogTwin is the log-twin half of #111: every
// catalog row emits one purview.sensitivity_label log carrying the per-row
// detail (id, name, priority, applicable_to, description) the metric
// deliberately never carries.
func TestSensitivityCollectEmitsLogTwin(t *testing.T) {
	body := `{"value":[
	  {"id":"aaa","applicableTo":"email,file","name":"` + piiLabelName + `","priority":5,"description":"Finance payroll data"},
	  {"id":"bbb","applicableTo":"file","name":"Secret","priority":6}
	]}`
	g := &fakeGraph{bodies: map[string]string{sensitivityURL: body}}
	rec := telemetrytest.New()

	if err := NewSensitivity(g, nil).Collect(context.Background(), rec.Emitter()); err != nil {
		t.Fatalf("Collect: %v", err)
	}

	logs := rec.LogRecords()
	var twins []telemetrytest.LogRecord
	for _, l := range logs {
		if l.EventName == sensitivityLabelEventName {
			twins = append(twins, l)
		}
	}
	if len(twins) != 2 {
		t.Fatalf("got %d purview.sensitivity_label logs, want 2 (all: %+v)", len(twins), logs)
	}

	byID := map[string]telemetrytest.LogRecord{}
	for _, l := range twins {
		byID[l.Attrs["id"]] = l
	}

	first, ok := byID["aaa"]
	if !ok {
		t.Fatalf("no log record for id=aaa (all: %+v)", twins)
	}
	if first.Attrs["name"] != piiLabelName {
		t.Errorf("name = %q, want %q", first.Attrs["name"], piiLabelName)
	}
	if first.Attrs["priority"] != "5" {
		t.Errorf("priority = %q, want \"5\"", first.Attrs["priority"])
	}
	if first.Attrs["applicable_to"] != "email,file" {
		t.Errorf("applicable_to = %q, want \"email,file\"", first.Attrs["applicable_to"])
	}
	if first.Attrs["description"] != "Finance payroll data" {
		t.Errorf("description = %q, want %q", first.Attrs["description"], "Finance payroll data")
	}

	second, ok := byID["bbb"]
	if !ok {
		t.Fatalf("no log record for id=bbb (all: %+v)", twins)
	}
	if _, present := second.Attrs["description"]; present {
		t.Errorf("absent description should be omitted from attrs, got %q", second.Attrs["description"])
	}
}

func TestSensitivityGatingMetadata(t *testing.T) {
	c := NewSensitivity(&fakeGraph{}, nil)
	if got := c.RequiredCapability(); got != license.CapPurviewInfoProtection {
		t.Errorf("RequiredCapability = %v, want %v", got, license.CapPurviewInfoProtection)
	}
	// SensitivityLabel.Read is the scope that live-verified 200 on this endpoint
	// (#126). InformationProtectionPolicy.Read.All is a DIFFERENT permission for
	// a different endpoint; asserting it here is what kept the wrong scope in
	// docs/collectors.md, where it told operators to grant something that does
	// not unblock the collector.
	if got := c.RequiredPermissions(); len(got) != 1 || got[0] != "SensitivityLabel.Read" {
		t.Errorf("RequiredPermissions = %v, want [SensitivityLabel.Read]", got)
	}
	if c.Name() != sensitivityName {
		t.Errorf("Name = %q, want %q", c.Name(), sensitivityName)
	}
}

// --- retention labels + event types ---

func TestRetentionCollectBucketsAndCountsEventTypes(t *testing.T) {
	rl := `{"value":[
	  {"displayName":"` + piiLabelName + `","behaviorDuringRetentionPeriod":"retainAsRecord","actionAfterRetentionPeriod":"delete","retentionTrigger":"dateLabeled"},
	  {"displayName":"B","behaviorDuringRetentionPeriod":"retainAsRecord","actionAfterRetentionPeriod":"delete","retentionTrigger":"dateLabeled"},
	  {"displayName":"C","behaviorDuringRetentionPeriod":"retain","actionAfterRetentionPeriod":"none","retentionTrigger":"dateCreated"},
	  {"displayName":"D","behaviorDuringRetentionPeriod":"martian","actionAfterRetentionPeriod":"","retentionTrigger":"whatever"}
	]}`
	et := `{"value":[
	  {"displayName":"` + piiEventTypeName + `"},{"displayName":"E2"},{"displayName":"E3"}
	]}`
	g := &fakeGraph{bodies: map[string]string{retentionURL: rl, eventTypesURL: et}}
	rec := telemetrytest.New()

	if err := NewRetention(g, nil).Collect(context.Background(), rec.Emitter()); err != nil {
		t.Fatalf("Collect: %v", err)
	}

	// combo counts
	byCombo := map[string]float64{}
	for _, p := range rec.MetricPoints(retentionLabelsMetric) {
		key := p.Attrs["behavior_during_retention"] + "/" + p.Attrs["action_after_retention"] + "/" + p.Attrs["retention_trigger"]
		byCombo[key] = p.Value
	}
	if byCombo["retain_as_record/delete/date_labeled"] != 2 {
		t.Errorf("retain_as_record/delete/date_labeled = %v, want 2 (all: %v)", byCombo["retain_as_record/delete/date_labeled"], byCombo)
	}
	if byCombo["retain/none/date_created"] != 1 {
		t.Errorf("retain/none/date_created = %v, want 1", byCombo["retain/none/date_created"])
	}
	if byCombo["unknown/unknown/unknown"] != 1 {
		t.Errorf("unknown/unknown/unknown = %v, want 1", byCombo["unknown/unknown/unknown"])
	}

	// event-types total
	etPts := rec.MetricPoints(retentionEventTypesMetric)
	if len(etPts) != 1 || etPts[0].Value != 3 {
		t.Errorf("event types count = %v, want single point value 3", etPts)
	}
}

// TestRetentionNoPIIInLabels is the cardinality/PII guard for the retention
// collector.
func TestRetentionNoPIIInLabels(t *testing.T) {
	rl := `{"value":[{"displayName":"` + piiLabelName + `","behaviorDuringRetentionPeriod":"retain","actionAfterRetentionPeriod":"delete","retentionTrigger":"dateCreated"}]}`
	et := `{"value":[{"displayName":"` + piiEventTypeName + `"}]}`
	g := &fakeGraph{bodies: map[string]string{retentionURL: rl, eventTypesURL: et}}
	rec := telemetrytest.New()
	if err := NewRetention(g, nil).Collect(context.Background(), rec.Emitter()); err != nil {
		t.Fatalf("Collect: %v", err)
	}

	allowedKeys := map[string]bool{
		"behavior_during_retention": true,
		"action_after_retention":    true,
		"retention_trigger":         true,
	}
	pii := map[string]bool{piiLabelName: true, piiEventTypeName: true}
	for _, metric := range []string{retentionLabelsMetric, retentionEventTypesMetric} {
		for _, p := range rec.MetricPoints(metric) {
			for k, v := range p.Attrs {
				if metric == retentionLabelsMetric && !allowedKeys[k] {
					t.Errorf("%s: unexpected metric label key %q", metric, k)
				}
				if pii[v] {
					t.Errorf("%s: PII display name leaked into metric label %q=%q", metric, k, v)
				}
			}
		}
	}
}

func TestRetentionEventTypesFailureDoesNotBlockLabels(t *testing.T) {
	// A genuine (non-4xx-unavailable) failure on event types surfaces as an
	// error, but the labels metric still emits.
	rl := `{"value":[{"behaviorDuringRetentionPeriod":"retain","actionAfterRetentionPeriod":"none","retentionTrigger":"dateCreated"}]}`
	g := &fakeGraph{
		bodies: map[string]string{retentionURL: rl},
		errs:   map[string]error{eventTypesURL: errors.New("graphclient: GET " + eventTypesURL + ": status 500: boom")},
	}
	rec := telemetrytest.New()
	err := NewRetention(g, nil).Collect(context.Background(), rec.Emitter())
	if err == nil {
		t.Fatal("expected an error from the failing event-types fetch")
	}
	if len(rec.MetricPoints(retentionLabelsMetric)) == 0 {
		t.Error("retention labels should still emit despite event-types failure")
	}

	labelLogs := logsNamed(rec, retentionLabelEventName)
	if len(labelLogs) == 0 {
		t.Error("retention label log twin should still emit despite event-types failure")
	}
	if eventTypeLogs := logsNamed(rec, retentionEventTypeEventName); len(eventTypeLogs) != 0 {
		t.Errorf("expected no purview.retention_event_type logs when that fetch fails, got %+v", eventTypeLogs)
	}
}

func TestRetentionUnavailableIsSkipped(t *testing.T) {
	g := &fakeGraph{errs: map[string]error{
		retentionURL:  errors.New("graphclient: GET " + retentionURL + ": status 404: not found"),
		eventTypesURL: errors.New("graphclient: GET " + eventTypesURL + ": status 404: not found"),
	}}
	rec := telemetrytest.New()
	if err := NewRetention(g, nil).Collect(context.Background(), rec.Emitter()); err != nil {
		t.Fatalf("Collect on 404 should skip gracefully, got: %v", err)
	}
	if len(rec.LogRecords()) != 0 {
		t.Error("expected no log twin records when both endpoints are unavailable")
	}
}

func TestRetentionDataInsightsForbiddenIsSkipped(t *testing.T) {
	// Live 2026-07-16: app-only access to retention labels is blocked at the
	// Exchange compliance data-plane, which returns HTTP 500 wrapping
	// DataInsightsRequestError "...FAILED - Forbidden". That specific signature is
	// an app-only-unavailable condition, NOT a collector failure — it must skip
	// gracefully (unlike the generic 500 in the test above, which still surfaces).
	// The same signature FAILS the sensitivity collector — see
	// TestForbiddenSkipIsRetentionOnly.
	g := &fakeGraph{errs: map[string]error{
		retentionURL:  errors.New("graphclient: GET " + retentionURL + ": " + dataInsightsForbidden),
		eventTypesURL: errors.New("graphclient: GET " + eventTypesURL + ": " + dataInsightsForbidden),
	}}
	rec := telemetrytest.New()
	if err := NewRetention(g, nil).Collect(context.Background(), rec.Emitter()); err != nil {
		t.Fatalf("Collect on DataInsights Forbidden 500 should skip gracefully, got: %v", err)
	}
	if len(rec.LogRecords()) != 0 {
		t.Error("expected no log twin records when both endpoints are DataInsights-Forbidden")
	}
}

// TestRetentionCollectEmitsLogTwins is the log-twin half of #111 for the
// retention collector: one purview.retention_label log per label (using the
// SAME normalized enum values the gauge buckets on) and one
// purview.retention_event_type log per event type — a catalog this collector
// previously decoded nothing for.
func TestRetentionCollectEmitsLogTwins(t *testing.T) {
	rl := `{"value":[
	  {"id":"lbl-1","displayName":"` + piiLabelName + `","behaviorDuringRetentionPeriod":"retainAsRecord","actionAfterRetentionPeriod":"delete","retentionTrigger":"dateLabeled","descriptionForAdmins":"admin desc","descriptionForUsers":"user desc"},
	  {"id":"lbl-2","displayName":"Weird","behaviorDuringRetentionPeriod":"martian","actionAfterRetentionPeriod":"","retentionTrigger":"whatever"}
	]}`
	et := `{"value":[
	  {"id":"evt-1","displayName":"` + piiEventTypeName + `","description":"fires on termination"},
	  {"id":"evt-2","displayName":"E2"}
	]}`
	g := &fakeGraph{bodies: map[string]string{retentionURL: rl, eventTypesURL: et}}
	rec := telemetrytest.New()

	if err := NewRetention(g, nil).Collect(context.Background(), rec.Emitter()); err != nil {
		t.Fatalf("Collect: %v", err)
	}

	labelLogs := logsNamed(rec, retentionLabelEventName)
	if len(labelLogs) != 2 {
		t.Fatalf("got %d purview.retention_label logs, want 2 (all: %+v)", len(labelLogs), labelLogs)
	}
	byLabelID := map[string]telemetrytest.LogRecord{}
	for _, l := range labelLogs {
		byLabelID[l.Attrs["id"]] = l
	}
	l1, ok := byLabelID["lbl-1"]
	if !ok {
		t.Fatalf("no log record for id=lbl-1 (all: %+v)", labelLogs)
	}
	if l1.Attrs["name"] != piiLabelName {
		t.Errorf("name = %q, want %q", l1.Attrs["name"], piiLabelName)
	}
	if l1.Attrs["behavior_during_retention"] != "retain_as_record" {
		t.Errorf("behavior_during_retention = %q, want normalized \"retain_as_record\"", l1.Attrs["behavior_during_retention"])
	}
	if l1.Attrs["action_after_retention"] != "delete" {
		t.Errorf("action_after_retention = %q, want \"delete\"", l1.Attrs["action_after_retention"])
	}
	if l1.Attrs["retention_trigger"] != "date_labeled" {
		t.Errorf("retention_trigger = %q, want \"date_labeled\"", l1.Attrs["retention_trigger"])
	}
	if l1.Attrs["description_for_admins"] != "admin desc" {
		t.Errorf("description_for_admins = %q, want \"admin desc\"", l1.Attrs["description_for_admins"])
	}
	if l1.Attrs["description_for_users"] != "user desc" {
		t.Errorf("description_for_users = %q, want \"user desc\"", l1.Attrs["description_for_users"])
	}

	l2, ok := byLabelID["lbl-2"]
	if !ok {
		t.Fatalf("no log record for id=lbl-2 (all: %+v)", labelLogs)
	}
	if l2.Attrs["behavior_during_retention"] != "unknown" || l2.Attrs["action_after_retention"] != "unknown" || l2.Attrs["retention_trigger"] != "unknown" {
		t.Errorf("expected unrecognized enums to normalize to \"unknown\", got %+v", l2.Attrs)
	}
	if _, present := l2.Attrs["description_for_admins"]; present {
		t.Errorf("absent description_for_admins should be omitted, got %q", l2.Attrs["description_for_admins"])
	}

	eventLogs := logsNamed(rec, retentionEventTypeEventName)
	if len(eventLogs) != 2 {
		t.Fatalf("got %d purview.retention_event_type logs, want 2 (all: %+v)", len(eventLogs), eventLogs)
	}
	byEventID := map[string]telemetrytest.LogRecord{}
	for _, l := range eventLogs {
		byEventID[l.Attrs["id"]] = l
	}
	e1, ok := byEventID["evt-1"]
	if !ok {
		t.Fatalf("no log record for id=evt-1 (all: %+v)", eventLogs)
	}
	if e1.Attrs["name"] != piiEventTypeName {
		t.Errorf("name = %q, want %q", e1.Attrs["name"], piiEventTypeName)
	}
	if e1.Attrs["description"] != "fires on termination" {
		t.Errorf("description = %q, want \"fires on termination\"", e1.Attrs["description"])
	}
	e2, ok := byEventID["evt-2"]
	if !ok {
		t.Fatalf("no log record for id=evt-2 (all: %+v)", eventLogs)
	}
	if _, present := e2.Attrs["description"]; present {
		t.Errorf("absent description should be omitted, got %q", e2.Attrs["description"])
	}
}

// logsNamed filters the recorder's log records to a single EventName.
func logsNamed(rec *telemetrytest.Recorder, name string) []telemetrytest.LogRecord {
	var out []telemetrytest.LogRecord
	for _, l := range rec.LogRecords() {
		if l.EventName == name {
			out = append(out, l)
		}
	}
	return out
}

func TestRetentionGatingMetadata(t *testing.T) {
	c := NewRetention(&fakeGraph{}, nil)
	if got := c.RequiredCapability(); got != license.CapPurviewRecordsMgmt {
		t.Errorf("RequiredCapability = %v, want %v", got, license.CapPurviewRecordsMgmt)
	}
	if got := c.RequiredPermissions(); len(got) != 1 || got[0] != "RecordsManagement.Read.All" {
		t.Errorf("RequiredPermissions = %v, want [RecordsManagement.Read.All]", got)
	}
	if c.Name() != retentionName {
		t.Errorf("Name = %q, want %q", c.Name(), retentionName)
	}
}
