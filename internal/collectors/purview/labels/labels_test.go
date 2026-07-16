package labels

import (
	"context"
	"errors"
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

func TestSensitivityUnavailableIsSkipped(t *testing.T) {
	g := &fakeGraph{errs: map[string]error{
		sensitivityURL: errors.New("graphclient: GET " + sensitivityURL + ": status 403: forbidden"),
	}}
	rec := telemetrytest.New()
	if err := NewSensitivity(g, nil).Collect(context.Background(), rec.Emitter()); err != nil {
		t.Fatalf("Collect on 403 should skip gracefully, got: %v", err)
	}
	if len(rec.MetricPoints(sensitivityMetric)) != 0 {
		t.Error("expected no metric points when endpoint unavailable")
	}
}

func TestSensitivityGatingMetadata(t *testing.T) {
	c := NewSensitivity(&fakeGraph{}, nil)
	if got := c.RequiredCapability(); got != license.CapPurviewInfoProtection {
		t.Errorf("RequiredCapability = %v, want %v", got, license.CapPurviewInfoProtection)
	}
	if got := c.RequiredPermissions(); len(got) != 1 || got[0] != "InformationProtectionPolicy.Read.All" {
		t.Errorf("RequiredPermissions = %v, want [InformationProtectionPolicy.Read.All]", got)
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
}

func TestRetentionDataInsightsForbiddenIsSkipped(t *testing.T) {
	// Live 2026-07-16: app-only access to retention labels is blocked at the
	// Exchange compliance data-plane, which returns HTTP 500 wrapping
	// DataInsightsRequestError "...FAILED - Forbidden". That specific signature is
	// an app-only-unavailable condition, NOT a collector failure — it must skip
	// gracefully (unlike the generic 500 in the test above, which still surfaces).
	forbidden := `status 500: {"error":{"code":"UnknownError","message":"{\"ErrorCode\":\"DataInsightsRequestError\",\"Message\":\"DataInsights command(GET) FAILED - Forbidden. TargetServer = X.PROD.OUTLOOK.COM\"}"}}`
	g := &fakeGraph{errs: map[string]error{
		retentionURL:  errors.New("graphclient: GET " + retentionURL + ": " + forbidden),
		eventTypesURL: errors.New("graphclient: GET " + eventTypesURL + ": " + forbidden),
	}}
	rec := telemetrytest.New()
	if err := NewRetention(g, nil).Collect(context.Background(), rec.Emitter()); err != nil {
		t.Fatalf("Collect on DataInsights Forbidden 500 should skip gracefully, got: %v", err)
	}
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
