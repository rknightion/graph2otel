package securescore

import (
	"context"
	"errors"
	"fmt"
	"testing"

	"github.com/rknightion/graph2otel/internal/collectors"
	"github.com/rknightion/graph2otel/internal/telemetrytest"
)

// fakeGraph maps request URLs to canned response bodies (or errors). It
// satisfies collectors.GraphClient without any live Graph call.
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

const base = "https://graph.microsoft.com/v1.0"

const scoreURL = base + "/security/secureScores?$top=1"
const profilesURL = base + "/security/secureScoreControlProfiles"

// twoScores has TWO entries in "value" to prove the collector only emits the
// latest (first) one, not the whole retained daily series.
const twoScores = `{
  "value": [
    {"currentScore": 387.0, "maxScore": 697.0},
    {"currentScore": 300.0, "maxScore": 700.0}
  ]
}`

const zeroMaxScore = `{
  "value": [
    {"currentScore": 0.0, "maxScore": 0.0}
  ]
}`

const emptyScores = `{"value": []}`

const mixedProfiles = `{
  "value": [
    {"controlCategory": "Identity", "controlStateUpdates": []},
    {"controlCategory": "Identity", "controlStateUpdates": [
      {"state": "reviewed", "updatedDateTime": "2026-01-01T00:00:00Z"}
    ]},
    {"controlCategory": "Data", "controlStateUpdates": [
      {"state": "ignored", "updatedDateTime": "2026-01-01T00:00:00Z"},
      {"state": "thirdParty", "updatedDateTime": "2026-02-01T00:00:00Z"}
    ]},
    {"controlCategory": "SomeNewCategoryNotYetKnown", "controlStateUpdates": [
      {"state": "someBrandNewState", "updatedDateTime": "2026-01-01T00:00:00Z"}
    ]}
  ]
}`

const emptyProfiles = `{"value": []}`

func TestCollectEmitsScoreGauges(t *testing.T) {
	g := &fakeGraph{bodies: map[string]string{scoreURL: twoScores, profilesURL: emptyProfiles}}
	rec := telemetrytest.New()

	if err := New(g, nil).Collect(context.Background(), rec.Emitter()); err != nil {
		t.Fatalf("Collect: %v", err)
	}

	assertSingleGauge(t, rec, metricCurrent, 387.0)
	assertSingleGauge(t, rec, metricMax, 697.0)
	wantPct := 387.0 / 697.0 * 100
	assertSingleGaugeApprox(t, rec, metricPercentage, wantPct)
}

func TestCollectOnlyEmitsLatestScoreNotFullSeries(t *testing.T) {
	g := &fakeGraph{bodies: map[string]string{scoreURL: twoScores, profilesURL: emptyProfiles}}
	rec := telemetrytest.New()

	if err := New(g, nil).Collect(context.Background(), rec.Emitter()); err != nil {
		t.Fatalf("Collect: %v", err)
	}

	pts := rec.MetricPoints(metricCurrent)
	if len(pts) != 1 {
		t.Fatalf("got %d %s series, want exactly 1 (only the latest score)", len(pts), metricCurrent)
	}
	if pts[0].Value != 387.0 {
		t.Errorf("%s = %v, want 387 (the first/latest entry, not the second)", metricCurrent, pts[0].Value)
	}
}

func TestCollectSkipsPercentageWhenMaxScoreZero(t *testing.T) {
	g := &fakeGraph{bodies: map[string]string{scoreURL: zeroMaxScore, profilesURL: emptyProfiles}}
	rec := telemetrytest.New()

	if err := New(g, nil).Collect(context.Background(), rec.Emitter()); err != nil {
		t.Fatalf("Collect: %v", err)
	}
	if pts := rec.MetricPoints(metricPercentage); len(pts) != 0 {
		t.Errorf("got %d %s series with maxScore=0, want 0 (avoid divide-by-zero series)", len(pts), metricPercentage)
	}
}

func TestCollectHandlesNoPublishedScoreYet(t *testing.T) {
	g := &fakeGraph{bodies: map[string]string{scoreURL: emptyScores, profilesURL: emptyProfiles}}
	rec := telemetrytest.New()

	if err := New(g, nil).Collect(context.Background(), rec.Emitter()); err != nil {
		t.Fatalf("Collect: %v", err)
	}
	if pts := rec.MetricPoints(metricCurrent); len(pts) != 0 {
		t.Errorf("got %d %s series with no published score, want 0", len(pts), metricCurrent)
	}
}

func TestCollectEmitsControlProfileCountsByCategoryAndStatus(t *testing.T) {
	g := &fakeGraph{bodies: map[string]string{scoreURL: emptyScores, profilesURL: mixedProfiles}}
	rec := telemetrytest.New()

	if err := New(g, nil).Collect(context.Background(), rec.Emitter()); err != nil {
		t.Fatalf("Collect: %v", err)
	}

	gotCat := map[string]float64{}
	for _, p := range rec.MetricPoints(metricByCategory) {
		gotCat[p.Attrs["category"]] = p.Value
	}
	wantCat := map[string]float64{"identity": 2, "data": 1, "unknown": 1}
	if len(gotCat) != len(wantCat) {
		t.Fatalf("got %d category series, want %d: %v", len(gotCat), len(wantCat), gotCat)
	}
	for cat, v := range wantCat {
		if gotCat[cat] != v {
			t.Errorf("category=%s = %v, want %v", cat, gotCat[cat], v)
		}
	}

	gotStatus := map[string]float64{}
	for _, p := range rec.MetricPoints(metricByStatus) {
		gotStatus[p.Attrs["status"]] = p.Value
	}
	// identity/no-updates -> default; identity/reviewed -> reviewed;
	// data/ignored+thirdParty (latest by time wins) -> third_party;
	// unknown-category profile with an unrecognized state -> unknown.
	wantStatus := map[string]float64{"default": 1, "reviewed": 1, "third_party": 1, "unknown": 1}
	if len(gotStatus) != len(wantStatus) {
		t.Fatalf("got %d status series, want %d: %v", len(gotStatus), len(wantStatus), gotStatus)
	}
	for st, v := range wantStatus {
		if gotStatus[st] != v {
			t.Errorf("status=%s = %v, want %v", st, gotStatus[st], v)
		}
	}
}

// TestNoUnboundedLabelsFromUnknownCategoryOrState pins the cardinality rule: a
// category or state Graph has never returned before must collapse into the
// bounded "unknown" bucket, never pass through as a fresh, unbounded label.
func TestNoUnboundedLabelsFromUnknownCategoryOrState(t *testing.T) {
	g := &fakeGraph{bodies: map[string]string{scoreURL: emptyScores, profilesURL: mixedProfiles}}
	rec := telemetrytest.New()

	if err := New(g, nil).Collect(context.Background(), rec.Emitter()); err != nil {
		t.Fatalf("Collect: %v", err)
	}
	for _, p := range rec.MetricPoints(metricByCategory) {
		if p.Attrs["category"] == "SomeNewCategoryNotYetKnown" {
			t.Error("raw unrecognized category value leaked through as a label; must normalize to a bounded bucket")
		}
	}
	for _, p := range rec.MetricPoints(metricByStatus) {
		if p.Attrs["status"] == "someBrandNewState" {
			t.Error("raw unrecognized state value leaked through as a label; must normalize to a bounded bucket")
		}
	}
}

func TestCollectIsResilientToSecureScoreFailure(t *testing.T) {
	g := &fakeGraph{
		bodies: map[string]string{profilesURL: mixedProfiles},
		errs:   map[string]error{scoreURL: errors.New("throttled")},
	}
	rec := telemetrytest.New()

	err := New(g, nil).Collect(context.Background(), rec.Emitter())
	if err == nil {
		t.Fatal("expected Collect to surface the secure score failure as an error")
	}
	if pts := rec.MetricPoints(metricCurrent); len(pts) != 0 {
		t.Errorf("got %d %s series despite score fetch failing, want 0", len(pts), metricCurrent)
	}
	// The control profile counts must still emit despite the score failure.
	if pts := rec.MetricPoints(metricByCategory); len(pts) == 0 {
		t.Error("control-profile categories absent despite succeeding independently of the score fetch")
	}
}

func TestCollectIsResilientToControlProfilesFailure(t *testing.T) {
	g := &fakeGraph{
		bodies: map[string]string{scoreURL: twoScores},
		errs:   map[string]error{profilesURL: errors.New("throttled")},
	}
	rec := telemetrytest.New()

	err := New(g, nil).Collect(context.Background(), rec.Emitter())
	if err == nil {
		t.Fatal("expected Collect to surface the control-profiles failure as an error")
	}
	// The score gauges must still emit despite the control-profiles failure.
	if pts := rec.MetricPoints(metricCurrent); len(pts) != 1 {
		t.Errorf("got %d %s series despite score fetch succeeding independently, want 1", len(pts), metricCurrent)
	}
	if pts := rec.MetricPoints(metricByCategory); len(pts) != 0 {
		t.Errorf("got %d %s series despite control-profiles fetch failing, want 0", len(pts), metricByCategory)
	}
}

func TestNameAndPermissions(t *testing.T) {
	c := New(&fakeGraph{}, nil)
	if c.Name() != "entra.secure_score" {
		t.Errorf("Name = %q", c.Name())
	}
	perms := c.RequiredPermissions()
	if len(perms) != 1 || perms[0] != "SecurityEvents.Read.All" {
		t.Errorf("RequiredPermissions = %v, want [SecurityEvents.Read.All]", perms)
	}
}

func assertSingleGauge(t *testing.T, rec *telemetrytest.Recorder, name string, want float64) {
	t.Helper()
	pts := rec.MetricPoints(name)
	if len(pts) != 1 {
		t.Fatalf("got %d %s series, want 1", len(pts), name)
	}
	if pts[0].Value != want {
		t.Errorf("%s = %v, want %v", name, pts[0].Value, want)
	}
}

// assertSingleGaugeApprox is assertSingleGauge for a value computed via
// floating-point division, where the OTEL SDK's own float64<->float32-adjacent
// plumbing can introduce a last-decimal-place difference irrelevant to the
// collector's correctness.
func assertSingleGaugeApprox(t *testing.T, rec *telemetrytest.Recorder, name string, want float64) {
	t.Helper()
	pts := rec.MetricPoints(name)
	if len(pts) != 1 {
		t.Fatalf("got %d %s series, want 1", len(pts), name)
	}
	const epsilon = 1e-9
	if diff := pts[0].Value - want; diff > epsilon || diff < -epsilon {
		t.Errorf("%s = %v, want %v", name, pts[0].Value, want)
	}
}
