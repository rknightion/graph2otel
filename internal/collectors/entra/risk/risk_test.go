package risk

import (
	"context"
	"encoding/json"
	"errors"
	"testing"

	"github.com/rknightion/graph2otel/internal/collectors"
	"github.com/rknightion/graph2otel/internal/license"
	"github.com/rknightion/graph2otel/internal/telemetry"
	"github.com/rknightion/graph2otel/internal/telemetrytest"
)

// fakeGraph maps request URLs to canned page bodies (or errors). It satisfies
// collectors.GraphClient so Collector can be driven through
// collectors.GetAllValues without any live Graph call.
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
	return []byte(f.bodies[url]), nil
}

var _ collectors.GraphClient = (*fakeGraph)(nil)

const base = "https://graph.microsoft.com/v1.0"

const usersURL = base + "/identityProtection/riskyUsers"
const spsURL = base + "/identityProtection/riskyServicePrincipals"

// The per-entity fields below (UPN, appId, display names) MUST reach the log
// twin and MUST NOT reach any metric attribute — see TestCollectNoPerEntitySeries
// for the metric half of that boundary and the log-twin tests for the other.
// u2 is deliberately sparse: it exercises the omit-absent-attrs path.
const usersBody = `{"value":[
	{"id":"u1","riskLevel":"high","riskState":"atRisk","riskDetail":"userPassedMFADrivenByRiskBasedPolicy","riskLastUpdatedDateTime":"2026-07-16T09:00:00Z","userPrincipalName":"alice@example.com","userDisplayName":"Alice Example"},
	{"id":"u2","riskLevel":"high","riskState":"atRisk"},
	{"id":"u3","riskLevel":"medium","riskState":"confirmedCompromised","userPrincipalName":"carol@example.com","userDisplayName":"Carol Example"}
]}`

const spsBody = `{"value":[
	{"id":"sp1","riskLevel":"low","riskState":"remediated","riskDetail":"adminConfirmedServicePrincipalCompromised","riskLastUpdatedDateTime":"2026-07-16T08:30:00Z","appId":"11111111-2222-3333-4444-555555555555","displayName":"Legacy Sync App","servicePrincipalType":"Application"}
]}`

// liveUsersBody wraps a VERBATIM GET /identityProtection/riskyUsers record from
// the m7kni tenant, read as graph2otel-poller on 2026-07-17
// `[live-measured 2026-07-17, #129/#153]`. It is the risky user #129 synthesized,
// and the only real one this project has ever observed — riskyUsers is empty on a
// healthy tenant, which is why unmapped fields went unnoticed for the life of the
// project.
//
// Pinned rather than hand-written because it settles two things no doc could:
//
//  1. isProcessing IS on the wire (#153). It is mapped; see the log-twin test.
//  2. isDeleted is `false` on a user that was definitively deleted — 404 on
//     /users/{id}, and present in /directory/deletedItems. That is #153's second
//     defect, still reproducing on this read. isDeleted is therefore deliberately
//     NOT mapped: an operator filtering isDeleted=false would believe they had
//     excluded deleted users while including this very one. The decision is parked
//     on a post-purge re-check after 2026-08-16, which is what distinguishes
//     soft-delete lag from a permanent lie. Do not map it before that check.
//
// Note riskLevel is "low" here while the same user's riskDetections record says
// "medium" — Microsoft aggregates user risk differently from detection risk, so
// entra.risk and entra.risk_detections legitimately disagree on severity for one
// incident. Not a graph2otel bug; documented in docs/signals.md.
const liveUsersBody = `{"value":[
	{
		"id": "5289e9c7-3945-4ffd-8fd3-d56124baf45d",
		"isDeleted": false,
		"isProcessing": false,
		"riskLevel": "low",
		"riskState": "atRisk",
		"riskDetail": "none",
		"riskLastUpdatedDateTime": "2026-07-17T10:14:47.3023572Z",
		"userDisplayName": "RISK SYNTH - DELETE ME (graph2otel #129)",
		"userPrincipalName": "risk-synth-DELETE-ME@m7kni.io"
	}
]}`

func fullFixture() *fakeGraph {
	return &fakeGraph{bodies: map[string]string{
		usersURL: usersBody,
		spsURL:   spsBody,
	}}
}

// liveFixture serves the pinned live riskyUsers record, with no risky service
// principals (the live tenant has none).
func liveFixture() *fakeGraph {
	return &fakeGraph{bodies: map[string]string{
		usersURL: liveUsersBody,
		spsURL:   `{"value":[]}`,
	}}
}

func bothCaps() license.Capabilities {
	return license.Capabilities{
		license.CapEntraP2:                   true,
		license.CapWorkloadIdentitiesPremium: true,
	}
}

func metricAttrCounts(pts []telemetrytest.MetricPoint) map[[2]string]float64 {
	got := map[[2]string]float64{}
	for _, p := range pts {
		got[[2]string{p.Attrs["risk_level"], p.Attrs["risk_state"]}] = p.Value
	}
	return got
}

func TestCollectBothLicensedEmitsBothMetrics(t *testing.T) {
	g := fullFixture()
	rec := telemetrytest.New()

	c := New(g, bothCaps(), nil)
	if err := c.Collect(context.Background(), rec.Emitter()); err != nil {
		t.Fatalf("Collect: %v", err)
	}

	userPts := rec.MetricPoints(metricRiskyUsers)
	gotUsers := metricAttrCounts(userPts)
	wantUsers := map[[2]string]float64{
		{"high", "atRisk"}:                 2,
		{"medium", "confirmedCompromised"}: 1,
	}
	if len(gotUsers) != len(wantUsers) {
		t.Fatalf("got %d risky-user series, want %d: %v", len(gotUsers), len(wantUsers), gotUsers)
	}
	for k, v := range wantUsers {
		if gotUsers[k] != v {
			t.Errorf("risky users level=%s state=%s = %v, want %v", k[0], k[1], gotUsers[k], v)
		}
	}

	spPts := rec.MetricPoints(metricRiskyServicePrincipals)
	gotSPs := metricAttrCounts(spPts)
	wantSPs := map[[2]string]float64{{"low", "remediated"}: 1}
	if len(gotSPs) != len(wantSPs) {
		t.Fatalf("got %d risky-SP series, want %d: %v", len(gotSPs), len(wantSPs), gotSPs)
	}
	for k, v := range wantSPs {
		if gotSPs[k] != v {
			t.Errorf("risky SPs level=%s state=%s = %v, want %v", k[0], k[1], gotSPs[k], v)
		}
	}
}

func TestCollectNoPerEntitySeries(t *testing.T) {
	g := fullFixture()
	rec := telemetrytest.New()

	if err := New(g, bothCaps(), nil).Collect(context.Background(), rec.Emitter()); err != nil {
		t.Fatalf("Collect: %v", err)
	}

	for _, name := range []string{metricRiskyUsers, metricRiskyServicePrincipals} {
		for _, p := range rec.MetricPoints(name) {
			for k := range p.Attrs {
				if k != "risk_level" && k != "risk_state" {
					t.Errorf("metric %s has unexpected attribute %q (per-entity leak?): %v", name, k, p.Attrs)
				}
			}
		}
	}
}

// TestLogTwinEmitsIsProcessingFromLiveRiskyUser pins #153's isProcessing
// finding: the field is on the wire and reaches the log twin.
//
// It carries real operational meaning rather than trivia: isProcessing=true means
// Identity Protection is still recalculating that user's risk, so riskLevel and
// riskState are mid-flight and may change without any new detection. An analyst
// who does not know that reads a transient value as settled fact.
//
// It is a bool, so `false` is a real answer ("this state is settled"), not an
// absence — hence it is emitted whenever the field is present, unlike the string
// attributes which are omitted when empty. A filter on is_processing=false would
// silently drop every settled user if false were treated as "unset".
// It is asserted against logTwin directly rather than through the recorder on
// purpose: telemetrytest flattens log attributes with log.Value.AsString(), which
// yields "" for every non-string kind — so a bool attribute reads as present-but-
// empty there and its VALUE cannot be checked. Driving the mapper is what the
// recorder's own doc comment recommends.
func TestLogTwinEmitsIsProcessingFromLiveRiskyUser(t *testing.T) {
	item := decodeFirstUser(t, liveUsersBody)

	// The *bool decode is half of what is under test: absent must survive as nil.
	if item.IsProcessing == nil {
		t.Fatal("isProcessing decoded to nil from a live record that carries it")
	}

	ev := logTwin(item, usersHalf)
	got, ok := ev.Attrs["is_processing"]
	if !ok {
		t.Fatalf("is_processing absent, want false from the live record; attrs=%v", ev.Attrs)
	}
	if got != false {
		t.Errorf("is_processing = %#v, want the bool false (not a string)", got)
	}

	// isDeleted must NOT be mapped — see liveUsersBody. Guarding it here keeps the
	// parked decision (#153, post-2026-08-16 re-check) from being quietly undone.
	if v, ok := ev.Attrs["is_deleted"]; ok {
		t.Errorf("is_deleted = %v, want it unmapped: it reports false for a deleted user, so emitting it would let a filter exclude deleted users while including this one (#153)", v)
	}
}

// TestCollectLiveRecordKeepsGaugeBounded pins that the live record — now that it
// contributes a bool attribute to the log twin — still buckets the gauge by only
// the two bounded enums. Per-entity detail belongs to the twin, never a series
// (#112).
func TestCollectLiveRecordKeepsGaugeBounded(t *testing.T) {
	rec := telemetrytest.New()
	if err := New(liveFixture(), bothCaps(), nil).Collect(context.Background(), rec.Emitter()); err != nil {
		t.Fatalf("Collect: %v", err)
	}

	pts := rec.MetricPoints(metricRiskyUsers)
	if len(pts) != 1 {
		t.Fatalf("got %d %s series, want 1", len(pts), metricRiskyUsers)
	}
	for _, p := range pts {
		for k := range p.Attrs {
			if k != "risk_level" && k != "risk_state" {
				t.Errorf("metric %s gained attribute %q from the live record (per-entity leak?): %v", metricRiskyUsers, k, p.Attrs)
			}
		}
	}
	if got := logsNamed(rec.LogRecords(), eventRiskyUser); len(got) != 1 {
		t.Errorf("emitted %d %s logs, want 1 (the log twin carries the entity)", len(got), eventRiskyUser)
	}
}

// decodeFirstUser pulls the first riskyUser out of a list-response body.
func decodeFirstUser(t *testing.T, body string) riskyEntity {
	t.Helper()
	var resp struct {
		Value []riskyEntity `json:"value"`
	}
	if err := json.Unmarshal([]byte(body), &resp); err != nil {
		t.Fatalf("decode riskyUsers body: %v", err)
	}
	if len(resp.Value) == 0 {
		t.Fatal("no riskyUser records in body")
	}
	return resp.Value[0]
}

// TestLogTwinOmitsIsProcessingWhenAbsentFromWire pins the absent-vs-false
// distinction. riskyServicePrincipal has no isProcessing field at all, and a
// riskyUser record that omits it must not be reported as "not processing" — that
// would be graph2otel asserting a fact the wire never stated.
func TestLogTwinOmitsIsProcessingWhenAbsentFromWire(t *testing.T) {
	rec := telemetrytest.New()
	if err := New(fullFixture(), bothCaps(), nil).Collect(context.Background(), rec.Emitter()); err != nil {
		t.Fatalf("Collect: %v", err)
	}

	for _, name := range []string{eventRiskyUser, eventRiskySP} {
		for _, r := range logsNamed(rec.LogRecords(), name) {
			if v, ok := r.Attrs["is_processing"]; ok {
				t.Errorf("%s (id=%s) emitted is_processing = %q, want it omitted: the record carries no isProcessing field", name, r.Attrs["id"], v)
			}
		}
	}
}

// logsNamed returns the recorded log records carrying the given EventName.
func logsNamed(recs []telemetrytest.LogRecord, name string) []telemetrytest.LogRecord {
	var out []telemetrytest.LogRecord
	for _, r := range recs {
		if r.EventName == name {
			out = append(out, r)
		}
	}
	return out
}

// TestCollectEmitsRiskyUserLogTwin is the other half of the cardinality
// boundary: the per-entity detail the gauge cannot carry must land in the LOGS
// pipeline, not be dropped. Without it the collector answers "how much risk"
// but never "which user" — the question an analyst actually asks.
func TestCollectEmitsRiskyUserLogTwin(t *testing.T) {
	rec := telemetrytest.New()
	if err := New(fullFixture(), bothCaps(), nil).Collect(context.Background(), rec.Emitter()); err != nil {
		t.Fatalf("Collect: %v", err)
	}

	got := logsNamed(rec.LogRecords(), eventRiskyUser)
	if len(got) != 3 {
		t.Fatalf("emitted %d %s logs, want 3 (one per risky user)", len(got), eventRiskyUser)
	}

	var alice *telemetrytest.LogRecord
	for i := range got {
		if got[i].Attrs["id"] == "u1" {
			alice = &got[i]
		}
	}
	if alice == nil {
		t.Fatalf("no log for risky user u1; got %v", got)
	}

	want := map[string]string{
		"id":                  "u1",
		"user_principal_name": "alice@example.com",
		"user_display_name":   "Alice Example",
		"risk_level":          "high",
		"risk_state":          "atRisk",
		"risk_detail":         "userPassedMFADrivenByRiskBasedPolicy",
		"risk_last_updated":   "2026-07-16T09:00:00Z",
	}
	for k, v := range want {
		if alice.Attrs[k] != v {
			t.Errorf("risky-user log attr %q = %q, want %q", k, alice.Attrs[k], v)
		}
	}
}

// TestLogTwinSeverityTracksRiskLevel drives the mapper directly (the
// securityincidents idiom) so the assertion compares telemetry.Severity values
// rather than the recorder's already-translated OTEL wire numbers. Only "high"
// escalates — everything else is routine background state.
func TestLogTwinSeverityTracksRiskLevel(t *testing.T) {
	for _, tc := range []struct {
		level string
		want  telemetry.Severity
	}{
		{"high", telemetry.SeverityWarn},
		{"High", telemetry.SeverityWarn}, // Graph casing is not guaranteed
		{"medium", telemetry.SeverityInfo},
		{"low", telemetry.SeverityInfo},
		{"none", telemetry.SeverityInfo},
		{"", telemetry.SeverityInfo},
	} {
		ev := logTwin(riskyEntity{ID: "u1", RiskLevel: tc.level, RiskState: "atRisk"}, usersHalf)
		if ev.Severity != tc.want {
			t.Errorf("risk_level=%q severity = %v, want %v", tc.level, ev.Severity, tc.want)
		}
	}
}

// TestCollectEmitsRiskyServicePrincipalLogTwin covers the workload-identity
// half, whose per-entity shape differs (appId/displayName, no UPN).
func TestCollectEmitsRiskyServicePrincipalLogTwin(t *testing.T) {
	rec := telemetrytest.New()
	if err := New(fullFixture(), bothCaps(), nil).Collect(context.Background(), rec.Emitter()); err != nil {
		t.Fatalf("Collect: %v", err)
	}

	got := logsNamed(rec.LogRecords(), eventRiskySP)
	if len(got) != 1 {
		t.Fatalf("emitted %d %s logs, want 1", len(got), eventRiskySP)
	}

	want := map[string]string{
		"id":                     "sp1",
		"app_id":                 "11111111-2222-3333-4444-555555555555",
		"display_name":           "Legacy Sync App",
		"service_principal_type": "Application",
		"risk_level":             "low",
		"risk_state":             "remediated",
		"risk_detail":            "adminConfirmedServicePrincipalCompromised",
		"risk_last_updated":      "2026-07-16T08:30:00Z",
	}
	for k, v := range want {
		if got[0].Attrs[k] != v {
			t.Errorf("risky-SP log attr %q = %q, want %q", k, got[0].Attrs[k], v)
		}
	}
}

// TestLogTwinOmitsAbsentAttrs asserts a sparse entity (u2 — no UPN, no
// riskDetail) omits those attributes rather than emitting empty strings.
func TestLogTwinOmitsAbsentAttrs(t *testing.T) {
	rec := telemetrytest.New()
	if err := New(fullFixture(), bothCaps(), nil).Collect(context.Background(), rec.Emitter()); err != nil {
		t.Fatalf("Collect: %v", err)
	}

	for _, r := range logsNamed(rec.LogRecords(), eventRiskyUser) {
		if r.Attrs["id"] != "u2" {
			continue
		}
		for _, k := range []string{"user_principal_name", "user_display_name", "risk_detail", "risk_last_updated"} {
			if v, ok := r.Attrs[k]; ok {
				t.Errorf("sparse entity emitted absent attr %q = %q, want it omitted", k, v)
			}
		}
		return
	}
	t.Fatal("no log for sparse risky user u2")
}

// TestUnlicensedHalfEmitsNoLogTwin asserts the license gate short-circuits the
// log twin too — an unlicensed half must emit nothing, not empty logs.
func TestUnlicensedHalfEmitsNoLogTwin(t *testing.T) {
	rec := telemetrytest.New()
	caps := license.Capabilities{license.CapEntraP2: true}
	if err := New(fullFixture(), caps, nil).Collect(context.Background(), rec.Emitter()); err != nil {
		t.Fatalf("Collect: %v", err)
	}

	if got := logsNamed(rec.LogRecords(), eventRiskySP); len(got) != 0 {
		t.Errorf("unlicensed workload-identity half emitted %d logs, want 0", len(got))
	}
	if got := logsNamed(rec.LogRecords(), eventRiskyUser); len(got) != 3 {
		t.Errorf("licensed half emitted %d logs, want 3", len(got))
	}
}

func TestCollectOnlyP2EmitsUsersSkipsServicePrincipals(t *testing.T) {
	g := fullFixture()
	rec := telemetrytest.New()

	caps := license.Capabilities{license.CapEntraP2: true}
	if err := New(g, caps, nil).Collect(context.Background(), rec.Emitter()); err != nil {
		t.Fatalf("Collect: %v", err)
	}

	if pts := rec.MetricPoints(metricRiskyUsers); len(pts) == 0 {
		t.Error("expected risky-user series to be emitted under CapEntraP2")
	}
	if pts := rec.MetricPoints(metricRiskyServicePrincipals); len(pts) != 0 {
		t.Errorf("expected risky-SP series to be skipped without CapWorkloadIdentitiesPremium, got %v", pts)
	}
}

func TestCollectOnlyWorkloadIDEmitsServicePrincipalsSkipsUsers(t *testing.T) {
	g := fullFixture()
	rec := telemetrytest.New()

	caps := license.Capabilities{license.CapWorkloadIdentitiesPremium: true}
	if err := New(g, caps, nil).Collect(context.Background(), rec.Emitter()); err != nil {
		t.Fatalf("Collect: %v", err)
	}

	if pts := rec.MetricPoints(metricRiskyServicePrincipals); len(pts) == 0 {
		t.Error("expected risky-SP series to be emitted under CapWorkloadIdentitiesPremium")
	}
	if pts := rec.MetricPoints(metricRiskyUsers); len(pts) != 0 {
		t.Errorf("expected risky-user series to be skipped without CapEntraP2, got %v", pts)
	}
}

func TestCollectNeitherLicenseSkipsBothWithoutError(t *testing.T) {
	g := fullFixture()
	rec := telemetrytest.New()

	err := New(g, license.Capabilities{}, nil).Collect(context.Background(), rec.Emitter())
	if err != nil {
		t.Fatalf("Collect: %v, want nil (both halves gated off, not an error)", err)
	}
	if pts := rec.MetricPoints(metricRiskyUsers); len(pts) != 0 {
		t.Errorf("expected no risky-user series, got %v", pts)
	}
	if pts := rec.MetricPoints(metricRiskyServicePrincipals); len(pts) != 0 {
		t.Errorf("expected no risky-SP series, got %v", pts)
	}
}

func TestCollectNilCapabilitiesSkipsBothWithoutError(t *testing.T) {
	g := fullFixture()
	rec := telemetrytest.New()

	// A nil Capabilities map (Has is documented safe on nil) must behave
	// exactly like the empty set: both halves skipped, no panic, no error.
	err := New(g, nil, nil).Collect(context.Background(), rec.Emitter())
	if err != nil {
		t.Fatalf("Collect: %v, want nil", err)
	}
}

func TestCollectSurfacesPerHalfFailureButOtherHalfStillEmits(t *testing.T) {
	g := fullFixture()
	g.errs = map[string]error{usersURL: errors.New("throttled")}
	rec := telemetrytest.New()

	err := New(g, bothCaps(), nil).Collect(context.Background(), rec.Emitter())
	if err == nil {
		t.Fatal("expected Collect to surface the risky-users failure")
	}
	if pts := rec.MetricPoints(metricRiskyUsers); len(pts) != 0 {
		t.Errorf("risky-users should have no data on failure, got %v", pts)
	}
	if pts := rec.MetricPoints(metricRiskyServicePrincipals); len(pts) == 0 {
		t.Error("risky-SPs should still emit despite the risky-users failure")
	}
}

func TestNameAndPermissions(t *testing.T) {
	c := New(&fakeGraph{}, license.Capabilities{}, nil)
	if c.Name() != "entra.risk" {
		t.Errorf("Name = %q, want entra.risk", c.Name())
	}
	perms := c.RequiredPermissions()
	want := map[string]bool{"IdentityRiskyUser.Read.All": true, "IdentityRiskyServicePrincipal.Read.All": true}
	if len(perms) != len(want) {
		t.Fatalf("RequiredPermissions = %v, want %v", perms, want)
	}
	for _, p := range perms {
		if !want[p] {
			t.Errorf("unexpected permission %q", p)
		}
	}
}
