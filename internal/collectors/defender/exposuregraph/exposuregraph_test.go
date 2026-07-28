package exposuregraph

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/rknightion/graph2otel/internal/collectors"
	"github.com/rknightion/graph2otel/internal/semconv"
	"github.com/rknightion/graph2otel/internal/telemetry"
	"github.com/rknightion/graph2otel/internal/telemetrytest"
)

// loadArray reads testdata/<name> and unmarshals it as a []map[string]any.
func loadArray(t *testing.T, name string) []map[string]any {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("testdata", name))
	if err != nil {
		t.Fatalf("read %s: %v", name, err)
	}
	var out []map[string]any
	if err := json.Unmarshal(b, &out); err != nil {
		t.Fatalf("unmarshal %s: %v", name, err)
	}
	return out
}

// nodeCensus / edgeCensus load the verbatim live-captured census fixtures
// (2026-07-28, m7kni, #350): 19 bounded node labels plus the two
// bulk-inventory labels (Cve, mdcSecurityRecommendation), and the 13 pruned
// edge labels.
func nodeCensusFixture(t *testing.T) []map[string]any  { return loadArray(t, "node_census.json") }
func edgeCensusFixture(t *testing.T) []map[string]any  { return loadArray(t, "edge_census.json") }
func nodeSamplesFixture(t *testing.T) []map[string]any { return loadArray(t, "node_samples.json") }
func edgeSamplesFixture(t *testing.T) []map[string]any { return loadArray(t, "edge_samples.json") }

// fakeHunt routes queries by substring: "ExposureGraphNodes" without "|
// where" gets the node census; "ExposureGraphEdges" without a NodeLabel/
// EdgeLabel filter gets the edge census; anything else is matched against
// twin fixtures keyed by a substring of the query. Every query is recorded
// for assertions.
type fakeHunt struct {
	nodeCensus []map[string]any
	edgeCensus []map[string]any
	nodeTwins  []map[string]any // returned for any node twin query
	edgeTwins  []map[string]any // returned for any edge twin query

	// perLabelNodeTwins / perLabelEdgeTwins, when set, return a distinct
	// fixture keyed by an exact-match `== "<label>"` clause, for fallback
	// tests. Falls back to nodeTwins/edgeTwins when unset.
	perLabelNodeTwins map[string][]map[string]any
	perLabelEdgeTwins map[string][]map[string]any

	queries []string

	nodeCensusErr error
	edgeCensusErr error
	nodeTwinErr   error
	edgeTwinErr   error
}

func (f *fakeHunt) Query(_ context.Context, _ string, kql string) ([]map[string]any, error) {
	f.queries = append(f.queries, kql)

	switch {
	case kql == nodeCensusQuery:
		if f.nodeCensusErr != nil {
			return nil, f.nodeCensusErr
		}
		return f.nodeCensus, nil
	case strings.Contains(kql, "ExposureGraphEdges") && strings.Contains(kql, "summarize"):
		if f.edgeCensusErr != nil {
			return nil, f.edgeCensusErr
		}
		return f.edgeCensus, nil
	case strings.Contains(kql, "ExposureGraphNodes"):
		if f.nodeTwinErr != nil {
			return nil, f.nodeTwinErr
		}
		for label, rows := range f.perLabelNodeTwins {
			if strings.Contains(kql, `NodeLabel == "`+label+`"`) {
				return rows, nil
			}
		}
		return f.nodeTwins, nil
	case strings.Contains(kql, "ExposureGraphEdges"):
		if f.edgeTwinErr != nil {
			return nil, f.edgeTwinErr
		}
		for label, rows := range f.perLabelEdgeTwins {
			if strings.Contains(kql, `EdgeLabel == "`+label+`"`) {
				return rows, nil
			}
		}
		return f.edgeTwins, nil
	}
	return nil, nil
}

func newFake(t *testing.T) *fakeHunt {
	t.Helper()
	return &fakeHunt{
		nodeCensus: nodeCensusFixture(t),
		edgeCensus: edgeCensusFixture(t),
		nodeTwins:  nodeSamplesFixture(t),
		edgeTwins:  edgeSamplesFixture(t),
	}
}

// TestCollect_BoundingRule is the heart of #350: a label over twinThreshold
// (mdcSecurityRecommendation, Cve) is counted with twinned=false and
// contributes NO twins; every label under it is twinned=true.
func TestCollect_BoundingRule(t *testing.T) {
	f := newFake(t)
	rec := telemetrytest.New()
	c := New(collectors.HuntDeps{Client: f})
	if err := c.Collect(context.Background(), rec.Emitter(), nil); err != nil {
		t.Fatalf("Collect: %v", err)
	}

	pts := rec.MetricPoints(metricNodes)
	if len(pts) != 21 {
		t.Fatalf("metricNodes: got %d points, want 21 (19 bounded + 2 bulk)", len(pts))
	}
	for _, p := range pts {
		label := p.Attrs[semconv.AttrNodeLabel]
		wantTwinned := "true"
		if label == "Cve" || label == "mdcSecurityRecommendation" {
			wantTwinned = "false"
		}
		if got := p.Attrs[semconv.AttrTwinned]; got != wantTwinned {
			t.Errorf("node label %q: twinned=%q, want %q", label, got, wantTwinned)
		}
	}

	// The over-threshold labels must never appear in a node twin fetch query.
	for _, q := range f.queries {
		if strings.Contains(q, "ExposureGraphNodes") {
			if strings.Contains(q, `"Cve"`) && strings.Contains(q, "==") {
				t.Errorf("a node twin query selected Cve by ==, which is over threshold: %q", q)
			}
		}
	}
}

// TestCollect_ExcludedLabelsMetric splits by entity_type: 2 excluded node
// labels (Cve, mdcSecurityRecommendation) and 0 excluded edge labels on this
// fixture — and the edge series must still be seeded at 0, not absent.
func TestCollect_ExcludedLabelsMetric(t *testing.T) {
	f := newFake(t)
	rec := telemetrytest.New()
	c := New(collectors.HuntDeps{Client: f})
	if err := c.Collect(context.Background(), rec.Emitter(), nil); err != nil {
		t.Fatalf("Collect: %v", err)
	}
	pts := rec.MetricPoints(metricExcludedLabels)
	if len(pts) != 2 {
		t.Fatalf("metricExcludedLabels: got %d points, want 2 (node and edge, always seeded)", len(pts))
	}
	byType := map[string]float64{}
	for _, p := range pts {
		byType[p.Attrs[semconv.AttrEntityType]] = p.Value
	}
	if v, ok := byType["node"]; !ok || v != 2 {
		t.Errorf("node excluded-labels = %v (present=%v), want 2", v, ok)
	}
	if v, ok := byType["edge"]; !ok || v != 0 {
		t.Errorf("edge excluded-labels = %v (present=%v), want 0 (seeded, not absent)", v, ok)
	}
}

// TestCollect_NodeTwinsPerLiveLabel proves every one of the 19 live node
// labels maps without panicking and produces a twin.
func TestCollect_NodeTwinsPerLiveLabel(t *testing.T) {
	samples := nodeSamplesFixture(t)
	f := &fakeHunt{
		nodeCensus: nodeCensusFixture(t),
		edgeCensus: nil,
		nodeTwins:  samples,
	}
	rec := telemetrytest.New()
	c := New(collectors.HuntDeps{Client: f})
	if err := c.Collect(context.Background(), rec.Emitter(), nil); err != nil {
		t.Fatalf("Collect: %v", err)
	}
	logs := rec.LogRecords()
	var nodeLogs int
	seen := map[string]bool{}
	for _, l := range logs {
		if l.EventName != eventNode {
			continue
		}
		nodeLogs++
		seen[l.Attrs[semconv.AttrNodeLabel]] = true
	}
	if nodeLogs != len(samples) {
		t.Fatalf("got %d node twins, want %d (one per live sample)", nodeLogs, len(samples))
	}
	for _, s := range samples {
		label := s["NodeLabel"].(string)
		if !seen[label] {
			t.Errorf("label %q produced no twin", label)
		}
	}
}

// TestCollect_EdgeTwinsPerLiveLabel proves every one of the 13 live edge
// labels maps without panicking and produces a twin, and that userRights /
// logonMethods / isLocalAdmin land on "can authenticate to".
func TestCollect_EdgeTwinsPerLiveLabel(t *testing.T) {
	samples := edgeSamplesFixture(t)
	f := &fakeHunt{
		nodeCensus: nodeCensusFixture(t),
		edgeCensus: edgeCensusFixture(t),
		edgeTwins:  samples,
	}
	rec := telemetrytest.New()
	c := New(collectors.HuntDeps{Client: f})
	if err := c.Collect(context.Background(), rec.Emitter(), nil); err != nil {
		t.Fatalf("Collect: %v", err)
	}
	logs := rec.LogRecords()
	var edgeLogs int
	seen := map[string]bool{}
	for _, l := range logs {
		if l.EventName != eventEdge {
			continue
		}
		edgeLogs++
		seen[l.Attrs[semconv.AttrEdgeLabel]] = true
	}
	if edgeLogs != len(samples) {
		t.Fatalf("got %d edge twins, want %d (one per live sample)", edgeLogs, len(samples))
	}
	for _, s := range samples {
		label := s["EdgeLabel"].(string)
		if !seen[label] {
			t.Errorf("edge label %q produced no twin", label)
		}
	}
}

// TestEdgeQueries_AlwaysCarryNodeLabelPredicate is the #350 504 regression
// guard: every edge query (census AND twin) issued while there is a
// non-empty excluded node-label set must carry the SourceNodeLabel/
// TargetNodeLabel prune. A missing predicate is the known unbounded-query
// shape that returned HTTP 504 on ExposureGraphEdges.
func TestEdgeQueries_AlwaysCarryNodeLabelPredicate(t *testing.T) {
	f := newFake(t)
	rec := telemetrytest.New()
	c := New(collectors.HuntDeps{Client: f})
	if err := c.Collect(context.Background(), rec.Emitter(), nil); err != nil {
		t.Fatalf("Collect: %v", err)
	}
	var edgeQueries int
	for _, q := range f.queries {
		if !strings.Contains(q, "ExposureGraphEdges") {
			continue
		}
		edgeQueries++
		if !strings.Contains(q, "SourceNodeLabel !in") || !strings.Contains(q, "TargetNodeLabel !in") {
			t.Errorf("edge query missing the node-label prune (the known 504 shape): %q", q)
		}
	}
	if edgeQueries == 0 {
		t.Fatal("no edge queries were issued")
	}
}

// TestCollect_NodeCensusFailureIsFatal: without the census there is no
// excluded set, and nothing downstream can safely run.
func TestCollect_NodeCensusFailureIsFatal(t *testing.T) {
	f := &fakeHunt{nodeCensusErr: errors.New("403")}
	rec := telemetrytest.New()
	c := New(collectors.HuntDeps{Client: f})
	if err := c.Collect(context.Background(), rec.Emitter(), nil); err == nil {
		t.Fatal("node census failure should be fatal to the tick")
	}
	if len(rec.MetricPoints(metricNodes)) != 0 {
		t.Error("no gauges should emit when the node census fails")
	}
}

// TestCollect_EdgeCensusFailureIsNonFatal: the node census/twins and gauges
// still emit even when the edge side fails.
func TestCollect_EdgeCensusFailureIsNonFatal(t *testing.T) {
	f := &fakeHunt{
		nodeCensus:    nodeCensusFixture(t),
		nodeTwins:     nodeSamplesFixture(t),
		edgeCensusErr: errors.New("throttled"),
	}
	rec := telemetrytest.New()
	c := New(collectors.HuntDeps{Client: f})
	err := c.Collect(context.Background(), rec.Emitter(), nil)
	if err == nil {
		t.Fatal("an edge census failure should surface an aggregated error")
	}
	if len(rec.MetricPoints(metricNodes)) == 0 {
		t.Error("node gauges should still emit when the edge census fails")
	}
	if len(rec.MetricPoints(metricEdges)) != 0 {
		t.Error("edge gauges should not emit when the edge census failed")
	}
}

// TestCollect_NodeTwinFailureIsNonFatal: gauges still emit even when the twin
// fetch fails.
func TestCollect_NodeTwinFailureIsNonFatal(t *testing.T) {
	f := &fakeHunt{
		nodeCensus:  nodeCensusFixture(t),
		edgeCensus:  edgeCensusFixture(t),
		nodeTwinErr: errors.New("throttled"),
	}
	rec := telemetrytest.New()
	c := New(collectors.HuntDeps{Client: f})
	err := c.Collect(context.Background(), rec.Emitter(), nil)
	if err == nil {
		t.Fatal("a node twin failure should surface an aggregated error")
	}
	if len(rec.MetricPoints(metricNodes)) == 0 {
		t.Error("node gauges should still emit when the twin fetch fails")
	}
}

// TestCollect_Fallback_PerLabelQueries forces a tiny twinCap so the combined
// twin query is abandoned in favor of one query per twinned label, and
// proves every twinned label is covered exactly once — no duplicate, no
// drop.
func TestCollect_Fallback_PerLabelQueries(t *testing.T) {
	nodeCensus := []map[string]any{
		{"NodeLabel": "device", "n": float64(50)},
		{"NodeLabel": "user", "n": float64(50)},
		{"NodeLabel": "Cve", "n": float64(372330)},
	}
	perLabel := map[string][]map[string]any{
		"device": {{"NodeId": "d1", "NodeLabel": "device", "NodeName": "dev1"}},
		"user":   {{"NodeId": "u1", "NodeLabel": "user", "NodeName": "user1"}},
	}
	f := &fakeHunt{nodeCensus: nodeCensus, perLabelNodeTwins: perLabel}
	rec := telemetrytest.New()
	c := New(collectors.HuntDeps{Client: f})
	c.twinCap = 10 // force fallback: sum of twinned (100) > cap

	if err := c.Collect(context.Background(), rec.Emitter(), nil); err != nil {
		t.Fatalf("Collect: %v", err)
	}
	logs := rec.LogRecords()
	got := map[string]bool{}
	var nodeLogCount int
	for _, l := range logs {
		if l.EventName != eventNode {
			continue
		}
		nodeLogCount++
		got[l.Attrs[semconv.AttrNodeLabel]] = true
	}
	if nodeLogCount != 2 {
		t.Fatalf("got %d node twins, want 2 (one per fallback label, none dropped/duplicated)", nodeLogCount)
	}
	for _, label := range []string{"device", "user"} {
		if !got[label] {
			t.Errorf("label %q was not emitted under the fallback", label)
		}
	}
	// Every node twin query in the fallback must be a single `==` selector,
	// never the combined `!in`.
	for _, q := range f.queries {
		if strings.Contains(q, "ExposureGraphNodes") && strings.Contains(q, "!in") {
			t.Errorf("fallback should issue per-label == queries, not a combined !in query: %q", q)
		}
	}
}

// TestCollect_EdgeFallback_PerLabelQueries mirrors the node fallback for
// edges, using a synthetic over-threshold edge label to drive the EdgeLabel
// !in / == branches (no live edge label exceeds twinThreshold today).
func TestCollect_EdgeFallback_PerLabelQueries(t *testing.T) {
	nodeCensus := []map[string]any{{"NodeLabel": "device", "n": float64(5)}}
	edgeCensus := []map[string]any{
		{"EdgeLabel": "runs on", "n": float64(5)},
		{"EdgeLabel": "contains", "n": float64(5)},
		{"EdgeLabel": "has permissions to", "n": float64(50_000)}, // over threshold
	}
	perLabel := map[string][]map[string]any{
		"runs on":  {{"EdgeId": "e1", "EdgeLabel": "runs on"}},
		"contains": {{"EdgeId": "e2", "EdgeLabel": "contains"}},
	}
	f := &fakeHunt{nodeCensus: nodeCensus, edgeCensus: edgeCensus, perLabelEdgeTwins: perLabel}
	rec := telemetrytest.New()
	c := New(collectors.HuntDeps{Client: f})
	c.twinCap = 1 // force per-edge-label fallback

	if err := c.Collect(context.Background(), rec.Emitter(), nil); err != nil {
		t.Fatalf("Collect: %v", err)
	}
	logs := rec.LogRecords()
	got := map[string]bool{}
	for _, l := range logs {
		if l.EventName == eventEdge {
			got[l.Attrs[semconv.AttrEdgeLabel]] = true
		}
	}
	for _, label := range []string{"runs on", "contains"} {
		if !got[label] {
			t.Errorf("edge label %q was not emitted under the fallback", label)
		}
	}
	if got["has permissions to"] {
		t.Error("the over-threshold edge label must never be twinned")
	}
	// The over-threshold edge metric point must read twinned=false.
	for _, p := range rec.MetricPoints(metricEdges) {
		if p.Attrs[semconv.AttrEdgeLabel] == "has permissions to" && p.Attrs[semconv.AttrTwinned] != "false" {
			t.Errorf("has permissions to: twinned=%q, want false", p.Attrs[semconv.AttrTwinned])
		}
	}
}

// TestKqlString_Escaping covers a label containing a space (live: "Microsoft
// Entra OAuth App"), a double quote and a backslash — fmt.Sprintf("%q") is Go
// escaping, not KQL, so this must be its own helper and its own test.
func TestKqlString_Escaping(t *testing.T) {
	cases := []struct {
		in, want string
	}{
		{`Microsoft Entra OAuth App`, `"Microsoft Entra OAuth App"`},
		{`say "hi"`, `"say \"hi\""`},
		{`back\slash`, `"back\\slash"`},
		{`both \ and "`, `"both \\ and \""`},
	}
	for _, tc := range cases {
		if got := kqlString(tc.in); got != tc.want {
			t.Errorf("kqlString(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

func TestKqlStringList(t *testing.T) {
	got := kqlStringList([]string{"a", `b"c`})
	want := `"a", "b\"c"`
	if got != want {
		t.Errorf("kqlStringList = %q, want %q", got, want)
	}
}

// TestEntityIds_DoubleDecode covers the happy path and the unparsed-element
// path, index-aligned.
func TestEntityIds_DoubleDecode(t *testing.T) {
	raw := []any{
		`{"type":"AadObjectId","id":"tenantid=x;objectid=y"}`,
		`not json at all`,
	}
	ids, types, truncated := decodeEntityIDs(raw)
	if truncated {
		t.Error("2 elements should not truncate")
	}
	wantIDs := []string{"tenantid=x;objectid=y", "not json at all"}
	wantTypes := []string{"AadObjectId", "unparsed"}
	if !reflect.DeepEqual(ids, wantIDs) {
		t.Errorf("ids = %v, want %v", ids, wantIDs)
	}
	if !reflect.DeepEqual(types, wantTypes) {
		t.Errorf("types = %v, want %v", types, wantTypes)
	}
}

func TestEntityIds_Empty(t *testing.T) {
	ids, types, truncated := decodeEntityIDs(nil)
	if ids != nil || types != nil || truncated {
		t.Errorf("decodeEntityIDs(nil) = (%v,%v,%v), want (nil,nil,false)", ids, types, truncated)
	}
}

// TestBoolFrom covers all three accepted wire shapes plus absence.
func TestBoolFrom(t *testing.T) {
	if v, ok := boolFrom(true); !ok || !v {
		t.Errorf("boolFrom(true) = (%v,%v), want (true,true)", v, ok)
	}
	if v, ok := boolFrom(false); !ok || v {
		t.Errorf("boolFrom(false) = (%v,%v), want (false,true)", v, ok)
	}
	if v, ok := boolFrom(float64(1)); !ok || !v {
		t.Errorf("boolFrom(1.0) = (%v,%v), want (true,true)", v, ok)
	}
	if v, ok := boolFrom(float64(0)); !ok || v {
		t.Errorf("boolFrom(0.0) = (%v,%v), want (false,true)", v, ok)
	}
	if v, ok := boolFrom(json.Number("1")); !ok || !v {
		t.Errorf("boolFrom(json.Number(1)) = (%v,%v), want (true,true)", v, ok)
	}
	if v, ok := boolFrom(json.Number("0")); !ok || v {
		t.Errorf("boolFrom(json.Number(0)) = (%v,%v), want (false,true)", v, ok)
	}
	if _, ok := boolFrom(nil); ok {
		t.Error("boolFrom(nil) should be ok=false")
	}
	if _, ok := boolFrom("true"); ok {
		t.Error("boolFrom(string) should be ok=false")
	}
}

// TestNodeTwin_SidecarKeysNeverBecomeAttributes asserts no key containing "@"
// ever surfaces as an attribute, across every live node sample.
func TestNodeTwin_SidecarKeysNeverBecomeAttributes(t *testing.T) {
	for _, row := range nodeSamplesFixture(t) {
		ev := nodeTwin(row)
		for k := range ev.Attrs {
			if strings.Contains(k, "@") {
				t.Errorf("label %v: sidecar-looking attribute key %q leaked through", row["NodeLabel"], k)
			}
		}
	}
}

// TestNodeTwin_DescriptionNeverEmitted asserts semconv.AttrDescription never
// appears, across every live sample (several finding-shaped labels carry
// multi-paragraph HTML description prose that is identical on every tenant).
func TestNodeTwin_DescriptionNeverEmitted(t *testing.T) {
	for _, row := range nodeSamplesFixture(t) {
		ev := nodeTwin(row)
		if _, present := ev.Attrs[semconv.AttrDescription]; present {
			t.Errorf("label %v: semconv.AttrDescription must never be emitted", row["NodeLabel"])
		}
	}
}

// TestNodeTwin_DeprecationDateTypo asserts the wire's depricationDate typo is
// read correctly and published under the correctly spelled attribute. This is
// a WIRE FACT (live-observed 2026-07-28, #350), not a bug to fix.
func TestNodeTwin_DeprecationDateTypo(t *testing.T) {
	for _, row := range nodeSamplesFixture(t) {
		if row["NodeLabel"] != "baseModel" {
			continue
		}
		ev := nodeTwin(row)
		got, _ := ev.Attrs[semconv.AttrDeprecationDate].(string)
		if got == "" {
			t.Fatal("deprecation_date was not set from the wire's depricationDate field")
		}
		if got != "2026-09-21T00:00:00.0000000Z" {
			t.Errorf("deprecation_date = %q, want the live wire value", got)
		}
		return
	}
	t.Fatal("no baseModel sample found")
}

// TestNodeTwin_AbsentBooleanOmitsAttribute asserts a boolean the wire did not
// send produces NO attribute — never a fabricated false.
func TestNodeTwin_AbsentBooleanOmitsAttribute(t *testing.T) {
	row := map[string]any{
		"NodeId": "x", "NodeLabel": "device", "NodeName": "n",
		"NodeProperties": map[string]any{
			"rawData": map[string]any{
				"deviceName": "n", // no isExcluded key at all
			},
		},
	}
	ev := nodeTwin(row)
	if _, present := ev.Attrs[semconv.AttrIsExcluded]; present {
		t.Error("is_excluded should be absent when the wire did not send it, not false")
	}
}

// TestNodeTwin_UserRiskFields asserts hasLeakedCredentials/hasAdLeakedCredentials
// escalate severity to Warn, and Info otherwise.
func TestNodeTwin_UserRiskFields(t *testing.T) {
	leaked := map[string]any{
		"NodeId": "x", "NodeLabel": "user", "NodeName": "n",
		"NodeProperties": map[string]any{
			"rawData": map[string]any{"hasLeakedCredentials": true, "hasAdLeakedCredentials": false},
		},
	}
	if ev := nodeTwin(leaked); ev.Severity != telemetry.SeverityWarn {
		t.Errorf("hasLeakedCredentials=true severity = %v, want Warn", ev.Severity)
	}

	adLeaked := map[string]any{
		"NodeId": "x", "NodeLabel": "user", "NodeName": "n",
		"NodeProperties": map[string]any{
			"rawData": map[string]any{"hasLeakedCredentials": false, "hasAdLeakedCredentials": true},
		},
	}
	if ev := nodeTwin(adLeaked); ev.Severity != telemetry.SeverityWarn {
		t.Errorf("hasAdLeakedCredentials=true severity = %v, want Warn", ev.Severity)
	}

	clean := map[string]any{
		"NodeId": "x", "NodeLabel": "user", "NodeName": "n",
		"NodeProperties": map[string]any{
			"rawData": map[string]any{"hasLeakedCredentials": false, "hasAdLeakedCredentials": false},
		},
	}
	if ev := nodeTwin(clean); ev.Severity != telemetry.SeverityInfo {
		t.Errorf("no leaked credentials severity = %v, want Info", ev.Severity)
	}
}

// TestNodeTwin_Timestamps proves twins are stamped at poll time (zero), never
// from any wire field — there is no Timestamp column on this table.
func TestNodeTwin_Timestamps(t *testing.T) {
	for _, row := range nodeSamplesFixture(t) {
		if ev := nodeTwin(row); !ev.Timestamp.IsZero() {
			t.Errorf("label %v: Timestamp = %v, want zero", row["NodeLabel"], ev.Timestamp)
		}
	}
}

func TestEdgeTwin_Timestamps(t *testing.T) {
	for _, row := range edgeSamplesFixture(t) {
		if ev := edgeTwin(row); !ev.Timestamp.IsZero() {
			t.Errorf("edge %v: Timestamp = %v, want zero", row["EdgeLabel"], ev.Timestamp)
		}
	}
}

// TestEdgeTwin_UserRightsOnDevice asserts the "can authenticate to" edge maps
// user_rights, logon_methods and is_local_admin, using reflect.DeepEqual
// against the RAW []string in Attrs (not a rendered/joined form — a joined
// comparison cannot see an element-boundary bug, per the #350 brief).
func TestEdgeTwin_UserRightsOnDevice(t *testing.T) {
	for _, row := range edgeSamplesFixture(t) {
		if row["EdgeLabel"] != "can authenticate to" {
			continue
		}
		ev := edgeTwin(row)
		wantRights := []string{
			"SeDebugPrivilege", "SeImpersonatePrivilege", "SeBackupPrivilege",
			"SeRestorePrivilege", "SeLoadDriverPrivilege", "SeTakeOwnershipPrivilege",
		}
		gotRights, _ := ev.Attrs[semconv.AttrUserRights].([]string)
		if !reflect.DeepEqual(gotRights, wantRights) {
			t.Errorf("user_rights = %v, want %v", gotRights, wantRights)
		}
		wantMethods := []string{"remoteInteractive", "interactive", "network", "batch"}
		gotMethods, _ := ev.Attrs[semconv.AttrLogonMethods].([]string)
		if !reflect.DeepEqual(gotMethods, wantMethods) {
			t.Errorf("logon_methods = %v, want %v", gotMethods, wantMethods)
		}
		if ev.Attrs[semconv.AttrIsLocalAdmin] != "true" {
			t.Errorf("is_local_admin = %v, want true", ev.Attrs[semconv.AttrIsLocalAdmin])
		}
		return
	}
	t.Fatal("no 'can authenticate to' sample found")
}

// propertyAttrsByLabel is every attribute key sourced from an edge's
// EdgeProperties sub-object (i.e. everything except the endpoint/identity
// attributes every edge carries), keyed by the ONE edge label the live
// sample carrying that shape has.
var propertyAttrsByLabel = map[string][]string{
	"can authenticate to": {semconv.AttrUserRights, semconv.AttrLogonMethods, semconv.AttrIsLocalAdmin},
	// applicationPermissions.permissions is EMPTY on the live sample, so it
	// correctly produces no attribute — only delegated_permissions is
	// expected here (absent-is-not-empty; see TestEdgeTwin_HasPermissionsTo).
	"has permissions to": {semconv.AttrDelegatedPermissions},
	"has role on":        {semconv.AttrRolePermissions},
	"has credentials of": {semconv.AttrHasPrimaryRefreshToken},
}

// allPropertyAttrs is the union of every key in propertyAttrsByLabel, used to
// assert a label gets ONLY its own sub-object's attributes.
func allPropertyAttrs() map[string]bool {
	out := map[string]bool{}
	for _, keys := range propertyAttrsByLabel {
		for _, k := range keys {
			out[k] = true
		}
	}
	return out
}

// TestEdgeTwin_OnlyOwnPropertyAttrs asserts each edge label carries ONLY the
// property attributes its own EdgeProperties sub-object maps to — e.g. "runs
// on" and "member of" (whose rawData is empty) carry NONE of the four mapped
// property shapes, and "has permissions to" never picks up user_rights or
// role_permissions.
func TestEdgeTwin_OnlyOwnPropertyAttrs(t *testing.T) {
	all := allPropertyAttrs()
	for _, row := range edgeSamplesFixture(t) {
		label := row["EdgeLabel"].(string)
		want := map[string]bool{}
		for _, k := range propertyAttrsByLabel[label] {
			want[k] = true
		}
		ev := edgeTwin(row)
		for k := range all {
			_, present := ev.Attrs[k]
			switch {
			case want[k] && !present:
				t.Errorf("edge %q: expected property attribute %q, got none", label, k)
			case !want[k] && present:
				t.Errorf("edge %q: unexpected property attribute %q (belongs to a different label's shape)", label, k)
			}
		}
	}
}

// TestEdgeTwin_HasPermissionsTo covers the "has permissions to" live sample:
// delegatedPermissions.permissions decodes to its values, and
// applicationPermissions.permissions (empty on the wire) is OMITTED, not an
// empty list — absent-is-not-empty.
func TestEdgeTwin_HasPermissionsTo(t *testing.T) {
	for _, row := range edgeSamplesFixture(t) {
		if row["EdgeLabel"] != "has permissions to" {
			continue
		}
		ev := edgeTwin(row)
		want := []string{
			"DeviceManagementApps.ReadWrite.All",
			"DeviceManagementConfiguration.ReadWrite.All",
			"DeviceManagementManagedDevices.ReadWrite.All",
			"DeviceManagementServiceConfig.ReadWrite.All",
			"DeviceManagementRBAC.ReadWrite.All",
			"DeviceManagementManagedDevices.PrivilegedOperations.All",
		}
		got, _ := ev.Attrs[semconv.AttrDelegatedPermissions].([]string)
		if !reflect.DeepEqual(got, want) {
			t.Errorf("delegated_permissions = %v, want %v", got, want)
		}
		if _, present := ev.Attrs[semconv.AttrApplicationPermissions]; present {
			t.Error("application_permissions should be absent — the live sample's array is empty")
		}
		return
	}
	t.Fatal("no 'has permissions to' sample found")
}

// TestEdgeTwin_HasRoleOn covers the "has role on" live sample.
func TestEdgeTwin_HasRoleOn(t *testing.T) {
	for _, row := range edgeSamplesFixture(t) {
		if row["EdgeLabel"] != "has role on" {
			continue
		}
		ev := edgeTwin(row)
		want := []string{"Owner"}
		got, _ := ev.Attrs[semconv.AttrRolePermissions].([]string)
		if !reflect.DeepEqual(got, want) {
			t.Errorf("role_permissions = %v, want %v", got, want)
		}
		return
	}
	t.Fatal("no 'has role on' sample found")
}

// TestEdgeTwin_HasCredentialsOf covers the "has credentials of" live sample:
// primaryRefreshToken.primaryRefreshToken is a plain JSON bool, not wrapped.
func TestEdgeTwin_HasCredentialsOf(t *testing.T) {
	for _, row := range edgeSamplesFixture(t) {
		if row["EdgeLabel"] != "has credentials of" {
			continue
		}
		ev := edgeTwin(row)
		if ev.Attrs[semconv.AttrHasPrimaryRefreshToken] != "true" {
			t.Errorf("has_primary_refresh_token = %v, want true", ev.Attrs[semconv.AttrHasPrimaryRefreshToken])
		}
		return
	}
	t.Fatal("no 'has credentials of' sample found")
}

// TestDecodeWrappedValues covers the happy path and a not-valid-JSON element,
// generalizing the EntityIds double-decode trap onto the permission/role
// shapes.
func TestDecodeWrappedValues(t *testing.T) {
	raw := []any{
		`{"permissionValue":"Foo.Read"}`,
		`not json`,
	}
	got, truncated := decodeWrappedValues(raw, "permissionValue")
	if truncated {
		t.Error("2 elements should not truncate")
	}
	want := []string{"Foo.Read", "not json"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("decodeWrappedValues = %v, want %v", got, want)
	}
}

// TestDecodeWrappedValues_Empty asserts an empty array decodes to nothing —
// the caller (edgeTwin, via SetStrs) then omits the attribute entirely,
// rather than publishing an empty list.
func TestDecodeWrappedValues_Empty(t *testing.T) {
	got, truncated := decodeWrappedValues([]any{}, "permissionValue")
	if got != nil || truncated {
		t.Errorf("decodeWrappedValues(empty) = (%v,%v), want (nil,false)", got, truncated)
	}
}

// TestNodeTwin_ArraysTruncated proves the cap and the truncation flag.
func TestNodeTwin_ArraysTruncated(t *testing.T) {
	long := make([]any, maxListItems+5)
	for i := range long {
		long[i] = "tag"
	}
	row := map[string]any{
		"NodeId": "x", "NodeLabel": "group", "NodeName": "n",
		"NodeProperties": map[string]any{
			"rawData": map[string]any{"tags": long},
		},
	}
	ev := nodeTwin(row)
	got, _ := ev.Attrs[semconv.AttrTags].([]string)
	if len(got) != maxListItems {
		t.Errorf("tags length = %d, want capped at %d", len(got), maxListItems)
	}
	if ev.Attrs[semconv.AttrArraysTruncated] != "true" {
		t.Errorf("arrays_truncated = %v, want true", ev.Attrs[semconv.AttrArraysTruncated])
	}
}

func TestNodeTwin_NoTruncationUnderCap(t *testing.T) {
	row := map[string]any{
		"NodeId": "x", "NodeLabel": "group", "NodeName": "n",
		"NodeProperties": map[string]any{
			"rawData": map[string]any{"tags": []any{"a", "b"}},
		},
	}
	ev := nodeTwin(row)
	if _, present := ev.Attrs[semconv.AttrArraysTruncated]; present {
		t.Error("arrays_truncated should be absent when nothing was capped")
	}
}
