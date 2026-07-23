package telemetry_test

import (
	"bytes"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"log/slog"
	"sort"
	"strconv"
	"strings"
	"testing"

	"github.com/rknightion/graph2otel/internal/telemetry"
	"github.com/rknightion/graph2otel/internal/telemetrytest"
)

// snapshotOf builds n GaugePoints whose value is their index, so the ranking a
// test expects is stated by construction: point i has value i, and the top-N are
// the highest indices.
func snapshotOf(n int) []telemetry.GaugePoint {
	pts := make([]telemetry.GaugePoint, n)
	for i := range pts {
		pts[i] = telemetry.GaugePoint{
			Value: float64(i),
			Attrs: telemetry.Attrs{"app_name": "app" + strconv.Itoa(i), "platform": "windows"},
		}
	}
	return pts
}

func pointsByAttr(t *testing.T, rec *telemetrytest.Recorder, metric, key string) map[string]float64 {
	t.Helper()
	out := map[string]float64{}
	for _, p := range rec.MetricPoints(metric) {
		out[p.Attrs[key]] = p.Value
	}
	return out
}

// TestUnderTheLimitIsAnExactPassthrough is the case that matters most, because
// it is every metric on a healthy deploy. Live max per-metric series on m7kni is
// 175 against a default limit of 5000 (#235), so the limiter's normal job is to
// do nothing, and doing nothing must be indistinguishable from not being there.
func TestUnderTheLimitIsAnExactPassthrough(t *testing.T) {
	rec := telemetrytest.New()
	lim := telemetry.WithCardinalityLimits(rec.Emitter(), telemetry.Limits{PerMetric: 100})

	lim.GaugeSnapshot("intune.detected_apps.device_count", "{device}", "d", snapshotOf(100))

	got := pointsByAttr(t, rec, "intune.detected_apps.device_count", "app_name")
	if len(got) != 100 {
		t.Fatalf("got %d series, want all 100 passed through untouched", len(got))
	}
	if _, folded := got["other"]; folded {
		t.Error("an `other` bucket was emitted at exactly the limit — the limit is a ceiling, not a trigger")
	}
}

// TestAdditiveTailFoldsIntoOtherKeepingTheTopByValue is the headline behavior:
// significance-ranked survival instead of the SDK's arrival order.
func TestAdditiveTailFoldsIntoOtherKeepingTheTopByValue(t *testing.T) {
	rec := telemetrytest.New()
	lim := telemetry.WithCardinalityLimits(rec.Emitter(), telemetry.Limits{PerMetric: 10})

	// Values 0..99; the top 10 by value are apps 90..99.
	lim.GaugeSnapshot("intune.detected_apps.device_count", "{device}", "d", snapshotOf(100))

	got := pointsByAttr(t, rec, "intune.detected_apps.device_count", "app_name")
	for i := 90; i < 100; i++ {
		name := "app" + strconv.Itoa(i)
		if v, ok := got[name]; !ok || v != float64(i) {
			t.Errorf("%s = %v (present=%v), want it kept at %d — it is in the top 10 by value", name, v, ok, i)
		}
	}
	if _, ok := got["app0"]; ok {
		t.Error("app0 (value 0, the least significant series) survived the clip")
	}
	// The tail is 0..89 inclusive, whose sum is 89*90/2.
	if v := got["other"]; v != 4005 {
		t.Errorf("other = %v, want 4005 (the sum of the folded tail) — a device count is "+
			"additive, so the fold must carry the tail's contribution rather than discard it", v)
	}
}

// TestFoldPreservesTheBoundedDimensions is the fork the issue did not surface.
//
// Folding {app_name, platform} by setting BOTH to `other` would destroy the
// platform breakdown, which is bounded and is exactly the shape #112 wants on a
// metric. Only the unbounded key — the one with the most distinct values — may
// become `other`.
func TestFoldPreservesTheBoundedDimensions(t *testing.T) {
	rec := telemetrytest.New()
	lim := telemetry.WithCardinalityLimits(rec.Emitter(), telemetry.Limits{PerMetric: 4})

	var pts []telemetry.GaugePoint
	for i := range 20 {
		platform := "windows"
		if i%2 == 1 {
			platform = "macos"
		}
		pts = append(pts, telemetry.GaugePoint{
			Value: float64(i),
			Attrs: telemetry.Attrs{"app_name": "app" + strconv.Itoa(i), "platform": platform},
		})
	}
	lim.GaugeSnapshot("intune.detected_apps.device_count", "{device}", "d", pts)

	var otherPlatforms []string
	for _, p := range rec.MetricPoints("intune.detected_apps.device_count") {
		if p.Attrs["app_name"] == "other" {
			otherPlatforms = append(otherPlatforms, p.Attrs["platform"])
		}
		if p.Attrs["platform"] == "other" {
			t.Errorf("platform was folded to `other` on %+v — platform has 2 distinct values "+
				"against app_name's 20; the clip key must be the unbounded one", p.Attrs)
		}
	}
	if len(otherPlatforms) != 2 {
		t.Errorf("got %d `other` series (%v), want 2 — one per platform, so the bounded "+
			"breakdown survives the fold", len(otherPlatforms), otherPlatforms)
	}
}

// TestNonAdditiveTailIsDroppedNotSummed is #235 fork 2, and the failure it
// prevents is worse than the one it accepts. Losing the tail of a score is a
// smaller number, visibly labeled as clipped. Summing it emits "the total of
// 4,000 health scores" under a legitimate-looking metric name, and nothing
// querying it can tell it was invented.
func TestNonAdditiveTailIsDroppedNotSummed(t *testing.T) {
	rec := telemetrytest.New()
	lim := telemetry.WithCardinalityLimits(rec.Emitter(), telemetry.Limits{PerMetric: 10})

	lim.GaugeSnapshot("intune.uxa.app_health.score", "{score}", "d", snapshotOf(100))

	got := pointsByAttr(t, rec, "intune.uxa.app_health.score", "app_name")
	if v, ok := got["other"]; ok {
		t.Errorf("an `other` bucket worth %v was emitted for a {score} gauge — summing scores "+
			"invents a number that was never measured", v)
	}
	if len(got) != 10 {
		t.Errorf("got %d series, want exactly 10 — the top by value, with the tail dropped", len(got))
	}
	if _, ok := got["app99"]; !ok {
		t.Error("app99, the highest-valued series, was not kept")
	}
}

// TestSelfObservabilityIsNeverClipped: graph2otel.* is bounded by collector and
// tenant count by construction, and silently dropping our own health signals
// under load is the worst available failure mode — it removes the evidence at
// exactly the moment it is needed.
func TestSelfObservabilityIsNeverClipped(t *testing.T) {
	rec := telemetrytest.New()
	lim := telemetry.WithCardinalityLimits(rec.Emitter(), telemetry.Limits{PerMetric: 5})

	lim.GaugeSnapshot("graph2otel.scrape.success", "{scrape}", "d", snapshotOf(50))

	if got := pointsByAttr(t, rec, "graph2otel.scrape.success", "app_name"); len(got) != 50 {
		t.Errorf("got %d self-obs series, want all 50 — graph2otel.* is never a clip candidate", len(got))
	}
}

// TestZeroLimitIsUnlimited is the self-hosted Prometheus/Mimir escape hatch: an
// operator who does not pay per active series turns the whole mechanism off.
func TestZeroLimitIsUnlimited(t *testing.T) {
	rec := telemetrytest.New()
	lim := telemetry.WithCardinalityLimits(rec.Emitter(), telemetry.Limits{PerMetric: 0})

	lim.GaugeSnapshot("intune.detected_apps.device_count", "{device}", "d", snapshotOf(5000))

	if got := pointsByAttr(t, rec, "intune.detected_apps.device_count", "app_name"); len(got) != 5000 {
		t.Errorf("got %d series with PerMetric=0, want all 5000 — 0 means unlimited", len(got))
	}
}

// TestIncumbentSurvivesAShallowRankDrop is the hysteresis (#235 fork 4).
//
// Without it, a series oscillating around the boundary appears and disappears
// every cycle: gaps in every graph, and an active series billed for anyway. An
// incumbent is evicted only once it falls clear of the band, so oscillation
// inside the band cannot flap it.
func TestIncumbentSurvivesAShallowRankDrop(t *testing.T) {
	rec := telemetrytest.New()
	lim := telemetry.WithCardinalityLimits(rec.Emitter(), telemetry.Limits{PerMetric: 100})

	// Cycle 1: app99..app0 by value; the top 100 of 200 are app199..app100.
	lim.GaugeSnapshot("intune.detected_apps.device_count", "{device}", "d", snapshotOf(200))
	first := pointsByAttr(t, rec, "intune.detected_apps.device_count", "app_name")
	if _, ok := first["app100"]; !ok {
		t.Fatalf("precondition: app100 should be admitted in cycle 1")
	}

	// Cycle 2: app100 slips just below the cut — rank 105 of 200, inside the
	// 10% band — while everything else is unchanged.
	pts := snapshotOf(200)
	pts[100].Value = 94.5 // between app94 and app95, i.e. rank ~105
	lim.GaugeSnapshot("intune.detected_apps.device_count", "{device}", "d", pts)

	second := pointsByAttr(t, rec, "intune.detected_apps.device_count", "app_name")
	if _, ok := second["app100"]; !ok {
		t.Error("app100 was evicted after a rank drop inside the hysteresis band — " +
			"a series oscillating around the boundary must not flap in and out every cycle")
	}
}

// TestIncumbentIsEvictedOnceItFallsClearOfTheBand is hysteresis' other half. A
// band that never evicts is not hysteresis, it is a permanent lease on a slot,
// and the top-N would freeze to whatever the process saw first — which is the
// arrival-ordered behavior this whole mechanism replaces.
func TestIncumbentIsEvictedOnceItFallsClearOfTheBand(t *testing.T) {
	rec := telemetrytest.New()
	lim := telemetry.WithCardinalityLimits(rec.Emitter(), telemetry.Limits{PerMetric: 100})

	lim.GaugeSnapshot("intune.detected_apps.device_count", "{device}", "d", snapshotOf(200))

	pts := snapshotOf(200)
	pts[100].Value = 1 // rank ~198 of 200, far outside the band
	lim.GaugeSnapshot("intune.detected_apps.device_count", "{device}", "d", pts)

	if _, ok := pointsByAttr(t, rec, "intune.detected_apps.device_count", "app_name")["app100"]; ok {
		t.Error("app100 kept its slot after collapsing to rank 198 — an incumbency that never " +
			"expires freezes the top-N to whatever arrived first")
	}
}

// TestSyncCounterFoldsUnadmittedSeriesIntoOther covers the instruments that have
// no set to rank: a Counter arrives one point at a time. Admission is by arrival
// and STICKY, which is what makes the fold safe — a series that never had its
// own slot contributes to `other` from its first observation, so `other` is
// monotonic and no series ever migrates into it retroactively (#235 fork 3).
func TestSyncCounterFoldsUnadmittedSeriesIntoOther(t *testing.T) {
	rec := telemetrytest.New()
	lim := telemetry.WithCardinalityLimits(rec.Emitter(), telemetry.Limits{PerMetric: 3})

	for i := range 10 {
		lim.Counter("entra.graph_activity.endpoint_requests", "{request}", "d", 1,
			telemetry.Attrs{"normalized_path": "/p" + strconv.Itoa(i), "method": "GET"})
	}

	got := pointsByAttr(t, rec, "entra.graph_activity.endpoint_requests", "normalized_path")
	if len(got) != 4 {
		t.Fatalf("got %d series (%v), want 4 — three admitted plus the `other` bucket. "+
			"PerMetric bounds the ADMITTED series; `other` is emitted in addition, which is "+
			"what keeps the fold from having to shrink the ranked set it just computed.", len(got), got)
	}
	if v := got["other"]; v != 7 {
		t.Errorf("other = %v, want 7 — the 7 paths that never won a slot", v)
	}
	for _, p := range rec.MetricPoints("entra.graph_activity.endpoint_requests") {
		if p.Attrs["method"] != "GET" {
			t.Errorf("method was clobbered on %+v — only the unbounded key becomes `other`", p.Attrs)
		}
	}
}

// TestSyncAdmissionIsStickyAcrossCalls: once a series has its own slot it keeps
// it, so nothing is ever folded retroactively and the counter stays monotonic.
func TestSyncAdmissionIsStickyAcrossCalls(t *testing.T) {
	rec := telemetrytest.New()
	lim := telemetry.WithCardinalityLimits(rec.Emitter(), telemetry.Limits{PerMetric: 2})

	add := func(path string) {
		lim.Counter("test.calls", "{request}", "d", 1, telemetry.Attrs{"normalized_path": path})
	}
	add("/a")
	for i := range 20 { // flood, so /a would lose on any re-ranking
		add("/flood" + strconv.Itoa(i))
	}
	add("/a")

	if v := pointsByAttr(t, rec, "test.calls", "normalized_path")["/a"]; v != 2 {
		t.Errorf("/a = %v, want 2 — an admitted series keeps its slot for the process lifetime, "+
			"or `other` would jump by its accumulated value and break monotonicity", v)
	}
}

// TestNonAdditiveSyncGaugeDropsRatherThanFolds mirrors the snapshot rule on the
// synchronous path: a dimensionless gauge is a flag or a ratio, and folding
// several entities' last values into one series produces whichever wrote last.
func TestNonAdditiveSyncGaugeDropsRatherThanFolds(t *testing.T) {
	rec := telemetrytest.New()
	lim := telemetry.WithCardinalityLimits(rec.Emitter(), telemetry.Limits{PerMetric: 2})

	for i := range 10 {
		lim.Gauge("test.ratio", "1", "d", float64(i), telemetry.Attrs{"policy_name": "p" + strconv.Itoa(i)})
	}

	got := pointsByAttr(t, rec, "test.ratio", "policy_name")
	if _, ok := got["other"]; ok {
		t.Error("a dimensionless gauge was folded into `other` — the result is whichever entity wrote last")
	}
	if len(got) != 2 {
		t.Errorf("got %d series (%v), want 2 admitted with the rest dropped", len(got), got)
	}
}

// TestClippingIsReported: clipping is data loss, and #235 fork 6 requires it be
// impossible for it to happen silently.
func TestClippingIsReported(t *testing.T) {
	rec := telemetrytest.New()
	lim := telemetry.NewLimiter(telemetry.Limits{PerMetric: 10})
	e := lim.Wrap(rec.Emitter())

	e.GaugeSnapshot("intune.detected_apps.device_count", "{device}", "d", snapshotOf(100))
	e.GaugeSnapshot("intune.uxa.app_health.score", "{score}", "d", snapshotOf(100))
	lim.Report(rec.Emitter(), nil)

	byMetricMode := map[string]float64{}
	for _, p := range rec.MetricPoints("graph2otel.series.clipped") {
		byMetricMode[p.Attrs["metric.name"]+"/"+p.Attrs["mode"]] = p.Value
	}
	if v := byMetricMode["intune.detected_apps.device_count/folded"]; v != 90 {
		t.Errorf("folded count = %v, want 90", v)
	}
	if v := byMetricMode["intune.uxa.app_health.score/dropped"]; v != 90 {
		t.Errorf("dropped count = %v, want 90", v)
	}
}

// TestGlobalLimitShrinksTheWorstOffenderFirst is #235 fork 5. A per-metric cap
// alone cannot honor a total budget: 200 metrics at 5000 each is a million
// series. The arbitration has to be a documented rule rather than an emergent
// one, and max-min fairness is the standard: metrics under their fair share are
// untouched, and only the metrics actually responsible for the overage shrink.
func TestGlobalLimitShrinksTheWorstOffenderFirst(t *testing.T) {
	// Three metrics: two small, one enormous. Budget 300 across all of them.
	got := telemetry.EffectiveLimits(
		map[string]int{"small.a": 10, "small.b": 20, "huge.c": 5000},
		300, 5000,
	)
	if got["small.a"] < 10 || got["small.b"] < 20 {
		t.Errorf("effective = %v — a metric under its fair share must not be shrunk to pay "+
			"for another metric's overage", got)
	}
	if got["huge.c"] > 300-30 {
		t.Errorf("huge.c = %d, want it shrunk to absorb the whole overage (<= 270)", got["huge.c"])
	}
	total := 0
	for m, lim := range got {
		total += min(lim, map[string]int{"small.a": 10, "small.b": 20, "huge.c": 5000}[m])
	}
	if total > 300 {
		t.Errorf("effective limits admit %d series against a global budget of 300: %v", total, got)
	}
}

// TestGlobalLimitUnderBudgetChangesNothing keeps the arbiter from having an
// opinion when there is no scarcity to arbitrate.
func TestGlobalLimitUnderBudgetChangesNothing(t *testing.T) {
	got := telemetry.EffectiveLimits(map[string]int{"a": 10, "b": 20}, 1000, 5000)
	for m, lim := range got {
		if lim != 5000 {
			t.Errorf("%s = %d, want the unmodified per-metric limit 5000 when the total is "+
				"comfortably under the global budget", m, lim)
		}
	}
}

// TestGlobalLimitZeroIsUnlimited mirrors the per-metric escape hatch.
func TestGlobalLimitZeroIsUnlimited(t *testing.T) {
	got := telemetry.EffectiveLimits(map[string]int{"a": 999999}, 0, 5000)
	if got["a"] != 5000 {
		t.Errorf("a = %d, want 5000 — a global limit of 0 means unlimited and must not "+
			"constrain the per-metric limit", got["a"])
	}
}

// TestLimiterStampsNothingAndPreservesAttrs guards the property every emitter
// decorator in this package has to have: it must never mutate the caller's Attrs
// map. mapSignIn is deliberately one mapper shared by two transports, so its
// output map can be live in two decorated emitters at once (see WithTenant).
func TestLimiterStampsNothingAndPreservesAttrs(t *testing.T) {
	rec := telemetrytest.New()
	lim := telemetry.WithCardinalityLimits(rec.Emitter(), telemetry.Limits{PerMetric: 1})

	attrs := telemetry.Attrs{"app_name": "a", "platform": "windows"}
	lim.Counter("test.m", "{request}", "d", 1, attrs)
	lim.Counter("test.m", "{request}", "d", 1, telemetry.Attrs{"app_name": "b", "platform": "windows"})

	if fmt.Sprint(attrs) != fmt.Sprint(telemetry.Attrs{"app_name": "a", "platform": "windows"}) {
		t.Errorf("the caller's Attrs were mutated: %v", attrs)
	}
}

// TestEveryEmitterMethodIsLimited is the same gate tenant.go has, for the same
// reason and against a nastier failure.
//
// limiterEmitter embeds Emitter, so a method it does not override is PROMOTED
// from the wrapped emitter and compiles perfectly — while emitting completely
// unlimited. Since the OTEL SDK's own cardinality cap is now disabled in favor
// of this (provider.go), a promoted method has NOTHING bounding it: one
// mis-scoped label on that instrument grows active series without any ceiling at
// all. Add an 8th method to Emitter and this fails until it is handled.
func TestEveryEmitterMethodIsLimited(t *testing.T) {
	fset := token.NewFileSet()

	iface, err := parser.ParseFile(fset, "types.go", nil, 0)
	if err != nil {
		t.Fatalf("parsing types.go: %v", err)
	}
	var want []string
	ast.Inspect(iface, func(n ast.Node) bool {
		ts, ok := n.(*ast.TypeSpec)
		if !ok || ts.Name.Name != "Emitter" {
			return true
		}
		it, ok := ts.Type.(*ast.InterfaceType)
		if !ok {
			return true
		}
		for _, m := range it.Methods.List {
			for _, name := range m.Names {
				want = append(want, name.Name)
			}
		}
		return false
	})
	if len(want) == 0 {
		t.Fatal("found no methods on the Emitter interface — did types.go move?")
	}

	impl, err := parser.ParseFile(fset, "limit.go", nil, 0)
	if err != nil {
		t.Fatalf("parsing limit.go: %v", err)
	}
	got := map[string]bool{}
	for _, d := range impl.Decls {
		fn, ok := d.(*ast.FuncDecl)
		if !ok || fn.Recv == nil || len(fn.Recv.List) != 1 {
			continue
		}
		star, ok := fn.Recv.List[0].Type.(*ast.StarExpr)
		if !ok {
			continue
		}
		if id, ok := star.X.(*ast.Ident); ok && id.Name == "limiterEmitter" {
			got[fn.Name.Name] = true
		}
	}

	var missing []string
	for _, m := range want {
		if !got[m] {
			missing = append(missing, m)
		}
	}
	sort.Strings(missing)
	for _, m := range missing {
		t.Errorf("limiterEmitter does not override Emitter.%s — it is promoted from the embedded\n"+
			"Emitter and emits with NO cardinality bound at all, since the SDK's own cap is\n"+
			"disabled in favor of this limiter. Add a %s method to limit.go.", m, m)
	}
}

// TestClippingLogsOnceOnTheTransition: a metric that starts clipping is an
// operator-visible event, and one that clips every 60s forever is not. The WARN
// fires on the transition into clipping, not on every interval, or it becomes
// noise nobody reads.
func TestClippingLogsOnceOnTheTransition(t *testing.T) {
	var buf bytes.Buffer
	lim := telemetry.NewLimiter(telemetry.Limits{PerMetric: 10})
	lim.SetLogger(slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelWarn})))
	rec := telemetrytest.New()
	e := lim.Wrap(rec.Emitter())

	for range 3 {
		e.GaugeSnapshot("intune.detected_apps.device_count", "{device}", "d", snapshotOf(100))
	}

	if n := strings.Count(buf.String(), "cardinality limit reached"); n != 1 {
		t.Errorf("logged %d times over 3 clipping cycles, want exactly 1 — a per-interval WARN "+
			"for a steady state is noise:\n%s", n, buf.String())
	}
}
