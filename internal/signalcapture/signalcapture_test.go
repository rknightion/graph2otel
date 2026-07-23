package signalcapture_test

import (
	"strings"
	"testing"

	"github.com/rknightion/graph2otel/internal/semconv"
	"github.com/rknightion/graph2otel/internal/signalcapture"
	"github.com/rknightion/graph2otel/internal/telemetry"
	"github.com/rknightion/graph2otel/internal/telemetrytest"
)

// TestUnionCollectsMetricsAndLogsAcrossRecorders pins the mechanism the whole
// gate rests on: the union of what a package's tests emitted, gathered without
// any test opting in.
func TestUnionCollectsMetricsAndLogsAcrossRecorders(t *testing.T) {
	a := telemetrytest.New()
	a.Emitter().Gauge("test.alpha", "1", "d", 1, telemetry.Attrs{"state": "ok"})
	b := telemetrytest.New()
	b.Emitter().LogEvent(telemetry.Event{Name: "test.beta", Attrs: telemetry.Attrs{"id": "x"}})

	got := signalcapture.Union([]*telemetrytest.Recorder{a, b})

	if len(got.Metrics) != 1 || got.Metrics[0].Name != "test.alpha" {
		t.Fatalf("metrics = %+v, want one named test.alpha", got.Metrics)
	}
	if len(got.Metrics[0].AttrKeys) != 1 || got.Metrics[0].AttrKeys[0] != "state" {
		t.Errorf("metric attr keys = %v, want [state]", got.Metrics[0].AttrKeys)
	}
	if len(got.Logs) != 1 || got.Logs[0].EventName != "test.beta" {
		t.Fatalf("logs = %+v, want one named test.beta", got.Logs)
	}
	if len(got.Logs[0].AttrKeys) != 1 || got.Logs[0].AttrKeys[0] != "id" {
		t.Errorf("log attr keys = %v, want [id]", got.Logs[0].AttrKeys)
	}
}

// TestUnionMergesAttrKeysForTheSameMetric: two tests exercising different code
// paths of one collector see different attribute sets. The union must be the
// merge, or the gate judges a collector on whichever test ran last.
func TestUnionMergesAttrKeysForTheSameMetric(t *testing.T) {
	a := telemetrytest.New()
	a.Emitter().Gauge("test.merged", "1", "d", 1, telemetry.Attrs{"state": "ok"})
	b := telemetrytest.New()
	b.Emitter().Gauge("test.merged", "1", "d", 1, telemetry.Attrs{"os": "windows"})

	got := signalcapture.Union([]*telemetrytest.Recorder{a, b})

	if len(got.Metrics) != 1 {
		t.Fatalf("got %d metrics, want 1 merged: %+v", len(got.Metrics), got.Metrics)
	}
	if strings.Join(got.Metrics[0].AttrKeys, ",") != "os,state" {
		t.Errorf("attr keys = %v, want sorted merge [os state]", got.Metrics[0].AttrKeys)
	}
}

// TestPerEntityMetricLabelIsAViolation is the gate #112 has never had.
//
// #110/#111/#114 exist because twelve collectors quietly put per-entity data on
// metric labels, and #83 is a thirteenth that survived the sweep — it shipped
// app_name as a metric label, 1,870 series on a SIX-device tenant. Every one was
// found by a human reading code. This makes it a build failure.
func TestPerEntityMetricLabelIsAViolation(t *testing.T) {
	for _, key := range []string{
		"user_principal_name", "user_id", "device_id", "device_name",
		"serial_number", "ip_address", "correlation_id", "id",
	} {
		t.Run(key, func(t *testing.T) {
			r := telemetrytest.New()
			r.Emitter().Gauge("test.bad", "1", "d", 1, telemetry.Attrs{key: "v"})

			v := signalcapture.PerEntityViolations(signalcapture.Union([]*telemetrytest.Recorder{r}))

			if len(v) != 1 {
				t.Fatalf("got %d violations for metric label %q, want 1 — a series keyed by "+
					"this grows with tenant size (#112)", len(v), key)
			}
			if v[0].Metric != "test.bad" || v[0].AttrKey != key {
				t.Errorf("violation = %+v, want test.bad/%s", v[0], key)
			}
		})
	}
}

// TestPerEntityLogAttributeIsNotAViolation pins the other half of #112, and it
// is the half people get wrong. The rule is a DATA-MODELING rule, not a privacy
// control: per-entity data belongs in logs, by design, and graph2otel is a SIEM
// feed whose whole point is per-entity detail. A gate that flagged UPNs in LOGS
// would be enforcing the exact misreading (#112) that caused #110/#111 and a
// third recurrence on #100.
func TestPerEntityLogAttributeIsNotAViolation(t *testing.T) {
	r := telemetrytest.New()
	r.Emitter().LogEvent(telemetry.Event{
		Name: "test.twin",
		Attrs: telemetry.Attrs{
			"user_principal_name": "a@b.c",
			"device_id":           "d1",
			"ip_address":          "1.2.3.4",
		},
	})

	if v := signalcapture.PerEntityViolations(signalcapture.Union([]*telemetrytest.Recorder{r})); len(v) != 0 {
		t.Errorf("per-entity attributes on a LOG were flagged: %+v — logs are exactly where "+
			"this data belongs (#112/#114); flagging them inverts the rule", v)
	}
}

// TestBoundedMetricLabelIsNotAViolation guards against the gate being so eager
// it blocks the shape #112 actively wants: bounded, tenant-shaped aggregates.
func TestBoundedMetricLabelIsNotAViolation(t *testing.T) {
	r := telemetrytest.New()
	r.Emitter().Gauge("test.good", "1", "d", 1, telemetry.Attrs{
		"state": "compliant", "os": "windows", "severity": "high", "status": "ok",
	})

	if v := signalcapture.PerEntityViolations(signalcapture.Union([]*telemetrytest.Recorder{r})); len(v) != 0 {
		t.Errorf("bounded aggregate labels were flagged: %+v — these are the shape the rule wants", v)
	}
}

// TestSelfObsTenantIDIsNotAViolation: tenant_id is legitimately a metric label
// on graph2otel.* self-obs signals (#143), and is bounded by tenant count. The
// denylist must not break the one place it is correct.
func TestSelfObsTenantIDIsNotAViolation(t *testing.T) {
	r := telemetrytest.New()
	r.Emitter().Gauge("graph2otel.scrape.success", "1", "d", 1, telemetry.Attrs{
		"collector": "entra.risk", "tenant_id": "t1",
	})

	if v := signalcapture.PerEntityViolations(signalcapture.Union([]*telemetrytest.Recorder{r})); len(v) != 0 {
		t.Errorf("self-obs labels flagged: %+v — tenant_id on graph2otel.* is correct (#143)", v)
	}
}

// TestNoSignalsAtAllIsThin is #164's floor: a collector package whose tests
// drove no emission at all produces a golden that asserts nothing, while looking
// exactly like a passing gate.
//
// entra/graphactivity shipped in that state — `"Logs": null` against a mapper
// setting 22 attributes — and the gate was green over it for as long as it
// existed.
func TestNoSignalsAtAllIsThin(t *testing.T) {
	reasons := signalcapture.ThinReasons(signalcapture.Signals{})

	if len(reasons) != 1 {
		t.Fatalf("ThinReasons(empty) = %v, want exactly 1 reason — a collector "+
			"package that emitted nothing has a golden that gates nothing (#164)", reasons)
	}
	if !strings.Contains(reasons[0], "no signals") {
		t.Errorf("reason = %q, want it to name the empty capture", reasons[0])
	}
}

// TestLogCarryingOnlyFrameworkStampsIsThin closes the cheapest escape from the
// floor above.
//
// The floor asks for "at least one signal". The lowest-effort way to satisfy it
// without doing the work #164 asks for is to drive an EMPTY record through the
// engine: the emitter decorators still stamp ingest_transport (#141) and
// tenant_id (#143), so a log record appears, the golden is non-empty, and it
// still describes none of the collector's own attributes. Those two keys are
// authored by telemetry.WithTransport/WithTenant, not by the collector, so a
// record carrying only them is the "Logs": null failure one notch up.
func TestLogCarryingOnlyFrameworkStampsIsThin(t *testing.T) {
	for _, attrs := range []telemetry.Attrs{
		{semconv.AttrIngestTransport: "graph"},
		{semconv.AttrIngestTransport: "blob", semconv.AttrTenantID: "t1"},
	} {
		r := telemetrytest.New()
		r.Emitter().LogEvent(telemetry.Event{Name: "test.hollow", Attrs: attrs})

		reasons := signalcapture.ThinReasons(signalcapture.Union([]*telemetrytest.Recorder{r}))

		if len(reasons) != 1 {
			t.Fatalf("ThinReasons(log with only %v) = %v, want 1 reason — the collector "+
				"authored none of these keys, so the golden describes nothing (#164)", attrs, reasons)
		}
		if !strings.Contains(reasons[0], "test.hollow") {
			t.Errorf("reason = %q, want it to name the hollow event", reasons[0])
		}
	}
}

// TestLogWithOneCollectorAttrIsNotThin: the framework-stamp rule must trip only
// when the collector contributed NOTHING. One real attribute alongside the
// stamps is a real (if small) surface, and judging its richness is not something
// this check can do without reading the mapper — which #164 forbids.
func TestLogWithOneCollectorAttrIsNotThin(t *testing.T) {
	r := telemetrytest.New()
	r.Emitter().LogEvent(telemetry.Event{Name: "test.real", Attrs: telemetry.Attrs{
		semconv.AttrIngestTransport: "graph",
		"operation":                 "Add user",
	}})

	if reasons := signalcapture.ThinReasons(signalcapture.Union([]*telemetrytest.Recorder{r})); len(reasons) != 0 {
		t.Errorf("a log with a real collector attribute was flagged: %v", reasons)
	}
}

// TestBareMetricWithNoAttrKeysIsNotThin guards the false positive that killed
// the obvious generalization of this check.
//
// "Every signal must carry an attribute" reads well and is WRONG: measured
// 2026-07-17, 11 of 52 packages legitimately emit at least one metric with zero
// labels — entra.secure_score.current, entra.organization.age_days,
// entra.agreements.total, intune.devices.overview.enrolled_device_count. A
// tenant-wide total has nothing to break down BY. Flagging them would have made
// this gate cry wolf on a fifth of the tree on day one, and a gate people exempt
// is worse than no gate (the app_name lesson, one door down in perEntityKeys).
//
// So the attribute-level rule applies to LOGS only, where the framework stamps
// give a precise "the collector contributed nothing" test. `[live-measured
// 2026-07-17, #164]`
func TestBareMetricWithNoAttrKeysIsNotThin(t *testing.T) {
	r := telemetrytest.New()
	r.Emitter().Gauge("entra.secure_score.current", "1", "d", 42, telemetry.Attrs{})

	if reasons := signalcapture.ThinReasons(signalcapture.Union([]*telemetrytest.Recorder{r})); len(reasons) != 0 {
		t.Errorf("an unlabeled tenant-total metric was flagged as thin: %v\n"+
			"11 of 52 packages emit one; a tenant-wide total has nothing to break down by.", reasons)
	}
}

// TestLimiterBoundedAppNameIsNotAViolation pins the finding that shaped this
// denylist, so nobody "helpfully" re-adds app_name to it.
//
// app_name was on the first draft of the list, citing #83 (app_name as a metric
// label: 1,870 series on a six-device tenant). Run against the tree it flagged
// intune.detected_apps.device_count and intune.uxa.app_crash_count — and both
// were CORRECT code, because each bounded app_name at the emit site with a fixed
// package-level allow-list.
//
// #235 retired those allow-lists and the conclusion did not change: what bounds
// those metrics MOVED to the central cardinality limiter, which keeps the top N
// by value and folds the tail into app_name="other". The series count is now
// bounded by configuration rather than by a compile-time list — a stronger
// footing, since no collector has to remember to implement it.
//
// The lesson, and the rule for editing perEntityKeys: a key NAME cannot see
// boundedness. #83's app_name was the unbounded app catalog with nothing
// capping it; these are ranked and folded. Adding a key the limiter can
// meaningfully bound makes the gate cry wolf, and a gate people exempt is worse
// than no gate.
func TestLimiterBoundedAppNameIsNotAViolation(t *testing.T) {
	r := telemetrytest.New()
	// The shape intune.detected_apps and intune.uxa actually emit: app_name comes
	// from the tenant's catalog and is bounded downstream by the limiter.
	r.Emitter().Gauge("intune.detected_apps.device_count", "{device}", "d", 3,
		telemetry.Attrs{"app_name": "outlook.exe", "platform": "windows"})

	if v := signalcapture.PerEntityViolations(signalcapture.Union([]*telemetrytest.Recorder{r})); len(v) != 0 {
		t.Errorf("limiter-bounded app_name flagged: %+v\n"+
			"app_name must NOT be in perEntityKeys: the central cardinality limiter ranks and "+
			"folds it (#235), so the series count is bounded by cardinality.per_metric_limit. "+
			"See the perEntityKeys doc.", v)
	}
}

// TestUnionCapturesUnitAndAggregationKind pins the two facts a metric golden has
// never recorded and #235's limiter cannot work without.
//
// The golden captured the name and the attribute KEYS, which is what decides
// series COUNT. It never captured the unit or the aggregation kind, which is what
// decides what may legally be DONE with a clipped tail: summing the tail of a
// device count is correct, and summing the tail of a health score invents a
// number that was never real (#235 fork 2). telemetrytest.MetricPoint has carried
// both fields all along — Union simply never read them.
//
// Recording them in the golden also makes a unit or kind change a review prompt
// rather than a silent event, which is the same thing the attribute-key half buys.
func TestUnionCapturesUnitAndAggregationKind(t *testing.T) {
	r := telemetrytest.New()
	r.Emitter().Gauge("test.score", "{score}", "d", 1, telemetry.Attrs{"app_name": "a"})
	r.Emitter().Counter("test.calls", "{request}", "d", 1, telemetry.Attrs{"state": "ok"})

	got := signalcapture.Union([]*telemetrytest.Recorder{r})

	if len(got.Metrics) != 2 {
		t.Fatalf("got %d metrics, want 2: %+v", len(got.Metrics), got.Metrics)
	}
	byName := map[string]signalcapture.MetricSignal{}
	for _, m := range got.Metrics {
		byName[m.Name] = m
	}
	if u := byName["test.score"].Unit; u != "{score}" {
		t.Errorf("test.score unit = %q, want {score}", u)
	}
	if k := byName["test.score"].Kind; k != "gauge" {
		t.Errorf("test.score kind = %q, want gauge", k)
	}
	if u := byName["test.calls"].Unit; u != "{request}" {
		t.Errorf("test.calls unit = %q, want {request}", u)
	}
	if k := byName["test.calls"].Kind; k != "sum" {
		t.Errorf("test.calls kind = %q, want sum", k)
	}
}
