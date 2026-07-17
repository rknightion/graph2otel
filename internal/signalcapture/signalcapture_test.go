package signalcapture_test

import (
	"strings"
	"testing"

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

// TestAllowListBoundedAppNameIsNotAViolation pins the finding that shaped this
// denylist, so nobody "helpfully" re-adds app_name to it.
//
// app_name was on the first draft of the list, citing #83 (app_name as a metric
// label: 1,870 series on a six-device tenant). Run against the tree it flagged
// intune.detected_apps.device_count and intune.uxa.app_crash_count — and both
// were CORRECT code. Each bounds app_name with a fixed, package-level allow-list
// and filters at the emit site, so its series count is a compile-time constant:
// the bounded aggregate #112 asks for.
//
// The lesson, and the rule for editing perEntityKeys: a key NAME cannot see
// boundedness. #83's app_name was the unbounded app catalog; theirs is an
// allow-list. Same key, opposite cardinality, decided by collector logic this
// gate cannot observe. Adding a key that a collector can legitimately bound
// makes the gate cry wolf, and a gate people exempt is worse than no gate.
func TestAllowListBoundedAppNameIsNotAViolation(t *testing.T) {
	r := telemetrytest.New()
	// The shape intune.detected_apps and intune.uxa actually emit: app_name is
	// drawn from a fixed package-level allow-list, not from the tenant's catalog.
	r.Emitter().Gauge("intune.detected_apps.device_count", "{device}", "d", 3,
		telemetry.Attrs{"app_name": "outlook.exe", "platform": "windows"})

	if v := signalcapture.PerEntityViolations(signalcapture.Union([]*telemetrytest.Recorder{r})); len(v) != 0 {
		t.Errorf("allow-list-bounded app_name flagged: %+v\n"+
			"app_name must NOT be in perEntityKeys: intune/detectedapps and "+
			"intune/endpointanalytics bound it with defaultAllowedApps, making the series "+
			"count a compile-time constant. See the perEntityKeys doc.", v)
	}
}
