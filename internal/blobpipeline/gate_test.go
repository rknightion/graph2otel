package blobpipeline

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/rknightion/graph2otel/internal/telemetry"
	"github.com/rknightion/graph2otel/internal/telemetrytest"
)

// metricSum totals every recorded point of a metric by name.
func metricSum(r *telemetrytest.Recorder, name string) float64 {
	var s float64
	for _, p := range r.MetricPoints(name) {
		s += p.Value
	}
	return s
}

// gatedConfig maps each record to an event carrying its parsed "time", and
// derives one counter per record, so a test can prove the age gate routes.
func gatedConfig(window time.Duration) ContainerConfig {
	return ContainerConfig{
		Container:     "insights-logs-test",
		Prefix:        "tenantId=t1/",
		CollectorName: "test.collector",
		RecencyWindow: window,
		Map: func(r map[string]any) (telemetry.Event, bool) {
			id, _ := r["id"].(string)
			ts, _ := time.Parse(time.RFC3339Nano, r["time"].(string))
			return telemetry.Event{Name: "test.event", Body: id, Timestamp: ts}, true
		},
		Derive: func(_ map[string]any, _ telemetry.Event) []MetricPoint {
			return []MetricPoint{{
				Name: "entra.test.count", Kind: MetricCounter,
				Unit: "{r}", Desc: "test", Value: 1, Attrs: telemetry.Attrs{},
			}}
		},
	}
}

func tsRec(age time.Duration, id string) string {
	ts := time.Now().Add(-age).UTC().Format(time.RFC3339Nano)
	return fmt.Sprintf(`{"time":%q,"id":%q}`, ts, id) + "\r\n"
}

// A fresh record is counted; an old (backfilled) record is log-only. Both always log.
func TestPoll_GateRoutesMetricsByAge(t *testing.T) {
	src := &fakeSource{blobs: map[string]string{
		"tenantId=t1/h=00/b": tsRec(5*time.Minute, "new") + tsRec(2*time.Hour, "old"),
	}}
	r := telemetrytest.New()
	if err := Poll(context.Background(), gatedConfig(20*time.Minute), newCursor(), src, r.Emitter(), discardLogger(), nil); err != nil {
		t.Fatalf("Poll: %v", err)
	}

	if got := len(r.LogRecords()); got != 2 {
		t.Fatalf("log records = %d, want 2 (both records always log)", got)
	}
	if got := metricSum(r, "entra.test.count"); got != 1 {
		t.Fatalf("entra.test.count = %v, want 1 (the old record must not count)", got)
	}
	if got := metricSum(r, metricGated); got != 1 {
		t.Fatalf("%s = %v, want 1", metricGated, got)
	}
	if got := metricSum(r, metricEmitted); got != 1 {
		t.Fatalf("%s = %v, want 1", metricEmitted, got)
	}
}

// A container with no Derive touches no metric and no gate self-obs — log-only, unchanged.
func TestPoll_NoDeriveIsLogOnly(t *testing.T) {
	src := &fakeSource{blobs: map[string]string{
		"tenantId=t1/h=00/b": tsRec(5*time.Minute, "a") + tsRec(2*time.Hour, "b"),
	}}
	cfg := gatedConfig(20 * time.Minute)
	cfg.Derive = nil
	r := telemetrytest.New()
	if err := Poll(context.Background(), cfg, newCursor(), src, r.Emitter(), discardLogger(), nil); err != nil {
		t.Fatalf("Poll: %v", err)
	}
	if got := len(r.LogRecords()); got != 2 {
		t.Fatalf("log records = %d, want 2", got)
	}
	for _, name := range []string{metricGated, metricEmitted, "entra.test.count"} {
		if got := metricSum(r, name); got != 0 {
			t.Fatalf("%s = %v, want 0 when Derive is nil", name, got)
		}
	}
}
