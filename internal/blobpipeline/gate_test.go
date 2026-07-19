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

// Re-reading a blob that grew must count only the NEW record, never re-count the
// bytes already past the cursor — the single most likely metric bug (#128 q1).
func TestPoll_ReReadNoDoubleCount(t *testing.T) {
	name := "tenantId=t1/h=00/b"
	a := tsRec(5*time.Minute, "a")
	src := &fakeSource{blobs: map[string]string{name: a}}
	r := telemetrytest.New()
	cur := newCursor()
	cfg := gatedConfig(20 * time.Minute)

	if err := Poll(context.Background(), cfg, cur, src, r.Emitter(), discardLogger(), nil); err != nil {
		t.Fatalf("Poll 1: %v", err)
	}
	src.blobs[name] = a + tsRec(5*time.Minute, "b") // Azure appends a second record
	if err := Poll(context.Background(), cfg, cur, src, r.Emitter(), discardLogger(), nil); err != nil {
		t.Fatalf("Poll 2: %v", err)
	}

	if got := metricSum(r, "entra.test.count"); got != 2 {
		t.Fatalf("counter = %v across a re-read, want exactly 2 (record 'a' must not be re-counted)", got)
	}
}

// A restart mid-blob (persisted byte offset, fresh emitter) must not re-count the
// records the previous run already emitted (#128 q2). The cursor offset survives;
// the counter's cumulative value resets — each record must still be counted once
// across the two emitters.
func TestPoll_RestartNoDoubleCount(t *testing.T) {
	name := "tenantId=t1/h=00/b"
	a, b := tsRec(5*time.Minute, "a"), tsRec(5*time.Minute, "b")
	src := &fakeSource{blobs: map[string]string{name: a + b}}
	cfg := gatedConfig(20 * time.Minute)
	cfg.MaxBytesPerTick = int64(len(a)) + 5 // consume only record 'a' this tick

	cur := newCursor() // the persisted cursor; the same offsets survive the "restart"

	before := telemetrytest.New()
	if err := Poll(context.Background(), cfg, cur, src, before.Emitter(), discardLogger(), nil); err != nil {
		t.Fatalf("Poll before restart: %v", err)
	}
	after := telemetrytest.New() // fresh process: new meter, counter resets to 0
	if err := Poll(context.Background(), cfg, cur, src, after.Emitter(), discardLogger(), nil); err != nil {
		t.Fatalf("Poll after restart: %v", err)
	}

	total := metricSum(before, "entra.test.count") + metricSum(after, "entra.test.count")
	if total != 2 {
		t.Fatalf("counter total across restart = %v, want exactly 2 (no record counted twice)", total)
	}
}
