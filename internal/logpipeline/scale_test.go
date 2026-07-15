package logpipeline

import (
	"context"
	"fmt"
	"runtime"
	"testing"
	"time"

	"github.com/rknightion/graph2otel/internal/checkpoint"
	"github.com/rknightion/graph2otel/internal/telemetry"
	"github.com/rknightion/graph2otel/internal/telemetrytest"
)

// TestScaleWatermarkDurableAcrossRestart is the #32 soak-validation guard for
// the one failure mode paper analysis can't catch: a process restart mid-stream
// must not drop a late-arriving event and must not re-emit already-seen events
// unboundedly. It drives the real LogCollector Load -> Poll -> Save chain, then
// simulates a crash by building a BRAND NEW Store over the SAME on-disk dir
// (nothing carried in memory) and polling an overlapping window that re-serves
// already-seen events PLUS a late arrival whose timestamp predates the first
// poll's watermark. Correctness rests on the persisted watermark+overlap+SeenIDs,
// exactly as a real restart would.
func TestScaleWatermarkDurableAcrossRestart(t *testing.T) {
	dir := t.TempDir()
	base := time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)
	cfg := EndpointConfig{
		Path:            "/auditLogs/signIns",
		TimeField:       "createdDateTime",
		Flavor:          FlavorGeLe,
		OrderByReliable: false,
		SafetyLag:       15 * time.Minute,
		Overlap:         30 * time.Minute,
		Map:             mapByID,
	}

	// --- Poll 1: initial window, records a..d ---
	rec1 := telemetrytest.New()
	store1 := checkpoint.NewStore(dir)
	fetch1 := pageFetcherFunc(func(_ context.Context, _ string) ([]map[string]any, string, error) {
		return []map[string]any{
			{"id": "a", "createdDateTime": base.Add(10 * time.Minute).Format(time.RFC3339)},
			{"id": "b", "createdDateTime": base.Add(20 * time.Minute).Format(time.RFC3339)},
			{"id": "c", "createdDateTime": base.Add(40 * time.Minute).Format(time.RFC3339)},
			{"id": "d", "createdDateTime": base.Add(50 * time.Minute).Format(time.RFC3339)},
		}, "", nil
	})
	c1 := NewLogCollector("entra.signins", time.Minute, cfg.SafetyLag, "t1", cfg, fetch1, store1)
	hw1, err := c1.CollectWindow(context.Background(), base, base.Add(time.Hour), rec1.Emitter())
	if err != nil {
		t.Fatalf("poll 1: %v", err)
	}
	if got := emittedIDSet(rec1); !sameSet(got, []string{"a", "b", "c", "d"}) {
		t.Fatalf("poll 1 emitted %v, want a,b,c,d", got)
	}

	// --- Simulated crash-restart: fresh Store over the SAME dir, nothing in memory ---
	store2 := checkpoint.NewStore(dir)
	rec2 := telemetrytest.New()
	// Poll 2 re-serves the overlap-window records (b,c,d — already seen) plus a
	// LATE arrival e whose time predates hw1 (it was still landing out of order
	// at poll 1), plus a genuinely new record f.
	fetch2 := pageFetcherFunc(func(_ context.Context, _ string) ([]map[string]any, string, error) {
		return []map[string]any{
			{"id": "b", "createdDateTime": base.Add(20 * time.Minute).Format(time.RFC3339)},
			{"id": "c", "createdDateTime": base.Add(40 * time.Minute).Format(time.RFC3339)},
			{"id": "d", "createdDateTime": base.Add(50 * time.Minute).Format(time.RFC3339)},
			{"id": "e", "createdDateTime": base.Add(30 * time.Minute).Format(time.RFC3339)}, // late, < hw1
			{"id": "f", "createdDateTime": base.Add(90 * time.Minute).Format(time.RFC3339)},
		}, "", nil
	})
	c2 := NewLogCollector("entra.signins", time.Minute, cfg.SafetyLag, "t1", cfg, fetch2, store2)
	// The scheduler passes a fresh [from,to]; CollectWindow resumes from
	// watermark-overlap internally, so `from` here is only the floor.
	if _, err := c2.CollectWindow(context.Background(), base.Add(2*time.Hour), base.Add(2*time.Hour), rec2.Emitter()); err != nil {
		t.Fatalf("poll 2: %v", err)
	}

	got2 := emittedIDSet(rec2)
	// No data loss: the late arrival e is captured on the restart poll.
	if !contains(got2, "e") {
		t.Errorf("late-arriving event e was DROPPED across restart; poll 2 emitted %v", got2)
	}
	// No unbounded duplication: already-seen b,c,d are NOT re-emitted.
	for _, seen := range []string{"b", "c", "d"} {
		if contains(got2, seen) {
			t.Errorf("already-seen event %q re-emitted after restart (dedup failed); poll 2 emitted %v", seen, got2)
		}
	}
	// New event f still flows.
	if !contains(got2, "f") {
		t.Errorf("new event f not emitted; poll 2 emitted %v", got2)
	}
	_ = hw1
}

// BenchmarkPollWindowMemory characterizes the #32 memory finding: Poll drains the
// whole window into an in-memory slice before emitting (required for client-side
// ordering when OrderByReliable is false). Run with `-benchmem` to see that
// allocations scale with the number of records in the window — i.e. per-poll
// memory is bounded by MaxWindow * event-rate, NOT by total backlog (cold-start
// backfill walks in MaxWindow-sized chunks). Documented, not a leak.
func BenchmarkPollWindowMemory(b *testing.B) {
	base := time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)
	cfg := EndpointConfig{
		Path: "/auditLogs/signIns", TimeField: "createdDateTime",
		Flavor: FlavorGeLe, OrderByReliable: false, Map: mapByID,
	}
	const recordsPerWindow = 50_000
	records := make([]map[string]any, recordsPerWindow)
	for i := range records {
		records[i] = map[string]any{
			"id":              fmt.Sprintf("evt-%d", i),
			"createdDateTime": base.Add(time.Duration(i) * time.Millisecond).Format(time.RFC3339),
		}
	}
	fetcher := pageFetcherFunc(func(_ context.Context, _ string) ([]map[string]any, string, error) {
		return records, "", nil
	})
	rec := telemetrytest.New()

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		cp := &checkpoint.Checkpoint{SeenIDs: checkpoint.NewSeenIDs()}
		if _, err := Poll(context.Background(), cfg, cp, base, base.Add(24*time.Hour), fetcher, rec.Emitter()); err != nil {
			b.Fatal(err)
		}
	}
}

// TestScalePollMemoryBoundedByWindowNotBacklog asserts the memory characteristic
// concretely: draining a window holds ~O(window records) live, and a second
// disjoint window does not retain the first window's records (no cross-poll
// accumulation / leak). It's a coarse guard, not a precise budget.
func TestScalePollMemoryBoundedByWindowNotBacklog(t *testing.T) {
	base := time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)
	cfg := EndpointConfig{
		Path: "/auditLogs/signIns", TimeField: "createdDateTime",
		Flavor: FlavorGeLe, OrderByReliable: false, Map: mapByID,
	}
	makeWindow := func(prefix string, n int, start time.Time) []map[string]any {
		out := make([]map[string]any, n)
		for i := range out {
			out[i] = map[string]any{
				"id":              fmt.Sprintf("%s-%d", prefix, i),
				"createdDateTime": start.Add(time.Duration(i) * time.Second).Format(time.RFC3339),
			}
		}
		return out
	}
	poll := func(records []map[string]any, from time.Time) {
		f := pageFetcherFunc(func(_ context.Context, _ string) ([]map[string]any, string, error) {
			return records, "", nil
		})
		cp := &checkpoint.Checkpoint{SeenIDs: checkpoint.NewSeenIDs()}
		if _, err := Poll(context.Background(), cfg, cp, from, from.Add(time.Hour), f, telemetrytest.New().Emitter()); err != nil {
			t.Fatal(err)
		}
	}

	runtime.GC()
	var before runtime.MemStats
	runtime.ReadMemStats(&before)

	// Two large, disjoint windows polled in sequence. If Poll leaked the first
	// window's records, heap-in-use would grow across the pair rather than the
	// GC reclaiming window 1 before window 2.
	poll(makeWindow("w1", 20_000, base), base)
	poll(makeWindow("w2", 20_000, base.Add(2*time.Hour)), base.Add(2*time.Hour))

	runtime.GC()
	var after runtime.MemStats
	runtime.ReadMemStats(&after)

	// After GC, retained heap should be a small fraction of two windows' worth of
	// records (each ~a few hundred bytes). A leak would keep 40k records live.
	const perRecordFloor = 200
	retained := int64(after.HeapAlloc) - int64(before.HeapAlloc)
	if retained > int64(20_000*perRecordFloor) {
		t.Errorf("retained heap %d B after two disjoint windows suggests cross-poll accumulation (window records not released)", retained)
	}
}

// --- test helpers ---

func emittedIDSet(rec *telemetrytest.Recorder) []string {
	logs := rec.LogRecords()
	ids := make([]string, 0, len(logs))
	for _, l := range logs {
		ids = append(ids, l.Attrs["id"])
	}
	return ids
}

func sameSet(got, want []string) bool {
	if len(got) != len(want) {
		return false
	}
	for _, w := range want {
		if !contains(got, w) {
			return false
		}
	}
	return true
}

func contains(s []string, v string) bool {
	for _, x := range s {
		if x == v {
			return true
		}
	}
	return false
}

var _ = telemetry.Event{}
