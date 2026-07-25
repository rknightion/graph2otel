package collector

import (
	"testing"
	"time"

	"github.com/rknightion/graph2otel/internal/recordoutcome"
)

func TestStatusTracker_RecordSuccessThenFailure(t *testing.T) {
	tr := NewStatusTracker()
	t0 := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	tr.record("devices", t0, t0.Add(2*time.Second), 2*time.Second, "", recordoutcome.Summary{Result: recordoutcome.ResultSuccess})
	tr.record("devices", t0.Add(time.Minute), t0.Add(time.Minute+time.Second), time.Second, "boom", recordoutcome.Summary{Result: recordoutcome.ResultFailure})

	r, ok := tr.Snapshot()["devices"]
	if !ok {
		t.Fatalf("no record for devices")
	}
	if r.Runs != 2 {
		t.Errorf("Runs = %d, want 2", r.Runs)
	}
	if r.Failures != 1 {
		t.Errorf("Failures = %d, want 1", r.Failures)
	}
	if r.LastSuccess {
		t.Errorf("LastSuccess = true, want false (last run failed)")
	}
	if r.LastError != "boom" {
		t.Errorf("LastError = %q, want boom", r.LastError)
	}
	if r.LastDuration != time.Second {
		t.Errorf("LastDuration = %v, want 1s", r.LastDuration)
	}
	if !r.LastStarted.Equal(t0.Add(time.Minute)) {
		t.Errorf("LastStarted = %v, want %v", r.LastStarted, t0.Add(time.Minute))
	}
}

func TestStatusTracker_SuccessClearsLastError(t *testing.T) {
	tr := NewStatusTracker()
	t0 := time.Now()
	tr.record("x", t0, t0, time.Millisecond, "err", recordoutcome.Summary{Result: recordoutcome.ResultFailure})
	tr.record("x", t0, t0, time.Millisecond, "", recordoutcome.Summary{Result: recordoutcome.ResultSuccess})

	r := tr.Snapshot()["x"]
	if !r.LastSuccess || r.LastError != "" {
		t.Fatalf("after success: LastSuccess=%v LastError=%q, want true/empty", r.LastSuccess, r.LastError)
	}
	if r.Failures != 1 {
		t.Errorf("Failures = %d, want 1 (the earlier failure still counts)", r.Failures)
	}
}

func TestStatusTracker_SnapshotIsCopy(t *testing.T) {
	tr := NewStatusTracker()
	tr.record("x", time.Now(), time.Now(), 0, "", recordoutcome.Summary{Result: recordoutcome.ResultSuccess})

	snap := tr.Snapshot()
	snap["x"] = CollectorRun{Runs: 999}
	if got := tr.Snapshot()["x"].Runs; got != 1 {
		t.Fatalf("mutating the snapshot affected the tracker: Runs = %d, want 1", got)
	}
}

func TestStatusTracker_SnapshotCarriesImmutableLastOutcome(t *testing.T) {
	tr := NewStatusTracker()
	now := time.Now()
	want := recordoutcome.Summary{
		Result: recordoutcome.ResultPartial,
		Cause:  recordoutcome.CauseSourceError,
		Counts: recordoutcome.Counts{
			Fetched: 2,
			Mapped:  1,
			Emitted: 1,
			Errored: 1,
		},
	}
	tr.record("x", now, now, time.Millisecond, "page failed", want)

	snapshot := tr.Snapshot()
	if got := snapshot["x"].LastOutcome; got != want {
		t.Fatalf("LastOutcome = %+v, want %+v", got, want)
	}
	changed := snapshot["x"]
	changed.LastOutcome = recordoutcome.Summary{Result: recordoutcome.ResultSuccess}
	snapshot["x"] = changed
	if got := tr.Snapshot()["x"].LastOutcome; got != want {
		t.Fatalf("mutating snapshot changed tracker LastOutcome: got %+v, want %+v", got, want)
	}
}

func TestStatusTracker_NilSafe(t *testing.T) {
	var tr *StatusTracker
	tr.record("x", time.Now(), time.Now(), 0, "", recordoutcome.Summary{Result: recordoutcome.ResultSuccess}) // must not panic
	if len(tr.Snapshot()) != 0 {
		t.Fatalf("nil tracker Snapshot non-empty")
	}
}

func TestStatusTracker_ConsecutiveFailures(t *testing.T) {
	tr := NewStatusTracker()
	t0 := time.Now()
	tr.record("x", t0, t0, time.Millisecond, "", recordoutcome.Summary{Result: recordoutcome.ResultSuccess}) // success -> 0
	if got := tr.Snapshot()["x"].ConsecutiveFailures; got != 0 {
		t.Errorf("after success ConsecutiveFailures = %d, want 0", got)
	}
	tr.record("x", t0, t0, time.Millisecond, "e1", recordoutcome.Summary{Result: recordoutcome.ResultFailure}) // fail -> 1
	tr.record("x", t0, t0, time.Millisecond, "e2", recordoutcome.Summary{Result: recordoutcome.ResultFailure}) // fail -> 2
	if got := tr.Snapshot()["x"].ConsecutiveFailures; got != 2 {
		t.Errorf("after 2 failures ConsecutiveFailures = %d, want 2", got)
	}
	tr.record("x", t0, t0, time.Millisecond, "", recordoutcome.Summary{Result: recordoutcome.ResultSuccess}) // success resets -> 0
	if got := tr.Snapshot()["x"].ConsecutiveFailures; got != 0 {
		t.Errorf("success did not reset ConsecutiveFailures = %d, want 0", got)
	}
}

func TestStatusTracker_HistorySnapshot(t *testing.T) {
	tr := NewStatusTracker()
	t0 := time.Now()
	tr.record("x", t0, t0, 10*time.Millisecond, "", recordoutcome.Summary{Result: recordoutcome.ResultSuccess})
	tr.record("x", t0, t0, 20*time.Millisecond, "boom", recordoutcome.Summary{Result: recordoutcome.ResultFailure})
	tr.record("x", t0, t0, 30*time.Millisecond, "", recordoutcome.Summary{Result: recordoutcome.ResultSuccess})

	h, ok := tr.HistorySnapshot()["x"]
	if !ok {
		t.Fatalf("no history for x")
	}
	if want := []int64{10, 20, 30}; !equalInt64(h.DurationMs, want) {
		t.Errorf("DurationMs = %v, want %v", h.DurationMs, want)
	}
	if len(h.Outcomes) != 3 || h.Outcomes[0] != true || h.Outcomes[1] != false || h.Outcomes[2] != true {
		t.Errorf("Outcomes = %v, want [true false true]", h.Outcomes)
	}
}

func TestStatusTracker_HistoryCapsAtHistoryLen(t *testing.T) {
	tr := NewStatusTracker()
	t0 := time.Now()
	for i := range historyLen + 10 {
		tr.record("x", t0, t0, time.Duration(i)*time.Millisecond, "", recordoutcome.Summary{Result: recordoutcome.ResultSuccess})
	}
	h := tr.HistorySnapshot()["x"]
	if len(h.DurationMs) != historyLen {
		t.Fatalf("DurationMs len = %d, want %d", len(h.DurationMs), historyLen)
	}
	if got := h.DurationMs[len(h.DurationMs)-1]; got != int64(historyLen+9) {
		t.Errorf("newest DurationMs = %d, want %d", got, historyLen+9)
	}
}

func TestStatusTracker_HistorySnapshotNilSafe(t *testing.T) {
	var tr *StatusTracker
	if len(tr.HistorySnapshot()) != 0 {
		t.Fatalf("nil tracker HistorySnapshot non-empty")
	}
}

func equalInt64(a, b []int64) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
