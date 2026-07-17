package jobpipeline

import (
	"context"
	"errors"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/rknightion/graph2otel/internal/checkpoint"
	"github.com/rknightion/graph2otel/internal/telemetrytest"
)

// fixedNow returns a Now func pinned to t.
func fixedNow(t time.Time) func() time.Time { return func() time.Time { return t } }

// recordsURL is the page URL Run derives for a query id at the default page size.
func recordsURL(id string, pageSize int) string {
	return graphV1BaseURL + "/security/auditLog/queries/" + id + "/records?$top=" + strconv.Itoa(pageSize)
}

// TestRun_PersistsInFlightBeforePolling pins the ordering the whole feature
// rests on: the query id must be durable BEFORE the first status poll. If it
// were persisted after the poll loop instead, a process killed mid-poll — the
// exact case #118 is about, and a >10-minute window live (#100) — would persist
// nothing and orphan the job anyway.
func TestRun_PersistsInFlightBeforePolling(t *testing.T) {
	rec := telemetrytest.New()
	from := time.Date(2026, 7, 16, 10, 0, 0, 0, time.UTC)
	to := from.Add(time.Hour)

	var persistedAtStatusCall []int
	client := &fakeJobClient{statuses: []string{StatusRunning, StatusSucceeded}}

	sleeps := 0
	cfg := baseConfig()
	cfg.Sleep = noSleep(&sleeps)
	cfg.Now = fixedNow(to)
	cfg.Persist = func(cp *checkpoint.Checkpoint) error {
		persistedAtStatusCall = append(persistedAtStatusCall, client.statusCalls)
		if cp.InFlight == nil {
			t.Error("Persist called with a nil InFlight — the point of the hook is to durably record the job id")
			return nil
		}
		if cp.InFlight.ID != "query-1" {
			t.Errorf("persisted InFlight.ID = %q, want query-1", cp.InFlight.ID)
		}
		return nil
	}
	client.pages = map[string]fakePage{
		recordsURL("query-1", DefaultPageSize): {records: []map[string]any{
			{"id": "a", "createdDateTime": from.Add(time.Minute).Format(time.RFC3339)},
		}},
	}

	cp := newCheckpoint("t1", cfg.CreatePath)
	if _, err := Run(context.Background(), cfg, cp, from, to, client, rec.Emitter()); err != nil {
		t.Fatalf("Run: %v", err)
	}

	if len(persistedAtStatusCall) == 0 {
		t.Fatal("Persist was never called; the created query id is not durable and a restart would orphan it")
	}
	if persistedAtStatusCall[0] != 0 {
		t.Errorf("first Persist happened after %d status poll(s), want 0 — the id must be durable before polling starts",
			persistedAtStatusCall[0])
	}
}

// TestRun_ClearsInFlightOnSuccess proves a drained job does not linger as an
// adoptable record: the next tick must create a fresh query for the next window.
func TestRun_ClearsInFlightOnSuccess(t *testing.T) {
	rec := telemetrytest.New()
	from := time.Date(2026, 7, 16, 10, 0, 0, 0, time.UTC)
	to := from.Add(time.Hour)

	sleeps := 0
	cfg := baseConfig()
	cfg.Sleep = noSleep(&sleeps)
	cfg.Now = fixedNow(to)

	client := &fakeJobClient{
		statuses: []string{StatusSucceeded},
		pages: map[string]fakePage{
			recordsURL("query-1", DefaultPageSize): {records: []map[string]any{
				{"id": "a", "createdDateTime": from.Add(time.Minute).Format(time.RFC3339)},
			}},
		},
	}

	cp := newCheckpoint("t1", cfg.CreatePath)
	if _, err := Run(context.Background(), cfg, cp, from, to, client, rec.Emitter()); err != nil {
		t.Fatalf("Run: %v", err)
	}
	if cp.InFlight != nil {
		t.Errorf("InFlight = %+v after a fully drained query, want nil", cp.InFlight)
	}
}

// TestRun_KeepsInFlightOnPollError is the resume case: a status poll that fails
// transiently must LEAVE the record, because that is precisely the job the next
// tick should adopt. Clearing it here would reintroduce the duplicate create on
// every transient 429/5xx.
func TestRun_KeepsInFlightOnPollError(t *testing.T) {
	rec := telemetrytest.New()
	from := time.Date(2026, 7, 16, 10, 0, 0, 0, time.UTC)
	to := from.Add(time.Hour)

	cfg := baseConfig()
	cfg.Now = fixedNow(to)
	client := &fakeJobClient{statusErr: errors.New("graph: status 429")}

	cp := newCheckpoint("t1", cfg.CreatePath)
	if _, err := Run(context.Background(), cfg, cp, from, to, client, rec.Emitter()); err == nil {
		t.Fatal("Run: want an error when the status poll fails")
	}
	if cp.InFlight == nil {
		t.Fatal("InFlight = nil after a transient poll failure, want the job retained for the next tick to adopt")
	}
	if cp.InFlight.ID != "query-1" {
		t.Errorf("InFlight.ID = %q, want query-1", cp.InFlight.ID)
	}
	if !cp.InFlight.WindowFrom.Equal(from) || !cp.InFlight.WindowTo.Equal(to) {
		t.Errorf("InFlight window = [%v, %v], want [%v, %v]", cp.InFlight.WindowFrom, cp.InFlight.WindowTo, from, to)
	}
}

// TestRun_ClearsInFlightOnTerminalFailure: a query that reports failed/cancelled
// will never succeed, so re-polling the same id forever is pure waste — the
// record must go so the next tick submits a fresh one.
func TestRun_ClearsInFlightOnTerminalFailure(t *testing.T) {
	for _, tt := range []struct {
		name    string
		status  string
		wantErr error
	}{
		{name: "failed", status: StatusFailed, wantErr: ErrJobFailed},
		{name: "cancelled", status: StatusCancelled, wantErr: ErrJobCancelled},
	} {
		t.Run(tt.name, func(t *testing.T) {
			rec := telemetrytest.New()
			from := time.Date(2026, 7, 16, 10, 0, 0, 0, time.UTC)
			to := from.Add(time.Hour)

			cfg := baseConfig()
			cfg.Now = fixedNow(to)
			client := &fakeJobClient{statuses: []string{tt.status}}

			cp := newCheckpoint("t1", cfg.CreatePath)
			_, err := Run(context.Background(), cfg, cp, from, to, client, rec.Emitter())
			if !errors.Is(err, tt.wantErr) {
				t.Fatalf("Run error = %v, want %v", err, tt.wantErr)
			}
			if cp.InFlight != nil {
				t.Errorf("InFlight = %+v after a %s query, want nil (it can never succeed)", cp.InFlight, tt.status)
			}
		})
	}
}

// TestRun_AdoptsInFlightRatherThanCreating is the core of #118 at engine level:
// a checkpoint carrying an in-flight id must be polled, not re-created — and
// crucially it must be adopted even though `to` has advanced since, because
// `to` is now-lag and advances on EVERY tick.
func TestRun_AdoptsInFlightRatherThanCreating(t *testing.T) {
	rec := telemetrytest.New()
	from := time.Date(2026, 7, 16, 10, 0, 0, 0, time.UTC)
	jobTo := from.Add(time.Hour)
	// This tick's `to` is 20 minutes later than the in-flight job's: wall-clock
	// moved on while the query ran.
	to := jobTo.Add(20 * time.Minute)

	sleeps := 0
	cfg := baseConfig()
	cfg.Sleep = noSleep(&sleeps)
	cfg.Now = fixedNow(to)

	client := &fakeJobClient{
		statuses: []string{StatusSucceeded},
		pages: map[string]fakePage{
			recordsURL("query-77", DefaultPageSize): {records: []map[string]any{
				{"id": "a", "createdDateTime": from.Add(time.Minute).Format(time.RFC3339)},
			}},
		},
	}

	cp := newCheckpoint("t1", cfg.CreatePath)
	cp.InFlight = &checkpoint.InFlightJob{
		ID:         "query-77",
		CreatedAt:  from.Add(50 * time.Minute),
		WindowFrom: from,
		WindowTo:   jobTo,
	}

	hw, err := Run(context.Background(), cfg, cp, from, to, client, rec.Emitter())
	if err != nil {
		t.Fatalf("Run: %v", err)
	}

	if client.createCalls != 0 {
		t.Errorf("CreateQuery called %d times, want 0 — the in-flight query must be adopted, not duplicated", client.createCalls)
	}
	if len(client.statusURLs) == 0 || !strings.HasSuffix(client.statusURLs[0], "/query-77") {
		t.Errorf("polled %v, want the adopted query-77", client.statusURLs)
	}
	if logs := rec.LogRecords(); len(logs) != 1 {
		t.Errorf("emitted %d records, want 1 from the adopted query", len(logs))
	}
	// The watermark advances only as far as the ADOPTED job's window, not this
	// tick's `to` — the remaining 20 minutes were never queried and belong to the
	// next tick. Advancing to `to` here would silently skip them.
	wantHW := jobTo.Add(-DefaultSafetyLag)
	if !hw.Equal(wantHW) {
		t.Errorf("high-water = %v, want %v (the adopted job's to - SafetyLag, NOT this tick's to)", hw, wantHW)
	}
	if cp.InFlight != nil {
		t.Errorf("InFlight = %+v after draining the adopted job, want nil", cp.InFlight)
	}
}

// TestRun_DiscardsStaleInFlight covers the wedge guard: a job old enough to be
// presumed dead must be dropped and replaced, not polled forever. Without this,
// a query id that 404s on every status poll wedges the collector permanently —
// poll errors are deliberately non-terminal.
func TestRun_DiscardsStaleInFlight(t *testing.T) {
	rec := telemetrytest.New()
	from := time.Date(2026, 7, 16, 10, 0, 0, 0, time.UTC)
	to := from.Add(time.Hour)

	sleeps := 0
	cfg := baseConfig()
	cfg.Sleep = noSleep(&sleeps)
	cfg.Now = fixedNow(to)
	cfg.JobMaxAge = 30 * time.Minute

	client := &fakeJobClient{
		statuses: []string{StatusSucceeded},
		pages: map[string]fakePage{
			recordsURL("query-1", DefaultPageSize): {records: []map[string]any{
				{"id": "a", "createdDateTime": from.Add(time.Minute).Format(time.RFC3339)},
			}},
		},
	}

	cp := newCheckpoint("t1", cfg.CreatePath)
	cp.InFlight = &checkpoint.InFlightJob{
		ID:         "query-dead",
		CreatedAt:  to.Add(-2 * time.Hour), // far older than JobMaxAge
		WindowFrom: from,
		WindowTo:   to,
	}

	if _, err := Run(context.Background(), cfg, cp, from, to, client, rec.Emitter()); err != nil {
		t.Fatalf("Run: %v", err)
	}
	if client.createCalls != 1 {
		t.Errorf("CreateQuery called %d times, want 1 — a stale job must be replaced, not adopted", client.createCalls)
	}
	for _, u := range client.statusURLs {
		if strings.HasSuffix(u, "/query-dead") {
			t.Errorf("polled the stale query-dead (%s); it should have been discarded", u)
		}
	}
}

// TestRun_DiscardsInFlightWhenWindowMovedOn: on a WARM checkpoint a job whose
// `from` no longer matches belongs to a window already dealt with. Adopting it
// would waste the call and re-query a range the watermark has passed.
//
// The watermark is what makes that inference sound, so this test sets one: with a
// watermark, CollectWindow derives `from` from it (collector.go), so `from` is a
// pure function of persisted state and a differing `from` can ONLY mean the
// watermark moved. On a COLD checkpoint `from` is wall-clock-derived and the same
// inference is invalid — that is #147, covered separately below. This test is the
// guard that #147's cold-start relaxation does not leak into the warm path.
func TestRun_DiscardsInFlightWhenWindowMovedOn(t *testing.T) {
	rec := telemetrytest.New()
	from := time.Date(2026, 7, 16, 10, 0, 0, 0, time.UTC)
	to := from.Add(time.Hour)

	sleeps := 0
	cfg := baseConfig()
	cfg.Sleep = noSleep(&sleeps)
	cfg.Now = fixedNow(to)

	client := &fakeJobClient{
		statuses: []string{StatusSucceeded},
		pages: map[string]fakePage{
			recordsURL("query-1", DefaultPageSize): {records: []map[string]any{}},
		},
	}

	cp := newCheckpoint("t1", cfg.CreatePath)
	// Warm: a window has been drained before, so `from` is watermark-derived.
	cp.Watermark = from.Add(cfg.Overlap)
	cp.InFlight = &checkpoint.InFlightJob{
		ID:         "query-stale-window",
		CreatedAt:  to.Add(-5 * time.Minute),
		WindowFrom: from.Add(-3 * time.Hour), // a different, older window
		WindowTo:   from.Add(-2 * time.Hour),
	}

	if _, err := Run(context.Background(), cfg, cp, from, to, client, rec.Emitter()); err != nil {
		t.Fatalf("Run: %v", err)
	}
	if client.createCalls != 1 {
		t.Errorf("CreateQuery called %d times, want 1 — a job for a superseded window must be discarded", client.createCalls)
	}
}

// TestRun_ColdCheckpointAdoptsJobStartingBeforeThisTicksFrom is #147 at engine
// level. On a cold checkpoint (no watermark) `from` is now-lag-lookback — pure
// wall-clock — so it advances on every tick exactly like `to` does. A job created
// by the previous process therefore has a WindowFrom strictly BEFORE this tick's
// `from`, and the warm rule's `from` equality can never hold.
//
// Adopting it is lossless: the job covers [WindowFrom, WindowTo], a superset at
// the low end of what this tick asked for, and emitAndAdvance advances the
// watermark only to the job's own WindowTo.
func TestRun_ColdCheckpointAdoptsJobStartingBeforeThisTicksFrom(t *testing.T) {
	rec := telemetrytest.New()
	// The previous process's cold window, 20 minutes of wall-clock ago.
	jobFrom := time.Date(2026, 7, 16, 10, 0, 0, 0, time.UTC)
	jobTo := jobFrom.Add(time.Hour)
	// This tick's cold window: both bounds have slid forward by the same 20 min.
	from := jobFrom.Add(20 * time.Minute)
	to := jobTo.Add(20 * time.Minute)

	sleeps := 0
	cfg := baseConfig()
	cfg.Sleep = noSleep(&sleeps)
	cfg.Now = fixedNow(to)

	client := &fakeJobClient{
		statuses: []string{StatusSucceeded},
		pages: map[string]fakePage{
			recordsURL("query-cold", DefaultPageSize): {records: []map[string]any{
				{"id": "a", "createdDateTime": jobFrom.Add(time.Minute).Format(time.RFC3339)},
			}},
		},
	}

	cp := newCheckpoint("t1", cfg.CreatePath) // cold: no watermark
	cp.InFlight = &checkpoint.InFlightJob{
		ID:         "query-cold",
		CreatedAt:  jobTo,
		WindowFrom: jobFrom,
		WindowTo:   jobTo,
	}

	hw, err := Run(context.Background(), cfg, cp, from, to, client, rec.Emitter())
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if client.createCalls != 0 {
		t.Errorf("CreateQuery called %d times, want 0 — a cold checkpoint must still adopt the in-flight query, not orphan it", client.createCalls)
	}
	if len(client.statusURLs) == 0 || !strings.HasSuffix(client.statusURLs[0], "/query-cold") {
		t.Errorf("polled %v, want the adopted query-cold", client.statusURLs)
	}
	if logs := rec.LogRecords(); len(logs) != 1 {
		t.Errorf("emitted %d records, want 1 from the adopted query", len(logs))
	}
	// The watermark tracks the ADOPTED job's window, never this tick's `to`.
	if wantHW := jobTo.Add(-DefaultSafetyLag); !hw.Equal(wantHW) {
		t.Errorf("high-water = %v, want %v (the adopted job's to - SafetyLag)", hw, wantHW)
	}
}

// TestRun_ColdCheckpointDiscardsJobThatWouldLeaveAGap pins the limit of the
// cold-start relaxation: a job whose window starts AFTER this tick's `from` must
// NOT be adopted. There is no watermark, so nothing has covered [from,
// WindowFrom) — adopting would drain [WindowFrom, WindowTo], advance the
// watermark past it, and lose that range for good.
//
// Reachable in practice by widening initial_lookback across a restart, which
// moves `from` backwards while a job for the older, narrower window is still on
// disk.
func TestRun_ColdCheckpointDiscardsJobThatWouldLeaveAGap(t *testing.T) {
	rec := telemetrytest.New()
	from := time.Date(2026, 7, 16, 10, 0, 0, 0, time.UTC)
	to := from.Add(time.Hour)

	sleeps := 0
	cfg := baseConfig()
	cfg.Sleep = noSleep(&sleeps)
	cfg.Now = fixedNow(to)

	client := &fakeJobClient{
		statuses: []string{StatusSucceeded},
		pages: map[string]fakePage{
			recordsURL("query-1", DefaultPageSize): {records: []map[string]any{}},
		},
	}

	cp := newCheckpoint("t1", cfg.CreatePath) // cold
	cp.InFlight = &checkpoint.InFlightJob{
		ID:         "query-leaves-a-gap",
		CreatedAt:  to.Add(-5 * time.Minute),
		WindowFrom: from.Add(30 * time.Minute), // starts INSIDE the requested window
		WindowTo:   to,
	}

	if _, err := Run(context.Background(), cfg, cp, from, to, client, rec.Emitter()); err != nil {
		t.Fatalf("Run: %v", err)
	}
	if client.createCalls != 1 {
		t.Errorf("CreateQuery called %d times, want 1 — adopting a job that starts after `from` would silently drop [from, WindowFrom)", client.createCalls)
	}
	for _, u := range client.statusURLs {
		if strings.HasSuffix(u, "/query-leaves-a-gap") {
			t.Errorf("polled %s; a job that would leave a gap must be discarded", u)
		}
	}
}

// TestRun_ColdCheckpointDiscardsJobEndingAfterThisTicksTo: the prefix rule holds
// on a cold checkpoint too. A job reaching BEYOND this tick's `to` would advance
// the watermark past what this tick believes is safe to consume (the clock went
// backwards, or lag/max_window changed), so it is discarded rather than adopted.
func TestRun_ColdCheckpointDiscardsJobEndingAfterThisTicksTo(t *testing.T) {
	rec := telemetrytest.New()
	from := time.Date(2026, 7, 16, 10, 0, 0, 0, time.UTC)
	to := from.Add(time.Hour)

	sleeps := 0
	cfg := baseConfig()
	cfg.Sleep = noSleep(&sleeps)
	cfg.Now = fixedNow(to)

	client := &fakeJobClient{
		statuses: []string{StatusSucceeded},
		pages: map[string]fakePage{
			recordsURL("query-1", DefaultPageSize): {records: []map[string]any{}},
		},
	}

	cp := newCheckpoint("t1", cfg.CreatePath) // cold
	cp.InFlight = &checkpoint.InFlightJob{
		ID:         "query-overshoots",
		CreatedAt:  to.Add(-5 * time.Minute),
		WindowFrom: from.Add(-time.Minute),
		WindowTo:   to.Add(time.Minute), // beyond the requested `to`
	}

	if _, err := Run(context.Background(), cfg, cp, from, to, client, rec.Emitter()); err != nil {
		t.Fatalf("Run: %v", err)
	}
	if client.createCalls != 1 {
		t.Errorf("CreateQuery called %d times, want 1 — a job overshooting `to` must be discarded on a cold checkpoint too", client.createCalls)
	}
}

// TestRun_NegativeJobMaxAgeDisablesAdoption pins the escape hatch: adoption
// resumes work against APIs that punish duplication, so there has to be a way to
// switch it off per-endpoint without reverting code. A negative JobMaxAge must
// mean "never adopt" — NOT "never expire", which would be the exact opposite and
// would turn the knob into the wedge it is meant to prevent.
func TestRun_NegativeJobMaxAgeDisablesAdoption(t *testing.T) {
	rec := telemetrytest.New()
	from := time.Date(2026, 7, 16, 10, 0, 0, 0, time.UTC)
	to := from.Add(time.Hour)

	sleeps := 0
	cfg := baseConfig()
	cfg.Sleep = noSleep(&sleeps)
	cfg.Now = fixedNow(to)
	cfg.JobMaxAge = -1

	client := &fakeJobClient{
		statuses: []string{StatusSucceeded},
		pages: map[string]fakePage{
			recordsURL("query-1", DefaultPageSize): {records: []map[string]any{}},
		},
	}

	cp := newCheckpoint("t1", cfg.CreatePath)
	// A perfectly adoptable job: fresh, exact window.
	cp.InFlight = &checkpoint.InFlightJob{ID: "query-adoptable", CreatedAt: to.Add(-time.Minute), WindowFrom: from, WindowTo: to}

	if _, err := Run(context.Background(), cfg, cp, from, to, client, rec.Emitter()); err != nil {
		t.Fatalf("Run: %v", err)
	}
	if client.createCalls != 1 {
		t.Errorf("CreateQuery called %d times, want 1 — a negative JobMaxAge must disable adoption entirely", client.createCalls)
	}
}

// TestRun_AdoptedJobSkipsBuildRequest is a small but real saving: an adopted job
// needs no request body, so BuildRequest must not run (and a BuildRequest error
// must not fail a tick that was going to adopt).
func TestRun_AdoptedJobSkipsBuildRequest(t *testing.T) {
	rec := telemetrytest.New()
	from := time.Date(2026, 7, 16, 10, 0, 0, 0, time.UTC)
	to := from.Add(time.Hour)

	sleeps := 0
	cfg := baseConfig()
	cfg.Sleep = noSleep(&sleeps)
	cfg.Now = fixedNow(to)
	built := 0
	cfg.BuildRequest = func(_, _ time.Time) ([]byte, error) { built++; return []byte(`{}`), nil }

	client := &fakeJobClient{
		statuses: []string{StatusSucceeded},
		pages: map[string]fakePage{
			recordsURL("query-9", DefaultPageSize): {records: []map[string]any{}},
		},
	}

	cp := newCheckpoint("t1", cfg.CreatePath)
	cp.InFlight = &checkpoint.InFlightJob{ID: "query-9", CreatedAt: to.Add(-time.Minute), WindowFrom: from, WindowTo: to}

	if _, err := Run(context.Background(), cfg, cp, from, to, client, rec.Emitter()); err != nil {
		t.Fatalf("Run: %v", err)
	}
	if built != 0 {
		t.Errorf("BuildRequest called %d times on an adopted job, want 0", built)
	}
}

// TestJobCollector_RestartAdoptsInFlightQuery is acceptance criterion #1 for
// jobpipeline, end to end through the real file store: process A creates a query
// and dies mid-poll; process B starts fresh, loads the checkpoint off disk, and
// must POLL that query rather than submit a second one against an API that 429s
// on rapid create (#98).
func TestJobCollector_RestartAdoptsInFlightQuery(t *testing.T) {
	store := checkpoint.NewStore(t.TempDir())
	from := time.Date(2026, 7, 16, 10, 0, 0, 0, time.UTC)
	to := from.Add(time.Hour)

	sleeps := 0
	cfg := baseConfig()
	cfg.Sleep = noSleep(&sleeps)
	cfg.Now = fixedNow(to)

	// --- process A: creates the query, then dies while polling it.
	clientA := &fakeJobClient{statusErr: errors.New("process is going away")}
	collA := NewJobCollector("m365.unified_audit", 30*time.Minute, 15*time.Minute, "t1", cfg, clientA, store)
	if _, err := collA.CollectWindow(context.Background(), from, to, telemetrytest.New().Emitter()); err == nil {
		t.Fatal("CollectWindow: want an error when the poll never completes")
	}
	if clientA.createCalls != 1 {
		t.Fatalf("process A created %d queries, want 1", clientA.createCalls)
	}

	// The id must be on DISK now — process A never reached its own Save.
	saved, err := store.Load("t1", cfg.CreatePath)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if saved.InFlight == nil || saved.InFlight.ID != "query-1" {
		t.Fatalf("persisted InFlight = %+v, want query-1 recorded before the poll loop", saved.InFlight)
	}

	// --- process B: restarted. Wall-clock has moved on, so its `to` is later.
	toB := to.Add(20 * time.Minute)
	cfgB := baseConfig()
	cfgB.Sleep = noSleep(&sleeps)
	cfgB.Now = fixedNow(toB)

	rec := telemetrytest.New()
	clientB := &fakeJobClient{
		statuses: []string{StatusSucceeded},
		pages: map[string]fakePage{
			recordsURL("query-1", DefaultPageSize): {records: []map[string]any{
				{"id": "a", "createdDateTime": from.Add(2 * time.Minute).Format(time.RFC3339)},
				{"id": "b", "createdDateTime": from.Add(3 * time.Minute).Format(time.RFC3339)},
			}},
		},
	}
	collB := NewJobCollector("m365.unified_audit", 30*time.Minute, 15*time.Minute, "t1", cfgB, clientB, store)
	if _, err := collB.CollectWindow(context.Background(), from, toB, rec.Emitter()); err != nil {
		t.Fatalf("process B CollectWindow: %v", err)
	}

	if clientB.createCalls != 0 {
		t.Errorf("process B created %d queries, want 0 — it must adopt process A's in-flight query", clientB.createCalls)
	}
	if len(clientB.statusURLs) == 0 || !strings.HasSuffix(clientB.statusURLs[0], "/query-1") {
		t.Errorf("process B polled %v, want the adopted query-1", clientB.statusURLs)
	}
	if logs := rec.LogRecords(); len(logs) != 2 {
		t.Errorf("process B emitted %d records, want 2 from the adopted query", len(logs))
	}

	after, err := store.Load("t1", cfg.CreatePath)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if after.InFlight != nil {
		t.Errorf("persisted InFlight = %+v after the adopted query drained, want nil", after.InFlight)
	}
}

// coldWindow mirrors collector/window.go's cold-start arithmetic: with no
// checkpoint the scheduler asks for [now-lag-lookback, now-lag]. BOTH bounds are
// pure wall-clock, so every tick taken before the first watermark exists asks for
// a DIFFERENT `from` — which is exactly what #147 is about. Once a watermark
// exists, `from` is the watermark and stops moving; that is why the warm path
// adopts and the cold path did not.
func coldWindow(now time.Time, lag, lookback time.Duration) (from, to time.Time) {
	to = now.Add(-lag)
	return to.Add(-lookback), to
}

// TestJobCollector_ColdCheckpointRestartAdoptsInFlightQuery is #147, end to end
// through the real file store: the #118 restart case with the ONE difference that
// makes it real — the checkpoint is cold, as it is on a first deploy or after a
// wiped checkpoint dir, so process B recomputes `from` off the wall clock instead
// of off a watermark.
//
// #118's own restart test held `from` fixed across the restart, which only models
// a checkpoint that already has a watermark. That is what let this ship green: the
// live run on camden (#118 verification, 2026-07-16) still orphaned and re-created
// on first deploy.
func TestJobCollector_ColdCheckpointRestartAdoptsInFlightQuery(t *testing.T) {
	store := checkpoint.NewStore(t.TempDir())

	const (
		lag      = 15 * time.Minute
		lookback = 24 * time.Hour
	)

	// --- process A: first deploy. Creates the query, then dies while polling it.
	nowA := time.Date(2026, 7, 16, 10, 0, 0, 0, time.UTC)
	fromA, toA := coldWindow(nowA, lag, lookback)

	sleeps := 0
	cfgA := baseConfig()
	cfgA.Sleep = noSleep(&sleeps)
	cfgA.Now = fixedNow(nowA)

	clientA := &fakeJobClient{statusErr: errors.New("process is going away")}
	collA := NewJobCollector("m365.unified_audit", 30*time.Minute, lag, "t1", cfgA, clientA, store)
	if _, err := collA.CollectWindow(context.Background(), fromA, toA, telemetrytest.New().Emitter()); err == nil {
		t.Fatal("CollectWindow: want an error when the poll never completes")
	}
	if clientA.createCalls != 1 {
		t.Fatalf("process A created %d queries, want 1", clientA.createCalls)
	}

	saved, err := store.Load("t1", cfgA.CreatePath)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if saved.InFlight == nil || saved.InFlight.ID != "query-1" {
		t.Fatalf("persisted InFlight = %+v, want query-1 recorded before the poll loop", saved.InFlight)
	}
	// The premise of this test: process A drained nothing, so the checkpoint is
	// STILL cold. Without this the case under test is just #118's.
	if !saved.Watermark.IsZero() {
		t.Fatalf("persisted Watermark = %v, want zero — process A never drained a window, so the checkpoint must still be cold", saved.Watermark)
	}

	// --- process B: restarted 20 minutes later, still with no watermark, so its
	// window slides forward by the full 20 minutes — `from` included.
	nowB := nowA.Add(20 * time.Minute)
	fromB, toB := coldWindow(nowB, lag, lookback)
	if fromB.Equal(fromA) {
		t.Fatal("test bug: a cold restart must recompute `from`; if it matched, this would be the #118 case, not #147")
	}

	cfgB := baseConfig()
	cfgB.Sleep = noSleep(&sleeps)
	cfgB.Now = fixedNow(nowB)

	rec := telemetrytest.New()
	clientB := &fakeJobClient{
		statuses: []string{StatusSucceeded},
		pages: map[string]fakePage{
			recordsURL("query-1", DefaultPageSize): {records: []map[string]any{
				{"id": "a", "createdDateTime": toA.Add(-2 * time.Minute).Format(time.RFC3339)},
				{"id": "b", "createdDateTime": toA.Add(-time.Minute).Format(time.RFC3339)},
			}},
		},
	}
	collB := NewJobCollector("m365.unified_audit", 30*time.Minute, lag, "t1", cfgB, clientB, store)
	hw, err := collB.CollectWindow(context.Background(), fromB, toB, rec.Emitter())
	if err != nil {
		t.Fatalf("process B CollectWindow: %v", err)
	}

	if clientB.createCalls != 0 {
		t.Errorf("process B created %d queries, want 0 — it must adopt process A's in-flight query rather than orphan it and re-create against an API that 429s on rapid create (#98)", clientB.createCalls)
	}
	if len(clientB.statusURLs) == 0 || !strings.HasSuffix(clientB.statusURLs[0], "/query-1") {
		t.Errorf("process B polled %v, want the adopted query-1", clientB.statusURLs)
	}
	if logs := rec.LogRecords(); len(logs) != 2 {
		t.Errorf("process B emitted %d records, want 2 from the adopted query", len(logs))
	}
	// The watermark follows the ADOPTED job's window (toA), not process B's `to`:
	// [toA, toB] was never queried and belongs to the next tick.
	if wantHW := toA.Add(-DefaultSafetyLag); !hw.Equal(wantHW) {
		t.Errorf("high-water = %v, want %v (the adopted job's to - SafetyLag, NOT process B's to)", hw, wantHW)
	}

	after, err := store.Load("t1", cfgA.CreatePath)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if after.InFlight != nil {
		t.Errorf("persisted InFlight = %+v after the adopted query drained, want nil", after.InFlight)
	}
}

// TestJobCollector_StaleInFlightDoesNotWedge is acceptance criterion #2: a job
// that never reaches a terminal state must not block the collector forever. Once
// it ages past JobMaxAge the collector submits a fresh query and recovers on its
// own, with no operator intervention.
func TestJobCollector_StaleInFlightDoesNotWedge(t *testing.T) {
	store := checkpoint.NewStore(t.TempDir())
	from := time.Date(2026, 7, 16, 10, 0, 0, 0, time.UTC)
	to := from.Add(time.Hour)

	// A dead query id is already on disk, created hours ago.
	cp := newCheckpoint("t1", "/security/auditLog/queries")
	cp.InFlight = &checkpoint.InFlightJob{
		ID:         "query-zombie",
		CreatedAt:  to.Add(-6 * time.Hour),
		WindowFrom: from,
		WindowTo:   to,
	}
	if err := store.Save(cp); err != nil {
		t.Fatalf("Save: %v", err)
	}

	sleeps := 0
	cfg := baseConfig()
	cfg.Sleep = noSleep(&sleeps)
	cfg.Now = fixedNow(to)

	rec := telemetrytest.New()
	client := &fakeJobClient{
		statuses: []string{StatusSucceeded},
		pages: map[string]fakePage{
			recordsURL("query-1", DefaultPageSize): {records: []map[string]any{
				{"id": "a", "createdDateTime": from.Add(time.Minute).Format(time.RFC3339)},
			}},
		},
	}
	coll := NewJobCollector("m365.unified_audit", 30*time.Minute, 15*time.Minute, "t1", cfg, client, store)
	if _, err := coll.CollectWindow(context.Background(), from, to, rec.Emitter()); err != nil {
		t.Fatalf("CollectWindow: %v", err)
	}

	if client.createCalls != 1 {
		t.Errorf("CreateQuery called %d times, want 1 — the zombie must be dropped and replaced", client.createCalls)
	}
	for _, u := range client.statusURLs {
		if strings.HasSuffix(u, "/query-zombie") {
			t.Errorf("polled the zombie query (%s) instead of discarding it", u)
		}
	}
	if logs := rec.LogRecords(); len(logs) != 1 {
		t.Errorf("emitted %d records, want 1 — the collector recovered", len(logs))
	}
}

// TestRun_PersistErrorDoesNotAbandonTheCreatedJob: if the id cannot be written to
// disk we have still already created the job server-side, so abandoning the tick
// would waste it AND emit nothing. The run continues; the caller's own Save hits
// the same failure and surfaces it (and an unwritable checkpoint dir is already a
// fail-fast condition at startup, #117).
func TestRun_PersistErrorDoesNotAbandonTheCreatedJob(t *testing.T) {
	rec := telemetrytest.New()
	from := time.Date(2026, 7, 16, 10, 0, 0, 0, time.UTC)
	to := from.Add(time.Hour)

	sleeps := 0
	cfg := baseConfig()
	cfg.Sleep = noSleep(&sleeps)
	cfg.Now = fixedNow(to)
	cfg.Persist = func(*checkpoint.Checkpoint) error { return errors.New("disk full") }

	client := &fakeJobClient{
		statuses: []string{StatusSucceeded},
		pages: map[string]fakePage{
			recordsURL("query-1", DefaultPageSize): {records: []map[string]any{
				{"id": "a", "createdDateTime": from.Add(time.Minute).Format(time.RFC3339)},
			}},
		},
	}

	cp := newCheckpoint("t1", cfg.CreatePath)
	if _, err := Run(context.Background(), cfg, cp, from, to, client, rec.Emitter()); err != nil {
		t.Fatalf("Run: %v — a persist failure must not abandon the query it just created", err)
	}
	if logs := rec.LogRecords(); len(logs) != 1 {
		t.Errorf("emitted %d records, want 1", len(logs))
	}
}
