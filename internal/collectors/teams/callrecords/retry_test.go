package callrecords

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/rknightion/graph2otel/internal/checkpoint"
	"github.com/rknightion/graph2otel/internal/collector"
	"github.com/rknightion/graph2otel/internal/collectors"
	"github.com/rknightion/graph2otel/internal/recordoutcome"
	"github.com/rknightion/graph2otel/internal/telemetry"
	"github.com/rknightion/graph2otel/internal/telemetrytest"
)

func assertDeferred(t *testing.T, c *Collector, want ...checkpoint.DeferredRecord) {
	t.Helper()
	cp, err := c.Store.Load(c.TenantID, Name)
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(cp.DeferredRecords, want) {
		t.Fatalf("durable deferred refs = %+v, want %+v", cp.DeferredRecords, want)
	}
}

// This integration test captures call logs, not scheduler infrastructure
// metrics (which have their own signal gate).
type scheduledCallEmitter struct{ telemetry.Emitter }

func (scheduledCallEmitter) Histogram(string, string, string, float64, []float64, telemetry.Attrs) {
}

func TestScheduledDiscoveryPassesPersistentDeliveryFailure(t *testing.T) {
	clock := now
	const overlap = maxCallDuration + arrivalAllowance
	old := now.Add(-overlap + 10*time.Minute)
	calls := map[string]time.Time{
		"broken": old, "sibling": old.Add(time.Minute), "later": old.Add(maxWindow + time.Hour),
	}
	listOrder := []string{"broken", "sibling", "later"}
	broken := true
	brokenVersion := 2
	var attempts int
	var listedBroken bool
	g := fakeGraph(func(address, prefer string) ([]byte, error) {
		if strings.HasPrefix(address, absolutePath+"?") {
			bounds := strings.Fields(assertList(t, address, prefer))
			lo, hi := parseTime(bounds[2]), parseTime(bounds[6])
			var rows []any
			listedBroken = false
			for _, id := range listOrder {
				start := calls[id]
				if !start.Before(lo) && !start.After(hi) {
					rows = append(rows, listEntry(id, 1, start))
					listedBroken = listedBroken || id == "broken"
				}
			}
			return collection(t, "", rows...), nil
		}
		for _, id := range listOrder {
			switch address {
			case absolutePath + "/" + id + "?$expand=sessions($expand=segments)":
				version := 1
				if id == "broken" {
					version = brokenVersion // the list hint was stale before hydration failed
				}
				return fmt.Appendf(nil, `{"id":%q,"version":%d,"startDateTime":%q,"sessions":[]}`, id, version, stamp(calls[id])), nil
			case absolutePath + "/" + id + "/participants_v2":
				if id == "broken" {
					attempts++
					if broken {
						return nil, errors.New("synthetic persistent auxiliary failure")
					}
				}
				return collection(t, ""), nil
			}
		}
		t.Errorf("unexpected request: %s", address)
		return nil, errors.New("unexpected request")
	})
	dir := t.TempDir()
	rec := telemetrytest.New()
	var c *Collector
	var registry *collector.Registry
	var store collector.CheckpointStore
	restart := func() {
		c = collectorForTest(t, collectors.WindowDeps{Graph: g, Store: checkpoint.NewStore(dir), TenantID: "synthetic-tenant"})
		c.now = func() time.Time { return clock }
		registry = &collector.Registry{}
		registry.RegisterWindow(c, time.Hour, overlap, maxWindow)
		var err error
		store, err = collector.NewFileStore(filepath.Join(dir, "scheduler.json"))
		if err != nil {
			t.Fatal(err)
		}
	}
	tick := func() recordoutcome.Summary {
		t.Helper()
		status := collector.NewStatusTracker()
		ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
		defer cancel()
		s := collector.NewScheduler(scheduledCallEmitter{rec.Emitter()}, store, collector.WithClock(func() time.Time { return clock }),
			collector.WithStaggerWindow(0), collector.WithSelfObs(false), collector.WithStatusTracker(status),
			collector.WithLogger(c.logger), collector.WithSourceRecordRecorder(func(telemetry.Attribution, uint64) { cancel() }))
		if err := s.Run(ctx, registry); !errors.Is(err, context.Canceled) {
			t.Fatalf("scheduler did not finish a tick: %v", err)
		}
		return status.Snapshot()[Name].LastOutcome
	}
	witness := func() map[string]int {
		counts := make(map[string]int)
		for _, log := range rec.LogRecords() {
			if log.EventName == callEvent {
				counts[log.Attrs["call_id"]+":"+log.Attrs["version"]]++
			}
		}
		return counts
	}
	restart()
	tick()
	first := c.CheckpointState().Watermark
	restart()
	for range 6 {
		if got := tick(); got.Cause != recordoutcome.CauseSourceError || got.Counts.Errored != 1 {
			t.Fatalf("pending failure was not reconciled as unhealthy: %+v", got)
		}
	}
	if got := witness(); got["sibling:1"] != 1 || got["later:1"] != 1 || len(got) != 2 || c.CheckpointState().Watermark.Sub(first) <= maxWindow {
		t.Fatalf("persistent failure still pins discovery: call versions=%v, watermark=%v (first=%v)", got, c.CheckpointState().Watermark, first)
	}
	// Each lower bound uses the prior watermark. Move past the discovery
	// overlap for all three calls rather than relying on the list to omit one.
	for range 2 {
		clock = clock.Add(maxWindow)
		tick()
	}
	clock = clock.Add(interval)
	if got := tick(); listedBroken || got.Result != recordoutcome.ResultFailure || got.Counts != (recordoutcome.Counts{Fetched: 1, Errored: 1}) || attempts != 10 {
		t.Fatalf("a queue-only failure must stay visible without list help: listed=%v, attempts=%d, outcome=%+v", listedBroken, attempts, got)
	}
	broken = false
	brokenVersion = 1 // a stale detail cannot satisfy the saved version 2 ref
	restart()
	clock = clock.Add(interval)
	if got := tick(); got.Result != recordoutcome.ResultFailure || got.Counts != (recordoutcome.Counts{Fetched: 1, Errored: 1}) || attempts != 10 {
		t.Fatalf("stale detail was accepted or hydrated: attempts=%d, outcome=%+v", attempts, got)
	}
	brokenVersion = 2
	clock = clock.Add(interval)
	if got := tick(); got.Result != recordoutcome.ResultSuccess || got.Counts.Emitted != 1 || listedBroken {
		t.Fatalf("queue-only recovery failed: listed=%v, outcome=%+v", listedBroken, got)
	}
	restart()
	clock = clock.Add(interval)
	if got := tick(); got.Result != recordoutcome.ResultEmpty || witness()["broken:2"] != 1 || attempts != 11 {
		t.Fatalf("version replayed or retry stayed queued: call versions=%v, attempts=%d, outcome=%+v", witness(), attempts, got)
	}
}

func TestDeferredCapacityAndRetryRotationAcrossListFailure(t *testing.T) {
	const next = absolutePath + "?$skiptoken=next"
	ids := []string{"a", "b", "c", "overflow"}
	start := now.Add(-time.Hour)
	ref := func(id string) checkpoint.DeferredRecord {
		return checkpoint.DeferredRecord{ID: id, Version: 1, SourceTime: start}
	}
	phase := "anchor"
	var gets []string
	g := fakeGraph(func(address, prefer string) ([]byte, error) {
		switch address {
		case next:
			if phase == "list-failure" {
				return nil, errors.New("synthetic continuation failure")
			}
			return collection(t, "", listEntry("overflow", 1, start)), nil
		case absolutePath + "/b/participants_v2":
			return collection(t, ""), nil
		}
		for _, id := range ids {
			if address == absolutePath+"/"+id+"?$expand=sessions($expand=segments)" {
				gets = append(gets, id)
				if phase == "recovery" && id == "b" {
					return fmt.Appendf(nil, `{"id":"b","version":1,"startDateTime":%q,"sessions":[]}`, stamp(start)), nil
				}
				return nil, errors.New("synthetic detail failure")
			}
		}
		assertList(t, address, prefer)
		if phase == "anchor" {
			return collection(t, ""), nil
		}
		return collection(t, next, listEntry("a", 1, start), listEntry("b", 1, start), listEntry("c", 1, start)), nil
	})
	dir := t.TempDir()
	newC := func() *Collector {
		c := collectorForTest(t, collectors.WindowDeps{Graph: g, Store: checkpoint.NewStore(dir), TenantID: "synthetic-tenant"})
		policy := *c.Config.Deferred
		policy.Capacity, policy.RetriesPerPoll = 3, 1
		c.Config.Deferred = &policy
		return c
	}
	c := newC()
	rec := telemetrytest.New()
	from := now.Add(-2 * time.Hour)
	anchor, err := c.CollectWindow(t.Context(), from, now, rec.Emitter(), nil)
	if err != nil {
		t.Fatal(err)
	}
	tick := func(wantErr string, want recordoutcome.Counts, wantGets ...string) {
		t.Helper()
		gets = nil
		outcomes := recordoutcome.NewRecorder()
		hw, err := c.CollectWindow(t.Context(), anchor, now.Add(interval), rec.Emitter(), outcomes)
		if wantErr == "" {
			if err != nil || !hw.After(anchor) {
				t.Fatalf("fully disposed list did not advance: %v, %v", hw, err)
			}
		} else if err == nil || !strings.Contains(err.Error(), wantErr) || !hw.Equal(anchor) || !c.CheckpointState().Watermark.Equal(anchor) {
			t.Fatalf("discovery moved or lost %q: hw=%v err=%v", wantErr, hw, err)
		}
		got := outcomes.Snapshot()
		if got.Counts != want || got.Validate() != nil || got.Summarize(err, false).Cause != recordoutcome.CauseSourceError || !slices.Equal(gets, wantGets) {
			t.Fatalf("incorrect retry work or accounting: gets=%v, outcome=%+v", gets, got)
		}
	}
	phase = "capacity"
	tick("deferred delivery capacity of 3 exceeded", recordoutcome.Counts{Fetched: 4, Errored: 4}, "a", "b", "c", "overflow")
	assertDeferred(t, c, ref("a"), ref("b"), ref("c"))
	c = newC()
	phase = "list-failure"
	tick("synthetic continuation failure", recordoutcome.Counts{Fetched: 4, Errored: 4}, "a")
	assertDeferred(t, c, ref("b"), ref("c"), ref("a"))
	c = newC()
	phase = "recovery"
	tick("", recordoutcome.Counts{Fetched: 5, Mapped: 1, Emitted: 1, Filtered: 3, Errored: 1}, "b", "overflow")
	assertDeferred(t, c, ref("c"), ref("a"), ref("overflow"))
	if logs := rec.LogRecords(); len(logs) != 1 || logs[0].Attrs["call_id"] != "b" {
		t.Fatalf("unexpected delivery across cap and list failure: %+v", logs)
	}
}

func TestDeferredDiscoveryDoesNotCommitOnSaveFailure(t *testing.T) {
	start := now.Add(-time.Hour)
	phase := "anchor"
	g := fakeGraph(func(address, prefer string) ([]byte, error) {
		switch address {
		case absolutePath + "/broken?$expand=sessions($expand=segments)":
			if phase == "bad-save" {
				return nil, errors.New("synthetic detail failure")
			}
			return fmt.Appendf(nil, `{"id":"broken","version":1,"startDateTime":%q,"sessions":[]}`, stamp(start)), nil
		case absolutePath + "/broken/participants_v2":
			return collection(t, ""), nil
		default:
			assertList(t, address, prefer)
			if phase == "anchor" {
				return collection(t, ""), nil
			}
			return collection(t, "", listEntry("broken", 1, start)), nil
		}
	})
	dir := t.TempDir()
	newC := func() *Collector {
		return collectorForTest(t, collectors.WindowDeps{Graph: g, Store: checkpoint.NewStore(dir), TenantID: "synthetic-tenant"})
	}
	c := newC()
	rec := telemetrytest.New()
	anchor, err := c.CollectWindow(t.Context(), now.Add(-2*time.Hour), now, rec.Emitter(), nil)
	if err != nil {
		t.Fatal(err)
	}
	files, err := os.ReadDir(dir)
	if err != nil || len(files) != 1 {
		t.Fatalf("expected one source checkpoint: %v, %v", files, err)
	}
	blocked := filepath.Join(dir, files[0].Name()+".tmp")
	if err := os.Mkdir(blocked, 0o700); err != nil {
		t.Fatal(err)
	}
	phase = "bad-save"
	outcomes := recordoutcome.NewRecorder()
	hw, err := c.CollectWindow(t.Context(), anchor, now.Add(interval), rec.Emitter(), outcomes)
	got := outcomes.Snapshot()
	if err == nil || !strings.Contains(err.Error(), "save checkpoint") || !hw.Equal(anchor) || !c.CheckpointState().Watermark.Equal(anchor) ||
		got.Counts != (recordoutcome.Counts{Fetched: 1, Errored: 1}) || got.Validate() != nil || got.Summarize(err, false).Result != recordoutcome.ResultFailure {
		t.Fatalf("save failure was not visible or falsely committed discovery: %v; %v; %+v", hw, err, got)
	}
	assertDeferred(t, c)
	if err := os.Remove(blocked); err != nil {
		t.Fatal(err)
	}
	phase = "healthy"
	c = newC()
	hw, err = c.CollectWindow(t.Context(), anchor, now.Add(interval), rec.Emitter(), nil)
	logs := rec.LogRecords()
	if err != nil || !hw.After(anchor) || len(logs) != 1 || logs[0].Attrs["call_id"] != "broken" {
		t.Fatalf("unrecorded failure was not rediscovered: %v; %v; %+v", hw, err, logs)
	}
}

func TestUnrecordableFailureHoldsDiscovery(t *testing.T) {
	g := fakeGraph(func(address, prefer string) ([]byte, error) {
		if strings.HasPrefix(address, absolutePath+"?") {
			assertList(t, address, prefer)
			return []byte(`{"value":[{"id":"undated","version":1}]}`), nil
		}
		if address == absolutePath+"/undated?$expand=sessions($expand=segments)" {
			return nil, errors.New("synthetic detail failure")
		}
		t.Errorf("unexpected request: %s", address)
		return nil, errors.New("unexpected request")
	})
	c := collectorForTest(t, collectors.WindowDeps{Graph: g, Store: checkpoint.NewStore(t.TempDir()), TenantID: "synthetic-tenant"})
	rec := telemetrytest.New()
	outcomes := recordoutcome.NewRecorder()
	hw, err := c.CollectWindow(t.Context(), now.Add(-2*time.Hour), now, rec.Emitter(), outcomes)
	got := outcomes.Snapshot()
	if err == nil || !strings.Contains(err.Error(), "without valid source reference") || !hw.IsZero() || !c.CheckpointState().Watermark.IsZero() ||
		got.Counts != (recordoutcome.Counts{Fetched: 1, Errored: 1}) || got.Validate() != nil || len(rec.LogRecords()) != 0 {
		t.Fatalf("unrecordable failure was not held for rediscovery: %v; %v; %+v", hw, err, got)
	}
	assertDeferred(t, c)
}

func TestDeferredRetentionDropAndDirectDedupe(t *testing.T) {
	clock := now
	start := now.Add(-retention + time.Minute)
	phase := "discover"
	g := fakeGraph(func(address, prefer string) ([]byte, error) {
		if strings.HasPrefix(address, absolutePath+"?") {
			assertList(t, address, prefer)
			if phase == "discover" {
				return collection(t, "", listEntry("expires", 1, start), listEntry("direct", 1, start)), nil
			}
			return collection(t, ""), nil
		}
		if phase == "discover" {
			return nil, errors.New("synthetic detail failure")
		}
		if phase == "direct" {
			switch address {
			case absolutePath + "/direct?$expand=sessions($expand=segments)":
				return fmt.Appendf(nil, `{"id":"direct","version":1,"startDateTime":%q,"sessions":[]}`, stamp(start)), nil
			case absolutePath + "/direct/participants_v2":
				return collection(t, ""), nil
			}
		}
		t.Errorf("unexpected auxiliary request in %s: %s", phase, address)
		return nil, errors.New("unexpected request")
	})
	dir := t.TempDir()
	newC := func() *Collector {
		c := collectorForTest(t, collectors.WindowDeps{Graph: g, Store: checkpoint.NewStore(dir), TenantID: "synthetic-tenant"})
		c.now = func() time.Time { return clock }
		return c
	}
	c := newC()
	rec := telemetrytest.New()
	anchor, err := c.CollectWindow(t.Context(), start, now, rec.Emitter(), nil)
	if err != nil {
		t.Fatal(err)
	}
	phase = "direct"
	if err := c.CollectCall(t.Context(), "direct", rec.Emitter(), nil); err != nil || !c.CheckpointState().Watermark.Equal(anchor) {
		t.Fatalf("direct delivery failed or moved discovery: %v", err)
	}
	phase = "expire"
	clock = clock.Add(interval)
	c = newC()
	outcomes := recordoutcome.NewRecorder()
	_, err = c.CollectWindow(t.Context(), anchor, clock, rec.Emitter(), outcomes)
	got := outcomes.Snapshot()
	if err != nil || got.Counts != (recordoutcome.Counts{Fetched: 1, Dropped: 1}) || got.Summarize(err, false).Cause != recordoutcome.CauseSourceError {
		t.Fatalf("only the undelivered expired ref should count as loss: %v; %+v", err, got)
	}
	assertDeferred(t, c)
	if logs := rec.LogRecords(); len(logs) != 1 || logs[0].Attrs["call_id"] != "direct" || !logs[0].Timestamp.Equal(start) {
		t.Fatalf("unexpected direct delivery or retention replay: %+v", logs)
	}
}
