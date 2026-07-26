package logpipeline

import (
	"context"
	"errors"
	"maps"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/rknightion/graph2otel/internal/checkpoint"
	"github.com/rknightion/graph2otel/internal/telemetrytest"
)

// TestLogCollectorPersistsAndResumesAcrossRestart drives LogCollector
// (the thin collector.WindowCollector wrapper) across two "poll cycles"
// backed by two independently-constructed checkpoint.Stores over the same
// directory, simulating a process restart. It verifies the checkpoint is
// persisted, the second cycle's query resumes from watermark - overlap
// (not the scheduler's bare `from`), and the already-seen record is deduped
// rather than re-emitted.
func TestLogCollectorPersistsAndResumesAcrossRestart(t *testing.T) {
	dir := t.TempDir()

	cfg := EndpointConfig{
		Path:            "/auditLogs/signIns",
		TimeField:       "createdDateTime",
		Flavor:          FlavorGeLe,
		OrderByReliable: true,
		SafetyLag:       5 * time.Minute,
		Overlap:         30 * time.Minute,
		Map:             mapByID,
	}
	base := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)

	var seenURLs []string
	fetcher := pageFetcherFunc(func(_ context.Context, pageURL string) ([]map[string]any, string, error) {
		seenURLs = append(seenURLs, pageURL)
		return []map[string]any{
			{"id": "a", "createdDateTime": base.Add(10 * time.Minute).Format(time.RFC3339)},
		}, "", nil
	})

	rec := telemetrytest.New()
	store1 := checkpoint.NewStore(dir)
	c1 := NewLogCollector("sign_ins", time.Minute, 5*time.Minute, "tenant1", cfg, fetcher, store1)

	hw1, err := c1.CollectWindow(context.Background(), base, base.Add(30*time.Minute), rec.Emitter(), nil)
	if err != nil {
		t.Fatalf("CollectWindow #1: %v", err)
	}
	wantHW1 := base.Add(10 * time.Minute).Add(-cfg.SafetyLag)
	if !hw1.Equal(wantHW1) {
		t.Fatalf("high water #1 = %v, want %v", hw1, wantHW1)
	}

	// Simulate a restart: a brand-new Store + LogCollector over the SAME
	// checkpoint dir must resume from watermark - overlap, not from the
	// scheduler's bare `from`.
	store2 := checkpoint.NewStore(dir)
	c2 := NewLogCollector("sign_ins", time.Minute, 5*time.Minute, "tenant1", cfg, fetcher, store2)

	if _, err := c2.CollectWindow(context.Background(), base.Add(20*time.Minute), base.Add(40*time.Minute), rec.Emitter(), nil); err != nil {
		t.Fatalf("CollectWindow #2: %v", err)
	}

	if len(seenURLs) != 2 {
		t.Fatalf("expected 2 page fetches (one per cycle), got %d", len(seenURLs))
	}
	u2, err := url.Parse(seenURLs[1])
	if err != nil {
		t.Fatalf("url.Parse(%q): %v", seenURLs[1], err)
	}
	wantResumeFrom := wantHW1.Add(-cfg.Overlap)
	filter := u2.Query().Get("$filter")
	if !strings.Contains(filter, wantResumeFrom.UTC().Format(time.RFC3339)) {
		t.Fatalf("2nd cycle $filter = %q, want it to contain resumed from-time %v (watermark - overlap)", filter, wantResumeFrom)
	}

	// "a" was already recorded in cycle 1's checkpoint and must be deduped
	// on cycle 2, not re-emitted.
	logs := rec.LogRecords()
	if len(logs) != 1 {
		t.Fatalf("expected 'a' emitted exactly once across the restart, got %d: %+v", len(logs), logs)
	}
}

// TestLogCollectorReliableFailureRetriesOnlyEmittedPrefix exercises the real
// Load -> Poll -> Save boundary across fresh Store instances. A failed ordered
// walk may emit its successful prefix, but that prefix remains absent from the
// durable checkpoint and is therefore replayed once on the successful retry.
func TestLogCollectorReliableFailureRetriesOnlyEmittedPrefix(t *testing.T) {
	dir := t.TempDir()
	base := time.Date(2026, 7, 26, 10, 0, 0, 0, time.UTC)
	cfg := EndpointConfig{
		Path:            "/auditLogs/signIns",
		TimeField:       "createdDateTime",
		Flavor:          FlavorGeLe,
		OrderByReliable: true,
		SafetyLag:       5 * time.Minute,
		Overlap:         30 * time.Minute,
		Map:             mapByID,
	}

	initialStore := checkpoint.NewStore(dir)
	initial := newCheckpoint("tenant1", cfg.Path)
	initial.Watermark = base.Add(-10 * time.Minute)
	initial.OverlapWindow = cfg.Overlap
	initial.SeenIDs.Add("durable-before", base.Add(-5*time.Minute))
	if err := initialStore.Save(initial); err != nil {
		t.Fatalf("seed checkpoint: %v", err)
	}
	wantSeen := maps.Clone(initial.SeenIDs)

	firstCalls := 0
	firstFetcher := pageFetcherFunc(func(_ context.Context, _ string) ([]map[string]any, string, error) {
		firstCalls++
		if firstCalls == 1 {
			return []map[string]any{
				{"id": "a", "createdDateTime": base.Add(time.Minute).Format(time.RFC3339)},
				{"id": "b", "createdDateTime": base.Add(2 * time.Minute).Format(time.RFC3339)},
			}, "page-2", nil
		}
		return nil, "", errors.New("page two failed")
	})
	firstRecorder := telemetrytest.New()
	first := NewLogCollector(
		"sign_ins",
		time.Minute,
		cfg.SafetyLag,
		"tenant1",
		cfg,
		firstFetcher,
		checkpoint.NewStore(dir),
	)
	if _, err := first.CollectWindow(
		context.Background(),
		base,
		base.Add(time.Hour),
		firstRecorder.Emitter(),
		nil,
	); err == nil {
		t.Fatal("first CollectWindow error = nil, want later-page failure")
	}

	durableAfterFailure, err := checkpoint.NewStore(dir).Load("tenant1", cfg.Path)
	if err != nil {
		t.Fatalf("load checkpoint after failure: %v", err)
	}
	if !durableAfterFailure.Watermark.Equal(initial.Watermark) ||
		durableAfterFailure.OverlapWindow != initial.OverlapWindow ||
		!maps.Equal(durableAfterFailure.SeenIDs, wantSeen) {
		t.Fatalf(
			"durable checkpoint after failure = {watermark:%v overlap:%v seen:%v}, want unchanged {%v %v %v}",
			durableAfterFailure.Watermark,
			durableAfterFailure.OverlapWindow,
			durableAfterFailure.SeenIDs,
			initial.Watermark,
			initial.OverlapWindow,
			wantSeen,
		)
	}
	if got := emittedIDSet(firstRecorder); !sameSet(got, []string{"a", "b"}) {
		t.Fatalf("first attempt emitted = %v, want successful prefix [a b]", got)
	}

	secondCalls := 0
	secondFetcher := pageFetcherFunc(func(_ context.Context, _ string) ([]map[string]any, string, error) {
		secondCalls++
		if secondCalls == 1 {
			return []map[string]any{
				{"id": "a", "createdDateTime": base.Add(time.Minute).Format(time.RFC3339)},
				{"id": "b", "createdDateTime": base.Add(2 * time.Minute).Format(time.RFC3339)},
			}, "page-2", nil
		}
		return []map[string]any{{
			"id":              "c",
			"createdDateTime": base.Add(3 * time.Minute).Format(time.RFC3339),
		}}, "", nil
	})
	secondRecorder := telemetrytest.New()
	second := NewLogCollector(
		"sign_ins",
		time.Minute,
		cfg.SafetyLag,
		"tenant1",
		cfg,
		secondFetcher,
		checkpoint.NewStore(dir),
	)
	if _, err := second.CollectWindow(
		context.Background(),
		base,
		base.Add(time.Hour),
		secondRecorder.Emitter(),
		nil,
	); err != nil {
		t.Fatalf("second CollectWindow: %v", err)
	}
	if got := emittedIDSet(secondRecorder); !sameSet(got, []string{"a", "b", "c"}) {
		t.Fatalf("retry emitted = %v, want replayed prefix plus suffix [a b c]", got)
	}

	durableAfterSuccess, err := checkpoint.NewStore(dir).Load("tenant1", cfg.Path)
	if err != nil {
		t.Fatalf("load checkpoint after success: %v", err)
	}
	for _, id := range []string{"a", "b", "c", "durable-before"} {
		if !durableAfterSuccess.SeenIDs.Has(id) {
			t.Fatalf("durable checkpoint after success missing %q: %v", id, durableAfterSuccess.SeenIDs)
		}
	}

	thirdRecorder := telemetrytest.New()
	third := NewLogCollector(
		"sign_ins",
		time.Minute,
		cfg.SafetyLag,
		"tenant1",
		cfg,
		onePageFetcher([]map[string]any{
			{"id": "a", "createdDateTime": base.Add(time.Minute).Format(time.RFC3339)},
			{"id": "b", "createdDateTime": base.Add(2 * time.Minute).Format(time.RFC3339)},
			{"id": "c", "createdDateTime": base.Add(3 * time.Minute).Format(time.RFC3339)},
		}),
		checkpoint.NewStore(dir),
	)
	if _, err := third.CollectWindow(
		context.Background(),
		base,
		base.Add(time.Hour),
		thirdRecorder.Emitter(),
		nil,
	); err != nil {
		t.Fatalf("third CollectWindow: %v", err)
	}
	if got := emittedIDSet(thirdRecorder); len(got) != 0 {
		t.Fatalf("third attempt emitted = %v, want zero after durable success", got)
	}
}

// TestLogCollectorCheckpointKeyIsolatesSharedPath verifies that two
// collectors polling the SAME Graph path ("/auditLogs/signIns" — as the four
// sign-in event-type streams do) but declaring distinct CheckpointKeys keep
// independent checkpoint namespaces: a record seen by one must NOT be deduped
// away for the other. Without CheckpointKey they would collide on Path and
// silently drop each other's events.
func TestLogCollectorCheckpointKeyIsolatesSharedPath(t *testing.T) {
	dir := t.TempDir()
	base := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)

	fetcher := pageFetcherFunc(func(_ context.Context, _ string) ([]map[string]any, string, error) {
		return []map[string]any{
			{"id": "shared-id", "createdDateTime": base.Add(10 * time.Minute).Format(time.RFC3339)},
		}, "", nil
	})

	newCfg := func(key string) EndpointConfig {
		return EndpointConfig{
			Path:            "/auditLogs/signIns",
			CheckpointKey:   key,
			TimeField:       "createdDateTime",
			Flavor:          FlavorGeLe,
			OrderByReliable: true,
			SafetyLag:       5 * time.Minute,
			Overlap:         30 * time.Minute,
			Map:             mapByID,
		}
	}

	store := checkpoint.NewStore(dir)
	rec := telemetrytest.New()
	interactive := NewLogCollector("interactive", time.Minute, 5*time.Minute, "tenant1", newCfg("/auditLogs/signIns#interactive"), fetcher, store)
	noninteractive := NewLogCollector("noninteractive", time.Minute, 5*time.Minute, "tenant1", newCfg("/auditLogs/signIns#nonInteractiveUser"), fetcher, store)

	if _, err := interactive.CollectWindow(context.Background(), base, base.Add(30*time.Minute), rec.Emitter(), nil); err != nil {
		t.Fatalf("interactive CollectWindow: %v", err)
	}
	if _, err := noninteractive.CollectWindow(context.Background(), base, base.Add(30*time.Minute), rec.Emitter(), nil); err != nil {
		t.Fatalf("noninteractive CollectWindow: %v", err)
	}

	// The same "shared-id" is a DISTINCT event in each stream: both must emit.
	logs := rec.LogRecords()
	if len(logs) != 2 {
		t.Fatalf("expected each stream to emit its own record (2 total), got %d — the two collectors collided on one checkpoint namespace: %+v", len(logs), logs)
	}
}
