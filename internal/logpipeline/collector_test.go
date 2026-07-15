package logpipeline

import (
	"context"
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

	hw1, err := c1.CollectWindow(context.Background(), base, base.Add(30*time.Minute), rec.Emitter())
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

	if _, err := c2.CollectWindow(context.Background(), base.Add(20*time.Minute), base.Add(40*time.Minute), rec.Emitter()); err != nil {
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

	if _, err := interactive.CollectWindow(context.Background(), base, base.Add(30*time.Minute), rec.Emitter()); err != nil {
		t.Fatalf("interactive CollectWindow: %v", err)
	}
	if _, err := noninteractive.CollectWindow(context.Background(), base, base.Add(30*time.Minute), rec.Emitter()); err != nil {
		t.Fatalf("noninteractive CollectWindow: %v", err)
	}

	// The same "shared-id" is a DISTINCT event in each stream: both must emit.
	logs := rec.LogRecords()
	if len(logs) != 2 {
		t.Fatalf("expected each stream to emit its own record (2 total), got %d — the two collectors collided on one checkpoint namespace: %+v", len(logs), logs)
	}
}
