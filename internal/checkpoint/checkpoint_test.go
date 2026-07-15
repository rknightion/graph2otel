package checkpoint

import (
	"testing"
	"time"
)

func TestSeenIDsAddHas(t *testing.T) {
	ids := NewSeenIDs()
	now := time.Now()

	if ids.Has("a") {
		t.Fatal("Has(\"a\") = true before Add, want false")
	}

	ids.Add("a", now)

	if !ids.Has("a") {
		t.Fatal("Has(\"a\") = false after Add, want true")
	}
	if ids.Has("b") {
		t.Fatal("Has(\"b\") = true, want false (never added)")
	}
}

func TestSeenIDsEvictBounded(t *testing.T) {
	ids := NewSeenIDs()
	base := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)

	ids.Add("old", base.Add(-2*time.Hour))
	ids.Add("boundary", base.Add(-time.Hour))
	ids.Add("recent", base.Add(-time.Minute))

	ids.Evict(base.Add(-time.Hour)) // evict strictly-before the horizon

	if ids.Has("old") {
		t.Error("Has(\"old\") = true after Evict, want evicted (older than horizon)")
	}
	if !ids.Has("boundary") {
		t.Error("Has(\"boundary\") = false after Evict, want kept (exactly at horizon)")
	}
	if !ids.Has("recent") {
		t.Error("Has(\"recent\") = false after Evict, want kept (newer than horizon)")
	}
	if len(ids) != 2 {
		t.Errorf("len(ids) = %d after Evict, want 2", len(ids))
	}
}

func TestCheckpointEvictStale(t *testing.T) {
	watermark := time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)
	cp := &Checkpoint{
		TenantID:      "tenant-1",
		Endpoint:      "/auditLogs/signIns",
		Watermark:     watermark,
		OverlapWindow: time.Hour,
		SeenIDs:       NewSeenIDs(),
	}
	cp.SeenIDs.Add("stale", watermark.Add(-2*time.Hour))
	cp.SeenIDs.Add("fresh", watermark.Add(-30*time.Minute))

	cp.EvictStale()

	if cp.SeenIDs.Has("stale") {
		t.Error("Has(\"stale\") = true after EvictStale, want evicted (older than watermark-overlap)")
	}
	if !cp.SeenIDs.Has("fresh") {
		t.Error("Has(\"fresh\") = false after EvictStale, want kept")
	}
}
