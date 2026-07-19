package logpipeline

import (
	"testing"
	"time"

	"github.com/rknightion/graph2otel/internal/checkpoint"
	"github.com/rknightion/graph2otel/internal/collector"
)

// CheckpointState reads the durable window checkpoint read-only for the admin
// page (#178 Part B): watermark, seen-id set size, and any in-flight job id.
func TestLogCollectorCheckpointState(t *testing.T) {
	dir := t.TempDir()
	store := checkpoint.NewStore(dir)

	cfg := EndpointConfig{Path: "/auditLogs/signIns", TimeField: "createdDateTime", Map: mapByID}
	wm := time.Date(2026, 7, 19, 12, 0, 0, 0, time.UTC)

	seen := checkpoint.NewSeenIDs()
	seen.Add("a", wm)
	seen.Add("b", wm)
	if err := store.Save(&checkpoint.Checkpoint{
		TenantID:  "tenant1",
		Endpoint:  cfg.checkpointKey(),
		Watermark: wm,
		SeenIDs:   seen,
		InFlight:  &checkpoint.InFlightJob{ID: "job-9", CreatedAt: wm},
	}); err != nil {
		t.Fatalf("Save: %v", err)
	}

	c := NewLogCollector("sign_ins", time.Minute, 5*time.Minute, "tenant1", cfg, nil, store)
	st := c.CheckpointState()
	if st == nil {
		t.Fatalf("CheckpointState() = nil, want a window checkpoint")
	}
	if st.Kind != collector.CheckpointKindWindow {
		t.Errorf("Kind = %q, want %q", st.Kind, collector.CheckpointKindWindow)
	}
	if !st.Watermark.Equal(wm) {
		t.Errorf("Watermark = %v, want %v", st.Watermark, wm)
	}
	if st.SeenIDs != 2 {
		t.Errorf("SeenIDs = %d, want 2", st.SeenIDs)
	}
	if st.InFlightJob != "job-9" {
		t.Errorf("InFlightJob = %q, want job-9", st.InFlightJob)
	}
}
