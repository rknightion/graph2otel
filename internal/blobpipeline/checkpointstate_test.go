package blobpipeline

import (
	"testing"
	"time"

	"github.com/rknightion/graph2otel/internal/checkpoint"
	"github.com/rknightion/graph2otel/internal/collector"
)

// CheckpointState reads the durable blob cursor read-only for the admin page
// (#178 Part B): total bytes, blobs tracked, and the newest (lexically greatest)
// blob name.
func TestBlobCollectorCheckpointState(t *testing.T) {
	dir := t.TempDir()
	store := checkpoint.NewStore(dir)

	// Persist a cursor with two tracked blobs; cursorKey defaults to Container.
	if err := store.SaveCursor(&checkpoint.BlobCursor{
		TenantID: "t1",
		Key:      testConfig().Container,
		Offsets:  map[string]int64{"h=03/PT1H.json": 1000, "h=05/PT1H.json": 3096},
	}); err != nil {
		t.Fatalf("SaveCursor: %v", err)
	}

	c := NewBlobCollector("test.blob", time.Minute, "t1", testConfig(), nil, store, discardLogger())
	st := c.CheckpointState()
	if st == nil {
		t.Fatalf("CheckpointState() = nil, want a blob cursor")
	}
	if st.Kind != collector.CheckpointKindBlob {
		t.Errorf("Kind = %q, want %q", st.Kind, collector.CheckpointKindBlob)
	}
	if st.ByteOffset != 4096 {
		t.Errorf("ByteOffset = %d, want 4096 (sum of offsets)", st.ByteOffset)
	}
	if st.BlobsTracked != 2 {
		t.Errorf("BlobsTracked = %d, want 2", st.BlobsTracked)
	}
	if st.NewestBlob != "h=05/PT1H.json" {
		t.Errorf("NewestBlob = %q, want the lexically-greatest blob", st.NewestBlob)
	}
}

// A cold blob collector (no cursor persisted yet) reports an empty-but-present
// blob state rather than nil, so the page can show "0 blobs" honestly.
func TestBlobCollectorCheckpointStateCold(t *testing.T) {
	c := NewBlobCollector("test.blob", time.Minute, "t1", testConfig(), nil,
		checkpoint.NewStore(t.TempDir()), discardLogger())
	st := c.CheckpointState()
	if st == nil {
		t.Fatalf("CheckpointState() = nil, want an empty blob state")
	}
	if st.ByteOffset != 0 || st.BlobsTracked != 0 || st.NewestBlob != "" {
		t.Errorf("cold state = %+v, want zero offset/blobs/newest", st)
	}
}
