package blobpipeline

import (
	"context"
	"testing"
	"time"

	"github.com/rknightion/graph2otel/internal/checkpoint"
	"github.com/rknightion/graph2otel/internal/collector"
	"github.com/rknightion/graph2otel/internal/telemetrytest"
)

// The blob collector must satisfy the interface the scheduler type-switches on,
// or it silently never runs.
var _ collector.SnapshotCollector = (*BlobCollector)(nil)

func newTestCollector(t *testing.T, src Source) *BlobCollector {
	t.Helper()
	return NewBlobCollector("test.blob", time.Minute, "t1", testConfig(), src,
		checkpoint.NewStore(t.TempDir()), discardLogger())
}

func TestBlobCollectorEmitsAndPersistsAcrossRestart(t *testing.T) {
	name := "tenantId=t1/y=2026/m=07/d=16/h=00/m=00/PT1H.json"
	src := &fakeSource{blobs: map[string]string{name: rec("a")}}
	dir := t.TempDir()

	r1 := telemetrytest.New()
	c1 := NewBlobCollector("test.blob", time.Minute, "t1", testConfig(), src,
		checkpoint.NewStore(dir), discardLogger())
	if err := c1.Collect(context.Background(), r1.Emitter()); err != nil {
		t.Fatalf("Collect: %v", err)
	}
	if got := bodies(r1); len(got) != 1 || got[0] != "a" {
		t.Fatalf("first run emitted %v, want [a]", got)
	}

	// A completely fresh process against the same checkpoint dir: it must
	// resume, not re-emit.
	r2 := telemetrytest.New()
	c2 := NewBlobCollector("test.blob", time.Minute, "t1", testConfig(), src,
		checkpoint.NewStore(dir), discardLogger())
	if err := c2.Collect(context.Background(), r2.Emitter()); err != nil {
		t.Fatalf("Collect after restart: %v", err)
	}
	if got := bodies(r2); len(got) != 0 {
		t.Fatalf("restart re-emitted %v; the cursor did not survive the restart", got)
	}

	// New data after the restart still lands.
	src.blobs[name] = rec("a") + rec("b")
	r3 := telemetrytest.New()
	c3 := NewBlobCollector("test.blob", time.Minute, "t1", testConfig(), src,
		checkpoint.NewStore(dir), discardLogger())
	if err := c3.Collect(context.Background(), r3.Emitter()); err != nil {
		t.Fatalf("Collect after growth: %v", err)
	}
	if got := bodies(r3); len(got) != 1 || got[0] != "b" {
		t.Fatalf("post-restart growth emitted %v, want [b]", got)
	}
}

func TestBlobCollectorNameAndInterval(t *testing.T) {
	c := newTestCollector(t, &fakeSource{blobs: map[string]string{}})
	if c.Name() != "test.blob" {
		t.Errorf("Name() = %q, want %q", c.Name(), "test.blob")
	}
	if c.DefaultInterval() != time.Minute {
		t.Errorf("DefaultInterval() = %v, want %v", c.DefaultInterval(), time.Minute)
	}
}

// Two collectors sharing one container must not share a cursor.
func TestBlobCollectorHonoursCursorKeyOverride(t *testing.T) {
	name := "tenantId=t1/y=2026/m=07/d=16/h=00/m=00/PT1H.json"
	src := &fakeSource{blobs: map[string]string{name: rec("a")}}
	dir := t.TempDir()
	store := checkpoint.NewStore(dir)

	cfgA := testConfig()
	cfgA.CursorKey = "stream-a"
	cfgB := testConfig()
	cfgB.CursorKey = "stream-b"

	rA := telemetrytest.New()
	if err := NewBlobCollector("a", time.Minute, "t1", cfgA, src, store, discardLogger()).
		Collect(context.Background(), rA.Emitter()); err != nil {
		t.Fatalf("Collect a: %v", err)
	}
	rB := telemetrytest.New()
	if err := NewBlobCollector("b", time.Minute, "t1", cfgB, src, store, discardLogger()).
		Collect(context.Background(), rB.Emitter()); err != nil {
		t.Fatalf("Collect b: %v", err)
	}
	if got := bodies(rB); len(got) != 1 {
		t.Errorf("second stream emitted %v, want 1 record — a distinct CursorKey must give it its own cursor", got)
	}
}
