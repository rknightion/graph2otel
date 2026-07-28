package exposuregraph

import (
	"context"
	"testing"

	"github.com/rknightion/graph2otel/internal/collectors"
	"github.com/rknightion/graph2otel/internal/recordoutcome"
	"github.com/rknightion/graph2otel/internal/telemetrytest"
)

// TestCollect_RecordsEachCensusRowOnce pins the outcome accounting for a
// full, successful cycle over the live fixtures: every node-census row and
// every edge-census row is fetched, mapped and emitted exactly once as a
// gauge point, in addition to the twin rows.
func TestCollect_RecordsEachCensusRowOnce(t *testing.T) {
	f := newFake(t)
	outcomes := recordoutcome.NewRecorder()

	if err := New(collectors.HuntDeps{Client: f}).Collect(context.Background(), telemetrytest.New().Emitter(), outcomes); err != nil {
		t.Fatalf("Collect: %v", err)
	}

	snap := outcomes.Snapshot().Counts
	// 21 node-census rows + 13 edge-census rows + 19 node twins + 13 edge
	// twins, each fetched/mapped/emitted once.
	wantFetched := uint64(21 + 13 + 19 + 13)
	if snap.Fetched != wantFetched {
		t.Errorf("Fetched = %d, want %d", snap.Fetched, wantFetched)
	}
	if snap.Mapped != wantFetched {
		t.Errorf("Mapped = %d, want %d", snap.Mapped, wantFetched)
	}
	if snap.Emitted != wantFetched {
		t.Errorf("Emitted = %d, want %d", snap.Emitted, wantFetched)
	}
}
