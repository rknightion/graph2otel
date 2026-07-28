package mdorules

import (
	"context"
	"testing"

	"github.com/rknightion/graph2otel/internal/recordoutcome"
	"github.com/rknightion/graph2otel/internal/telemetrytest"
)

// TestCollect_RecordsReconcilableOutcomes pins the outcome accounting over the
// baseline live fixture: 3 rule records (the three non-empty rule cmdlets) and
// 7 policy records (the baseline join fixture), where every fetched policy is
// referenced by an enabled rule and therefore FILTERED rather than mapped —
// see the package doc on the join. Reconciliation (recordoutcome.Snapshot.
// Validate) requires Fetched = Mapped+Filtered+Dropped+Errored and
// Mapped = Emitted+Deduped; this test pins the concrete counts that satisfy
// it for this fixture.
func TestCollect_RecordsReconcilableOutcomes(t *testing.T) {
	outcomes := recordoutcome.NewRecorder()

	if err := newCollector(t, liveFake(t)).Collect(context.Background(), telemetrytest.New().Emitter(), outcomes); err != nil {
		t.Fatalf("Collect: %v", err)
	}

	snap := outcomes.Snapshot()
	if err := snap.Validate(); err != nil {
		t.Fatalf("Snapshot failed reconciliation: %v", err)
	}

	want := recordoutcome.Counts{Fetched: 10, Mapped: 3, Filtered: 7, Emitted: 3}
	if got := snap.Counts; got != want {
		t.Fatalf("outcomes = %+v, want %+v", got, want)
	}
}

// TestCollect_OrphanIsMappedAndEmittedNotFiltered proves an orphan policy
// takes the Mapped+Emitted path rather than Filtered.
func TestCollect_OrphanIsMappedAndEmittedNotFiltered(t *testing.T) {
	f := liveFake(t)
	f.byCmdlet["Get-SafeLinksPolicy"] = append(f.byCmdlet["Get-SafeLinksPolicy"],
		map[string]any{"Name": "Orphaned Policy"})
	outcomes := recordoutcome.NewRecorder()

	if err := newCollector(t, f).Collect(context.Background(), telemetrytest.New().Emitter(), outcomes); err != nil {
		t.Fatalf("Collect: %v", err)
	}

	snap := outcomes.Snapshot()
	if err := snap.Validate(); err != nil {
		t.Fatalf("Snapshot failed reconciliation: %v", err)
	}
	// One more policy fetched (8 total), one more mapped+emitted (4 rule+unref
	// twins), filtered count unchanged (7 — the orphan is not filtered).
	want := recordoutcome.Counts{Fetched: 11, Mapped: 4, Filtered: 7, Emitted: 4}
	if got := snap.Counts; got != want {
		t.Fatalf("outcomes = %+v, want %+v", got, want)
	}
}
