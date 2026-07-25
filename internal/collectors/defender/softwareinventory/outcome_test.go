package softwareinventory

import (
	"context"
	"testing"

	"github.com/rknightion/graph2otel/internal/collectors"
	"github.com/rknightion/graph2otel/internal/recordoutcome"
	"github.com/rknightion/graph2otel/internal/telemetrytest"
)

func TestCollect_RecordsEachSummaryRowOnce(t *testing.T) {
	f := &fakeHunt{summary: rowsFromArray(t, liveSummary), twins: map[string][]map[string]any{}}
	outcomes := recordoutcome.NewRecorder()

	if err := New(collectors.HuntDeps{Client: f}).Collect(context.Background(), telemetrytest.New().Emitter(), outcomes); err != nil {
		t.Fatalf("Collect: %v", err)
	}

	want := recordoutcome.Counts{Fetched: 4, Mapped: 4, Emitted: 4}
	if got := outcomes.Snapshot().Counts; got != want {
		t.Fatalf("outcomes = %+v, want %+v", got, want)
	}
}
