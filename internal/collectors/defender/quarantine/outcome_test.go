package quarantine

import (
	"context"
	"testing"

	"github.com/rknightion/graph2otel/internal/recordoutcome"
	"github.com/rknightion/graph2otel/internal/telemetrytest"
)

func TestCollect_RecordsOneOutcomePerHeldMessage(t *testing.T) {
	f := &fakeEXO{pages: [][]map[string]any{{decode(t, liveRecord)}}}
	outcomes := recordoutcome.NewRecorder()

	if err := newCollector(t, f).Collect(context.Background(), telemetrytest.New().Emitter(), outcomes); err != nil {
		t.Fatalf("Collect: %v", err)
	}

	want := recordoutcome.Counts{Fetched: 1, Mapped: 1, Emitted: 1}
	if got := outcomes.Snapshot().Counts; got != want {
		t.Fatalf("outcomes = %+v, want %+v", got, want)
	}
}
