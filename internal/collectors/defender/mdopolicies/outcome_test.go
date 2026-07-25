package mdopolicies

import (
	"context"
	"testing"

	"github.com/rknightion/graph2otel/internal/recordoutcome"
	"github.com/rknightion/graph2otel/internal/telemetrytest"
)

func TestCollect_RecordsOneOutcomePerPolicy(t *testing.T) {
	outcomes := recordoutcome.NewRecorder()

	if err := newCollector(t, liveFake(t)).Collect(context.Background(), telemetrytest.New().Emitter(), outcomes); err != nil {
		t.Fatalf("Collect: %v", err)
	}

	want := recordoutcome.Counts{Fetched: 12, Mapped: 12, Emitted: 12}
	if got := outcomes.Snapshot().Counts; got != want {
		t.Fatalf("outcomes = %+v, want %+v", got, want)
	}
}
