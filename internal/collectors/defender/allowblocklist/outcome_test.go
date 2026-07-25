package allowblocklist

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/rknightion/graph2otel/internal/collectors"
	"github.com/rknightion/graph2otel/internal/recordoutcome"
	"github.com/rknightion/graph2otel/internal/telemetrytest"
)

func TestCollect_RecordsOneOutcomePerListEntry(t *testing.T) {
	outcomes := recordoutcome.NewRecorder()
	c := New(collectors.EXODeps{Client: liveTenant(t)})
	c.now = func() time.Time { return fixedNow }

	if err := c.Collect(context.Background(), telemetrytest.New().Emitter(), outcomes); err != nil {
		t.Fatalf("Collect: %v", err)
	}

	want := recordoutcome.Counts{Fetched: 6, Mapped: 6, Emitted: 6}
	if got := outcomes.Snapshot().Counts; got != want {
		t.Fatalf("outcomes = %+v, want %+v", got, want)
	}
}

func TestCollect_RecordsSourceFailure(t *testing.T) {
	outcomes := recordoutcome.NewRecorder()
	c := New(collectors.EXODeps{Client: &fakeEXO{err: errors.New("invoke failed")}})

	if err := c.Collect(context.Background(), telemetrytest.New().Emitter(), outcomes); err == nil {
		t.Fatal("Collect returned nil, want source error")
	}

	got := outcomes.Snapshot()
	if got.Counts != (recordoutcome.Counts{}) {
		t.Fatalf("source-failure counts = %+v, want zero", got.Counts)
	}
	if len(got.Causes) != 1 || got.Causes[0] != recordoutcome.CauseSourceError {
		t.Fatalf("source-failure causes = %v, want [%s]", got.Causes, recordoutcome.CauseSourceError)
	}
}
