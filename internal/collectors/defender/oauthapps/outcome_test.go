package oauthapps

import (
	"context"
	"errors"
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

	want := recordoutcome.Counts{Fetched: 5, Mapped: 5, Emitted: 5}
	if got := outcomes.Snapshot().Counts; got != want {
		t.Fatalf("outcomes = %+v, want %+v", got, want)
	}
}

func TestCollect_RecordsEmptyAndSourceFailure(t *testing.T) {
	t.Run("empty", func(t *testing.T) {
		outcomes := recordoutcome.NewRecorder()
		if err := New(collectors.HuntDeps{Client: &fakeHunt{twins: map[string][]map[string]any{}}}).
			Collect(context.Background(), telemetrytest.New().Emitter(), outcomes); err != nil {
			t.Fatalf("Collect: %v", err)
		}
		if got := outcomes.Snapshot(); got.Counts != (recordoutcome.Counts{}) || len(got.Causes) != 0 {
			t.Fatalf("empty outcomes = %+v, want zero counts and no cause", got)
		}
	})

	t.Run("source failure", func(t *testing.T) {
		outcomes := recordoutcome.NewRecorder()
		err := New(collectors.HuntDeps{Client: &fakeHunt{err: errors.New("query failed")}}).
			Collect(context.Background(), telemetrytest.New().Emitter(), outcomes)
		if err == nil {
			t.Fatal("Collect returned nil, want source error")
		}
		got := outcomes.Snapshot()
		if got.Counts != (recordoutcome.Counts{}) {
			t.Fatalf("source-failure counts = %+v, want zero", got.Counts)
		}
		if len(got.Causes) != 1 || got.Causes[0] != recordoutcome.CauseSourceError {
			t.Fatalf("source-failure causes = %v, want [%s]", got.Causes, recordoutcome.CauseSourceError)
		}
	})
}
