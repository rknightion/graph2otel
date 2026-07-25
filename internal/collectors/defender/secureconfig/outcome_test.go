package secureconfig

import (
	"context"
	"testing"

	"github.com/rknightion/graph2otel/internal/collectors"
	"github.com/rknightion/graph2otel/internal/recordoutcome"
	"github.com/rknightion/graph2otel/internal/telemetrytest"
)

func TestCollect_RecordsEachSummaryRowOnce(t *testing.T) {
	f := &fakeHunt{
		assessments: rowsFromArray(t, liveAssessments),
		risk:        rowsFromArray(t, liveRisk),
		twins:       map[string][]map[string]any{},
	}
	outcomes := recordoutcome.NewRecorder()

	if err := New(collectors.HuntDeps{Client: f}).Collect(context.Background(), telemetrytest.New().Emitter(), outcomes); err != nil {
		t.Fatalf("Collect: %v", err)
	}

	want := recordoutcome.Counts{Fetched: 15, Mapped: 15, Emitted: 15}
	if got := outcomes.Snapshot().Counts; got != want {
		t.Fatalf("outcomes = %+v, want %+v", got, want)
	}
}
