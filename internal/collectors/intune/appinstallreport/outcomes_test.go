package appinstallreport

import (
	"context"
	"errors"
	"testing"

	"github.com/rknightion/graph2otel/internal/exportjob"
	"github.com/rknightion/graph2otel/internal/recordoutcome"
	"github.com/rknightion/graph2otel/internal/telemetrytest"
)

func TestCollectAccountsExportRowsOnceDespiteMetricAndLogOutputs(t *testing.T) {
	t.Parallel()

	runner := &fakeRunner{rows: []exportjob.Row{
		row("one", "app-1", "5", 1, 0, 0, 0, 0),
		row("two", "app-2", "2", 0, 1, 0, 0, 0),
		row("three", "app-3", "1", 0, 0, 1, 0, 0),
	}}
	outcomes := recordoutcome.NewRecorder()

	if err := New(runner, nil).Collect(context.Background(), telemetrytest.New().Emitter(), outcomes); err != nil {
		t.Fatalf("Collect() = %v", err)
	}

	got := outcomes.Snapshot()
	want := recordoutcome.Counts{Fetched: 3, Mapped: 3, Emitted: 3}
	if got.Counts != want {
		t.Fatalf("counts = %+v, want %+v", got.Counts, want)
	}
	if err := got.Validate(); err != nil {
		t.Fatalf("Validate() = %v", err)
	}
}

func TestCollectRecordsSwallowedExportFailure(t *testing.T) {
	t.Parallel()

	outcomes := recordoutcome.NewRecorder()
	errExport := errors.New("export failed")
	if err := New(&fakeRunner{err: errExport}, nil).Collect(context.Background(), telemetrytest.New().Emitter(), outcomes); err != nil {
		t.Fatalf("Collect() = %v, want swallowed export error", err)
	}

	got := outcomes.Snapshot().Summarize(nil, false)
	if got.Result != recordoutcome.ResultFailure || got.Cause != recordoutcome.CauseSourceError {
		t.Fatalf("summary = %+v, want failure/source_error", got)
	}
}

func TestCollectAccountsCleanEmptyExport(t *testing.T) {
	t.Parallel()

	outcomes := recordoutcome.NewRecorder()
	if err := New(&fakeRunner{}, nil).Collect(context.Background(), telemetrytest.New().Emitter(), outcomes); err != nil {
		t.Fatalf("Collect() = %v", err)
	}

	got := outcomes.Snapshot().Summarize(nil, false)
	if got.Result != recordoutcome.ResultEmpty || got.Cause != recordoutcome.CauseNone {
		t.Fatalf("summary = %+v, want clean empty", got)
	}
}
