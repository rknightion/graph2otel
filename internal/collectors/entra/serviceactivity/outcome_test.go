package serviceactivity

import (
	"context"
	"errors"
	"testing"

	"github.com/rknightion/graph2otel/internal/recordoutcome"
	"github.com/rknightion/graph2otel/internal/telemetrytest"
)

// TestCollect_RecordsOneOutcomePerFunction pins the accounting for the normal
// path: nineteen functions, each one source record, all mapped and emitted.
func TestCollect_RecordsOneOutcomePerFunction(t *testing.T) {
	outcomes := recordoutcome.NewRecorder()
	if err := newCollector(liveGraph()).Collect(context.Background(), telemetrytest.New().Emitter(), outcomes); err != nil {
		t.Fatalf("Collect: %v", err)
	}
	want := recordoutcome.Counts{Fetched: 19, Mapped: 19, Emitted: 19}
	if got := outcomes.Snapshot().Counts; got != want {
		t.Fatalf("outcomes = %+v, want %+v", got, want)
	}
}

// TestCollect_RecordsSourceFailureWithoutInventingARecord pins that a failed
// fetch contributes NOTHING to the outcome counts — a failed function is a
// gap, not a source record that merely failed to map.
func TestCollect_RecordsSourceFailureWithoutInventingARecord(t *testing.T) {
	outcomes := recordoutcome.NewRecorder()
	g := liveGraph()
	failURL := buildURL(betaBaseURL, "getMetricsForMfaSignInSuccess", wantStart, wantEnd)
	g.errs = map[string]error{failURL: errors.New("throttled")}

	if err := newCollector(g).Collect(context.Background(), telemetrytest.New().Emitter(), outcomes); err == nil {
		t.Fatal("expected Collect to surface the failure as an error")
	}

	got := outcomes.Snapshot()
	want := recordoutcome.Counts{Fetched: 18, Mapped: 18, Emitted: 18}
	if got.Counts != want {
		t.Fatalf("counts = %+v, want %+v (the failed function adds nothing)", got.Counts, want)
	}
	if len(got.Causes) != 1 || got.Causes[0] != recordoutcome.CauseSourceError {
		t.Fatalf("causes = %v, want [%s]", got.Causes, recordoutcome.CauseSourceError)
	}
}

// TestCollect_RecordsEmptyResponseAsFiltered pins that an empty `value` array
// is accounted as a fetched-but-filtered record (no usable bucket to map),
// never as an error and never as an emitted zero.
func TestCollect_RecordsEmptyResponseAsFiltered(t *testing.T) {
	outcomes := recordoutcome.NewRecorder()
	g := liveGraph()
	emptyURL := buildURL(betaBaseURL, "getMetricsForSamlSignInSuccess", wantStart, wantEnd)
	g.bodies[emptyURL] = `{"@odata.context":"x","value":[]}`

	if err := newCollector(g).Collect(context.Background(), telemetrytest.New().Emitter(), outcomes); err != nil {
		t.Fatalf("Collect: %v", err)
	}

	got := outcomes.Snapshot()
	want := recordoutcome.Counts{Fetched: 19, Mapped: 18, Emitted: 18, Filtered: 1}
	if got.Counts != want {
		t.Fatalf("counts = %+v, want %+v", got.Counts, want)
	}
}

// TestCollect_RecordsDecodeFailure pins the decode-error accounting path.
func TestCollect_RecordsDecodeFailure(t *testing.T) {
	outcomes := recordoutcome.NewRecorder()
	g := liveGraph()
	badURL := buildURL(betaBaseURL, "getMetricsForMfaSignInFailure", wantStart, wantEnd)
	g.bodies[badURL] = `not json`

	if err := newCollector(g).Collect(context.Background(), telemetrytest.New().Emitter(), outcomes); err == nil {
		t.Fatal("expected Collect to surface the decode failure as an error")
	}

	got := outcomes.Snapshot()
	want := recordoutcome.Counts{Fetched: 19, Mapped: 18, Emitted: 18, Errored: 1}
	if got.Counts != want {
		t.Fatalf("counts = %+v, want %+v", got.Counts, want)
	}
	if len(got.Causes) != 1 || got.Causes[0] != recordoutcome.CauseDecodeError {
		t.Fatalf("causes = %v, want [%s]", got.Causes, recordoutcome.CauseDecodeError)
	}
}
