package compliance

import (
	"context"
	"testing"

	"github.com/rknightion/graph2otel/internal/recordoutcome"
	"github.com/rknightion/graph2otel/internal/telemetrytest"
)

func TestCollectPoliciesDropsEmptyIDInsteadOfClaimingEmission(t *testing.T) {
	t.Parallel()

	g := &fakeGraph{bodies: map[string]string{
		policiesURL: `{"value":[{"displayName":"missing identity","version":1}]}`,
	}}
	recorder := recordoutcome.NewRecorder()
	c := New(g, nil)
	c.outcomes = recorder

	refs, err := c.collectPolicies(context.Background(), telemetrytest.New().Emitter())
	if err != nil {
		t.Fatalf("collectPolicies() = %v", err)
	}
	if len(refs) != 0 {
		t.Fatalf("refs = %v, want none", refs)
	}

	got := recorder.Snapshot()
	want := recordoutcome.Counts{Fetched: 1, Dropped: 1}
	if got.Counts != want {
		t.Fatalf("counts = %+v, want %+v", got.Counts, want)
	}
	if len(got.Causes) != 1 || got.Causes[0] != recordoutcome.CauseMappingError {
		t.Fatalf("causes = %v, want [mapping_error]", got.Causes)
	}
}
