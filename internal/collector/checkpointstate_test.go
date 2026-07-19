package collector

import (
	"context"
	"testing"
	"time"

	"github.com/rknightion/graph2otel/internal/telemetry"
)

// checkpointReporterStub is a Collector that reports a canned checkpoint state,
// standing in for an engine collector (logpipeline/blobpipeline/...).
type checkpointReporterStub struct {
	state *CheckpointState
}

func (checkpointReporterStub) Name() string                                     { return "stub" }
func (checkpointReporterStub) DefaultInterval() time.Duration                   { return time.Hour }
func (checkpointReporterStub) Collect(context.Context, telemetry.Emitter) error { return nil }
func (s checkpointReporterStub) CheckpointState() *CheckpointState              { return s.state }

// plainNoStateStub is a Collector that persists no cursor (an inline snapshot
// collector), so it is not a CheckpointReporter.
type plainNoStateStub struct{}

func (plainNoStateStub) Name() string                                     { return "plain" }
func (plainNoStateStub) DefaultInterval() time.Duration                   { return time.Hour }
func (plainNoStateStub) Collect(context.Context, telemetry.Emitter) error { return nil }

func TestCheckpointStateOf(t *testing.T) {
	want := &CheckpointState{Kind: CheckpointKindWindow, SeenIDs: 3}
	if got := CheckpointStateOf(checkpointReporterStub{state: want}); got != want {
		t.Errorf("CheckpointStateOf(reporter) = %+v, want %+v", got, want)
	}

	// A reporter may still report nil (no cursor persisted yet / read failed).
	if got := CheckpointStateOf(checkpointReporterStub{state: nil}); got != nil {
		t.Errorf("CheckpointStateOf(nil-reporting reporter) = %+v, want nil", got)
	}

	// A non-reporter collector yields nil, not a panic.
	if got := CheckpointStateOf(plainNoStateStub{}); got != nil {
		t.Errorf("CheckpointStateOf(plain) = %+v, want nil", got)
	}
}
