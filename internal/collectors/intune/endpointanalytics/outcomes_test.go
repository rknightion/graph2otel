package endpointanalytics

import (
	"context"
	"errors"
	"testing"

	"github.com/rknightion/graph2otel/internal/recordoutcome"
	"github.com/rknightion/graph2otel/internal/telemetrytest"
)

func TestCollectAccountsExactStartupFanoutFixtureRowsOnce(t *testing.T) {
	t.Parallel()

	rowsA := `{"value":[
	  {"managedDeviceId":"` + startupProcDeviceA + `","processName":"MsMpEng","startupImpactInMs":8038},
	  {"managedDeviceId":"` + startupProcDeviceA + `","processName":"MsSense","startupImpactInMs":4822}
	]}`
	rowsB := `{"value":[
	  {"managedDeviceId":"` + startupProcDeviceB + `","processName":"WmiPrvSE","startupImpactInMs":2599}
	]}`
	g := &fakeGraph{bodies: allEndpoints(map[string]string{
		deviceScoresURL:                          deviceScoresWithIDs(startupProcDeviceA, startupProcDeviceB, startupProcDeviceC),
		startupProcFilterURL(startupProcDeviceA): rowsA,
		startupProcFilterURL(startupProcDeviceB): rowsB,
		startupProcFilterURL(startupProcDeviceC): emptyPage,
	})}
	outcomes := recordoutcome.NewRecorder()

	if err := New(g, nil).Collect(context.Background(), telemetrytest.New().Emitter(), outcomes); err != nil {
		t.Fatalf("Collect() = %v", err)
	}

	// 3 device scores + the anomaly singleton + one WFA row + one app-health
	// OS row + 3 startup-process rows. Each maps to one logical record even
	// where that record produces several metrics and a log twin.
	want := recordoutcome.Counts{Fetched: 9, Mapped: 9, Emitted: 9}
	got := outcomes.Snapshot()
	if got.Counts != want {
		t.Fatalf("counts = %+v, want %+v", got.Counts, want)
	}
	if err := got.Validate(); err != nil {
		t.Fatalf("Validate() = %v", err)
	}
}

func TestCollectAccountsUsefulRowsBeforeBatchFailureAsPartial(t *testing.T) {
	t.Parallel()

	g := &fakeGraph{
		bodies:  allEndpoints(map[string]string{deviceScoresURL: deviceScoresWithIDs(startupProcDeviceA)}),
		postErr: errors.New("status 503"),
	}
	outcomes := recordoutcome.NewRecorder()
	err := New(g, nil).Collect(context.Background(), telemetrytest.New().Emitter(), outcomes)
	if err == nil {
		t.Fatal("Collect() error = nil, want batch failure")
	}

	got := outcomes.Snapshot().Summarize(err, false)
	if got.Result != recordoutcome.ResultPartial || got.Cause != recordoutcome.CauseSourceError {
		t.Fatalf("summary = %+v, want partial/source_error", got)
	}
}
