package featureupdatedevices

import (
	"context"
	"testing"

	"github.com/rknightion/graph2otel/internal/exportjob"
	"github.com/rknightion/graph2otel/internal/recordoutcome"
	"github.com/rknightion/graph2otel/internal/telemetrytest"
)

// TestCollectRecordsOneOutcomePerProfileAndDeviceRow pins the reconciliation
// equation over one profile: 1 fetched+filtered for the profile listing, plus
// fetched+mapped+emitted for every device row the export returned.
func TestCollectRecordsOneOutcomePerProfileAndDeviceRow(t *testing.T) {
	g := &fakeGraph{bodies: map[string]string{profilesURL: `{"value":[
		{"id":"` + firstPolicyID + `","displayName":"` + firstPolicyName + `","featureUpdateVersion":"Windows 11, version 25H2"}
	]}`}}
	rows := liveDeviceRows()[:3]
	exp := &fakeExport{rowsByFilter: map[string][]exportjob.Row{filterFor(firstPolicyID): rows}}
	c := New(g, exp, nil)
	outcomes := recordoutcome.NewRecorder()

	if err := c.Collect(context.Background(), telemetrytest.New().Emitter(), outcomes); err != nil {
		t.Fatalf("Collect: %v", err)
	}

	want := recordoutcome.Counts{
		Fetched:  1 + uint64(len(rows)),
		Mapped:   uint64(len(rows)),
		Emitted:  uint64(len(rows)),
		Filtered: 1,
	}
	if got := outcomes.Snapshot().Counts; got != want {
		t.Fatalf("outcomes = %+v, want %+v", got, want)
	}
}
