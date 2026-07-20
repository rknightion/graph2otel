package driverupdatesummary

import (
	"context"
	"errors"
	"testing"

	"github.com/rknightion/graph2otel/internal/exportjob"
	"github.com/rknightion/graph2otel/internal/semconv"
	"github.com/rknightion/graph2otel/internal/telemetry"
	"github.com/rknightion/graph2otel/internal/telemetrytest"
)

type fakeRunner struct {
	rows    []exportjob.Row
	err     error
	lastReq exportjob.Request
}

func (f *fakeRunner) Export(_ context.Context, req exportjob.Request, _ telemetry.Emitter) ([]exportjob.Row, error) {
	f.lastReq = req
	if f.err != nil {
		return nil, f.err
	}
	return f.rows, nil
}

var _ exportjob.Runner = (*fakeRunner)(nil)

// liveRow is VERBATIM the DriverUpdatePolicyStatusSummary row captured on m7kni,
// probed as graph2otel-poller 2026-07-20.
func liveRow() exportjob.Row {
	return exportjob.Row{
		"PolicyId":                     "ba79e66e-a36d-4b29-8495-7ebcc8b72e5f",
		"PolicyName":                   "Windows Autopatch Driver Update Policy - group - Test",
		"CountDevicesErrorStatus":      "0",
		"CountDevicesInProgressStatus": "2",
		"CountDevicesSuccessStatus":    "0",
		"CountDevicesCancelledStatus":  "0",
		"CountOfPausedDrivers":         "0",
		"CountOfNeedsReviewDrivers":    "0",
	}
}

// TestCollectEmitsPointPerState pins the fan-out: 1 row x 4 states = 4 points.
// The in_progress point must carry the parsed value 2 and the three expected attrs.
func TestCollectEmitsPointPerState(t *testing.T) {
	runner := &fakeRunner{rows: []exportjob.Row{liveRow()}}
	c := New(runner, nil)
	rec := telemetrytest.New()
	if err := c.Collect(context.Background(), rec.Emitter()); err != nil {
		t.Fatalf("Collect: %v", err)
	}
	if runner.lastReq.ReportName != reportName {
		t.Errorf("ReportName = %q, want %q", runner.lastReq.ReportName, reportName)
	}
	if len(runner.lastReq.Select) == 0 {
		t.Error("Select must be non-empty")
	}

	points := rec.MetricPoints(metricName)
	if len(points) != 4 {
		t.Fatalf("got %d points, want 4: %+v", len(points), points)
	}

	want := map[string]float64{
		stateError:      0,
		stateInProgress: 2,
		stateSuccess:    0,
		stateCancelled:  0,
	}

	var inProgress *telemetrytest.MetricPoint
	seen := map[string]bool{}
	for i, p := range points {
		state := p.Attrs[semconv.AttrUpdateDeploymentState]
		wv, ok := want[state]
		if !ok {
			t.Errorf("unexpected state %q: %+v", state, p)
			continue
		}
		if p.Value != wv {
			t.Errorf("state=%q value = %v, want %v", state, p.Value, wv)
		}
		seen[state] = true
		if state == stateInProgress {
			inProgress = &points[i]
		}
	}
	for state := range want {
		if !seen[state] {
			t.Errorf("missing point for state=%q", state)
		}
	}

	if inProgress == nil {
		t.Fatal("no in_progress point found")
	}
	if inProgress.Value != 2 {
		t.Errorf("in_progress value = %v, want 2", inProgress.Value)
	}
	if inProgress.Attrs[semconv.AttrPolicyId] != "ba79e66e-a36d-4b29-8495-7ebcc8b72e5f" {
		t.Errorf("in_progress policy_id = %q", inProgress.Attrs[semconv.AttrPolicyId])
	}
	if inProgress.Attrs[semconv.AttrPolicyName] != "Windows Autopatch Driver Update Policy - group - Test" {
		t.Errorf("in_progress policy_name = %q", inProgress.Attrs[semconv.AttrPolicyName])
	}
	if inProgress.Attrs[semconv.AttrUpdateDeploymentState] != stateInProgress {
		t.Errorf("in_progress update_deployment_state = %q", inProgress.Attrs[semconv.AttrUpdateDeploymentState])
	}
}

// TestNoAttrMapAliasing guards against a shared-map bug: the four points for one
// policy must carry four DISTINCT update_deployment_state values, not the same
// value repeated because all four points aliased one map.
func TestNoAttrMapAliasing(t *testing.T) {
	c := New(&fakeRunner{rows: []exportjob.Row{liveRow()}}, nil)
	rec := telemetrytest.New()
	if err := c.Collect(context.Background(), rec.Emitter()); err != nil {
		t.Fatalf("Collect: %v", err)
	}
	points := rec.MetricPoints(metricName)
	if len(points) != 4 {
		t.Fatalf("got %d points, want 4", len(points))
	}
	states := map[string]bool{}
	for _, p := range points {
		states[p.Attrs[semconv.AttrUpdateDeploymentState]] = true
	}
	want := []string{stateError, stateInProgress, stateSuccess, stateCancelled}
	if len(states) != len(want) {
		t.Errorf("got %d distinct states %v, want %d: %v", len(states), states, len(want), want)
	}
	for _, s := range want {
		if !states[s] {
			t.Errorf("missing distinct state %q among points: %v", s, states)
		}
	}
}

func TestMetricUnitAndName(t *testing.T) {
	c := New(&fakeRunner{rows: []exportjob.Row{liveRow()}}, nil)
	rec := telemetrytest.New()
	if err := c.Collect(context.Background(), rec.Emitter()); err != nil {
		t.Fatalf("Collect: %v", err)
	}
	points := rec.MetricPoints(metricName)
	if len(points) == 0 {
		t.Fatalf("no points for metric %q; emitted: %v", metricName, rec.MetricNames())
	}
	if got := points[0].Unit; got != "{device}" {
		t.Errorf("Unit = %q, want {device}", got)
	}
	if metricName != "intune.driver_update_summary.devices" {
		t.Errorf("metricName = %q", metricName)
	}
}

func TestCollectSkipsAndLogsOnExportError(t *testing.T) {
	c := New(&fakeRunner{err: errors.New("exportjob: DriverUpdatePolicyStatusSummary: boom")}, nil)
	rec := telemetrytest.New()
	if err := c.Collect(context.Background(), rec.Emitter()); err != nil {
		t.Fatalf("Collect returned error, want nil: %v", err)
	}
	if len(rec.MetricPoints(metricName)) != 0 || len(rec.LogRecords()) != 0 {
		t.Error("expected no emissions on export failure")
	}
}

func TestCollectSkipsWhenExportRunnerIsNil(t *testing.T) {
	c := New(nil, nil)
	rec := telemetrytest.New()
	if err := c.Collect(context.Background(), rec.Emitter()); err != nil {
		t.Fatalf("Collect: %v", err)
	}
	if len(rec.MetricPoints(metricName)) != 0 || len(rec.LogRecords()) != 0 {
		t.Error("expected no emissions when runner nil")
	}
}

func TestCollectEmptyReportEmitsNothing(t *testing.T) {
	c := New(&fakeRunner{rows: nil}, nil)
	rec := telemetrytest.New()
	if err := c.Collect(context.Background(), rec.Emitter()); err != nil {
		t.Fatalf("Collect: %v", err)
	}
	if len(rec.MetricPoints(metricName)) != 0 || len(rec.LogRecords()) != 0 {
		t.Error("expected no emissions for empty report")
	}
}

func TestCollectorContract(t *testing.T) {
	c := New(nil, nil)
	if !c.Experimental() {
		t.Error("Experimental() = false, want true")
	}
	perms := c.RequiredPermissions()
	if len(perms) != 1 || perms[0] != "DeviceManagementManagedDevices.ReadWrite.All" {
		t.Errorf("RequiredPermissions = %v", perms)
	}
	if c.Name() != collectorName {
		t.Errorf("Name() = %q", c.Name())
	}
	if c.DefaultInterval().Hours() != 6 {
		t.Errorf("DefaultInterval = %v, want 6h", c.DefaultInterval())
	}
	if c.IngestTransport() != telemetry.TransportReportExport {
		t.Errorf("IngestTransport = %q", c.IngestTransport())
	}
}

func TestSelectColumnsPinned(t *testing.T) {
	runner := &fakeRunner{rows: []exportjob.Row{liveRow()}}
	c := New(runner, nil)
	rec := telemetrytest.New()
	if err := c.Collect(context.Background(), rec.Emitter()); err != nil {
		t.Fatalf("Collect: %v", err)
	}
	want := []string{
		"PolicyId", "PolicyName",
		"CountDevicesErrorStatus", "CountDevicesInProgressStatus", "CountDevicesSuccessStatus", "CountDevicesCancelledStatus",
		"CountOfPausedDrivers", "CountOfNeedsReviewDrivers",
	}
	got := runner.lastReq.Select
	if len(got) != len(want) {
		t.Fatalf("Select = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("Select[%d] = %q, want %q (full: %v)", i, got[i], want[i], got)
		}
	}
}
