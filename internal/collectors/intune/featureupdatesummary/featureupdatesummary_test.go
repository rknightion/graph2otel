package featureupdatesummary

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

// liveRow is VERBATIM the FeatureUpdatePolicyStatusSummary row captured on m7kni,
// probed as graph2otel-poller 2026-07-20. The policy is inert on this tenant, so all
// three counts are legitimately 0 — this still validates column names and fan-out.
// syntheticRow is a hand-built second row with non-zero counts so the gauge values
// are actually exercised.
func liveRows() []exportjob.Row {
	return []exportjob.Row{
		{
			"PolicyId":                     "dae032f0-7c03-4a69-95b0-9e4b3abc82e7",
			"PolicyName":                   "g2o-193-featureupdate-DELETE-ME",
			"FeatureUpdateVersion":         "Windows 11, version 24H2",
			"CountDevicesInProgressStatus": "0",
			"CountDevicesErrorStatus":      "0",
			"CountDevicesSuccessStatus":    "0",
		},
		{
			"PolicyId":                     "11111111-2222-3333-4444-555555555555",
			"PolicyName":                   "synthetic-nonzero-policy",
			"FeatureUpdateVersion":         "Windows 11, version 23H2",
			"CountDevicesInProgressStatus": "3",
			"CountDevicesErrorStatus":      "2",
			"CountDevicesSuccessStatus":    "17",
		},
	}
}

// TestCollectEmitsThreeStatesPerPolicy pins the fan-out: 2 rows x 3 states = 6 points,
// each carrying all four attrs and the correctly parsed value for its state.
func TestCollectEmitsThreeStatesPerPolicy(t *testing.T) {
	runner := &fakeRunner{rows: liveRows()}
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
	if len(points) != 6 {
		t.Fatalf("got %d points, want 6: %+v", len(points), points)
	}

	type key struct{ policyID, state string }
	want := map[key]float64{
		{"dae032f0-7c03-4a69-95b0-9e4b3abc82e7", "in_progress"}: 0,
		{"dae032f0-7c03-4a69-95b0-9e4b3abc82e7", "error"}:       0,
		{"dae032f0-7c03-4a69-95b0-9e4b3abc82e7", "success"}:     0,
		{"11111111-2222-3333-4444-555555555555", "in_progress"}: 3,
		{"11111111-2222-3333-4444-555555555555", "error"}:       2,
		{"11111111-2222-3333-4444-555555555555", "success"}:     17,
	}

	seen := map[key]bool{}
	for _, p := range points {
		k := key{p.Attrs[semconv.AttrPolicyId], p.Attrs[semconv.AttrUpdateDeploymentState]}
		wv, ok := want[k]
		if !ok {
			t.Errorf("unexpected point for policy=%q state=%q: %+v", k.policyID, k.state, p)
			continue
		}
		if p.Value != wv {
			t.Errorf("policy=%q state=%q value = %v, want %v", k.policyID, k.state, p.Value, wv)
		}
		seen[k] = true
	}
	for k := range want {
		if !seen[k] {
			t.Errorf("missing point for policy=%q state=%q", k.policyID, k.state)
		}
	}
}

// TestMetricAttrsAreBoundedNoPerDeviceData pins #112: only the four bounded attrs
// (policy_id, policy_name, feature_update_version, update_deployment_state) — no
// per-device/entity attribute exists on this metric, and there is no log twin.
func TestMetricAttrsAreBoundedNoPerDeviceData(t *testing.T) {
	c := New(&fakeRunner{rows: liveRows()}, nil)
	rec := telemetrytest.New()
	if err := c.Collect(context.Background(), rec.Emitter()); err != nil {
		t.Fatalf("Collect: %v", err)
	}
	wantKeys := map[string]bool{
		semconv.AttrPolicyId:              true,
		semconv.AttrPolicyName:            true,
		semconv.AttrFeatureUpdateVersion:  true,
		semconv.AttrUpdateDeploymentState: true,
	}
	for _, p := range rec.MetricPoints(metricName) {
		if len(p.Attrs) != len(wantKeys) {
			t.Errorf("point has %d attrs, want %d: %+v", len(p.Attrs), len(wantKeys), p.Attrs)
		}
		for k := range p.Attrs {
			if !wantKeys[k] {
				t.Errorf("unexpected attr key %q on metric point", k)
			}
		}
	}
	if len(rec.LogRecords()) != 0 {
		t.Errorf("got %d log records, want 0 (pre-aggregated report, no log twin)", len(rec.LogRecords()))
	}
}

func TestMetricNameAndUnitPinned(t *testing.T) {
	c := New(&fakeRunner{rows: liveRows()[:1]}, nil)
	rec := telemetrytest.New()
	if err := c.Collect(context.Background(), rec.Emitter()); err != nil {
		t.Fatalf("Collect: %v", err)
	}
	points := rec.MetricPoints(metricName)
	if len(points) == 0 {
		t.Fatalf("no points; emitted: %v", rec.MetricNames())
	}
	if got := points[0].Unit; got != "{device}" {
		t.Errorf("Unit = %q, want {device}", got)
	}
}

func TestCollectSkipsAndLogsOnExportError(t *testing.T) {
	c := New(&fakeRunner{err: errors.New("exportjob: FeatureUpdatePolicyStatusSummary: boom")}, nil)
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
