package qualityupdatesummary

import (
	"context"
	"errors"
	"fmt"
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

// liveRows starts from the VERBATIM QualityUpdatePolicyStatusSummary row captured
// on m7kni, probed as graph2otel-poller 2026-07-20 — legitimately all-zero counts
// on this tenant — plus a second synthetic row with non-zero counts so gauge
// values are exercised.
func liveRows() []exportjob.Row {
	return []exportjob.Row{
		{
			"PolicyId": "5b0eba92-a709-4af6-8478-4cbde87ed3ef", "PolicyName": "g2o-193-qualityupdate-DELETE-ME",
			"ExpediteQUReleaseDate":        "2026-04-14T00:00:00Z",
			"CountDevicesInProgressStatus": "0", "CountDevicesErrorStatus": "0", "CountDevicesSuccessStatus": "0",
		},
		{
			"PolicyId": "9c1b1e2a-1111-4af6-8478-4cbde87ed3ef", "PolicyName": "synthetic-quality-update",
			"ExpediteQUReleaseDate":        "2026-05-01T00:00:00Z",
			"CountDevicesInProgressStatus": "3", "CountDevicesErrorStatus": "1", "CountDevicesSuccessStatus": "12",
		},
	}
}

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
		t.Fatalf("got %d points, want 6 (2 policies x 3 states): %+v", len(points), points)
	}

	type key struct {
		policyID string
		state    string
	}
	want := map[key]float64{
		{"5b0eba92-a709-4af6-8478-4cbde87ed3ef", "in_progress"}: 0,
		{"5b0eba92-a709-4af6-8478-4cbde87ed3ef", "error"}:       0,
		{"5b0eba92-a709-4af6-8478-4cbde87ed3ef", "success"}:     0,
		{"9c1b1e2a-1111-4af6-8478-4cbde87ed3ef", "in_progress"}: 3,
		{"9c1b1e2a-1111-4af6-8478-4cbde87ed3ef", "error"}:       1,
		{"9c1b1e2a-1111-4af6-8478-4cbde87ed3ef", "success"}:     12,
	}
	for _, p := range points {
		k := key{p.Attrs[semconv.AttrPolicyId], p.Attrs[semconv.AttrUpdateDeploymentState]}
		wv, ok := want[k]
		if !ok {
			t.Errorf("unexpected point %+v", p)
			continue
		}
		if p.Value != wv {
			t.Errorf("point %+v value = %v, want %v", k, p.Value, wv)
		}
		if len(p.Attrs) != 4 {
			t.Errorf("point %+v has %d attrs, want 4: %+v", k, len(p.Attrs), p.Attrs)
		}
		for attrKey := range p.Attrs {
			switch attrKey {
			case semconv.AttrPolicyId, semconv.AttrPolicyName, semconv.AttrExpediteReleaseDate, semconv.AttrUpdateDeploymentState:
			default:
				t.Errorf("point %+v carries unexpected attr %q; NO per-device data belongs on this metric", k, attrKey)
			}
		}
	}
}

func TestCollectAttrsCarryPolicyNameAndReleaseDate(t *testing.T) {
	c := New(&fakeRunner{rows: liveRows()[:1]}, nil)
	rec := telemetrytest.New()
	if err := c.Collect(context.Background(), rec.Emitter()); err != nil {
		t.Fatalf("Collect: %v", err)
	}
	points := rec.MetricPoints(metricName)
	if len(points) != 3 {
		t.Fatalf("got %d points, want 3", len(points))
	}
	for _, p := range points {
		if p.Attrs[semconv.AttrPolicyId] != "5b0eba92-a709-4af6-8478-4cbde87ed3ef" {
			t.Errorf("PolicyId = %q", p.Attrs[semconv.AttrPolicyId])
		}
		if p.Attrs[semconv.AttrPolicyName] != "g2o-193-qualityupdate-DELETE-ME" {
			t.Errorf("PolicyName = %q", p.Attrs[semconv.AttrPolicyName])
		}
		if p.Attrs[semconv.AttrExpediteReleaseDate] != "2026-04-14T00:00:00Z" {
			t.Errorf("ExpediteReleaseDate = %q", p.Attrs[semconv.AttrExpediteReleaseDate])
		}
	}
}

func TestCollectNoLogTwin(t *testing.T) {
	c := New(&fakeRunner{rows: liveRows()}, nil)
	rec := telemetrytest.New()
	if err := c.Collect(context.Background(), rec.Emitter()); err != nil {
		t.Fatalf("Collect: %v", err)
	}
	if logs := rec.LogRecords(); len(logs) != 0 {
		t.Errorf("got %d log records, want 0 (pre-aggregated report has no per-device data)", len(logs))
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

func TestParseErrorTreatedAsZero(t *testing.T) {
	rows := []exportjob.Row{
		{
			"PolicyId": "bad-count-policy", "PolicyName": "bad-count",
			"ExpediteQUReleaseDate":        "2026-06-01T00:00:00Z",
			"CountDevicesInProgressStatus": "not-a-number", "CountDevicesErrorStatus": "", "CountDevicesSuccessStatus": "5",
		},
	}
	c := New(&fakeRunner{rows: rows}, nil)
	rec := telemetrytest.New()
	if err := c.Collect(context.Background(), rec.Emitter()); err != nil {
		t.Fatalf("Collect: %v", err)
	}
	points := rec.MetricPoints(metricName)
	if len(points) != 3 {
		t.Fatalf("got %d points, want 3", len(points))
	}
	for _, p := range points {
		state := p.Attrs[semconv.AttrUpdateDeploymentState]
		switch state {
		case "in_progress", "error":
			if p.Value != 0 {
				t.Errorf("state %q value = %v, want 0 on parse failure", state, p.Value)
			}
		case "success":
			if p.Value != 5 {
				t.Errorf("state %q value = %v, want 5", state, p.Value)
			}
		default:
			t.Errorf("unexpected state %q", state)
		}
	}
}

func TestCollectSkipsAndLogsOnExportError(t *testing.T) {
	for _, tc := range []struct {
		name string
		err  error
	}{
		{"job failed", fmt.Errorf("exportjob: %s: %w", reportName, exportjob.ErrJobFailed)},
		{"forbidden", errors.New("exportjob: QualityUpdatePolicyStatusSummary: create: status 403: forbidden")},
		{"other", errors.New("exportjob: QualityUpdatePolicyStatusSummary: boom")},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := New(&fakeRunner{err: tc.err}, nil)
			rec := telemetrytest.New()
			if err := c.Collect(context.Background(), rec.Emitter()); err != nil {
				t.Fatalf("Collect returned error, want nil: %v", err)
			}
			if len(rec.MetricPoints(metricName)) != 0 || len(rec.LogRecords()) != 0 {
				t.Error("expected no emissions on export failure")
			}
		})
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
