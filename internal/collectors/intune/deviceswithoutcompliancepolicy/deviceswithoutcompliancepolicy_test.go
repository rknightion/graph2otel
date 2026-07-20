package deviceswithoutcompliancepolicy

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

// sampleRows use columns live-confirmed from the DevicesWithoutCompliancePolicy
// export default header (probed as graph2otel-poller 2026-07-20 on m7kni). The
// report returned ZERO rows on m7kni (every managed device has a compliance
// policy), so the column NAMES are live-confirmed but the field VALUES here are
// illustrative — used only to pin the column→attr wiring, never to assert a value
// exists on the wire (the #142 discipline).
func sampleRows() []exportjob.Row {
	return []exportjob.Row{
		{
			"DeviceId": "11111111-1111-1111-1111-111111111111", "DeviceName": "KIOSK-01",
			"OS": "Windows", "OSVersion": "10.0.26100", "OwnerType": "company",
			"UPN": "", "ComplianceState": "unknown",
		},
		{
			"DeviceId": "22222222-2222-2222-2222-222222222222", "DeviceName": "IPAD-07",
			"OS": "iOS", "OSVersion": "18.1", "OwnerType": "personal",
			"UPN": "user@m7kni.io", "ComplianceState": "unknown",
		},
	}
}

// TestCollectCountsByOs pins the bounded gauge: one point per distinct OS, value =
// device-row count, and confirms Select is omitted entirely (#203).
func TestCollectCountsByOs(t *testing.T) {
	runner := &fakeRunner{rows: sampleRows()}
	c := New(runner, nil)
	rec := telemetrytest.New()
	if err := c.Collect(context.Background(), rec.Emitter()); err != nil {
		t.Fatalf("Collect: %v", err)
	}
	if runner.lastReq.ReportName != reportName {
		t.Errorf("ReportName = %q", runner.lastReq.ReportName)
	}
	if len(runner.lastReq.Select) != 0 {
		t.Errorf("Select = %v, want empty (report 400s on selected _loc columns, #203)", runner.lastReq.Select)
	}

	want := map[string]float64{"Windows": 1, "iOS": 1}
	points := rec.MetricPoints(metricName)
	if len(points) != len(want) {
		t.Fatalf("got %d points, want %d: %+v", len(points), len(want), points)
	}
	for _, p := range points {
		if p.Value != want[p.Attrs[semconv.AttrOs]] {
			t.Errorf("os %q = %v", p.Attrs[semconv.AttrOs], p.Value)
		}
		if p.Unit != "{device}" {
			t.Errorf("Unit = %q, want {device}", p.Unit)
		}
	}
}

// TestMetricCarriesOnlyBoundedDimensions: many distinct devices on one OS must
// collapse to one series carrying only os.
func TestMetricCarriesOnlyBoundedDimensions(t *testing.T) {
	rows := make([]exportjob.Row, 0, 40)
	for i := range 40 {
		rows = append(rows, exportjob.Row{
			"DeviceId": fmt.Sprintf("dev-%d", i), "DeviceName": fmt.Sprintf("DEV-%d", i),
			"OS": "Windows", "OSVersion": "10.0.26100", "OwnerType": "company",
			"UPN": fmt.Sprintf("user%d@m7kni.io", i), "ComplianceState": "unknown",
		})
	}
	c := New(&fakeRunner{rows: rows}, nil)
	rec := telemetrytest.New()
	if err := c.Collect(context.Background(), rec.Emitter()); err != nil {
		t.Fatalf("Collect: %v", err)
	}
	points := rec.MetricPoints(metricName)
	if len(points) != 1 {
		t.Fatalf("got %d series from 40 rows on one OS, want 1: %+v", len(points), points)
	}
	for k := range points[0].Attrs {
		if k != semconv.AttrOs {
			t.Errorf("metric carries unbounded attribute %q; per-device detail belongs on the %s twin (#83, #112)", k, eventName)
		}
	}
}

// TestCollectEmitsTwinPerRow pins the twin: one WARN record per device row with the
// full per-device detail.
func TestCollectEmitsTwinPerRow(t *testing.T) {
	c := New(&fakeRunner{rows: sampleRows()}, nil)
	rec := telemetrytest.New()
	if err := c.Collect(context.Background(), rec.Emitter()); err != nil {
		t.Fatalf("Collect: %v", err)
	}
	logs := rec.LogRecords()
	if len(logs) != 2 {
		t.Fatalf("got %d twins, want 2", len(logs))
	}
	byDevice := map[string]telemetrytest.LogRecord{}
	for _, l := range logs {
		if l.EventName != eventName {
			t.Errorf("EventName = %q", l.EventName)
		}
		if l.SeverityText != "WARN" {
			t.Errorf("Severity = %q, want WARN (a device with no compliance policy is a posture gap)", l.SeverityText)
		}
		if !l.Timestamp.IsZero() {
			t.Errorf("Timestamp = %v, want zero (re-emitted state snapshot)", l.Timestamp)
		}
		byDevice[l.Attrs[semconv.AttrDeviceName]] = l
	}
	got := byDevice["KIOSK-01"]
	want := map[string]string{
		semconv.AttrDeviceId:        "11111111-1111-1111-1111-111111111111",
		semconv.AttrOs:              "Windows",
		semconv.AttrOsVersion:       "10.0.26100",
		semconv.AttrOwnerType:       "company",
		semconv.AttrUpn:             "",
		semconv.AttrComplianceState: "unknown",
	}
	for k, wv := range want {
		if got.Attrs[k] != wv {
			t.Errorf("twin attr %q = %q, want %q", k, got.Attrs[k], wv)
		}
	}
}

func TestCollectSkipsAndLogsOnExportError(t *testing.T) {
	for _, tc := range []struct {
		name string
		err  error
	}{
		{"job failed", fmt.Errorf("exportjob: %s: %w", reportName, exportjob.ErrJobFailed)},
		{"forbidden", errors.New("exportjob: " + reportName + ": create: status 403: forbidden")},
		{"other", errors.New("exportjob: " + reportName + ": boom")},
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

// TestCollectEmptyReportEmitsNothing pins the observed m7kni steady state: 0 rows
// (every managed device has a compliance policy) emits no gauge points, no twins,
// no error.
func TestCollectEmptyReportEmitsNothing(t *testing.T) {
	c := New(&fakeRunner{rows: nil}, nil)
	rec := telemetrytest.New()
	if err := c.Collect(context.Background(), rec.Emitter()); err != nil {
		t.Fatalf("Collect: %v", err)
	}
	if len(rec.MetricPoints(metricName)) != 0 || len(rec.LogRecords()) != 0 {
		t.Error("expected no emissions on empty report")
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

func TestCollectStampsReportExportTransport(t *testing.T) {
	c := New(&fakeRunner{rows: sampleRows()}, nil)
	rec := telemetrytest.New()
	if err := c.Collect(context.Background(), rec.Emitter()); err != nil {
		t.Fatalf("Collect: %v", err)
	}
	for i, l := range rec.LogRecords() {
		if got := l.Attrs[semconv.AttrIngestTransport]; got != string(telemetry.TransportReportExport) {
			t.Errorf("log[%d] transport = %q", i, got)
		}
	}
}
