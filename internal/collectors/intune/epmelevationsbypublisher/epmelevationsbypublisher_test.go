package epmelevationsbypublisher

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

// liveRows is the VERBATIM EpmAggregationReportByPublisher row captured on m7kni,
// probed as graph2otel-poller 2026-07-21 with an explicit select of exactly these
// three columns.
func liveRows() []exportjob.Row {
	return []exportjob.Row{
		{"CompanyName": "Microsoft Windows", "ElevationType": "UnmanagedElevation", "ElevationCount": "43"},
	}
}

// TestCollectSumsElevationCountByType pins the bounded gauge: one point per
// elevation_type, value = SUM of ElevationCount across publishers, and the wire
// enum value passed through verbatim (not lowercased, not re-mapped).
func TestCollectSumsElevationCountByType(t *testing.T) {
	runner := &fakeRunner{rows: liveRows()}
	c := New(runner, nil)
	rec := telemetrytest.New()
	if err := c.Collect(context.Background(), rec.Emitter()); err != nil {
		t.Fatalf("Collect: %v", err)
	}
	if runner.lastReq.ReportName != "EpmAggregationReportByPublisher" {
		t.Errorf("ReportName = %q", runner.lastReq.ReportName)
	}
	if len(runner.lastReq.Select) == 0 {
		t.Error("Select must be non-empty (the report accepts an explicit select; pin the columns)")
	}
	points := rec.MetricPoints(metricName)
	if len(points) != 1 {
		t.Fatalf("got %d points, want 1: %+v", len(points), points)
	}
	if points[0].Attrs[semconv.AttrElevationType] != "UnmanagedElevation" {
		t.Errorf("elevation_type = %q, want the verbatim wire enum UnmanagedElevation", points[0].Attrs[semconv.AttrElevationType])
	}
	if points[0].Value != 43 {
		t.Errorf("summed elevation count = %v, want 43", points[0].Value)
	}
}

// TestGaugeSumsAcrossTypes pins that two distinct types produce two points, each
// summing its own publishers' rows.
func TestGaugeSumsAcrossTypes(t *testing.T) {
	rows := append(liveRows(),
		exportjob.Row{"CompanyName": "Contoso Ltd", "ElevationType": "ManagedElevation", "ElevationCount": "5"},
		exportjob.Row{"CompanyName": "Fabrikam Inc", "ElevationType": "UnmanagedElevation", "ElevationCount": "2"},
	)
	c := New(&fakeRunner{rows: rows}, nil)
	rec := telemetrytest.New()
	if err := c.Collect(context.Background(), rec.Emitter()); err != nil {
		t.Fatalf("Collect: %v", err)
	}
	got := map[string]float64{}
	for _, p := range rec.MetricPoints(metricName) {
		got[p.Attrs[semconv.AttrElevationType]] = p.Value
	}
	if got["UnmanagedElevation"] != 45 || got["ManagedElevation"] != 5 {
		t.Errorf("sums = %+v, want Unmanaged:45 Managed:5", got)
	}
}

func TestMetricNameAndUnitPinned(t *testing.T) {
	c := New(&fakeRunner{rows: liveRows()}, nil)
	rec := telemetrytest.New()
	if err := c.Collect(context.Background(), rec.Emitter()); err != nil {
		t.Fatalf("Collect: %v", err)
	}
	points := rec.MetricPoints("intune.epm_elevations_by_publisher.count")
	if len(points) == 0 {
		t.Fatalf("no points; emitted: %v", rec.MetricNames())
	}
	if got := points[0].Unit; got != "{elevation}" {
		t.Errorf("Unit = %q, want {elevation}", got)
	}
}

// TestMetricNeverCarriesPublisher is the #112 guard: 40 distinct publishers on one
// elevation type must collapse to one series carrying only elevation_type.
func TestMetricNeverCarriesPublisher(t *testing.T) {
	rows := make([]exportjob.Row, 0, 40)
	for i := range 40 {
		rows = append(rows, exportjob.Row{
			"CompanyName":   fmt.Sprintf("Publisher %d Ltd", i),
			"ElevationType": "UnmanagedElevation", "ElevationCount": "1",
		})
	}
	c := New(&fakeRunner{rows: rows}, nil)
	rec := telemetrytest.New()
	if err := c.Collect(context.Background(), rec.Emitter()); err != nil {
		t.Fatalf("Collect: %v", err)
	}
	points := rec.MetricPoints(metricName)
	if len(points) != 1 {
		t.Fatalf("got %d series from 40 distinct publishers, want 1: %+v", len(points), points)
	}
	if points[0].Value != 40 {
		t.Errorf("summed count = %v, want 40", points[0].Value)
	}
	for k := range points[0].Attrs {
		if k != semconv.AttrElevationType {
			t.Errorf("metric carries attribute %q; per-publisher detail belongs on the %s twin (#83, #112)", k, eventName)
		}
	}
}

// TestCollectEmitsTwinPerPublisher pins the twin: one record per publisher row,
// WARN on an unmanaged elevation.
func TestCollectEmitsTwinPerPublisher(t *testing.T) {
	c := New(&fakeRunner{rows: liveRows()}, nil)
	rec := telemetrytest.New()
	if err := c.Collect(context.Background(), rec.Emitter()); err != nil {
		t.Fatalf("Collect: %v", err)
	}
	logs := rec.LogRecords()
	if len(logs) != 1 {
		t.Fatalf("got %d twins, want 1", len(logs))
	}
	l := logs[0]
	if l.EventName != eventName {
		t.Errorf("EventName = %q", l.EventName)
	}
	want := map[string]string{
		semconv.AttrCompanyName:    "Microsoft Windows",
		semconv.AttrElevationType:  "UnmanagedElevation",
		semconv.AttrElevationCount: "43",
	}
	for k, wv := range want {
		if l.Attrs[k] != wv {
			t.Errorf("twin attr %q = %q, want %q", k, l.Attrs[k], wv)
		}
	}
	if l.SeverityText != "WARN" {
		t.Errorf("unmanaged elevation: Severity = %q, want WARN", l.SeverityText)
	}
}

// TestManagedElevationIsInfo pins that a managed (policy-governed) elevation is INFO.
func TestManagedElevationIsInfo(t *testing.T) {
	c := New(&fakeRunner{rows: []exportjob.Row{{
		"CompanyName": "Contoso Ltd", "ElevationType": "ManagedElevation", "ElevationCount": "1",
	}}}, nil)
	rec := telemetrytest.New()
	if err := c.Collect(context.Background(), rec.Emitter()); err != nil {
		t.Fatalf("Collect: %v", err)
	}
	if got := rec.LogRecords()[0].SeverityText; got != "INFO" {
		t.Errorf("managed elevation: Severity = %q, want INFO", got)
	}
}

func TestCollectSkipsAndLogsOnExportError(t *testing.T) {
	for _, tc := range []struct {
		name string
		err  error
	}{
		{"job failed", fmt.Errorf("exportjob: %s: %w", reportName, exportjob.ErrJobFailed)},
		{"sas expired", fmt.Errorf("exportjob: %s: %w", reportName, exportjob.ErrSASExpired)},
		{"forbidden", errors.New("exportjob: EpmAggregationReportByPublisher: create: status 403: forbidden")},
		{"other", errors.New("exportjob: EpmAggregationReportByPublisher: boom")},
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
	if c.Name() != "intune.epm_elevations_by_publisher" {
		t.Errorf("collector name = %q, want intune.epm_elevations_by_publisher", c.Name())
	}
	if c.DefaultInterval().Hours() != 6 {
		t.Errorf("DefaultInterval = %v, want 6h", c.DefaultInterval())
	}
	if c.IngestTransport() != telemetry.TransportReportExport {
		t.Errorf("IngestTransport = %q", c.IngestTransport())
	}
}

func TestCollectStampsReportExportTransport(t *testing.T) {
	c := New(&fakeRunner{rows: liveRows()}, nil)
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
