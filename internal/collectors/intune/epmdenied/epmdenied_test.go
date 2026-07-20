package epmdenied

import (
	"context"
	"errors"
	"fmt"
	"reflect"
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

// sampleRows use the twelve columns live-confirmed from the EpmDeniedReport export
// header (probed as graph2otel-poller 2026-07-20 on m7kni). The report returned
// ZERO rows on m7kni (no denied elevations — the healthy state), so the column
// NAMES are live-confirmed but the field VALUES here are illustrative — used only
// to pin the column→attr wiring, never to assert a value exists on the wire (the
// #142 discipline).
func sampleRows() []exportjob.Row {
	return []exportjob.Row{
		{
			"UserName": "AzureAD\\RobKnight", "DeviceId": "11111111-1111-1111-1111-111111111111",
			"DeviceName": "LAPHAM", "FileName": "regedit.exe", "FileProductName": "Microsoft Windows",
			"FileDescription": "Registry Editor", "FileInternalName": "REGEDIT", "FileVersion": "10.0.26100.1",
			"HashValue": "ABC123", "Publisher": "Microsoft", "ElevationType": "UnmanagedElevation",
			"MonthElevationCount": "3",
		},
		{
			"UserName": "AzureAD\\RobKnight", "DeviceId": "22222222-2222-2222-2222-222222222222",
			"DeviceName": "DESKTOP-X", "FileName": "cmd.exe", "FileProductName": "Microsoft Windows",
			"FileDescription": "Command Prompt", "FileInternalName": "cmd", "FileVersion": "10.0.26100.1",
			"HashValue": "DEF456", "Publisher": "Microsoft", "ElevationType": "UnmanagedElevation",
			"MonthElevationCount": "1",
		},
	}
}

// TestCollectCountsByElevationType pins the bounded gauge: two rows sharing an
// ElevationType collapse into one point whose value is the row count.
func TestCollectCountsByElevationType(t *testing.T) {
	runner := &fakeRunner{rows: sampleRows()}
	c := New(runner, nil)
	rec := telemetrytest.New()
	if err := c.Collect(context.Background(), rec.Emitter()); err != nil {
		t.Fatalf("Collect: %v", err)
	}
	if runner.lastReq.ReportName != reportName {
		t.Errorf("ReportName = %q, want %q", runner.lastReq.ReportName, reportName)
	}
	if !reflect.DeepEqual(runner.lastReq.Select, selectColumns) {
		t.Errorf("Select = %v, want pinned %v", runner.lastReq.Select, selectColumns)
	}

	points := rec.MetricPoints(metricName)
	if len(points) != 1 {
		t.Fatalf("got %d points, want 1: %+v", len(points), points)
	}
	p := points[0]
	if p.Value != 2 {
		t.Errorf("Value = %v, want 2", p.Value)
	}
	if p.Unit != "{denial}" {
		t.Errorf("Unit = %q, want {denial}", p.Unit)
	}
	if p.Attrs[semconv.AttrElevationType] != "UnmanagedElevation" {
		t.Errorf("elevation_type = %q", p.Attrs[semconv.AttrElevationType])
	}
}

// TestMetricCarriesOnlyBoundedDimensions: many distinct denial rows on one
// elevation type must collapse to one series carrying only elevation_type.
func TestMetricCarriesOnlyBoundedDimensions(t *testing.T) {
	rows := make([]exportjob.Row, 0, 40)
	for i := range 40 {
		rows = append(rows, exportjob.Row{
			"UserName": fmt.Sprintf("AzureAD\\User%d", i), "DeviceId": fmt.Sprintf("dev-%d", i),
			"DeviceName": fmt.Sprintf("HOST-%d", i), "FileName": "regedit.exe",
			"FileProductName": "Microsoft Windows", "FileDescription": "Registry Editor",
			"FileInternalName": "REGEDIT", "FileVersion": "10.0.26100.1",
			"HashValue": fmt.Sprintf("HASH%d", i), "Publisher": "Microsoft",
			"ElevationType": "UnmanagedElevation", "MonthElevationCount": "1",
		})
	}
	c := New(&fakeRunner{rows: rows}, nil)
	rec := telemetrytest.New()
	if err := c.Collect(context.Background(), rec.Emitter()); err != nil {
		t.Fatalf("Collect: %v", err)
	}
	points := rec.MetricPoints(metricName)
	if len(points) != 1 {
		t.Fatalf("got %d series from 40 rows on one elevation type, want 1: %+v", len(points), points)
	}
	for k := range points[0].Attrs {
		if k != semconv.AttrElevationType {
			t.Errorf("metric carries unbounded attribute %q; per-denial detail belongs on the %s twin (#83, #112)", k, eventName)
		}
	}
}

// TestCollectEmitsTwinPerRow pins the twin: one record per denial row with the
// full per-denial detail and WARN severity.
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
			t.Errorf("EventName = %q, want %q", l.EventName, eventName)
		}
		if l.SeverityText != "WARN" {
			t.Errorf("Severity = %q, want WARN (a denied elevation is a security signal)", l.SeverityText)
		}
		if !l.Timestamp.IsZero() {
			t.Errorf("Timestamp = %v, want zero (re-emitted state snapshot)", l.Timestamp)
		}
		byDevice[l.Attrs[semconv.AttrDeviceId]] = l
	}
	got := byDevice["11111111-1111-1111-1111-111111111111"]
	want := map[string]string{
		semconv.AttrDeviceId:            "11111111-1111-1111-1111-111111111111",
		semconv.AttrDeviceName:          "LAPHAM",
		semconv.AttrUserName:            "AzureAD\\RobKnight",
		semconv.AttrFileName:            "regedit.exe",
		semconv.AttrFileDescription:     "Registry Editor",
		semconv.AttrPublisher:           "Microsoft",
		semconv.AttrHash:                "ABC123",
		semconv.AttrElevationType:       "UnmanagedElevation",
		semconv.AttrMonthElevationCount: "3",
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
// (no denied elevations) emits no gauge points, no twins, no error.
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

// TestSelectColumnsPinned locks the export select list: EpmDeniedReport has no
// "_loc" localized-column fallback, so this exact set (order included) is the only
// known-working select — a silent reorder or drop must fail this test.
func TestSelectColumnsPinned(t *testing.T) {
	want := []string{
		"UserName", "DeviceId", "DeviceName", "FileName", "FileProductName",
		"FileDescription", "FileInternalName", "FileVersion", "HashValue",
		"Publisher", "ElevationType", "MonthElevationCount",
	}
	if !reflect.DeepEqual(selectColumns, want) {
		t.Errorf("selectColumns = %v, want %v", selectColumns, want)
	}

	runner := &fakeRunner{rows: sampleRows()}
	c := New(runner, nil)
	rec := telemetrytest.New()
	if err := c.Collect(context.Background(), rec.Emitter()); err != nil {
		t.Fatalf("Collect: %v", err)
	}
	if !reflect.DeepEqual(runner.lastReq.Select, want) {
		t.Errorf("lastReq.Select = %v, want %v", runner.lastReq.Select, want)
	}
}
