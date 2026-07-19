package epmelevations

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

// liveRows are three of the seven VERBATIM EpmAggregationReportByApplication rows
// captured on m7kni, probed as graph2otel-poller 2026-07-19. All observed rows
// were UnmanagedElevation; ElevationCount sums to 12+8+3 = 23 across these three.
func liveRows() []exportjob.Row {
	return []exportjob.Row{
		{
			"CompanyName": "Microsoft Windows", "ElevationType": "UnmanagedElevation",
			"FileVersion": "10.0.26100.2992", "Hash": "C99282B49E7AFAEEB085624C1432DBB5E3B2BC5174847D043C5F3C901C1FC3D1",
			"InternalName": "taskhostw.exe", "ElevationCount": "12", "FileName": "taskhostw.exe",
			"IsBackgroundProcess": "True",
		},
		{
			"CompanyName": "Microsoft Windows", "ElevationType": "UnmanagedElevation",
			"FileVersion": "10.0.26100.1", "Hash": "6A73F3DDA06163BB6253E4F82A283E184D70755C067633C4190FBFF64F0BAECD",
			"InternalName": "POWERSHELL", "ElevationCount": "8", "FileName": "powershell.exe",
			"IsBackgroundProcess": "True",
		},
		{
			"CompanyName": "Microsoft Windows", "ElevationType": "UnmanagedElevation",
			"FileVersion": "10.0.26100.3281", "Hash": "1495562C7EF8F5BA1346CA39284CB2F5D1359A8486936083D380050E91A9EEBC",
			"InternalName": "Acquire License From Store", "ElevationCount": "3", "FileName": "ClipRenew.exe",
			"IsBackgroundProcess": "True",
		},
	}
}

// TestCollectSumsElevationCountByType pins the bounded gauge: one point per
// elevation_type, value = SUM of ElevationCount. All three live rows are
// UnmanagedElevation → one point of 23.
func TestCollectSumsElevationCountByType(t *testing.T) {
	runner := &fakeRunner{rows: liveRows()}
	c := New(runner, nil)
	rec := telemetrytest.New()
	if err := c.Collect(context.Background(), rec.Emitter()); err != nil {
		t.Fatalf("Collect: %v", err)
	}
	if runner.lastReq.ReportName != "EpmAggregationReportByApplication" {
		t.Errorf("ReportName = %q", runner.lastReq.ReportName)
	}
	if len(runner.lastReq.Select) == 0 {
		t.Error("Select must be non-empty")
	}
	points := rec.MetricPoints(metricName)
	if len(points) != 1 {
		t.Fatalf("got %d points, want 1: %+v", len(points), points)
	}
	if points[0].Attrs[semconv.AttrElevationType] != "UnmanagedElevation" {
		t.Errorf("elevation_type = %q", points[0].Attrs[semconv.AttrElevationType])
	}
	if points[0].Value != 23 {
		t.Errorf("summed elevation count = %v, want 23", points[0].Value)
	}
}

// TestGaugeSumsAcrossTypes pins that two distinct types produce two points, each
// summing its own rows.
func TestGaugeSumsAcrossTypes(t *testing.T) {
	rows := append(liveRows(), exportjob.Row{
		"ElevationType": "ManagedElevation", "FileName": "setup.exe", "ElevationCount": "5",
	})
	c := New(&fakeRunner{rows: rows}, nil)
	rec := telemetrytest.New()
	if err := c.Collect(context.Background(), rec.Emitter()); err != nil {
		t.Fatalf("Collect: %v", err)
	}
	got := map[string]float64{}
	for _, p := range rec.MetricPoints(metricName) {
		got[p.Attrs[semconv.AttrElevationType]] = p.Value
	}
	if got["UnmanagedElevation"] != 23 || got["ManagedElevation"] != 5 {
		t.Errorf("sums = %+v, want Unmanaged:23 Managed:5", got)
	}
}

func TestMetricNameAndUnitPinned(t *testing.T) {
	c := New(&fakeRunner{rows: liveRows()[:1]}, nil)
	rec := telemetrytest.New()
	if err := c.Collect(context.Background(), rec.Emitter()); err != nil {
		t.Fatalf("Collect: %v", err)
	}
	points := rec.MetricPoints("intune.epm_elevations.count")
	if len(points) == 0 {
		t.Fatalf("no points; emitted: %v", rec.MetricNames())
	}
	if got := points[0].Unit; got != "{elevation}" {
		t.Errorf("Unit = %q, want {elevation}", got)
	}
}

// TestMetricCarriesOnlyBoundedDimensions: 40 distinct applications on one
// elevation type must collapse to one series carrying only elevation_type.
func TestMetricCarriesOnlyBoundedDimensions(t *testing.T) {
	rows := make([]exportjob.Row, 0, 40)
	for i := range 40 {
		rows = append(rows, exportjob.Row{
			"ElevationType": "UnmanagedElevation", "FileName": fmt.Sprintf("app-%d.exe", i),
			"Hash": fmt.Sprintf("hash-%d", i), "ElevationCount": "1",
		})
	}
	c := New(&fakeRunner{rows: rows}, nil)
	rec := telemetrytest.New()
	if err := c.Collect(context.Background(), rec.Emitter()); err != nil {
		t.Fatalf("Collect: %v", err)
	}
	points := rec.MetricPoints(metricName)
	if len(points) != 1 {
		t.Fatalf("got %d series from 40 distinct apps on one type, want 1: %+v", len(points), points)
	}
	if points[0].Value != 40 {
		t.Errorf("summed count = %v, want 40", points[0].Value)
	}
	for k := range points[0].Attrs {
		if k != semconv.AttrElevationType {
			t.Errorf("metric carries unbounded attribute %q; per-application detail belongs on the %s twin (#83, #112)", k, eventName)
		}
	}
}

// TestCollectEmitsTwinPerApplication pins the twin: one record per row carrying
// the per-application detail, WARN on an unmanaged elevation.
func TestCollectEmitsTwinPerApplication(t *testing.T) {
	c := New(&fakeRunner{rows: liveRows()}, nil)
	rec := telemetrytest.New()
	if err := c.Collect(context.Background(), rec.Emitter()); err != nil {
		t.Fatalf("Collect: %v", err)
	}
	logs := rec.LogRecords()
	if len(logs) != 3 {
		t.Fatalf("got %d twins, want 3", len(logs))
	}
	byFile := map[string]telemetrytest.LogRecord{}
	for _, l := range logs {
		if l.EventName != eventName {
			t.Errorf("EventName = %q", l.EventName)
		}
		byFile[l.Attrs[semconv.AttrFileName]] = l
	}
	th := byFile["taskhostw.exe"]
	want := map[string]string{
		semconv.AttrCompanyName:         "Microsoft Windows",
		semconv.AttrFileVersion:         "10.0.26100.2992",
		semconv.AttrFileHash:            "C99282B49E7AFAEEB085624C1432DBB5E3B2BC5174847D043C5F3C901C1FC3D1",
		semconv.AttrInternalName:        "taskhostw.exe",
		semconv.AttrElevationType:       "UnmanagedElevation",
		semconv.AttrElevationCount:      "12",
		semconv.AttrIsBackgroundProcess: "True",
	}
	for k, wv := range want {
		if th.Attrs[k] != wv {
			t.Errorf("twin attr %q = %q, want %q", k, th.Attrs[k], wv)
		}
	}
	if th.SeverityText != "WARN" {
		t.Errorf("unmanaged elevation: Severity = %q, want WARN", th.SeverityText)
	}
}

// TestManagedElevationIsInfo pins that a managed (policy-governed) elevation is INFO.
func TestManagedElevationIsInfo(t *testing.T) {
	c := New(&fakeRunner{rows: []exportjob.Row{{
		"ElevationType": "ManagedElevation", "FileName": "setup.exe", "ElevationCount": "1",
	}}}, nil)
	rec := telemetrytest.New()
	if err := c.Collect(context.Background(), rec.Emitter()); err != nil {
		t.Fatalf("Collect: %v", err)
	}
	if rec.LogRecords()[0].SeverityText != "INFO" {
		t.Errorf("managed elevation: Severity = %q, want INFO", rec.LogRecords()[0].SeverityText)
	}
}

func TestCollectSkipsAndLogsOnExportError(t *testing.T) {
	for _, tc := range []struct {
		name string
		err  error
	}{
		{"job failed", fmt.Errorf("exportjob: %s: %w", reportName, exportjob.ErrJobFailed)},
		{"forbidden", errors.New("exportjob: EpmAggregationReportByApplication: create: status 403: forbidden")},
		{"other", errors.New("exportjob: EpmAggregationReportByApplication: boom")},
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
