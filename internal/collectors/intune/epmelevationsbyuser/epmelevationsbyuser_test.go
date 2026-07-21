package epmelevationsbyuser

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

// liveRows are the two VERBATIM EpmAggregationReportByUser rows captured on
// m7kni, probed as graph2otel-poller 2026-07-21 with an explicit select of
// exactly these four columns. Note the first row's Upn: the column is NOT always
// a real UPN — it carried the down-level logon name `AzureAD\RobKnight`.
func liveRows() []exportjob.Row {
	return []exportjob.Row{
		{
			"ManagedCount": "0", "UnmanagedCount": "40", "TotalCount": "40",
			"Upn": `AzureAD\RobKnight`,
		},
		{
			"ManagedCount": "0", "UnmanagedCount": "3", "TotalCount": "3",
			"Upn": "rob@m7kni.io",
		},
	}
}

// TestCollectSumsCountsByGovernance pins the bounded gauge: exactly two points,
// keyed only by elevation_governance, summing ManagedCount / UnmanagedCount
// across every user row (0+0 managed, 40+3 = 43 unmanaged on the live sample).
func TestCollectSumsCountsByGovernance(t *testing.T) {
	runner := &fakeRunner{rows: liveRows()}
	c := New(runner, nil)
	rec := telemetrytest.New()
	if err := c.Collect(context.Background(), rec.Emitter()); err != nil {
		t.Fatalf("Collect: %v", err)
	}
	if runner.lastReq.ReportName != "EpmAggregationReportByUser" {
		t.Errorf("ReportName = %q", runner.lastReq.ReportName)
	}
	if len(runner.lastReq.Select) == 0 {
		t.Error("Select must be non-empty (the report accepts an explicit select; pin the columns)")
	}
	got := map[string]float64{}
	for _, p := range rec.MetricPoints(metricName) {
		got[p.Attrs[semconv.AttrElevationGovernance]] = p.Value
	}
	if len(got) != 2 {
		t.Fatalf("got %d series, want 2 (managed + unmanaged): %+v", len(got), got)
	}
	if got[semconv.ElevationGovernanceManaged] != 0 {
		t.Errorf("managed = %v, want 0", got[semconv.ElevationGovernanceManaged])
	}
	if got[semconv.ElevationGovernanceUnmanaged] != 43 {
		t.Errorf("unmanaged = %v, want 43", got[semconv.ElevationGovernanceUnmanaged])
	}
}

// TestBothSeriesEmittedOnZeroRows: a quiet window must still produce both series
// so an alert on them has something to evaluate.
func TestBothSeriesEmittedOnZeroRows(t *testing.T) {
	c := New(&fakeRunner{rows: []exportjob.Row{}}, nil)
	rec := telemetrytest.New()
	if err := c.Collect(context.Background(), rec.Emitter()); err != nil {
		t.Fatalf("Collect: %v", err)
	}
	points := rec.MetricPoints(metricName)
	if len(points) != 2 {
		t.Fatalf("got %d points on zero rows, want 2: %+v", len(points), points)
	}
	for _, p := range points {
		if p.Value != 0 {
			t.Errorf("governance %q = %v, want 0", p.Attrs[semconv.AttrElevationGovernance], p.Value)
		}
	}
	if len(rec.LogRecords()) != 0 {
		t.Errorf("zero rows must emit no twin, got %d", len(rec.LogRecords()))
	}
}

func TestMetricNameAndUnitPinned(t *testing.T) {
	c := New(&fakeRunner{rows: liveRows()}, nil)
	rec := telemetrytest.New()
	if err := c.Collect(context.Background(), rec.Emitter()); err != nil {
		t.Fatalf("Collect: %v", err)
	}
	points := rec.MetricPoints("intune.epm_elevations_by_user.count")
	if len(points) == 0 {
		t.Fatalf("no points; emitted: %v", rec.MetricNames())
	}
	if got := points[0].Unit; got != "{elevation}" {
		t.Errorf("Unit = %q, want {elevation}", got)
	}
}

// TestMetricNeverCarriesUpn is the #112 guard: 40 distinct users must collapse to
// the same two series, and the UPN must never appear as a metric label.
func TestMetricNeverCarriesUpn(t *testing.T) {
	rows := make([]exportjob.Row, 0, 40)
	for i := range 40 {
		rows = append(rows, exportjob.Row{
			"Upn": fmt.Sprintf("user-%d@m7kni.io", i), "ManagedCount": "1",
			"UnmanagedCount": "2", "TotalCount": "3",
		})
	}
	c := New(&fakeRunner{rows: rows}, nil)
	rec := telemetrytest.New()
	if err := c.Collect(context.Background(), rec.Emitter()); err != nil {
		t.Fatalf("Collect: %v", err)
	}
	points := rec.MetricPoints(metricName)
	if len(points) != 2 {
		t.Fatalf("got %d series from 40 distinct users, want 2: %+v", len(points), points)
	}
	for _, p := range points {
		for k := range p.Attrs {
			if k != semconv.AttrElevationGovernance {
				t.Errorf("metric carries attribute %q; per-user detail belongs on the %s twin (#83, #112)", k, eventName)
			}
		}
	}
	got := map[string]float64{}
	for _, p := range points {
		got[p.Attrs[semconv.AttrElevationGovernance]] = p.Value
	}
	if got[semconv.ElevationGovernanceManaged] != 40 || got[semconv.ElevationGovernanceUnmanaged] != 80 {
		t.Errorf("sums = %+v, want managed:40 unmanaged:80", got)
	}
}

// TestCollectEmitsTwinPerUser pins the twin: one record per user row carrying the
// verbatim Upn plus the three counts, WARN when the user has any unmanaged
// elevation.
func TestCollectEmitsTwinPerUser(t *testing.T) {
	c := New(&fakeRunner{rows: liveRows()}, nil)
	rec := telemetrytest.New()
	if err := c.Collect(context.Background(), rec.Emitter()); err != nil {
		t.Fatalf("Collect: %v", err)
	}
	logs := rec.LogRecords()
	if len(logs) != 2 {
		t.Fatalf("got %d twins, want 2", len(logs))
	}
	byUpn := map[string]telemetrytest.LogRecord{}
	for _, l := range logs {
		if l.EventName != eventName {
			t.Errorf("EventName = %q", l.EventName)
		}
		byUpn[l.Attrs[semconv.AttrUpn]] = l
	}
	// The down-level logon name rides through verbatim — no parsing, no
	// normalisation, no validation.
	down, ok := byUpn[`AzureAD\RobKnight`]
	if !ok {
		t.Fatalf("down-level logon name not emitted verbatim; got %v", byUpn)
	}
	want := map[string]string{
		semconv.AttrManagedCount:   "0",
		semconv.AttrUnmanagedCount: "40",
		semconv.AttrTotalCount:     "40",
	}
	for k, wv := range want {
		if down.Attrs[k] != wv {
			t.Errorf("twin attr %q = %q, want %q", k, down.Attrs[k], wv)
		}
	}
	if down.SeverityText != "WARN" {
		t.Errorf("user with unmanaged elevations: Severity = %q, want WARN", down.SeverityText)
	}
}

// TestNoUnmanagedElevationsIsInfo pins that a fully policy-governed user is INFO.
func TestNoUnmanagedElevationsIsInfo(t *testing.T) {
	c := New(&fakeRunner{rows: []exportjob.Row{{
		"Upn": "rob@m7kni.io", "ManagedCount": "7", "UnmanagedCount": "0", "TotalCount": "7",
	}}}, nil)
	rec := telemetrytest.New()
	if err := c.Collect(context.Background(), rec.Emitter()); err != nil {
		t.Fatalf("Collect: %v", err)
	}
	if got := rec.LogRecords()[0].SeverityText; got != "INFO" {
		t.Errorf("no unmanaged elevations: Severity = %q, want INFO", got)
	}
}

func TestCollectSkipsAndLogsOnExportError(t *testing.T) {
	for _, tc := range []struct {
		name string
		err  error
	}{
		{"job failed", fmt.Errorf("exportjob: %s: %w", reportName, exportjob.ErrJobFailed)},
		{"sas expired", fmt.Errorf("exportjob: %s: %w", reportName, exportjob.ErrSASExpired)},
		{"forbidden", errors.New("exportjob: EpmAggregationReportByUser: create: status 403: forbidden")},
		{"other", errors.New("exportjob: EpmAggregationReportByUser: boom")},
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
	if c.Name() != "intune.epm_elevations_by_user" {
		t.Errorf("collector name = %q, want intune.epm_elevations_by_user", c.Name())
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
