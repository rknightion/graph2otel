package configsettingstatus

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

// liveRows are VERBATIM PerSettingDeviceSummaryByConfigurationPolicy rows captured
// on m7kni, probed as graph2otel-poller 2026-07-20. The first is all-compliant
// (INFO); the second is a real ERROR row (8 errored devices); the third is a real
// CONFLICT row (1 conflicting device) — proof the tenant genuinely has
// profile-assignment conflicts, so the WARN path is exercised against live data.
func liveRows() []exportjob.Row {
	return []exportjob.Row{
		{
			"PolicyId":                 "403db210-a793-4409-9248-b1337022c9c7",
			"SettingId":                "8b4c6571-6c97-f04c-d2f4-ebc8179a6196",
			"SettingName":              "Safari Allow Java Script",
			"NumberOfCompliantDevices": "2", "NumberOfErrorDevices": "0", "NumberOfConflictDevices": "0",
		},
		{
			"PolicyId":                 "5f5c5f4b-4e52-4715-ae06-ab9911322739",
			"SettingId":                "89851d3f-eb9a-561f-1a7b-d6c2343caaa5",
			"SettingName":              "Send elevation data for reporting",
			"NumberOfCompliantDevices": "6", "NumberOfErrorDevices": "8", "NumberOfConflictDevices": "0",
		},
		{
			"PolicyId":                 "73c764f2-088e-4304-87b6-c0a05d926c61",
			"SettingId":                "9f5544c9-fe21-830e-83ab-a3333b014cc3",
			"SettingName":              "Path",
			"NumberOfCompliantDevices": "0", "NumberOfErrorDevices": "0", "NumberOfConflictDevices": "1",
		},
	}
}

// TestCollectSumsIntoThreeBoundedPoints pins the rollup gauge: exactly three points
// (compliant/error/conflict), each summed across all rows.
func TestCollectSumsIntoThreeBoundedPoints(t *testing.T) {
	runner := &fakeRunner{rows: liveRows()}
	c := New(runner, nil)
	rec := telemetrytest.New()
	if err := c.Collect(context.Background(), rec.Emitter()); err != nil {
		t.Fatalf("Collect: %v", err)
	}
	if runner.lastReq.ReportName != reportName {
		t.Errorf("ReportName = %q", runner.lastReq.ReportName)
	}
	if len(runner.lastReq.Select) != 0 {
		t.Errorf("Select = %v, want empty (report rejects _loc select; #203)", runner.lastReq.Select)
	}

	points := rec.MetricPoints(metricName)
	if len(points) != 3 {
		t.Fatalf("got %d points, want 3: %+v", len(points), points)
	}
	want := map[string]float64{statusCompliant: 8, statusError: 8, statusConflict: 1}
	for _, p := range points {
		st := p.Attrs[semconv.AttrSettingDeviceStatus]
		if p.Value != want[st] {
			t.Errorf("status %q = %v, want %v", st, p.Value, want[st])
		}
		if p.Unit != "{device}" {
			t.Errorf("Unit = %q, want {device}", p.Unit)
		}
	}
}

// TestMetricCarriesOnlyBoundedDimensions: many distinct policy-setting rows must
// still collapse to exactly three series carrying only setting_device_status.
func TestMetricCarriesOnlyBoundedDimensions(t *testing.T) {
	rows := make([]exportjob.Row, 0, 40)
	for i := range 40 {
		rows = append(rows, exportjob.Row{
			"PolicyId": fmt.Sprintf("pol-%d", i), "SettingId": fmt.Sprintf("set-%d", i),
			"SettingName":              fmt.Sprintf("Setting %d", i),
			"NumberOfCompliantDevices": "1", "NumberOfErrorDevices": "0", "NumberOfConflictDevices": "0",
		})
	}
	c := New(&fakeRunner{rows: rows}, nil)
	rec := telemetrytest.New()
	if err := c.Collect(context.Background(), rec.Emitter()); err != nil {
		t.Fatalf("Collect: %v", err)
	}
	points := rec.MetricPoints(metricName)
	if len(points) != 3 {
		t.Fatalf("got %d series from 40 settings, want 3: %+v", len(points), points)
	}
	for _, p := range points {
		for k := range p.Attrs {
			if k != semconv.AttrSettingDeviceStatus {
				t.Errorf("metric carries unbounded attribute %q; per-setting detail belongs on the %s twin (#83, #112)", k, eventName)
			}
		}
	}
}

// TestCollectEmitsTwinPerSetting pins the twin: one record per row carrying that
// row's counts, with WARN severity on any error or conflict device.
func TestCollectEmitsTwinPerSetting(t *testing.T) {
	c := New(&fakeRunner{rows: liveRows()}, nil)
	rec := telemetrytest.New()
	if err := c.Collect(context.Background(), rec.Emitter()); err != nil {
		t.Fatalf("Collect: %v", err)
	}
	logs := rec.LogRecords()
	if len(logs) != 3 {
		t.Fatalf("got %d twins, want 3", len(logs))
	}
	bySetting := map[string]telemetrytest.LogRecord{}
	for _, l := range logs {
		if l.EventName != eventName {
			t.Errorf("EventName = %q", l.EventName)
		}
		if !l.Timestamp.IsZero() {
			t.Errorf("Timestamp = %v, want zero (state snapshot)", l.Timestamp)
		}
		bySetting[l.Attrs[semconv.AttrSettingId]] = l
	}

	// Compliant-only row -> INFO, counts carried verbatim.
	compliant := bySetting["8b4c6571-6c97-f04c-d2f4-ebc8179a6196"]
	if compliant.SeverityText != "INFO" {
		t.Errorf("compliant-only setting: Severity = %q, want INFO", compliant.SeverityText)
	}
	if compliant.Attrs[semconv.AttrSettingName] != "Safari Allow Java Script" ||
		compliant.Attrs[semconv.AttrCompliantDeviceCount] != "2" ||
		compliant.Attrs[semconv.AttrConflictDeviceCount] != "0" {
		t.Errorf("compliant twin attrs = %+v", compliant.Attrs)
	}

	// Error row -> WARN.
	if bySetting["89851d3f-eb9a-561f-1a7b-d6c2343caaa5"].SeverityText != "WARN" {
		t.Errorf("errored setting: Severity = %q, want WARN", bySetting["89851d3f-eb9a-561f-1a7b-d6c2343caaa5"].SeverityText)
	}
	// Conflict row -> WARN, conflict count carried.
	conflict := bySetting["9f5544c9-fe21-830e-83ab-a3333b014cc3"]
	if conflict.SeverityText != "WARN" {
		t.Errorf("conflicting setting: Severity = %q, want WARN", conflict.SeverityText)
	}
	if conflict.Attrs[semconv.AttrConflictDeviceCount] != "1" {
		t.Errorf("conflict twin conflict_device_count = %q, want 1", conflict.Attrs[semconv.AttrConflictDeviceCount])
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

// TestCollectEmptyReportEmitsNothing: 0 rows emits no gauge (not even zero points)
// and no twins.
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
