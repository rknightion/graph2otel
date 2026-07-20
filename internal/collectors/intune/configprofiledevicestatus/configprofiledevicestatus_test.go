package configprofiledevicestatus

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

// liveRows are the two VERBATIM DeviceStatusesByConfigurationProfile rows
// captured on m7kni, probed as graph2otel-poller 2026-07-20. Both are
// ReportStatus=Succeeded; the second row's DeviceName/UPN are genuinely
// empty on the wire (no user signed in / device-only assignment).
func liveRows() []exportjob.Row {
	return []exportjob.Row{
		{
			"PolicyId":          "6310fdf4-7c43-4371-b1ba-5410061ab33a",
			"PolicyName":        "Windows Tailscale",
			"IntuneDeviceId":    "d5900d67-e50c-44ef-9d5c-6a2f891099c6",
			"DeviceName":        "LAPHAM",
			"UPN":               "rob@m7kni.io",
			"PolicyStatus":      "2",
			"ReportStatus":      "Succeeded",
			"UnifiedPolicyType": "GroupPolicyConfiguration",
		},
		{
			"PolicyId":          "814e0ee7-cfb9-4efa-966b-de8a25a3f3f2",
			"PolicyName":        "Windows Google",
			"IntuneDeviceId":    "3854ffd5-1a3f-42ac-8b18-1610363ff656",
			"DeviceName":        "",
			"UPN":               "",
			"PolicyStatus":      "2",
			"ReportStatus":      "Succeeded",
			"UnifiedPolicyType": "GroupPolicyConfiguration",
		},
	}
}

// conflictRow is a SYNTHETIC row (no Conflict status was observed live on
// m7kni) constructed solely to exercise the WARN severity branch. Column
// names are live-confirmed via liveRows above; the values here are
// illustrative, not captured from the wire.
func conflictRow() exportjob.Row {
	return exportjob.Row{
		"PolicyId":          "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
		"PolicyName":        "Synthetic Conflicting Profile",
		"IntuneDeviceId":    "11111111-2222-3333-4444-555555555555",
		"DeviceName":        "SYNTH-DEVICE",
		"UPN":               "synthetic@m7kni.io",
		"PolicyStatus":      "5",
		"ReportStatus":      "Conflict",
		"UnifiedPolicyType": "GroupPolicyConfiguration",
	}
}

// TestCollectCountsByReportStatus pins the bounded gauge: one point per
// ReportStatus, value = row count. Both live rows share status Succeeded.
func TestCollectCountsByReportStatus(t *testing.T) {
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
		t.Errorf("Select = %v, want empty (report 400s on select, #203)", runner.lastReq.Select)
	}

	points := rec.MetricPoints(metricName)
	if len(points) != 1 {
		t.Fatalf("got %d points, want 1 (both live rows share status Succeeded): %+v", len(points), points)
	}
	if points[0].Attrs[semconv.AttrReportStatus] != "Succeeded" || points[0].Value != 2 {
		t.Errorf("point = %+v, want status Succeeded value 2", points[0])
	}
	if points[0].Unit != "{device}" {
		t.Errorf("Unit = %q, want {device}", points[0].Unit)
	}
}

// TestMetricCarriesOnlyBoundedDimensions: many distinct device rows on one
// status must collapse to one series carrying only report_status.
func TestMetricCarriesOnlyBoundedDimensions(t *testing.T) {
	rows := make([]exportjob.Row, 0, 40)
	for i := range 40 {
		rows = append(rows, exportjob.Row{
			"PolicyId": "policy-x", "PolicyName": "Policy X",
			"IntuneDeviceId": fmt.Sprintf("dev-%d", i), "DeviceName": fmt.Sprintf("DEV%d", i),
			"UPN": fmt.Sprintf("user%d@m7kni.io", i), "PolicyStatus": "2",
			"ReportStatus": "Succeeded", "UnifiedPolicyType": "GroupPolicyConfiguration",
		})
	}
	c := New(&fakeRunner{rows: rows}, nil)
	rec := telemetrytest.New()
	if err := c.Collect(context.Background(), rec.Emitter()); err != nil {
		t.Fatalf("Collect: %v", err)
	}
	points := rec.MetricPoints(metricName)
	if len(points) != 1 {
		t.Fatalf("got %d series from 40 rows on one status, want 1: %+v", len(points), points)
	}
	for k := range points[0].Attrs {
		if k != semconv.AttrReportStatus {
			t.Errorf("metric carries unbounded attribute %q; per-device detail belongs on the %s twin (#83, #112)", k, eventName)
		}
	}
}

// TestCollectEmitsTwinPerRow pins the twin: one record per (device, profile)
// row with the full per-device detail and INFO severity for Succeeded.
func TestCollectEmitsTwinPerRow(t *testing.T) {
	c := New(&fakeRunner{rows: liveRows()}, nil)
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
		if l.SeverityText != "INFO" {
			t.Errorf("Severity = %q, want INFO for Succeeded", l.SeverityText)
		}
		byDevice[l.Attrs[semconv.AttrDeviceId]] = l
	}
	got := byDevice["d5900d67-e50c-44ef-9d5c-6a2f891099c6"]
	want := map[string]string{
		semconv.AttrPolicyId:          "6310fdf4-7c43-4371-b1ba-5410061ab33a",
		semconv.AttrPolicyName:        "Windows Tailscale",
		semconv.AttrDeviceName:        "LAPHAM",
		semconv.AttrUpn:               "rob@m7kni.io",
		semconv.AttrReportStatus:      "Succeeded",
		semconv.AttrPolicyStatus:      "2",
		semconv.AttrUnifiedPolicyType: "GroupPolicyConfiguration",
	}
	for k, wv := range want {
		if got.Attrs[k] != wv {
			t.Errorf("twin attr %q = %q, want %q", k, got.Attrs[k], wv)
		}
	}
	if !got.Timestamp.IsZero() {
		t.Errorf("Timestamp = %v, want zero (re-emitted state snapshot)", got.Timestamp)
	}
}

// TestWarnOnConflict: a Conflict-status row escalates its twin to WARN.
func TestWarnOnConflict(t *testing.T) {
	c := New(&fakeRunner{rows: []exportjob.Row{conflictRow()}}, nil)
	rec := telemetrytest.New()
	if err := c.Collect(context.Background(), rec.Emitter()); err != nil {
		t.Fatalf("Collect: %v", err)
	}
	logs := rec.LogRecords()
	if len(logs) != 1 {
		t.Fatalf("got %d twins, want 1", len(logs))
	}
	if logs[0].SeverityText != "WARN" {
		t.Errorf("Severity = %q, want WARN for Conflict", logs[0].SeverityText)
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

// TestCollectEmptyReportEmitsNothing: 0 rows (no assigned profiles, or an
// empty tenant) is a valid steady state — no gauge points, no twins, no error.
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
