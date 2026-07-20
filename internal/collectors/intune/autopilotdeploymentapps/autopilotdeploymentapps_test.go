package autopilotdeploymentapps

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

// liveRows are the two VERBATIM AutopilotV2DeploymentStatusDetailedAppInfo rows
// captured on m7kni, probed as graph2otel-poller 2026-07-20. DeviceId eacc407b is
// the device whose overall deployment FAILED (see intune.autopilot_deployment
// fixture DESKTOP-Q8HBBJ4) yet its app install shows PolicyInstallStatus=2 — proof
// that app status is independent of the device deployment outcome, hence no invented
// severity.
func liveRows() []exportjob.Row {
	return []exportjob.Row{
		{
			"DeviceId":            "eacc407b-5c7a-40f5-a98a-d803198bb768",
			"ApplicationId":       "c6228d3a-59fc-4df0-be41-eb37f322a966",
			"PolicyInstallStatus": "2", "IsAdminSelected": "True",
			"ApplicationName": "Microsoft 365 Apps for Windows 10 and later",
			"AppType":         "OfficeSuiteApp",
		},
		{
			"DeviceId":            "69fb6f6d-8be7-4552-b1d0-98afc0d629f7",
			"ApplicationId":       "c6228d3a-59fc-4df0-be41-eb37f322a966",
			"PolicyInstallStatus": "2", "IsAdminSelected": "True",
			"ApplicationName": "Microsoft 365 Apps for Windows 10 and later",
			"AppType":         "OfficeSuiteApp",
		},
	}
}

// TestCollectCountsByInstallStatus pins the bounded gauge: one point per raw
// PolicyInstallStatus code, value = app-install-row count.
func TestCollectCountsByInstallStatus(t *testing.T) {
	runner := &fakeRunner{rows: liveRows()}
	c := New(runner, nil)
	rec := telemetrytest.New()
	if err := c.Collect(context.Background(), rec.Emitter()); err != nil {
		t.Fatalf("Collect: %v", err)
	}
	if runner.lastReq.ReportName != reportName {
		t.Errorf("ReportName = %q", runner.lastReq.ReportName)
	}
	if len(runner.lastReq.Select) == 0 {
		t.Error("Select must be non-empty")
	}

	points := rec.MetricPoints(metricName)
	if len(points) != 1 {
		t.Fatalf("got %d points, want 1 (both live rows share status 2): %+v", len(points), points)
	}
	if points[0].Attrs[semconv.AttrPolicyInstallStatus] != "2" || points[0].Value != 2 {
		t.Errorf("point = %+v, want status 2 value 2", points[0])
	}
	if points[0].Unit != "{app}" {
		t.Errorf("Unit = %q, want {app}", points[0].Unit)
	}
}

// TestMetricCarriesOnlyBoundedDimensions: many distinct (device, app) rows on one
// status must collapse to one series carrying only policy_install_status.
func TestMetricCarriesOnlyBoundedDimensions(t *testing.T) {
	rows := make([]exportjob.Row, 0, 40)
	for i := range 40 {
		rows = append(rows, exportjob.Row{
			"DeviceId": fmt.Sprintf("dev-%d", i), "ApplicationId": fmt.Sprintf("app-%d", i),
			"ApplicationName": fmt.Sprintf("App %d", i), "AppType": "Win32LobApp",
			"IsAdminSelected": "False", "PolicyInstallStatus": "2",
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
		if k != semconv.AttrPolicyInstallStatus {
			t.Errorf("metric carries unbounded attribute %q; per-app detail belongs on the %s twin (#83, #112)", k, eventName)
		}
	}
}

// TestCollectEmitsTwinPerRow pins the twin: one record per (device, app) row with
// the full per-app detail and INFO severity (no invented severity from the raw code).
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
			t.Errorf("Severity = %q, want INFO (raw status, no invented severity)", l.SeverityText)
		}
		byDevice[l.Attrs[semconv.AttrDeviceId]] = l
	}
	got := byDevice["eacc407b-5c7a-40f5-a98a-d803198bb768"]
	want := map[string]string{
		semconv.AttrApplicationId:       "c6228d3a-59fc-4df0-be41-eb37f322a966",
		semconv.AttrAppName:             "Microsoft 365 Apps for Windows 10 and later",
		semconv.AttrAppType:             "OfficeSuiteApp",
		semconv.AttrIsAdminSelected:     "True",
		semconv.AttrPolicyInstallStatus: "2",
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

// TestCollectEmptyReportEmitsNothing: 0 rows (a device-prep policy with no apps, or
// an empty tenant) is a valid steady state — no gauge points, no twins, no error.
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
