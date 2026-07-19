package autopilotdeployment

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

// liveRows are the two VERBATIM AutopilotV2DeploymentStatus rows captured on m7kni,
// probed as graph2otel-poller 2026-07-19. DESKTOP-Q8HBBJ4 is a failed deployment
// (ResultCode -2147023436, DeploymentStatus 3); DESKTOP-CB3D9AB succeeded
// (ResultCode 0, DeploymentStatus 2).
func liveRows() []exportjob.Row {
	return []exportjob.Row{
		{
			"DeviceId": "eacc407b-5c7a-40f5-a98a-d803198bb768", "DeviceName": "DESKTOP-Q8HBBJ4",
			"SerialNumber": "Parallels-90C8FD84C504411091B8666F5217E679", "UPN": "rob@m7kni.io",
			"EnrollmentTimeInUtc": "2026-07-19 15:35:56.3022384", "CurrentProvisioningPhase": "2",
			"DeploymentStatus": "3", "DeploymentDurationTimeInSeconds": "1237", "Phase": "1796",
			"ResultCode": "-2147023436",
		},
		{
			"DeviceId": "7ff14048-0b26-4608-9880-f358be7091e2", "DeviceName": "DESKTOP-CB3D9AB",
			"SerialNumber": "Parallels-FD7C46C2FA6741D5B882A020970C1F1F", "UPN": "rob@m7kni.io",
			"EnrollmentTimeInUtc": "2025-10-25 18:58:45.0000000", "CurrentProvisioningPhase": "4",
			"DeploymentStatus": "2", "DeploymentDurationTimeInSeconds": "214", "Phase": "6",
			"ResultCode": "0",
		},
	}
}

// TestCollectCountsByDeploymentStatus pins the bounded gauge: one point per raw
// DeploymentStatus code, value = device count.
func TestCollectCountsByDeploymentStatus(t *testing.T) {
	runner := &fakeRunner{rows: liveRows()}
	c := New(runner, nil)
	rec := telemetrytest.New()
	if err := c.Collect(context.Background(), rec.Emitter()); err != nil {
		t.Fatalf("Collect: %v", err)
	}
	if runner.lastReq.ReportName != "AutopilotV2DeploymentStatus" {
		t.Errorf("ReportName = %q", runner.lastReq.ReportName)
	}
	if len(runner.lastReq.Select) == 0 {
		t.Error("Select must be non-empty")
	}

	want := map[string]float64{"3": 1, "2": 1}
	points := rec.MetricPoints(metricName)
	if len(points) != len(want) {
		t.Fatalf("got %d points, want %d: %+v", len(points), len(want), points)
	}
	for _, p := range points {
		if p.Value != want[p.Attrs[semconv.AttrDeploymentStatus]] {
			t.Errorf("status %q = %v, want %v", p.Attrs[semconv.AttrDeploymentStatus], p.Value, want[p.Attrs[semconv.AttrDeploymentStatus]])
		}
	}
}

func TestMetricNameAndUnitPinned(t *testing.T) {
	c := New(&fakeRunner{rows: liveRows()[:1]}, nil)
	rec := telemetrytest.New()
	if err := c.Collect(context.Background(), rec.Emitter()); err != nil {
		t.Fatalf("Collect: %v", err)
	}
	points := rec.MetricPoints("intune.autopilot_deployment.deployments")
	if len(points) == 0 {
		t.Fatalf("no points; emitted: %v", rec.MetricNames())
	}
	if got := points[0].Unit; got != "{device}" {
		t.Errorf("Unit = %q, want {device}", got)
	}
}

// TestMetricCarriesOnlyBoundedDimensions: 40 distinct devices on one status must
// collapse to one series carrying only deployment_status.
func TestMetricCarriesOnlyBoundedDimensions(t *testing.T) {
	rows := make([]exportjob.Row, 0, 40)
	for i := range 40 {
		rows = append(rows, exportjob.Row{
			"DeviceId": fmt.Sprintf("id-%d", i), "DeviceName": fmt.Sprintf("DEV-%d", i),
			"SerialNumber": fmt.Sprintf("SN-%d", i), "DeploymentStatus": "2", "ResultCode": "0",
		})
	}
	c := New(&fakeRunner{rows: rows}, nil)
	rec := telemetrytest.New()
	if err := c.Collect(context.Background(), rec.Emitter()); err != nil {
		t.Fatalf("Collect: %v", err)
	}
	points := rec.MetricPoints(metricName)
	if len(points) != 1 {
		t.Fatalf("got %d series from 40 devices on one status, want 1: %+v", len(points), points)
	}
	for k := range points[0].Attrs {
		if k != semconv.AttrDeploymentStatus {
			t.Errorf("metric carries unbounded attribute %q; per-device detail belongs on the %s twin (#83, #112)", k, eventName)
		}
	}
}

// TestCollectEmitsTwinPerDevice pins the twin: one record per row with the full
// per-device deployment detail and WARN severity on a non-zero ResultCode.
func TestCollectEmitsTwinPerDevice(t *testing.T) {
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
		byDevice[l.Attrs[semconv.AttrDeviceName]] = l
	}
	failed := byDevice["DESKTOP-Q8HBBJ4"]
	want := map[string]string{
		semconv.AttrDeviceId:                  "eacc407b-5c7a-40f5-a98a-d803198bb768",
		semconv.AttrSerialNumber:              "Parallels-90C8FD84C504411091B8666F5217E679",
		semconv.AttrUpn:                       "rob@m7kni.io",
		semconv.AttrDeploymentStatus:          "3",
		semconv.AttrCurrentProvisioningPhase:  "2",
		semconv.AttrPhase:                     "1796",
		semconv.AttrResultCode:                "-2147023436",
		semconv.AttrDeploymentDurationSeconds: "1237",
		semconv.AttrEnrollmentTime:            "2026-07-19 15:35:56.3022384",
	}
	for k, wv := range want {
		if failed.Attrs[k] != wv {
			t.Errorf("twin attr %q = %q, want %q", k, failed.Attrs[k], wv)
		}
	}
	if failed.SeverityText != "WARN" {
		t.Errorf("failed deployment: Severity = %q, want WARN", failed.SeverityText)
	}
	if byDevice["DESKTOP-CB3D9AB"].SeverityText != "INFO" {
		t.Errorf("succeeded deployment: Severity = %q, want INFO", byDevice["DESKTOP-CB3D9AB"].SeverityText)
	}
}

// TestTwinTimestampLeftUnset pins that EnrollmentTimeInUtc is NOT the event time —
// this is a re-emitted state snapshot.
func TestTwinTimestampLeftUnset(t *testing.T) {
	c := New(&fakeRunner{rows: liveRows()[:1]}, nil)
	rec := telemetrytest.New()
	if err := c.Collect(context.Background(), rec.Emitter()); err != nil {
		t.Fatalf("Collect: %v", err)
	}
	if !rec.LogRecords()[0].Timestamp.IsZero() {
		t.Errorf("Timestamp = %v, want zero", rec.LogRecords()[0].Timestamp)
	}
}

func TestCollectSkipsAndLogsOnExportError(t *testing.T) {
	for _, tc := range []struct {
		name string
		err  error
	}{
		{"job failed", fmt.Errorf("exportjob: %s: %w", reportName, exportjob.ErrJobFailed)},
		{"forbidden", errors.New("exportjob: AutopilotV2DeploymentStatus: create: status 403: forbidden")},
		{"other", errors.New("exportjob: AutopilotV2DeploymentStatus: boom")},
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
