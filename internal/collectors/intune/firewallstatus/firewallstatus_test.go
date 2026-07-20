package firewallstatus

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

// liveRows are the two VERBATIM FirewallStatus rows captured on m7kni, probed as
// graph2otel-poller 2026-07-20. Both report FirewallStatus "0" (Enabled).
func liveRows() []exportjob.Row {
	return []exportjob.Row{
		{
			"DeviceId":             "76916de8-ab1c-4f94-a3e7-2655e79f1039",
			"DeviceName":           "CPC-rob-VR8USFP",
			"FirewallStatus":       "0",
			"FirewallStatus_loc":   "Enabled",
			"LastReportedDateTime": "2026-07-20 04:41:52.7475490",
			"UPN":                  "rob@m7kni.io",
			"UserName":             "Rob Knight",
		},
		{
			"DeviceId":             "60229bb6-6d50-4ed5-aaf6-28b13a597bca",
			"DeviceName":           "CPC-rob-G4M1EB0",
			"FirewallStatus":       "0",
			"FirewallStatus_loc":   "Enabled",
			"LastReportedDateTime": "2026-07-20 16:12:29.4716467",
			"UPN":                  "rob@m7kni.io",
			"UserName":             "Rob Knight",
		},
	}
}

// warnRow is a SYNTHETIC row (constructed, illustrative values, live column
// names) with FirewallStatus "1" to exercise the WARN path — no live example of
// a non-Enabled status has been observed on m7kni.
func warnRow() exportjob.Row {
	return exportjob.Row{
		"DeviceId":             "11111111-2222-3333-4444-555555555555",
		"DeviceName":           "SYNTH-DEVICE-01",
		"FirewallStatus":       "1",
		"FirewallStatus_loc":   "Disabled",
		"LastReportedDateTime": "2026-07-20 12:00:00.0000000",
		"UPN":                  "synthetic.user@m7kni.io",
		"UserName":             "Synthetic User",
	}
}

// TestCollectCountsByFirewallStatus pins the bounded gauge: one point per raw
// FirewallStatus code, value = device-row count. It also pins the #203 Select
// omission.
func TestCollectCountsByFirewallStatus(t *testing.T) {
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
		t.Errorf("Select = %v, want empty (this report's _loc columns 400 on selection, #203)", runner.lastReq.Select)
	}

	points := rec.MetricPoints(metricName)
	if len(points) != 1 {
		t.Fatalf("got %d points, want 1 (both live rows share status 0): %+v", len(points), points)
	}
	if points[0].Attrs[semconv.AttrFirewallStatus] != "0" || points[0].Value != 2 {
		t.Errorf("point = %+v, want status 0 value 2", points[0])
	}
	if points[0].Unit != "{device}" {
		t.Errorf("Unit = %q, want {device}", points[0].Unit)
	}
}

// TestMetricCarriesOnlyBoundedDimensions: many distinct device rows on one status
// must collapse to one series carrying only firewall_status.
func TestMetricCarriesOnlyBoundedDimensions(t *testing.T) {
	rows := make([]exportjob.Row, 0, 40)
	for i := range 40 {
		rows = append(rows, exportjob.Row{
			"DeviceId":             fmt.Sprintf("dev-%d", i),
			"DeviceName":           fmt.Sprintf("DEVICE-%d", i),
			"FirewallStatus":       "0",
			"LastReportedDateTime": "2026-07-20 00:00:00.0000000",
			"UPN":                  fmt.Sprintf("user%d@m7kni.io", i),
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
		if k != semconv.AttrFirewallStatus {
			t.Errorf("metric carries unbounded attribute %q; per-device detail belongs on the %s twin (#83, #112)", k, eventName)
		}
	}
}

// TestCollectEmitsTwinPerRow pins the twin: one record per device row with the
// full per-device detail and INFO severity for status 0 (Enabled).
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
			t.Errorf("Severity = %q, want INFO (status 0 = Enabled = healthy)", l.SeverityText)
		}
		byDevice[l.Attrs[semconv.AttrDeviceId]] = l
	}
	got := byDevice["76916de8-ab1c-4f94-a3e7-2655e79f1039"]
	want := map[string]string{
		semconv.AttrDeviceName:           "CPC-rob-VR8USFP",
		semconv.AttrUpn:                  "rob@m7kni.io",
		semconv.AttrFirewallStatus:       "0",
		semconv.AttrLastReportedDateTime: "2026-07-20 04:41:52.7475490",
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

// TestWarnWhenFirewallNotEnabled: a non-zero FirewallStatus escalates the twin
// to WARN.
func TestWarnWhenFirewallNotEnabled(t *testing.T) {
	c := New(&fakeRunner{rows: []exportjob.Row{warnRow()}}, nil)
	rec := telemetrytest.New()
	if err := c.Collect(context.Background(), rec.Emitter()); err != nil {
		t.Fatalf("Collect: %v", err)
	}
	logs := rec.LogRecords()
	if len(logs) != 1 {
		t.Fatalf("got %d twins, want 1", len(logs))
	}
	if logs[0].SeverityText != "WARN" {
		t.Errorf("Severity = %q, want WARN (status != 0)", logs[0].SeverityText)
	}
	if logs[0].Attrs[semconv.AttrFirewallStatus] != "1" {
		t.Errorf("firewall_status attr = %q, want 1", logs[0].Attrs[semconv.AttrFirewallStatus])
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

// TestCollectEmptyReportEmitsNothing: 0 rows is a valid steady state — no gauge
// points, no twins, no error.
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
