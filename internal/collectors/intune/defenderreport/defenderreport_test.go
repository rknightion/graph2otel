package defenderreport

import (
	"context"
	"errors"
	"fmt"
	"testing"

	"github.com/rknightion/graph2otel/internal/exportjob"
	"github.com/rknightion/graph2otel/internal/telemetry"
	"github.com/rknightion/graph2otel/internal/telemetrytest"
)

// fakeRunner is a canned exportjob.Runner: it returns a fixed set of rows or
// a fixed error, ignoring the request (tests assert the request separately
// where that matters). Mirrors the fake-Runner pattern the other M5 export
// consumers (e.g. appinstallreport) use to avoid any live Graph/export-job
// dependency in unit tests.
type fakeRunner struct {
	rows     []exportjob.Row
	err      error
	lastReq  exportjob.Request
	callSeen bool
}

func (f *fakeRunner) Export(_ context.Context, req exportjob.Request, _ telemetry.Emitter) ([]exportjob.Row, error) {
	f.lastReq = req
	f.callSeen = true
	if f.err != nil {
		return nil, f.err
	}
	return f.rows, nil
}

var _ exportjob.Runner = (*fakeRunner)(nil)

// row builds a DefenderAgents export row using the live-smoke-tested column
// set. Every flag column takes the export API's literal "true"/"false"
// string form.
func row(deviceID, deviceName, upn, deviceState, productStatus string, rtpEnabled, networkInspectionEnabled, signatureOverdue, tamperEnabled, malwareEnabled bool) exportjob.Row {
	return exportjob.Row{
		colDeviceID:                  deviceID,
		colDeviceName:                deviceName,
		colUPN:                       upn,
		colDeviceState:               deviceState,
		colProductStatus:             productStatus,
		colRealTimeProtectionEnabled: boolStr(rtpEnabled),
		colNetworkInspectionSystemOn: boolStr(networkInspectionEnabled),
		colSignatureUpdateOverdue:    boolStr(signatureOverdue),
		colTamperProtectionEnabled:   boolStr(tamperEnabled),
		colMalwareProtectionEnabled:  boolStr(malwareEnabled),
	}
}

func boolStr(b bool) string {
	if b {
		return "true"
	}
	return "false"
}

func TestSelectColumnsMatchLiveVerifiedSet(t *testing.T) {
	want := map[string]bool{
		colDeviceID:                  true,
		colDeviceName:                true,
		colDeviceState:               true,
		colMalwareProtectionEnabled:  true,
		colNetworkInspectionSystemOn: true,
		colProductStatus:             true,
		colRealTimeProtectionEnabled: true,
		colSignatureUpdateOverdue:    true,
		colTamperProtectionEnabled:   true,
		colUPN:                       true,
	}
	if len(selectColumns) != len(want) {
		t.Fatalf("selectColumns = %v, want %d columns", selectColumns, len(want))
	}
	for _, c := range selectColumns {
		if !want[c] {
			t.Errorf("unexpected column %q in selectColumns", c)
		}
	}
}

func TestCollectEmitsBoundedSignalGaugesAndUnhealthyLogsOnly(t *testing.T) {
	runner := &fakeRunner{rows: []exportjob.Row{
		// Fully healthy: no signal should trip, no log emitted.
		row("dev-1", "LAPTOP-1", "alice@contoso.com", "clean", "noStatus", true, true, false, true, true),
		// RTP off + signature overdue.
		row("dev-2", "LAPTOP-2", "bob@contoso.com", "clean", "avSignaturesOutOfDate", false, true, true, true, true),
		// Tamper protection off.
		row("dev-3", "LAPTOP-3", "carol@contoso.com", "clean", "noStatus", true, true, false, false, true),
		// Malware protection off.
		row("dev-4", "LAPTOP-4", "dave@contoso.com", "critical", "serviceStartedWithoutMalwareProtection", true, true, false, true, false),
		// Network inspection off.
		row("dev-5", "LAPTOP-5", "erin@contoso.com", "clean", "noStatus", true, false, false, true, true),
	}}
	c := New(runner, nil)
	rec := telemetrytest.New()

	if err := c.Collect(context.Background(), rec.Emitter()); err != nil {
		t.Fatalf("Collect returned error: %v", err)
	}

	if !runner.callSeen {
		t.Fatal("expected Export to be called")
	}
	if runner.lastReq.ReportName != reportName {
		t.Errorf("ReportName = %q, want %q", runner.lastReq.ReportName, reportName)
	}
	if len(runner.lastReq.Select) == 0 {
		t.Error("Select must be non-empty")
	}

	points := rec.MetricPoints(signalCountMetricName)
	want := map[string]float64{
		signalRealTimeProtectionOff:  1, // dev-2
		signalSignatureUpdateOverdue: 1, // dev-2
		signalTamperProtectionOff:    1, // dev-3
		signalMalwareProtectionOff:   1, // dev-4
		signalNetworkInspectionOff:   1, // dev-5
	}
	if len(points) != len(want) {
		t.Fatalf("got %d gauge points, want %d: %+v", len(points), len(want), points)
	}
	for _, p := range points {
		wv, ok := want[p.Attrs["signal"]]
		if !ok {
			t.Errorf("unexpected point %+v", p)
			continue
		}
		if p.Value != wv {
			t.Errorf("signal %q: value = %v, want %v", p.Attrs["signal"], p.Value, wv)
		}
	}

	logs := rec.LogRecords()
	if len(logs) != 4 {
		t.Fatalf("got %d log records, want 4 (healthy dev-1 must not log)", len(logs))
	}
	seenDevices := map[string]bool{}
	for _, l := range logs {
		if l.EventName != "intune.defender_agent" {
			t.Errorf("log EventName = %q, want intune.defender_agent", l.EventName)
		}
		if l.Attrs["device_id"] == "" {
			t.Error("expected device_id attr on every log record")
		}
		if l.Attrs["device_id"] == "dev-1" {
			t.Error("healthy device dev-1 must not produce a log record")
		}
		if l.Attrs["product_status"] == "" {
			t.Error("expected product_status attr on every log record")
		}
		seenDevices[l.Attrs["device_id"]] = true
	}
	for _, want := range []string{"dev-2", "dev-3", "dev-4", "dev-5"} {
		if !seenDevices[want] {
			t.Errorf("expected a log record for unhealthy device %s", want)
		}
	}

	// product_status is a top-line breakdown over ALL rows, not just the
	// unhealthy ones the signal gauge and logs cover.
	psPoints := rec.MetricPoints(productStatusMetricName)
	psWant := map[string]float64{
		"no_status":                 3, // dev-1, dev-3, dev-5
		"av_signatures_out_of_date": 1, // dev-2
		"service_started_without_malware_protection": 1, // dev-4
	}
	if len(psPoints) != len(psWant) {
		t.Fatalf("got %d product_status points, want %d: %+v", len(psPoints), len(psWant), psPoints)
	}
	for _, p := range psPoints {
		wv, ok := psWant[p.Attrs["status"]]
		if !ok {
			t.Errorf("unexpected product_status point %+v", p)
			continue
		}
		if p.Value != wv {
			t.Errorf("status %q: value = %v, want %v", p.Attrs["status"], p.Value, wv)
		}
	}
}

func TestCollectSkipsAndLogsOnExportError(t *testing.T) {
	for _, tc := range []struct {
		name string
		err  error
	}{
		{"job failed", fmt.Errorf("exportjob: %s: %w", reportName, exportjob.ErrJobFailed)},
		{"sas expired", fmt.Errorf("exportjob: %s: %w", reportName, exportjob.ErrSASExpired)},
		{"forbidden", errors.New("exportjob: DefenderAgents: create: graphclient: POST https://graph.microsoft.com/v1.0/deviceManagement/reports/exportJobs: status 403: forbidden")},
		{"other", errors.New("exportjob: DefenderAgents: create: boom")},
	} {
		t.Run(tc.name, func(t *testing.T) {
			runner := &fakeRunner{err: tc.err}
			c := New(runner, nil)
			rec := telemetrytest.New()

			if err := c.Collect(context.Background(), rec.Emitter()); err != nil {
				t.Fatalf("Collect returned error, want nil (skip-and-log): %v", err)
			}
			if points := rec.MetricPoints(signalCountMetricName); len(points) != 0 {
				t.Errorf("expected no gauge points on export failure, got %+v", points)
			}
			if logs := rec.LogRecords(); len(logs) != 0 {
				t.Errorf("expected no log records on export failure, got %+v", logs)
			}
		})
	}
}

func TestCollectSkipsWhenExportRunnerIsNil(t *testing.T) {
	c := New(nil, nil)
	rec := telemetrytest.New()

	if err := c.Collect(context.Background(), rec.Emitter()); err != nil {
		t.Fatalf("Collect returned error, want nil: %v", err)
	}
	if points := rec.MetricPoints(signalCountMetricName); len(points) != 0 {
		t.Errorf("expected no gauge points, got %+v", points)
	}
}

func TestProductStatusBucketForCollapsesUnknownValues(t *testing.T) {
	cases := map[string]string{
		"noStatus":              "no_status",
		"AVSignaturesOutOfDate": "av_signatures_out_of_date",
		"productExpired":        "product_expired",
		"someFutureBetaStatus":  "other",
		"":                      "other",
	}
	for raw, want := range cases {
		if got := productStatusBucketFor(raw); got != want {
			t.Errorf("productStatusBucketFor(%q) = %q, want %q", raw, got, want)
		}
	}
}

func TestExperimentalAndPermissions(t *testing.T) {
	c := New(nil, nil)
	if !c.Experimental() {
		t.Error("expected Experimental() = true")
	}
	perms := c.RequiredPermissions()
	if len(perms) != 1 || perms[0] != "DeviceManagementManagedDevices.ReadWrite.All" {
		t.Errorf("RequiredPermissions = %v, want [DeviceManagementManagedDevices.ReadWrite.All]", perms)
	}
	if c.Name() != collectorName {
		t.Errorf("Name() = %q, want %q", c.Name(), collectorName)
	}
	if c.DefaultInterval().Hours() != 6 {
		t.Errorf("DefaultInterval() = %v, want 6h", c.DefaultInterval())
	}
}
