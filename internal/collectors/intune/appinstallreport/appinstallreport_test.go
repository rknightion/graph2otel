package appinstallreport

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
// consumers use to avoid any live Graph/export-job dependency in unit tests.
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

// row builds one AppInstallStatusAggregate row: one row per app, with the
// five install-state device counts as they come back from the export
// (always strings - Row is map[string]string).
func row(displayName, applicationID, platform string, installed, failed, notApplicable, notInstalled, pending int) exportjob.Row {
	return exportjob.Row{
		"DisplayName":               displayName,
		"ApplicationId":             applicationID,
		"Platform":                  platform,
		"Publisher":                 "Contoso",
		"InstalledDeviceCount":      fmt.Sprint(installed),
		"FailedDeviceCount":         fmt.Sprint(failed),
		"NotApplicableDeviceCount":  fmt.Sprint(notApplicable),
		"NotInstalledDeviceCount":   fmt.Sprint(notInstalled),
		"PendingInstallDeviceCount": fmt.Sprint(pending),
	}
}

func TestCollectEmitsBoundedGaugeFromAggregateCounts(t *testing.T) {
	runner := &fakeRunner{rows: []exportjob.Row{
		row("Contoso Agent", "app-1", "windows", 10, 2, 1, 3, 0),
		row("Widget Tool", "app-2", "ios", 5, 0, 0, 0, 4),
	}}
	c := New(runner, nil)
	rec := telemetrytest.New()

	if err := c.Collect(context.Background(), rec.Emitter()); err != nil {
		t.Fatalf("Collect returned error: %v", err)
	}

	if !runner.callSeen {
		t.Fatal("expected Export to be called")
	}
	if runner.lastReq.ReportName != "AppInstallStatusAggregate" {
		t.Errorf("ReportName = %q, want AppInstallStatusAggregate (must not require an ApplicationId filter)", runner.lastReq.ReportName)
	}
	if len(runner.lastReq.Select) == 0 {
		t.Error("Select must be non-empty")
	}

	points := rec.MetricPoints(deviceInstallStatusMetricName)
	type key struct{ app, state, platform string }
	want := map[key]float64{
		{"Contoso Agent", "installed", "windows"}:      10,
		{"Contoso Agent", "failed", "windows"}:         2,
		{"Contoso Agent", "not_applicable", "windows"}: 1,
		{"Contoso Agent", "not_installed", "windows"}:  3,
		{"Contoso Agent", "pending", "windows"}:        0,
		{"Widget Tool", "installed", "ios"}:            5,
		{"Widget Tool", "failed", "ios"}:               0,
		{"Widget Tool", "not_applicable", "ios"}:       0,
		{"Widget Tool", "not_installed", "ios"}:        0,
		{"Widget Tool", "pending", "ios"}:              4,
	}
	if len(points) != len(want) {
		t.Fatalf("got %d gauge points, want %d: %+v", len(points), len(want), points)
	}
	for _, p := range points {
		k := key{p.Attrs["app_name"], p.Attrs["install_state"], p.Attrs["platform"]}
		wv, ok := want[k]
		if !ok {
			t.Errorf("unexpected point %+v", p)
			continue
		}
		if p.Value != wv {
			t.Errorf("point %+v: value = %v, want %v", k, p.Value, wv)
		}
	}

	// No per-device logs from the aggregate report (deferred - see package doc).
	if logs := rec.LogRecords(); len(logs) != 0 {
		t.Errorf("expected no log records from the aggregate report, got %+v", logs)
	}
}

func TestCollectTreatsUnparsableCountAsZero(t *testing.T) {
	r := row("Contoso Agent", "app-1", "windows", 10, 2, 1, 3, 0)
	r["FailedDeviceCount"] = "not-a-number"
	runner := &fakeRunner{rows: []exportjob.Row{r}}
	c := New(runner, nil)
	rec := telemetrytest.New()

	if err := c.Collect(context.Background(), rec.Emitter()); err != nil {
		t.Fatalf("Collect returned error: %v", err)
	}

	for _, p := range rec.MetricPoints(deviceInstallStatusMetricName) {
		if p.Attrs["install_state"] == "failed" && p.Value != 0 {
			t.Errorf("expected unparsable FailedDeviceCount to bucket to 0, got %v", p.Value)
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
		{"forbidden", errors.New("exportjob: AppInstallStatusAggregate: create: graphclient: POST https://graph.microsoft.com/v1.0/deviceManagement/reports/exportJobs: status 403: forbidden")},
		{"other", errors.New("exportjob: AppInstallStatusAggregate: create: boom")},
	} {
		t.Run(tc.name, func(t *testing.T) {
			runner := &fakeRunner{err: tc.err}
			c := New(runner, nil)
			rec := telemetrytest.New()

			if err := c.Collect(context.Background(), rec.Emitter()); err != nil {
				t.Fatalf("Collect returned error, want nil (skip-and-log): %v", err)
			}
			if points := rec.MetricPoints(deviceInstallStatusMetricName); len(points) != 0 {
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
	if points := rec.MetricPoints(deviceInstallStatusMetricName); len(points) != 0 {
		t.Errorf("expected no gauge points, got %+v", points)
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
}
