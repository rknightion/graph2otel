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

// TestCollectAggregatesCountsAcrossAppsIntoBoundedDimensions pins the post-#83
// metric shape: the per-app device counts are summed across every app into a
// series set keyed ONLY by install_state x platform, so the series count is
// fixed by Microsoft's report schema rather than growing with the tenant's app
// catalog. The three-row fixture deliberately puts two apps on "windows" so a
// collector that failed to aggregate (one point per app) would not match.
func TestCollectAggregatesCountsAcrossAppsIntoBoundedDimensions(t *testing.T) {
	runner := &fakeRunner{rows: []exportjob.Row{
		row("Contoso Agent", "app-1", "windows", 10, 2, 1, 3, 0),
		row("Widget Tool", "app-2", "ios", 5, 0, 0, 0, 4),
		row("Fabrikam Helper", "app-3", "windows", 1, 1, 0, 0, 0),
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

	points := rec.MetricPoints(installationsMetricName)
	type key struct{ state, platform string }
	want := map[key]float64{
		{"installed", "windows"}:      11, // 10 + 1, summed across two windows apps
		{"failed", "windows"}:         3,  // 2 + 1
		{"not_applicable", "windows"}: 1,
		{"not_installed", "windows"}:  3,
		{"pending", "windows"}:        0,
		{"installed", "ios"}:          5,
		{"failed", "ios"}:             0,
		{"not_applicable", "ios"}:     0,
		{"not_installed", "ios"}:      0,
		{"pending", "ios"}:            4,
	}
	if len(points) != len(want) {
		t.Fatalf("got %d gauge points, want %d: %+v", len(points), len(want), points)
	}
	for _, p := range points {
		k := key{p.Attrs["install_state"], p.Attrs["platform"]}
		wv, ok := want[k]
		if !ok {
			t.Errorf("unexpected point %+v", p)
			continue
		}
		if p.Value != wv {
			t.Errorf("point %+v: value = %v, want %v", k, p.Value, wv)
		}
	}
}

// TestMetricNameAndUnitPinned pins the wire contract as literals rather than
// via the const, which every other test here references — a rename of the const
// alone would otherwise sail through green while silently renaming the series
// operators build on.
//
// The name and unit say "installations", not "devices", deliberately: the gauge
// sums per-app device counts across the whole catalog, so a device running ten
// apps contributes ten times. It cannot report distinct devices — the
// AppInstallStatusAggregate report has no device rows to deduplicate.
func TestMetricNameAndUnitPinned(t *testing.T) {
	c := New(&fakeRunner{rows: []exportjob.Row{row("Contoso Agent", "app-1", "windows", 1, 0, 0, 0, 0)}}, nil)
	rec := telemetrytest.New()

	if err := c.Collect(context.Background(), rec.Emitter()); err != nil {
		t.Fatalf("Collect returned error: %v", err)
	}

	points := rec.MetricPoints("intune.app_install_status.installations")
	if len(points) == 0 {
		t.Fatalf("no points for intune.app_install_status.installations; emitted metrics: %v", rec.MetricNames())
	}
	if got := points[0].Unit; got != "{installation}" {
		t.Errorf("Unit = %q, want %q - the value counts installations, not distinct devices", got, "{installation}")
	}
}

// TestMetricCarriesOnlyBoundedDimensions is the #83 regression guard: it fails
// if app_name (or any other per-app attribute) is ever reintroduced as a metric
// label. Asserted as an exact key set rather than a denylist of known-bad keys,
// so ANY new unbounded dimension trips it, not just the one #83 found.
//
// The fixture is 40 distinct apps on ONE platform: under the pre-#83 shape that
// is 200 series, under the fixed shape it is 5 regardless of catalog size. On
// the live m7kni tenant the same bug produced 1,870 series from 341 apps on a
// 6-device fleet (#83).
func TestMetricCarriesOnlyBoundedDimensions(t *testing.T) {
	rows := make([]exportjob.Row, 0, 40)
	for i := range 40 {
		rows = append(rows, row(fmt.Sprintf("Store App %d", i), fmt.Sprintf("app-%d", i), "windows", i, 0, 0, 0, 0))
	}
	c := New(&fakeRunner{rows: rows}, nil)
	rec := telemetrytest.New()

	if err := c.Collect(context.Background(), rec.Emitter()); err != nil {
		t.Fatalf("Collect returned error: %v", err)
	}

	points := rec.MetricPoints(installationsMetricName)
	if len(points) != len(installStateColumns) {
		t.Fatalf("got %d series from a 40-app catalog on one platform, want %d (install_state only) - a per-app dimension has been reintroduced: %+v",
			len(points), len(installStateColumns), points)
	}
	for _, p := range points {
		if len(p.Attrs) != 2 {
			t.Errorf("point has %d attributes, want exactly 2 (install_state, platform): %+v", len(p.Attrs), p.Attrs)
		}
		for k := range p.Attrs {
			if k != "install_state" && k != "platform" {
				t.Errorf("metric point carries unbounded attribute %q = %q; per-app detail belongs on the %s log twin, never a metric label (#83, #112)",
					k, p.Attrs[k], eventName)
			}
		}
	}
}

// TestCollectEmitsOneLogTwinPerAppRow pins the other half of #83's fix: the
// per-app detail dropped from the metric MUST reach the logs pipeline, never
// the floor (#112's hard rule). One log per app row, carrying the app identity
// and every per-state device count.
func TestCollectEmitsOneLogTwinPerAppRow(t *testing.T) {
	runner := &fakeRunner{rows: []exportjob.Row{
		row("Contoso Agent", "app-1", "windows", 10, 2, 1, 3, 0),
		row("Widget Tool", "app-2", "ios", 5, 0, 0, 0, 4),
		row("Fabrikam Helper", "app-3", "windows", 1, 1, 0, 0, 0),
	}}
	c := New(runner, nil)
	rec := telemetrytest.New()

	if err := c.Collect(context.Background(), rec.Emitter()); err != nil {
		t.Fatalf("Collect returned error: %v", err)
	}

	logs := rec.LogRecords()
	if len(logs) != 3 {
		t.Fatalf("got %d log records, want one per app row (3): %+v", len(logs), logs)
	}

	byApp := map[string]telemetrytest.LogRecord{}
	for _, l := range logs {
		if l.EventName != eventName {
			t.Errorf("EventName = %q, want %q", l.EventName, eventName)
		}
		byApp[l.Attrs["app_name"]] = l
	}

	got, ok := byApp["Contoso Agent"]
	if !ok {
		t.Fatalf("no log twin for %q; got %v", "Contoso Agent", byApp)
	}
	want := map[string]string{
		"app_name":                     "Contoso Agent",
		"app_id":                       "app-1",
		"platform":                     "windows",
		"publisher":                    "Contoso",
		"installed_device_count":       "10",
		"failed_device_count":          "2",
		"not_applicable_device_count":  "1",
		"not_installed_device_count":   "3",
		"pending_install_device_count": "0",
	}
	for k, wv := range want {
		if got.Attrs[k] != wv {
			t.Errorf("log twin attr %q = %q, want %q", k, got.Attrs[k], wv)
		}
	}

	// A row with failed installs is worth an operator's attention; a clean row
	// is not. Mirrors the sibling export collectors' severity escalation.
	if got.SeverityText != "WARN" {
		t.Errorf("app with FailedDeviceCount=2: SeverityText = %q, want WARN", got.SeverityText)
	}
	if clean := byApp["Widget Tool"]; clean.SeverityText != "INFO" {
		t.Errorf("app with FailedDeviceCount=0: SeverityText = %q, want INFO", clean.SeverityText)
	}
}

// TestLogTwinOmitsAbsentColumns pins the frozen seam's setStr rule (#114): an
// absent export column emits no attribute at all, never an empty string.
func TestLogTwinOmitsAbsentColumns(t *testing.T) {
	r := row("Contoso Agent", "app-1", "windows", 1, 0, 0, 0, 0)
	delete(r, "Publisher")
	delete(r, "ApplicationId")
	c := New(&fakeRunner{rows: []exportjob.Row{r}}, nil)
	rec := telemetrytest.New()

	if err := c.Collect(context.Background(), rec.Emitter()); err != nil {
		t.Fatalf("Collect returned error: %v", err)
	}

	logs := rec.LogRecords()
	if len(logs) != 1 {
		t.Fatalf("got %d log records, want 1: %+v", len(logs), logs)
	}
	for _, k := range []string{"publisher", "app_id"} {
		if v, ok := logs[0].Attrs[k]; ok {
			t.Errorf("absent column emitted attr %q = %q, want the attribute omitted entirely", k, v)
		}
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

	for _, p := range rec.MetricPoints(installationsMetricName) {
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
			if points := rec.MetricPoints(installationsMetricName); len(points) != 0 {
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
	if points := rec.MetricPoints(installationsMetricName); len(points) != 0 {
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
