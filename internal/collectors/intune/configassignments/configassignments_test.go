package configassignments

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

// fakeRunner is a canned exportjob.Runner: it returns a fixed set of rows or a
// fixed error, ignoring the request (tests assert the request separately where
// that matters). Mirrors the fake-Runner pattern the other export consumers use
// to keep unit tests off any live Graph/export-job dependency.
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

// row builds one DeviceAssignmentStatusByConfigurationPolicy export row exactly
// as the live export returns it (LIVE-CAPTURED 2026-07-19, m7kni, as the
// poller). The column names and the AssignmentStatus/ReportStatus/platform
// values are real wire values; no test here asserts a value the API has never
// sent.
//
// Per the live sample, UnifiedPolicyPlatformType and its _loc sibling are equal,
// ReportStatus and its _loc sibling are equal, and UnifiedPolicyType_loc differs
// from the raw UnifiedPolicyType ("GroupPolicyConfiguration" -> "Endpoint
// Security").
func row(policyID, policyName, deviceID, deviceName, upn, assignmentStatus, platform, policyTypeLoc, reportStatus string) exportjob.Row {
	return exportjob.Row{
		"PolicyId":                      policyID,
		"PolicyName":                    policyName,
		"IntuneDeviceId":                deviceID,
		"DeviceName":                    deviceName,
		"AadDeviceId":                   "aad-" + deviceID,
		"UPN":                           upn,
		"AssignmentStatus":              assignmentStatus,
		"PspdpuLastModifiedTimeUtc":     "2026-06-19 20:29:04.0000000",
		"UnifiedPolicyPlatformType":     platform,
		"UnifiedPolicyPlatformType_loc": platform,
		"UnifiedPolicyType":             "GroupPolicyConfiguration",
		"UnifiedPolicyType_loc":         policyTypeLoc,
		"ReportStatus":                  reportStatus,
		"ReportStatus_loc":              reportStatus,
	}
}

// liveFixture is a multi-row export spanning several ReportStatus x platform
// combinations, drawn from the live distinct-value tallies (2026-07-19): the
// AssignmentStatus code -> ReportStatus pairings (0->Pending, 1->NotApplicable,
// 2->Succeeded, 4->Noncompliant, 5->Error, 6->Conflict) and the platform values
// seen (Windows10, MacOS, iOS, "Administrative Template"). Two rows share
// (Succeeded, Windows10) so a collector that failed to aggregate would not match.
func liveFixture() []exportjob.Row {
	return []exportjob.Row{
		row("pol-1", "Winget-AutoUpdate-aaS", "dev-1", "DESKTOP-CB3D9AB", "rob@m7kni.io", "2", "Windows10", "Endpoint Security", "Succeeded"),
		row("pol-1", "Winget-AutoUpdate-aaS", "dev-2", "DESKTOP-2", "amy@m7kni.io", "2", "Windows10", "Endpoint Security", "Succeeded"),
		row("pol-2", "Disk Encryption", "dev-3", "MAC-1", "joe@m7kni.io", "5", "MacOS", "Endpoint Security", "Error"),
		row("pol-3", "Wifi Profile", "dev-4", "IPHONE-1", "kim@m7kni.io", "6", "iOS", "Device Configuration", "Conflict"),
		row("pol-1", "Winget-AutoUpdate-aaS", "dev-5", "DESKTOP-5", "sam@m7kni.io", "4", "Windows10", "Endpoint Security", "Noncompliant"),
		row("pol-4", "Admin Template", "dev-6", "DESKTOP-6", "lee@m7kni.io", "0", "Administrative Template", "Administrative Templates", "Pending"),
		row("pol-2", "Disk Encryption", "dev-7", "MAC-2", "ben@m7kni.io", "1", "MacOS", "Endpoint Security", "NotApplicable"),
	}
}

// TestCollectBucketsRowsByReportStatusAndPlatform pins the metric shape: one
// gauge point per (report_status, policy_platform) carrying the COUNT of rows in
// that bucket, taken verbatim from the row's non-localized ReportStatus and
// UnifiedPolicyPlatformType columns.
func TestCollectBucketsRowsByReportStatusAndPlatform(t *testing.T) {
	runner := &fakeRunner{rows: liveFixture()}
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

	points := rec.MetricPoints(metricName)
	type key struct{ status, platform string }
	want := map[key]float64{
		{"Succeeded", "Windows10"}:             2,
		{"Error", "MacOS"}:                     1,
		{"Conflict", "iOS"}:                    1,
		{"Noncompliant", "Windows10"}:          1,
		{"Pending", "Administrative Template"}: 1,
		{"NotApplicable", "MacOS"}:             1,
	}
	if len(points) != len(want) {
		t.Fatalf("got %d gauge points, want %d: %+v", len(points), len(want), points)
	}
	for _, p := range points {
		k := key{p.Attrs[semconv.AttrReportStatus], p.Attrs[semconv.AttrPolicyPlatform]}
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

// TestMetricNameAndUnitPinned pins the wire contract as literals rather than via
// the const — a rename of the const alone would otherwise sail through green
// while silently renaming the series operators build on.
func TestMetricNameAndUnitPinned(t *testing.T) {
	c := New(&fakeRunner{rows: liveFixture()}, nil)
	rec := telemetrytest.New()

	if err := c.Collect(context.Background(), rec.Emitter()); err != nil {
		t.Fatalf("Collect returned error: %v", err)
	}

	points := rec.MetricPoints("intune.config_assignment_status.assignments")
	if len(points) == 0 {
		t.Fatalf("no points for intune.config_assignment_status.assignments; emitted: %v", rec.MetricNames())
	}
	if got := points[0].Unit; got != "{assignment}" {
		t.Errorf("Unit = %q, want %q", got, "{assignment}")
	}
}

// TestMetricUsesVerbatimNonLocalizedColumns pins that the gauge dimensions come
// from the canonical non-localized enum columns (ReportStatus,
// UnifiedPolicyPlatformType), NOT their locale-dependent _loc siblings. A label
// fed from _loc would split one bucket into two series as a function of a
// request header. The fixture feeds _loc values that differ from the canonical
// ones; the metric must be unmoved by them.
func TestMetricUsesVerbatimNonLocalizedColumns(t *testing.T) {
	r := row("pol-1", "P", "dev-1", "D", "u@x", "2", "Windows10", "Endpoint Security", "Succeeded")
	r["ReportStatus_loc"] = "Erfolgreich"          // a localized casing the en-US wire never sends
	r["UnifiedPolicyPlatformType_loc"] = "Fenster" // ditto
	c := New(&fakeRunner{rows: []exportjob.Row{r}}, nil)
	rec := telemetrytest.New()

	if err := c.Collect(context.Background(), rec.Emitter()); err != nil {
		t.Fatalf("Collect returned error: %v", err)
	}

	points := rec.MetricPoints(metricName)
	if len(points) != 1 {
		t.Fatalf("got %d points, want 1: %+v", len(points), points)
	}
	if got := points[0].Attrs[semconv.AttrReportStatus]; got != "Succeeded" {
		t.Errorf("report_status = %q, want %q (must be the non-localized ReportStatus, never _loc)", got, "Succeeded")
	}
	if got := points[0].Attrs[semconv.AttrPolicyPlatform]; got != "Windows10" {
		t.Errorf("policy_platform = %q, want %q (must be the non-localized UnifiedPolicyPlatformType, never _loc)", got, "Windows10")
	}
}

// TestMetricCarriesOnlyBoundedDimensions is the cardinality guard (mirrors
// appinstallreport's #83 guard): it fails if any per-entity attribute
// (device/policy/UPN) is ever reintroduced as a metric label. The fixture is 30
// distinct devices/policies/UPNs on ONE (report_status, platform) bucket — under
// a leaky shape that is 30 series, under the correct shape it is 1.
func TestMetricCarriesOnlyBoundedDimensions(t *testing.T) {
	rows := make([]exportjob.Row, 0, 30)
	for i := range 30 {
		rows = append(rows, row(
			fmt.Sprintf("pol-%d", i), fmt.Sprintf("Policy %d", i),
			fmt.Sprintf("dev-%d", i), fmt.Sprintf("DESKTOP-%d", i),
			fmt.Sprintf("user%d@m7kni.io", i),
			"2", "Windows10", "Endpoint Security", "Succeeded"))
	}
	c := New(&fakeRunner{rows: rows}, nil)
	rec := telemetrytest.New()

	if err := c.Collect(context.Background(), rec.Emitter()); err != nil {
		t.Fatalf("Collect returned error: %v", err)
	}

	points := rec.MetricPoints(metricName)
	if len(points) != 1 {
		t.Fatalf("got %d series from 30 distinct devices/policies on one bucket, want 1 — a per-entity dimension has been reintroduced: %+v", len(points), points)
	}
	if points[0].Value != 30 {
		t.Errorf("bucket count = %v, want 30", points[0].Value)
	}
	for _, p := range points {
		if len(p.Attrs) != 2 {
			t.Errorf("point has %d attributes, want exactly 2 (report_status, policy_platform): %+v", len(p.Attrs), p.Attrs)
		}
		for k := range p.Attrs {
			if k != semconv.AttrReportStatus && k != semconv.AttrPolicyPlatform {
				t.Errorf("metric point carries unbounded attribute %q = %q; per-entity detail belongs on the %s log twin, never a metric label (#83, #112)", k, p.Attrs[k], eventName)
			}
		}
	}
}

// TestCollectEmitsOneLogTwinPerRow pins the log half: one record per export row,
// carrying the per-entity identity dropped from the metric, with the exact attr
// mapping and body.
func TestCollectEmitsOneLogTwinPerRow(t *testing.T) {
	runner := &fakeRunner{rows: liveFixture()}
	c := New(runner, nil)
	rec := telemetrytest.New()

	if err := c.Collect(context.Background(), rec.Emitter()); err != nil {
		t.Fatalf("Collect returned error: %v", err)
	}

	logs := rec.LogRecords()
	if len(logs) != len(liveFixture()) {
		t.Fatalf("got %d log records, want one per row (%d): %+v", len(logs), len(liveFixture()), logs)
	}

	byDevice := map[string]telemetrytest.LogRecord{}
	for _, l := range logs {
		if l.EventName != eventName {
			t.Errorf("EventName = %q, want %q", l.EventName, eventName)
		}
		if l.Body != "Intune config policy assignment status" {
			t.Errorf("Body = %q, want %q", l.Body, "Intune config policy assignment status")
		}
		byDevice[l.Attrs[semconv.AttrDeviceName]] = l
	}

	got, ok := byDevice["DESKTOP-CB3D9AB"]
	if !ok {
		t.Fatalf("no log twin for DESKTOP-CB3D9AB; got %v", byDevice)
	}
	want := map[string]string{
		semconv.AttrDeviceName:           "DESKTOP-CB3D9AB",
		semconv.AttrDeviceId:             "dev-1",
		semconv.AttrUpn:                  "rob@m7kni.io",
		semconv.AttrPolicyName:           "Winget-AutoUpdate-aaS",
		semconv.AttrPolicyId:             "pol-1",
		semconv.AttrReportStatus:         "Succeeded",
		semconv.AttrAssignmentStatusCode: "2",
		semconv.AttrPolicyType:           "Endpoint Security", // UnifiedPolicyType_loc
		semconv.AttrPolicyPlatform:       "Windows10",
	}
	for k, wv := range want {
		if got.Attrs[k] != wv {
			t.Errorf("log twin attr %q = %q, want %q", k, got.Attrs[k], wv)
		}
	}
}

// TestLogTwinSeverity pins WARN on Error/Conflict/Noncompliant ReportStatus and
// INFO on everything else.
func TestLogTwinSeverity(t *testing.T) {
	runner := &fakeRunner{rows: liveFixture()}
	c := New(runner, nil)
	rec := telemetrytest.New()

	if err := c.Collect(context.Background(), rec.Emitter()); err != nil {
		t.Fatalf("Collect returned error: %v", err)
	}

	byDevice := map[string]telemetrytest.LogRecord{}
	for _, l := range rec.LogRecords() {
		byDevice[l.Attrs[semconv.AttrDeviceName]] = l
	}

	wantSeverity := map[string]string{
		"DESKTOP-CB3D9AB": "INFO", // Succeeded
		"MAC-1":           "WARN", // Error
		"IPHONE-1":        "WARN", // Conflict
		"DESKTOP-5":       "WARN", // Noncompliant
		"DESKTOP-6":       "INFO", // Pending
		"MAC-2":           "INFO", // NotApplicable
	}
	for device, wantSev := range wantSeverity {
		l, ok := byDevice[device]
		if !ok {
			t.Fatalf("no log twin for %q", device)
		}
		if l.SeverityText != wantSev {
			t.Errorf("device %q (report_status %q): SeverityText = %q, want %q", device, l.Attrs[semconv.AttrReportStatus], l.SeverityText, wantSev)
		}
	}
}

// TestSelectColumnsPinned pins the exact export column set — the report's
// default column set can change without notice, so the collector must request
// its columns explicitly.
func TestSelectColumnsPinned(t *testing.T) {
	runner := &fakeRunner{rows: liveFixture()}
	c := New(runner, nil)
	rec := telemetrytest.New()

	if err := c.Collect(context.Background(), rec.Emitter()); err != nil {
		t.Fatalf("Collect returned error: %v", err)
	}

	want := []string{
		"PolicyId", "PolicyName", "IntuneDeviceId", "DeviceName", "AadDeviceId",
		"UPN", "AssignmentStatus", "PspdpuLastModifiedTimeUtc",
		"UnifiedPolicyPlatformType", "UnifiedPolicyPlatformType_loc",
		"UnifiedPolicyType", "UnifiedPolicyType_loc", "ReportStatus", "ReportStatus_loc",
	}
	got := runner.lastReq.Select
	if len(got) != len(want) {
		t.Fatalf("Select = %v (len %d), want %v (len %d)", got, len(got), want, len(want))
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("Select[%d] = %q, want %q", i, got[i], want[i])
		}
	}
}

func TestCollectSkipsWhenExportRunnerIsNil(t *testing.T) {
	c := New(nil, nil)
	rec := telemetrytest.New()

	if err := c.Collect(context.Background(), rec.Emitter()); err != nil {
		t.Fatalf("Collect returned error, want nil: %v", err)
	}
	if points := rec.MetricPoints(metricName); len(points) != 0 {
		t.Errorf("expected no gauge points, got %+v", points)
	}
	if logs := rec.LogRecords(); len(logs) != 0 {
		t.Errorf("expected no log records, got %+v", logs)
	}
}

func TestCollectSkipsAndLogsOnExportError(t *testing.T) {
	for _, tc := range []struct {
		name string
		err  error
	}{
		{"job failed", fmt.Errorf("exportjob: %s: %w", reportName, exportjob.ErrJobFailed)},
		{"sas expired", fmt.Errorf("exportjob: %s: %w", reportName, exportjob.ErrSASExpired)},
		{"forbidden", errors.New("exportjob: create: status 403: forbidden")},
		{"other", errors.New("exportjob: create: boom")},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := New(&fakeRunner{err: tc.err}, nil)
			rec := telemetrytest.New()

			if err := c.Collect(context.Background(), rec.Emitter()); err != nil {
				t.Fatalf("Collect returned error, want nil (skip-and-log): %v", err)
			}
			if points := rec.MetricPoints(metricName); len(points) != 0 {
				t.Errorf("expected no gauge points on export failure, got %+v", points)
			}
			if logs := rec.LogRecords(); len(logs) != 0 {
				t.Errorf("expected no log records on export failure, got %+v", logs)
			}
		})
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
	if got := c.DefaultInterval(); got.Hours() != 6 {
		t.Errorf("DefaultInterval = %v, want 6h", got)
	}
	if c.IngestTransport() != telemetry.TransportReportExport {
		t.Errorf("IngestTransport = %q, want %q", c.IngestTransport(), telemetry.TransportReportExport)
	}
}

// TestCollectStampsReportExportTransport pins that this collector names its own
// transport (#141): exportjob has no LogEvent seam, so the stamp is on the
// collector.
func TestCollectStampsReportExportTransport(t *testing.T) {
	c := New(&fakeRunner{rows: liveFixture()}, nil)
	rec := telemetrytest.New()

	if err := c.Collect(context.Background(), rec.Emitter()); err != nil {
		t.Fatalf("Collect: %v", err)
	}

	logs := rec.LogRecords()
	if len(logs) == 0 {
		t.Fatal("no log records emitted")
	}
	for i, l := range logs {
		if got := l.Attrs[semconv.AttrIngestTransport]; got != string(telemetry.TransportReportExport) {
			t.Errorf("log[%d] %s = %q, want %q", i, semconv.AttrIngestTransport, got, telemetry.TransportReportExport)
		}
	}
}
