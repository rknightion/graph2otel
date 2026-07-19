package noncompliantsettings

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
// that matters). Mirrors the fake-Runner pattern the other M5 export consumers
// use to avoid any live Graph/export-job dependency in unit tests.
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

// row builds one NoncompliantDevicesAndSettings row exactly as the live export
// returns it. SettingStatus is a NUMERIC CODE and Microsoft returns a localized
// SettingStatus_loc sibling alongside it. Pass codes here, never decoded names —
// the code is the only stable key (the #142 lesson).
func row(deviceID, deviceName, upn, os, osVersion, settingName, settingNm, settingNmLoc, policyName, settingStatus, settingStatusLoc, errorCode string) exportjob.Row {
	return exportjob.Row{
		"DeviceId":          deviceID,
		"DeviceName":        deviceName,
		"UPN":               upn,
		"OS":                os,
		"OSVersion":         osVersion,
		"SettingName":       settingName,
		"SettingNm":         settingNm,
		"SettingNm_loc":     settingNmLoc,
		"PolicyName":        policyName,
		"SettingStatus":     settingStatus,
		"SettingStatus_loc": settingStatusLoc,
		"ErrorCode":         errorCode,
	}
}

// liveRows are the three rows the live NoncompliantDevicesAndSettings export
// returned, probed as graph2otel-poller against m7kni on 2026-07-19. All three
// carry SettingStatus="4" / SettingStatus_loc="Not compliant" — the ONLY code
// this report has been observed to send, and the only seed in statusNames.
func liveRows() []exportjob.Row {
	return []exportjob.Row{
		row("c90d9cd8-a1c8-49fa-a2bb-a483e6e42862", "HAMRIG", "rob@m7kni.io", "Windows", "10.0.26300.8376",
			"DefaultDeviceCompliancePolicy.RequireRemainContact", "DefaultDeviceCompliancePolicyRequireRemainContact", "Is active",
			"Default Device Compliance Policy", "4", "Not compliant", "0"),
		row("d5900d67-e50c-44ef-9d5c-6a2f891099c6", "LAPHAM", "rob@m7kni.io", "Windows", "10.0.26120.3281",
			"Windows10CompliancePolicy.SecureBootEnabled", "Windows10CompliancePolicySecureBootEnabled", "Secure Boot",
			"WinCompliance", "4", "Not compliant", "0"),
		row("d5900d67-e50c-44ef-9d5c-6a2f891099c6", "LAPHAM", "rob@m7kni.io", "Windows", "10.0.26120.3281",
			"Windows10CompliancePolicy.BitLockerEnabled", "Windows10CompliancePolicySecureBootEnabled_BitLocker", "BitLocker",
			"WinCompliance", "4", "Not compliant", "0"),
	}
}

// unknownRow is a synthetic row carrying a SettingStatus code absent from
// statusNames, to exercise the unknown-bucket + one-time Warn path. The code is
// deliberately not guessed at — statusNames grows only on live evidence (#142).
func unknownRow() exportjob.Row {
	return row("aaaa1111-0000-0000-0000-000000000000", "FUTUREDEV", "rob@m7kni.io", "Windows", "10.0.99999.0",
		"Windows10CompliancePolicy.SomethingNew", "Windows10CompliancePolicySomethingNew", "Something new",
		"WinCompliance", "99", "Some future status", "1")
}

// TestCollectCountsRowsByOsAndStatus pins the metric shape: one gauge point per
// (os, setting_status) whose value is the COUNT of noncompliant device×setting
// rows in that bucket. The three live rows all bucket to (Windows,
// not_compliant); the synthetic unknown row buckets to (Windows, unknown).
func TestCollectCountsRowsByOsAndStatus(t *testing.T) {
	rows := append(liveRows(), unknownRow())
	runner := &fakeRunner{rows: rows}
	c := New(runner, nil)
	rec := telemetrytest.New()

	if err := c.Collect(context.Background(), rec.Emitter()); err != nil {
		t.Fatalf("Collect returned error: %v", err)
	}

	if !runner.callSeen {
		t.Fatal("expected Export to be called")
	}
	if runner.lastReq.ReportName != "NoncompliantDevicesAndSettings" {
		t.Errorf("ReportName = %q, want NoncompliantDevicesAndSettings", runner.lastReq.ReportName)
	}
	wantSelect := []string{"DeviceId", "DeviceName", "UPN", "OS", "OSVersion", "SettingName", "SettingNm", "SettingNm_loc", "PolicyName", "SettingStatus", "SettingStatus_loc", "ErrorCode"}
	if len(runner.lastReq.Select) != len(wantSelect) {
		t.Fatalf("Select = %v, want %v", runner.lastReq.Select, wantSelect)
	}
	for i, col := range wantSelect {
		if runner.lastReq.Select[i] != col {
			t.Errorf("Select[%d] = %q, want %q", i, runner.lastReq.Select[i], col)
		}
	}

	points := rec.MetricPoints(countMetricName)
	type key struct{ os, status string }
	want := map[key]float64{
		{"Windows", "not_compliant"}: 3,
		{"Windows", "unknown"}:       1,
	}
	if len(points) != len(want) {
		t.Fatalf("got %d gauge points, want %d: %+v", len(points), len(want), points)
	}
	for _, p := range points {
		k := key{p.Attrs[semconv.AttrOs], p.Attrs[semconv.AttrSettingStatus]}
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
// the const, so a rename of the const alone cannot sail through green while
// silently renaming the series operators build on.
func TestMetricNameAndUnitPinned(t *testing.T) {
	c := New(&fakeRunner{rows: liveRows()}, nil)
	rec := telemetrytest.New()

	if err := c.Collect(context.Background(), rec.Emitter()); err != nil {
		t.Fatalf("Collect returned error: %v", err)
	}

	points := rec.MetricPoints("intune.noncompliant_settings.count")
	if len(points) == 0 {
		t.Fatalf("no points for intune.noncompliant_settings.count; emitted metrics: %v", rec.MetricNames())
	}
	if got := points[0].Unit; got != "{setting}" {
		t.Errorf("Unit = %q, want %q", got, "{setting}")
	}
}

// TestMetricCarriesOnlyBoundedDimensions is the cardinality guard: DeviceName,
// SettingName, and UPN must NEVER become metric labels — only os × setting_status
// are gauge dims. Asserted as an exact key set so ANY new unbounded dimension
// trips it. The fixture is 40 distinct devices/settings on ONE os/status: under a
// per-entity shape that is 40 series, under the fixed shape it is exactly 1.
func TestMetricCarriesOnlyBoundedDimensions(t *testing.T) {
	rows := make([]exportjob.Row, 0, 40)
	for i := range 40 {
		rows = append(rows, row(
			fmt.Sprintf("dev-%d", i), fmt.Sprintf("DEVICE-%d", i), fmt.Sprintf("user%d@m7kni.io", i),
			"Windows", "10.0.26100.1", fmt.Sprintf("Policy.Setting%d", i), fmt.Sprintf("PolicySetting%d", i),
			fmt.Sprintf("Setting %d", i), "WinCompliance", "4", "Not compliant", "0"))
	}
	c := New(&fakeRunner{rows: rows}, nil)
	rec := telemetrytest.New()

	if err := c.Collect(context.Background(), rec.Emitter()); err != nil {
		t.Fatalf("Collect returned error: %v", err)
	}

	points := rec.MetricPoints(countMetricName)
	if len(points) != 1 {
		t.Fatalf("got %d series from 40 distinct devices/settings on one os/status, want 1 — a per-entity dimension has been reintroduced: %+v", len(points), points)
	}
	for _, p := range points {
		if len(p.Attrs) != 2 {
			t.Errorf("point has %d attributes, want exactly 2 (os, setting_status): %+v", len(p.Attrs), p.Attrs)
		}
		for k := range p.Attrs {
			if k != semconv.AttrOs && k != semconv.AttrSettingStatus {
				t.Errorf("metric point carries unbounded attribute %q = %q; per-entity detail belongs on the %s log twin, never a metric label (#112)", k, p.Attrs[k], eventName)
			}
		}
	}
}

// TestCollectEmitsOneLogTwinPerRow pins the log-twin half: one log per row
// carrying the per-entity detail dropped from the metric, including the decoded
// setting_status, the raw setting_status_code, and the localized display name.
func TestCollectEmitsOneLogTwinPerRow(t *testing.T) {
	runner := &fakeRunner{rows: liveRows()}
	c := New(runner, nil)
	rec := telemetrytest.New()

	if err := c.Collect(context.Background(), rec.Emitter()); err != nil {
		t.Fatalf("Collect returned error: %v", err)
	}

	logs := rec.LogRecords()
	if len(logs) != 3 {
		t.Fatalf("got %d log records, want one per row (3): %+v", len(logs), logs)
	}

	var hamrig telemetrytest.LogRecord
	found := false
	for _, l := range logs {
		if l.EventName != eventName {
			t.Errorf("EventName = %q, want %q", l.EventName, eventName)
		}
		// This report only ever returns noncompliant/error settings, so every
		// twin is a warning.
		if l.SeverityText != "WARN" {
			t.Errorf("SeverityText = %q, want WARN (every noncompliant setting is a warning)", l.SeverityText)
		}
		if l.Attrs[semconv.AttrDeviceName] == "HAMRIG" {
			hamrig = l
			found = true
		}
	}
	if !found {
		t.Fatalf("no log twin for HAMRIG; got %+v", logs)
	}

	want := map[string]string{
		semconv.AttrDeviceName:         "HAMRIG",
		semconv.AttrDeviceId:           "c90d9cd8-a1c8-49fa-a2bb-a483e6e42862",
		semconv.AttrUpn:                "rob@m7kni.io",
		semconv.AttrOs:                 "Windows",
		semconv.AttrOsVersion:          "10.0.26300.8376",
		semconv.AttrSettingName:        "DefaultDeviceCompliancePolicy.RequireRemainContact",
		semconv.AttrSettingDisplayName: "Is active",
		semconv.AttrPolicyName:         "Default Device Compliance Policy",
		semconv.AttrSettingStatus:      "not_compliant",
		semconv.AttrSettingStatusCode:  "4",
		semconv.AttrErrorCode:          "0",
	}
	for k, wv := range want {
		if hamrig.Attrs[k] != wv {
			t.Errorf("log twin attr %q = %q, want %q", k, hamrig.Attrs[k], wv)
		}
	}
	if hamrig.Body != "Intune noncompliant setting" {
		t.Errorf("log twin Body = %q, want %q", hamrig.Body, "Intune noncompliant setting")
	}
}

// TestUnknownStatusBucketsKeepsRawCodeAndWarns pins the decode-miss path: a code
// absent from statusNames must bucket to "unknown" on the metric, must keep the
// raw code + localized display on the twin, and must emit a Warn naming both — so
// a new status code is discoverable without a live probe (the #142 lesson). The
// map grows only on evidence.
func TestUnknownStatusBucketsKeepsRawCodeAndWarns(t *testing.T) {
	c := New(&fakeRunner{rows: []exportjob.Row{unknownRow()}}, nil)
	rec := telemetrytest.New()

	if err := c.Collect(context.Background(), rec.Emitter()); err != nil {
		t.Fatalf("Collect returned error: %v", err)
	}

	points := rec.MetricPoints(countMetricName)
	if len(points) != 1 {
		t.Fatalf("got %d points, want 1: %+v", len(points), points)
	}
	if got := points[0].Attrs[semconv.AttrSettingStatus]; got != statusUnknown {
		t.Errorf("metric label setting_status = %q for unknown code 99, want %q — an unmapped code must bucket, never pass through", got, statusUnknown)
	}

	logs := rec.LogRecords()
	if len(logs) != 1 {
		t.Fatalf("got %d logs, want 1", len(logs))
	}
	if got := logs[0].Attrs[semconv.AttrSettingStatusCode]; got != "99" {
		t.Errorf("log attr setting_status_code = %q, want the raw wire code %q (the code must survive a decode miss)", got, "99")
	}
	if got := logs[0].Attrs[semconv.AttrSettingStatus]; got != statusUnknown {
		t.Errorf("log attr setting_status = %q, want %q — never invent a name for an unmapped code", got, statusUnknown)
	}
}

// TestKnownStatusDecodes pins the one live-verified decode: SettingStatus "4" →
// "not_compliant". Expectation comes from the wire (SettingStatus_loc "Not
// compliant"), not from this package's own source.
func TestKnownStatusDecodes(t *testing.T) {
	if got, known := decodeStatus("4"); got != "not_compliant" || !known {
		t.Errorf("decodeStatus(%q) = (%q, %v), want (not_compliant, true)", "4", got, known)
	}
	if got, known := decodeStatus("99"); got != statusUnknown || known {
		t.Errorf("decodeStatus(%q) = (%q, %v), want (unknown, false)", "99", got, known)
	}
	if got, known := decodeStatus(""); got != statusUnknown || known {
		t.Errorf("decodeStatus(%q) = (%q, %v), want (unknown, false)", "", got, known)
	}
}

func TestCollectSkipsWhenExportRunnerIsNil(t *testing.T) {
	c := New(nil, nil)
	rec := telemetrytest.New()

	if err := c.Collect(context.Background(), rec.Emitter()); err != nil {
		t.Fatalf("Collect returned error, want nil (skip-and-log): %v", err)
	}
	if points := rec.MetricPoints(countMetricName); len(points) != 0 {
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
		{"forbidden", errors.New("exportjob: NoncompliantDevicesAndSettings: create: graphclient: status 403: forbidden")},
		{"other", errors.New("exportjob: NoncompliantDevicesAndSettings: create: boom")},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := New(&fakeRunner{err: tc.err}, nil)
			rec := telemetrytest.New()

			if err := c.Collect(context.Background(), rec.Emitter()); err != nil {
				t.Fatalf("Collect returned error, want nil (skip-and-log): %v", err)
			}
			if points := rec.MetricPoints(countMetricName); len(points) != 0 {
				t.Errorf("expected no gauge points on export failure, got %+v", points)
			}
			if logs := rec.LogRecords(); len(logs) != 0 {
				t.Errorf("expected no log records on export failure, got %+v", logs)
			}
		})
	}
}

func TestExperimentalPermissionsIntervalAndName(t *testing.T) {
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
	if c.Name() != "intune.noncompliant_settings" {
		t.Errorf("Name() = %q, want intune.noncompliant_settings", c.Name())
	}
	if got := c.DefaultInterval(); got.Hours() != 6 {
		t.Errorf("DefaultInterval() = %v, want 6h", got)
	}
	if got := c.IngestTransport(); got != telemetry.TransportReportExport {
		t.Errorf("IngestTransport() = %q, want %q", got, telemetry.TransportReportExport)
	}
}

// TestCollectStampsReportExportTransport pins that this collector names its own
// transport (#141): the export subsystem has no LogEvent seam, so left unstamped
// the Scheduler's "graph" baseline would be a confident lie about the transport.
func TestCollectStampsReportExportTransport(t *testing.T) {
	c := New(&fakeRunner{rows: liveRows()}, nil)
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
