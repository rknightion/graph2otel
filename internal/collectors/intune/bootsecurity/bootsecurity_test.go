package bootsecurity

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

// fakeRunner is a canned exportjob.Runner mirroring the pattern the sibling
// export collectors use: it returns a fixed row set or a fixed error and records
// the request it saw, so unit tests carry no live Graph/export-job dependency.
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

// liveRows are the two VERBATIM WindowsDeviceHealthAttestationReport rows captured
// on m7kni, probed as graph2otel-poller 2026-07-19 (only the raw columns this
// collector selects — the `_loc` localized siblings are deliberately not
// requested). LAPHAM has BitLocker+SecureBoot Disabled with VSM Enabled;
// DESKTOP-Q8HBBJ4 is the mirror (BitLocker+SecureBoot Enabled, VSM Disabled).
// Both attest Success. The Memory*/SecuredCorePC/SystemManagementMode columns are
// empty on the wire (loc "Unknown") — the device did not report them.
func liveRows() []exportjob.Row {
	return []exportjob.Row{
		{
			"DeviceId": "d5900d67-e50c-44ef-9d5c-6a2f891099c6", "DeviceName": "LAPHAM",
			"PrimaryUser": "bbcfc3c5-0b93-4135-9ef9-18477a9fb504", "UPN": "rob@m7kni.io",
			"DeviceOS": "Windows 11", "BitlockerStatus": "Disabled", "CodeIntegrityStatus": "Enforce",
			"BootDebuggingStatus": "Disabled", "AIKKey": "Present", "SecureBootStatus": "Disabled",
			"DEPPolicy": "0", "HealthCertIssuedDate": "2026-07-13 20:09:19.0000000",
			"OSKernelDebuggingStatus": "Disabled", "SafeModeStatus": "False", "VSMStatus": "Enabled",
			"WinPEStatus": "NotActive", "ELAMDriverLoadedStatus": "Enabled",
			"FirmwareProtectionStatus": "NotApplicable", "MemoryIntegrityProtectionStatus": "",
			"MemoryAccessProtectionStatus": "", "SecuredCorePCStatus": "", "SystemManagementMode": "",
			"TpmVersion": "2", "AttestationError": "Success",
		},
		{
			"DeviceId": "eacc407b-5c7a-40f5-a98a-d803198bb768", "DeviceName": "DESKTOP-Q8HBBJ4",
			"PrimaryUser": "bbcfc3c5-0b93-4135-9ef9-18477a9fb504", "UPN": "rob@m7kni.io",
			"DeviceOS": "Windows 11", "BitlockerStatus": "Enabled", "CodeIntegrityStatus": "Enforce",
			"BootDebuggingStatus": "Disabled", "AIKKey": "NotPresent", "SecureBootStatus": "Enabled",
			"DEPPolicy": "0", "HealthCertIssuedDate": "2026-07-19 17:38:08.9589628",
			"OSKernelDebuggingStatus": "Disabled", "SafeModeStatus": "False", "VSMStatus": "Disabled",
			"WinPEStatus": "NotActive", "ELAMDriverLoadedStatus": "Enabled",
			"FirmwareProtectionStatus": "NotApplicable", "MemoryIntegrityProtectionStatus": "",
			"MemoryAccessProtectionStatus": "", "SecuredCorePCStatus": "", "SystemManagementMode": "",
			"TpmVersion": "2", "AttestationError": "Success",
		},
	}
}

// TestCollectCountsDevicesByPostureStatusOS pins the faceted gauge: one point per
// (posture, status, os), value = device count. Empty postures (Memory*, SecuredCorePC)
// contribute no point. From the two live rows: bitlocker {Disabled:1, Enabled:1},
// secure_boot {Disabled:1, Enabled:1}, code_integrity {Enforce:2}, vsm {Enabled:1,
// Disabled:1}, firmware_protection {NotApplicable:2}.
func TestCollectCountsDevicesByPostureStatusOS(t *testing.T) {
	runner := &fakeRunner{rows: liveRows()}
	c := New(runner, nil)
	rec := telemetrytest.New()

	if err := c.Collect(context.Background(), rec.Emitter()); err != nil {
		t.Fatalf("Collect: %v", err)
	}
	if runner.lastReq.ReportName != "WindowsDeviceHealthAttestationReport" {
		t.Errorf("ReportName = %q", runner.lastReq.ReportName)
	}
	if len(runner.lastReq.Select) == 0 {
		t.Error("Select must be non-empty")
	}

	type key struct{ posture, status, os string }
	want := map[key]float64{
		{"bitlocker", "Disabled", "Windows 11"}:                1,
		{"bitlocker", "Enabled", "Windows 11"}:                 1,
		{"secure_boot", "Disabled", "Windows 11"}:              1,
		{"secure_boot", "Enabled", "Windows 11"}:               1,
		{"code_integrity", "Enforce", "Windows 11"}:            2,
		{"vsm", "Enabled", "Windows 11"}:                       1,
		{"vsm", "Disabled", "Windows 11"}:                      1,
		{"firmware_protection", "NotApplicable", "Windows 11"}: 2,
	}
	points := rec.MetricPoints(devicesMetricName)
	got := map[key]float64{}
	for _, p := range points {
		got[key{p.Attrs[semconv.AttrPosture], p.Attrs[semconv.AttrStatus], p.Attrs[semconv.AttrOs]}] = p.Value
	}
	if len(got) != len(want) {
		t.Fatalf("got %d points, want %d: %+v", len(got), len(want), got)
	}
	for k, wv := range want {
		if got[k] != wv {
			t.Errorf("point %+v = %v, want %v", k, got[k], wv)
		}
	}
}

// TestMetricNameAndUnitPinned pins the wire contract as literals.
func TestMetricNameAndUnitPinned(t *testing.T) {
	c := New(&fakeRunner{rows: liveRows()[:1]}, nil)
	rec := telemetrytest.New()
	if err := c.Collect(context.Background(), rec.Emitter()); err != nil {
		t.Fatalf("Collect: %v", err)
	}
	points := rec.MetricPoints("intune.device_boot_security.devices")
	if len(points) == 0 {
		t.Fatalf("no points; emitted: %v", rec.MetricNames())
	}
	if got := points[0].Unit; got != "{device}" {
		t.Errorf("Unit = %q, want {device}", got)
	}
}

// TestMetricCarriesOnlyBoundedDimensions is the cardinality guard: no per-device
// identifier may become a metric label. 40 distinct devices on one posture/status
// must collapse to exactly one series, carrying only (posture, status, os).
func TestMetricCarriesOnlyBoundedDimensions(t *testing.T) {
	rows := make([]exportjob.Row, 0, 40)
	for i := range 40 {
		rows = append(rows, exportjob.Row{
			"DeviceId": fmt.Sprintf("id-%d", i), "DeviceName": fmt.Sprintf("DEV-%d", i),
			"UPN": fmt.Sprintf("u%d@m7kni.io", i), "DeviceOS": "Windows 11",
			"BitlockerStatus": "Enabled", "AttestationError": "Success",
		})
	}
	c := New(&fakeRunner{rows: rows}, nil)
	rec := telemetrytest.New()
	if err := c.Collect(context.Background(), rec.Emitter()); err != nil {
		t.Fatalf("Collect: %v", err)
	}
	points := rec.MetricPoints(devicesMetricName)
	if len(points) != 1 {
		t.Fatalf("got %d series from 40 distinct devices on one posture/status, want 1: %+v", len(points), points)
	}
	for k := range points[0].Attrs {
		if k != semconv.AttrPosture && k != semconv.AttrStatus && k != semconv.AttrOs {
			t.Errorf("metric carries unbounded attribute %q; per-device detail belongs on the %s twin (#83, #112)", k, eventName)
		}
	}
}

// TestCollectEmitsOneTwinPerDevice pins the per-device twin: one record per row,
// carrying the full boot-security posture detail dropped from the metric.
func TestCollectEmitsOneTwinPerDevice(t *testing.T) {
	c := New(&fakeRunner{rows: liveRows()}, nil)
	rec := telemetrytest.New()
	if err := c.Collect(context.Background(), rec.Emitter()); err != nil {
		t.Fatalf("Collect: %v", err)
	}
	logs := rec.LogRecords()
	if len(logs) != 2 {
		t.Fatalf("got %d twins, want 2: %+v", len(logs), logs)
	}
	byDevice := map[string]telemetrytest.LogRecord{}
	for _, l := range logs {
		if l.EventName != eventName {
			t.Errorf("EventName = %q, want %q", l.EventName, eventName)
		}
		byDevice[l.Attrs[semconv.AttrDeviceName]] = l
	}
	lapham, ok := byDevice["LAPHAM"]
	if !ok {
		t.Fatalf("no twin for LAPHAM; got %v", byDevice)
	}
	want := map[string]string{
		semconv.AttrDeviceName:               "LAPHAM",
		semconv.AttrDeviceId:                 "d5900d67-e50c-44ef-9d5c-6a2f891099c6",
		semconv.AttrUpn:                      "rob@m7kni.io",
		semconv.AttrIntuneUserId:             "bbcfc3c5-0b93-4135-9ef9-18477a9fb504",
		semconv.AttrOs:                       "Windows 11",
		semconv.AttrBitlockerStatus:          "Disabled",
		semconv.AttrSecureBootStatus:         "Disabled",
		semconv.AttrCodeIntegrityStatus:      "Enforce",
		semconv.AttrVsmStatus:                "Enabled",
		semconv.AttrFirmwareProtectionStatus: "NotApplicable",
		semconv.AttrBootDebuggingStatus:      "Disabled",
		semconv.AttrOsKernelDebuggingStatus:  "Disabled",
		semconv.AttrSafeModeStatus:           "False",
		semconv.AttrWinpeStatus:              "NotActive",
		semconv.AttrElamDriverLoadedStatus:   "Enabled",
		semconv.AttrAikKey:                   "Present",
		semconv.AttrDepPolicy:                "0",
		semconv.AttrTpmVersion:               "2",
		semconv.AttrAttestationError:         "Success",
		semconv.AttrHealthCertIssuedDate:     "2026-07-13 20:09:19.0000000",
	}
	for k, wv := range want {
		if lapham.Attrs[k] != wv {
			t.Errorf("twin attr %q = %q, want %q", k, lapham.Attrs[k], wv)
		}
	}
}

// TestTwinOmitsEmptyPostures pins that an empty posture column emits no attribute
// at all (never an empty string): the Memory*/SecuredCorePC/SystemManagementMode
// columns are "" on the wire.
func TestTwinOmitsEmptyPostures(t *testing.T) {
	c := New(&fakeRunner{rows: liveRows()[:1]}, nil)
	rec := telemetrytest.New()
	if err := c.Collect(context.Background(), rec.Emitter()); err != nil {
		t.Fatalf("Collect: %v", err)
	}
	logs := rec.LogRecords()
	if len(logs) != 1 {
		t.Fatalf("got %d twins, want 1", len(logs))
	}
	for _, k := range []string{semconv.AttrMemoryIntegrityProtection, semconv.AttrMemoryAccessProtectionStatus, semconv.AttrSecuredCorePcStatus, semconv.AttrSystemManagementMode} {
		if v, ok := logs[0].Attrs[k]; ok {
			t.Errorf("empty posture emitted attr %q = %q, want omitted", k, v)
		}
	}
}

// TestSeverityFromAttestationError pins WARN when AttestationError != Success.
func TestSeverityFromAttestationError(t *testing.T) {
	r := liveRows()[0]
	r["AttestationError"] = "TpmNotEnabled"
	c := New(&fakeRunner{rows: []exportjob.Row{r}}, nil)
	rec := telemetrytest.New()
	if err := c.Collect(context.Background(), rec.Emitter()); err != nil {
		t.Fatalf("Collect: %v", err)
	}
	logs := rec.LogRecords()
	if logs[0].SeverityText != "WARN" {
		t.Errorf("failed attestation: SeverityText = %q, want WARN", logs[0].SeverityText)
	}
	// A Success row is INFO.
	c2 := New(&fakeRunner{rows: liveRows()[:1]}, nil)
	rec2 := telemetrytest.New()
	_ = c2.Collect(context.Background(), rec2.Emitter())
	if rec2.LogRecords()[0].SeverityText != "INFO" {
		t.Errorf("clean attestation: SeverityText = %q, want INFO", rec2.LogRecords()[0].SeverityText)
	}
}

// TestTwinTimestampLeftUnset pins that HealthCertIssuedDate is NOT parsed into the
// event time — this is a state feed re-emitted each poll, so the emitter stamps
// arrival time.
func TestTwinTimestampLeftUnset(t *testing.T) {
	c := New(&fakeRunner{rows: liveRows()[:1]}, nil)
	rec := telemetrytest.New()
	if err := c.Collect(context.Background(), rec.Emitter()); err != nil {
		t.Fatalf("Collect: %v", err)
	}
	if !rec.LogRecords()[0].Timestamp.IsZero() {
		t.Errorf("Timestamp = %v, want zero (unset)", rec.LogRecords()[0].Timestamp)
	}
}

func TestCollectSkipsAndLogsOnExportError(t *testing.T) {
	for _, tc := range []struct {
		name string
		err  error
	}{
		{"job failed", fmt.Errorf("exportjob: %s: %w", reportName, exportjob.ErrJobFailed)},
		{"sas expired", fmt.Errorf("exportjob: %s: %w", reportName, exportjob.ErrSASExpired)},
		{"forbidden", errors.New("exportjob: WindowsDeviceHealthAttestationReport: create: status 403: forbidden")},
		{"other", errors.New("exportjob: WindowsDeviceHealthAttestationReport: boom")},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := New(&fakeRunner{err: tc.err}, nil)
			rec := telemetrytest.New()
			if err := c.Collect(context.Background(), rec.Emitter()); err != nil {
				t.Fatalf("Collect returned error, want nil (skip-and-log): %v", err)
			}
			if len(rec.MetricPoints(devicesMetricName)) != 0 || len(rec.LogRecords()) != 0 {
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
	if len(rec.MetricPoints(devicesMetricName)) != 0 || len(rec.LogRecords()) != 0 {
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
		t.Errorf("Name() = %q, want %q", c.Name(), collectorName)
	}
	if c.DefaultInterval().Hours() != 6 {
		t.Errorf("DefaultInterval = %v, want 6h", c.DefaultInterval())
	}
	if c.IngestTransport() != telemetry.TransportReportExport {
		t.Errorf("IngestTransport = %q", c.IngestTransport())
	}
}

// TestCollectStampsReportExportTransport pins that this collector names its own
// transport (#141): exportjob has no LogEvent call site.
func TestCollectStampsReportExportTransport(t *testing.T) {
	c := New(&fakeRunner{rows: liveRows()}, nil)
	rec := telemetrytest.New()
	if err := c.Collect(context.Background(), rec.Emitter()); err != nil {
		t.Fatalf("Collect: %v", err)
	}
	logs := rec.LogRecords()
	if len(logs) == 0 {
		t.Fatal("no logs")
	}
	for i, l := range logs {
		if got := l.Attrs[semconv.AttrIngestTransport]; got != string(telemetry.TransportReportExport) {
			t.Errorf("log[%d] transport = %q, want %q", i, got, telemetry.TransportReportExport)
		}
	}
}
