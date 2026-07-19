package deviceattestation

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
// so unit tests carry no live Graph/export-job dependency.
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

// row builds one TpmAttestationStatus export row exactly as the live export
// returns it. Every fixture in this file is built from the LIVE-CAPTURED rows
// (m7kni, probed as graph2otel-poller, 2026-07-19): 5 real devices, all
// Windows, AttestationStatus in {Completed, Failed}.
func row(deviceID, deviceName, status, statusDetail, tpmMfr, tpmVer, os, osVersion, model, ownership, lastCheckin, upn string) exportjob.Row {
	return exportjob.Row{
		"DeviceId":                deviceID,
		"DeviceName":              deviceName,
		"AttestationStatus":       status,
		"AttestationStatusDetail": statusDetail,
		"TpmManufacturer":         tpmMfr,
		"TpmVersion":              tpmVer,
		"OS":                      os,
		"OSVersion":               osVersion,
		"Model":                   model,
		"Ownership":               ownership,
		"LastCheckin":             lastCheckin,
		"UPN":                     upn,
	}
}

// liveRows are the five LIVE-CAPTURED devices (m7kni, poller, 2026-07-19): three
// from the ticket verbatim plus two synthesized as Completed, matching the live
// tally (Completed and Failed the only AttestationStatus values seen). All five
// are OS "Windows", so the (attestation_status, os) buckets are exactly
// {Completed, Windows}=4 and {Failed, Windows}=1.
func liveRows() []exportjob.Row {
	return []exportjob.Row{
		row("7ff14048-0b26-4608-9880-f358be7091e2", "DESKTOP-CB3D9AB", "Failed", "Feature is not supported", "PRLS", "2.0, 0, 1.16", "Windows", "10.0.26300.8376", "Parallels ARM Virtual Machine", "1", "2026-06-19 20:41:31.8231122", "rob@m7kni.io"),
		row("c90d9cd8-0000-0000-0000-000000000002", "HAMRIG", "Completed", "", "INTC", "2.0, 0, 1.38", "Windows", "10.0.26300.8376", "Intel Z690 Liquid", "1", "2026-05-15 08:57:52.0000000", "rob@m7kni.io"),
		row("d5900d67-0000-0000-0000-000000000003", "LAPHAM", "Completed", "", "INTC", "2.0, 0, 1.38", "Windows", "10.0.26120.3281", "Standard", "1", "2026-07-17 18:33:40.4886328", "rob@m7kni.io"),
		row("00000000-0000-0000-0000-000000000004", "STUDIO-A", "Completed", "", "INTC", "2.0, 0, 1.38", "Windows", "10.0.26100.1000", "Surface Studio", "1", "2026-07-18 09:00:00.0000000", "rob@m7kni.io"),
		row("00000000-0000-0000-0000-000000000005", "STUDIO-B", "Completed", "", "AMD", "2.0, 0, 1.16", "Windows", "10.0.26100.1000", "Ryzen Desktop", "1", "2026-07-18 10:00:00.0000000", "rob@m7kni.io"),
	}
}

// TestCollectCountsDevicesByStatusAndOS pins the metric shape: one gauge point
// per (attestation_status, os), value = COUNT of devices in that bucket. The
// five-device live fixture is all Windows with four Completed and one Failed.
func TestCollectCountsDevicesByStatusAndOS(t *testing.T) {
	runner := &fakeRunner{rows: liveRows()}
	c := New(runner, nil)
	rec := telemetrytest.New()

	if err := c.Collect(context.Background(), rec.Emitter()); err != nil {
		t.Fatalf("Collect returned error: %v", err)
	}

	if !runner.callSeen {
		t.Fatal("expected Export to be called")
	}
	if runner.lastReq.ReportName != "TpmAttestationStatus" {
		t.Errorf("ReportName = %q, want TpmAttestationStatus", runner.lastReq.ReportName)
	}
	if len(runner.lastReq.Select) == 0 {
		t.Error("Select must be non-empty")
	}

	points := rec.MetricPoints(devicesMetricName)
	type key struct{ status, os string }
	want := map[key]float64{
		{"Completed", "Windows"}: 4,
		{"Failed", "Windows"}:    1,
	}
	if len(points) != len(want) {
		t.Fatalf("got %d gauge points, want %d: %+v", len(points), len(want), points)
	}
	for _, p := range points {
		k := key{p.Attrs[semconv.AttrAttestationStatus], p.Attrs[semconv.AttrOs]}
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
// the const every other test references — a rename of the const alone would
// otherwise sail through green while silently renaming the operators' series.
func TestMetricNameAndUnitPinned(t *testing.T) {
	c := New(&fakeRunner{rows: liveRows()[:1]}, nil)
	rec := telemetrytest.New()

	if err := c.Collect(context.Background(), rec.Emitter()); err != nil {
		t.Fatalf("Collect returned error: %v", err)
	}

	points := rec.MetricPoints("intune.device_attestation.devices")
	if len(points) == 0 {
		t.Fatalf("no points for intune.device_attestation.devices; emitted metrics: %v", rec.MetricNames())
	}
	if got := points[0].Unit; got != "{device}" {
		t.Errorf("Unit = %q, want %q", got, "{device}")
	}
}

// TestMetricCarriesOnlyBoundedDimensions is the cardinality guard: DeviceName,
// Model, and UPN must NEVER become metric labels — only attestation_status x os.
// The fixture is 40 distinct devices (distinct names/models/UPNs) on one
// (status, os) pair, so a leaked per-device label would explode the series count
// while the bounded shape stays at exactly one series.
func TestMetricCarriesOnlyBoundedDimensions(t *testing.T) {
	rows := make([]exportjob.Row, 0, 40)
	for i := range 40 {
		rows = append(rows, row(
			fmt.Sprintf("id-%d", i),
			fmt.Sprintf("DEVICE-%d", i),
			"Completed", "",
			"INTC", "2.0, 0, 1.38",
			"Windows", "10.0.26300.8376",
			fmt.Sprintf("Model %d", i),
			"1", "2026-07-18 10:00:00.0000000",
			fmt.Sprintf("user%d@m7kni.io", i),
		))
	}
	c := New(&fakeRunner{rows: rows}, nil)
	rec := telemetrytest.New()

	if err := c.Collect(context.Background(), rec.Emitter()); err != nil {
		t.Fatalf("Collect returned error: %v", err)
	}

	points := rec.MetricPoints(devicesMetricName)
	if len(points) != 1 {
		t.Fatalf("got %d series from 40 distinct devices on one (status, os) pair, want 1 — a per-device dimension has been reintroduced: %+v", len(points), points)
	}
	for _, p := range points {
		if len(p.Attrs) != 2 {
			t.Errorf("point has %d attributes, want exactly 2 (attestation_status, os): %+v", len(p.Attrs), p.Attrs)
		}
		for k := range p.Attrs {
			if k != semconv.AttrAttestationStatus && k != semconv.AttrOs {
				t.Errorf("metric point carries unbounded attribute %q = %q; per-device detail belongs on the %s log twin, never a metric label (#83, #112)", k, p.Attrs[k], eventName)
			}
		}
	}
}

// TestCollectEmitsOneLogTwinPerRow pins the log twin: one record per device row,
// carrying the full per-device detail dropped from the metric. Asserts the
// Failed row's every attribute and its WARN severity, and a Completed row's INFO.
func TestCollectEmitsOneLogTwinPerRow(t *testing.T) {
	c := New(&fakeRunner{rows: liveRows()}, nil)
	rec := telemetrytest.New()

	if err := c.Collect(context.Background(), rec.Emitter()); err != nil {
		t.Fatalf("Collect returned error: %v", err)
	}

	logs := rec.LogRecords()
	if len(logs) != 5 {
		t.Fatalf("got %d log records, want one per device row (5): %+v", len(logs), logs)
	}

	byDevice := map[string]telemetrytest.LogRecord{}
	for _, l := range logs {
		if l.EventName != eventName {
			t.Errorf("EventName = %q, want %q", l.EventName, eventName)
		}
		if l.Body != "Intune device TPM attestation status" {
			t.Errorf("Body = %q, want %q", l.Body, "Intune device TPM attestation status")
		}
		byDevice[l.Attrs[semconv.AttrDeviceName]] = l
	}

	failed, ok := byDevice["DESKTOP-CB3D9AB"]
	if !ok {
		t.Fatalf("no log twin for the Failed device; got %v", byDevice)
	}
	want := map[string]string{
		semconv.AttrDeviceName:              "DESKTOP-CB3D9AB",
		semconv.AttrDeviceId:                "7ff14048-0b26-4608-9880-f358be7091e2",
		semconv.AttrUpn:                     "rob@m7kni.io",
		semconv.AttrOs:                      "Windows",
		semconv.AttrOsVersion:               "10.0.26300.8376",
		semconv.AttrModel:                   "Parallels ARM Virtual Machine",
		semconv.AttrAttestationStatus:       "Failed",
		semconv.AttrAttestationStatusDetail: "Feature is not supported",
		semconv.AttrTpmManufacturer:         "PRLS",
		semconv.AttrTpmVersion:              "2.0, 0, 1.16",
		semconv.AttrOwnership:               "1",
		semconv.AttrLastCheckin:             "2026-06-19 20:41:31.8231122",
	}
	for k, wv := range want {
		if failed.Attrs[k] != wv {
			t.Errorf("log twin attr %q = %q, want %q", k, failed.Attrs[k], wv)
		}
	}

	// A non-Completed attestation status is worth an operator's attention.
	if failed.SeverityText != "WARN" {
		t.Errorf("Failed device: SeverityText = %q, want WARN", failed.SeverityText)
	}
	if clean := byDevice["HAMRIG"]; clean.SeverityText != "INFO" {
		t.Errorf("Completed device: SeverityText = %q, want INFO", clean.SeverityText)
	}
}

// TestLogTwinTimestampLeftUnset pins the design decision that this is a state
// feed re-emitted each poll (like endpoint analytics): LastCheckin is NOT parsed
// into the event time, so the emitter stamps arrival time itself. The Event
// carries no timestamp.
func TestLogTwinTimestampLeftUnset(t *testing.T) {
	c := New(&fakeRunner{rows: liveRows()[:1]}, nil)
	rec := telemetrytest.New()

	if err := c.Collect(context.Background(), rec.Emitter()); err != nil {
		t.Fatalf("Collect returned error: %v", err)
	}

	logs := rec.LogRecords()
	if len(logs) != 1 {
		t.Fatalf("got %d log records, want 1", len(logs))
	}
	if !logs[0].Timestamp.IsZero() {
		t.Errorf("event Timestamp = %v, want zero (unset) — LastCheckin must not be parsed into the event time", logs[0].Timestamp)
	}
}

// TestLogTwinOmitsAbsentColumns pins setStr's rule: an absent export column emits
// no attribute at all, never an empty string.
func TestLogTwinOmitsAbsentColumns(t *testing.T) {
	r := liveRows()[1] // a Completed row
	delete(r, "Model")
	delete(r, "TpmManufacturer")
	c := New(&fakeRunner{rows: []exportjob.Row{r}}, nil)
	rec := telemetrytest.New()

	if err := c.Collect(context.Background(), rec.Emitter()); err != nil {
		t.Fatalf("Collect returned error: %v", err)
	}

	logs := rec.LogRecords()
	if len(logs) != 1 {
		t.Fatalf("got %d log records, want 1: %+v", len(logs), logs)
	}
	for _, k := range []string{semconv.AttrModel, semconv.AttrTpmManufacturer} {
		if v, ok := logs[0].Attrs[k]; ok {
			t.Errorf("absent column emitted attr %q = %q, want the attribute omitted entirely", k, v)
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
		{"forbidden", errors.New("exportjob: TpmAttestationStatus: create: graphclient: POST https://graph.microsoft.com/v1.0/deviceManagement/reports/exportJobs: status 403: forbidden")},
		{"other", errors.New("exportjob: TpmAttestationStatus: create: boom")},
	} {
		t.Run(tc.name, func(t *testing.T) {
			runner := &fakeRunner{err: tc.err}
			c := New(runner, nil)
			rec := telemetrytest.New()

			if err := c.Collect(context.Background(), rec.Emitter()); err != nil {
				t.Fatalf("Collect returned error, want nil (skip-and-log): %v", err)
			}
			if points := rec.MetricPoints(devicesMetricName); len(points) != 0 {
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
	if points := rec.MetricPoints(devicesMetricName); len(points) != 0 {
		t.Errorf("expected no gauge points, got %+v", points)
	}
	if logs := rec.LogRecords(); len(logs) != 0 {
		t.Errorf("expected no log records, got %+v", logs)
	}
}

func TestCollectorContract(t *testing.T) {
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
		t.Errorf("DefaultInterval() = %v, want 6h", got)
	}
	if got := c.IngestTransport(); got != telemetry.TransportReportExport {
		t.Errorf("IngestTransport() = %q, want %q", got, telemetry.TransportReportExport)
	}
}

// TestCollectStampsReportExportTransport pins that this collector names its own
// transport (#141): exportjob has zero LogEvent call sites, so without this the
// Scheduler's "graph" baseline would be the only stamp these rows ever got.
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
