package epmelevationevents

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/rknightion/graph2otel/internal/checkpoint"
	"github.com/rknightion/graph2otel/internal/exportjob"
	"github.com/rknightion/graph2otel/internal/semconv"
	"github.com/rknightion/graph2otel/internal/telemetry"
	"github.com/rknightion/graph2otel/internal/telemetrytest"
)

type fakeRunner struct {
	rows    []exportjob.Row
	err     error
	calls   int
	lastReq exportjob.Request
}

func (f *fakeRunner) Export(_ context.Context, req exportjob.Request, _ telemetry.Emitter) ([]exportjob.Row, error) {
	f.calls++
	f.lastReq = req
	if f.err != nil {
		return nil, f.err
	}
	return f.rows, nil
}

var _ exportjob.Runner = (*fakeRunner)(nil)

// liveRows are VERBATIM EpmElevationReportElevationEvent rows captured on m7kni,
// probed as graph2otel-poller 2026-07-20. Note the EventDateTime format
// ("2026-07-19 19:10:54.0000000" — space separator, 7 fractional digits, no
// zone; NOT RFC3339) and the "<Null>" sentinel in RuleId/PolicyId — both are the
// load-bearing wire traps this collector exists to handle.
func liveRows() []exportjob.Row {
	return []exportjob.Row{
		{
			"Id":       "2151a56123eee136b33eef2b5c1422859fc600576f2f34da29705fd0f08b59b5",
			"DeviceId": "eacc407b-5c7a-40f5-a98a-d803198bb768", "DeviceName": "DESKTOP-Q8HBBJ4",
			"EventDateTime": "2026-07-19 19:10:54.0000000", "ElevationType": "UnmanagedElevation",
			"FilePath": `C:\WINDOWS\SysWOW64\net.exe`, "Upn": `AzureAD\RobKnight`, "UserType": "Unknown",
			"ProductName": "Microsoft® Windows® Operating System", "CompanyName": "Microsoft Windows",
			"FileVersion": "10.0.26100.7019", "Justification": "",
			"Hash":         "E7A3A04DB13F7D5E65DB45DBED99B80C9AD9907BEEBA3416E2E5428E1EFB791E",
			"InternalName": "net.exe", "FileDescription": "Net Command", "Result": "0",
			"ProcessType": "Parent", "RuleId": "<Null>", "ParentProcessName": "powershell.exe",
			"PolicyId": "<Null>", "PolicyName": "", "IsSystemInitiated": "False",
		},
		{
			"Id":       "9d65da5e08826c9a63b3705e5af5690783da9049622fe7e797e0c542150dc58c",
			"DeviceId": "d5900d67-e50c-44ef-9d5c-6a2f891099c6", "DeviceName": "LAPHAM",
			"EventDateTime": "2026-07-15 18:45:23.0000000", "ElevationType": "UnmanagedElevation",
			"FilePath": `C:\WINDOWS\system32\taskhostw.exe`, "Upn": `AzureAD\RobKnight`, "UserType": "Unknown",
			"ProductName": "Microsoft® Windows® Operating System", "CompanyName": "Microsoft Windows",
			"FileVersion": "10.0.26100.2992", "Justification": "",
			"Hash":         "C99282B49E7AFAEEB085624C1432DBB5E3B2BC5174847D043C5F3C901C1FC3D1",
			"InternalName": "taskhostw.exe", "FileDescription": "Host Process for Windows Tasks", "Result": "0",
			"ProcessType": "Parent", "RuleId": "<Null>", "ParentProcessName": "svchost.exe",
			"PolicyId": "<Null>", "PolicyName": "", "IsSystemInitiated": "False",
		},
		{
			"Id":       "ceae1fa9716dfd43cbc8000976bbbdbea6ce747a814f54de0f72c71518b33511",
			"DeviceId": "d5900d67-e50c-44ef-9d5c-6a2f891099c6", "DeviceName": "LAPHAM",
			"EventDateTime": "2026-07-15 16:34:55.0000000", "ElevationType": "UnmanagedElevation",
			"FilePath": `C:\WINDOWS\system32\taskhostw.exe`, "Upn": "rob@m7kni.io", "UserType": "Unknown",
			"ProductName": "Microsoft® Windows® Operating System", "CompanyName": "Microsoft Windows",
			"FileVersion": "10.0.26100.2992", "Justification": "",
			"Hash":         "C99282B49E7AFAEEB085624C1432DBB5E3B2BC5174847D043C5F3C901C1FC3D1",
			"InternalName": "taskhostw.exe", "FileDescription": "Host Process for Windows Tasks", "Result": "0",
			"ProcessType": "Parent", "RuleId": "<Null>", "ParentProcessName": "svchost.exe",
			"PolicyId": "<Null>", "PolicyName": "", "IsSystemInitiated": "False",
		},
	}
}

func newStore(t *testing.T) *checkpoint.Store {
	t.Helper()
	return checkpoint.NewStore(t.TempDir())
}

// TestCollectEmitsOneTwinPerEvent pins the twin: one record per event row, each
// stamped with its own EventDateTime as the log event time (NOT "now").
func TestCollectEmitsOneTwinPerEvent(t *testing.T) {
	runner := &fakeRunner{rows: liveRows()}
	c := New(runner, newStore(t), "tenant-a", nil)
	rec := telemetrytest.New()
	if err := c.Collect(context.Background(), rec.Emitter()); err != nil {
		t.Fatalf("Collect: %v", err)
	}
	if runner.lastReq.ReportName != reportName {
		t.Errorf("ReportName = %q", runner.lastReq.ReportName)
	}

	logs := rec.LogRecords()
	if len(logs) != 3 {
		t.Fatalf("got %d twins, want 3", len(logs))
	}
	byID := map[string]telemetrytest.LogRecord{}
	for _, l := range logs {
		if l.EventName != eventName {
			t.Errorf("EventName = %q", l.EventName)
		}
		if l.Timestamp.IsZero() {
			t.Errorf("twin %q has zero timestamp; an event stream must carry EventDateTime", l.Attrs[semconv.AttrElevationId])
		}
		byID[l.Attrs[semconv.AttrElevationId]] = l
	}

	first := byID["2151a56123eee136b33eef2b5c1422859fc600576f2f34da29705fd0f08b59b5"]
	wantTime := time.Date(2026, 7, 19, 19, 10, 54, 0, time.UTC)
	if !first.Timestamp.Equal(wantTime) {
		t.Errorf("event time = %v, want %v (parsed from the space-separated 7-frac UTC format)", first.Timestamp, wantTime)
	}
	if first.SeverityText != "WARN" {
		t.Errorf("UnmanagedElevation severity = %q, want WARN", first.SeverityText)
	}
	if first.Attrs[semconv.AttrFilePath] != `C:\WINDOWS\SysWOW64\net.exe` ||
		first.Attrs[semconv.AttrUpn] != `AzureAD\RobKnight` ||
		first.Attrs[semconv.AttrFileHash] != "E7A3A04DB13F7D5E65DB45DBED99B80C9AD9907BEEBA3416E2E5428E1EFB791E" ||
		first.Attrs[semconv.AttrParentProcessName] != "powershell.exe" ||
		first.Attrs[semconv.AttrResult] != "0" ||
		first.Attrs[semconv.AttrDeviceName] != "DESKTOP-Q8HBBJ4" {
		t.Errorf("twin attrs = %+v", first.Attrs)
	}
	// "<Null>" and "" sentinels must be dropped, never emitted verbatim.
	if _, ok := first.Attrs[semconv.AttrRuleId]; ok {
		t.Errorf("rule_id present for a <Null> value: %q", first.Attrs[semconv.AttrRuleId])
	}
	if _, ok := first.Attrs[semconv.AttrPolicyId]; ok {
		t.Errorf("policy_id present for a <Null> value")
	}
	if _, ok := first.Attrs[semconv.AttrJustification]; ok {
		t.Errorf("justification present for an empty value")
	}
}

// TestMetricIsBoundedCounterByTypeAndResult: the metric is a monotonic counter
// keyed only by the bounded (elevation_type, result) pair — never by per-event
// identity — incremented once per NEW event.
func TestMetricIsBoundedCounterByTypeAndResult(t *testing.T) {
	c := New(&fakeRunner{rows: liveRows()}, newStore(t), "tenant-a", nil)
	rec := telemetrytest.New()
	if err := c.Collect(context.Background(), rec.Emitter()); err != nil {
		t.Fatalf("Collect: %v", err)
	}
	points := rec.MetricPoints(metricName)
	if len(points) != 1 {
		t.Fatalf("got %d series, want 1 (all rows UnmanagedElevation/result 0): %+v", len(points), points)
	}
	p := points[0]
	if p.Kind != "sum" || !p.Monotonic {
		t.Errorf("metric kind=%q monotonic=%v, want monotonic sum (counter)", p.Kind, p.Monotonic)
	}
	if p.Value != 3 {
		t.Errorf("counter = %v, want 3", p.Value)
	}
	if p.Attrs[semconv.AttrElevationType] != "UnmanagedElevation" || p.Attrs[semconv.AttrResult] != "0" {
		t.Errorf("counter attrs = %+v", p.Attrs)
	}
	for k := range p.Attrs {
		if k != semconv.AttrElevationType && k != semconv.AttrResult {
			t.Errorf("counter carries unbounded attribute %q; per-event detail belongs on the %s twin (#112)", k, eventName)
		}
	}
}

// TestSecondPollDeduplicates is the money test (#205): a second poll of the SAME
// rows through a FRESH emitter but the SAME persisted checkpoint must emit ZERO
// twins and add ZERO to the counter — no dup-storm across the 6h re-export.
func TestSecondPollDeduplicates(t *testing.T) {
	store := newStore(t)
	runner := &fakeRunner{rows: liveRows()}

	rec1 := telemetrytest.New()
	if err := New(runner, store, "tenant-a", nil).Collect(context.Background(), rec1.Emitter()); err != nil {
		t.Fatalf("poll 1: %v", err)
	}
	if n := len(rec1.LogRecords()); n != 3 {
		t.Fatalf("poll 1 emitted %d twins, want 3", n)
	}

	rec2 := telemetrytest.New()
	if err := New(runner, store, "tenant-a", nil).Collect(context.Background(), rec2.Emitter()); err != nil {
		t.Fatalf("poll 2: %v", err)
	}
	if n := len(rec2.LogRecords()); n != 0 {
		t.Fatalf("poll 2 re-emitted %d twins; expected 0 (persisted SeenIDs must dedupe)", n)
	}
	if pts := rec2.MetricPoints(metricName); len(pts) != 0 {
		t.Errorf("poll 2 incremented the counter (%+v); expected no new events", pts)
	}
}

// TestNewEventOnSecondPollEmits: a poll that brings a genuinely new event (later
// EventDateTime, new Id) emits exactly that one, not the whole report again.
func TestNewEventOnSecondPollEmits(t *testing.T) {
	store := newStore(t)

	rec1 := telemetrytest.New()
	if err := New(&fakeRunner{rows: liveRows()}, store, "tenant-a", nil).Collect(context.Background(), rec1.Emitter()); err != nil {
		t.Fatalf("poll 1: %v", err)
	}

	extra := append(liveRows(), exportjob.Row{
		"Id":       "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
		"DeviceId": "eacc407b-5c7a-40f5-a98a-d803198bb768", "DeviceName": "DESKTOP-Q8HBBJ4",
		"EventDateTime": "2026-07-20 08:00:00.0000000", "ElevationType": "UnmanagedElevation",
		"FilePath": `C:\WINDOWS\SysWOW64\cmd.exe`, "Upn": `AzureAD\RobKnight`, "Result": "0",
		"InternalName": "cmd.exe", "IsSystemInitiated": "False",
	})
	rec2 := telemetrytest.New()
	if err := New(&fakeRunner{rows: extra}, store, "tenant-a", nil).Collect(context.Background(), rec2.Emitter()); err != nil {
		t.Fatalf("poll 2: %v", err)
	}
	logs := rec2.LogRecords()
	if len(logs) != 1 {
		t.Fatalf("poll 2 emitted %d twins, want 1 (only the new event)", len(logs))
	}
	if logs[0].Attrs[semconv.AttrElevationId] != "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff" {
		t.Errorf("wrong event emitted: %+v", logs[0].Attrs)
	}
}

// TestUnparseableEventTimeIsDropped: a row whose EventDateTime cannot be parsed
// is dropped, never emitted stamped-now (which would misdate it — the emitter
// rule). A missing Id is likewise undedupeable → dropped.
func TestUnparseableEventTimeIsDropped(t *testing.T) {
	rows := []exportjob.Row{
		{"Id": "good", "EventDateTime": "2026-07-19 19:10:54.0000000", "ElevationType": "UnmanagedElevation", "Result": "0"},
		{"Id": "bad-time", "EventDateTime": "not-a-date", "ElevationType": "UnmanagedElevation", "Result": "0"},
		{"Id": "", "EventDateTime": "2026-07-19 19:10:54.0000000", "ElevationType": "UnmanagedElevation", "Result": "0"},
	}
	c := New(&fakeRunner{rows: rows}, newStore(t), "tenant-a", nil)
	rec := telemetrytest.New()
	if err := c.Collect(context.Background(), rec.Emitter()); err != nil {
		t.Fatalf("Collect: %v", err)
	}
	logs := rec.LogRecords()
	if len(logs) != 1 {
		t.Fatalf("got %d twins, want 1 (bad-time and empty-id dropped)", len(logs))
	}
	if logs[0].Attrs[semconv.AttrElevationId] != "good" {
		t.Errorf("wrong row survived: %+v", logs[0].Attrs)
	}
}

func TestCollectStampsReportExportTransport(t *testing.T) {
	c := New(&fakeRunner{rows: liveRows()}, newStore(t), "tenant-a", nil)
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
			c := New(&fakeRunner{err: tc.err}, newStore(t), "tenant-a", nil)
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

func TestCollectSkipsWhenExportOrStoreNil(t *testing.T) {
	for _, tc := range []struct {
		name   string
		runner exportjob.Runner
		store  *checkpoint.Store
	}{
		{"nil export", nil, checkpoint.NewStore(t.TempDir())},
		{"nil store", &fakeRunner{rows: liveRows()}, nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := New(tc.runner, tc.store, "tenant-a", nil)
			rec := telemetrytest.New()
			if err := c.Collect(context.Background(), rec.Emitter()); err != nil {
				t.Fatalf("Collect: %v", err)
			}
			if len(rec.MetricPoints(metricName)) != 0 || len(rec.LogRecords()) != 0 {
				t.Error("expected no emissions")
			}
		})
	}
}

func TestCollectEmptyReportEmitsNothing(t *testing.T) {
	c := New(&fakeRunner{rows: nil}, newStore(t), "tenant-a", nil)
	rec := telemetrytest.New()
	if err := c.Collect(context.Background(), rec.Emitter()); err != nil {
		t.Fatalf("Collect: %v", err)
	}
	if len(rec.MetricPoints(metricName)) != 0 || len(rec.LogRecords()) != 0 {
		t.Error("expected no emissions on empty report")
	}
}

func TestCollectorContract(t *testing.T) {
	c := New(nil, nil, "", nil)
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
