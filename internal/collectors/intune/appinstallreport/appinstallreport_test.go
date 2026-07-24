package appinstallreport

import (
	"context"
	"errors"
	"fmt"
	"testing"

	"github.com/rknightion/graph2otel/internal/exportjob"
	"github.com/rknightion/graph2otel/internal/semconv"
	"github.com/rknightion/graph2otel/internal/telemetry"
	"github.com/rknightion/graph2otel/internal/telemetrytest"
	"github.com/rknightion/graph2otel/internal/wirecheck"
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

// livePlatformLoc is the EXACT Platform -> Platform_loc pairing the live
// AppInstallStatusAggregate export returns, probed as graph2otel-poller on
// 2026-07-17 (#142). Every fixture below builds its Platform_loc from this
// map rather than a hand-written string, so no test in this file can assert a
// value the API has never sent.
//
// Note 2 is iOS and 5 is Windows: the codes are NOT in an order anyone would
// have guessed, which is precisely why they must come from the wire.
var livePlatformLoc = map[string]string{
	"1": "Android",
	"2": "iOS",
	"3": "MacOS",
	"5": "Windows",
}

// row builds one AppInstallStatusAggregate row exactly as the live export
// returns it (#142, live 2026-07-17): platformCode is a NUMERIC CODE, and
// Microsoft returns a localized Platform_loc sibling alongside it whether or
// not it was selected.
//
// An earlier version of this helper took a display string ("windows", "ios")
// and emitted no _loc sibling at all. That fixture was fiction - the export
// has never sent it - and it is the reason platform="2" shipped to production
// green (#142). Pass codes here, never names.
func row(displayName, applicationID, platformCode string, installed, failed, notApplicable, notInstalled, pending int) exportjob.Row {
	return exportjob.Row{
		"DisplayName":               displayName,
		"ApplicationId":             applicationID,
		"Platform":                  platformCode,
		"Platform_loc":              livePlatformLoc[platformCode],
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
		row("Contoso Agent", "app-1", "5", 10, 2, 1, 3, 0),
		row("Widget Tool", "app-2", "2", 5, 0, 0, 0, 4),
		row("Fabrikam Helper", "app-3", "5", 1, 1, 0, 0, 0),
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
	c := New(&fakeRunner{rows: []exportjob.Row{row("Contoso Agent", "app-1", "5", 1, 0, 0, 0, 0)}}, nil)
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
		rows = append(rows, row(fmt.Sprintf("Store App %d", i), fmt.Sprintf("app-%d", i), "5", i, 0, 0, 0, 0))
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
		row("Contoso Agent", "app-1", "5", 10, 2, 1, 3, 0),
		row("Widget Tool", "app-2", "2", 5, 0, 0, 0, 4),
		row("Fabrikam Helper", "app-3", "5", 1, 1, 0, 0, 0),
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
		"app_name": "Contoso Agent",
		"app_id":   "app-1",
		// platform is the DECODED name and platform_code the raw wire value.
		// Before #142 this asserted "windows" against a fixture that fed
		// "windows" in - so it passed while production shipped platform="2".
		"platform":                     "windows",
		"platform_code":                "5",
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
	r := row("Contoso Agent", "app-1", "5", 1, 0, 0, 0, 0)
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
	r := row("Contoso Agent", "app-1", "5", 10, 2, 1, 3, 0)
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

// TestPlatformDecodesEveryLiveWireCode is the #142 regression guard, and the
// only test here whose expectations come from the wire rather than from this
// package's own source.
//
// Probed as graph2otel-poller against AppInstallStatusAggregate on 2026-07-17:
// Platform returned exactly ['1','2','3','5'] across 371 rows, paired with
// Platform_loc ['Android','iOS','MacOS','Windows'] respectively. If Microsoft
// ever adds a code, this test still passes (it asserts the known set decodes,
// not that the set is closed) - the unknown-code path below covers that.
func TestPlatformDecodesEveryLiveWireCode(t *testing.T) {
	// The live Platform -> canonical label mapping. Keys and the _loc column
	// they were derived from are wire-measured; the canonical values are this
	// project's stable snake_case rendering of them.
	cases := []struct{ code, wantName, liveLoc string }{
		{"1", "android", "Android"},
		{"2", "ios", "iOS"},
		{"3", "macos", "MacOS"},
		{"5", "windows", "Windows"},
	}
	for _, tc := range cases {
		t.Run(tc.code, func(t *testing.T) {
			if got := livePlatformLoc[tc.code]; got != tc.liveLoc {
				t.Fatalf("fixture drift: livePlatformLoc[%q] = %q, want the wire value %q", tc.code, got, tc.liveLoc)
			}
			c := New(&fakeRunner{rows: []exportjob.Row{row("App", "app-1", tc.code, 1, 0, 0, 0, 0)}}, nil)
			rec := telemetrytest.New()
			if err := c.Collect(context.Background(), rec.Emitter()); err != nil {
				t.Fatalf("Collect returned error: %v", err)
			}

			for _, p := range rec.MetricPoints(installationsMetricName) {
				if got := p.Attrs["platform"]; got != tc.wantName {
					t.Errorf("metric label platform = %q, want %q - a raw code must never reach a metric label (#142)", got, tc.wantName)
				}
			}

			logs := rec.LogRecords()
			if len(logs) != 1 {
				t.Fatalf("got %d logs, want 1", len(logs))
			}
			if got := logs[0].Attrs["platform"]; got != tc.wantName {
				t.Errorf("log attr platform = %q, want %q", got, tc.wantName)
			}
			// The raw code is emitted unconditionally and losslessly, per the
			// house pattern (m365/activity's record_type_id): Microsoft's
			// published tables have not covered every live value on this
			// project, so the code must survive a decode miss.
			if got := logs[0].Attrs["platform_code"]; got != tc.code {
				t.Errorf("log attr platform_code = %q, want the raw wire code %q", got, tc.code)
			}
		})
	}
}

// TestPlatformUnknownCodeKeepsRawCodeAndStaysBounded pins the decode-miss path:
// a code absent from the table must not invent a name, must not grow the label
// set, and must not lose the raw value - the log twin stays the record of what
// the wire actually said.
func TestPlatformUnknownCodeKeepsRawCodeAndStaysBounded(t *testing.T) {
	c := New(&fakeRunner{rows: []exportjob.Row{row("Future App", "app-9", "99", 1, 0, 0, 0, 0)}}, nil)
	rec := telemetrytest.New()
	if err := c.Collect(context.Background(), rec.Emitter()); err != nil {
		t.Fatalf("Collect returned error: %v", err)
	}

	for _, p := range rec.MetricPoints(installationsMetricName) {
		if got := p.Attrs["platform"]; got != platformUnknown {
			t.Errorf("metric label platform = %q for unknown code 99, want %q - an unmapped code must bucket, never pass through", got, platformUnknown)
		}
	}

	logs := rec.LogRecords()
	if len(logs) != 1 {
		t.Fatalf("got %d logs, want 1", len(logs))
	}
	if got := logs[0].Attrs["platform_code"]; got != "99" {
		t.Errorf("log attr platform_code = %q, want %q - the raw code must survive a decode miss (#142)", got, "99")
	}
	if got := logs[0].Attrs["platform"]; got != platformUnknown {
		t.Errorf("log attr platform = %q, want %q - never invent a name for an unmapped code", got, platformUnknown)
	}
}

// --- wire-assumption watchdog (#233/#234) --------------------------------
//
// platform is a METRIC LABEL and platformNames is a LIVE-MEASURED code table
// (2026-07-17, #142). The announce log above makes a decode miss diagnosable
// but not ALERTABLE — nothing counts it — so a new Microsoft code silently
// moves installs into "unknown". The bounded counter closes that; the announce
// log stays, because it carries the _loc sibling that names the new code.

func TestUnmappedPlatformCodeIsCounted(t *testing.T) {
	c := New(&fakeRunner{rows: []exportjob.Row{row("Future App", "app-9", "99", 1, 0, 0, 0, 0)}}, nil)
	rec := telemetrytest.New()
	if err := c.Collect(context.Background(), rec.Emitter()); err != nil {
		t.Fatalf("Collect returned error: %v", err)
	}

	pts := rec.MetricPoints(wirecheck.MetricUnexpected)
	if len(pts) != 1 {
		t.Fatalf("got %d %s points, want 1", len(pts), wirecheck.MetricUnexpected)
	}
	if got := pts[0].Attrs[semconv.AttrKind]; got != wirecheck.KindUnmappedValue {
		t.Errorf("kind = %q, want %q", got, wirecheck.KindUnmappedValue)
	}
	if got := pts[0].Attrs[semconv.AttrField]; got != semconv.AttrPlatformCode {
		t.Errorf("field = %q, want %q", got, semconv.AttrPlatformCode)
	}
	// Report-only: the row still counts toward the installations gauge.
	if len(rec.MetricPoints(installationsMetricName)) == 0 {
		t.Error("an unmapped platform code must not stop the collector emitting")
	}
}

// A live-measured code must stay quiet, or the watchdog fires on every row of a
// healthy tenant and gets muted.
func TestMappedPlatformCodeIsNotCounted(t *testing.T) {
	c := New(&fakeRunner{rows: []exportjob.Row{row("Teams", "app-1", "5", 1, 0, 0, 0, 0)}}, nil)
	rec := telemetrytest.New()
	if err := c.Collect(context.Background(), rec.Emitter()); err != nil {
		t.Fatalf("Collect returned error: %v", err)
	}
	if got := len(rec.MetricPoints(wirecheck.MetricUnexpected)); got != 0 {
		t.Errorf("a live-measured platform code produced %d findings, want 0", got)
	}
}

// TestPlatformLocSiblingIsNeverUsedAsALabel pins the #142 design decision that
// cost a live probe to establish, so a later reader cannot "simplify" it away.
//
// Platform_loc is LOCALIZED. Probed 2026-07-17 by replaying the same export job
// under four Accept-Language values: code 3 came back "MacOS" under en/fr-FR
// but "macOS" under de-DE/ja-JP. Reading _loc into a metric label therefore
// makes the series set a function of a request header - two series for one
// platform. The decode is keyed off the stable numeric code for that reason.
//
// This fixture feeds a _loc casing the en-US wire never sends; the label must
// be unmoved by it.
func TestPlatformLocSiblingIsNeverUsedAsALabel(t *testing.T) {
	r := row("App", "app-1", "3", 1, 0, 0, 0, 0)
	r["Platform_loc"] = "macOS" // the de-DE/ja-JP casing, live 2026-07-17
	c := New(&fakeRunner{rows: []exportjob.Row{r}}, nil)
	rec := telemetrytest.New()
	if err := c.Collect(context.Background(), rec.Emitter()); err != nil {
		t.Fatalf("Collect returned error: %v", err)
	}

	for _, p := range rec.MetricPoints(installationsMetricName) {
		if got := p.Attrs["platform"]; got != "macos" {
			t.Errorf("metric label platform = %q, want %q - the label must derive from the stable Platform code, never the locale-dependent Platform_loc (#142)", got, "macos")
		}
	}
}

// TestCollectStampsReportExportTransport pins that this collector names its own
// transport (#141).
//
// The stamp is here, on the collector, rather than in an engine — and that is
// forced, not a shortcut. internal/exportjob has ZERO LogEvent call sites: it
// creates, polls, and downloads a job, then hands rows back for the collector to
// emit. So there is no engine seam to stamp report_export from, and without this
// the Scheduler's "graph" baseline would be the only stamp these rows ever got,
// which would be a confident lie about a transport that is not Graph polling.
func TestCollectStampsReportExportTransport(t *testing.T) {
	c := New(&fakeRunner{rows: []exportjob.Row{row("Contoso Agent", "app-1", "5", 10, 2, 1, 3, 0)}}, nil)
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
