package admin

import (
	"strings"
	"testing"
)

// renderString renders s to HTML and fails the test on any template error.
func renderString(t *testing.T, s Status) string {
	t.Helper()
	var b strings.Builder
	if err := render(&b, pageModel{Status: s}); err != nil {
		t.Fatalf("render: %v", err)
	}
	return b.String()
}

// TestRender_RefreshMs asserts the configurable auto-refresh interval is
// rendered into the page (and consumed by the poll loop).
func TestRender_RefreshMs(t *testing.T) {
	body := renderString(t, Status{Service: ServiceInfo{Version: "0.1.0"}, Health: healthHealthy, RefreshMs: 3000})
	i := strings.Index(body, "__refreshMs")
	if i < 0 || !strings.Contains(body[i:i+40], "3000") {
		t.Fatalf("refresh interval 3000 not rendered into page")
	}
}

// TestRender_TabbedShellAndLayout locks the fleet-aligned single-page shell:
// tabs, theme toggle, pause/resume, disconnect banner, freshness ticker, the
// ~90%-viewport wide collectors table, and throttle-headroom placed ABOVE the
// collector tables (#206).
func TestRender_TabbedShellAndLayout(t *testing.T) {
	s := Status{
		Service: ServiceInfo{Version: "0.1.0"}, Health: healthHealthy,
		Tenants: []TenantStatus{{
			TenantID:     "t-a",
			EnabledCount: 1,
			Collectors:   []CollectorStatus{{Name: "devices", Enabled: true, HasRun: true, LastSuccess: true, IntervalSec: 300}},
			RateLimits:   []RateLimitStatus{{Workload: "graph", LimitPerSec: 10, Burst: 20, Tokens: 15, HeadroomPct: 75}},
		}},
	}
	body := renderString(t, s)
	for _, want := range []string{
		`data-tab="overview"`, `data-tab="collectors"`,
		`id="themeToggle"`, `id="pauseBtn"`, `id="staleBanner"`, `id="tabs"`,
		"graph2otel-theme", `class="wide"`, "Throttle headroom",
		"function showTab", "function toggleTheme", "function refresh",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("page missing %q", want)
		}
	}
	// Throttle headroom must appear before the collectors table (top of page).
	if ti, ci := strings.Index(body, "Throttle headroom"), strings.Index(body, `data-tab="collectors"`); ti < 0 || ci < 0 || ti > ci {
		t.Errorf("throttle headroom (%d) should precede the collectors tab (%d)", ti, ci)
	}
}

func TestRender_ZeroCollectors(t *testing.T) {
	// A minimal snapshot with no tenants must still render a complete page.
	s := Status{
		Service:     ServiceInfo{Version: "0.1.0", GoVersion: "go1.24"},
		Health:      healthHealthy,
		GeneratedAt: "2026-07-16T12:00:00Z",
	}
	body := renderString(t, s)
	for _, want := range []string{"<html", "graph2otel", "No tenants configured", "healthy", "0.1.0"} {
		if !strings.Contains(body, want) {
			t.Errorf("body missing %q", want)
		}
	}
}

func TestRender_MultiTenantWithSkipReasons(t *testing.T) {
	s := Status{
		Service: ServiceInfo{Version: "0.1.0", GoVersion: "go1.24", Uptime: "5m0s"},
		Health:  healthDegraded,
		HealthReasons: []string{
			`tenant "t-a" collector "devices": last run failed`,
		},
		Tenants: []TenantStatus{
			{
				TenantID:     "t-a",
				EnabledCount: 1,
				FailingCount: 1,
				Collectors: []CollectorStatus{
					{
						Name: "devices", Enabled: true, HasRun: true, LastSuccess: false,
						IntervalSec: 3600, Runs: 4, Failures: 1, ConsecutiveFailures: 1,
						LastError: "boom", NextRunInSec: 120, NextRunIn: "2m0s",
						Staleness: "1m0s", LastDurationMs: 42,
						DurationMsSeries: []int64{40, 44, 42}, OutcomeSeries: []bool{true, true, false},
					},
				},
			},
			{
				TenantID:     "t-b",
				EnabledCount: 1,
				PendingCount: 1,
				SkippedCount: 3,
				Collectors: []CollectorStatus{
					{Name: "signins", Enabled: true, HasRun: false, IntervalSec: 300},
					{Name: "riskyusers", SkipReason: "requires entra_p2", SkipCategory: skipCatLicense},
					{Name: "auditbeta", SkipReason: "beta; enable explicitly to opt in", SkipCategory: skipCatExperimental},
					{Name: "signins_off", SkipReason: "disabled by config", SkipCategory: skipCatDisabled},
				},
			},
		},
		GeneratedAt: "2026-07-16T12:00:00Z",
	}
	body := renderString(t, s)

	wants := []string{
		"t-a", "t-b", // both tenants
		"devices", "signins", "riskyusers", "auditbeta", "signins_off",
		"requires entra_p2", "beta; enable explicitly to opt in", "disabled by config",
		skipCatLicense, skipCatExperimental, skipCatDisabled, // category badge labels
		"last run failed",                                // health reason rendered in the reasons bar
		"<svg class=\"spark\"", `<span class="outcome">`, // sparkline + outcome strip
		"2m0s",     // next-run
		"failing",  // failing state badge
		"starting", // pending state badge
	}
	for _, want := range wants {
		if !strings.Contains(body, want) {
			t.Errorf("body missing %q", want)
		}
	}
}

// A covered-but-off collector must render as "collected via <twin>", never as a
// bare "disabled"/gap; a genuinely-off collector still reads "skipped"; and an
// enabled collector shows its ingest transport (#178 Part A).
func TestRender_TransportAndCoverage(t *testing.T) {
	s := Status{
		Service: ServiceInfo{Version: "0.1.0", GoVersion: "go1.24"},
		Health:  healthHealthy,
		Tenants: []TenantStatus{{
			TenantID: "t", EnabledCount: 1, SkippedCount: 2,
			Collectors: []CollectorStatus{
				// enabled, ingesting over blob (a source=blob collector).
				{Name: "entra.directory_audits", Enabled: true, HasRun: true, LastSuccess: true,
					IntervalSec: 300, Runs: 3, Transport: "blob"},
				// off, but covered by a registered blob twin -> not a gap.
				{Name: "entra.signins.non_interactive", Enabled: false,
					SkipReason: "beta; enable explicitly to opt in", SkipCategory: skipCatExperimental,
					CoveredBy: &Coverage{Collector: "entra.signins.non_interactive.blob", Transport: "blob"}},
				// off, no covering twin -> honest gap.
				{Name: "entra.identityprotection", Enabled: false,
					SkipReason: "requires entra_p2", SkipCategory: skipCatLicense},
			},
		}},
		GeneratedAt: "2026-07-16T12:00:00Z",
	}
	body := renderString(t, s)

	wants := []string{
		"via blob",                           // enabled row transport chip
		"collected via",                      // covered row copy
		"entra.signins.non_interactive.blob", // named twin
		"polled form off by design",          // covered secondary note
		"covered",                            // covered badge
		"skipped &mdash; requires entra_p2",  // genuine gap still reads "skipped"
	}
	for _, want := range wants {
		if !strings.Contains(body, want) {
			t.Errorf("body missing %q", want)
		}
	}
	// The covered collector must NOT be dressed as a plain skip.
	if strings.Contains(body, "skipped &mdash; beta; enable explicitly to opt in") {
		t.Errorf("covered collector rendered as a bare skip; should read 'collected via'")
	}
}

// A registered collector's durable checkpoint state renders inline under its
// name: a window poller shows watermark + staleness (+ seen/job); a blob
// consumer shows byte offset + blobs + newest hour (#178 Part B).
func TestRender_CheckpointState(t *testing.T) {
	s := Status{
		Service: ServiceInfo{Version: "0.1.0", GoVersion: "go1.24"},
		Health:  healthHealthy,
		Tenants: []TenantStatus{{
			TenantID: "t", EnabledCount: 2,
			Collectors: []CollectorStatus{
				{Name: "entra.signins", Enabled: true, HasRun: true, LastSuccess: true, IntervalSec: 300, Runs: 3,
					Transport: "graph", State: &CollectorState{
						Kind: "window", Watermark: "2026-07-19T12:00:00Z", StalenessSec: 300, Staleness: "5m0s",
						SeenIDs: 4, InFlightJob: "job-1",
					}},
				{Name: "entra.signins.blob", Enabled: true, HasRun: true, LastSuccess: true, IntervalSec: 300, Runs: 3,
					Transport: "blob", State: &CollectorState{
						Kind: "blob", ByteOffset: 4096, BlobsTracked: 2, NewestBlob: "h=05/x.json",
					}},
			},
		}},
		GeneratedAt: "2026-07-19T12:00:00Z",
	}
	body := renderString(t, s)

	wants := []string{
		"watermark 2026-07-19T12:00:00Z", // window watermark
		"5m0s behind",                    // window staleness
		"4 seen",                         // window seen-ids
		"job-1",                          // in-flight job id
		"cursor 4096B",                   // blob byte offset
		"2 blobs",                        // blob count
		"newest",                         // newest-hour label
		"h=05/x.json",                    // newest blob name
	}
	for _, want := range wants {
		if !strings.Contains(body, want) {
			t.Errorf("body missing %q", want)
		}
	}
}

// A tenant with RateLimits renders the throttle-headroom panel; a tenant with
// none renders no panel at all (#85).
func TestRender_ThrottleHeadroomPanel(t *testing.T) {
	s := Status{
		Service: ServiceInfo{Version: "0.1.0", GoVersion: "go1.24"},
		Health:  healthHealthy,
		Tenants: []TenantStatus{
			{
				TenantID: "t-a", EnabledCount: 1,
				Collectors: []CollectorStatus{{Name: "c", Enabled: true, HasRun: true, LastSuccess: true, IntervalSec: 300}},
				RateLimits: []RateLimitStatus{
					{Workload: "reporting", LimitPerSec: 0.5, Burst: 5, Tokens: 2.5, HeadroomPct: 50},
				},
			},
			{
				TenantID: "t-idle", EnabledCount: 1,
				Collectors: []CollectorStatus{{Name: "c", Enabled: true, HasRun: true, LastSuccess: true, IntervalSec: 300}},
			},
		},
		GeneratedAt: "2026-07-19T12:00:00Z",
	}
	body := renderString(t, s)
	for _, want := range []string{"Throttle headroom", "reporting", "50%"} {
		if !strings.Contains(body, want) {
			t.Errorf("body missing %q", want)
		}
	}
	// The idle tenant contributes no second panel: exactly one "Throttle headroom".
	if n := strings.Count(body, "Throttle headroom"); n != 1 {
		t.Errorf("Throttle headroom panels = %d, want 1 (idle tenant renders none)", n)
	}
}

func TestRender_OverdueBadge(t *testing.T) {
	s := Status{
		Service: ServiceInfo{Version: "0.1.0", GoVersion: "go1.24"},
		Health:  healthHealthy,
		Tenants: []TenantStatus{{
			TenantID: "t-a", EnabledCount: 1,
			Collectors: []CollectorStatus{{
				Name: "wedged", Enabled: true, HasRun: true, LastSuccess: true,
				IntervalSec: 300, Overdue: true, Runs: 2,
			}},
		}},
		GeneratedAt: "2026-07-16T12:00:00Z",
	}
	if !strings.Contains(renderString(t, s), "overdue") {
		t.Errorf("body missing overdue badge")
	}
}

func TestSparkline_Empty(t *testing.T) {
	if got := sparkline(nil); got != "" {
		t.Errorf("sparkline(nil) = %q, want empty", got)
	}
	if got := sparkline([]int64{5}); got != "" {
		t.Errorf("sparkline(single) = %q, want empty (needs >=2 points)", got)
	}
	if got := sparkline([]int64{1, 2, 3}); !strings.Contains(string(got), "<polyline") {
		t.Errorf("sparkline(3) = %q, want a polyline", got)
	}
}

func TestOutcomeStrip(t *testing.T) {
	if got := outcomeStrip(nil); got != "" {
		t.Errorf("outcomeStrip(nil) = %q, want empty", got)
	}
	got := string(outcomeStrip([]bool{true, false}))
	if !strings.Contains(got, `<i></i>`) || !strings.Contains(got, `<i class="f"></i>`) {
		t.Errorf("outcomeStrip = %q, want ok and fail ticks", got)
	}
}

// TestRender_NoTimeDependence guards that render never panics on a fully
// zero-valued CollectorStatus (defensive: an unrun, no-history row).
func TestRender_NoTimeDependence(t *testing.T) {
	s := Status{
		Service: ServiceInfo{Version: "0.1.0"},
		Health:  healthStarting,
		Tenants: []TenantStatus{{TenantID: "t", EnabledCount: 1, PendingCount: 1,
			Collectors: []CollectorStatus{{Name: "c", Enabled: true}}}},
	}
	_ = renderString(t, s)
}

// TestRender_TrendChartsAndCards locks the Overview tab's trend sections
// (#227): every chart id the JS registers must exist in the markup, or
// registerChart silently binds to nothing and the chart never draws.
func TestRender_TrendChartsAndCards(t *testing.T) {
	s := Status{
		Service: ServiceInfo{Version: "0.1.0"}, Health: healthHealthy,
		Runtime: RuntimeInfo{
			Goroutines: 42, GOMAXPROCS: 8, HeapAlloc: "12M", HeapAllocBytes: 12 << 20, NumGC: 7,
			GoroutinesSeries: []int{40, 42}, HeapAllocSeries: []uint64{1, 2}, GCRateSeries: []float64{0.5},
		},
		Throughput: ThroughputInfo{
			MetricPointsPerSec: 12.5, LogRecordsPerSec: 3,
			MetricPointsSeries: []float64{10, 12.5}, LogRecordsSeries: []float64{2, 3},
		},
		Fleet:       FleetInfo{Enabled: 58, Failing: 1, Pending: 0, MeanDurationMs: 431.5},
		SeriesTrend: CardinalityTrend{TotalSeries: 1200, Series: []int{1100, 1200}},
	}
	body := renderString(t, s)

	for _, want := range []string{
		"Runtime trend", "Throughput &amp; fleet trend",
		`id="chGoroutines"`, `id="chHeap"`, `id="chGC"`,
		`id="chEmit"`, `id="chCard"`, `id="chFailing"`, `id="chDuration"`,
		`id="goroutines"`, `id="heapAlloc"`, `id="numGC"`, `id="gcRate"`,
		`id="metricRate"`, `id="logRate"`, `id="activeSeries"`, `id="fleetFailing"`, `id="meanDuration"`,
		"function registerChart", "function drawChart", "function redrawCharts",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("page missing %q", want)
		}
	}

	// Every chart the JS registers must have a matching element in the markup.
	for _, id := range []string{"chGoroutines", "chHeap", "chGC", "chEmit", "chCard", "chFailing", "chDuration"} {
		if !strings.Contains(body, "registerChart('"+id+"'") {
			t.Errorf("chart %q has markup but is never registered", id)
		}
	}

	// The server-rendered (noscript) values must be present, so the page is
	// meaningful before the first poll completes.
	for _, want := range []string{">42<", ">12M<", ">58<"} {
		if !strings.Contains(body, want) {
			t.Errorf("page missing server-rendered value %q", want)
		}
	}
}

// TestRender_ThrottleHeadroomSparkline asserts each throttle row carries its
// headroom trend, so a bucket that is draining is visible as a slope and not
// only as a single instantaneous percentage.
func TestRender_ThrottleHeadroomSparkline(t *testing.T) {
	s := Status{
		Service: ServiceInfo{Version: "0.1.0"}, Health: healthHealthy,
		Tenants: []TenantStatus{{
			TenantID: "t-a",
			RateLimits: []RateLimitStatus{{
				Workload: "reporting", LimitPerSec: 0.5, Burst: 5, Tokens: 2.5, HeadroomPct: 50,
				HeadroomSeries: []float64{100, 80, 50},
			}},
		}},
	}
	body := renderString(t, s)
	if !strings.Contains(body, ">trend<") {
		t.Errorf("throttle table missing the trend column header")
	}
	if !strings.Contains(body, `class="spark"`) {
		t.Errorf("throttle row missing its headroom sparkline")
	}
}
