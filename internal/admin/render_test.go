package admin

import (
	"strings"
	"testing"
)

// renderString renders s to HTML and fails the test on any template error.
func renderString(t *testing.T, s Status) string {
	t.Helper()
	var b strings.Builder
	if err := render(&b, s); err != nil {
		t.Fatalf("render: %v", err)
	}
	return b.String()
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
		"Why not healthy", "last run failed", // health reasons block
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
