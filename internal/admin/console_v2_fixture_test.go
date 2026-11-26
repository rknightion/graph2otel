package admin

import (
	"github.com/rknightion/graph2otel/internal/availability"
	"github.com/rknightion/graph2otel/internal/telemetry"
)

// richStatus is a fabricated, identifier-free status that exercises every
// section of the page: every availability state, a failing row, a covered row,
// skip categories, throttle rows, trends, delivery, capacity and cost.
func richStatus() Status {
	states := []availability.State{
		availability.StateHealthy, availability.StateHealthyEmpty, availability.StateLimited,
		availability.StateDegraded, availability.StateBlocked, availability.StateFailed,
		availability.StateStartupFailed, availability.StateCovered, availability.StateDisabled,
		availability.StateStarting,
	}
	rows := []CollectorStatus{
		{Name: "devices", Enabled: true, HasRun: true, LastSuccess: true, IntervalSec: 300, Runs: 12,
			DurationMsSeries: []int64{10, 20, 15}, OutcomeSeries: []bool{true, true, false}},
		{Name: "signins", Enabled: true, HasRun: true, LastSuccess: false, Failures: 3, ConsecutiveFailures: 3, IntervalSec: 300, LastError: "boom"},
		{Name: "riskyusers", SkipReason: "requires entra_p2", SkipCategory: skipCatLicense},
		{Name: "auditbeta", SkipReason: "beta; enable explicitly to opt in", SkipCategory: skipCatExperimental},
		{Name: "off", SkipReason: "disabled by config", SkipCategory: skipCatDisabled},
	}
	for _, st := range states {
		rows = append(rows, CollectorStatus{
			Name: "state." + string(st), Enabled: st != availability.StateDisabled && st != availability.StateCovered,
			Availability: &CollectorAvailability{State: st, Reason: availability.Reason("reason")},
		})
	}
	return Status{
		Service: ServiceInfo{Version: "0.1.0", GoVersion: "go1.24", StartedAt: "2026-01-01T00:00:00Z", Uptime: "1h0m0s"},
		Health:  healthDegraded, HealthReasons: []string{"a collector failed"},
		Readiness: ReadinessStatus{Ready: true, State: "ready"},
		Tenants: []TenantStatus{{
			TenantID: "tenant-a", EnabledCount: 2, FailingCount: 1, Collectors: rows,
			RateLimits: []RateLimitStatus{
				{Workload: "reporting", LimitPerSec: 0.5, Burst: 5, Tokens: 4, HeadroomPct: 80, HeadroomSeries: []float64{100, 90, 80}},
				{Workload: "ipc", LimitPerSec: 1, Burst: 5, Tokens: 1, HeadroomPct: 10, HeadroomSeries: []float64{40, 20, 10}},
			},
		}},
		Runtime:     RuntimeInfo{Goroutines: 42, GOMAXPROCS: 8, HeapAlloc: "12M", NumGC: 7, GoroutinesSeries: []int{40, 42}},
		Throughput:  ThroughputInfo{MetricPointsPerSec: 12.5, LogRecordsPerSec: 3},
		Fleet:       FleetInfo{Enabled: 5, Failing: 1},
		SeriesTrend: CardinalityTrend{TotalSeries: 100, Series: []int{90, 100}},
		Delivery: &DeliveryStatus{
			Metrics: DeliverySignalStatus{State: telemetry.DeliveryStateHealthy, ExportAttempts: 4, ExportSuccesses: 4},
			Logs:    DeliverySignalStatus{State: telemetry.DeliveryStateDegraded, ExportAttempts: 4, ExportSuccesses: 3, ExportFailures: 1, ShutdownFailures: 1},
		},
		GeneratedAt: "2026-01-01T01:00:00Z",
	}
}
