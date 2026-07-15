package admin

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/rknightion/graph2otel/internal/collector"
)

// Health states surfaced on the admin status page.
const (
	healthHealthy  = "healthy"
	healthDegraded = "degraded"
	healthStarting = "starting"
)

// consecutiveFailureThreshold is the number of back-to-back failures at which
// a collector drags overall health to "degraded".
const consecutiveFailureThreshold = 3

// CollectorSource pairs one tenant's registered collectors with the
// StatusTracker its Scheduler records into. The admin package never keeps its
// own copy of run state — it renders a fresh Snapshot()/HistorySnapshot() of
// these on every request.
type CollectorSource struct {
	// TenantID identifies which tenant this Registry/Status pair belongs to
	// (graph2otel runs one Scheduler, Registry and StatusTracker per tenant).
	TenantID string
	Registry *collector.Registry
	Status   *collector.StatusTracker
}

// SkipKey identifies a collector that the composition root chose not to
// register for a tenant (e.g. a missing Graph permission or license tier).
type SkipKey struct {
	TenantID  string
	Collector string
}

// Status is the full admin status snapshot, serialized as JSON at
// /api/status.json and rendered as HTML at "/".
type Status struct {
	Service       ServiceInfo    `json:"service"`
	Health        string         `json:"health"`
	HealthReasons []string       `json:"health_reasons,omitempty"`
	Tenants       []TenantStatus `json:"tenants"`
	GeneratedAt   string         `json:"generated_at"`
}

// ServiceInfo is the process identity/liveness header of the page.
type ServiceInfo struct {
	Version   string `json:"version"`
	GoVersion string `json:"go_version"`
	StartedAt string `json:"started_at"`
	UptimeSec int64  `json:"uptime_seconds"`
	Uptime    string `json:"uptime"`
}

// TenantStatus is one tenant's collector table.
type TenantStatus struct {
	TenantID   string            `json:"tenant_id"`
	Collectors []CollectorStatus `json:"collectors"`
}

// CollectorStatus is one row of a tenant's collector table: either a
// registered collector's latest run state, or a skipped collector's reason.
type CollectorStatus struct {
	Name string `json:"name"`
	// Enabled is false for a collector the composition root chose not to
	// register at all; SkipReason then explains why (e.g. "requires P2").
	Enabled     bool   `json:"enabled"`
	SkipReason  string `json:"skip_reason,omitempty"`
	IntervalSec int64  `json:"interval_seconds,omitempty"`

	HasRun         bool   `json:"has_run"`
	Runs           int64  `json:"runs"`
	Failures       int64  `json:"failures"`
	LastStartedAt  string `json:"last_started_at,omitempty"`
	LastFinishedAt string `json:"last_finished_at,omitempty"`
	LastDurationMs int64  `json:"last_duration_ms"`
	LastSuccess    bool   `json:"last_success"`
	LastError      string `json:"last_error,omitempty"`
	// ConsecutiveFailures is the current unbroken run of failures (0 on the
	// last success). SuccessRatePct is (runs-failures)/runs over the process
	// lifetime.
	ConsecutiveFailures int64   `json:"consecutive_failures"`
	SuccessRatePct      float64 `json:"success_rate_pct"`
	// StalenessSec/Staleness are the time since the last run attempt
	// (success or failure) — not specifically the last success, since
	// CollectorRun keeps only the most recent run's outcome.
	StalenessSec int64  `json:"staleness_seconds,omitempty"`
	Staleness    string `json:"staleness,omitempty"`
	// DurationMsSeries/OutcomeSeries are the recent-run history (oldest
	// first, aligned), feeding a duration sparkline and outcome strip.
	DurationMsSeries []int64 `json:"duration_ms_series,omitempty"`
	OutcomeSeries    []bool  `json:"outcome_series,omitempty"`
}

// buildTenantStatuses renders sources into one TenantStatus per source: a row
// per registered collector (from Registry.Entries(), reflecting the matching
// StatusTracker snapshot) plus a row per skip reason that names a collector
// the registry has no entry for. Tenants are returned in the order given;
// within a tenant, registered collectors keep registration order and skipped
// collectors are appended sorted by name for deterministic output.
func buildTenantStatuses(sources []CollectorSource, skipReasons map[SkipKey]string, now time.Time) []TenantStatus {
	tenants := make([]TenantStatus, 0, len(sources))
	for _, src := range sources {
		runs := src.Status.Snapshot()
		hist := src.Status.HistorySnapshot()

		var entries []collector.Entry
		if src.Registry != nil {
			entries = src.Registry.Entries()
		}
		registered := make(map[string]bool, len(entries))
		rows := make([]CollectorStatus, 0, len(entries))
		for _, e := range entries {
			name := e.Collector.Name()
			registered[name] = true
			rows = append(rows, collectorStatusFor(name, e.Interval, runs, hist, now))
		}

		var skipNames []string
		for key := range skipReasons {
			if key.TenantID != src.TenantID || registered[key.Collector] {
				continue
			}
			skipNames = append(skipNames, key.Collector)
		}
		sort.Strings(skipNames)
		for _, name := range skipNames {
			rows = append(rows, CollectorStatus{
				Name:       name,
				Enabled:    false,
				SkipReason: skipReasons[SkipKey{TenantID: src.TenantID, Collector: name}],
			})
		}

		tenants = append(tenants, TenantStatus{TenantID: src.TenantID, Collectors: rows})
	}
	return tenants
}

// collectorStatusFor builds one registered collector's status row from its
// StatusTracker run/history snapshots (absent when the collector has not run
// yet, e.g. immediately after startup).
func collectorStatusFor(name string, interval time.Duration, runs map[string]collector.CollectorRun, hist map[string]collector.CollectorHistory, now time.Time) CollectorStatus {
	cs := CollectorStatus{
		Name:        name,
		Enabled:     true,
		IntervalSec: int64(interval / time.Second),
	}
	if run, ok := runs[name]; ok {
		cs.HasRun = true
		cs.Runs = run.Runs
		cs.Failures = run.Failures
		cs.LastStartedAt = run.LastStarted.UTC().Format(time.RFC3339)
		cs.LastFinishedAt = run.LastFinished.UTC().Format(time.RFC3339)
		cs.LastDurationMs = run.LastDuration.Milliseconds()
		cs.LastSuccess = run.LastSuccess
		cs.LastError = run.LastError
		cs.ConsecutiveFailures = run.ConsecutiveFailures
		cs.SuccessRatePct = successRatePct(run.Runs, run.Failures)

		staleness := now.Sub(run.LastFinished)
		if staleness < 0 { // guard a backward wall-clock jump (NTP)
			staleness = 0
		}
		cs.StalenessSec = int64(staleness / time.Second)
		cs.Staleness = staleness.Round(time.Second).String()
	}
	if h, ok := hist[name]; ok {
		cs.DurationMsSeries = h.DurationMs
		cs.OutcomeSeries = h.Outcomes
	}
	return cs
}

// successRatePct reports the lifetime success rate as a percentage. It
// returns 0 when no run has happened yet (rate is undefined), which pairs
// with HasRun=false so a consumer can show "—" rather than a misleading 0%.
func successRatePct(runs, failures int64) float64 {
	if runs <= 0 {
		return 0
	}
	return float64(runs-failures) / float64(runs) * 100
}

// deriveHealth summarizes overall service health from the per-tenant
// collector rows. Skipped collectors (Enabled=false) never affect health —
// they are an intentional configuration choice, not a failure. Precedence:
// any collector with 3+ consecutive failures or whose last run failed makes
// the service "degraded"; otherwise a collector that has not yet run makes it
// "starting"; otherwise "healthy".
func deriveHealth(tenants []TenantStatus) (string, []string) {
	var reasons, pending []string
	for _, tenant := range tenants {
		for _, c := range tenant.Collectors {
			if !c.Enabled {
				continue
			}
			if !c.HasRun {
				pending = append(pending, tenant.TenantID+"/"+c.Name)
				continue
			}
			switch {
			case c.ConsecutiveFailures >= consecutiveFailureThreshold:
				reasons = append(reasons, fmt.Sprintf("tenant %q collector %q: %d consecutive failures", tenant.TenantID, c.Name, c.ConsecutiveFailures))
			case !c.LastSuccess:
				reasons = append(reasons, fmt.Sprintf("tenant %q collector %q: last run failed", tenant.TenantID, c.Name))
			}
		}
	}
	switch {
	case len(reasons) > 0:
		return healthDegraded, reasons
	case len(pending) > 0:
		return healthStarting, []string{"waiting for first run: " + strings.Join(pending, ", ")}
	default:
		return healthHealthy, nil
	}
}
