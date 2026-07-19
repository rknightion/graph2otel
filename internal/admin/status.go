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

// overdueIntervalFactor is how many whole intervals a collector may go without
// starting a run before the page flags it "overdue" (a wedged-ticker signal).
const overdueIntervalFactor = 2

// Skip categories classify why a collector the operator might expect to see was
// never registered. They are derived from the free-form reason string the
// composition root supplies (admin has no dependency on license/preflight), so
// the page can style license gating differently from a deliberate opt-out.
const (
	skipCatLicense      = "license"      // license/permission tier missing ("requires ...")
	skipCatDisabled     = "disabled"     // turned off in config ("disabled by config")
	skipCatExperimental = "experimental" // beta, not opted into ("beta; enable ...")
)

// skipCategory buckets a skip-reason string into one of the skipCat* constants,
// or "" when it matches none. It matches on the prefixes the composition root
// (cmd/graph2otel/tenants.go) emits: "requires <cap>", "disabled by config",
// and "beta; enable explicitly to opt in".
func skipCategory(reason string) string {
	switch {
	case strings.HasPrefix(reason, "requires "):
		return skipCatLicense
	case strings.HasPrefix(reason, "disabled"):
		return skipCatDisabled
	case strings.HasPrefix(reason, "beta"):
		return skipCatExperimental
	default:
		return ""
	}
}

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

// TenantStatus is one tenant's collector table plus a small roll-up used by the
// page's per-tenant header. The counts are derived from Collectors: EnabledCount
// is registered collectors, FailingCount those whose last run failed, PendingCount
// those that have not run yet, SkippedCount the genuinely-off rows, and
// CoveredCount the off rows whose records a registered twin still ships (#178).
// Covered rows are deliberately NOT in SkippedCount — a covered signal is not a
// gap, and the header must not tally it as one.
type TenantStatus struct {
	TenantID     string            `json:"tenant_id"`
	Collectors   []CollectorStatus `json:"collectors"`
	EnabledCount int               `json:"enabled_count"`
	FailingCount int               `json:"failing_count"`
	PendingCount int               `json:"pending_count"`
	SkippedCount int               `json:"skipped_count"`
	CoveredCount int               `json:"covered_count"`
}

// CollectorStatus is one row of a tenant's collector table: either a
// registered collector's latest run state, or a skipped collector's reason.
type CollectorStatus struct {
	Name string `json:"name"`
	// Enabled is false for a collector the composition root chose not to
	// register at all; SkipReason then explains why (e.g. "requires P2").
	Enabled bool `json:"enabled"`
	// SkipReason is the raw reason a skipped collector was not registered;
	// SkipCategory buckets it (see skipCategory) so the page can badge
	// license-gating separately from a deliberate opt-out or a beta opt-in.
	SkipReason   string `json:"skip_reason,omitempty"`
	SkipCategory string `json:"skip_category,omitempty"`
	IntervalSec  int64  `json:"interval_seconds,omitempty"`

	// Transport names the ingest path a REGISTERED collector runs over — the
	// same taxonomy as the ingest_transport log attribute (#141), derived from
	// collector.TransportOf. For a source-switchable collector (#135 group D)
	// this is the ACTIVE source: a directory_audits running source=blob reports
	// "blob", because the collector registered under that name is the blob one.
	// Empty on a skipped row (nothing is running to have a transport).
	Transport string `json:"transport,omitempty"`
	// CoveredBy is set on a collector that is OFF but whose records are shipped
	// by a registered twin over another transport (a beta polled form covered by
	// its GA blob twin, or m365.unified_audit covered by m365.activity). It names
	// that twin and its transport so the page states "collected via X" rather
	// than a bare "disabled" — a covered signal is not a gap (#178). Nil when the
	// collector is genuinely uncollected anywhere (the only real gap).
	CoveredBy *Coverage `json:"covered_by,omitempty"`
	// State is the collector's durable checkpoint progress, read read-only from
	// the checkpoint store at render time (#178 Part B) — the watermark (+
	// staleness) for a window poller, the byte offset/blobs/newest-hour for a blob
	// consumer, and any in-flight job id. Nil for a collector that persists no
	// cursor (an inline snapshot collector) or a skipped row (nothing running).
	State *CollectorState `json:"state,omitempty"`

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
	// NextRunInSec/NextRunIn estimate the time until the next scheduled tick
	// (0 / "" when due or not yet run), derived from LastStarted+interval since
	// the scheduler's ticker is anchored near run start. Overdue is set when the
	// collector has not started a run in over overdueIntervalFactor intervals — a
	// wedged-ticker signal, distinct from a run that simply failed.
	NextRunInSec int64  `json:"next_run_in_seconds,omitempty"`
	NextRunIn    string `json:"next_run_in,omitempty"`
	Overdue      bool   `json:"overdue,omitempty"`
	// DurationMsSeries/OutcomeSeries are the recent-run history (oldest
	// first, aligned), feeding a duration sparkline and outcome strip.
	DurationMsSeries []int64 `json:"duration_ms_series,omitempty"`
	OutcomeSeries    []bool  `json:"outcome_series,omitempty"`
}

// Coverage names the registered twin that ships an off collector's records, and
// the transport it uses. It is the payload of CollectorStatus.CoveredBy (#178).
type Coverage struct {
	Collector string `json:"collector"`
	Transport string `json:"transport"`
}

// CollectorState is a registered collector's durable checkpoint progress, the
// payload of CollectorStatus.State (#178 Part B). Kind ("window"/"blob") selects
// which fields are meaningful; empty fields are omitted from the JSON. It is a
// read-only render-time snapshot — this is ops visibility, not per-entity data.
type CollectorState struct {
	Kind string `json:"kind"`
	// Window fields.
	Watermark    string `json:"watermark,omitempty"` // RFC3339; empty on cold start
	StalenessSec int64  `json:"staleness_seconds,omitempty"`
	Staleness    string `json:"staleness,omitempty"`
	SeenIDs      int    `json:"seen_ids,omitempty"`
	InFlightJob  string `json:"in_flight_job,omitempty"`
	// Blob fields.
	ByteOffset   int64  `json:"byte_offset,omitempty"`
	BlobsTracked int    `json:"blobs_tracked,omitempty"`
	NewestBlob   string `json:"newest_blob,omitempty"`
}

// collectorStateFrom maps a collector.CheckpointState (read from the checkpoint
// store) into the admin JSON payload, computing watermark staleness (now -
// watermark) for a window poller. Returns nil for a nil input so a collector
// that persists nothing shows no State block.
func collectorStateFrom(st *collector.CheckpointState, now time.Time) *CollectorState {
	if st == nil {
		return nil
	}
	cs := &CollectorState{
		Kind:         st.Kind,
		SeenIDs:      st.SeenIDs,
		InFlightJob:  st.InFlightJob,
		ByteOffset:   st.ByteOffset,
		BlobsTracked: st.BlobsTracked,
		NewestBlob:   st.NewestBlob,
	}
	if !st.Watermark.IsZero() {
		cs.Watermark = st.Watermark.UTC().Format(time.RFC3339)
		staleness := now.Sub(st.Watermark)
		if staleness < 0 { // guard a backward wall-clock jump (NTP)
			staleness = 0
		}
		cs.StalenessSec = int64(staleness / time.Second)
		cs.Staleness = staleness.Round(time.Second).String()
	}
	return cs
}

// conflicter is the subset of collectors.ConflictsWith the admin page needs to
// pair an off collector with the registered twin that covers it. Declared here
// (structurally) so admin does not import internal/collectors just to read one
// method — a blob/o365 twin already names its polled peer via ConflictsWith().
type conflicter interface {
	ConflictsWith() []string
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
		// coveredBy pairs a polled peer name with the REGISTERED twin that ships
		// its records. Built from the live registry (not a hand list), so a new
		// twin is recognized the day it lands — the same robustness the conflict
		// check (checkRegistryConflicts) relies on.
		coveredBy := map[string]Coverage{}
		for _, e := range entries {
			name := e.Collector.Name()
			registered[name] = true
			row := collectorStatusFor(name, e.Interval, runs, hist, now)
			row.Transport = string(collector.TransportOf(e.Collector))
			// Read the collector's durable checkpoint (watermark/byte offset/job id)
			// read-only at render time, so the page shows progress, not just
			// registration (#178 Part B). Nil for a collector that persists no cursor.
			row.State = collectorStateFrom(collector.CheckpointStateOf(e.Collector), now)
			rows = append(rows, row)
			if cw, ok := e.Collector.(conflicter); ok {
				for _, peer := range cw.ConflictsWith() {
					coveredBy[peer] = Coverage{Collector: name, Transport: row.Transport}
				}
			}
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
			reason := skipReasons[SkipKey{TenantID: src.TenantID, Collector: name}]
			row := CollectorStatus{
				Name:         name,
				Enabled:      false,
				SkipReason:   reason,
				SkipCategory: skipCategory(reason),
			}
			// If a registered twin ships this off collector's records, it is not a
			// gap — name the twin + transport so the page says "collected via X".
			if cov, ok := coveredBy[name]; ok {
				c := cov
				row.CoveredBy = &c
			}
			rows = append(rows, row)
		}

		ten := TenantStatus{TenantID: src.TenantID, Collectors: rows}
		for _, c := range rows {
			switch {
			case !c.Enabled:
				// A covered collector is not a gap — count it apart from real skips
				// so the header roll-up never tallies a collected signal as missing.
				if c.CoveredBy != nil {
					ten.CoveredCount++
				} else {
					ten.SkippedCount++
				}
			default:
				ten.EnabledCount++
				switch {
				case !c.HasRun:
					ten.PendingCount++
				case !c.LastSuccess:
					ten.FailingCount++
				}
			}
		}
		tenants = append(tenants, ten)
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

		if interval > 0 {
			until := run.LastStarted.Add(interval).Sub(now)
			if until < 0 { // due/overdue
				until = 0
			}
			cs.NextRunInSec = int64(until / time.Second)
			cs.NextRunIn = until.Round(time.Second).String()
			if now.Sub(run.LastStarted) > overdueIntervalFactor*interval {
				cs.Overdue = true
			}
		}
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
