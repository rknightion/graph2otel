// Package jobpipeline is the async job-poll engine for Graph APIs that don't
// answer a single paged GET but instead take a submitted query that runs
// server-side: POST a query, poll its status to a terminal state, then page
// its results. The canonical surface is Microsoft Purview Audit exposed through
// Graph — POST /security/auditLog/queries → GET .../queries/{id} until
// status=succeeded → GET .../queries/{id}/records — which backs BOTH the M365
// unified-audit collector and a future Purview unified-audit-event collector
// (same endpoint, different recordTypeFilters). Building it once here avoids two
// collectors reimplementing create/poll/page/dedupe.
//
// It is a SIBLING of internal/logpipeline, not a modification of it: the
// existing WindowCollector engine (a single paged GET with a time-window
// $filter) is untouched. jobpipeline reuses the same checkpoint.Checkpoint
// (watermark + overlap + SeenIDs) and telemetry.Emitter plumbing, and mirrors
// its watermark math, so a collector built on either engine checkpoints and
// dedupes identically.
//
// Checkpoint scheme: the watermark advances to (to - SafetyLag) once a query
// window [from, to] has been fully drained — the window's filterEndDateTime is
// confirmed processed, so it is never re-submitted. Per-record dedupe is by the
// record's immutable id (auditLogRecord.id) held in the checkpoint's SeenIDs
// across the overlap window, so records that reorder across result blobs (the
// polymorphic-blob architecture this API inherits from the old O365 Management
// Activity API) are emitted exactly once even when they arrive out of order or
// span two overlapping query windows.
package jobpipeline

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strconv"
	"time"

	"github.com/rknightion/graph2otel/internal/checkpoint"
	"github.com/rknightion/graph2otel/internal/telemetry"
)

// graphV1BaseURL is the Graph v1.0 service root QueryConfig.CreatePath resolves
// against for the create call and the status/records URLs derived from the
// returned query id. Only consulted when BaseURLOverride is empty.
const graphV1BaseURL = "https://graph.microsoft.com/v1.0"

// Default tuning applied by QueryConfig.withDefaults when a field is left zero.
const (
	// DefaultSafetyLag trails the window's upper bound so the watermark never
	// advances into a range where a record could still be landing. The unified
	// audit log's record-availability latency is long (Microsoft documents up to
	// 30 min–24 h), but the collector's Lag() — not this SafetyLag — is what
	// accounts for that; SafetyLag only guards the watermark against the tail of
	// the window just queried.
	DefaultSafetyLag = 15 * time.Minute
	// DefaultOverlap is how far behind the watermark a restart re-queries, made
	// idempotent by SeenIDs.
	DefaultOverlap = 2 * time.Hour
	// DefaultPageSize is the $top page size requested per records page.
	DefaultPageSize = 200
	// DefaultPollInitial is the first delay between status polls; it doubles up
	// to DefaultPollMax. No Microsoft SLA is documented for query completion, so
	// these are deliberate working defaults, overridable per collector.
	DefaultPollInitial = 5 * time.Second
	// DefaultPollMax caps the status-poll backoff (Microsoft's general
	// long-running-operation guidance).
	DefaultPollMax = 4 * time.Minute
	// DefaultCreateInitial is the first delay before retrying a failed create
	// call; it doubles up to DefaultCreateMax. Creating queries in rapid
	// succession returns HTTP 429 (verified live, #98), so create is retried
	// with backoff independently of the status poll.
	DefaultCreateInitial = 5 * time.Second
	// DefaultCreateMax caps the create-retry backoff.
	DefaultCreateMax = 60 * time.Second
	// DefaultCreateMaxRetries bounds create attempts (1 create + this many
	// retries) before the error surfaces. The collector's poll interval
	// (15/30/60 min) is the primary throttle guard; this handles a transient
	// collision, not a tight submit loop.
	DefaultCreateMaxRetries = 3
)

// Job status values returned by the query resource. Terminal states are
// succeeded (page the records), failed, and cancelled.
const (
	StatusNotStarted = "notStarted"
	StatusRunning    = "running"
	StatusSucceeded  = "succeeded"
	StatusFailed     = "failed"
	StatusCancelled  = "cancelled"
)

// Distinct, classifiable terminal errors (returned wrapped; errors.Is applies).
var (
	// ErrJobFailed means the query reported status "failed". Re-polling the same
	// id won't help; the next tick re-submits the window.
	ErrJobFailed = errors.New("jobpipeline: query reported status failed")
	// ErrJobCancelled means the query reported status "cancelled".
	ErrJobCancelled = errors.New("jobpipeline: query reported status cancelled")
)

// JobClient is the Graph seam this engine builds on: create a query, poll its
// status, and page its records — all through the instrumented, rate-limited,
// retrying transport. Satisfied by the real adapter over *graphclient.Client
// (graphclient_adapter.go) and by a fake in tests.
type JobClient interface {
	// CreateQuery POSTs body to createURL and returns the new query's id and its
	// initial status.
	CreateQuery(ctx context.Context, createURL string, body []byte) (queryID, status string, err error)
	// QueryStatus GETs queryURL and returns the query's current status.
	QueryStatus(ctx context.Context, queryURL string) (status string, err error)
	// FetchRecordsPage GETs pageURL and returns its records plus the opaque
	// @odata.nextLink to follow next (empty on the last page).
	FetchRecordsPage(ctx context.Context, pageURL string) (records []map[string]any, nextLink string, err error)
}

// QueryConfig describes one async job-poll endpoint: how to build its query
// request for a time window, and how to turn one raw result record into a
// dedupe id plus an OTLP log Event.
type QueryConfig struct {
	// CreatePath is the POST path that creates a query, e.g.
	// "/security/auditLog/queries". Resolved against graphV1BaseURL (or
	// BaseURLOverride) for the create call; the status and records URLs are
	// derived from it plus the returned query id.
	CreatePath string
	// BaseURLOverride replaces graphV1BaseURL for this endpoint when non-empty
	// (e.g. a /beta root). The records pager still follows the response's
	// absolute @odata.nextLink verbatim.
	BaseURLOverride string
	// CheckpointKey overrides CreatePath as the checkpoint namespace, so two
	// collectors polling the same CreatePath with different BuildRequest filters
	// (M365 vs Purview recordTypeFilters) keep independent watermarks/SeenIDs.
	// Defaults to CreatePath when empty.
	CheckpointKey string
	// BuildRequest returns the JSON request body for the window [from, to]. The
	// caller is workload-specific: it sets filterStartDateTime/filterEndDateTime
	// (typically from `from`/`to`) plus recordTypeFilters and any other query
	// parameters. Required.
	BuildRequest func(from, to time.Time) ([]byte, error)
	// Map turns one raw result record into its immutable dedupe id and the OTLP
	// log Event to emit. Per-entity detail (UPN, IP, object id, operation) belongs
	// in Event.Attrs as structured log attributes, never a metric label — same
	// cardinality rule as logpipeline. Map need not set Event.Timestamp: Run
	// parses TimeField from the record and fills it when left zero. Required.
	Map func(record map[string]any) (id string, ev telemetry.Event)
	// TimeField is the record's event-time field (RFC3339 string), used to fill
	// Event.Timestamp and to time-stamp SeenIDs entries for eviction. Optional:
	// when empty (or absent on a record) the record is timestamped with the
	// window's `to`, which still evicts correctly relative to the watermark.
	TimeField string

	// SafetyLag trails the window's upper bound; defaults to DefaultSafetyLag.
	SafetyLag time.Duration
	// Overlap is how far behind the watermark a restart re-queries; defaults to
	// DefaultOverlap.
	Overlap time.Duration
	// PageSize is the requested $top for records pages; defaults to
	// DefaultPageSize.
	PageSize int

	// PollInitial/PollMax bound the status-poll backoff; default to
	// DefaultPollInitial/DefaultPollMax.
	PollInitial, PollMax time.Duration
	// CreateInitial/CreateMax bound the create-retry backoff; default to
	// DefaultCreateInitial/DefaultCreateMax.
	CreateInitial, CreateMax time.Duration
	// CreateMaxRetries bounds create retries after the first attempt; defaults to
	// DefaultCreateMaxRetries. Set negative to disable retries entirely.
	CreateMaxRetries int

	// Now returns the current time; defaults to time.Now. Injectable for tests.
	Now func() time.Time
	// Sleep waits d honoring ctx cancellation; defaults to a real ctx-aware
	// sleep. Tests inject a no-op so backoff tests don't burn wall-clock time.
	Sleep func(ctx context.Context, d time.Duration) error
}

func (cfg QueryConfig) withDefaults() QueryConfig {
	if cfg.SafetyLag <= 0 {
		cfg.SafetyLag = DefaultSafetyLag
	}
	if cfg.Overlap <= 0 {
		cfg.Overlap = DefaultOverlap
	}
	if cfg.PageSize <= 0 {
		cfg.PageSize = DefaultPageSize
	}
	if cfg.PollInitial <= 0 {
		cfg.PollInitial = DefaultPollInitial
	}
	if cfg.PollMax <= 0 {
		cfg.PollMax = DefaultPollMax
	}
	if cfg.CreateInitial <= 0 {
		cfg.CreateInitial = DefaultCreateInitial
	}
	if cfg.CreateMax <= 0 {
		cfg.CreateMax = DefaultCreateMax
	}
	if cfg.CreateMaxRetries == 0 {
		cfg.CreateMaxRetries = DefaultCreateMaxRetries
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	if cfg.Sleep == nil {
		cfg.Sleep = ctxSleep
	}
	return cfg
}

// checkpointKey returns the checkpoint namespace: CheckpointKey when set, else
// CreatePath.
func (cfg QueryConfig) checkpointKey() string {
	if cfg.CheckpointKey != "" {
		return cfg.CheckpointKey
	}
	return cfg.CreatePath
}

func (cfg QueryConfig) baseURL() string {
	if cfg.BaseURLOverride != "" {
		return cfg.BaseURLOverride
	}
	return graphV1BaseURL
}

// ctxSleep is Sleep's production default: waits d unless ctx is canceled first.
func ctxSleep(ctx context.Context, d time.Duration) error {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}

// Run submits a query for [from, to], polls it to a terminal status, pages its
// results, dedupes against cp.SeenIDs, emits each newly-seen record as an OTLP
// log through e, and returns the new high-water mark. It mutates cp in place
// (Watermark, OverlapWindow, SeenIDs) but does NOT persist it — the caller owns
// persistence (checkpoint.Store.Save), so Run stays testable without a
// filesystem. JobCollector.CollectWindow (collector.go) Loads, Runs, and Saves.
//
// On a failed/cancelled query, or any create/poll/page error, Run returns the
// current watermark unchanged (wrapped error) so the window is retried next
// tick rather than silently skipped.
func Run(ctx context.Context, cfg QueryConfig, cp *checkpoint.Checkpoint, from, to time.Time, client JobClient, e telemetry.Emitter) (highWater time.Time, err error) {
	cfg = cfg.withDefaults()
	if cfg.BuildRequest == nil || cfg.Map == nil {
		return cp.Watermark, fmt.Errorf("jobpipeline: %s: BuildRequest and Map are required", cfg.CreatePath)
	}

	body, err := cfg.BuildRequest(from, to)
	if err != nil {
		return cp.Watermark, fmt.Errorf("jobpipeline: %s: build request: %w", cfg.CreatePath, err)
	}

	queryID, err := createWithBackoff(ctx, cfg, client, body)
	if err != nil {
		return cp.Watermark, fmt.Errorf("jobpipeline: %s: create query: %w", cfg.CreatePath, err)
	}

	queryURL := cfg.baseURL() + cfg.CreatePath + "/" + queryID
	if err := pollToSucceeded(ctx, cfg, client, queryURL); err != nil {
		return cp.Watermark, fmt.Errorf("jobpipeline: %s: %w", cfg.CreatePath, err)
	}

	records, err := drainRecords(ctx, cfg, client, queryURL)
	if err != nil {
		return cp.Watermark, fmt.Errorf("jobpipeline: %s: page records: %w", cfg.CreatePath, err)
	}

	return emitAndAdvance(cfg, cp, records, to, e), nil
}

// createWithBackoff creates the query, retrying transient failures (chiefly the
// documented rapid-submit HTTP 429, #98) with exponential backoff up to
// cfg.CreateMaxRetries.
func createWithBackoff(ctx context.Context, cfg QueryConfig, client JobClient, body []byte) (string, error) {
	createURL := cfg.baseURL() + cfg.CreatePath
	delay := cfg.CreateInitial
	var lastErr error
	attempts := cfg.CreateMaxRetries + 1
	if attempts < 1 {
		attempts = 1
	}
	for i := 0; i < attempts; i++ {
		if err := ctx.Err(); err != nil {
			return "", err
		}
		id, _, err := client.CreateQuery(ctx, createURL, body)
		if err == nil {
			if id == "" {
				return "", fmt.Errorf("create response missing query id")
			}
			return id, nil
		}
		lastErr = err
		if i == attempts-1 {
			break
		}
		if serr := cfg.Sleep(ctx, delay); serr != nil {
			return "", serr
		}
		delay = min(delay*2, cfg.CreateMax)
	}
	return "", lastErr
}

// pollToSucceeded polls the query status to a terminal state, backing off from
// PollInitial to PollMax between polls. notStarted/running keep polling;
// succeeded returns nil; failed/cancelled return the classifiable sentinel.
func pollToSucceeded(ctx context.Context, cfg QueryConfig, client JobClient, queryURL string) error {
	delay := cfg.PollInitial
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		status, err := client.QueryStatus(ctx, queryURL)
		if err != nil {
			return fmt.Errorf("poll status: %w", err)
		}
		switch status {
		case StatusSucceeded:
			return nil
		case StatusFailed:
			return ErrJobFailed
		case StatusCancelled:
			return ErrJobCancelled
		case StatusNotStarted, StatusRunning, "":
			// keep polling
		default:
			// Unknown status: treat as non-terminal and keep polling rather than
			// aborting — a new Graph status value shouldn't fail the collector.
		}
		if err := cfg.Sleep(ctx, delay); err != nil {
			return err
		}
		delay = min(delay*2, cfg.PollMax)
	}
}

// drainRecords pages the query's /records collection to exhaustion, following
// @odata.nextLink.
func drainRecords(ctx context.Context, cfg QueryConfig, client JobClient, queryURL string) ([]map[string]any, error) {
	var out []map[string]any
	pageURL := queryURL + "/records?$top=" + strconv.Itoa(cfg.PageSize)
	for pageURL != "" {
		records, next, err := client.FetchRecordsPage(ctx, pageURL)
		if err != nil {
			return nil, err
		}
		out = append(out, records...)
		pageURL = next
	}
	return out, nil
}

// emitAndAdvance dedupes the drained records against cp.SeenIDs, emits each
// newly-seen one as an OTLP log, and advances the watermark to (to - SafetyLag)
// — the window [from, to] is confirmed drained, so it is never re-submitted.
func emitAndAdvance(cfg QueryConfig, cp *checkpoint.Checkpoint, records []map[string]any, to time.Time, e telemetry.Emitter) time.Time {
	type drained struct {
		id string
		ev telemetry.Event
		t  time.Time
	}
	all := make([]drained, 0, len(records))
	for _, rec := range records {
		id, ev := cfg.Map(rec)
		t, ok := recordTime(rec, cfg.TimeField)
		if !ok {
			if !ev.Timestamp.IsZero() {
				t = ev.Timestamp
			} else {
				t = to
			}
		}
		if ev.Timestamp.IsZero() {
			ev.Timestamp = t
		}
		all = append(all, drained{id: id, ev: ev, t: t})
	}
	// Result blobs are not chronologically ordered; sort so SeenIDs eviction and
	// any downstream ordering reflect real event time.
	sort.Slice(all, func(i, j int) bool { return all[i].t.Before(all[j].t) })

	for _, d := range all {
		if cp.SeenIDs.Has(d.id) {
			continue
		}
		e.LogEvent(d.ev)
		cp.SeenIDs.Add(d.id, d.t)
	}

	hw := to.Add(-cfg.SafetyLag)
	if hw.Before(cp.Watermark) {
		hw = cp.Watermark
	}
	cp.Watermark = hw
	cp.OverlapWindow = cfg.Overlap
	cp.EvictStale()
	return hw
}

// recordTime extracts and parses record[timeField] as an RFC3339 timestamp. ok
// is false when timeField is empty, the field is absent/non-string, or it fails
// to parse.
func recordTime(record map[string]any, timeField string) (time.Time, bool) {
	if timeField == "" {
		return time.Time{}, false
	}
	raw, ok := record[timeField]
	if !ok {
		return time.Time{}, false
	}
	s, ok := raw.(string)
	if !ok {
		return time.Time{}, false
	}
	t, err := time.Parse(time.RFC3339, s)
	if err != nil {
		return time.Time{}, false
	}
	return t, true
}
