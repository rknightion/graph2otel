// Package logpipeline is the generic watermark-poller engine every
// WindowCollector for a log-shaped Graph endpoint runs on (signIns,
// directoryAudits, provisioning, riskDetections, riskyUsers, Intune
// auditEvents, ...). None of those endpoints support a delta query or a
// reliable server-side cursor, so this package owns, once, the mechanics
// every one of them would otherwise hand-roll: build a time-window $filter,
// follow @odata.nextLink to exhaustion, dedupe by immutable id against the
// checkpoint's overlap window, emit each record as an OTLP log, and advance
// the watermark. An M3/M5 collector becomes a thin EndpointConfig plus a
// Map function; it does not re-implement pagination, dedupe, or watermark
// math.
package logpipeline

import (
	"context"
	"fmt"
	"net/url"
	"sort"
	"strconv"
	"time"

	"github.com/rknightion/graph2otel/internal/checkpoint"
	"github.com/rknightion/graph2otel/internal/telemetry"
)

// Default tuning applied by EndpointConfig.withDefaults when the
// corresponding field is left zero.
const (
	// DefaultSafetyLag trails the poll window's upper bound so the watermark
	// never advances into a range where a record could still be landing.
	DefaultSafetyLag = 15 * time.Minute
	// DefaultOverlap is how far behind the watermark a restart re-queries,
	// to catch events that were still arriving out of order at last poll.
	DefaultOverlap = 2 * time.Hour
	// DefaultPageSize is the $top page size requested per Graph page.
	DefaultPageSize = 1000
)

// FilterFlavor selects the pair of OData comparison operators Poll builds
// for an endpoint's time-window $filter.
type FilterFlavor int

const (
	// FlavorGeLe builds inclusive `ge`/`le` bounds. Use for endpoints where
	// $orderby asc on the time field is reliable (signIns createdDateTime,
	// directoryAudits activityDateTime).
	FlavorGeLe FilterFlavor = iota
	// FlavorGtLt builds strict `gt`/`lt` bounds. Use for endpoints where
	// $orderby is unreliable (provisioning activityDateTime) — pair with
	// OrderByReliable=false so Poll sorts the drained window client-side
	// instead of trusting server order.
	FlavorGtLt
)

// EndpointConfig describes one log-shaped Graph endpoint: how to query its
// time window and how to turn one raw JSON record into a dedupe id plus an
// OTLP log Event.
type EndpointConfig struct {
	// Path is the Graph API path, e.g. "/auditLogs/signIns". Relative to the
	// v1.0 service root; the real PageFetcher adapter (see
	// graphclient_adapter.go) resolves it against that root.
	Path string
	// BaseURLOverride, when non-empty, replaces the default v1.0 service root
	// for this endpoint's FIRST page — e.g.
	// "https://graph.microsoft.com/beta" for the signInEventTypes-filtered
	// sign-in streams (nonInteractiveUser/servicePrincipal/managedIdentity),
	// which return HTTP 400 on v1.0 ("Could not find a property named
	// 'signInEventTypes'") and exist only on beta. Subsequent pages follow the
	// response's already-absolute @odata.nextLink verbatim, so only the first
	// page URL consults this. The path still carries Path, so the transport's
	// Contains-based workload classification is unaffected by the /beta prefix.
	BaseURLOverride string
	// FilterExtra, when non-empty, is an additional OData $filter predicate
	// ANDed (parenthesized) onto the time-window clause — e.g.
	// "signInEventTypes/any(t: t eq 'nonInteractiveUser')" for the filtered
	// sign-in streams. Left empty for endpoints that filter on time alone.
	FilterExtra string
	// CheckpointKey, when non-empty, overrides Path as the checkpoint
	// namespace (the endpoint component of the (tenant, endpoint) checkpoint
	// key). Several collectors legitimately poll the SAME Path with different
	// FilterExtra — the four sign-in event-type streams all hit
	// "/auditLogs/signIns" — and would otherwise collide on one checkpoint,
	// deduping each other's events away. Each sets a distinct CheckpointKey
	// (e.g. "/auditLogs/signIns#nonInteractiveUser") so their watermarks and
	// SeenIDs stay independent. Defaults to Path when empty.
	CheckpointKey string
	// TimeField is the record's time-window field used in $filter and (when
	// OrderByReliable) $orderby, e.g. "createdDateTime" or
	// "activityDateTime".
	TimeField string
	// Flavor selects the $filter operator pair for TimeField (see
	// FilterFlavor).
	Flavor FilterFlavor
	// OrderByReliable, when true, adds "$orderby={TimeField} asc" to the
	// query and trusts the server's page order. When false, Poll drains the
	// whole window before sorting client-side by the record's parsed
	// TimeField value rather than trusting server order.
	OrderByReliable bool
	// SafetyLag trails the window's upper bound; defaults to
	// DefaultSafetyLag when zero.
	SafetyLag time.Duration
	// Overlap is how far behind the watermark a restart re-queries;
	// defaults to DefaultOverlap when zero.
	Overlap time.Duration
	// PageSize is the requested $top page size; defaults to
	// DefaultPageSize when zero.
	PageSize int
	// Map turns one raw JSON record (as decoded from the Graph response's
	// "value" array) into its immutable id — used for SeenIDs dedupe across
	// the overlap window — and the OTLP log Event to emit for it.
	//
	// Per-entity detail (UPN, device name, IP address, correlation id, the
	// record's own id) belongs in Event.Attrs as structured log attributes,
	// never surfaced as a metric label — see the project's cardinality
	// guidance. Map need not set Event.Timestamp: Poll parses TimeField from
	// the raw record and fills it in when left zero.
	Map func(record map[string]any) (id string, ev telemetry.Event)
}

// withDefaults returns a copy of cfg with zero-valued tuning fields replaced
// by their documented defaults.
func (cfg EndpointConfig) withDefaults() EndpointConfig {
	if cfg.SafetyLag <= 0 {
		cfg.SafetyLag = DefaultSafetyLag
	}
	if cfg.Overlap <= 0 {
		cfg.Overlap = DefaultOverlap
	}
	if cfg.PageSize <= 0 {
		cfg.PageSize = DefaultPageSize
	}
	return cfg
}

// checkpointKey returns the checkpoint namespace for this endpoint:
// CheckpointKey when set, otherwise Path. See CheckpointKey's field doc for
// why the two are decoupled.
func (cfg EndpointConfig) checkpointKey() string {
	if cfg.CheckpointKey != "" {
		return cfg.CheckpointKey
	}
	return cfg.Path
}

// PageFetcher fetches one page of a Graph collection response, abstracting
// the GET + JSON decode of the "{"value": [...], "@odata.nextLink": "..."}"
// shape so Poll is unit-testable against a fake or an httptest server
// without a live Graph client. See graphclient_adapter.go for the real
// adapter over *graphclient.Client.
type PageFetcher interface {
	// FetchPage GETs pageURL and returns its records plus the opaque
	// @odata.nextLink to follow next (empty when this was the last page).
	FetchPage(ctx context.Context, pageURL string) (records []map[string]any, nextLink string, err error)
}

// Poll drains every record in [from, to] for cfg from fetcher, deduping
// against cp.SeenIDs, emitting each newly-seen record as an OTLP log through
// e, and returning the new high-water mark. It mutates cp in place
// (Watermark, OverlapWindow, SeenIDs via EvictStale) but does NOT persist
// it — the caller owns persistence (checkpoint.Store.Save), so Poll stays
// testable without a filesystem. LogCollector.CollectWindow (collector.go)
// is the convenience that Loads, Polls, and Saves for a WindowCollector.
func Poll(ctx context.Context, cfg EndpointConfig, cp *checkpoint.Checkpoint, from, to time.Time, fetcher PageFetcher, e telemetry.Emitter) (highWater time.Time, err error) {
	cfg = cfg.withDefaults()

	type drainedRecord struct {
		id string
		ev telemetry.Event
		t  time.Time
	}

	var all []drainedRecord
	pageURL := buildFirstURL(cfg, from, to)
	for pageURL != "" {
		records, next, ferr := fetcher.FetchPage(ctx, pageURL)
		if ferr != nil {
			return cp.Watermark, fmt.Errorf("logpipeline: %s: fetch page: %w", cfg.Path, ferr)
		}
		for _, rec := range records {
			id, ev := cfg.Map(rec)
			t, ok := recordTime(rec, cfg.TimeField)
			if !ok {
				t = ev.Timestamp
			}
			if ev.Timestamp.IsZero() {
				ev.Timestamp = t
			}
			all = append(all, drainedRecord{id: id, ev: ev, t: t})
		}
		pageURL = next
	}

	// $orderby is not honored (or not trusted) server-side for this
	// endpoint: sort the fully-drained window client-side before emitting,
	// so "newest" below reflects real event time, not arrival order.
	if !cfg.OrderByReliable {
		sort.Slice(all, func(i, j int) bool { return all[i].t.Before(all[j].t) })
	}

	newest := cp.Watermark
	sawAny := false
	for _, d := range all {
		if cp.SeenIDs.Has(d.id) {
			continue
		}
		e.LogEvent(d.ev)
		cp.SeenIDs.Add(d.id, d.t)
		if !sawAny || d.t.After(newest) {
			newest = d.t
		}
		sawAny = true
	}

	// The watermark always advances at least to `to - SafetyLag` once this
	// window has been fully drained, even when it drained zero NEW records:
	// the window up to `to` has been confirmed empty (or fully deduped), so
	// there is no reason to re-scan it forever. When records were seen,
	// newest <= to by construction (every record matched the [from, to]
	// $filter bound), so newest - SafetyLag can never exceed to -
	// SafetyLag: the "never advance past now - lag" invariant holds without
	// an extra clamp.
	candidate := to
	if sawAny {
		candidate = newest
	}
	hw := candidate.Add(-cfg.SafetyLag)
	highWater = cp.Watermark
	if hw.After(highWater) {
		highWater = hw
	}

	cp.Watermark = highWater
	cp.OverlapWindow = cfg.Overlap
	cp.EvictStale()

	return highWater, nil
}

// buildFirstURL builds the first page URL for cfg's time window [from, to]:
// a $filter using cfg.Flavor's operators on cfg.TimeField, "$orderby
// {TimeField} asc" ONLY when cfg.OrderByReliable, and $top=cfg.PageSize.
// Every subsequent page is fetched by following the previous page's opaque
// @odata.nextLink verbatim — Poll never builds $skip itself.
func buildFirstURL(cfg EndpointConfig, from, to time.Time) string {
	q := url.Values{}
	q.Set("$filter", buildFilter(cfg, from, to))
	if cfg.OrderByReliable {
		q.Set("$orderby", cfg.TimeField+" asc")
	}
	q.Set("$top", strconv.Itoa(cfg.PageSize))
	base := graphV1BaseURL
	if cfg.BaseURLOverride != "" {
		base = cfg.BaseURLOverride
	}
	return base + cfg.Path + "?" + q.Encode()
}

// buildFilter renders the $filter expression for cfg's time window, in
// RFC3339 UTC, using ge/le for FlavorGeLe or gt/lt for FlavorGtLt.
func buildFilter(cfg EndpointConfig, from, to time.Time) string {
	fromStr := from.UTC().Format(time.RFC3339)
	toStr := to.UTC().Format(time.RFC3339)
	op1, op2 := "ge", "le"
	if cfg.Flavor == FlavorGtLt {
		op1, op2 = "gt", "lt"
	}
	window := fmt.Sprintf("%s %s %s and %s %s %s", cfg.TimeField, op1, fromStr, cfg.TimeField, op2, toStr)
	if cfg.FilterExtra != "" {
		return window + " and (" + cfg.FilterExtra + ")"
	}
	return window
}

// recordTime extracts and parses record[timeField] (an RFC3339 string, as
// every Graph log-shaped time field is documented to be) as the record's
// event time. ok is false when the field is absent, not a string, or fails
// to parse — Poll falls back to whatever Event.Timestamp cfg.Map set.
func recordTime(record map[string]any, timeField string) (time.Time, bool) {
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
