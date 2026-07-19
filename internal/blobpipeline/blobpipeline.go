// Package blobpipeline is the generic engine every collector that reads Azure
// Storage blobs runs on — the blob-side counterpart to logpipeline (#89).
//
// It exists because a handful of signals have NO Graph endpoint at all
// (MicrosoftGraphActivityLogs, MicrosoftServicePrincipalSignInLogs, Intune
// OperationalLogs) and reach us only as Azure Monitor diagnostic-settings
// output written to a storage account. This is the one place graph2otel
// deliberately reads from outside Graph, so the Azure SDK is confined to
// azblob_adapter.go behind the Source interface and the rest of the codebase
// never learns about Azure.
//
// The engine is READ-ONLY by design (#89): it never deletes or writes a blob.
// Retention belongs entirely to the storage account's server-side lifecycle
// rule. That is not just least-privilege hygiene — a "delete the hours we have
// consumed" design would have destroyed live data, because a closed hour's blob
// keeps growing (see the Poll docs).
package blobpipeline

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"sort"
	"time"

	"github.com/rknightion/graph2otel/internal/checkpoint"
	"github.com/rknightion/graph2otel/internal/semconv"
	"github.com/rknightion/graph2otel/internal/telemetry"
)

// DefaultMaxBytesPerTick bounds how much of a single blob one tick reads into
// memory. MicrosoftGraphActivityLogs — by far the largest category — was
// measured at ~6.1 MB per hourly blob on a small tenant (#89), so 32 MiB clears
// a full hour in one tick with room for a much busier tenant, while still
// capping the memory a single tick can claim. It only paces: a blob that
// exceeds it is finished on the next tick, never dropped.
const DefaultMaxBytesPerTick = 32 << 20

// metricSelfExcluded counts records dropped by exclude_self (#154): a blob record
// whose actor appId equals the tenant's own poller client_id — graph2otel's own
// polling exhaust, up to ~60% of MicrosoftGraphActivityLogs volume (#152). It is
// a LOUD drop, never a silent one: a self-observability counter labeled per
// collector, so a blob stream that goes ~60% quieter with the filter on reads as
// "the filter is working", not "ingest broke". Normalizes to
// graph2otel_blob_self_excluded_total on the Prometheus side (#82).
const metricSelfExcluded = "graph2otel.blob.self_excluded"

// Blob-derived-metrics gate self-obs (#128). Counters are batched per tick per
// category so a catch-up burst is one Add, not thousands.
const (
	metricGated          = "graph2otel.blob.metric_gated"
	metricEmitted        = "graph2otel.blob.metric_emitted"
	metricRecordsDropped = "graph2otel.blob.records_dropped"
	metricEventAge       = "graph2otel.blob.event_age"
)

// gateStats accumulates one tick's recency-gate decisions across all of a
// container's blobs, so the summary is logged and the self-obs counters emitted
// once per tick per category — never once per record (a 12h backfill would
// otherwise flood the log with the exact events the gate keeps out of metrics).
type gateStats struct {
	emitted, gated, dropped int
	oldestGated             time.Duration
	freshestAge             time.Duration
	freshestSet             bool
}

// BlobInfo is one blob as returned by a listing: its name and current size.
// Size is the read bound for this tick — the blob may grow immediately after,
// which is picked up next tick.
type BlobInfo struct {
	Name string
	Size int64
}

// Source lists and reads blobs. It is the seam that keeps the Azure SDK out of
// collector code: production wiring uses NewAzureSource, tests use a fake.
// Implementations must be safe for concurrent use.
type Source interface {
	// List returns every blob in container whose name starts with prefix.
	List(ctx context.Context, container, prefix string) ([]BlobInfo, error)
	// ReadRange returns count bytes of the named blob starting at offset. A
	// range extending past the blob's end returns what exists rather than
	// failing, since the blob may have been truncated by a lifecycle delete.
	ReadRange(ctx context.Context, container, name string, offset, count int64) ([]byte, error)
}

// SaveFunc persists the cursor. Poll calls it after each blob it advances, so a
// crash mid-tick costs a re-read of only the blob in flight rather than every
// blob the tick had already drained.
type SaveFunc func(*checkpoint.BlobCursor) error

// ContainerConfig describes one container to consume and how to turn one raw
// JSON-Lines record into an OTLP log Event.
type ContainerConfig struct {
	// Container is the blob container, e.g.
	// "insights-logs-microsoftgraphactivitylogs". Azure Monitor names it
	// "insights-logs-" + the diagnostic-settings category, lowercased.
	Container string
	// Prefix restricts the listing. For a TENANT-level (microsoft.aadiam)
	// diagnostic setting this is "tenantId=<guid>/" — NOT the
	// "resourceId=/tenants/<guid>/providers/..." form every published Microsoft
	// example shows, which is subscription-scoped and matches nothing here
	// (verified live 2026-07-16, #89).
	Prefix string
	// CursorKey overrides Container as the cursor namespace, for the case where
	// two collectors read one container. Defaults to Container.
	CursorKey string
	// MaxBytesPerTick bounds the per-blob read; defaults to
	// DefaultMaxBytesPerTick when zero.
	MaxBytesPerTick int64
	// Map turns one raw record (a decoded JSON line) into the OTLP log Event to
	// emit. Returning false drops the record — the bytes are still consumed, so
	// a record this collector does not want never stalls the cursor.
	Map func(rec map[string]any) (telemetry.Event, bool)

	// Derive turns one record into zero or more bounded metric increments,
	// called only for records within RecencyWindow (#128), AFTER Map, and given
	// Map's Event so it reuses one parse and one event-time source. Nil (the
	// default) means this container emits no metrics — log-only, unchanged.
	Derive func(rec map[string]any, ev telemetry.Event) []MetricPoint
	// RecencyWindow gates Derive: a record whose event time is older than this
	// takes the log path only (never a counter), so a backfilled event is never
	// credited to "now". Set by the factory from BlobDeps.MetricRecencyWindow;
	// a per-collector knob on ContainerConfig (like MaxBytesPerTick), not a Poll
	// parameter. Only read when Derive is non-nil.
	RecencyWindow time.Duration

	// ExcludeSelf, when true, drops a record whose actor appId equals SelfClientID
	// before Map is called — graph2otel's own polling exhaust in the categories
	// that carry an appId (MicrosoftGraphActivityLogs and the service-principal
	// sign-in categories), which is up to ~60% of MGAL volume (#152/#154). Default
	// false: nothing is filtered unless a tenant opts in with
	// blob_ingest.exclude_self. A dropped record's bytes are still consumed, so the
	// cursor advances exactly as for a Map-rejected record — undedupeable is
	// degraded, misdated is wrong; this is neither, just deliberately unshipped.
	ExcludeSelf bool
	// SelfClientID is this tenant's own poller client_id, the value ExcludeSelf
	// compares each record's SelfAppID against. Empty disables the filter even when
	// ExcludeSelf is true — there is no "self" to match — so a tenant relying on a
	// shared AZURE_CLIENT_ID rather than a configured client_id safely no-ops
	// rather than matching every record's empty appId.
	SelfClientID string
	// SelfAppID extracts the actor appId from a raw record, reading the SAME field
	// the category's Map does (one source of truth, so the filter can never compare
	// a different field than the one emitted). Nil means this category carries no
	// appId (e.g. AuditLogs) and is therefore NEVER self-filtered, regardless of
	// ExcludeSelf.
	SelfAppID func(rec map[string]any) string

	// CollectorName labels the metricSelfExcluded self-obs counter so a drop is
	// attributable to its collector. Read only when a self-exclusion fires.
	CollectorName string
}

// cursorKey returns the cursor namespace for this container.
func (c ContainerConfig) cursorKey() string {
	if c.CursorKey != "" {
		return c.CursorKey
	}
	return c.Container
}

// maxBytes returns the per-blob read bound.
func (c ContainerConfig) maxBytes() int64 {
	if c.MaxBytesPerTick > 0 {
		return c.MaxBytesPerTick
	}
	return DefaultMaxBytesPerTick
}

// Poll consumes everything new in cfg's container and advances cur.
//
// It re-examines EVERY listed blob on every call, not just the newest ones, and
// that is load-bearing rather than lazy (#89, verified live 2026-07-16): Azure
// partitions these blobs by EVENT time and backfills history into already-
// closed hour buckets progressively — a blob for the 00:00 hour was still being
// appended to 13 hours later. A consumer that walked forward and forgot would
// silently lose every late-arriving record. Re-listing is affordable because
// the 7-day lifecycle rule bounds the set to ~168 blobs per category, and an
// unchanged blob costs a size comparison rather than a read.
//
// Ordering: blobs are read oldest-first, which the zero-padded y=/m=/d=/h=
// layout makes a plain name sort. That is a nicety for readability of the
// emitted stream, not a correctness property — each blob's offset is
// independent, so a mis-sorted listing would still be consumed completely.
//
// Failure semantics mirror the logpipeline engine: records are emitted BEFORE
// the cursor advances, so a crash re-reads rather than skips (at-least-once,
// never a gap). A List failure fails the tick, because a tick that saw nothing
// must not look successful. A per-blob read failure, a malformed line, or a
// failed cursor save do not: they are logged and the remaining blobs still
// drain.
func Poll(
	ctx context.Context,
	cfg ContainerConfig,
	cur *checkpoint.BlobCursor,
	src Source,
	e telemetry.Emitter,
	log *slog.Logger,
	save SaveFunc,
) error {
	// Name the transport once per cycle rather than per record (#141). This is
	// the stamp that makes a blob-ingested record distinguishable from its
	// Graph-polled twin — they are byte-identical otherwise, deliberately, via
	// one shared mapper.
	e = telemetry.WithTransport(e, telemetry.TransportBlob)

	blobs, err := src.List(ctx, cfg.Container, cfg.Prefix)
	if err != nil {
		return fmt.Errorf("blobpipeline: list %s/%s: %w", cfg.Container, cfg.Prefix, err)
	}
	sort.Slice(blobs, func(i, j int) bool { return blobs[i].Name < blobs[j].Name })

	pruneDeleted(cur, blobs)

	var stats gateStats
	for _, b := range blobs {
		if err := ctx.Err(); err != nil {
			return err
		}
		advanced, err := consumeBlob(ctx, cfg, cur, src, e, &stats, log, b)
		if err != nil {
			// One unreadable blob must not cost us the other 167.
			log.Warn("blob read failed; skipping until next tick",
				"container", cfg.Container, "blob", b.Name, "error", err)
			continue
		}
		if !advanced || save == nil {
			continue
		}
		if err := save(cur); err != nil {
			// The records are already emitted. Failing the tick would not
			// un-emit them, and the next tick simply re-reads from the last
			// persisted offset, so this is a duplicate risk, not a data loss.
			log.Warn("blob cursor save failed; records may be re-emitted after a restart",
				"container", cfg.Container, "blob", b.Name, "error", err)
		}
	}
	reportGate(e, log, cfg, stats)
	return nil
}

// reportGate emits the per-tick gate self-obs and the one summary line per tick
// per category (#128). No-op unless a Derive is configured. Counters are batched
// (one Add of the tick total) — under cumulative temporality that is identical
// to N individual Add(1) calls, and keeps a backfill burst from thousands of
// per-record emissions.
func reportGate(e telemetry.Emitter, log *slog.Logger, cfg ContainerConfig, stats gateStats) {
	if cfg.Derive == nil {
		return
	}
	cat := cfg.CollectorName
	window := cfg.RecencyWindow
	if stats.emitted > 0 {
		e.Counter(metricEmitted, "{record}", "Blob records that reached the metrics path (#128).",
			float64(stats.emitted), telemetry.Attrs{semconv.AttrCollector: cat})
		e.Gauge(metricEventAge, "s", "Freshest blob event age this tick — the metric propagation floor (#128).",
			stats.freshestAge.Seconds(), telemetry.Attrs{semconv.AttrCollector: cat})
	}
	if stats.gated > 0 {
		e.Counter(metricGated, "{record}", "Blob records too old for the metrics path, taken log-only (#128).",
			float64(stats.gated), telemetry.Attrs{semconv.AttrCollector: cat})
	}
	if stats.dropped > 0 {
		e.Counter(metricRecordsDropped, "{record}", "Blob records skipped by the metrics path for an unparseable event time (#128).",
			float64(stats.dropped), telemetry.Attrs{semconv.AttrCollector: cat})
	}
	if stats.gated > 0 || stats.freshestSet {
		log.Info("blob metric gate",
			"category", cat, "emitted", stats.emitted, "gated", stats.gated,
			"dropped", stats.dropped, "oldest_gated", stats.oldestGated.String(),
			"freshest_age", stats.freshestAge.String(), "window", window.String())
	}
	if stats.freshestSet && stats.freshestAge > window*3/4 {
		log.Warn("blob metric latency approaching gate",
			"category", cat, "freshest_age", stats.freshestAge.String(), "window", window.String())
	}
}

// pruneDeleted drops cursor offsets for blobs that are no longer listed. The
// storage account's lifecycle rule deletes blobs past its retention window, and
// without this the cursor would accumulate an entry per hour per category
// forever.
func pruneDeleted(cur *checkpoint.BlobCursor, blobs []BlobInfo) {
	live := make(map[string]struct{}, len(blobs))
	for _, b := range blobs {
		live[b.Name] = struct{}{}
	}
	for name := range cur.Offsets {
		if _, ok := live[name]; !ok {
			delete(cur.Offsets, name)
		}
	}
}

// consumeBlob reads and emits whatever is new in one blob, returning whether
// the cursor advanced.
func consumeBlob(
	ctx context.Context,
	cfg ContainerConfig,
	cur *checkpoint.BlobCursor,
	src Source,
	e telemetry.Emitter,
	stats *gateStats,
	log *slog.Logger,
	b BlobInfo,
) (bool, error) {
	off := cur.Offsets[b.Name]
	if off > b.Size {
		// An append blob cannot shrink, so this means the name was reused —
		// a lifecycle delete followed by a backfill recreating the hour. Re-read
		// from the start: re-emitting an hour is recoverable, silently skipping
		// it forever is not.
		log.Warn("blob is smaller than the stored offset; re-reading from the start",
			"container", cfg.Container, "blob", b.Name, "offset", off, "size", b.Size)
		off = 0
	}
	if off == b.Size {
		return false, nil // no growth: the common case, and it costs no read
	}

	count := b.Size - off
	if max := cfg.maxBytes(); count > max {
		count = max
	}
	chunk, err := src.ReadRange(ctx, cfg.Container, b.Name, off, count)
	if err != nil {
		return false, err
	}

	// Consume only up to the last line terminator. Azure Monitor writes whole
	// JSON Lines records per append block today, so in practice the chunk ends
	// cleanly — but if a partial line ever were exposed, emitting it would
	// produce one garbage record and advancing past it would lose that record
	// permanently. Stopping short instead costs one re-read of a few hundred
	// bytes next tick.
	nl := bytes.LastIndexByte(chunk, '\n')
	if nl < 0 {
		return false, nil
	}
	complete := chunk[:nl+1]

	emitLines(complete, cfg, e, stats, log, b.Name)
	cur.Offsets[b.Name] = off + int64(len(complete))
	return true, nil
}

// emitLines decodes and emits every complete JSON-Lines record in data. It
// always emits the log twin; for a container with a Derive it additionally
// routes each record's bounded metric increments, gated by RecencyWindow so a
// backfilled event never touches a counter (#128). stats accumulates the gate
// decisions for the per-tick summary.
func emitLines(data []byte, cfg ContainerConfig, e telemetry.Emitter, stats *gateStats, log *slog.Logger, blob string) {
	for _, line := range bytes.Split(data, []byte("\n")) {
		line = bytes.TrimSpace(line) // drops the \r of the blobs' CRLF terminator
		if len(line) == 0 {
			continue
		}
		var rec map[string]any
		if err := json.Unmarshal(line, &rec); err != nil {
			// A data defect, not a reason to stop: skip it and keep the blob
			// moving. The bytes are still consumed, so this never wedges.
			log.Warn("skipping malformed record", "container", cfg.Container, "blob", blob, "error", err)
			continue
		}
		if cfg.ExcludeSelf && cfg.SelfAppID != nil && cfg.SelfClientID != "" && cfg.SelfAppID(rec) == cfg.SelfClientID {
			// graph2otel's own polling exhaust (#154). Drop it before Map, but
			// LOUDLY: a per-collector self-obs counter, never a silent skip, so a
			// quieter blob stream reads as "the filter is working", not "ingest
			// broke". The bytes are still consumed by consumeBlob's cursor math,
			// exactly as a Map-rejected record is, so an excluded record never
			// stalls the cursor. Self-ONLY: any other appId falls through
			// untouched — a third party's records are never filtered.
			e.Counter(metricSelfExcluded, "{record}",
				"Blob records dropped by blob_ingest.exclude_self because their appId matched this tenant's own poller client_id (#154).",
				1, telemetry.Attrs{semconv.AttrCollector: cfg.CollectorName})
			continue
		}
		ev, ok := cfg.Map(rec)
		if !ok {
			continue
		}
		e.LogEvent(ev)

		if cfg.Derive == nil {
			continue
		}
		if ev.Timestamp.IsZero() {
			// No parseable event time: the log twin still emitted (with no
			// timestamp), but a counter stamped "now" from an undated record
			// would be a guess — skip the metric path and count it dropped.
			stats.dropped++
			continue
		}
		age, ok := withinWindow(ev.Timestamp, time.Now(), cfg.RecencyWindow)
		if !ok {
			// Too old (backfill/catch-up) or future-dated: log-only. Crediting it
			// to "now" would be a spike that never happened (#128).
			stats.gated++
			if age > stats.oldestGated {
				stats.oldestGated = age
			}
			continue
		}
		stats.emitted++
		if !stats.freshestSet || age < stats.freshestAge {
			stats.freshestAge, stats.freshestSet = age, true
		}
		for _, mp := range cfg.Derive(rec, ev) {
			switch mp.Kind {
			case MetricCounter:
				e.Counter(mp.Name, mp.Unit, mp.Desc, mp.Value, mp.Attrs)
			case MetricNativeHistogram:
				// No explicit bounds: a View in provider.go maps these instrument
				// names to base-2 exponential aggregation (#186), so the SDK
				// produces a native histogram. Passing nil bounds is deliberate —
				// the View overrides any bounds anyway.
				e.Histogram(mp.Name, mp.Unit, mp.Desc, mp.Value, nil, mp.Attrs)
			}
		}
	}
}
