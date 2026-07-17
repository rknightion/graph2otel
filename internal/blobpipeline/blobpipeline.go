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

	"github.com/rknightion/graph2otel/internal/checkpoint"
	"github.com/rknightion/graph2otel/internal/telemetry"
)

// DefaultMaxBytesPerTick bounds how much of a single blob one tick reads into
// memory. MicrosoftGraphActivityLogs — by far the largest category — was
// measured at ~6.1 MB per hourly blob on a small tenant (#89), so 32 MiB clears
// a full hour in one tick with room for a much busier tenant, while still
// capping the memory a single tick can claim. It only paces: a blob that
// exceeds it is finished on the next tick, never dropped.
const DefaultMaxBytesPerTick = 32 << 20

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

	for _, b := range blobs {
		if err := ctx.Err(); err != nil {
			return err
		}
		advanced, err := consumeBlob(ctx, cfg, cur, src, e, log, b)
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
	return nil
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

	emitLines(complete, cfg, e, log, b.Name)
	cur.Offsets[b.Name] = off + int64(len(complete))
	return true, nil
}

// emitLines decodes and emits every complete JSON-Lines record in data.
func emitLines(data []byte, cfg ContainerConfig, e telemetry.Emitter, log *slog.Logger, blob string) {
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
		ev, ok := cfg.Map(rec)
		if !ok {
			continue
		}
		e.LogEvent(ev)
	}
}
