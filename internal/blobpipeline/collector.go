package blobpipeline

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"github.com/rknightion/graph2otel/internal/checkpoint"
	"github.com/rknightion/graph2otel/internal/telemetry"
)

// BlobCollector is a thin collector.SnapshotCollector over one container: it
// loads the (tenant, container) blob cursor, delegates listing + ranged reads +
// emitting + cursor math to Poll, and persists as it goes. A blob-sourced
// collector is one of these plus its ContainerConfig — it does not
// re-implement any of that.
//
// Why SnapshotCollector and not WindowCollector, despite emitting logs: the
// interface split in package collector is about the CURSOR, not the signal
// shape. A WindowCollector is handed a [from, to] time range by the scheduler,
// which this engine cannot use — Azure backfills records into already-closed
// hour buckets, so blob progress is a byte offset per blob and never a
// timestamp (see checkpoint.BlobCursor). SnapshotCollector's "here is a tick,
// do your thing" contract is the exact fit, and it means the scheduler needs no
// change to drive this: panic recovery, scrape self-obs, and the status page
// all work as they do for every other collector.
type BlobCollector struct {
	// NameField is returned by Name() — the stable collector identifier used in
	// self-obs attributes and as the config key.
	NameField string
	// Interval is returned by DefaultInterval().
	Interval time.Duration
	// TenantID is the tenant this collector serves; also the tenant component
	// of the cursor key.
	TenantID string
	// Config is the container this collector consumes.
	Config ContainerConfig
	// Source lists and reads the blobs. Production wiring uses NewAzureSource.
	Source Source
	// Store persists the blob cursor across restarts.
	Store *checkpoint.Store
	// Logger records per-blob diagnostics (skipped records, read failures).
	Logger *slog.Logger
}

// NewBlobCollector returns a BlobCollector wired to persist through store. See
// the field docs for what each argument controls.
func NewBlobCollector(
	name string,
	interval time.Duration,
	tenantID string,
	cfg ContainerConfig,
	src Source,
	store *checkpoint.Store,
	logger *slog.Logger,
) *BlobCollector {
	return &BlobCollector{
		NameField: name,
		Interval:  interval,
		TenantID:  tenantID,
		Config:    cfg,
		Source:    src,
		Store:     store,
		Logger:    logger,
	}
}

// Name implements collector.Collector.
func (c *BlobCollector) Name() string { return c.NameField }

// DefaultInterval implements collector.Collector.
func (c *BlobCollector) DefaultInterval() time.Duration { return c.Interval }

// Collect implements collector.SnapshotCollector: it loads this container's
// cursor, drains whatever is new, and persists as each blob advances.
//
// A cursor load failure fails the tick rather than starting from zero: an empty
// cursor would re-emit every byte of every retained blob (up to a week per
// category), so a duplicate storm is a much worse outcome than a failed tick
// the scheduler retries.
func (c *BlobCollector) Collect(ctx context.Context, e telemetry.Emitter) error {
	cur, err := c.Store.LoadCursor(c.TenantID, c.Config.cursorKey())
	if err != nil {
		return fmt.Errorf("blobpipeline: %s: load cursor: %w", c.NameField, err)
	}
	if err := Poll(ctx, c.Config, cur, c.Source, e, c.Logger, c.Store.SaveCursor); err != nil {
		return fmt.Errorf("blobpipeline: %s: %w", c.NameField, err)
	}
	return nil
}
