package logpipeline

import (
	"context"
	"fmt"
	"time"

	"github.com/rknightion/graph2otel/internal/checkpoint"
	"github.com/rknightion/graph2otel/internal/telemetry"
)

// LogCollector is a thin generic collector.WindowCollector: it Loads the
// (tenant, endpoint) checkpoint, resumes from watermark-overlap, delegates
// draining + emitting + watermark math to Poll, then Saves the checkpoint.
// An M3/M5 collector is one of these plus its EndpointConfig — it does not
// re-implement pagination, dedupe, or persistence.
type LogCollector struct {
	// NameField is returned by Name() — a stable identifier used in
	// self-observability attributes and as the checkpoint key alongside
	// TenantID + Config.Path.
	NameField string
	// Interval is returned by DefaultInterval().
	Interval time.Duration
	// LagValue is returned by Lag() — the trailing safety margin the
	// scheduler subtracts from "now" to compute CollectWindow's `to`.
	LagValue time.Duration
	// TenantID identifies which tenant's checkpoint namespace this
	// collector polls.
	TenantID string
	// Config is the endpoint this collector polls.
	Config EndpointConfig
	// Fetcher pages through Config's endpoint. Production wiring uses
	// NewGraphPageFetcher; tests may supply a fake.
	Fetcher PageFetcher
	// Store persists the checkpoint across restarts.
	Store *checkpoint.Store
}

// NewLogCollector returns a LogCollector wired to persist through store. See
// the field docs for what each argument controls.
func NewLogCollector(name string, interval, lag time.Duration, tenantID string, cfg EndpointConfig, fetcher PageFetcher, store *checkpoint.Store) *LogCollector {
	return &LogCollector{
		NameField: name,
		Interval:  interval,
		LagValue:  lag,
		TenantID:  tenantID,
		Config:    cfg,
		Fetcher:   fetcher,
		Store:     store,
	}
}

// Name implements collector.Collector.
func (c *LogCollector) Name() string { return c.NameField }

// DefaultInterval implements collector.Collector.
func (c *LogCollector) DefaultInterval() time.Duration { return c.Interval }

// IngestTransport reports the transport this collector ingests over — the same
// telemetry.Transport that CollectWindow stamps onto every record via
// telemetry.WithTransport (#141), so the admin status page (#178) and the log
// records agree by construction.
func (c *LogCollector) IngestTransport() telemetry.Transport { return telemetry.TransportGraph }

// Lag implements collector.WindowCollector.
func (c *LogCollector) Lag() time.Duration { return c.LagValue }

// CollectWindow implements collector.WindowCollector: it loads the
// checkpoint for (c.TenantID, c.Config.Path) and resumes from
// watermark-overlap rather than the scheduler's bare `from`, polls
// [resumeFrom, to], persists the updated checkpoint, and returns the new
// high-water mark.
//
// resumeFrom deliberately ignores `from` whenever a watermark already
// exists, rather than taking max(from, watermark-overlap): in steady state
// the scheduler's own `from` is (approximately) the previous tick's
// watermark, so max(from, watermark-overlap) would collapse right back to
// ~watermark and never actually re-query the overlap window — defeating the
// whole point of persisting OverlapWindow/SeenIDs. Re-querying
// watermark-overlap on every tick is what continuously catches
// out-of-order/late-arriving records; SeenIDs makes that redundant range
// cheap (dedup, not re-emission). `from` is used only on a genuine cold
// start (no watermark yet), where it carries the collector's configured
// InitialLookback.
func (c *LogCollector) CollectWindow(ctx context.Context, from, to time.Time, e telemetry.Emitter) (time.Time, error) {
	cfg := c.Config.withDefaults()

	cp, err := c.Store.Load(c.TenantID, cfg.checkpointKey())
	if err != nil {
		return from, fmt.Errorf("logpipeline: %s: load checkpoint: %w", c.NameField, err)
	}

	resumeFrom := from
	if !cp.Watermark.IsZero() {
		resumeFrom = cp.Watermark.Add(-cfg.Overlap)
	}

	hw, err := Poll(ctx, cfg, cp, resumeFrom, to, c.Fetcher, e)
	if err != nil {
		return cp.Watermark, fmt.Errorf("logpipeline: %s: poll: %w", c.NameField, err)
	}

	if err := c.Store.Save(cp); err != nil {
		return hw, fmt.Errorf("logpipeline: %s: save checkpoint: %w", c.NameField, err)
	}
	return hw, nil
}
