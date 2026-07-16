package jobpipeline

import (
	"context"
	"fmt"
	"time"

	"github.com/rknightion/graph2otel/internal/checkpoint"
	"github.com/rknightion/graph2otel/internal/telemetry"
)

// JobCollector is a thin generic collector.WindowCollector over the job-poll
// engine — the async-query counterpart to logpipeline.LogCollector. It Loads
// the (tenant, endpoint) checkpoint, resumes from watermark-overlap, delegates
// submit/poll/page/dedupe/watermark to Run, then Saves the checkpoint. A M365
// or Purview unified-audit collector is one of these plus its QueryConfig; it
// does not re-implement the create/poll/page cycle.
type JobCollector struct {
	// NameField is returned by Name() — the stable identifier used in
	// self-observability attributes.
	NameField string
	// Interval is returned by DefaultInterval(). The unified-audit query
	// endpoint 429s on rapid create (#98), so this must stay coarse (15/30/60m).
	Interval time.Duration
	// LagValue is returned by Lag(): the trailing safety margin the scheduler
	// subtracts from "now" for CollectWindow's `to`. Set it to cover the unified
	// audit log's record-availability latency (Microsoft: up to 30 min–24 h).
	LagValue time.Duration
	// TenantID identifies which tenant's checkpoint namespace this collector polls.
	TenantID string
	// Config is the async endpoint this collector queries.
	Config QueryConfig
	// Client submits/polls/pages Config's endpoint. Production wiring uses
	// NewGraphJobClient; tests supply a fake.
	Client JobClient
	// Store persists the checkpoint across restarts.
	Store *checkpoint.Store
}

// NewJobCollector returns a JobCollector wired to persist through store.
func NewJobCollector(name string, interval, lag time.Duration, tenantID string, cfg QueryConfig, client JobClient, store *checkpoint.Store) *JobCollector {
	return &JobCollector{
		NameField: name,
		Interval:  interval,
		LagValue:  lag,
		TenantID:  tenantID,
		Config:    cfg,
		Client:    client,
		Store:     store,
	}
}

// Name implements collector.Collector.
func (c *JobCollector) Name() string { return c.NameField }

// DefaultInterval implements collector.Collector.
func (c *JobCollector) DefaultInterval() time.Duration { return c.Interval }

// Lag implements collector.WindowCollector.
func (c *JobCollector) Lag() time.Duration { return c.LagValue }

// CollectWindow implements collector.WindowCollector. It loads the checkpoint
// for (c.TenantID, c.Config.checkpointKey()), resumes from watermark-overlap
// (re-querying the overlap window every tick to catch late/reordered records,
// deduped by SeenIDs), runs one submit→poll→page cycle for [resumeFrom, to],
// persists the updated checkpoint, and returns the new high-water mark. `from`
// is used only on a cold start (no watermark yet). Mirrors
// logpipeline.LogCollector.CollectWindow exactly.
func (c *JobCollector) CollectWindow(ctx context.Context, from, to time.Time, e telemetry.Emitter) (time.Time, error) {
	cfg := c.Config.withDefaults()

	cp, err := c.Store.Load(c.TenantID, cfg.checkpointKey())
	if err != nil {
		return from, fmt.Errorf("jobpipeline: %s: load checkpoint: %w", c.NameField, err)
	}

	resumeFrom := from
	if !cp.Watermark.IsZero() {
		resumeFrom = cp.Watermark.Add(-cfg.Overlap)
	}

	hw, err := Run(ctx, cfg, cp, resumeFrom, to, c.Client, e)
	if err != nil {
		return cp.Watermark, fmt.Errorf("jobpipeline: %s: run: %w", c.NameField, err)
	}

	if err := c.Store.Save(cp); err != nil {
		return hw, fmt.Errorf("jobpipeline: %s: save checkpoint: %w", c.NameField, err)
	}
	return hw, nil
}
