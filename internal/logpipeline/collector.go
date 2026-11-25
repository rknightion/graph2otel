package logpipeline

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"time"

	"github.com/rknightion/graph2otel/internal/checkpoint"
	"github.com/rknightion/graph2otel/internal/collector"
	"github.com/rknightion/graph2otel/internal/recordoutcome"
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

// CheckpointState reports this window poller's durable progress for the admin
// status page (#178 Part B): its watermark and overlap-dedupe set size, read
// read-only from the same checkpoint the tick persists. A read failure returns
// nil rather than erroring the page — the failure already surfaces as the
// collector's own run error, since CollectWindow loads the same file.
func (c *LogCollector) CheckpointState() *collector.CheckpointState {
	cp, err := c.Store.Load(c.TenantID, c.Config.withDefaults().checkpointKey())
	if err != nil {
		return nil
	}
	st := &collector.CheckpointState{
		Kind:      collector.CheckpointKindWindow,
		Watermark: cp.Watermark,
		SeenIDs:   len(cp.SeenIDs),
	}
	if cp.InFlight != nil {
		st.InFlightJob = cp.InFlight.ID
	}
	return st
}

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
func (c *LogCollector) CollectWindow(
	ctx context.Context,
	from, to time.Time,
	e telemetry.Emitter,
	outcomes *recordoutcome.Recorder,
) (time.Time, error) {
	cfg := c.Config.withDefaults()

	cp, err := c.Store.Load(c.TenantID, cfg.checkpointKey())
	if err != nil {
		return from, fmt.Errorf("logpipeline: %s: load checkpoint: %w", c.NameField, err)
	}

	commit := cfg.stageCheckpoint(cp, c.Store)
	resumeFrom := from
	if !cp.Watermark.IsZero() {
		resumeFrom = cp.Watermark.Add(-cfg.Overlap)
	}

	durableWatermark := cp.Watermark
	seenBefore, deferredBefore := len(cp.SeenIDs), cp.DeferredRecords
	hw, err := Poll(ctx, cfg, cp, resumeFrom, to, c.Fetcher, e, outcomes)
	if err != nil {
		if cfg.Prepare != nil && (len(cp.SeenIDs) > seenBefore || !slices.Equal(cp.DeferredRecords, deferredBefore)) {
			err = errors.Join(err, commit()) // delivery progress only, unchanged watermark
		}
		return durableWatermark, fmt.Errorf("logpipeline: %s: poll: %w", c.NameField, err)
	}

	if err := commit(); err != nil {
		if cfg.Deferred != nil {
			hw = durableWatermark
		}
		return hw, fmt.Errorf("logpipeline: %s: save checkpoint: %w", c.NameField, err)
	}
	return hw, nil
}

// CollectRecord prepares one row outside the window, using the same durable
// key set as CollectWindow without advancing its watermark. It requires a
// Prepare hook. The caller must serialize it with CollectWindow and with other
// calls for the same tenant and endpoint across the entire load/emit/save cycle.
func (c *LogCollector) CollectRecord(ctx context.Context, row map[string]any, e telemetry.Emitter, outcomes *recordoutcome.Recorder) error {
	cfg := c.Config.withDefaults()
	if cfg.Prepare == nil {
		return errors.New("logpipeline: CollectRecord requires Prepare")
	}
	cp, err := c.Store.Load(c.TenantID, cfg.checkpointKey())
	if err != nil {
		return err
	}
	commit := cfg.stageCheckpoint(cp, c.Store)
	outcomes.Add(recordoutcome.OutcomeFetched, 1)
	rec, err := ingestPrepared(ctx, cfg, cp, row, telemetry.WithTransport(e, telemetry.TransportGraph), outcomes)
	if err != nil {
		failFetchedRecords(outcomes, 1, fetchFailureCause(err))
		return err
	}
	if cfg.Deferred != nil && rec.SourceVersion > 0 && cp.SeenIDs.Has(rec.Key) {
		// Do not later report a retention drop for a ref the direct path
		// already delivered. A lower version does not discharge the ref.
		id, _ := row["id"].(string)
		cp.DeferredRecords = slices.DeleteFunc(cp.DeferredRecords, func(ref checkpoint.DeferredRecord) bool {
			return ref.ID == id && ref.Version <= rec.SourceVersion
		})
	}
	if !cfg.NotBefore.IsZero() {
		cp.SeenIDs.Evict(cfg.NotBefore)
	}
	return commit()
}

// Stage against the loaded checkpoint, not Poll's temporary watermark state.
// Poll deliberately preserves the prepared keys on partial delivery failure.
func (cfg *EndpointConfig) stageCheckpoint(cp *checkpoint.Checkpoint, store *checkpoint.Store) func() error {
	if cfg.MaintainCheckpoint != nil {
		cfg.MaintainCheckpoint(cp)
	}
	var afterSave []func()
	cfg.stage = func(stage func(*checkpoint.Checkpoint, telemetry.Emitter) func(), e telemetry.Emitter) {
		if release := stage(cp, e); release != nil {
			afterSave = append(afterSave, release)
		}
	}
	return func() error {
		save := store.Save
		if cfg.MaintainCheckpoint != nil || len(afterSave) != 0 {
			save = store.SaveDurable
		}
		if err := save(cp); err != nil {
			return err
		}
		for _, release := range afterSave {
			release()
		}
		return nil
	}
}
