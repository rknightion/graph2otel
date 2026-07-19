package o365pipeline

import (
	"context"
	"time"

	"github.com/rknightion/graph2otel/internal/checkpoint"
	"github.com/rknightion/graph2otel/internal/collector"
	"github.com/rknightion/graph2otel/internal/o365activityclient"
	"github.com/rknightion/graph2otel/internal/telemetry"
)

// ActivityCollector is a thin generic collector.WindowCollector over the
// Management Activity API engine — the content-feed counterpart to
// logpipeline.LogCollector and jobpipeline.JobCollector. It adds the scalar
// accessors the scheduler reads (Name/DefaultInterval/Lag) and the
// CollectWindow signature it calls, and delegates every actual decision —
// subscribe, list, fetch, dedupe, watermark, persist — to the embedded
// Collector.
//
// A collector on this engine is one of these plus its EndpointConfig, plus
// whatever policy is genuinely its own (Experimental, ConflictsWith,
// RequiredPermissions). Those stay in the collector package: they describe that
// signal, not this transport.
//
// It lives here rather than in the collector package for the same reason its two
// siblings do. The adapter is a property of the ENGINE's shape — Collector
// exposes Collect(ctx, from, to, e) error, collector.WindowCollector wants
// CollectWindow plus three accessors — so every collector on this engine needs
// the identical bridge. Keeping it in one collector made the second one either
// copy it or import a sibling collector package for plumbing.
type ActivityCollector struct {
	// Collector is the engine. It is embedded rather than held in a field so the
	// engine's own surface stays reachable, exactly as this adapter's previous
	// home did it.
	*Collector

	// NameField is returned by Name() — the stable collector identifier used in
	// self-observability attributes and error messages.
	NameField string
	// Interval is returned by DefaultInterval(). Unlike jobpipeline's, this one
	// is not throttle-bound: the API quotes 2,000 req/min per tenant and content
	// lists ~2 minutes after the event (live, #100), so the cadence is set by
	// usefulness.
	Interval time.Duration
	// LagValue is returned by Lag() — the trailing safety margin the scheduler
	// subtracts from "now" to compute CollectWindow's `to`. Records land minutes
	// behind the event and blobs are explicitly non-sequential, so a `to` of
	// "now" would repeatedly miss late arrivals.
	LagValue time.Duration
}

// NewActivityCollector returns an ActivityCollector wired to client and
// persisting through store. See the field docs for what each argument controls.
func NewActivityCollector(
	name string,
	interval, lag time.Duration,
	client *o365activityclient.Client,
	store *checkpoint.Store,
	cfg EndpointConfig,
) *ActivityCollector {
	return &ActivityCollector{
		Collector: New(client, store, cfg),
		NameField: name,
		Interval:  interval,
		LagValue:  lag,
	}
}

// Name implements collector.Collector.
func (c *ActivityCollector) Name() string { return c.NameField }

// DefaultInterval implements collector.Collector.
func (c *ActivityCollector) DefaultInterval() time.Duration { return c.Interval }

// IngestTransport reports the transport this collector ingests over — the same
// telemetry.Transport the underlying Collector stamps onto every record via
// telemetry.WithTransport (#141), so the admin status page (#178) and the log
// records agree by construction.
func (c *ActivityCollector) IngestTransport() telemetry.Transport {
	return telemetry.TransportO365Activity
}

// CheckpointState reports this content-feed poller's durable progress for the
// admin status page (#178 Part B): its watermark and seen-id set size, read
// read-only from the embedded engine's checkpoint. A read failure returns nil
// rather than erroring the page. The engine's watermark — not the scheduler's
// cosmetic high-water mark — is this feed's real cursor (see CollectWindow).
func (c *ActivityCollector) CheckpointState() *collector.CheckpointState {
	cp, err := c.store.Load(c.client.TenantID, c.cfg.CheckpointKey)
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
func (c *ActivityCollector) Lag() time.Duration { return c.LagValue }

// CollectWindow implements collector.WindowCollector by delegating to the
// engine.
//
// It returns `to` as the high-water mark, which is cosmetic rather than
// load-bearing: the engine keeps its OWN durable watermark (plus seen contentIds
// and record Ids) in the checkpoint store and resumes from watermark-overlap,
// ignoring the scheduler's `from` once that watermark exists. The scheduler's
// separate checkpoint is therefore not this feed's real cursor, and a zero return
// would be equivalent — the scheduler substitutes `to` for a zero hwm. Returning
// it explicitly says so.
//
// On error it returns a zero high-water mark. That is an honest convention
// rather than a safety mechanism, and the difference is worth stating so nobody
// "hardens" the wrong thing: the scheduler DISCARDS the hwm entirely when err is
// non-nil (scheduler.go:308-314 returns before touching the checkpoint, so the
// next tick retries the same window), and the zero-means-`to` substitution runs
// only on the success path. Returning `to` alongside an error would therefore be
// equally safe today. Zero is returned anyway because a high-water mark for a
// window that was not drained is a claim that is simply untrue, and relying on a
// caller to ignore an untrue value is a worse contract than not making it.
func (c *ActivityCollector) CollectWindow(ctx context.Context, from, to time.Time, e telemetry.Emitter) (time.Time, error) {
	// Collect is the embedded Collector's method, not this type's.
	if err := c.Collect(ctx, from, to, e); err != nil {
		return time.Time{}, err
	}
	return to, nil
}
