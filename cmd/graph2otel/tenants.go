package main

import (
	"context"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/rknightion/graph2otel/internal/admin"
	"github.com/rknightion/graph2otel/internal/auth"
	"github.com/rknightion/graph2otel/internal/checkpoint"
	"github.com/rknightion/graph2otel/internal/collector"
	"github.com/rknightion/graph2otel/internal/collectors"
	"github.com/rknightion/graph2otel/internal/config"
	"github.com/rknightion/graph2otel/internal/graphclient"
	"github.com/rknightion/graph2otel/internal/license"
	"github.com/rknightion/graph2otel/internal/logpipeline"
	"github.com/rknightion/graph2otel/internal/telemetry"
)

// startTenants builds one Graph client + collector set per configured tenant,
// gates each collector by license tier and config, and launches a per-tenant
// Scheduler goroutine bound to ctx. It returns the admin status sources (one
// per tenant) and the skip-reason map so the admin page can show both the
// running collectors and the ones deliberately not registered.
//
// It never fails the process for a single tenant: an auth/client or license
// error for one tenant is logged and that tenant is skipped, so a
// misconfigured tenant can't take down the others. The returned wait func
// blocks until every launched Scheduler has drained (after ctx is canceled).
func startTenants(
	ctx context.Context,
	cfg *config.Config,
	provider *telemetry.Provider,
	logger *slog.Logger,
) (sources []admin.CollectorSource, skips map[admin.SkipKey]string, wait func()) {
	skips = map[admin.SkipKey]string{}
	var wg sync.WaitGroup

	// One limiter shared across tenants: its buckets are keyed per tenant
	// internally, so this correctly isolates each tenant's per-app throttle
	// budget while keeping a single instance.
	limiter := graphclient.NewWorkloadLimiter()

	auths, err := auth.BuildAll(cfg.Tenants)
	if err != nil {
		logger.Error("building tenant credentials", "error", err)
		return nil, skips, wg.Wait
	}

	for _, ta := range auths {
		src, launched := setupTenant(ctx, ta, cfg, provider, logger, limiter, skips, &wg)
		if launched {
			sources = append(sources, src)
		}
	}
	return sources, skips, wg.Wait
}

// setupTenant wires one tenant end to end. launched is false when the tenant
// could not be brought up (client build failed) — its collectors are skipped
// rather than aborting the whole process.
func setupTenant(
	ctx context.Context,
	ta *auth.TenantAuth,
	cfg *config.Config,
	provider *telemetry.Provider,
	logger *slog.Logger,
	limiter *graphclient.WorkloadLimiter,
	skips map[admin.SkipKey]string,
	wg *sync.WaitGroup,
) (admin.CollectorSource, bool) {
	tlog := logger.With("tenant", ta.TenantID)
	emitter := provider.Emitter()

	gc, err := graphclient.NewClient(ctx, ta, graphclient.Options{
		Emitter:  emitter,
		Limiter:  limiter,
		TenantID: ta.TenantID,
	})
	if err != nil {
		tlog.Error("building Graph client", "error", err)
		return admin.CollectorSource{}, false
	}

	// License detection is best-effort: on failure, proceed with no premium
	// capabilities (gated collectors skip, ungated collectors still run) rather
	// than taking the tenant down.
	caps, err := license.Detect(ctx, license.NewGraphSkuLister(gc))
	if err != nil {
		tlog.Warn("license detection failed; proceeding with base tier", "error", err)
	}
	license.EmitLicenseTier(emitter, ta.TenantID, caps)

	registry := collector.NewRegistry()

	// Snapshot collectors (metric-shaped inventory polls).
	deps := collectors.Deps{Graph: gc, TenantID: ta.TenantID, Logger: tlog, Caps: caps}
	for _, factory := range collectors.All() {
		c := factory(deps)
		if interval, ok := gateCollector(c, ta, cfg, caps, tlog, skips); ok {
			registry.Register(c, interval)
		}
	}

	// Window collectors (log-shaped event-stream polls on the logpipeline
	// engine). They share the tenant's single instrumented, rate-limited
	// transport (one PageFetcher over gc) and the file-based checkpoint store.
	fetcher := logpipeline.NewGraphPageFetcher(gc)
	store := checkpoint.NewStore(cfg.CheckpointDir)
	wdeps := collectors.WindowDeps{
		Graph:    gc,
		TenantID: ta.TenantID,
		Logger:   tlog,
		Caps:     caps,
		Fetcher:  fetcher,
		Store:    store,
	}
	for _, wf := range collectors.WindowAll() {
		rw := wf(wdeps)
		if rw.Collector == nil {
			continue
		}
		if interval, ok := gateCollector(rw.Collector, ta, cfg, caps, tlog, skips); ok {
			registry.RegisterWindow(rw.Collector, interval, rw.InitialLookback, rw.MaxWindow)
		}
	}

	status := collector.NewStatusTracker()
	sched := collector.NewScheduler(emitter, collector.NewMemoryStore(),
		collector.WithTenant(ta.TenantID),
		collector.WithStatusTracker(status),
		collector.WithLogger(tlog),
	)
	wg.Go(func() {
		_ = sched.Run(ctx, registry)
	})

	tlog.Info("tenant started", "collectors", len(registry.Entries()))
	return admin.CollectorSource{TenantID: ta.TenantID, Registry: registry, Status: status}, true
}

// gateCollector applies the three registration gates shared by snapshot and
// window collectors — license tier (license.CapabilityRequirer), config
// enable/disable, and the experimental (beta) opt-in — and returns the
// resolved poll interval with ok=true only when the collector should be
// registered. On any skip it records the reason in skips (for the admin page)
// and returns ok=false. Experimental collectors register only on an explicit
// config enable, never on the default-enabled state, so a beta Graph surface
// change can't break a default deployment.
func gateCollector(
	c collector.Collector,
	ta *auth.TenantAuth,
	cfg *config.Config,
	caps license.Capabilities,
	tlog *slog.Logger,
	skips map[admin.SkipKey]string,
) (time.Duration, bool) {
	if ok, requiredCap, _ := license.ShouldRun(c, caps); !ok {
		tlog.Info("skipping collector", "collector", c.Name(), "reason", license.SkipReason(c.Name(), ta.TenantID, requiredCap))
		skips[admin.SkipKey{TenantID: ta.TenantID, Collector: c.Name()}] = fmt.Sprintf("requires %s", requiredCap)
		return 0, false
	}
	enabled, interval := cfg.CollectorSettings(ta.TenantID, c.Name())
	if !enabled {
		tlog.Info("collector disabled by config", "collector", c.Name())
		skips[admin.SkipKey{TenantID: ta.TenantID, Collector: c.Name()}] = "disabled by config"
		return 0, false
	}
	if exp, ok := c.(collectors.Experimental); ok && exp.Experimental() &&
		!cfg.CollectorExplicitlyEnabled(ta.TenantID, c.Name()) {
		tlog.Info("skipping experimental collector (opt-in)", "collector", c.Name())
		skips[admin.SkipKey{TenantID: ta.TenantID, Collector: c.Name()}] = "beta; enable explicitly to opt in"
		return 0, false
	}
	return interval, true
}
