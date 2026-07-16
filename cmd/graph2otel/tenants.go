package main

import (
	"context"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/rknightion/graph2otel/internal/admin"
	"github.com/rknightion/graph2otel/internal/auth"
	"github.com/rknightion/graph2otel/internal/blobpipeline"
	"github.com/rknightion/graph2otel/internal/checkpoint"
	"github.com/rknightion/graph2otel/internal/collector"
	"github.com/rknightion/graph2otel/internal/collectors"
	"github.com/rknightion/graph2otel/internal/config"
	"github.com/rknightion/graph2otel/internal/exportjob"
	"github.com/rknightion/graph2otel/internal/graphclient"
	"github.com/rknightion/graph2otel/internal/jobpipeline"
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

	// Snapshot collectors (metric-shaped inventory polls). exporter runs the
	// Intune reports export-job pipeline (POST → poll → download → parse) for the
	// M5 export-based report collectors; it shares gc's instrumented, rate-limited
	// (48/min export bucket) transport for create/poll and a plain client for the
	// unauthenticated SAS download.
	exporter := exportjob.New(gc, exportjob.DefaultDownloader(), exportjob.Options{})
	// One shared managedDevices fetcher per tenant: intune.devices (hourly) and
	// intune.malware (30m) both page the same fleet list every cycle, so a 30m
	// TTL lets whichever ticks first warm the cache and the other reuse it —
	// halving the full-fleet page-walk on a large tenant (#87). 30m matches the
	// shorter default interval; widening either interval past 30m (large-tenant
	// tuning) just reduces the reuse rate, never correctness.
	fleet := collectors.NewCachingFleetFetcher(gc, "https://graph.microsoft.com/v1.0", 30*time.Minute)
	deps := collectors.Deps{Graph: gc, TenantID: ta.TenantID, Logger: tlog, Caps: caps, Export: exporter, Fleet: fleet}
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
	jobClient := jobpipeline.NewGraphJobClient(gc)
	store := checkpoint.NewStore(cfg.CheckpointDir)
	wdeps := collectors.WindowDeps{
		Graph:     gc,
		TenantID:  ta.TenantID,
		Logger:    tlog,
		Caps:      caps,
		Fetcher:   fetcher,
		JobClient: jobClient,
		Store:     store,
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

	// Blob collectors (read-only Azure Storage ingest, #89) — the one place
	// graph2otel reads from outside Graph, for the signals Graph has no endpoint
	// for at all. Configuring blob_ingest.account_url IS the opt-in: a tenant
	// that has provisioned no storage account registers none of these, so a
	// default deployment is untouched.
	registerBlobCollectors(cfg, ta, caps, store, tlog, registry, skips)

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

// registerBlobCollectors wires the tenant's blob-sourced collectors, if it has
// configured a storage account to read from.
//
// A Source build failure skips only the blob collectors: the tenant's Graph
// polling is unaffected, so a mistyped account URL or a missing storage role
// degrades this one lane rather than taking the tenant down. The skip is
// recorded per collector so the admin status page says why they are absent —
// otherwise "blob ingest is silently doing nothing" looks identical to "the
// data has not arrived yet", which is the documented way this path gets
// misdiagnosed.
func registerBlobCollectors(
	cfg *config.Config,
	ta *auth.TenantAuth,
	caps license.Capabilities,
	store *checkpoint.Store,
	tlog *slog.Logger,
	registry *collector.Registry,
	skips map[admin.SkipKey]string,
) {
	accountURL := tenantBlobAccountURL(cfg, ta.TenantID)
	if accountURL == "" {
		return
	}

	src, err := blobpipeline.NewAzureSource(accountURL, ta.Cred)
	if err != nil {
		tlog.Error("blob ingest disabled: building the storage source failed",
			"account_url", accountURL, "error", err)
		for _, bf := range collectors.BlobAll() {
			c := bf(collectors.BlobDeps{TenantID: ta.TenantID, Logger: tlog, Store: store})
			skips[admin.SkipKey{TenantID: ta.TenantID, Collector: c.Name()}] = "blob ingest unavailable: " + err.Error()
		}
		return
	}

	bdeps := collectors.BlobDeps{Source: src, TenantID: ta.TenantID, Logger: tlog, Store: store}
	for _, bf := range collectors.BlobAll() {
		c := bf(bdeps)
		if interval, ok := gateCollector(c, ta, cfg, caps, tlog, skips); ok {
			registry.Register(c, interval)
		}
	}
}

// tenantBlobAccountURL returns the storage account URL configured for tenantID,
// or "" when blob ingest is off for it.
func tenantBlobAccountURL(cfg *config.Config, tenantID string) string {
	for _, t := range cfg.Tenants {
		if t.TenantID == tenantID {
			return t.BlobIngest.AccountURL
		}
	}
	return ""
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
