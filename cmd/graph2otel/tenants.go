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
	"github.com/rknightion/graph2otel/internal/o365activityclient"
	"github.com/rknightion/graph2otel/internal/telemetry"
)

// startTenants builds one Graph client + collector set per configured tenant,
// gates each collector by license tier and config, and launches a per-tenant
// Scheduler goroutine bound to ctx. It returns the admin status sources (one
// per tenant) and the skip-reason map so the admin page can show both the
// running collectors and the ones deliberately not registered.
//
// A runtime failure never takes the process down for a single tenant's sake:
// an auth/client or license error for one tenant is logged and that tenant is
// skipped, so a misconfigured tenant can't take down the others. The returned
// wait func blocks until every launched Scheduler has drained (after ctx is
// canceled).
//
// The returned error is the narrow exception to that rule, and today it has
// exactly one source: a tenant registering two transports for the same records
// (#144). It is process-fatal because it is a config that was never working
// rather than a runtime fault, so there is nothing to degrade to and nothing to
// recover from — and the state it describes is invisible from the outside. The
// caller must cancel ctx and drain wait before exiting; tenants set up before
// the offending one may already be running.
func startTenants(
	ctx context.Context,
	cfg *config.Config,
	provider *telemetry.Provider,
	logger *slog.Logger,
) (sources []admin.CollectorSource, skips map[admin.SkipKey]string, wait func(), err error) {
	skips = map[admin.SkipKey]string{}
	var wg sync.WaitGroup

	// One limiter shared across tenants: its buckets are keyed per tenant
	// internally, so this correctly isolates each tenant's per-app throttle
	// budget while keeping a single instance.
	limiter := graphclient.NewWorkloadLimiter()

	auths, err := auth.BuildAll(cfg.Tenants)
	if err != nil {
		logger.Error("building tenant credentials", "error", err)
		return nil, skips, wg.Wait, nil
	}

	for _, ta := range auths {
		src, launched, ferr := setupTenant(ctx, ta, cfg, provider, logger, limiter, skips, &wg)
		if ferr != nil {
			return sources, skips, wg.Wait, ferr
		}
		if launched {
			sources = append(sources, src)
		}
	}
	return sources, skips, wg.Wait, nil
}

// setupTenant wires one tenant end to end.
//
// launched is false when the tenant could not be brought up (client build
// failed) — its collectors are skipped rather than aborting the whole process.
// A non-nil error is the opposite call: a configuration that must not run at
// all, so the caller aborts startup rather than continuing without this tenant.
// See the conflict check below for why that distinction exists.
func setupTenant(
	ctx context.Context,
	ta *auth.TenantAuth,
	cfg *config.Config,
	provider *telemetry.Provider,
	logger *slog.Logger,
	limiter *graphclient.WorkloadLimiter,
	skips map[admin.SkipKey]string,
	wg *sync.WaitGroup,
) (admin.CollectorSource, bool, error) {
	tlog := logger.With("tenant", ta.TenantID)
	emitter := provider.Emitter()

	gc, err := graphclient.NewClient(ctx, ta, graphclient.Options{
		Emitter:  emitter,
		Limiter:  limiter,
		TenantID: ta.TenantID,
	})
	if err != nil {
		tlog.Error("building Graph client", "error", err)
		return admin.CollectorSource{}, false, nil
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

	// The file-based checkpoint store, shared by everything that needs to survive
	// a restart: window collectors' watermarks (logpipeline + jobpipeline) and both
	// async engines' in-flight job ids (#118).
	store := checkpoint.NewStore(cfg.CheckpointDir)

	// Snapshot collectors (metric-shaped inventory polls). exporter runs the
	// Intune reports export-job pipeline (POST → poll → download → parse) for the
	// M5 export-based report collectors; it shares gc's instrumented, rate-limited
	// (48/min export bucket) transport for create/poll and a plain client for the
	// unauthenticated SAS download. Store/TenantID let it resume an export job it
	// created but had not downloaded when the process restarted, rather than
	// POSTing a second one against that same 48/min budget (#118).
	exporter := exportjob.New(gc, exportjob.DefaultDownloader(), exportjob.Options{
		Store:    store,
		TenantID: ta.TenantID,
	})
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
			registry.RegisterWindow(rw.Collector, interval, initialLookback(cfg, rw), rw.MaxWindow)
		}
	}

	// Blob collectors (read-only Azure Storage ingest, #89) — the one place
	// graph2otel reads from outside Graph, for the signals Graph has no endpoint
	// for at all. Configuring blob_ingest.account_url IS the opt-in: a tenant
	// that has provisioned no storage account registers none of these, so a
	// default deployment is untouched.
	registerBlobCollectors(cfg, ta, caps, store, tlog, registry, skips)

	// O365 Management Activity API collectors (#100) — the second non-Graph
	// first-party API. Unlike blob ingest this needs no infrastructure opt-in:
	// the tenant's existing credential just requests a different audience, so
	// these are default-on.
	registerO365Collectors(cfg, ta, caps, store, tlog, emitter, registry, skips)

	// Transport mutual-exclusion, checked AFTER every registration path above
	// and before anything is scheduled (#144). Position is load-bearing: run
	// between two paths and this silently stops seeing half the registry.
	//
	// This is the one condition that fails the PROCESS rather than skipping the
	// tenant, and the exception is deliberate. Every other failure here is
	// partial and recoverable at runtime — a dead credential, an unreachable
	// storage account, a missing license — so degrading one tenant beats taking
	// the fleet down. A conflicting pair is neither: it is a config that was
	// never working, it cannot heal, and its whole failure mode is that it looks
	// healthy while shipping every record twice into the operator's backend.
	// Booting is the harmful outcome. #117 drew the same line for an unwritable
	// checkpoint dir.
	if err := checkRegistryConflicts(registry); err != nil {
		return admin.CollectorSource{}, false, fmt.Errorf("tenant %s: %w", ta.TenantID, err)
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
	return admin.CollectorSource{TenantID: ta.TenantID, Registry: registry, Status: status}, true, nil
}

// checkRegistryConflicts refuses a tenant whose enabled collector set contains
// two transports for the same records (#144).
//
// It walks the assembled REGISTRY rather than re-walking collectors.All(),
// WindowAll(), BlobAll() and O365All(), and that is the whole reason it can be
// trusted. Every construction path funnels into this one Registry, so reading
// it sees all of them without knowing how many there are — a fifth path is
// covered the day it lands, for free.
//
// The alternative is precisely the bug #139/#100 records: collectordoc.Rows
// enumerated the registration paths by hand, O365All() landed as a fourth, and
// TestCollectorAnnotationsCoverEveryCollector went GREEN over a collector
// missing from the reference entirely — the gate passed because it was blind,
// not because it was satisfied. A conflict check that goes blind is worse
// still: it reports a config safe while it double-ships every record.
//
// What this shape moves the risk to is the CALL SITE — the check must run after
// ALL registration, never between two paths. See setupTenant, where it is the
// last thing before the scheduler launches.
func checkRegistryConflicts(reg *collector.Registry) error {
	entries := reg.Entries()
	cs := make([]collector.Collector, 0, len(entries))
	for _, e := range entries {
		cs = append(cs, e.Collector)
	}
	return collectors.CheckConflicts(cs)
}

// initialLookback resolves a window collector's cold-start backfill window:
// backfill.initial_lookback when the operator set one, else the collector's own
// built-in value (#118).
//
// This is the single place the config key is applied, deliberately. Threading it
// through WindowDeps into every collector factory would mean nine collectors each
// re-deciding the same precedence — and one that forgot would silently ignore the
// key. The factories keep declaring the value they were tuned with; the override
// happens once, here, at registration.
func initialLookback(cfg *config.Config, rw collectors.RegisteredWindow) time.Duration {
	if cfg.Backfill.InitialLookback > 0 {
		return cfg.Backfill.InitialLookback
	}
	return rw.InitialLookback
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

// registerO365Collectors wires the tenant's Office 365 Management Activity API
// collectors (#100).
//
// Unlike registerBlobCollectors there is no infrastructure gate: this API needs
// no storage account and no extra credential, only the tenant's existing one
// requesting the manage.office.com audience instead of Graph's. So these are
// default-on, which is the entire point — m365.unified_audit is Experimental
// only because the audit-query API it polls is beta-only, and this transport is
// stable v1.0.
//
// A client build failure skips only these collectors, exactly as a blob Source
// failure skips only that lane: the tenant's Graph polling is unaffected, and
// the skip is recorded per collector so the admin page says why they are absent.
// "Silently doing nothing" and "no data yet" must never look alike — that is the
// documented way this whole class of path gets misdiagnosed.
func registerO365Collectors(
	cfg *config.Config,
	ta *auth.TenantAuth,
	caps license.Capabilities,
	store *checkpoint.Store,
	tlog *slog.Logger,
	emitter telemetry.Emitter,
	registry *collector.Registry,
	skips map[admin.SkipKey]string,
) {
	types, err := tenantO365ContentTypes(cfg, ta.TenantID)
	if err != nil {
		tlog.Error("o365 activity disabled: invalid content_types", "error", err)
		recordO365Skips(store, ta, tlog, skips, "o365 activity unavailable: "+err.Error())
		return
	}

	client, err := o365activityclient.NewClient(ta, o365activityclient.Options{
		Emitter: emitter,
		// PublisherIdentifier is the tenant's OWN GUID, deliberately. Microsoft's
		// reference calls it "the tenant GUID of the vendor coding against the
		// API ... not the GUID of the customer", but that model is being retired:
		// the same page says "We're moving from a publisher-level limit to a
		// tenant-level limit", and the AF429 error text spells out
		// "PublisherId={1} = Tenant GUID used as PublisherIdentifier".
		//
		// The vendor reading would also be actively wrong for an OSS tool: every
		// graph2otel deployment worldwide would send the same publisher GUID and
		// pool into ONE shared quota — precisely the behavior the docs describe
		// escaping. Sending each tenant's own GUID gets each its own 2,000/min.
		PublisherIdentifier: ta.TenantID,
		Limiter:             o365activityclient.NewLimiter(),
	})
	if err != nil {
		tlog.Error("o365 activity disabled: building the client failed", "error", err)
		recordO365Skips(store, ta, tlog, skips, "o365 activity unavailable: "+err.Error())
		return
	}

	odeps := collectors.O365Deps{
		Client:       client,
		ContentTypes: types,
		TenantID:     ta.TenantID,
		Logger:       tlog,
		Store:        store,
	}
	for _, of := range collectors.O365All() {
		rw := of(odeps)
		if rw.Collector == nil {
			continue
		}
		if interval, ok := gateCollector(rw.Collector, ta, cfg, caps, tlog, skips); ok {
			registry.RegisterWindow(rw.Collector, interval, initialLookback(cfg, rw), rw.MaxWindow)
		}
	}
}

// recordO365Skips marks every O365 collector absent-with-a-reason. Constructed
// with a nil Client purely to read each collector's Name(); the factories do no
// I/O at construction.
func recordO365Skips(
	store *checkpoint.Store,
	ta *auth.TenantAuth,
	tlog *slog.Logger,
	skips map[admin.SkipKey]string,
	reason string,
) {
	for _, of := range collectors.O365All() {
		rw := of(collectors.O365Deps{TenantID: ta.TenantID, Logger: tlog, Store: store})
		if rw.Collector == nil {
			continue
		}
		skips[admin.SkipKey{TenantID: ta.TenantID, Collector: rw.Collector.Name()}] = reason
	}
}

// tenantO365ContentTypes resolves and validates the tenant's configured content
// types. A nil result means "unset" — the collector then uses its own default.
//
// Validation is here rather than in the collector so a typo fails loudly at
// startup instead of becoming a silent 400 on every tick.
func tenantO365ContentTypes(cfg *config.Config, tenantID string) ([]o365activityclient.ContentType, error) {
	for _, t := range cfg.Tenants {
		if t.TenantID != tenantID {
			continue
		}
		if len(t.O365Activity.ContentTypes) == 0 {
			return nil, nil
		}
		out := make([]o365activityclient.ContentType, 0, len(t.O365Activity.ContentTypes))
		for _, s := range t.O365Activity.ContentTypes {
			ct := o365activityclient.ContentType(s)
			if !ct.Valid() {
				return nil, fmt.Errorf("unknown content type %q (valid: %v)", s, o365activityclient.ContentTypes())
			}
			out = append(out, ct)
		}
		return out, nil
	}
	return nil, nil
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
