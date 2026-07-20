package main

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"strings"
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
	"github.com/rknightion/graph2otel/internal/mdcaclient"
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
) (sources []admin.CollectorSource, skips map[admin.SkipKey]string, limiter *graphclient.WorkloadLimiter, wait func(), err error) {
	skips = map[admin.SkipKey]string{}
	var wg sync.WaitGroup

	// One limiter shared across tenants: its buckets are keyed per tenant
	// internally, so this correctly isolates each tenant's per-app throttle
	// budget while keeping a single instance. It is returned so the admin status
	// page can render its per-tenant throttle-headroom panel (#85).
	limiter = graphclient.NewWorkloadLimiter()

	auths, err := auth.BuildAll(cfg.Tenants)
	if err != nil {
		logger.Error("building tenant credentials", "error", err)
		return nil, skips, limiter, wg.Wait, nil
	}

	for _, ta := range auths {
		src, launched, ferr := setupTenant(ctx, ta, cfg, provider, logger, limiter, skips, &wg)
		if ferr != nil {
			return sources, skips, limiter, wg.Wait, ferr
		}
		if launched {
			sources = append(sources, src)
		}
	}
	return sources, skips, limiter, wg.Wait, nil
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
	deps := collectors.Deps{Graph: gc, TenantID: ta.TenantID, Logger: tlog, Caps: caps, Export: exporter, Fleet: fleet, Store: store}
	// polledNames records the stable name of every graph/window (polled)
	// collector, gated in or not, so a same-named blob twin can be recognized as
	// the second TRANSPORT of a polled collector and selected against it by
	// `source: graph|blob` (#135 group D) rather than registered as an always-on
	// duplicate. blobConfigured guards the source=blob path from silently
	// disabling a collector when there is no blob source to switch to.
	polledNames := map[string]bool{}
	blobConfigured := tenantBlobAccountURL(cfg, ta.TenantID) != ""
	// #135-C: a polled collector that emits both gauges and a per-entity twin
	// (entra.risk, intune.devices) suppresses its twin when a blob-sourced twin
	// owns it and will actually run (blob configured AND the blob collector
	// enabled) — the same per-entity record must not ship on both transports.
	// Gauges are unaffected. Computed BEFORE the factory loop so every polled
	// collector reads a stable set. Unlike the log-only source: graph|blob swap
	// (#135-D), here the polled collector keeps running for its gauges.
	deps.SuppressedTwins = collectors.SuppressedTwins(blobConfigured, func(name string) bool {
		enabled, _ := cfg.CollectorSettings(ta.TenantID, name)
		return enabled
	})
	for _, factory := range collectors.All() {
		c := factory(deps)
		polledNames[c.Name()] = true
		if interval, ok := gateCollector(c, ta, cfg, caps, tlog, skips); ok {
			registry.Register(c, interval)
		}
	}

	// Window collectors (log-shaped event-stream polls on the logpipeline
	// engine). They share the tenant's single instrumented, rate-limited
	// transport (one PageFetcher over gc) and the file-based checkpoint store.
	fetcher := logpipeline.NewGraphPageFetcher(gc)
	jobClient := jobpipeline.NewGraphJobClient(gc)
	// exclude_self also filters the Graph-polled service-principal sign-in stream
	// (#176): the same tenant flag that drops the poller's blob exhaust drops its
	// own SP sign-ins. The self-share there is small (~1.1% live-measured) so this
	// is off by default, but it is wired through so a tenant that opts in filters
	// both transports with one key. A window collector that is not self-excludable
	// simply ignores these fields.
	wExcludeSelf, wClientID := tenantExcludeSelf(cfg, ta.TenantID)
	wdeps := collectors.WindowDeps{
		Graph:        gc,
		TenantID:     ta.TenantID,
		Logger:       tlog,
		Caps:         caps,
		Fetcher:      fetcher,
		JobClient:    jobClient,
		Store:        store,
		ExcludeSelf:  wExcludeSelf,
		SelfClientID: wClientID,
	}
	for _, wf := range collectors.WindowAll() {
		rw := wf(wdeps)
		if rw.Collector == nil {
			continue
		}
		wname := rw.Collector.Name()
		polledNames[wname] = true
		// source: blob selects the blob transport for a source-switchable
		// collector — skip its polled (graph) registration so the same-named blob
		// twin (registerBlobCollectors) is the one that runs. Exactly one side
		// registers, so the event is never ingested twice (#135 group D).
		wsource := cfg.CollectorSource(ta.TenantID, wname)
		if !graphPollingActive(wsource, blobConfigured) {
			tlog.Info("collector source is blob: graph polling disabled; the blob twin is active", "collector", wname)
			continue
		}
		if wsource == "blob" {
			tlog.Warn("collector source=blob but no blob_ingest.account_url is configured; falling back to graph polling", "collector", wname)
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
	registerBlobCollectors(cfg, ta, caps, store, tlog, registry, skips, polledNames)

	// O365 Management Activity API collectors (#100) — the second non-Graph
	// first-party API. Unlike blob ingest this needs no infrastructure opt-in:
	// the tenant's existing credential just requests a different audience, so
	// these are default-on.
	registerO365Collectors(cfg, ta, caps, store, tlog, emitter, registry, skips)

	// MDCA Cloud Discovery collectors (#145) — the FIFTH registration path and
	// the one non-Graph, non-poller signal. Opt-in like blob ingest: setting the
	// tenant's mdca.portal_url is the switch, so a tenant with no mdca block
	// registers none of these.
	registerMDCACollectors(cfg, ta, caps, store, tlog, emitter, registry, skips)

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
	// The transport baseline (#141). Every collector receives its emitter from
	// the Scheduler, so this is the one seam that reaches all of them — including
	// the SnapshotCollector log twins (entra/risk being the reference shape) that
	// poll Graph and emit inline with no engine between them and the emitter.
	// "graph" is the truthful default for those.
	//
	// Everything that is NOT a direct Graph poll re-wraps with its own transport
	// closer to the record, and the outermost stamp wins, so this baseline never
	// clobbers a truer one: the four engines stamp at their own entry points, and
	// the three exportjob collectors stamp themselves (exportjob emits no logs, so
	// report_export has no engine seam — see appinstallreport.Collect).
	//
	// Self-obs is unaffected by the transport stamp: emitScrapeMetrics and
	// emitCheckpointPersistError emit metrics only, and that decorator is
	// log-only by design (#82).
	//
	// WithTenant (#143) wraps outermost and is the mirror image: it stamps
	// METRICS as well as logs, because without it two tenants' domain metrics are
	// the same series rather than merely unsliceable. It is the same seam for the
	// same reason — the Scheduler is the one place that reaches all 58 collectors
	// — and collector.WithTenant below already gave the Scheduler this tenant for
	// self-obs labels and checkpoint namespacing. Self-obs metrics reach the
	// decorator already stamped by selfObsAttrs with the identical value, and the
	// first stamp wins, so they are unchanged.
	sched := collector.NewScheduler(
		telemetry.WithTenant(
			telemetry.WithTransport(emitter, telemetry.TransportGraph), ta.TenantID),
		collector.NewMemoryStore(),
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
// WindowAll(), BlobAll(), O365All() and MDCAAll(), and that is the whole reason
// it can be trusted. Every construction path funnels into this one Registry, so
// reading it sees all of them without knowing how many there are — MDCAAll()
// landed as the fifth path and was covered for free.
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
// graphPollingActive reports whether a source-switchable collector's polled
// (graph) registration should run. It is skipped ONLY when source=blob AND a
// blob source is actually configured to take over — so source=blob with no blob
// ingest falls back to graph rather than leaving the collector running nowhere
// (#135 group D).
func graphPollingActive(source string, blobConfigured bool) bool {
	return source != "blob" || !blobConfigured
}

// blobTwinSelected reports whether a blob collector should register. A blob
// collector whose name also belongs to a polled collector is that collector's
// second TRANSPORT (a source-switchable twin) and registers only when
// source=blob; a pure-blob collector (no polled twin) always registers. Together
// with graphPollingActive this makes graph and blob mutually exclusive per
// collector: exactly one side registers, so an event is never ingested twice.
func blobTwinSelected(name string, polledNames map[string]bool, source string) bool {
	return !polledNames[name] || source == "blob"
}

func registerBlobCollectors(
	cfg *config.Config,
	ta *auth.TenantAuth,
	caps license.Capabilities,
	store *checkpoint.Store,
	tlog *slog.Logger,
	registry *collector.Registry,
	skips map[admin.SkipKey]string,
	polledNames map[string]bool,
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

	excludeSelf, clientID := tenantExcludeSelf(cfg, ta.TenantID)
	if excludeSelf && clientID == "" {
		// exclude_self on but no way to identify "self": the filter would no-op
		// silently, which is the exact failure mode the loud-drop design (#154)
		// exists to avoid. Say so once at startup rather than leaving an operator
		// to wonder why a ~60% reduction never appeared. (Emitted once at the blob
		// path; the window path shares the same resolver so a second warning would
		// be redundant.)
		tlog.Warn("exclude_self is enabled but 'self' cannot be identified; "+
			"self-exhaust filtering is DISABLED — set tenants[].client_id to the poller's "+
			"app registration ID, or provide AZURE_CLIENT_ID in the environment (#176)",
			"tenant", ta.TenantID)
	}
	bdeps := collectors.BlobDeps{
		Source: src, TenantID: ta.TenantID, Logger: tlog, Store: store,
		ExcludeSelf: excludeSelf, SelfClientID: clientID,
		MetricRecencyWindow: cfg.BlobMetricRecencyWindow(ta.TenantID),
	}
	for _, bf := range collectors.BlobAll() {
		c := bf(bdeps)
		// A blob collector whose name matches a polled collector is that
		// collector's second TRANSPORT (#135 group D): register it only when
		// source=blob, so it and the polled twin are never both active. A
		// pure-blob collector (no polled twin — sign-ins, graph_activity) has no
		// name match and always registers, exactly as before.
		if !blobTwinSelected(c.Name(), polledNames, cfg.CollectorSource(ta.TenantID, c.Name())) {
			continue
		}
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

// registerMDCACollectors wires the tenant's MDCA Cloud Discovery collectors
// (#145), the fifth registration path.
//
// Opt-in like blob ingest: a tenant with no mdca.portal_url registers none of
// these and records no skips (there is nothing to be absent). When it IS
// configured, the static token is read from mdca.token_file — never from YAML or
// env, because a per-tenant secret has no env path in this config (koanf cannot
// bind a value into a tenants[] slice element; it wipes the slice). A token-file
// read failure or a client-build failure skips only these collectors and records
// the reason per collector, exactly as a blob Source failure skips only that
// lane — "silently doing nothing" and "no data yet" must never look alike.
func registerMDCACollectors(
	cfg *config.Config,
	ta *auth.TenantAuth,
	caps license.Capabilities,
	store *checkpoint.Store,
	tlog *slog.Logger,
	emitter telemetry.Emitter,
	registry *collector.Registry,
	skips map[admin.SkipKey]string,
) {
	mc := tenantMDCAConfig(cfg, ta.TenantID)
	if !mc.Configured() {
		return // opt-out: no mdca block, nothing to register or skip.
	}

	token, err := os.ReadFile(mc.TokenFile)
	if err != nil {
		tlog.Error("mdca disabled: reading token_file failed", "path", mc.TokenFile, "error", err)
		recordMDCASkips(store, ta, tlog, skips, "mdca unavailable: reading token_file failed: "+err.Error())
		return
	}
	client, err := mdcaclient.NewClient(ta.TenantID, mdcaclient.Options{
		Emitter: emitter,
		BaseURL: mc.PortalURL,
		Token:   strings.TrimSpace(string(token)),
		Limiter: mdcaclient.NewLimiter(),
	})
	if err != nil {
		tlog.Error("mdca disabled: building the client failed", "error", err)
		recordMDCASkips(store, ta, tlog, skips, "mdca unavailable: "+err.Error())
		return
	}

	mdeps := collectors.MDCADeps{
		Client:   client,
		TenantID: ta.TenantID,
		Logger:   tlog,
		Store:    store,
	}
	for _, mf := range collectors.MDCAAll() {
		rw := mf(mdeps)
		if rw.Collector == nil {
			continue
		}
		if interval, ok := gateCollector(rw.Collector, ta, cfg, caps, tlog, skips); ok {
			registry.RegisterWindow(rw.Collector, interval, initialLookback(cfg, rw), rw.MaxWindow)
		}
	}
}

// recordMDCASkips marks every MDCA collector absent-with-a-reason. Constructed
// with a nil Client purely to read each collector's Name(); the factories do no
// I/O at construction.
func recordMDCASkips(
	store *checkpoint.Store,
	ta *auth.TenantAuth,
	tlog *slog.Logger,
	skips map[admin.SkipKey]string,
	reason string,
) {
	for _, mf := range collectors.MDCAAll() {
		rw := mf(collectors.MDCADeps{TenantID: ta.TenantID, Logger: tlog, Store: store})
		if rw.Collector == nil {
			continue
		}
		skips[admin.SkipKey{TenantID: ta.TenantID, Collector: rw.Collector.Name()}] = reason
	}
}

// tenantMDCAConfig returns the tenant's MDCA block, or a zero (opt-out) value if
// the tenant is not found.
func tenantMDCAConfig(cfg *config.Config, tenantID string) config.MDCAConfig {
	for _, t := range cfg.Tenants {
		if t.TenantID == tenantID {
			return t.MDCA
		}
	}
	return config.MDCAConfig{}
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

// tenantExcludeSelf returns the tenant's exclude_self flag and its poller
// client_id — the two values every transport's self-exhaust filter needs (#176,
// generalized from #154's blob-only tenantBlobExcludeSelf). The flag is a
// tenant-level key (tenants[].exclude_self) because "self" spans transports; the
// client_id is the identity "self" is matched against, and an empty one leaves
// the filter unable to identify self (it then no-ops, and the caller warns).
func tenantExcludeSelf(cfg *config.Config, tenantID string) (excludeSelf bool, clientID string) {
	for _, t := range cfg.Tenants {
		if t.TenantID == tenantID {
			clientID = t.ClientID
			if clientID == "" {
				// The poller commonly authenticates through
				// DefaultAzureCredential's AZURE_CLIENT_ID env leg (camden does),
				// which never lands in config — so fall back to it, else
				// exclude_self silently no-ops on the exact production deployment
				// it exists for. Config client_id still wins, so a multi-tenant
				// process running a distinct app per tenant stays per-tenant
				// correct (#176).
				clientID = os.Getenv("AZURE_CLIENT_ID")
			}
			return t.ExcludeSelf, clientID
		}
	}
	return false, ""
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
