package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/rknightion/graph2otel/internal/admin"
	"github.com/rknightion/graph2otel/internal/armclient"
	"github.com/rknightion/graph2otel/internal/auth"
	"github.com/rknightion/graph2otel/internal/availability"
	"github.com/rknightion/graph2otel/internal/blobpipeline"
	"github.com/rknightion/graph2otel/internal/checkpoint"
	"github.com/rknightion/graph2otel/internal/collector"
	"github.com/rknightion/graph2otel/internal/collectors"
	"github.com/rknightion/graph2otel/internal/config"
	"github.com/rknightion/graph2otel/internal/exoclient"
	"github.com/rknightion/graph2otel/internal/exportjob"
	"github.com/rknightion/graph2otel/internal/graphclient"
	"github.com/rknightion/graph2otel/internal/huntclient"
	"github.com/rknightion/graph2otel/internal/jobpipeline"
	"github.com/rknightion/graph2otel/internal/license"
	"github.com/rknightion/graph2otel/internal/logpipeline"
	"github.com/rknightion/graph2otel/internal/mdcaclient"
	"github.com/rknightion/graph2otel/internal/o365activityclient"
	"github.com/rknightion/graph2otel/internal/telemetry"
)

// runtimeFactoryVisitor owns the runtime view of every collector registration
// family. Its explicit implementation is a compile-time tripwire: a newly
// added family cannot be registered at runtime without extending this type.
type runtimeFactoryVisitor struct {
	snapshot []collectors.Factory
	window   []collectors.WindowFactory
	blob     []collectors.BlobFactory
	o365     []collectors.O365Factory
	mdca     []collectors.MDCAFactory
	exo      []collectors.EXOFactory
	hunt     []collectors.HuntFactory
}

func (v *runtimeFactoryVisitor) Snapshot(fs []collectors.Factory)     { v.snapshot = fs }
func (v *runtimeFactoryVisitor) Window(fs []collectors.WindowFactory) { v.window = fs }
func (v *runtimeFactoryVisitor) Blob(fs []collectors.BlobFactory)     { v.blob = fs }
func (v *runtimeFactoryVisitor) O365(fs []collectors.O365Factory)     { v.o365 = fs }
func (v *runtimeFactoryVisitor) MDCA(fs []collectors.MDCAFactory)     { v.mdca = fs }
func (v *runtimeFactoryVisitor) EXO(fs []collectors.EXOFactory)       { v.exo = fs }
func (v *runtimeFactoryVisitor) Hunt(fs []collectors.HuntFactory)     { v.hunt = fs }

var _ collectorFactoryVisitor = (*runtimeFactoryVisitor)(nil)

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
type tenantAuthBuilder func(config.TenantConfig) (*auth.TenantAuth, error)

type tenantSetup func(
	context.Context,
	*auth.TenantAuth,
	*config.Config,
	*telemetry.Provider,
	*slog.Logger,
	*graphclient.WorkloadLimiter,
	map[admin.SkipKey]string,
	*sync.WaitGroup,
) (admin.CollectorSource, error)

type tenantGraphClientBuilder func(
	context.Context,
	*auth.TenantAuth,
	graphclient.Options,
) (*graphclient.Client, error)

type tenantLicenseDetector func(
	context.Context,
	*graphclient.Client,
) (license.Capabilities, error)

type availabilityStartupFailure struct {
	family    availabilityFamily
	transport telemetry.Transport
	collector string
	reason    availability.Reason
}

func startTenants(
	ctx context.Context,
	cfg *config.Config,
	provider *telemetry.Provider,
	logger *slog.Logger,
) (sources []admin.CollectorSource, skips map[admin.SkipKey]string, limiter *graphclient.WorkloadLimiter, wait func(), err error) {
	return startTenantsWithBuilders(ctx, cfg, provider, logger, auth.NewTenantAuth, setupTenant)
}

// startTenantsWithBuilders is the injectable composition-root seam for tenant
// startup. Production supplies auth.NewTenantAuth and setupTenant; tests replace
// only those external construction boundaries so the retention/order contract
// is exercised without contacting Entra or Graph.
func startTenantsWithBuilders(
	ctx context.Context,
	cfg *config.Config,
	provider *telemetry.Provider,
	logger *slog.Logger,
	buildAuth tenantAuthBuilder,
	setup tenantSetup,
) (sources []admin.CollectorSource, skips map[admin.SkipKey]string, limiter *graphclient.WorkloadLimiter, wait func(), err error) {
	skips = map[admin.SkipKey]string{}
	var wg sync.WaitGroup

	// One limiter shared across tenants: its buckets are keyed per tenant
	// internally, so this correctly isolates each tenant's per-app throttle
	// budget while keeping a single instance. It is returned so the admin status
	// page can render its per-tenant throttle-headroom panel (#85).
	limiter = graphclient.NewWorkloadLimiter()

	for _, tenantCfg := range cfg.Tenants {
		inventory := resolveAvailabilityInventory(cfg, tenantCfg.TenantID, nil, false)
		ta, buildErr := buildAuth(tenantCfg)
		if buildErr != nil || ta == nil {
			if buildErr == nil {
				buildErr = errors.New("credential builder returned nil TenantAuth")
			}
			logger.Error("building tenant credential", "tenant", tenantCfg.TenantID, "error", buildErr)
			tracker := availability.NewTracker(
				tenantCfg.TenantID,
				startupFailedInventory(
					inventory,
					cfg,
					tenantCfg.TenantID,
					nil,
					false,
					availability.ReasonCredentialInitializationFailed,
				),
			)
			if provider != nil {
				tracker.Emit(provider.Emitter())
			}
			sources = append(sources, admin.CollectorSource{
				TenantID:       tenantCfg.TenantID,
				Availability:   tracker,
				StartupFailure: admin.StartupFailureCredentialInitialization,
			})
			continue
		}

		src, ferr := setup(ctx, ta, cfg, provider, logger, limiter, skips, &wg)
		if ferr != nil {
			return sources, skips, limiter, wg.Wait, ferr
		}
		// Config order and identity are the operator contract. The production
		// auth builder copies this ID, but pinning it here also prevents a faulty
		// injected builder from losing or reordering the configured tenant row.
		src.TenantID = tenantCfg.TenantID
		sources = append(sources, src)
	}
	return sources, skips, limiter, wg.Wait, nil
}

func startupFailedInventory(
	inventory []availability.Static,
	cfg *config.Config,
	tenantID string,
	caps license.Capabilities,
	licenseKnown bool,
	reason availability.Reason,
) []availability.Static {
	candidates := availabilityCandidates()
	selected := make([]availabilityCandidate, 0, 148)
	statics := make([]availability.Static, 0, 148)
	blobConfigured := tenantBlobAccountURL(cfg, tenantID) != ""
	for start := 0; start < len(candidates); {
		end := start + 1
		for end < len(candidates) && candidates[end].Name == candidates[start].Name {
			end++
		}
		candidate, fallback := selectAvailabilityCandidate(
			cfg, tenantID, candidates[start:end], blobConfigured,
		)
		static := resolveAvailabilityStatic(
			cfg, tenantID, candidate, caps, licenseKnown, blobConfigured, fallback,
		)
		if static.State != availability.StateDisabled {
			static.State = availability.StateStartupFailed
			static.Reason = reason
			static.Limitations = nil
		}
		selected = append(selected, candidate)
		statics = append(statics, static)
		start = end
	}
	applyAvailabilityCoverage(statics, selected)
	if len(statics) != len(inventory) {
		panic("availability inventory: tenant-wide startup failure changed census size")
	}
	return statics
}

func applyAvailabilityStartupFailures(
	inventory []availability.Static,
	cfg *config.Config,
	tenantID string,
	caps license.Capabilities,
	licenseKnown bool,
	failures []availabilityStartupFailure,
) {
	if len(failures) == 0 {
		return
	}
	candidates := availabilityCandidates()
	selected := make([]availabilityCandidate, 0, len(inventory))
	statics := make([]availability.Static, 0, len(inventory))
	blobConfigured := tenantBlobAccountURL(cfg, tenantID) != ""
	for start := 0; start < len(candidates); {
		end := start + 1
		for end < len(candidates) && candidates[end].Name == candidates[start].Name {
			end++
		}
		candidate, fallback := selectAvailabilityCandidate(
			cfg, tenantID, candidates[start:end], blobConfigured,
		)
		static := resolveAvailabilityStatic(
			cfg, tenantID, candidate, caps, licenseKnown, blobConfigured, fallback,
		)
		for _, failure := range failures {
			if !availabilityFailureMatches(failure, candidate) ||
				!availabilityStaticActive(static) {
				continue
			}
			static.State = availability.StateStartupFailed
			static.Reason = failure.reason
			static.Limitations = nil
			break
		}
		selected = append(selected, candidate)
		statics = append(statics, static)
		start = end
	}
	applyAvailabilityCoverage(statics, selected)
	if len(inventory) != len(statics) {
		panic("availability inventory: startup override changed census size")
	}
	copy(inventory, statics)
}

func availabilityFailureMatches(
	failure availabilityStartupFailure,
	candidate availabilityCandidate,
) bool {
	if failure.collector != "" && failure.collector != candidate.Name {
		return false
	}
	if failure.family != "" && failure.family != candidate.Family {
		return false
	}
	return failure.transport == "" || failure.transport == candidate.Transport
}

// runtimeCollectorReady prevents a configured factory from silently declining
// after its canonical census row was resolved active. Optional factories may
// still return nil when their transport is intentionally disabled; that absence
// is already represented by the census and needs no startup failure.
func runtimeCollectorReady(
	c collector.Collector,
	expected availabilityCandidate,
	inventory []availability.Static,
	failures *[]availabilityStartupFailure,
	logger *slog.Logger,
) bool {
	active := false
	for _, static := range inventory {
		if static.Collector != expected.Name || static.Transport != expected.Transport {
			continue
		}
		active = availabilityStaticActive(static)
		break
	}
	if !active {
		return false
	}
	if c != nil && c.Name() == expected.Name {
		return true
	}
	if c == nil || c.Name() != expected.Name {
		logger.Error(
			"configured collector factory did not construct its canonical runtime collector",
			"collector", expected.Name,
			"family", expected.Family,
		)
		*failures = append(*failures, availabilityStartupFailure{
			family:    expected.Family,
			transport: expected.Transport,
			collector: expected.Name,
			reason:    availability.ReasonTransportInitializationFailed,
		})
	}
	return false
}

func validateRuntimeRegistryCensus(
	registry *collector.Registry,
	inventory []availability.Static,
) error {
	canonical := make(map[string]struct{}, len(inventory))
	for _, static := range inventory {
		canonical[static.Collector] = struct{}{}
	}
	for _, entry := range registry.Entries() {
		name := entry.Collector.Name()
		if _, ok := canonical[name]; !ok {
			return fmt.Errorf("runtime collector %q is absent from the canonical availability census", name)
		}
	}
	return nil
}

// setupTenant wires one tenant end to end.
//
// A Graph-client construction failure is returned as a retained source with a
// bounded StartupFailure code. A non-nil error is the opposite call: a
// configuration that must not run at all, so the caller aborts startup rather
// than continuing without this tenant. See the conflict check below for why
// that distinction exists.
func setupTenant(
	ctx context.Context,
	ta *auth.TenantAuth,
	cfg *config.Config,
	provider *telemetry.Provider,
	logger *slog.Logger,
	limiter *graphclient.WorkloadLimiter,
	skips map[admin.SkipKey]string,
	wg *sync.WaitGroup,
) (admin.CollectorSource, error) {
	return setupTenantWithGraphAndLicenseBuilders(
		ctx, ta, cfg, provider, logger, limiter, skips, wg,
		graphclient.NewClient,
		func(ctx context.Context, client *graphclient.Client) (license.Capabilities, error) {
			return license.Detect(ctx, license.NewGraphSkuLister(client))
		},
	)
}

func setupTenantWithGraphClientBuilder(
	ctx context.Context,
	ta *auth.TenantAuth,
	cfg *config.Config,
	provider *telemetry.Provider,
	logger *slog.Logger,
	limiter *graphclient.WorkloadLimiter,
	skips map[admin.SkipKey]string,
	wg *sync.WaitGroup,
	buildGraphClient tenantGraphClientBuilder,
) (admin.CollectorSource, error) {
	return setupTenantWithGraphAndLicenseBuilders(
		ctx, ta, cfg, provider, logger, limiter, skips, wg,
		buildGraphClient,
		func(ctx context.Context, client *graphclient.Client) (license.Capabilities, error) {
			return license.Detect(ctx, license.NewGraphSkuLister(client))
		},
	)
}

func setupTenantWithGraphAndLicenseBuilders(
	ctx context.Context,
	ta *auth.TenantAuth,
	cfg *config.Config,
	provider *telemetry.Provider,
	logger *slog.Logger,
	limiter *graphclient.WorkloadLimiter,
	skips map[admin.SkipKey]string,
	wg *sync.WaitGroup,
	buildGraphClient tenantGraphClientBuilder,
	detectLicense tenantLicenseDetector,
) (admin.CollectorSource, error) {
	tlog := logger.With("tenant", ta.TenantID)
	emitter := provider.Emitter()
	inventory := resolveAvailabilityInventory(cfg, ta.TenantID, nil, false)
	var availabilityFailures []availabilityStartupFailure

	// Prove the configured directory before constructing any tenant-labeled
	// ingest path. TenantAuth's credential wrapper pins every request and
	// verifies the returned tid claim; doing one request here prevents a
	// blob-only or otherwise idle Graph path from emitting under an unproved
	// tenant label.
	if err := ta.SmokeToken(ctx); err != nil {
		tlog.Error("proving tenant credential", "error", err)
		tracker := availability.NewTracker(
			ta.TenantID,
			startupFailedInventory(
				inventory,
				cfg,
				ta.TenantID,
				nil,
				false,
				availability.ReasonCredentialInitializationFailed,
			),
		)
		tracker.Emit(emitter)
		return admin.CollectorSource{
			TenantID:       ta.TenantID,
			Availability:   tracker,
			StartupFailure: admin.StartupFailureCredentialInitialization,
		}, nil
	}

	gc, err := buildGraphClient(ctx, ta, graphclient.Options{
		Emitter:  emitter,
		Limiter:  limiter,
		TenantID: ta.TenantID,
	})
	if err != nil {
		tlog.Error("building Graph client", "error", err)
		tracker := availability.NewTracker(
			ta.TenantID,
			startupFailedInventory(
				inventory,
				cfg,
				ta.TenantID,
				nil,
				false,
				availability.ReasonGraphClientInitializationFailed,
			),
		)
		tracker.Emit(emitter)
		return admin.CollectorSource{
			TenantID:       ta.TenantID,
			Availability:   tracker,
			StartupFailure: admin.StartupFailureGraphClientInitialization,
		}, nil
	}

	// License detection is best-effort: on failure, proceed with no premium
	// capabilities (gated collectors skip, ungated collectors still run) rather
	// than taking the tenant down.
	caps, err := detectLicense(ctx, gc)
	licenseKnown := err == nil
	if err != nil {
		tlog.Warn("license detection failed; proceeding with base tier", "error", err)
	}
	inventory = resolveAvailabilityInventory(cfg, ta.TenantID, caps, licenseKnown)
	license.EmitLicenseTier(emitter, ta.TenantID, caps)

	registry := collector.NewRegistry()

	// The file-based checkpoint store, shared by everything that needs to survive
	// a restart: window collectors' watermarks (logpipeline + jobpipeline) and both
	// async engines' in-flight job ids (#118).
	store := checkpoint.NewStore(cfg.CheckpointDir)
	schedulerStore, schedulerStoreErr := newTenantSchedulerStore(cfg, ta.TenantID)
	if schedulerStoreErr != nil {
		if errors.Is(schedulerStoreErr, collector.ErrCorruptCheckpoint) {
			tlog.Warn(
				"scheduler checkpoint file is corrupt; starting its window cursors cold",
				"error",
				schedulerStoreErr,
			)
		} else {
			return admin.CollectorSource{}, fmt.Errorf(
				"tenant %s: open scheduler checkpoint store: %w",
				ta.TenantID,
				schedulerStoreErr,
			)
		}
	}

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
	deps := collectors.Deps{
		Graph: gc, TenantID: ta.TenantID, Logger: tlog, Caps: caps,
		Export: exporter, Fleet: fleet, Store: store,
		PrivilegedGroupAllowlist: tenantPrivilegedGroupIDs(cfg, ta.TenantID),
	}
	var paths runtimeFactoryVisitor
	visitRegisteredCollectorFactories(&paths)
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
	// The blob-category census (#238) reads the aadiam diagnostic-settings object
	// on the ARM control plane (authorized by the poller's Entra roles, not Azure
	// RBAC) and diffs it against the containers graph2otel's blob collectors read.
	// Only wired when blob ingest is configured — there is nothing to census
	// otherwise, and a nil ARM is treated as a composition-root wiring failure.
	// The container set is
	// the same one every blob collector declares (BlobContainers introspects the
	// registry), so a new blob collector is counted the moment it is registered.
	if blobConfigured {
		deps.ARM = armclient.NewClient(ta.Cred, armclient.Options{Logger: tlog})
		deps.BlobContainerNames = collectors.BlobContainers(ta.TenantID, tlog)
	}
	for _, factory := range paths.snapshot {
		expected := newAvailabilityCandidate(
			factory(collectors.Deps{}),
			availabilityFamilySnapshot,
		)
		c := factory(deps)
		if !runtimeCollectorReady(c, expected, inventory, &availabilityFailures, tlog) {
			continue
		}
		if c.Name() == "graph2otel.blob_categories" && !blobConfigured {
			continue
		}
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
	// own SP sign-ins. Resolve the application identity once from the token issued
	// to this TenantAuth, then reuse that proof across both transport paths. A
	// configured client_id is only a consistency assertion; it is never the
	// comparison authority.
	selfIdentity := resolveTenantSelfIdentity(ctx, cfg, ta, logger)
	// The Exchange Online client is built HERE, once, rather than inside
	// registerEXOCollectors, because two paths now need it: the EXO snapshot
	// collectors and the window collectors whose stream lives on that transport
	// (m365.message_trace). Building it twice would give the tenant two
	// independent client-side rate limiters over one service — that is, no
	// effective limit at all — so both paths share this instance. It is nil, and
	// buildErr is nil, for a tenant with no exchange_online block.
	exoClient, exoBuildErr := tenantEXOClient(cfg, ta, tlog, emitter)
	wdeps := collectors.WindowDeps{
		Graph:     gc,
		EXO:       exoClient,
		TenantID:  ta.TenantID,
		Logger:    tlog,
		Caps:      caps,
		Fetcher:   fetcher,
		JobClient: jobClient,
		Store:     store,
	}
	selfIdentity.applyWindow(&wdeps)
	for _, wf := range paths.window {
		expected := newAvailabilityCandidate(
			wf(snapshotWindowDeps()).Collector,
			availabilityFamilyWindow,
		)
		rw := wf(wdeps)
		if !runtimeCollectorReady(
			rw.Collector, expected, inventory, &availabilityFailures, tlog,
		) {
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
	if reason := registerBlobCollectors(
		cfg, ta, caps, store, tlog, selfIdentity, registry, skips, polledNames, paths.blob,
		func(accountURL string, ta *auth.TenantAuth) (blobpipeline.Source, error) {
			return blobpipeline.NewAzureSource(accountURL, ta.Cred)
		},
		inventory,
		&availabilityFailures,
	); reason != "" {
		clear(deps.SuppressedTwins)
		availabilityFailures = append(availabilityFailures, availabilityStartupFailure{
			family: availabilityFamilyBlob,
			reason: reason,
		})
	}

	// O365 Management Activity API collectors (#100) — the second non-Graph
	// first-party API. Unlike blob ingest this needs no infrastructure opt-in:
	// the tenant's existing credential just requests a different audience, so
	// these are default-on.
	if reason := registerO365Collectors(
		cfg, ta, caps, store, tlog, emitter, registry, skips, paths.o365,
		o365activityclient.NewClient,
		inventory,
		&availabilityFailures,
	); reason != "" {
		availabilityFailures = append(availabilityFailures, availabilityStartupFailure{
			family: availabilityFamilyO365,
			reason: reason,
		})
	}

	// MDCA Cloud Discovery collectors (#145) — the FIFTH registration path and
	// the one non-Graph, non-poller signal. Opt-in like blob ingest: setting the
	// tenant's mdca.portal_url is the switch, so a tenant with no mdca block
	// registers none of these.
	if reason := registerMDCACollectors(
		cfg, ta, caps, store, tlog, emitter, registry, skips, paths.mdca,
		mdcaclient.NewClient,
		inventory,
		&availabilityFailures,
	); reason != "" {
		availabilityFailures = append(availabilityFailures, availabilityStartupFailure{
			family: availabilityFamilyMDCA,
			reason: reason,
		})
	}

	// Exchange Online admin API collectors (#233) — the SIXTH registration path
	// and the fourth first-party API. Opt-in like blob ingest and MDCA, but for
	// a different reason: the credential needs no new secret, just two grants
	// (an app role AND an Entra directory role) that graph2otel cannot detect in
	// advance and that most tenants will not have, so the switch is
	// exchange_online.enabled rather than the presence of a URL or token.
	if reason := registerEXOCollectors(
		cfg, ta, caps, tlog, exoClient, exoBuildErr, registry, skips, paths.exo,
		inventory,
		&availabilityFailures,
	); reason != "" {
		availabilityFailures = append(availabilityFailures, availabilityStartupFailure{
			family: availabilityFamilyEXO,
			reason: reason,
		})
	}

	// Advanced-hunting collectors (#249) — the SEVENTH registration path. The
	// DeviceTvm* threat-and-vulnerability-management posture, reached over the
	// Graph runHuntingQuery API. Opt-in like Exchange Online (hunting.enabled),
	// for two reasons graph2otel cannot detect in advance: it needs the
	// ThreatHunting.Read.All app role (the query 403s at runtime without it), and
	// every query draws on a per-tenant advanced-hunting CPU budget shared with
	// humans in the Defender portal (#106), so an operator turns it on
	// deliberately.
	if reason := registerHuntCollectors(
		cfg, ta, caps, tlog, emitter, registry, skips, paths.hunt,
		huntclient.NewClient,
		inventory,
		&availabilityFailures,
	); reason != "" {
		availabilityFailures = append(availabilityFailures, availabilityStartupFailure{
			family: availabilityFamilyHunt,
			reason: reason,
		})
	}

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
		return admin.CollectorSource{}, fmt.Errorf("tenant %s: %w", ta.TenantID, err)
	}

	applyAvailabilityStartupFailures(
		inventory, cfg, ta.TenantID, caps, licenseKnown, availabilityFailures,
	)
	if err := validateRuntimeRegistryCensus(registry, inventory); err != nil {
		return admin.CollectorSource{}, fmt.Errorf("tenant %s: %w", ta.TenantID, err)
	}
	// graph2otel.collector.expected_interval (#299): one snapshot, taken once the
	// registry is final. Every entry's Interval is already the scheduler's
	// EFFECTIVE value (Register/RegisterWindow resolve a non-positive override to
	// the collector's DefaultInterval — see internal/collector/collector.go), so
	// this reports the real interval the staleness alert's ratio compares
	// against, not the raw config override. No periodic re-emission is needed:
	// the interval is fixed for the process's life, and GaugeSnapshot's
	// observable callback keeps reporting this exact set on its own.
	registry.EmitExpectedIntervals(emitter, ta.TenantID)
	status := collector.NewStatusTracker()
	availabilityTracker := availability.NewTracker(ta.TenantID, inventory)
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
	// same reason — the Scheduler is the one place that reaches every registered collector
	// — and collector.WithTenant below already gave the Scheduler this tenant for
	// self-obs labels and checkpoint namespacing. Self-obs metrics reach the
	// decorator already stamped by selfObsAttrs with the identical value, and the
	// first stamp wins, so they are unchanged.
	sched := collector.NewScheduler(
		telemetry.WithTenant(
			telemetry.WithTransport(emitter, telemetry.TransportGraph), ta.TenantID),
		schedulerStore,
		tenantSchedulerOptions(
			provider,
			ta.TenantID,
			status,
			availabilityTracker,
			tlog,
		)...,
	)
	startTenantWorkers(
		ctx,
		availabilityTracker,
		emitter,
		wg,
		runPeriodicAvailability,
		func() { _ = sched.Run(ctx, registry) },
	)

	tlog.Info("tenant started", "collectors", len(registry.Entries()))
	return admin.CollectorSource{
		TenantID:     ta.TenantID,
		Registry:     registry,
		Status:       status,
		Availability: availabilityTracker,
	}, nil
}

func newTenantSchedulerStore(
	cfg *config.Config,
	tenantID string,
) (collector.CheckpointStore, error) {
	return collector.NewFileStore(filepath.Join(
		cfg.CheckpointDir,
		"scheduler-"+tenantID+".json",
	))
}

func tenantSchedulerOptions(
	provider *telemetry.Provider,
	tenantID string,
	status *collector.StatusTracker,
	availabilityTracker *availability.Tracker,
	logger *slog.Logger,
) []collector.SchedulerOption {
	return []collector.SchedulerOption{
		collector.WithEmitterFactory(annotatedCollectorEmitter(provider)),
		collector.WithSourceRecordRecorder(provider.RecordSourceRecords),
		collector.WithTenant(tenantID),
		collector.WithStatusTracker(status),
		collector.WithAvailabilityTracker(availabilityTracker),
		collector.WithLogger(logger),
	}
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
//
// The result is CLAMPED to telemetry.EventHorizon (#401). Reaching further back
// than the backend accepts is not a longer recovery: every record beyond the
// window is rejected per-entry and lost, so the extra reach buys API calls,
// throttling and rejection noise rather than data. Config.Warnings() tells the
// operator when a configured value is being clamped — a silent clamp would leave
// someone believing they had a 30-day recovery while getting 165h of it.
//
// A collector's own built-in lookback is clamped too, not just the override. The
// widest today is 24h, so this is a guard against a future factory rather than a
// live correction; leaving it unclamped would mean the protection depended on
// which of two code paths supplied the value.
func initialLookback(cfg *config.Config, rw collectors.RegisteredWindow) time.Duration {
	lookback := rw.InitialLookback
	if cfg.Backfill.InitialLookback > 0 {
		lookback = cfg.Backfill.InitialLookback
	}
	if lookback > telemetry.EventHorizon {
		return telemetry.EventHorizon
	}
	return lookback
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
	selfIdentity tenantSelfIdentity,
	registry *collector.Registry,
	skips map[admin.SkipKey]string,
	polledNames map[string]bool,
	blobFactories []collectors.BlobFactory,
	buildSource func(string, *auth.TenantAuth) (blobpipeline.Source, error),
	inventory []availability.Static,
	failures *[]availabilityStartupFailure,
) availability.Reason {
	accountURL := tenantBlobAccountURL(cfg, ta.TenantID)
	if accountURL == "" {
		return ""
	}

	src, err := buildSource(accountURL, ta)
	if err != nil {
		tlog.Error("blob ingest disabled: building the storage source failed",
			"account_url", accountURL, "error", err)
		for _, bf := range blobFactories {
			c := bf(collectors.BlobDeps{TenantID: ta.TenantID, Logger: tlog, Store: store})
			skips[admin.SkipKey{TenantID: ta.TenantID, Collector: c.Name()}] =
				"blob transport initialization failed"
		}
		return availability.ReasonTransportInitializationFailed
	}

	bdeps := collectors.BlobDeps{
		Source: src, TenantID: ta.TenantID, Logger: tlog, Store: store,
		MetricRecencyWindow: cfg.BlobMetricRecencyWindow(ta.TenantID),
	}
	selfIdentity.applyBlob(&bdeps)
	for _, bf := range blobFactories {
		expected := newAvailabilityCandidate(
			bf(collectors.BlobDeps{}),
			availabilityFamilyBlob,
		)
		c := bf(bdeps)
		if !runtimeCollectorReady(c, expected, inventory, failures, tlog) {
			continue
		}
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
	return ""
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
	o365Factories []collectors.O365Factory,
	buildClient func(*auth.TenantAuth, o365activityclient.Options) (*o365activityclient.Client, error),
	inventory []availability.Static,
	failures *[]availabilityStartupFailure,
) availability.Reason {
	types, err := tenantO365ContentTypes(cfg, ta.TenantID)
	if err != nil {
		tlog.Error("o365 activity disabled: invalid content_types", "error", err)
		recordO365Skips(
			store, ta, tlog, skips,
			"o365 activity transport configuration is invalid",
			o365Factories,
		)
		return availability.ReasonInvalidTransportConfiguration
	}

	client, err := buildClient(ta, o365activityclient.Options{
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
		recordO365Skips(
			store, ta, tlog, skips,
			"o365 activity transport initialization failed",
			o365Factories,
		)
		return availability.ReasonTransportInitializationFailed
	}

	odeps := collectors.O365Deps{
		Client:       client,
		ContentTypes: types,
		TenantID:     ta.TenantID,
		Logger:       tlog,
		Store:        store,
	}
	for _, of := range o365Factories {
		expected := newAvailabilityCandidate(
			of(collectors.O365Deps{}).Collector,
			availabilityFamilyO365,
		)
		rw := of(odeps)
		if !runtimeCollectorReady(
			rw.Collector, expected, inventory, failures, tlog,
		) {
			continue
		}
		if interval, ok := gateCollector(rw.Collector, ta, cfg, caps, tlog, skips); ok {
			registry.RegisterWindow(rw.Collector, interval, initialLookback(cfg, rw), rw.MaxWindow)
		}
	}
	return ""
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
	mdcaFactories []collectors.MDCAFactory,
	buildClient func(string, mdcaclient.Options) (*mdcaclient.Client, error),
	inventory []availability.Static,
	failures *[]availabilityStartupFailure,
) availability.Reason {
	mc := tenantMDCAConfig(cfg, ta.TenantID)
	if !mc.Configured() {
		return "" // opt-out: no mdca block, nothing to register or skip.
	}

	token, err := os.ReadFile(mc.TokenFile)
	if err != nil {
		tlog.Error("mdca disabled: reading token_file failed", "path", mc.TokenFile, "error", err)
		recordMDCASkips(store, ta, tlog, skips, "mdca transport initialization failed", mdcaFactories)
		return availability.ReasonTransportInitializationFailed
	}
	client, err := buildClient(ta.TenantID, mdcaclient.Options{
		Emitter: emitter,
		BaseURL: mc.PortalURL,
		Token:   strings.TrimSpace(string(token)),
		Limiter: mdcaclient.NewLimiter(),
	})
	if err != nil {
		tlog.Error("mdca disabled: building the client failed", "error", err)
		recordMDCASkips(store, ta, tlog, skips, "mdca transport initialization failed", mdcaFactories)
		return availability.ReasonTransportInitializationFailed
	}

	mdeps := collectors.MDCADeps{
		Client:   client,
		TenantID: ta.TenantID,
		Logger:   tlog,
		Store:    store,
	}
	for _, mf := range mdcaFactories {
		expected := newAvailabilityCandidate(
			mf(collectors.MDCADeps{}).Collector,
			availabilityFamilyMDCA,
		)
		rw := mf(mdeps)
		if !runtimeCollectorReady(
			rw.Collector, expected, inventory, failures, tlog,
		) {
			continue
		}
		if interval, ok := gateCollector(rw.Collector, ta, cfg, caps, tlog, skips); ok {
			registry.RegisterWindow(rw.Collector, interval, initialLookback(cfg, rw), rw.MaxWindow)
		}
	}
	return ""
}

// tenantEXOClient builds the tenant's single Exchange Online admin API client,
// or returns (nil, nil) when the tenant configured no exchange_online block.
//
// One client per tenant, shared by both consumers — the EXO snapshot path and
// WindowDeps.EXO — because the client owns the client-side rate limiter for a
// transport whose real ceiling is unmeasured (see internal/exoclient). Two
// clients would mean two limiters and twice the permitted rate.
//
// The typed-nil trap is why this returns collectors.EXOClient rather than
// *exoclient.Client: a nil *Client assigned to the interface makes a non-nil
// interface value, and every "the tenant has no Exchange Online" check
// downstream is an interface nil check.
func tenantEXOClient(
	cfg *config.Config,
	ta *auth.TenantAuth,
	tlog *slog.Logger,
	emitter telemetry.Emitter,
) (collectors.EXOClient, error) {
	if !tenantEXOConfig(cfg, ta.TenantID).Enabled {
		return nil, nil
	}
	client, err := exoclient.NewClient(ta, exoclient.Options{Emitter: emitter, Logger: tlog})
	if err != nil {
		return nil, err
	}
	return client, nil
}

// registerEXOCollectors wires the tenant's Exchange Online collectors (#233),
// the sixth registration path.
//
// Opt-in: a tenant without exchange_online.enabled registers none of these and
// records no skips (there is nothing to be absent). It carries no secret of its
// own — the tenant's existing DefaultAzureCredential is reused and only the
// audience differs — so the only failure mode before the first request is a
// client-build error, which skips just these collectors with the reason
// attached. "Silently doing nothing" and "no data yet" must never look alike.
//
// The two grants this needs (Exchange.ManageAsApp plus an Entra directory role)
// cannot be checked here: a token mints fine without either, and the failure
// surfaces only when a cmdlet runs. That is exactly why the switch is explicit
// rather than inferred — see config.ExchangeOnlineConfig.
func registerEXOCollectors(
	cfg *config.Config,
	ta *auth.TenantAuth,
	caps license.Capabilities,
	tlog *slog.Logger,
	client collectors.EXOClient,
	buildErr error,
	registry *collector.Registry,
	skips map[admin.SkipKey]string,
	exoFactories []collectors.EXOFactory,
	inventory []availability.Static,
	failures *[]availabilityStartupFailure,
) availability.Reason {
	if !tenantEXOConfig(cfg, ta.TenantID).Enabled {
		return "" // opt-out: no exchange_online block, nothing to register or skip.
	}

	if buildErr != nil {
		tlog.Error("exchange online disabled: building the client failed", "error", buildErr)
		reason := "exchange online transport initialization failed"
		for _, ef := range exoFactories {
			c := ef(collectors.EXODeps{TenantID: ta.TenantID, Logger: tlog})
			skips[admin.SkipKey{TenantID: ta.TenantID, Collector: c.Name()}] = reason
		}
		return availability.ReasonTransportInitializationFailed
	}

	edeps := collectors.EXODeps{Client: client, TenantID: ta.TenantID, Logger: tlog}
	for _, ef := range exoFactories {
		expected := newAvailabilityCandidate(
			ef(collectors.EXODeps{}),
			availabilityFamilyEXO,
		)
		c := ef(edeps)
		if !runtimeCollectorReady(c, expected, inventory, failures, tlog) {
			continue
		}
		if interval, ok := gateCollector(c, ta, cfg, caps, tlog, skips); ok {
			registry.Register(c, interval)
		}
	}
	return ""
}

// tenantEXOConfig returns the tenant's Exchange Online block, or a zero
// (opt-out) value if the tenant is not found.
func tenantEXOConfig(cfg *config.Config, tenantID string) config.ExchangeOnlineConfig {
	for _, t := range cfg.Tenants {
		if t.TenantID == tenantID {
			return t.ExchangeOnline
		}
	}
	return config.ExchangeOnlineConfig{}
}

// registerHuntCollectors wires the tenant's advanced-hunting collectors (#249),
// the seventh registration path.
//
// Opt-in: a tenant without hunting.enabled registers none of these and records
// no skips (there is nothing to be absent). Like Exchange Online it carries no
// secret of its own — the tenant's existing DefaultAzureCredential is reused
// against the Graph audience — so the only failure mode before the first query
// is a client-build error, which skips just these collectors with the reason
// attached.
//
// The one grant this needs (ThreatHunting.Read.All) cannot be checked here: a
// token mints fine without it, and the 403 surfaces only when a query runs. That
// is why the switch is explicit rather than inferred — see config.HuntingConfig.
func registerHuntCollectors(
	cfg *config.Config,
	ta *auth.TenantAuth,
	caps license.Capabilities,
	tlog *slog.Logger,
	emitter telemetry.Emitter,
	registry *collector.Registry,
	skips map[admin.SkipKey]string,
	huntFactories []collectors.HuntFactory,
	buildClient func(*auth.TenantAuth, huntclient.Options) (*huntclient.Client, error),
	inventory []availability.Static,
	failures *[]availabilityStartupFailure,
) availability.Reason {
	if !tenantHuntingConfig(cfg, ta.TenantID).Enabled {
		return "" // opt-out: no hunting block, nothing to register or skip.
	}

	client, err := buildClient(ta, huntclient.Options{Emitter: emitter})
	if err != nil {
		tlog.Error("advanced hunting disabled: building the client failed", "error", err)
		reason := "advanced hunting transport initialization failed"
		for _, hf := range huntFactories {
			c := hf(collectors.HuntDeps{TenantID: ta.TenantID, Logger: tlog})
			skips[admin.SkipKey{TenantID: ta.TenantID, Collector: c.Name()}] = reason
		}
		return availability.ReasonTransportInitializationFailed
	}

	hdeps := collectors.HuntDeps{Client: client, TenantID: ta.TenantID, Logger: tlog}
	for _, hf := range huntFactories {
		expected := newAvailabilityCandidate(
			hf(collectors.HuntDeps{}),
			availabilityFamilyHunt,
		)
		c := hf(hdeps)
		if !runtimeCollectorReady(c, expected, inventory, failures, tlog) {
			continue
		}
		if interval, ok := gateCollector(c, ta, cfg, caps, tlog, skips); ok {
			registry.Register(c, interval)
		}
	}
	return ""
}

// tenantHuntingConfig returns the tenant's advanced-hunting block, or a zero
// (opt-out) value if the tenant is not found.
func tenantHuntingConfig(cfg *config.Config, tenantID string) config.HuntingConfig {
	for _, t := range cfg.Tenants {
		if t.TenantID == tenantID {
			return t.Hunting
		}
	}
	return config.HuntingConfig{}
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
	mdcaFactories []collectors.MDCAFactory,
) {
	for _, mf := range mdcaFactories {
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
	o365Factories []collectors.O365Factory,
) {
	for _, of := range o365Factories {
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
// tenantPrivilegedGroupIDs returns the tenant's configured privileged-group
// allowlist (#337), or nil when the tenant configured none — which is the
// opt-out: the collector registers and no-ops rather than being absent, so its
// documented surface does not change with configuration.
func tenantPrivilegedGroupIDs(cfg *config.Config, tenantID string) []string {
	for _, t := range cfg.Tenants {
		if t.TenantID == tenantID {
			return t.PrivilegedGroups.GroupIDs
		}
	}
	return nil
}

func tenantBlobAccountURL(cfg *config.Config, tenantID string) string {
	for _, t := range cfg.Tenants {
		if t.TenantID == tenantID {
			return t.BlobIngest.AccountURL
		}
	}
	return ""
}

const (
	selfIdentityReasonTokenRequestFailed = string(auth.ApplicationIdentityTokenRequestFailed)
	selfIdentityReasonMalformedToken     = string(auth.ApplicationIdentityMalformedToken)
	selfIdentityReasonMissingAppID       = string(auth.ApplicationIdentityMissingAppID)
)

// tenantSelfIdentity is the one resolved self-filter pair shared by the Graph
// window and blob paths. enabled is true only when the tenant opted in and the
// actual TenantAuth proved a non-empty appid from its Graph access token.
type tenantSelfIdentity struct {
	enabled bool
	appID   string
}

func (i tenantSelfIdentity) applyWindow(deps *collectors.WindowDeps) {
	deps.ExcludeSelf = i.enabled
	deps.SelfClientID = i.appID
}

func (i tenantSelfIdentity) applyBlob(deps *collectors.BlobDeps) {
	deps.ExcludeSelf = i.enabled
	deps.SelfClientID = i.appID
}

// resolveTenantSelfIdentity proves the tenant's authenticated application once
// during startup. Failure is deliberately fail-open: disable filtering, keep
// starting the tenant, and log one bounded warning without the token, payload,
// or raw credential error.
func resolveTenantSelfIdentity(
	ctx context.Context,
	cfg *config.Config,
	ta *auth.TenantAuth,
	logger *slog.Logger,
) tenantSelfIdentity {
	var configuredClientID string
	enabled := false
	for _, tenant := range cfg.Tenants {
		if tenant.TenantID == ta.TenantID {
			enabled = tenant.ExcludeSelf
			configuredClientID = tenant.ClientID
			break
		}
	}
	if !enabled {
		return tenantSelfIdentity{}
	}

	appID, err := ta.AuthenticatedApplicationID(ctx)
	tlog := logger.With("tenant", ta.TenantID)
	if err != nil {
		tlog.Warn(
			"exclude_self disabled: authenticated application identity could not be proved",
			"reason", selfIdentityFailureReason(err),
		)
		return tenantSelfIdentity{}
	}
	if configuredClientID != "" && configuredClientID != appID {
		tlog.Warn(
			"configured client_id does not match authenticated application identity",
			"configured_client_id", configuredClientID,
			"authenticated_app_id", appID,
		)
	}
	return tenantSelfIdentity{enabled: true, appID: appID}
}

func selfIdentityFailureReason(err error) string {
	var identityErr *auth.ApplicationIdentityError
	if !errors.As(err, &identityErr) {
		return selfIdentityReasonMissingAppID
	}
	switch identityErr.Code {
	case auth.ApplicationIdentityTokenRequestFailed:
		return selfIdentityReasonTokenRequestFailed
	case auth.ApplicationIdentityMalformedToken:
		return selfIdentityReasonMalformedToken
	default:
		// Missing/invalid appid and unfamiliar typed codes stay within the
		// bounded warning vocabulary and fail open.
		return selfIdentityReasonMissingAppID
	}
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
	interval, enabled, reason := collectorGate(c, cfg, ta.TenantID, caps)
	if !enabled {
		tlog.Info("skipping collector", "collector", c.Name(), "reason", reason)
		skips[admin.SkipKey{TenantID: ta.TenantID, Collector: c.Name()}] = reason
		return 0, false
	}
	return interval, true
}

// collectorEnabledForConfig is the pure enablement portion of gateCollector.
// It is shared by the permission preflight so the preflight inventory follows
// the runtime's license/config/experimental/high-volume decisions without
// constructing a tenant client or recording runtime skips.
func collectorEnabledForConfig(c collector.Collector, cfg *config.Config, tenantID string, caps license.Capabilities) bool {
	_, enabled, _ := collectorGate(c, cfg, tenantID, caps)
	return enabled
}

// collectorGate is the shared, side-effect-free runtime selection rule. The
// scheduler records its skip reason; preflight only needs the selected bit.
func collectorGate(c collector.Collector, cfg *config.Config, tenantID string, caps license.Capabilities) (time.Duration, bool, string) {
	if ok, requiredCap, _ := license.ShouldRun(c, caps); !ok {
		return 0, false, fmt.Sprintf("requires %s", requiredCap)
	}
	enabled, interval := cfg.CollectorSettings(tenantID, c.Name())
	if !enabled {
		return 0, false, "disabled by config"
	}
	if exp, ok := c.(collectors.Experimental); ok && exp.Experimental() && !cfg.CollectorExplicitlyEnabled(tenantID, c.Name()) {
		return 0, false, "beta; enable explicitly to opt in"
	}
	if hv, ok := c.(collectors.HighVolume); ok && hv.HighVolume() && !cfg.CollectorExplicitlyEnabled(tenantID, c.Name()) {
		return 0, false, "high volume; enable explicitly to opt in"
	}
	return interval, true, ""
}
