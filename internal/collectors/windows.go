package collectors

import (
	"log/slog"
	"time"

	"github.com/rknightion/graph2otel/internal/checkpoint"
	"github.com/rknightion/graph2otel/internal/collector"
	"github.com/rknightion/graph2otel/internal/jobpipeline"
	"github.com/rknightion/graph2otel/internal/license"
	"github.com/rknightion/graph2otel/internal/logpipeline"
)

// WindowDeps is everything a WindowFactory needs to construct a window
// collector for one tenant. It is the log-pipeline analog of Deps: window
// collectors poll log-shaped Graph endpoints (signIns, directoryAudits,
// provisioning, riskDetections, security alerts) through the logpipeline
// engine, so on top of the common fields they receive a PageFetcher (built by
// the composition root over the tenant's rate-limited Graph client) and the
// file-based checkpoint Store that persists each stream's watermark + SeenIDs.
type WindowDeps struct {
	// Graph is the per-tenant Graph client, for any auxiliary lookup a window
	// collector needs beyond paging its endpoint (most need none).
	Graph GraphClient
	// TenantID is the tenant this collector instance serves; it is also the
	// tenant component of every checkpoint key.
	TenantID string
	// Logger is the process logger, for collector-side diagnostics.
	Logger *slog.Logger
	// Caps are the tenant's detected license capabilities. A window collector
	// that is fully premium-gated (sign-ins need P1, risk detections need P2)
	// declares license.CapabilityRequirer; the composition root then skips it
	// entirely on an insufficient tier, exactly as for snapshot collectors.
	Caps license.Capabilities
	// Fetcher pages through Graph collection responses for the logpipeline
	// engine. Built once per tenant via logpipeline.NewGraphPageFetcher(gc), so
	// every window collector shares the tenant's single instrumented,
	// rate-limited transport.
	Fetcher logpipeline.PageFetcher
	// JobClient drives the async job-poll engine (internal/jobpipeline) for
	// window collectors built on POST-a-query→poll→page endpoints (the M365 /
	// Purview unified-audit collectors over /security/auditLog/queries). Built
	// once per tenant via jobpipeline.NewGraphJobClient(gc) over the SAME
	// instrumented, rate-limited transport as Fetcher. A logpipeline-based
	// collector leaves this unused; a jobpipeline-based one ignores Fetcher.
	JobClient jobpipeline.JobClient
	// Store persists each window collector's checkpoint (watermark, overlap,
	// SeenIDs) across restarts, namespaced per (tenant, endpoint). Shared by
	// both engines (logpipeline and jobpipeline use the same checkpoint.Store).
	Store *checkpoint.Store
	// ExcludeSelf mirrors the tenant's exclude_self flag (#176): when true, a
	// self-excludable window collector drops records authored by this tenant's own
	// poller (SelfClientID). Default false — no filtering. Only the
	// entra.signins.service_principal stream acts on it today; every other window
	// collector ignores it. The self-share on this transport is small (~1.1%
	// live-measured 2026-07-19), so this is opt-in, but the mechanism is wired so
	// one tenant flag covers both the blob and Graph transports.
	ExcludeSelf bool
	// SelfClientID is this tenant's poller client_id (config tenants[].client_id,
	// falling back to AZURE_CLIENT_ID), the value ExcludeSelf matches a record's
	// appId against. Per-tenant, never a third party's id. Empty disables the
	// filter even when ExcludeSelf is true — there is no "self" to match.
	SelfClientID string
}

// RegisteredWindow bundles a constructed window collector with the schedule
// bounds the composition root passes to collector.Registry.RegisterWindow.
// InitialLookback is the cold-start backfill window (no checkpoint yet);
// MaxWindow caps how large a single tick's [from, to] range may grow after an
// outage, so catch-up is spread across ticks rather than one huge query.
type RegisteredWindow struct {
	Collector       collector.WindowCollector
	InitialLookback time.Duration
	MaxWindow       time.Duration
}

// WindowFactory constructs one window collector instance for a tenant. Like
// Factory (snapshot collectors) it is registered from a collector subpackage's
// init() via RegisterWindow, and the composition root calls it once per
// configured tenant, then license/config/experimental-gates the returned
// collector before scheduling it. A factory returning a zero RegisteredWindow
// (nil Collector) is skipped.
type WindowFactory func(WindowDeps) RegisteredWindow

// registeredWindows accumulates every window-collector factory. Populated only
// from subpackage init() functions (single-threaded package initialization),
// so it needs no synchronization. Kept separate from `registered` (snapshot
// factories) because the two have different Deps and construction paths.
var registeredWindows []WindowFactory

// RegisterWindow adds a window-collector factory. Call it from a collector
// subpackage's init(). A subpackage may register several (the four sign-in
// event-type streams all live in one package and register one factory each).
// Registration order is preserved by WindowAll().
func RegisterWindow(f WindowFactory) { registeredWindows = append(registeredWindows, f) }

// WindowAll returns every registered window-collector factory in registration
// order. The composition root calls each one per tenant.
func WindowAll() []WindowFactory { return registeredWindows }
