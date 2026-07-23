// Package admin implements the operator health/status HTTP endpoint (#12):
// an unconditional /healthz liveness probe plus a per-tenant, per-collector
// status page served as both HTML ("/") and JSON ("/api/status.json") from
// one shared data model (see status.go). The package never keeps its own
// copy of collector run state — every request renders a fresh snapshot of
// the collector.StatusTracker(s) the composition root wires in, so the page
// can never drift from what the scheduler actually recorded.
//
// This is single-instance ops visibility, not a control plane: it has no
// mutating endpoints and no dependency on any other tenant's state.
package admin

import (
	"context"
	"errors"
	"net/http"
	"runtime"
	"time"

	"github.com/rknightion/graph2otel/internal/config"
	"github.com/rknightion/graph2otel/internal/graphclient"
	"github.com/rknightion/graph2otel/internal/telemetry"
	"github.com/rknightion/graph2otel/internal/version"
)

// RateLimiter snapshots per-(tenant,workload) throttle headroom for the status
// page. *graphclient.WorkloadLimiter satisfies it. May be nil (no panel).
type RateLimiter interface {
	Snapshot(now time.Time) []graphclient.WorkloadHeadroom
}

// Server is the admin HTTP server. A nil *Server (returned by New when
// AdminConfig.Enabled is false) is safe to call Start/Shutdown on — both are
// no-ops — so callers never need a separate "is admin enabled" check.
type Server struct {
	sources     []CollectorSource
	skipReasons map[SkipKey]string
	limiter     RateLimiter
	startedAt   time.Time
	now         func() time.Time
	refreshMs   int

	// cfg is the full effective configuration, read PASSIVELY to render the
	// Config tab (#211) and to source the Cardinality tab's per_metric_limit (#215).
	// May be nil (renders an empty Config view). Secrets are never surfaced from
	// it beyond presence — see configView.
	cfg *config.Config
	// card is the output-side cardinality tracker, read passively for the
	// Cardinality tab (#215). May be nil when self-obs is disabled; all reads go
	// through Snapshot, which is a pure in-memory, nil-safe call.
	card *telemetry.CardinalityTracker
	// trend holds the ~10-minute in-process trend rings behind the Overview
	// tab's charts (#227). It is populated by a background ticker Start
	// launches; a Server that is never Started renders empty series, which the
	// page shows as "collecting…".
	trend *sampler

	srv *http.Server
	mux *http.ServeMux
}

// New builds the admin Server for cfg. It returns nil when cfg.Enabled is
// false: the composition root should skip calling Start entirely in that
// case (though doing so is also safe, since Start/Shutdown are nil-safe).
//
// sources is one entry per tenant, pairing that tenant's collector.Registry
// (the collectors actually registered to run) with the collector.StatusTracker
// its Scheduler records into. skipReasons explains, per (tenant, collector)
// pair, why a collector the operator might expect to see was never
// registered at all (e.g. "requires P2", "missing permission X") — supplied
// by the composition root, which owns the license/preflight decisions this
// package has no dependency on.
//
// limiter, when non-nil, feeds the per-tenant throttle-headroom panel (#85) —
// *graphclient.WorkloadLimiter from the composition root satisfies it. A nil
// limiter renders no rate-limit panel and never panics.
//
// fullCfg is the full effective configuration (for the Config tab, #211) and
// card is the output-side cardinality tracker (for the Cardinality tab, #215).
// Both are read passively — no live tenant call — and both are nil-safe: a nil
// fullCfg renders an empty Config view, a nil card an empty Cardinality view.
//
// tp is the emit-side throughput source for the Overview tab's throughput
// trend (#227) — *telemetry.Provider satisfies it. Nil leaves that one chart
// empty and changes nothing else.
func New(cfg config.AdminConfig, sources []CollectorSource, skipReasons map[SkipKey]string, limiter RateLimiter, fullCfg *config.Config, card *telemetry.CardinalityTracker, tp ThroughputSource) *Server {
	if !cfg.Enabled {
		return nil
	}
	refreshMs := int(cfg.RefreshInterval / time.Millisecond)
	if refreshMs <= 0 {
		refreshMs = 5000
	}
	s := &Server{
		sources:     sources,
		skipReasons: skipReasons,
		limiter:     limiter,
		startedAt:   time.Now(),
		now:         time.Now,
		refreshMs:   refreshMs,
		cfg:         fullCfg,
		card:        card,
	}
	s.trend = newSampler(samplerHistoryLen, card, tp, sources, limiter, s.now)
	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", s.handleHealthz)
	mux.HandleFunc("/api/status.json", s.handleStatusJSON)
	mux.HandleFunc("/api/config.json", s.handleConfigJSON)
	mux.HandleFunc("/api/cardinality.json", s.handleCardinalityJSON)
	mux.HandleFunc("/", s.handleIndex)
	s.mux = mux
	s.srv = &http.Server{
		Addr:              cfg.Addr,
		Handler:           mux,
		ReadHeaderTimeout: 10 * time.Second,
	}
	return s
}

// Handler returns the server's http.Handler (its ServeMux), for tests to
// drive via httptest without binding a real listener.
func (s *Server) Handler() http.Handler { return s.mux }

// Start binds cfg.Addr and serves until ctx is canceled, then shuts down
// gracefully (a 5-second grace period). Returns nil on a clean shutdown or
// on a nil (disabled) Server; any other listen/serve error is returned as-is.
// The caller is responsible for canceling ctx (e.g. on SIGINT/SIGTERM).
func (s *Server) Start(ctx context.Context) error {
	if s == nil {
		return nil
	}
	errCh := make(chan error, 1)
	go func() { errCh <- s.srv.ListenAndServe() }()
	// The trend sampler lives for as long as the server does: it takes the first
	// observation immediately, then ticks, and stops when ctx is canceled.
	go s.trend.run(ctx)
	select {
	case <-ctx.Done():
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		return s.srv.Shutdown(shutdownCtx)
	case err := <-errCh:
		if errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		return err
	}
}

// Shutdown gracefully stops the server, or is a no-op on a nil (disabled)
// Server.
func (s *Server) Shutdown(ctx context.Context) error {
	if s == nil {
		return nil
	}
	return s.srv.Shutdown(ctx)
}

// snapshot builds the current Status from the wired sources/skip reasons.
func (s *Server) snapshot() Status {
	now := s.now()
	tenants := buildTenantStatuses(s.sources, s.skipReasons, now)
	if s.limiter != nil {
		attachRateLimits(tenants, s.limiter.Snapshot(now))
	}
	attachHeadroomTrends(tenants, s.trend)
	health, reasons := deriveHealth(tenants)
	uptime := now.Sub(s.startedAt)
	return Status{
		Service: ServiceInfo{
			Version:   version.String(),
			GoVersion: runtime.Version(),
			StartedAt: s.startedAt.UTC().Format(time.RFC3339),
			UptimeSec: int64(uptime / time.Second),
			Uptime:    uptime.Round(time.Second).String(),
		},
		Health:        health,
		HealthReasons: reasons,
		Tenants:       tenants,
		GeneratedAt:   now.UTC().Format(time.RFC3339),
		RefreshMs:     s.refreshMs,
		Runtime:       s.trend.runtimeInfo(),
		Throughput:    s.trend.throughputInfo(),
		Fleet:         s.trend.fleetInfo(),
		SeriesTrend:   s.trend.cardinalityTrend(),
	}
}

// pageModel is the full render context for the HTML page: the status snapshot
// (embedded, so every existing {{.Health}}/{{.Tenants}}/… reference still
// resolves via field promotion) plus the Config (#211) and Cardinality (#215)
// tab views.
type pageModel struct {
	Status
	Config      ConfigView
	Cardinality CardinalityView
}

// pageSnapshot assembles the full HTML page model: the live status snapshot plus
// the passive Config and Cardinality views. Every part is an in-memory read.
func (s *Server) pageSnapshot() pageModel {
	return pageModel{
		Status:      s.snapshot(),
		Config:      s.configView(),
		Cardinality: s.cardinalityView(),
	}
}
