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
	"github.com/rknightion/graph2otel/internal/version"
)

// Server is the admin HTTP server. A nil *Server (returned by New when
// AdminConfig.Enabled is false) is safe to call Start/Shutdown on — both are
// no-ops — so callers never need a separate "is admin enabled" check.
type Server struct {
	sources     []CollectorSource
	skipReasons map[SkipKey]string
	startedAt   time.Time
	now         func() time.Time

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
func New(cfg config.AdminConfig, sources []CollectorSource, skipReasons map[SkipKey]string) *Server {
	if !cfg.Enabled {
		return nil
	}
	s := &Server{
		sources:     sources,
		skipReasons: skipReasons,
		startedAt:   time.Now(),
		now:         time.Now,
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", s.handleHealthz)
	mux.HandleFunc("/api/status.json", s.handleStatusJSON)
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
	}
}
