package main

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/rknightion/graph2otel/internal/annotations"
	"github.com/rknightion/graph2otel/internal/config"
	"github.com/rknightion/graph2otel/internal/startupevent"
	"github.com/rknightion/graph2otel/internal/telemetry"
	"github.com/rknightion/graph2otel/internal/version"
)

// annotator is the process-wide Grafana annotation writer (#400), or nil when
// grafana_annotations.url is unset — which is the default, and must cost nothing.
//
// # Why a composition-root singleton rather than a threaded parameter
//
// There is exactly ONE of these per process: one Grafana base URL, one
// service-account token, one HTTP client, one rate-limit budget, one publisher
// goroutine. Threading it would mean adding an eleventh parameter to five
// already-wide tenant-setup functions and to the injectable tenantSetup seam,
// for a value that is identical on every path — churn whose only effect is a
// wider signature.
//
// It is written EXACTLY ONCE, by startAnnotator, before any tenant or scheduler
// exists, and read-only afterwards, so there is no race to reason about. That is
// the same discipline processStart uses, for the same reason.
//
// A nil *annotations.Annotator is fully functional: Decorate passes the emitter
// through and Close is a no-op, so no call site branches on the feature being
// off.
var annotator *annotations.Annotator

// startAnnotator builds and PROVES the annotation writer, assigning the
// singleton. It returns an error only when the feature is configured and cannot
// work — the caller must treat that as fatal.
//
// Ordering matters and is not arbitrary:
//
//   - It runs AFTER the checkpoint directory has been proved writable, because
//     the persisted dedupe set lives there. Without it every restart republishes
//     everything inside the source collectors' overlap windows.
//   - It runs BEFORE startTenants, because a token that cannot write must be
//     reported at startup rather than at the first real event, and because a
//     collector that starts before the recorder exists emits records the rule set
//     never sees.
func startAnnotator(ctx context.Context, cfg *config.Config, provider *telemetry.Provider, logger *slog.Logger) error {
	if !cfg.GrafanaAnnotations.Configured() {
		return nil
	}
	// The SAME one-way, secret-free fingerprint #310 shipped, from the same
	// function. It is deliberately not recomputed here: two fingerprint
	// definitions would drift, and an operator comparing a Loki startup marker
	// against a Grafana annotation would see two different values for one
	// configuration.
	fingerprint, err := startupevent.Fingerprint(cfg)
	if err != nil {
		return fmt.Errorf("grafana annotation writer: %w", err)
	}
	tenantIDs := make([]string, 0, len(cfg.Tenants))
	for _, tenant := range cfg.Tenants {
		tenantIDs = append(tenantIDs, tenant.TenantID)
	}

	// A nil provider is only reachable from a test that exercises the fail-fast
	// path; the Annotator treats a nil emitter as "no self-observability", never
	// as an error.
	var emitter telemetry.Emitter
	if provider != nil {
		emitter = provider.Emitter()
	}
	a, err := annotations.Start(ctx, annotations.Options{
		Config:            cfg.GrafanaAnnotations,
		Emitter:           emitter,
		CheckpointDir:     cfg.CheckpointDir,
		Logger:            logger,
		Version:           version.String(),
		ConfigFingerprint: fingerprint,
		TenantIDs:         tenantIDs,
		StartedAt:         processStart,
	})
	if err != nil {
		return err
	}
	annotator = a
	logger.Info("grafana annotation writer started",
		"url", cfg.GrafanaAnnotations.URL,
		"dashboard_uid", cfg.GrafanaAnnotations.DashboardUID,
		"max_per_minute", cfg.GrafanaAnnotations.MaxPerMinute)
	return nil
}

// annotatedCollectorEmitter returns the scheduler's per-run emitter factory,
// teed through the annotation rule set when the writer is configured.
//
// The tee wraps OUTSIDE provider.CollectorEmitter, so the record it observes is
// the one the collector produced, before the tenant and transport stamps are
// applied. That is deliberate: the tenant is already known exactly, from the
// Attribution, and reading it from a stamp would make the annotation depend on
// decorator ordering.
func annotatedCollectorEmitter(provider *telemetry.Provider) func(telemetry.Attribution) telemetry.Emitter {
	return func(attribution telemetry.Attribution) telemetry.Emitter {
		return annotator.Decorate(attribution, provider.CollectorEmitter(attribution))
	}
}
