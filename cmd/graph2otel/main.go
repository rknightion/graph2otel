// Command graph2otel polls Microsoft Entra ID / Intune (Microsoft Graph) and
// exports OTEL metrics + logs.
package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/rknightion/graph2otel/internal/admin"
	"github.com/rknightion/graph2otel/internal/checkpoint"
	"github.com/rknightion/graph2otel/internal/collector"
	"github.com/rknightion/graph2otel/internal/config"
	"github.com/rknightion/graph2otel/internal/profiling"
	"github.com/rknightion/graph2otel/internal/telemetry"
)

// version is overridden at build time via -ldflags "-X main.version=...".
var version = "dev"

// selfObsReportInterval is how often the cardinality tracker snapshots and emits
// the graph2otel.series.* self-observability gauges. It matches the telemetry
// PeriodicReader's default export interval (60s) so each report covers exactly
// one export window's distinct series.
const selfObsReportInterval = 60 * time.Second

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	os.Exit(dispatch(ctx, os.Args[1:], os.Stdout, os.Stderr))
}

// dispatch routes to the "check" subcommand (see check.go) when it's the
// first argument, otherwise falls through to the default run mode. It exists
// so run's own flag parsing (and its existing tests) stay untouched: run is
// never given a chance to see "check" as a bogus flag value.
func dispatch(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	if len(args) > 0 && args[0] == "check" {
		return runCheck(ctx, args[1:], stdout, stderr)
	}
	return run(ctx, args, stdout, stderr)
}

// run parses flags, loads and validates the config, and (barring -version or
// an error) blocks until ctx is canceled — by a real SIGINT/SIGTERM in main,
// or directly by a test. Splitting it out of main lets every exit path be
// exercised by tests without touching os.Args, real signals, or process exit.
func run(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("graph2otel", flag.ContinueOnError)
	fs.SetOutput(stderr)
	configPath := fs.String("config", "", "path to the YAML config file (empty = env-only defaults)")
	showVersion := fs.Bool("version", false, "print the version and exit")
	if err := fs.Parse(args); err != nil {
		return 2
	}

	if *showVersion {
		fmt.Fprintln(stdout, version)
		return 0
	}

	cfg, err := config.Load(*configPath)
	if err != nil {
		fmt.Fprintf(stderr, "failed to load config: %v\n", err)
		return 1
	}
	if err := cfg.Validate(); err != nil {
		fmt.Fprintf(stderr, "invalid config: %v\n", err)
		return 1
	}

	logger := slog.New(slog.NewTextHandler(stderr, &slog.HandlerOptions{Level: parseLevel(cfg.LogLevel)}))

	logger.Info("graph2otel starting",
		"version", version, "otlp_protocol", cfg.OTLP.Protocol, "tenants", len(cfg.Tenants))

	// Advisories: valid settings that take effect exactly as written and are
	// still probably not what was meant (#118). Logged rather than fatal — each
	// one is a judgment about a backend graph2otel cannot inspect, so refusing to
	// start would break a correctly-configured deployment. Emitted here rather
	// than from Validate because they need the logger, which needs the config.
	for _, w := range cfg.Warnings() {
		logger.Warn("config advisory", "detail", w)
	}

	// Telemetry provider: the single OTLP metrics+logs pipeline everything emits
	// through. Built here so the process fails fast on a bad exporter config.
	provider, err := telemetry.NewProvider(ctx, telemetry.Options{
		ServiceName:      "graph2otel",
		ServiceVersion:   version,
		Protocol:         cfg.OTLP.Protocol,
		Endpoint:         cfg.OTLP.Endpoint,
		InstanceID:       cfg.OTLP.GrafanaCloud.InstanceID,
		Token:            cfg.OTLP.GrafanaCloud.Token.Reveal(),
		SelfObsEnabled:   true,
		CardinalityLimit: cfg.Cardinality.MetricLimit,
		StdoutWriter:     stdout,
	})
	if err != nil {
		fmt.Fprintf(stderr, "failed to build telemetry provider: %v\n", err)
		return 1
	}
	// Flush and release the pipeline on the way out (background ctx: the run
	// ctx is already canceled by the time we shut down).
	defer func() {
		if err := provider.Shutdown(context.Background()); err != nil {
			logger.Warn("telemetry provider shutdown", "error", err)
		}
	}()
	collector.EmitBuildInfo(provider.Emitter())

	// Continuous profiling is opt-in (default off). Start also applies the
	// runtime mutex/block sampling rates. A failure to reach Pyroscope is
	// non-fatal — the exporter's core job is unaffected.
	if prof, perr := profiling.Start(cfg.Profiling, "graph2otel", version, logger); perr != nil {
		logger.Error("pyroscope profiler failed to start", "error", perr)
	} else if prof != nil {
		defer func() { _ = prof.Stop() }()
		logger.Info("pyroscope continuous profiling started",
			"server", cfg.Profiling.Pyroscope.ServerAddress)
	}

	// Fail fast on an unusable checkpoint dir (#117). This is deliberately a
	// hard error, not a warning: window collectors persist their watermark
	// here, and if the directory is unwritable, Save's failure is caught by the
	// scheduler and logged at Warn while the tick carries on — so the exporter
	// runs "fine" forever while re-polling its whole lookback window every
	// cycle and re-emitting duplicate log records into the backend. Silently
	// duplicating a security-posture feed is worse than not starting.
	//
	// Checked once here rather than in startTenants because the directory is
	// global (one path shared by every tenant), and because startTenants
	// deliberately never fails the process for one tenant's sake.
	if err := checkpoint.NewStore(cfg.CheckpointDir).Verify(); err != nil {
		logger.Error("checkpoint directory unusable", "error", err)
		return 1
	}

	// Per-tenant Graph clients + collector schedulers. Each configured tenant
	// gets its own client, license-gated collector set, and Scheduler goroutine
	// bound to tenantCtx; startTenants returns the admin status sources and skip
	// reasons. With zero tenants (stdout mode) this is a no-op.
	//
	// tenantCtx is a cancelable child of ctx purely so a fatal startup error can
	// wind the schedulers back down: tenants are set up in order, so an error on
	// the third has already launched the first two, and returning without
	// canceling would leave them polling Graph while the process exits.
	tenantCtx, cancelTenants := context.WithCancel(ctx)
	defer cancelTenants()
	sources, skips, limiter, waitTenants, err := startTenants(tenantCtx, cfg, provider, logger)
	if err != nil {
		// A collector config that must not run (#144). Fatal on purpose: this
		// state ships every record twice while every collector reports healthy,
		// so a warning would be a line in a log about a system that looks fine.
		logger.Error("refusing to start", "error", err)
		cancelTenants()
		waitTenants()
		return 1
	}

	// Self-observability cardinality accounting: the emitter Observes every
	// data point's series into the tracker on the hot path; Report snapshots the
	// per-metric distinct-series counts and emits graph2otel.series.active/.limit/
	// .overflowing once per export interval, then resets. Drive it on the metric
	// export cadence (60s, matching the PeriodicReader default) so series.active
	// reflects one interval's distinct series. No-op when self-obs is disabled
	// (Cardinality() is nil).
	if card := provider.Cardinality(); card != nil {
		go func() {
			t := time.NewTicker(selfObsReportInterval)
			defer t.Stop()
			for {
				select {
				case <-ctx.Done():
					return
				case <-t.C:
					card.Report(provider.Emitter())
				}
			}
		}()
	}

	// Admin/health endpoint, fed the live per-tenant status sources and skip
	// reasons. Start blocks until ctx is canceled, then shuts the server down
	// itself, so run it in the background.
	adminSrv := admin.New(cfg.Admin, sources, skips, limiter, cfg, provider.Cardinality())
	go func() {
		if err := adminSrv.Start(ctx); err != nil {
			logger.Error("admin server", "error", err)
		}
	}()

	<-ctx.Done()
	waitTenants() // drain the per-tenant schedulers before releasing telemetry

	logger.Info("graph2otel stopped")
	return 0
}

func parseLevel(s string) slog.Level {
	switch strings.ToLower(s) {
	case "debug":
		return slog.LevelDebug
	case "warn":
		return slog.LevelWarn
	case "error":
		return slog.LevelError
	default:
		return slog.LevelInfo
	}
}
