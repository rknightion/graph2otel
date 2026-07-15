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

	"github.com/rknightion/graph2otel/internal/admin"
	"github.com/rknightion/graph2otel/internal/collector"
	"github.com/rknightion/graph2otel/internal/config"
	"github.com/rknightion/graph2otel/internal/profiling"
	"github.com/rknightion/graph2otel/internal/telemetry"
)

// version is overridden at build time via -ldflags "-X main.version=...".
var version = "dev"

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

	// Telemetry provider: the single OTLP metrics+logs pipeline everything emits
	// through. Built here so the process fails fast on a bad exporter config.
	provider, err := telemetry.NewProvider(ctx, telemetry.Options{
		ServiceName:    "graph2otel",
		ServiceVersion: version,
		Protocol:       cfg.OTLP.Protocol,
		Endpoint:       cfg.OTLP.Endpoint,
		InstanceID:     cfg.OTLP.GrafanaCloud.InstanceID,
		Token:          cfg.OTLP.GrafanaCloud.Token.Reveal(),
		SelfObsEnabled: true,
		StdoutWriter:   stdout,
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

	// Per-tenant Graph clients + collector schedulers. Each configured tenant
	// gets its own client, license-gated collector set, and Scheduler goroutine
	// bound to ctx; startTenants returns the admin status sources and skip
	// reasons. With zero tenants (stdout mode) this is a no-op.
	sources, skips, waitTenants := startTenants(ctx, cfg, provider, logger)

	// Admin/health endpoint, fed the live per-tenant status sources and skip
	// reasons. Start blocks until ctx is canceled, then shuts the server down
	// itself, so run it in the background.
	adminSrv := admin.New(cfg.Admin, sources, skips)
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
