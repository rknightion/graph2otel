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

	"github.com/rknightion/graph2otel/internal/config"
)

// version is overridden at build time via -ldflags "-X main.version=...".
var version = "dev"

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	os.Exit(run(ctx, os.Args[1:], os.Stdout, os.Stderr))
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

	<-ctx.Done()

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
