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
	"sync"
	"syscall"
	"time"

	"go.opentelemetry.io/otel"

	"github.com/rknightion/graph2otel/internal/admin"
	"github.com/rknightion/graph2otel/internal/availability"
	"github.com/rknightion/graph2otel/internal/checkpoint"
	"github.com/rknightion/graph2otel/internal/collector"
	"github.com/rknightion/graph2otel/internal/config"
	"github.com/rknightion/graph2otel/internal/profiling"
	"github.com/rknightion/graph2otel/internal/startupevent"
	"github.com/rknightion/graph2otel/internal/telemetry"
	"github.com/rknightion/graph2otel/internal/version"
)

// otelErrorHandler adapts the OTEL SDK's error channel onto a slog logger. See
// the call site for why this is wired at all.
func otelErrorHandler(logger *slog.Logger) otel.ErrorHandler {
	return otel.ErrorHandlerFunc(func(err error) {
		logger.Error("otel sdk error", "error", err)
	})
}

// selfObsReportInterval is how often the cardinality tracker snapshots and emits
// the graph2otel.series.* self-observability gauges. It matches the telemetry
// PeriodicReader's default export interval (60s) so each report covers exactly
// one export window's distinct series.
const selfObsReportInterval = 60 * time.Second

// processStart is when this process began, captured at package init — the
// earliest moment in-process code runs, and therefore the most truthful event
// time available for the graph2otel.startup marker (#310).
//
// It is a package var rather than a time.Now() at the emit site on purpose: the
// marker's whole job is to line a dashboard annotation up against the moment the
// deployment changed, and taking the clock after config load, provider
// construction and a checkpoint-directory probe would date it several hundred
// milliseconds late — silently, and in the direction that makes a marker appear
// AFTER the metric change it is supposed to explain.
var processStart = time.Now()

func reportAvailability(
	ctx context.Context,
	tracker *availability.Tracker,
	emitter telemetry.Emitter,
	ticks <-chan time.Time,
) {
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticks:
			tracker.Emit(emitter)
		}
	}
}

type periodicAvailabilityReporter func(
	context.Context,
	*availability.Tracker,
	telemetry.Emitter,
)

func runPeriodicAvailability(
	ctx context.Context,
	tracker *availability.Tracker,
	emitter telemetry.Emitter,
) {
	ticker := time.NewTicker(selfObsReportInterval)
	defer ticker.Stop()
	reportAvailability(ctx, tracker, emitter, ticker.C)
}

func startTenantWorkers(
	ctx context.Context,
	tracker *availability.Tracker,
	emitter telemetry.Emitter,
	wg *sync.WaitGroup,
	reportPeriodic periodicAvailabilityReporter,
	runScheduler func(),
) {
	tracker.Emit(emitter)
	wg.Go(func() {
		reportPeriodic(ctx, tracker, emitter)
	})
	wg.Go(runScheduler)
}

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

// newTelemetryProvider constructs the process-wide telemetry pipeline from the
// effective config. Keeping this composition-root boundary explicit lets tests
// exercise the real provider resource built by the command.
func newTelemetryProvider(ctx context.Context, cfg *config.Config, stdout io.Writer) (*telemetry.Provider, error) {
	return telemetry.NewProvider(ctx, telemetry.Options{
		ServiceName:    "graph2otel",
		ServiceVersion: version.String(),
		Protocol:       cfg.OTLP.Protocol,
		Endpoint:       cfg.OTLP.Endpoint,
		InstanceID:     cfg.OTLP.GrafanaCloud.InstanceID,
		Token:          cfg.OTLP.GrafanaCloud.Token.Reveal(),
		SelfObsEnabled: true,
		Cost:           costOptionsFromConfig(cfg.Cost),
		Limits: telemetry.Limits{
			PerMetric: cfg.Cardinality.PerMetricLimit,
			Global:    cfg.Cardinality.GlobalLimit,
		},
		StdoutWriter: stdout,
	})
}

func costOptionsFromConfig(cost config.CostConfig) telemetry.CostOptions {
	return telemetry.CostOptions{
		Enabled:      cost.Enabled,
		Currency:     cost.Currency,
		PriceVersion: cost.Version,
		Period:       cost.Period,
		Rates: telemetry.CostRates{
			SourceRecordMicrounits: nonNegativeMicrounits(
				cost.Rates.SourceRecord,
			),
			MetricPointMicrounits: nonNegativeMicrounits(
				cost.Rates.MetricPoint,
			),
			LogRecordMicrounits: nonNegativeMicrounits(
				cost.Rates.LogRecord,
			),
			TransmittedPayloadByteMicrounits: nonNegativeMicrounits(
				cost.Rates.TransmittedPayloadByte,
			),
		},
	}
}

func nonNegativeMicrounits(rate *int64) uint64 {
	if rate == nil || *rate < 0 {
		return 0
	}
	return uint64(*rate)
}

var buildTelemetryProvider = newTelemetryProvider

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
		fmt.Fprintln(stdout, version.String())
		return 0
	}

	cfg, err := loadValidatedConfig(*configPath)
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 1
	}

	logger := slog.New(slog.NewTextHandler(stderr, &slog.HandlerOptions{Level: parseLevel(cfg.LogLevel)}))

	logger.Info("graph2otel starting",
		"version", version.String(), "otlp_protocol", cfg.OTLP.Protocol, "tenants", len(cfg.Tenants))

	// Advisories: valid settings that take effect exactly as written and are
	// still probably not what was meant (#118). Logged rather than fatal — each
	// one is a judgment about a backend graph2otel cannot inspect, so refusing to
	// start would break a correctly-configured deployment. Emitted here rather
	// than from Validate because they need the logger, which needs the config.
	for _, w := range cfg.Warnings() {
		logger.Warn("config advisory", "detail", w)
	}

	// Route the OTEL SDK's own errors into this logger. Without this they go to
	// the global default handler, which writes to Go's standard log package —
	// unstructured, unlevelled, and outside every filter an operator has set up
	// for graph2otel's output.
	//
	// This is the channel that carries EXPORT REJECTIONS, which is why it
	// matters (#226). The OTLP gateway refuses a log record timestamped beyond
	// its 7-day accept window with a 400 naming both the offending timestamp and
	// the limit — genuinely actionable, and previously arriving in a different
	// format from every other line the process emits. A rejection is a data-loss
	// event, so it is logged at ERROR.
	otel.SetErrorHandler(otelErrorHandler(logger))

	// Telemetry provider: the single OTLP metrics+logs pipeline everything emits
	// through. Built here so the process fails fast on a bad exporter config.
	provider, err := buildTelemetryProvider(ctx, cfg, stdout)
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
	// The limiter announces the transition into clipping for a metric, once —
	// clipping is data loss, and a metric quietly shedding its tail while every
	// dashboard still renders is exactly the failure nobody notices.
	provider.Limiter().SetLogger(logger)
	collector.EmitBuildInfo(provider.Emitter())

	// The deploy/version/config-change marker the dashboards annotate from
	// (#310): one log record per configured tenant, carrying the same version
	// build_info reports plus a one-way, secret-free config fingerprint, stamped
	// with the process start time above. A failure here means the marker was NOT
	// emitted (never emitted wrong), so it is logged loudly and is not fatal —
	// the exporter's core job is unaffected and an operator losing a dashboard
	// annotation is not a reason to refuse to collect telemetry.
	if err := startupevent.Emit(provider.Emitter(), cfg, processStart); err != nil {
		logger.Error("startup marker not emitted", "error", err)
	}

	// Continuous profiling is opt-in (default off). Start also applies the
	// runtime mutex/block sampling rates. A failure to reach Pyroscope is
	// non-fatal — the exporter's core job is unaffected.
	if prof, perr := profiling.Start(cfg.Profiling, "graph2otel", version.String(), logger); perr != nil {
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

	// The opt-in Grafana annotation writer (#400) — graph2otel's one authorized
	// second egress path, and a no-op unless grafana_annotations.url is set.
	//
	// Fatal on failure, unlike the startup marker above, and deliberately so: the
	// marker's absence is a missing dashboard nicety, while a token that cannot
	// write annotations means every annotation an operator later relies on for
	// incident context is silently absent at exactly the moment they look for it.
	// The maintainer's decision on #400 is explicit — fail fast and loudly at
	// startup, not at the first event.
	//
	// After the checkpoint probe (the persisted dedupe set lives in that
	// directory) and before startTenants (a collector that starts first emits
	// records the rule set never sees).
	if err := startAnnotator(ctx, cfg, provider, logger); err != nil {
		logger.Error("refusing to start", "error", err)
		return 1
	}
	defer func() {
		if err := annotator.Close(context.Background()); err != nil {
			logger.Warn("grafana annotation writer shutdown", "error", err)
		}
	}()

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

	// Self-observability cardinality accounting: the emitter Observes every data
	// point's series into the tracker on the hot path; ReportSelfObs snapshots the
	// per-metric distinct-series counts, emits graph2otel.series.active/.limit
	// plus the limiter's .clipped/.total, and recomputes the global arbitration
	// for the next interval. Drive it on the metric export cadence (60s, matching
	// the PeriodicReader default) so series.active reflects one interval's
	// distinct series. No-op when self-obs is disabled (Cardinality() is nil).
	if card := provider.Cardinality(); card != nil {
		go func() {
			t := time.NewTicker(selfObsReportInterval)
			defer t.Stop()
			for {
				select {
				case <-tenantCtx.Done():
					return
				case <-t.C:
					provider.ReportSelfObs()
				}
			}
		}()
	}

	// Admin/health endpoint, fed the live per-tenant status sources and skip
	// reasons. When enabled, this is an operator contract: a bind/serve failure
	// (or an unexpected clean return while the process is live) is process-fatal
	// rather than a log line beside an exporter that has lost its health
	// surface. The buffered result and explicit cancellation-path drain ensure
	// Start always gets to report its shutdown result without leaking a
	// goroutine.
	adminSrv := admin.New(cfg.Admin, sources, skips, limiter, cfg, provider.Cardinality(), provider)
	if !cfg.Admin.Enabled {
		<-ctx.Done()
		cancelTenants()
		waitTenants()
		logger.Info("graph2otel stopped")
		return 0
	}

	if err := superviseAdmin(ctx, adminSrv.Start, cancelTenants, waitTenants); err != nil {
		logger.Error("admin server", "error", err)
		return 1
	}

	logger.Info("graph2otel stopped")
	return 0
}

// superviseAdmin runs an enabled admin server until it reports a result or the
// process context is canceled. Tenant cancellation and scheduler drainage are
// a common epilogue rather than select-branch side effects: ctx cancellation
// and a clean admin result can both be ready at once, and either selected
// branch must still fully stop tenant work before telemetry is released.
func superviseAdmin(
	ctx context.Context,
	start func(context.Context) error,
	cancelTenants func(),
	waitTenants func(),
) error {
	adminResult := make(chan error, 1)
	go func() { adminResult <- start(ctx) }()

	var resultErr error
	select {
	case resultErr = <-adminResult:
		if resultErr == nil && ctx.Err() == nil {
			resultErr = fmt.Errorf("admin server stopped unexpectedly")
		}
	case <-ctx.Done():
		resultErr = <-adminResult
	}

	cancelTenants()
	waitTenants()
	return resultErr
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
