package collector

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"math/rand/v2"
	"sync"
	"time"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/trace"
	tracenoop "go.opentelemetry.io/otel/trace/noop"

	"github.com/rknightion/graph2otel/internal/availability"
	"github.com/rknightion/graph2otel/internal/recordoutcome"
	"github.com/rknightion/graph2otel/internal/semconv"
	"github.com/rknightion/graph2otel/internal/telemetry"
)

// noopSchedulerTracer is the shared fallback for a nil Scheduler.tracer, so span
// creation in runTick never allocates a fresh no-op provider on every tick.
var noopSchedulerTracer = tracenoop.NewTracerProvider().Tracer("")

// Scheduler runs each registered collector on its own goroutine and ticker,
// isolating failures so one collector cannot stop the others.
type Scheduler struct {
	emitter telemetry.Emitter
	// emitterFactory binds collector data handoffs to their bounded attribution.
	// Scheduler self-observability deliberately continues through emitter.
	emitterFactory func(telemetry.Attribution) telemetry.Emitter
	// sourceRecordRecorder feeds the in-process volume/cost snapshot from the
	// same immutable #269 snapshot used by source-record self-observability.
	sourceRecordRecorder func(telemetry.Attribution, uint64)
	store                CheckpointStore
	now                  func() time.Time
	// staggerWindow bounds the random startup delay applied to each collector's
	// first tick, to de-synchronize polls (see WithStaggerWindow). Zero disables it.
	staggerWindow time.Duration
	logger        *slog.Logger
	selfObs       bool
	status        *StatusTracker // optional; records per-collector run outcomes for the status page
	availability  *availability.Tracker
	tracer        trace.Tracer // optional; emits one root span per scrape cycle
	// tenant, when non-empty, is the tenant ID this Scheduler instance polls.
	// graph2otel runs one Scheduler per configured tenant, so this both (a)
	// labels every self-obs metric with semconv.AttrTenantID alongside
	// semconv.AttrCollector, and (b) namespaces every checkpoint store key
	// with tenant+"/" so multiple tenants sharing a CheckpointStore don't
	// collide. Empty keeps bare attrs/keys (single-tenant continuity, and
	// keeps unit tests simple).
	tenant string
}

// SchedulerOption configures a Scheduler.
type SchedulerOption func(*Scheduler)

// WithStaggerWindow sets the upper bound on the random startup delay applied to
// each collector's first tick, used to de-synchronize collectors so they don't
// hit the Graph API in lock-step. The delay is an absolute duration,
// independent of the collector's Interval: the first tick always fires within
// this window (then every Interval thereafter). Zero makes every first tick
// fire immediately. Defaults to defaultStaggerWindow.
func WithStaggerWindow(d time.Duration) SchedulerOption {
	return func(s *Scheduler) { s.staggerWindow = d }
}

// WithClock overrides the time source (used in tests).
func WithClock(now func() time.Time) SchedulerOption { return func(s *Scheduler) { s.now = now } }

// WithLogger sets the logger used for collector errors.
func WithLogger(l *slog.Logger) SchedulerOption { return func(s *Scheduler) { s.logger = l } }

// WithSelfObs toggles per-collector self-observability scrape metrics
// (graph2otel.scrape.*). It defaults to enabled; passing false suppresses
// all scrape metric emission, leaving behavior identical to having no self-obs.
func WithSelfObs(enabled bool) SchedulerOption { return func(s *Scheduler) { s.selfObs = enabled } }

// WithEmitterFactory binds each collector run to an emitter carrying its
// tenant, collector, transport, and traffic class. It applies only to collector
// data handoffs; scrape/outcome/source-record self-observability stays on the
// Scheduler's un-attributed emitter.
func WithEmitterFactory(factory func(telemetry.Attribution) telemetry.Emitter) SchedulerOption {
	return func(s *Scheduler) { s.emitterFactory = factory }
}

// WithSourceRecordRecorder records the exact fetched-row count from each
// completed non-shutdown run into an in-process consumer such as #289's volume
// tracker. It is independent of WithSelfObs so disabling OTLP self-observation
// does not disable admin/cost accounting.
func WithSourceRecordRecorder(record func(telemetry.Attribution, uint64)) SchedulerOption {
	return func(s *Scheduler) { s.sourceRecordRecorder = record }
}

// WithStatusTracker records each collector's latest run outcome into t for
// in-process introspection (e.g. the admin status page). Recording happens on
// every tick regardless of WithSelfObs, so the status page works even when
// scrape metrics are suppressed.
func WithStatusTracker(t *StatusTracker) SchedulerOption { return func(s *Scheduler) { s.status = t } }

// WithAvailabilityTracker records every completed non-shutdown collector run
// into t. Snapshot emission is owned by the tenant lifecycle rather than the
// scheduler tick, so a run update does not publish an incomplete tenant set.
func WithAvailabilityTracker(t *availability.Tracker) SchedulerOption {
	return func(s *Scheduler) { s.availability = t }
}

// WithTracer sets the tracer used to emit one root span per scrape cycle. A nil
// tracer (the default) disables span emission via a package-level no-op tracer,
// so callers and the tick path never need a nil check.
func WithTracer(tr trace.Tracer) SchedulerOption { return func(s *Scheduler) { s.tracer = tr } }

// WithTenant sets the tenant ID this Scheduler polls. It is added as
// semconv.AttrTenantID to every self-obs metric alongside semconv.AttrCollector,
// and used to namespace checkpoint store keys (tenant+"/"+collector) so
// multiple tenants sharing a CheckpointStore don't collide. Empty (the
// default) omits the tenant attribute and keeps bare checkpoint keys.
func WithTenant(tenantID string) SchedulerOption {
	return func(s *Scheduler) { s.tenant = tenantID }
}

// checkpointKey returns the store key for a collector, applying the optional
// tenant namespace.
func (s *Scheduler) checkpointKey(name string) string {
	if s.tenant == "" {
		return name
	}
	return s.tenant + "/" + name
}

// NewScheduler returns a Scheduler that drives collectors with the given
// emitter and checkpoint store.
func NewScheduler(e telemetry.Emitter, store CheckpointStore, opts ...SchedulerOption) *Scheduler {
	s := &Scheduler{
		emitter:       e,
		store:         store,
		now:           time.Now,
		staggerWindow: defaultStaggerWindow,
		logger:        slog.Default(),
		selfObs:       true,
	}
	for _, o := range opts {
		o(s)
	}
	return s
}

// Run launches one goroutine per registered collector and blocks until ctx is
// canceled, then drains. Returns ctx.Err().
func (s *Scheduler) Run(ctx context.Context, r *Registry) error {
	var wg sync.WaitGroup
	for _, entry := range r.Entries() {
		wg.Add(1)
		go func(e Entry) {
			defer wg.Done()
			s.runLoop(ctx, e)
		}(entry)
	}
	wg.Wait()
	return ctx.Err()
}

// defaultStaggerWindow bounds the random startup delay applied to each
// collector's first tick. It de-synchronizes collectors (so they don't poll the
// Graph API in lock-step) without delaying the first poll by a fraction of a
// potentially long interval: a 600s collector still produces data within seconds
// of startup, not 10 minutes later.
const defaultStaggerWindow = 3 * time.Second

// coldStartTargetKeyPrefix reserves an internal checkpoint namespace which
// cannot collide with the ordinary tenant/collector keys. The leading NUL is
// outside the stable collector-name/config alphabet; appending checkpointKey is
// injective and retains tenant isolation.
const coldStartTargetKeyPrefix = "\x00graph2otel/cold-start-target/"

func (s *Scheduler) coldStartTargetKey(name string) string {
	return coldStartTargetKeyPrefix + s.checkpointKey(name)
}

func (s *Scheduler) runLoop(ctx context.Context, e Entry) {
	// Baseline for scrape.staleness: until the first successful run, staleness
	// counts up from here (loop start), so a collector that never succeeds shows
	// a growing — and therefore alertable — value.
	lastSuccess := s.now()
	if d := s.initialDelay(); d > 0 {
		t := time.NewTimer(d)
		select {
		case <-ctx.Done():
			t.Stop()
			return
		case <-t.C:
		}
	}
	// Run the first tick immediately after the stagger so fresh data lands
	// within seconds of startup rather than one full Interval later.
	select {
	case <-ctx.Done():
		return
	default:
	}
	s.runTick(ctx, e, &lastSuccess)
	ticker := time.NewTicker(e.Interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			s.runTick(ctx, e, &lastSuccess)
		}
	}
}

func (s *Scheduler) initialDelay() time.Duration {
	if s.staggerWindow <= 0 {
		return 0
	}
	return time.Duration(rand.Float64() * float64(s.staggerWindow)) //nolint:gosec // G404: scheduling jitter is not security-sensitive
}

// isShutdownCancellation reports whether err represents a collector run being
// interrupted by ctx's own cancellation (e.g. process shutdown) rather than a
// genuine collection failure. It requires BOTH that ctx itself is done — so an
// unrelated, request-scoped cancellation/timeout elsewhere is never
// misclassified — and that err is context.Canceled or context.DeadlineExceeded,
// the two sentinel errors an interrupted in-flight operation can surface
// depending on exactly when it observed ctx being done.
func isShutdownCancellation(ctx context.Context, err error) bool {
	if err == nil || ctx.Err() == nil {
		return false
	}
	return errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded)
}

// declinedPermission reports whether a run finished by DECLINING rather than by
// failing: it completed normally — no panic, no returned error — and its only
// complaint is that the source refused it. Several endpoints are simply not
// available on a given tenant (an unlicensed preview, a workload the tenant does
// not own), so their collectors deliberately record permission_denied and return
// nil rather than erroring; see riskyagents and retentionlabels.
//
// Such a run stamps last-success, because scrape.staleness answers "is this
// collector still running" and the answer is yes — it ran, and the tenant said
// no. Ratcheting staleness instead pages g2o-collector-staleness at critical
// forever over a permanent condition no operator action can clear (#408).
// Nothing else is softened: the run is still unhealthy, so scrape.success is 0,
// the outcome is still result=failure with cause=permission_denied, the
// availability tracker and status page still show it degraded, and the WARN
// "degraded outcome" line is still logged every tick.
//
// The runErr test is what keeps this narrow. A 403 the collector could NOT
// handle returns an error, which is an unfinished run and still goes stale —
// otherwise a genuinely revoked scope would silently stop alerting.
func declinedPermission(outcome recordoutcome.Summary, runErr error, panicked bool) bool {
	return runErr == nil && !panicked && outcome.Cause == recordoutcome.CausePermissionDenied
}

// runTick executes one collection, recovering from panics so a single bad
// collector run never crashes the scheduler. The whole run is timed and, when
// self-obs is enabled, the per-collector scrape.* and record-outcome metrics are
// emitted — even on the panic-recovery path, which preserves recorder progress
// and records success=0 plus an errors{panic} count.
// A run interrupted purely by shutdown cancellation (see isShutdownCancellation)
// is treated as neither success nor failure: it is skipped entirely from
// scrape.* metrics, the StatusTracker, and WARN logging, so a routine shutdown
// never leaves behind a false "collector failed" final sample.
func (s *Scheduler) runTick(ctx context.Context, e Entry, lastSuccess *time.Time) {
	started := time.Now()  // monotonic: used for duration only
	startedWall := s.now() // wall-clock: for the status page's LastStarted

	// Start a root span for this scrape cycle. API child spans nest under this
	// automatically because the span-bearing ctx is threaded down through
	// Collect / runWindow. When tracing is disabled, tr resolves to the
	// package-level no-op tracer — zero allocation cost per tick.
	tr := s.tracer
	if tr == nil {
		tr = noopSchedulerTracer
	}
	ctx, span := tr.Start(ctx, "scrape "+e.Collector.Name(),
		trace.WithSpanKind(trace.SpanKindInternal),
		trace.WithAttributes(attribute.String(semconv.AttrCollector, e.Collector.Name())))
	outcomes := recordoutcome.NewRecorder()
	attribution := telemetry.Attribution{
		TenantID:     s.tenant,
		Collector:    e.Collector.Name(),
		Transport:    TransportOf(e.Collector),
		TrafficClass: telemetry.TrafficClassSteadyState,
	}

	var runErr error
	panicked := false
	var panicVal any
	defer func() {
		if r := recover(); r != nil {
			panicked = true
			panicVal = r
			s.logger.Error("collector panicked", "collector", e.Collector.Name(), "panic", r)
		}
		outcomeSnapshot := outcomes.Snapshot()
		outcome := outcomeSnapshot.Summarize(runErr, panicked)
		healthy := outcome.Result == recordoutcome.ResultEmpty ||
			outcome.Result == recordoutcome.ResultSuccess
		// Finalize the scrape span before emitting metrics so the span is ended
		// (and therefore visible to any span processor) prior to the scrape metrics.
		switch {
		case panicked:
			span.SetStatus(codes.Error, fmt.Sprintf("panic: %v", panicVal))
		case runErr != nil:
			span.RecordError(runErr)
			span.SetStatus(codes.Error, runErr.Error())
		case !healthy:
			span.SetStatus(codes.Error, string(outcome.Cause))
		}
		span.End()

		if !panicked && isShutdownCancellation(ctx, runErr) {
			// Shutdown, not a real failure: skip scrape metrics, status
			// tracking, and WARN logging entirely (the tracing span above is
			// still recorded, since that's a per-run trace rather than a
			// persisted last-sample metric).
			return
		}

		if s.sourceRecordRecorder != nil {
			s.sourceRecordRecorder(attribution, outcomeSnapshot.Counts.Fetched)
		}

		if s.availability != nil {
			s.availability.Record(e.Collector.Name(), outcome)
		}

		duration := time.Since(started)
		finishedWall := s.now()
		if healthy || declinedPermission(outcome, runErr, panicked) {
			*lastSuccess = finishedWall
		}
		staleness := finishedWall.Sub(*lastSuccess)
		if staleness < 0 { // guard a backward wall-clock jump (NTP)
			staleness = 0
		}
		if s.selfObs {
			emitSourceRecordMetric(s.emitter, attribution, outcomeSnapshot.Counts.Fetched)
			emitScrapeMetrics(s.emitter, scrapeResult{
				collector:  e.Collector.Name(),
				tenant:     s.tenant,
				duration:   duration,
				interval:   e.Interval,
				finishedAt: finishedWall,
				staleness:  staleness,
				err:        runErr,
				panicked:   panicked,
				outcome:    outcome,
			})
			emitOutcomeMetrics(
				s.emitter,
				e.Collector.Name(),
				s.tenant,
				TransportOf(e.Collector),
				outcomeSnapshot,
				outcome,
			)
		}
		if s.status != nil {
			errStr := ""
			switch {
			case panicked:
				errStr = fmt.Sprintf("panic: %v", panicVal)
			case runErr != nil:
				errStr = runErr.Error()
			case !healthy:
				errStr = string(outcome.Cause)
			}
			s.status.record(e.Collector.Name(), startedWall, finishedWall, duration, errStr, outcome)
		}
		if !panicked && runErr == nil && !healthy {
			message := "collector completed with degraded outcome"
			if outcome.Cause == recordoutcome.CauseAccountingMismatch {
				message = "collector outcome accounting failed"
			}
			s.logger.Warn(message, "collector", e.Collector.Name(), "cause", outcome.Cause)
		}
	}()
	switch c := e.Collector.(type) {
	case WindowCollector:
		last, hasLast := s.store.Get(s.checkpointKey(c.Name()))
		targetKey := s.coldStartTargetKey(c.Name())
		coldTarget, hasColdTarget := s.store.Get(targetKey)
		if hasColdTarget && coldTarget.IsZero() {
			hasColdTarget = false
		}
		windowNow := s.now()
		switch {
		case !hasLast:
			attribution.TrafficClass = telemetry.TrafficClassColdStartBackfill
			if !hasColdTarget {
				// Freeze the original uncapped now-lag target BEFORE collection.
				// Retries and later MaxWindow slices remain anchored to it rather
				// than chasing a moving wall clock and silently becoming steady.
				coldTarget = windowNow.Add(-c.Lag())
				if err := s.store.Set(targetKey, coldTarget); err != nil {
					s.reportCheckpointPersistError(
						c.Name(),
						"cold-start target persist failed",
						err,
					)
					runErr = fmt.Errorf("persist cold-start target: %w", err)
					break
				}
				hasColdTarget = true
			}
		case hasColdTarget:
			attribution.TrafficClass = telemetry.TrafficClassColdStartBackfill
			if !last.Before(coldTarget) {
				// A prior final-slice clear failed. Retry it before scheduling
				// steady traffic; until zero is persisted, remain conservatively
				// cold even though the main HWM reached its target.
				if err := s.clearColdStartTarget(targetKey, coldTarget); err != nil {
					s.reportCheckpointPersistError(
						c.Name(),
						"cold-start target clear failed",
						err,
					)
					runErr = fmt.Errorf("clear cold-start target: %w", err)
				} else {
					hasColdTarget = false
					attribution.TrafficClass = telemetry.TrafficClassSteadyState
				}
			}
		}
		if runErr != nil {
			break
		}
		if hasColdTarget {
			// nextWindow subtracts Lag from now. Supplying target+Lag fixes its
			// uncapped upper bound at the original cold-start target.
			windowNow = coldTarget.Add(c.Lag())
		}
		runEmitter := s.runEmitter(attribution)
		runErr = s.runWindow(
			ctx,
			c,
			e,
			runEmitter,
			outcomes,
			last,
			hasLast,
			windowNow,
			targetKey,
			coldTarget,
			hasColdTarget,
		)
	case SnapshotCollector:
		runEmitter := s.runEmitter(attribution)
		runErr = c.Collect(ctx, runEmitter, outcomes)
		if runErr != nil && !isShutdownCancellation(ctx, runErr) {
			s.logger.Warn("collector failed", "collector", c.Name(), "error", runErr)
		}
	default:
		// Defensive-only: Register requires SnapshotCollector and RegisterWindow
		// requires WindowCollector, both compile-time, so a registered collector
		// always matches a case above. This branch can only be reached by a
		// future code path that appends to Registry.entries directly.
		s.logger.Warn("collector implements neither SnapshotCollector nor WindowCollector",
			"collector", c.Name())
	}
}

// runEmitter returns the collector-bound data emitter for one run and adds
// event-lag observation outside it. The factory is optional for backwards
// compatibility with package users and unit tests.
func (s *Scheduler) runEmitter(attribution telemetry.Attribution) telemetry.Emitter {
	e := s.emitter
	if s.emitterFactory != nil {
		e = s.emitterFactory(attribution)
	}
	// The horizon guard sits INSIDE the lag histogram, so an over-age record is
	// still measured as lag before being dropped: otherwise the one signal that
	// explains why records are disappearing would go quiet at exactly the moment
	// it matters.
	return telemetry.WithEventLag(
		telemetry.WithEventHorizon(
			e,
			telemetry.EventHorizon,
			attribution.Collector,
			attribution.TenantID,
			attribution.Transport,
			s.now,
		),
		attribution.Collector,
		attribution.TenantID,
		attribution.Transport,
		s.now,
	)
}

func (s *Scheduler) clearColdStartTarget(key string, target time.Time) error {
	if err := s.store.Set(key, time.Time{}); err != nil {
		// File-backed Set updates its in-memory map before persistence. Restore the
		// nonzero target even when the failed zero-write mutated memory, so the
		// running process cannot silently switch to steady. On disk, the failed
		// clear leaves the prior nonzero target intact across restart.
		restoreErr := s.store.Set(key, target)
		return errors.Join(err, restoreErr)
	}
	return nil
}

func (s *Scheduler) reportCheckpointPersistError(collectorName, message string, err error) {
	s.logger.Warn(message, "collector", collectorName, "error", err)
	if s.selfObs {
		emitCheckpointPersistError(s.emitter, collectorName, s.tenant)
	}
}

// runWindow polls a window collector's next [from, to] range and advances the
// checkpoint on success. It returns the collector's error (nil on success or
// when there is no new window to poll) so the caller can record scrape metrics.
func (s *Scheduler) runWindow(
	ctx context.Context,
	c WindowCollector,
	e Entry,
	emitter telemetry.Emitter,
	outcomes *recordoutcome.Recorder,
	last time.Time,
	hasLast bool,
	windowNow time.Time,
	coldTargetKey string,
	coldTarget time.Time,
	hasColdTarget bool,
) error {
	from, to, ok := nextWindow(last, hasLast, windowNow, c.Lag(), e.InitialLookback, e.MaxWindow)
	if !ok {
		return nil
	}
	hwm, err := c.CollectWindow(ctx, from, to, emitter, outcomes)
	if err != nil {
		// Do not advance the checkpoint: the next tick retries the same window
		// (at-least-once, no gaps).
		if !isShutdownCancellation(ctx, err) {
			s.logger.Warn("window collector failed", "collector", c.Name(), "error", err)
		}
		return err
	}
	if hwm.IsZero() {
		hwm = to
	}
	if err := s.store.Set(s.checkpointKey(c.Name()), hwm); err != nil {
		s.reportCheckpointPersistError(c.Name(), "checkpoint persist failed", err)
		return nil
	}
	if hasColdTarget && !hwm.Before(coldTarget) {
		if err := s.clearColdStartTarget(coldTargetKey, coldTarget); err != nil {
			s.reportCheckpointPersistError(c.Name(), "cold-start target clear failed", err)
			return fmt.Errorf("clear cold-start target: %w", err)
		}
	}
	return nil
}
