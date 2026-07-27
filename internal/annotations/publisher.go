package annotations

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"sync/atomic"
	"time"

	"github.com/rknightion/graph2otel/internal/checkpoint"
	"github.com/rknightion/graph2otel/internal/config"
	"github.com/rknightion/graph2otel/internal/semconv"
	"github.com/rknightion/graph2otel/internal/telemetry"
)

// Self-observability metric names. They live in the graph2otel.* namespace
// because they describe the exporter, not a Microsoft tenant's data.
const (
	// metricPublished counts annotations Grafana accepted, by category.
	metricPublished = "graph2otel.annotation.published"
	// metricDropped counts annotations that did NOT reach Grafana, by reason.
	// One counter rather than one per failure mode: the reason set is closed and
	// small, and splitting it would multiply the dashboard surface without
	// telling an operator anything the label does not.
	metricDropped = "graph2otel.annotation.dropped"
	// metricDegraded is 1 while the most recent write failed and no later write
	// has succeeded — the same unrecovered-failure shape as
	// graph2otel.otlp.delivery.degraded (#268), so an operator reads annotation
	// health exactly as they read OTLP delivery health.
	metricDegraded = "graph2otel.annotation.degraded"
)

// unitAnnotation is the UCUM annotation unit for a count of annotations.
const unitAnnotation = "{annotation}"

// DropReason is the bounded reason an annotation did not reach Grafana. It is a
// metric label, so the set is closed (#112).
type DropReason string

const (
	// DropDuplicate is the STEADY STATE, not a fault: a state stream re-emits its
	// whole current set every tick and every already-published identity lands
	// here. It is counted rather than logged for exactly that reason.
	DropDuplicate DropReason = "duplicate"
	// DropQueueFull means the publisher's hand-off buffer was full. The
	// alternative — blocking — would make a Graph poll wait on Grafana.
	DropQueueFull DropReason = "queue_full"
	// DropRateLimited means graph2otel's own max_per_minute ceiling was hit. This
	// annotation never reached the wire.
	DropRateLimited DropReason = "local_rate_limited"
)

// DropReasons returns every non-failure drop reason in a stable order.
func DropReasons() []DropReason {
	return []DropReason{DropDuplicate, DropQueueFull, DropRateLimited}
}

// Annotator is the whole feature: the record tee, the dedupe set, the rollup
// buckets, the rate limiter and the one HTTP client. A nil *Annotator is a
// fully functional no-op, which is what makes the unset-credential path free of
// branches at every call site.
type Annotator struct {
	client   *Client
	emitter  telemetry.Emitter
	logger   *slog.Logger
	recorder *Recorder
	dedupe   *dedupeStore
	limiter  *rateLimiter
	now      func() time.Time

	queue chan Annotation
	// degraded is read by the gauge report and written by the worker only.
	degraded atomic.Bool

	workerDone chan struct{}
	closeOnce  sync.Once
	cancel     context.CancelFunc
}

// Options are Start's inputs.
type Options struct {
	// Config is the validated grafana_annotations block.
	Config config.GrafanaAnnotationsConfig
	// Emitter receives the self-observability metrics. It must be the BASE
	// process emitter, never a teed one — self-obs counters emitted through the
	// tee would be offered back to the recorder on every publish.
	Emitter telemetry.Emitter
	// CheckpointDir is where the persisted dedupe set lives. It is the same
	// directory the collectors' watermarks use, and needs the same persistent
	// volume: without it every restart republishes everything inside the source
	// collectors' overlap windows.
	CheckpointDir string
	Logger        *slog.Logger
	// Version and ConfigFingerprint carry #310's startup contract into the
	// lifecycle annotation. ConfigFingerprint MUST be startupevent.Fingerprint's
	// output — a one-way, secret-free digest. Never pass configuration here.
	Version           string
	ConfigFingerprint string
	// TenantIDs are the configured tenants, used only for the lifecycle marker.
	TenantIDs []string
	// StartedAt is the process start time, so the lifecycle marker lands where
	// the deploy happened rather than where the HTTP call completed.
	StartedAt time.Time
	// Now defaults to time.Now.
	Now func() time.Time
}

// Start builds the annotation writer, PROVES the token can write, and launches
// the publisher goroutine.
//
// It returns (nil, nil) when the feature is not configured — no client, no
// goroutine, no log line. That is the default deployment and it must be silent.
//
// When it IS configured, a write failure here is a HARD error the caller should
// treat as fatal. Discovering a token that cannot write at the first real event
// means the annotations an operator is relying on for incident context simply
// are not there when they look, and nothing in the process would have said so.
func Start(ctx context.Context, opts Options) (*Annotator, error) {
	if !opts.Config.Configured() {
		return nil, nil
	}
	now := opts.Now
	if now == nil {
		now = time.Now
	}
	logger := opts.Logger
	if logger == nil {
		logger = slog.New(slog.DiscardHandler)
	}
	client, err := NewClient(opts.Config)
	if err != nil {
		return nil, err
	}

	a := &Annotator{
		client:  client,
		emitter: opts.Emitter,
		logger:  logger,
		dedupe: newDedupeStore(
			checkpoint.NewStore(opts.CheckpointDir),
			opts.Config.DedupeRetention,
		),
		limiter:    newRateLimiter(opts.Config.MaxPerMinute, now),
		now:        now,
		queue:      make(chan Annotation, opts.Config.QueueSize),
		workerDone: make(chan struct{}),
	}
	a.recorder = NewRecorder(RecorderOptions{
		Config: opts.Config,
		Sink:   a,
		Dedupe: a.dedupe,
		Now:    now,
	})

	if err := a.preflight(ctx, opts); err != nil {
		return nil, err
	}

	workerCtx, cancel := context.WithCancel(context.WithoutCancel(ctx))
	a.cancel = cancel
	go a.run(workerCtx)
	return a, nil
}

// preflight writes the lifecycle annotation SYNCHRONOUSLY, before any collector
// runs, and reports a failure as an error.
//
// The probe and the marker are deliberately the same write. A synthetic
// "can I write?" probe would either leave a junk annotation in the operator's
// Grafana or need a delete — which would require annotations:delete, widening
// exactly the token scope this feature's narrowness rests on.
//
// Its text carries #310's contract: the build version and the one-way,
// secret-free configuration fingerprint. Two consecutive markers whose
// fingerprints differ ARE the "configuration changed" signal; the marker itself
// never claims something changed.
func (a *Annotator) preflight(ctx context.Context, opts Options) error {
	tenants := opts.TenantIDs
	if len(tenants) == 0 {
		// stdout / no-tenant mode: one unstamped marker, so the writer is still
		// proved and the marker never silently disappears.
		tenants = []string{""}
	}
	startedAt := opts.StartedAt
	if startedAt.IsZero() {
		startedAt = a.now()
	}
	text := fmt.Sprintf("graph2otel %s started; config fingerprint %s",
		opts.Version, opts.ConfigFingerprint)

	// The first write proves the permission; a later tenant's marker failing is
	// the same call with the same token, so it is equally fatal here and equally
	// worth refusing to start over.
	for _, tenantID := range tenants {
		marker := Annotation{
			Category:  CategoryLifecycle,
			TenantID:  tenantID,
			RuleID:    "graph2otel.startup",
			Time:      startedAt,
			Text:      text,
			DedupeKey: DedupeKey(tenantID, "graph2otel.startup", startedAt.UTC().Format(time.RFC3339Nano)),
		}
		if err := a.client.Publish(ctx, marker); err != nil {
			return fmt.Errorf("grafana annotation writer refusing to start: %w\n"+
				"The service-account token must hold the Grafana action "+
				"`annotations:create` on scope `annotations:type:organization` "+
				"(fixed role `fixed:annotations:writer`). graph2otel needs no other "+
				"Grafana permission. Unset grafana_annotations.url to run without "+
				"annotations", err)
		}
		a.recordPublished(marker)
	}
	return nil
}

// Decorate wraps a collector run's emitter so the records it emits are offered
// to the curated rule set. A nil *Annotator returns base unchanged, so the
// composition root needs no conditional.
func (a *Annotator) Decorate(attribution telemetry.Attribution, base telemetry.Emitter) telemetry.Emitter {
	if a == nil {
		return base
	}
	return Tee(base, a.recorder, a.recorder.BeginRun(attribution.TenantID, attribution.Collector))
}

// Publish enqueues an annotation. It NEVER blocks: a full queue drops and
// counts, because the caller is a collector goroutine mid-poll.
func (a *Annotator) Publish(annotation Annotation) {
	select {
	case a.queue <- annotation:
	default:
		a.recordDropped(annotation.TenantID, DropQueueFull)
	}
}

// Duplicate counts one occurrence suppressed by the dedupe set.
func (a *Annotator) Duplicate(tenantID string) {
	a.recordDropped(tenantID, DropDuplicate)
}

// run is the single publisher goroutine. Everything that touches Grafana happens
// here, so the rate limiter and the HTTP client need no locking and no collector
// goroutine can ever be inside an HTTP call.
func (a *Annotator) run(ctx context.Context) {
	defer close(a.workerDone)
	// The tick drives three things: closing rollup buckets, flushing the dedupe
	// set to disk, and refreshing the degraded gauge. One second is well below
	// any rollup interval and costs nothing when there is nothing to do.
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case annotation := <-a.queue:
			a.write(ctx, annotation)
		case <-ticker.C:
			a.recorder.Flush(a.now())
			a.reportDegraded()
			if err := a.dedupe.Persist(); err != nil {
				a.logger.Warn("annotation dedupe state not persisted", "error", err)
			}
		}
	}
}

// write performs one annotation write, applying the local ceiling first.
func (a *Annotator) write(ctx context.Context, annotation Annotation) {
	if !a.limiter.allow() {
		a.recordDropped(annotation.TenantID, DropRateLimited)
		return
	}
	err := a.client.Publish(ctx, annotation)
	if err == nil {
		a.degraded.Store(false)
		a.recordPublished(annotation)
		return
	}
	a.degraded.Store(true)
	code := FailureTransport
	var pubErr *PublishError
	if errors.As(err, &pubErr) {
		code = pubErr.Code
	}
	a.recordDropped(annotation.TenantID, DropReason(code))
	// Logged at Warn, not Error, and never fatal: a Grafana outage is not a
	// collection failure. The bounded code is on the metric; the detail is here,
	// because Grafana's own body is the most useful line for a permission
	// failure.
	a.logger.Warn("grafana annotation not published",
		"category", annotation.Category, "rule", annotation.RuleID, "error", err)
}

func (a *Annotator) recordPublished(annotation Annotation) {
	if a.emitter == nil {
		return
	}
	a.emitter.Counter(metricPublished, unitAnnotation,
		"Annotations accepted by the Grafana annotations API since process start.",
		1, telemetry.Attrs{
			semconv.AttrCategory: string(annotation.Category),
			semconv.AttrTenantID: annotation.TenantID,
		})
}

func (a *Annotator) recordDropped(tenantID string, reason DropReason) {
	if a.emitter == nil {
		return
	}
	a.emitter.Counter(metricDropped, unitAnnotation,
		"Annotations that did not reach Grafana since process start, by bounded reason "+
			"(duplicate is the steady state on a state-shaped source, not a fault).",
		1, telemetry.Attrs{
			semconv.AttrReason:   string(reason),
			semconv.AttrTenantID: tenantID,
		})
}

// reportDegraded republishes the degraded gauge. GaugeSnapshot rather than Gauge
// for the same reason telemetry's delivery gauge uses it: an observable gauge
// reports exactly what the callback observes each cycle, so the value cannot
// linger at a stale 1 under forced cumulative temporality.
func (a *Annotator) reportDegraded() {
	if a.emitter == nil {
		return
	}
	value := 0.0
	if a.degraded.Load() {
		value = 1
	}
	a.emitter.GaugeSnapshot(metricDegraded, semconv.UnitDimensionless,
		"Whether the most recent Grafana annotation write failed and has not been "+
			"recovered by a later success.",
		[]telemetry.GaugePoint{{Value: value}})
}

// Close stops the publisher, flushes the open rollup buckets, drains what is
// already queued, and persists the dedupe set.
//
// The drain is bounded by ctx: a Grafana that is down must not hold up process
// shutdown, and a lost annotation at shutdown is exactly the "degraded" this
// feature is designed to tolerate.
func (a *Annotator) Close(ctx context.Context) error {
	if a == nil {
		return nil
	}
	var err error
	a.closeOnce.Do(func() {
		a.cancel()
		<-a.workerDone
		a.recorder.FlushAll()
		for {
			select {
			case annotation := <-a.queue:
				a.write(ctx, annotation)
				continue
			default:
			}
			break
		}
		err = a.dedupe.Persist()
	})
	return err
}
