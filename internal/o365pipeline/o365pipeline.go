// Package o365pipeline is the engine every collector on the Office 365
// Management Activity API runs on (#100). It is the third ingest engine in
// graph2otel, alongside logpipeline (paged Graph GET, time watermark) and
// blobpipeline (Azure Storage append blobs, byte offset).
//
// # Why this is not logpipeline
//
// logpipeline's endpoints hand back records from one paged GET, so its cursor
// is a time watermark over the records themselves. This API is a TWO-STEP
// fetch: /subscriptions/content lists opaque content blobs, and each blob is
// then fetched to get the records inside. The two steps have different
// identities and different dedupe needs, so the cursor is a watermark over blob
// contentCreated PLUS two id sets, not a watermark alone.
//
// # The read-only break
//
// POST /subscriptions/start is a WRITE — the second break in graph2otel's
// read-only property, after the Intune reports-export job. This engine performs
// it lazily on the first Collect for each configured content type, because
// listing content for a type that was never subscribed returns AF20022 forever
// and there is no read-only way out of that state. It is narrower than the
// export-job break: it creates a subscription rather than mutating tenant data,
// and ActivityFeed.Read authorizes it with no ReadWrite scope. Starting an
// already-started subscription is not an error — the API treats it as an update
// — which is what makes the lazy start safe to repeat across restarts.
//
// # Why BOTH id sets are load-bearing
//
// Blobs are explicitly non-sequential: the reference states one blob "can
// contain actions and events that occurred prior to" an earlier blob. Two
// consequences, and they need different defenses:
//
//   - The same BLOB is re-listed by the overlap window on a later tick.
//     contentId dedupe skips it without spending a fetch.
//   - The same RECORD can appear in two DIFFERENT blobs, which contentId dedupe
//     cannot catch because the ids differ. Record-Id dedupe catches it. Azure's
//     at-least-once delivery (#138, measured ~2.3% re-delivery on the blob path)
//     is the same hazard class.
//
// # Both id sets are evicted on the BLOB's contentCreated, never on event time
//
// This is subtle and getting it wrong breaks dedupe silently. Records inside a
// blob can be far older than the blob itself (that is what "non-sequential"
// means). The watermark and the overlap window are both denominated in
// contentCreated, so what governs whether a record can be handed to us AGAIN is
// its blob's contentCreated — not the record's own event time. Evicting a
// record id on event time would drop it from the set while its blob is still
// inside the overlap window and still being re-listed, re-emitting it.
package o365pipeline

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"sort"
	"sync"
	"time"

	"github.com/rknightion/graph2otel/internal/checkpoint"
	"github.com/rknightion/graph2otel/internal/o365activityclient"
	"github.com/rknightion/graph2otel/internal/telemetry"
)

const (
	// DefaultOverlap is how far behind the watermark every tick re-lists, to
	// catch blobs that became available out of order. It is not tunable per
	// endpoint because every collector on this engine reads the same feed with
	// the same ordering guarantees (namely, none).
	DefaultOverlap = 2 * time.Hour

	// contentIDPrefix and recordIDPrefix namespace the two id sets — blob ids and
	// record ids — inside the checkpoint's SINGLE SeenIDs map.
	//
	// DO NOT "CLEAN THIS UP" INTO TWO MAPS. The single map is the point, not a
	// workaround for reusing checkpoint.Checkpoint. Both namespaces are
	// denominated in the same clock — the blob's contentCreated — and MUST be
	// evicted against it (see the package doc). One map means one EvictStale call
	// and therefore one eviction clock, structurally: the invariant cannot be got
	// wrong. Two maps would be two eviction calls that merely have to REMEMBER to
	// agree, and the day they diverge, record ids get evicted on event time while
	// their blobs are still re-listable and the dedupe silently starts re-emitting.
	// That is the #135 class of bug: two plausible timestamps, no error either way.
	//
	// The prefixes are printable rather than NUL-separated so the on-disk
	// checkpoint stays human-inspectable, which is the stated design goal of the
	// store's file naming. They cannot collide with real ids: contentIds are
	// '$'-delimited and record Ids are GUIDs.
	contentIDPrefix = "content:"
	recordIDPrefix  = "record:"
)

// EndpointConfig describes one Management Activity API feed: which content
// types to subscribe to and how to turn one raw audit record into a dedupe id
// plus an OTLP log Event.
type EndpointConfig struct {
	// CollectorName is the stable collector identifier, used in error messages
	// and log lines.
	CollectorName string
	// ContentTypes are the content types to subscribe to and drain. Each is
	// listed and fetched independently, but they share one checkpoint.
	ContentTypes []o365activityclient.ContentType
	// CheckpointKey is the checkpoint namespace (the endpoint component of the
	// (tenant, endpoint) store key).
	CheckpointKey string
	// EventName is the OTEL EventName applied to any Event whose Map left Name
	// empty.
	EventName string
	// Map turns one raw audit record into its immutable id — used for
	// record-level dedupe — and the OTLP log Event to emit. Returning ok=false
	// drops the record.
	//
	// Two obligations land here rather than in the engine. First, the record
	// carries ModifiedProperties with OldValue/NewValue: emit the NAMES of
	// changed properties, NEVER the values, which can carry credentials and
	// certificates. Second, Map owns the Event's Timestamp — the engine does not
	// derive one, because this API's two plausible time fields mean different
	// things and a silent fallback between them is exactly the bug #135
	// documents on the blob path.
	//
	// WHEN TO RETURN ok=false. The two ways a record can be deficient are NOT
	// the same, and the difference is the whole contract:
	//
	//   - NO ID: return ok=TRUE anyway, and the engine emits it. An id-less
	//     record is merely UNDEDUPEABLE, not unusable — its CreationTime, UPN,
	//     ClientIP and Operation still make a perfectly good log line. Dropping
	//     it would be #112 verbatim: a per-entity row that reaches no pipeline.
	//     Both dedupe branches below are guarded on a non-empty id precisely so
	//     this path works; the record ships untracked, so an at-least-once
	//     re-delivery of it would duplicate. Degraded, not lost — and degraded
	//     beats discarded.
	//   - NO PARSEABLE EVENT TIME: return ok=false. This one genuinely cannot be
	//     emitted honestly. A zero Event.Timestamp does NOT mean "unknown":
	//     telemetry's LogEvent leaves the timestamp unset (emitter.go, `if
	//     !ev.Timestamp.IsZero()`), so the record is stamped on arrival and
	//     silently claims to have happened now. Undedupeable is degraded;
	//     misdated is WRONG, and only wrong justifies a drop. Do NOT rescue it
	//     with the blob's contentCreated — that is the #135 trap exactly.
	//
	// So a mapper should return a stable id wherever the record has one, and
	// ok=false ONLY for the un-dateable case. ok=false must never be used to
	// filter records the collector merely does not want: ship those with ok=true
	// and let LogQL filter (#112). The engine cannot enforce that, so it is the
	// mapper's discipline.
	//
	// In practice both Id and CreationTime are mandatory in the Common Schema,
	// so neither path should ever fire — they are specified because a contract
	// that is silent on its edges gets read two different ways.
	Map func(rec map[string]any) (id string, ev telemetry.Event, ok bool)
}

// There is deliberately NO InitialLookback here, and no clock. The scheduler
// owns the cold-start window: collectors.RegisteredWindow carries
// InitialLookback and MaxWindow, and collector.nextWindow turns them into the
// [from, to] handed to Collect (window.go: `from = to.Add(-initialLookback)`
// when there is no checkpoint). A second copy on this struct would let the
// engine and the scheduler disagree about the same window with the engine
// winning silently — and the 7-day clamp would then live in two places too,
// when o365activityclient.ListContent already owns it and logs when it fires.
// logpipeline.EndpointConfig carries no lookback for exactly this reason.

// Collector drives one feed: it subscribes lazily, lists content over the
// window, fetches each new blob, dedupes at both the blob and record level, and
// advances a durable watermark.
type Collector struct {
	client *o365activityclient.Client
	store  *checkpoint.Store
	cfg    EndpointConfig

	mu      sync.Mutex
	started map[o365activityclient.ContentType]bool
}

// New returns a Collector for cfg, persisting through store.
func New(c *o365activityclient.Client, store *checkpoint.Store, cfg EndpointConfig) *Collector {
	return &Collector{
		client:  c,
		store:   store,
		cfg:     cfg,
		started: make(map[o365activityclient.ContentType]bool),
	}
}

// Collect drains every content type's new blobs in the window, emitting each
// newly-seen record through e, then persists the checkpoint.
//
// from is used ONLY on a genuine cold start, and even then only when
// InitialLookback is unset: once a watermark exists, the window resumes from
// watermark-DefaultOverlap rather than from the caller's from. That mirrors
// logpipeline for the same reason — in steady state the caller's from is
// roughly the last watermark, so honoring it would collapse the overlap window
// to nothing and defeat the out-of-order catch it exists for.
//
// The checkpoint is persisted even when a content type fails, so partial
// progress survives; the failure is still returned.
func (c *Collector) Collect(ctx context.Context, from, to time.Time, e telemetry.Emitter) error {
	cp, err := c.store.Load(c.client.TenantID, c.cfg.CheckpointKey)
	if err != nil {
		return fmt.Errorf("o365pipeline: %s: load checkpoint: %w", c.cfg.CollectorName, err)
	}

	resumeFrom := c.resumeFrom(cp, from)

	var errs []error
	var maxConsumed, earliestFailed time.Time
	for _, ct := range c.cfg.ContentTypes {
		consumed, failed, cerr := c.collectContentType(ctx, ct, cp, resumeFrom, to, e)
		if cerr != nil {
			errs = append(errs, cerr)
		}
		if !consumed.IsZero() && consumed.After(maxConsumed) {
			maxConsumed = consumed
		}
		if !failed.IsZero() && (earliestFailed.IsZero() || failed.Before(earliestFailed)) {
			earliestFailed = failed
		}
	}

	c.advance(cp, maxConsumed, earliestFailed)

	if serr := c.store.Save(cp); serr != nil {
		errs = append(errs, fmt.Errorf("o365pipeline: %s: save checkpoint: %w", c.cfg.CollectorName, serr))
	}
	return errors.Join(errs...)
}

// resumeFrom picks the window's lower bound: watermark-overlap once a watermark
// exists, otherwise the caller's from verbatim.
//
// On a COLD start from is the scheduler's cold-start window, already computed
// from the collector's declared InitialLookback, so it is used as given. It is
// left unclamped against MaxLookback on purpose — ListContent clamps it and
// logs why, and duplicating that here would put the 7-day bound in two places
// that could drift apart.
//
// On a WARM tick from is deliberately IGNORED. In steady state the scheduler's
// from is roughly the previous tick's high-water mark, so honoring it (or taking
// max(from, watermark-overlap)) would collapse the overlap window to nothing and
// defeat the out-of-order catch it exists for. SeenIDs is what makes re-querying
// that range cheap: dedupe, not re-emission. Same reasoning as
// logpipeline.CollectWindow.
func (c *Collector) resumeFrom(cp *checkpoint.Checkpoint, from time.Time) time.Time {
	if !cp.Watermark.IsZero() {
		return cp.Watermark.Add(-DefaultOverlap)
	}
	return from
}

// advance moves the watermark to the newest blob actually consumed — never to
// `to`, and never past a blob that failed.
//
// Advancing to `to` is the bug jobpipeline's emitAndAdvance warns about: `to` is
// what we ASKED for, and the gap between that and what we actually consumed is
// exactly the data a later tick would skip. Stopping short of earliestFailed
// keeps the invariant that everything at or below the watermark has been
// consumed, so a blob whose fetch failed is re-listed and retried rather than
// silently dropped once the overlap window slides past it.
func (c *Collector) advance(cp *checkpoint.Checkpoint, maxConsumed, earliestFailed time.Time) {
	candidate := maxConsumed
	if !earliestFailed.IsZero() && !candidate.Before(earliestFailed) {
		candidate = earliestFailed.Add(-time.Nanosecond)
	}
	if candidate.After(cp.Watermark) {
		cp.Watermark = candidate
	}
	cp.OverlapWindow = DefaultOverlap
	cp.EvictStale()
}

// collectContentType drains one content type, returning the newest blob
// contentCreated it consumed and the oldest it failed to consume.
func (c *Collector) collectContentType(
	ctx context.Context,
	ct o365activityclient.ContentType,
	cp *checkpoint.Checkpoint,
	from, to time.Time,
	e telemetry.Emitter,
) (consumed, failed time.Time, err error) {
	if err := c.ensureSubscription(ctx, ct); err != nil {
		return time.Time{}, time.Time{}, err
	}

	blobs, err := c.list(ctx, ct, from, to)
	if err != nil {
		return time.Time{}, time.Time{}, err
	}

	// The API does not list blobs in contentCreated order, and the watermark is
	// a claim about a prefix of that order, so sort before consuming.
	sort.Slice(blobs, func(i, j int) bool { return blobs[i].ContentCreated.Before(blobs[j].ContentCreated) })

	for _, b := range blobs {
		if err := c.consume(ctx, b, cp, e); err != nil {
			if failed.IsZero() || b.ContentCreated.Before(failed) {
				failed = b.ContentCreated
			}
			return consumed, failed, err
		}
		if b.ContentCreated.After(consumed) {
			consumed = b.ContentCreated
		}
	}
	return consumed, failed, nil
}

// list lists content for ct, recovering once from AF20022 by starting the
// subscription. That code means the subscription is genuinely absent — an admin
// stopped it, or it was never started — and a restart is the only way forward.
func (c *Collector) list(ctx context.Context, ct o365activityclient.ContentType, from, to time.Time) ([]o365activityclient.ContentBlob, error) {
	blobs, err := c.client.ListContent(ctx, ct, from, to)
	if err == nil {
		return blobs, nil
	}
	if !o365activityclient.IsNoSubscription(err) {
		return nil, fmt.Errorf("o365pipeline: %s: list %s: %w", c.cfg.CollectorName, ct, err)
	}

	slog.Info("no subscription for content type; starting it and retrying the listing once",
		"collector", c.cfg.CollectorName, "tenant_id", c.client.TenantID, "content_type", ct)
	if serr := c.startSubscription(ctx, ct); serr != nil {
		return nil, serr
	}
	blobs, err = c.client.ListContent(ctx, ct, from, to)
	if err != nil {
		return nil, fmt.Errorf("o365pipeline: %s: list %s after starting subscription: %w",
			c.cfg.CollectorName, ct, err)
	}
	return blobs, nil
}

// consume fetches one blob and emits its new records, unless the blob was
// already consumed on an earlier tick.
func (c *Collector) consume(ctx context.Context, b o365activityclient.ContentBlob, cp *checkpoint.Checkpoint, e telemetry.Emitter) error {
	if cp.SeenIDs.Has(contentIDPrefix + b.ContentID) {
		// Already drained on an earlier tick; the overlap window re-listed it.
		// Skipping here is what makes the overlap cheap — no fetch is spent.
		return nil
	}

	records, err := c.client.FetchContent(ctx, b.ContentURI)
	if err != nil {
		// An expired blob is terminally unretrievable, so it is consumed-as-empty
		// rather than retried forever: a blob listed shortly before it aged out is
		// a normal race, not a fault. Every other failure — a throttle, a real
		// malformed-request 400, a 5xx — is returned, because blanket-swallowing a
		// status is how a genuine bug hides.
		if o365activityclient.IsContentExpired(err) {
			slog.Info("content blob expired before it could be fetched; skipping it",
				"collector", c.cfg.CollectorName, "tenant_id", c.client.TenantID,
				"content_id", b.ContentID, "content_created", b.ContentCreated.Format(time.RFC3339))
			cp.SeenIDs.Add(contentIDPrefix+b.ContentID, b.ContentCreated)
			return nil
		}
		return fmt.Errorf("o365pipeline: %s: fetch blob %s: %w", c.cfg.CollectorName, b.ContentID, err)
	}

	for _, raw := range records {
		id, ev, ok := c.cfg.Map(raw)
		if !ok {
			continue
		}
		if id != "" && cp.SeenIDs.Has(recordIDPrefix+id) {
			// The same record reached us in a different blob. contentId dedupe
			// cannot catch this — the blob ids differ.
			continue
		}
		if ev.Name == "" {
			ev.Name = c.cfg.EventName
		}
		e.LogEvent(ev)
		if id != "" {
			cp.SeenIDs.Add(recordIDPrefix+id, b.ContentCreated)
		}
	}

	cp.SeenIDs.Add(contentIDPrefix+b.ContentID, b.ContentCreated)
	return nil
}

// ensureSubscription starts ct's subscription once per process.
func (c *Collector) ensureSubscription(ctx context.Context, ct o365activityclient.ContentType) error {
	c.mu.Lock()
	done := c.started[ct]
	c.mu.Unlock()
	if done {
		return nil
	}
	return c.startSubscription(ctx, ct)
}

// startSubscription performs the write, tolerating a subscription that is
// already enabled.
//
// The tolerance is NOT theoretical politeness — without it this collector fails
// on every tick against any tenant whose subscriptions were started by anything
// else (a previous deployment, another tool, an operator). Verified live
// 2026-07-16: /subscriptions/start against an enabled content type returns
//
//	HTTP 400  AF20024: The subscription is already enabled. No property change.
//
// The reference says a re-start "is used to update the properties of an active
// webhook", i.e. that it is a safe no-op, and omits AF20024 from its error table
// altogether. Both are wrong. This comment previously claimed the tolerance
// existed while the code did not implement it — the claim was inherited from the
// docs and never tested, so the bug shipped and was caught only on a live tenant.
func (c *Collector) startSubscription(ctx context.Context, ct o365activityclient.ContentType) error {
	if _, err := c.client.StartSubscription(ctx, ct); err != nil && !o365activityclient.IsAlreadyEnabled(err) {
		return fmt.Errorf("o365pipeline: %s: start subscription %s: %w", c.cfg.CollectorName, ct, err)
	}
	c.mu.Lock()
	c.started[ct] = true
	c.mu.Unlock()
	return nil
}
