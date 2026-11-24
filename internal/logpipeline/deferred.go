package logpipeline

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/rknightion/graph2otel/internal/checkpoint"
	"github.com/rknightion/graph2otel/internal/recordoutcome"
	"github.com/rknightion/graph2otel/internal/telemetry"
)

// DeferredPolicy lets a prepared endpoint commit discovery separately from
// delivery. Rows carry a string "id", int64 "version" (zero if unknown),
// and a source timestamp in TimeField. Detail must enforce the minimum version
// when fetching the latest record by ID.
type DeferredPolicy struct {
	Capacity, RetriesPerPoll int
	ValidID                  func(string) bool
}

type deferredQueue struct {
	policy   *DeferredPolicy
	order    []string
	pending  map[string]checkpoint.DeferredRecord
	resolved map[string]int64 // references disposed of by retry in this poll
	failed   bool             // a queued failure already accounted for this poll
}

func openDeferred(cfg EndpointConfig, refs []checkpoint.DeferredRecord) (*deferredQueue, error) {
	p := cfg.Deferred
	if cfg.Prepare == nil || p.ValidID == nil || p.RetriesPerPoll < 1 || p.Capacity < p.RetriesPerPoll {
		return nil, errors.New("invalid deferred delivery policy")
	}
	if len(refs) > p.Capacity {
		return nil, fmt.Errorf("checkpoint exceeds deferred delivery capacity of %d", p.Capacity)
	}
	q := &deferredQueue{policy: p, pending: make(map[string]checkpoint.DeferredRecord), resolved: make(map[string]int64)}
	for _, ref := range refs {
		if _, duplicate := q.pending[ref.ID]; duplicate || !q.valid(ref) {
			return nil, errors.New("invalid deferred delivery reference in checkpoint")
		}
		q.push(ref)
	}
	return q, nil
}

func (q *deferredQueue) valid(ref checkpoint.DeferredRecord) bool {
	return q.policy.ValidID(ref.ID) && ref.Version >= 0 && !ref.SourceTime.IsZero()
}

func (q *deferredQueue) push(ref checkpoint.DeferredRecord) {
	q.pending[ref.ID] = ref
	q.order = append(q.order, ref.ID)
}

func (q *deferredQueue) checkpoint() []checkpoint.DeferredRecord {
	if len(q.order) == 0 {
		return nil
	}
	refs := make([]checkpoint.DeferredRecord, 0, len(q.order))
	for _, id := range q.order {
		refs = append(refs, q.pending[id])
	}
	return refs
}

func (q *deferredQueue) retry(ctx context.Context, cfg EndpointConfig, cp *checkpoint.Checkpoint, e telemetry.Emitter, outcomes *recordoutcome.Recorder) {
	for range min(q.policy.RetriesPerPoll, len(q.order)) {
		if ctx.Err() != nil {
			return
		}
		id := q.order[0]
		q.order = q.order[1:]
		ref := q.pending[id]
		delete(q.pending, id)
		outcomes.Add(recordoutcome.OutcomeFetched, 1)
		if ref.SourceTime.Before(cfg.NotBefore) {
			// The source no longer promises to serve this deferred record. This
			// is evidence of delivery loss, not an empty or successful tick.
			outcomes.Add(recordoutcome.OutcomeDropped, 1)
			outcomes.Cause(recordoutcome.CauseSourceError)
			q.resolved[id] = ref.Version
			continue
		}
		row := map[string]any{"id": id, "version": ref.Version, cfg.TimeField: ref.SourceTime.Format(time.RFC3339Nano)}
		rec, err := ingestPrepared(ctx, cfg, cp, row, e, outcomes)
		if err != nil {
			failFetchedRecords(outcomes, 1, fetchFailureCause(err))
			q.failed = true
			q.push(refinedRef(ref, rec)) // rotate failures behind untouched refs
			continue
		}
		q.resolved[id] = max(ref.Version, rec.SourceVersion)
	}
}

func (q *deferredQueue) discover(ctx context.Context, cfg EndpointConfig, cp *checkpoint.Checkpoint, rows []map[string]any, e telemetry.Emitter, outcomes *recordoutcome.Recorder) error {
	for i, row := range rows {
		if err := q.ingest(ctx, cfg, cp, row, e, outcomes); err != nil {
			// The failing row was already counted; the remainder will be
			// revisited because discovery does not commit on this path.
			failFetchedRecords(outcomes, uint64(len(rows[i+1:])), fetchFailureCause(err))
			return err
		}
	}
	return ctx.Err()
}

// ingest disposes of one discovered row. A valid queued ref is a disposition,
// not a delivered key. A failure without a ref (including capacity overflow)
// remains a hard error so discovery will revisit this window.
func (q *deferredQueue) ingest(ctx context.Context, cfg EndpointConfig, cp *checkpoint.Checkpoint, row map[string]any, e telemetry.Emitter, outcomes *recordoutcome.Recorder) error {
	if err := ctx.Err(); err != nil {
		failFetchedRecords(outcomes, 1, fetchFailureCause(err))
		return err
	}
	id, _ := row["id"].(string)
	version, _ := row["version"].(int64)
	sourceTime, _ := recordTime(row, cfg.TimeField)
	ref := checkpoint.DeferredRecord{ID: id, Version: version, SourceTime: sourceTime.UTC()}
	if q.valid(ref) {
		if pending, ok := q.pending[id]; ok {
			// There is one latest-by-ID fetch, not a historical version API.
			// Keep the newest known minimum without resetting the FIFO position.
			if ref.Version > pending.Version {
				q.pending[id] = ref
			}
			outcomes.Add(recordoutcome.OutcomeFiltered, 1)
			return nil
		}
		if version, ok := q.resolved[id]; ok && version >= ref.Version {
			outcomes.Add(recordoutcome.OutcomeFiltered, 1)
			return nil
		}
	}
	rec, err := ingestPrepared(ctx, cfg, cp, row, e, outcomes)
	if err == nil {
		return nil
	}
	failFetchedRecords(outcomes, 1, fetchFailureCause(err))
	if ctx.Err() != nil {
		return ctx.Err()
	}
	ref = refinedRef(ref, rec)
	if !q.valid(ref) {
		return fmt.Errorf("cannot defer row without valid source reference: %w", err)
	}
	if len(q.pending) >= q.policy.Capacity {
		outcomes.Cause(recordoutcome.CauseSourceError)
		return fmt.Errorf("deferred delivery capacity of %d exceeded: %w", q.policy.Capacity, err)
	}
	q.push(ref)
	q.failed = true
	return nil
}

func refinedRef(ref checkpoint.DeferredRecord, rec PreparedRecord) checkpoint.DeferredRecord {
	if rec.SourceVersion > 0 && rec.SourceVersion >= ref.Version && !rec.Time.IsZero() {
		ref.Version = rec.SourceVersion
		ref.SourceTime = rec.Time.UTC()
	}
	return ref
}
