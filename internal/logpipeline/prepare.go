package logpipeline

import (
	"context"
	"errors"
	"time"

	"github.com/rknightion/graph2otel/internal/checkpoint"
	"github.com/rknightion/graph2otel/internal/recordoutcome"
	"github.com/rknightion/graph2otel/internal/telemetry"
	"github.com/rknightion/graph2otel/internal/wirecheck"
)

// PrepareRecord hydrates a list row. seen is read-only and can avoid auxiliary
// reads for a known key. Return the authoritative key and timestamp, not a
// provisional key read from a list index. On error no output is delivered;
// a deferred poll can retain the source version and time learned so far.
type PrepareRecord func(ctx context.Context, row map[string]any, seen func(string) bool) (PreparedRecord, error)

// PreparedRecord holds a source row ready for delivery. Deliver runs only for
// a new key within retention, before the key becomes seen. A known key needs no
// other fields. A zero Time drops the row. Deliver's emitter rejects undated
// logs rather than inheriting Time or using arrival time.
type PreparedRecord struct {
	Key     string
	Time    time.Time
	Deliver func(telemetry.Emitter)
	// SourceVersion is the authoritative version when known. If an auxiliary
	// read fails after it is known, a deferred poll keeps it and Time as the
	// new retry reference. Neither field permits delivery on error.
	SourceVersion int64
	// Stage can update collector-owned checkpoint state for a new key and
	// return a callback to release its observations after a successful Save.
	// Unlike logs, those observations must never be replayed on a save error.
	Stage func(*checkpoint.Checkpoint, telemetry.Emitter) func()
}

type datedEmitter struct {
	telemetry.Emitter
	missingTime func()
}

func (e datedEmitter) LogEvent(ev telemetry.Event) {
	if ev.Timestamp.IsZero() {
		e.missingTime()
		return
	}
	e.Emitter.LogEvent(ev)
}

func ingestPrepared(ctx context.Context, cfg EndpointConfig, cp *checkpoint.Checkpoint, row map[string]any, e telemetry.Emitter, outcomes *recordoutcome.Recorder) (PreparedRecord, error) {
	if err := ctx.Err(); err != nil {
		return PreparedRecord{}, err
	}
	rec, err := cfg.Prepare(ctx, row, cp.SeenIDs.Has)
	if err != nil {
		return rec, err
	}
	missingTime := func() {
		outcomes.Cause(recordoutcome.CauseMissingEventTime)
		wirecheck.Shared(cfg.CollectorName).MissingField(e, "event_time")
	}
	switch {
	case rec.Key != "" && cp.SeenIDs.Has(rec.Key):
		outcomes.Add(recordoutcome.OutcomeMapped, 1)
		outcomes.Add(recordoutcome.OutcomeDeduped, 1)
	case rec.Time.IsZero():
		outcomes.Add(recordoutcome.OutcomeDropped, 1)
		missingTime()
	case rec.Time.Before(cfg.NotBefore):
		outcomes.Add(recordoutcome.OutcomeFiltered, 1)
	default:
		if rec.Deliver == nil {
			return rec, errors.New("logpipeline: new prepared row has no delivery function")
		}
		outcomes.Add(recordoutcome.OutcomeMapped, 1)
		rec.Deliver(datedEmitter{Emitter: e, missingTime: missingTime})
		if rec.Stage != nil && cfg.stage != nil {
			cfg.stage(rec.Stage, e)
		}
		outcomes.Add(recordoutcome.OutcomeEmitted, 1)
		if rec.Key != "" {
			cp.SeenIDs.Add(rec.Key, rec.Time)
		}
	}
	return rec, nil
}

func later(a, b time.Time) time.Time {
	if b.After(a) {
		return b
	}
	return a
}
