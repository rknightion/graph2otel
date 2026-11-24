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
// provisional key read from a list index. No output is used on error.
type PrepareRecord func(ctx context.Context, row map[string]any, seen func(string) bool) (PreparedRecord, error)

// PreparedRecord holds a source row ready for delivery. Deliver runs only for
// a new key within retention, before the key becomes seen. A known key needs no
// other fields. A zero Time drops the row. Deliver's emitter rejects undated
// logs rather than inheriting Time or using arrival time.
type PreparedRecord struct {
	Key     string
	Time    time.Time
	Deliver func(telemetry.Emitter)
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

func ingestPrepared(ctx context.Context, cfg EndpointConfig, cp *checkpoint.Checkpoint, row map[string]any, e telemetry.Emitter, outcomes *recordoutcome.Recorder) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	rec, err := cfg.Prepare(ctx, row, cp.SeenIDs.Has)
	if err != nil {
		return err
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
			return errors.New("logpipeline: new prepared row has no delivery function")
		}
		outcomes.Add(recordoutcome.OutcomeMapped, 1)
		rec.Deliver(datedEmitter{Emitter: e, missingTime: missingTime})
		outcomes.Add(recordoutcome.OutcomeEmitted, 1)
		if rec.Key != "" {
			cp.SeenIDs.Add(rec.Key, rec.Time)
		}
	}
	return nil
}

func later(a, b time.Time) time.Time {
	if b.After(a) {
		return b
	}
	return a
}
