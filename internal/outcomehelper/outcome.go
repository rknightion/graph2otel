// Package outcomehelper provides conservation-safe operations shared by
// collectors. Each helper accounts for logical source records, never for the
// number of OTLP signals a record produces.
package outcomehelper

import (
	"github.com/rknightion/graph2otel/internal/recordoutcome"
)

// Recorder aliases the process-wide outcome recorder so collector method
// signatures still implement collector.SnapshotCollector exactly.
type Recorder = recordoutcome.Recorder

// Emitted records n source records that mapped and emitted successfully.
func Emitted(r *Recorder, n uint64) {
	r.Add(recordoutcome.OutcomeFetched, n)
	r.Add(recordoutcome.OutcomeMapped, n)
	r.Add(recordoutcome.OutcomeEmitted, n)
}

// Filtered records n source records deliberately excluded before mapping.
func Filtered(r *Recorder, n uint64) {
	r.Add(recordoutcome.OutcomeFetched, n)
	r.Add(recordoutcome.OutcomeFiltered, n)
}

// Dropped records n source records that could not produce a usable signal.
func Dropped(r *Recorder, n uint64, cause recordoutcome.Cause) {
	r.Add(recordoutcome.OutcomeFetched, n)
	r.Add(recordoutcome.OutcomeDropped, n)
	r.Cause(cause)
}

// Errored records n source records whose processing failed.
func Errored(r *Recorder, n uint64, cause recordoutcome.Cause) {
	r.Add(recordoutcome.OutcomeFetched, n)
	r.Add(recordoutcome.OutcomeErrored, n)
	r.Cause(cause)
}

// CauseForError converts an error to one bounded run cause.
func CauseForError(err error) recordoutcome.Cause {
	return recordoutcome.CauseForError(err)
}

// RecordError records the bounded cause for a run-level error.
func RecordError(r *Recorder, err error) {
	r.Cause(CauseForError(err))
}

// SourceError records a source failure without inventing a source row.
func SourceError(r *Recorder) {
	r.Cause(recordoutcome.CauseSourceError)
}
