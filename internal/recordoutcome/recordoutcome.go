// Package recordoutcome records bounded per-run source-record outcomes.
package recordoutcome

import (
	"context"
	"errors"
	"fmt"
	"math"
	"slices"
	"sync"
)

// Outcome is one bounded source-record lifecycle outcome.
type Outcome string

const (
	OutcomeFetched  Outcome = "fetched"
	OutcomeMapped   Outcome = "mapped"
	OutcomeEmitted  Outcome = "emitted"
	OutcomeDeduped  Outcome = "deduped"
	OutcomeFiltered Outcome = "filtered"
	OutcomeDropped  Outcome = "dropped"
	OutcomeErrored  Outcome = "errored"
)

// Result is the bounded result of one collector run.
type Result string

const (
	ResultEmpty   Result = "empty"
	ResultSuccess Result = "success"
	ResultPartial Result = "partial"
	ResultFailure Result = "failure"
)

// Cause is one bounded degradation or failure cause.
type Cause string

const (
	CauseNone               Cause = ""
	CausePermissionDenied   Cause = "permission_denied"
	CauseSourceError        Cause = "source_error"
	CauseDecodeError        Cause = "decode_error"
	CauseMappingError       Cause = "mapping_error"
	CauseMissingEventTime   Cause = "missing_event_time"
	CauseAccountingMismatch Cause = "accounting_mismatch"
	CauseTimeout            Cause = "timeout"
	CausePanic              Cause = "panic"
)

// Counts holds the record totals for one collector run.
type Counts struct {
	Fetched  uint64
	Mapped   uint64
	Emitted  uint64
	Deduped  uint64
	Filtered uint64
	Dropped  uint64
	Errored  uint64
}

// TypeMismatch describes a JSON shape mismatch without retaining a field value.
type TypeMismatch struct {
	Field        string
	ExpectedType string
	ActualType   string
	Count        uint64
}

// Summary is the immutable classification of one collector run.
type Summary struct {
	Result Result
	Cause  Cause
	Counts Counts
}

// Snapshot is an immutable copy of a Recorder's current state.
type Snapshot struct {
	Counts         Counts
	Causes         []Cause
	TypeMismatches []TypeMismatch
}

// Recorder accumulates bounded record outcomes for one collector run.
type Recorder struct {
	mu             sync.RWMutex
	counts         Counts
	causes         map[Cause]struct{}
	typeMismatches map[typeMismatchKey]uint64
}

type typeMismatchKey struct {
	field        string
	expectedType string
	actualType   string
}

// NewRecorder returns an empty Recorder.
func NewRecorder() *Recorder {
	return &Recorder{
		causes:         make(map[Cause]struct{}),
		typeMismatches: make(map[typeMismatchKey]uint64),
	}
}

// Add increments one bounded outcome. An invalid outcome or an overflow is
// surfaced as an accounting mismatch rather than retained as an unbounded key.
func (r *Recorder) Add(outcome Outcome, n uint64) {
	if r == nil {
		return
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	dst := outcomeCount(&r.counts, outcome)
	if dst == nil || math.MaxUint64-*dst < n {
		r.addCauseLocked(CauseAccountingMismatch)
		return
	}
	*dst += n
}

// Cause records one bounded cause. Repeated causes are coalesced.
func (r *Recorder) Cause(cause Cause) {
	if r == nil || cause == CauseNone {
		return
	}

	r.mu.Lock()
	defer r.mu.Unlock()
	if !validCause(cause) {
		r.addCauseLocked(CauseAccountingMismatch)
		return
	}
	r.addCauseLocked(cause)
}

// TypeMismatch records a JSON type mismatch without retaining the field value.
// Unsupported JSON types and malformed mismatches become accounting mismatches.
func (r *Recorder) TypeMismatch(field, expectedType, actualType string) {
	if r == nil {
		return
	}

	r.mu.Lock()
	defer r.mu.Unlock()
	mismatch := TypeMismatch{
		Field:        field,
		ExpectedType: expectedType,
		ActualType:   actualType,
		Count:        1,
	}
	if !validTypeMismatch(mismatch) {
		r.addCauseLocked(CauseAccountingMismatch)
		return
	}
	key := typeMismatchKey{
		field: field, expectedType: expectedType, actualType: actualType,
	}
	if r.typeMismatches == nil {
		r.typeMismatches = make(map[typeMismatchKey]uint64)
	}
	if r.typeMismatches[key] == math.MaxUint64 {
		r.addCauseLocked(CauseAccountingMismatch)
		return
	}
	r.typeMismatches[key]++
}

// Snapshot returns a deterministic deep copy of the recorder state.
func (r *Recorder) Snapshot() Snapshot {
	if r == nil {
		return Snapshot{}
	}

	r.mu.RLock()
	defer r.mu.RUnlock()

	snapshot := Snapshot{
		Counts:         r.counts,
		Causes:         make([]Cause, 0, len(r.causes)),
		TypeMismatches: make([]TypeMismatch, 0, len(r.typeMismatches)),
	}
	for cause := range r.causes {
		snapshot.Causes = append(snapshot.Causes, cause)
	}
	for mismatch, count := range r.typeMismatches {
		snapshot.TypeMismatches = append(snapshot.TypeMismatches, TypeMismatch{
			Field:        mismatch.field,
			ExpectedType: mismatch.expectedType,
			ActualType:   mismatch.actualType,
			Count:        count,
		})
	}
	slices.Sort(snapshot.Causes)
	slices.SortFunc(snapshot.TypeMismatches, func(a, b TypeMismatch) int {
		if a.Field != b.Field {
			return compareString(a.Field, b.Field)
		}
		if a.ExpectedType != b.ExpectedType {
			return compareString(a.ExpectedType, b.ExpectedType)
		}
		return compareString(a.ActualType, b.ActualType)
	})
	return snapshot
}

// Validate checks the two source-record reconciliation equations and bounded
// snapshot dimensions.
func (s Snapshot) Validate() error {
	var errs []error

	first, ok := checkedSum(
		s.Counts.Mapped,
		s.Counts.Filtered,
		s.Counts.Dropped,
		s.Counts.Errored,
	)
	if !ok || s.Counts.Fetched != first {
		errs = append(errs, fmt.Errorf(
			"fetched reconciliation failed: fetched=%d accounted=%d",
			s.Counts.Fetched,
			first,
		))
	}

	second, ok := checkedSum(s.Counts.Emitted, s.Counts.Deduped)
	if !ok || s.Counts.Mapped != second {
		errs = append(errs, fmt.Errorf(
			"mapped reconciliation failed: mapped=%d accounted=%d",
			s.Counts.Mapped,
			second,
		))
	}

	for _, cause := range s.Causes {
		if !validCause(cause) {
			errs = append(errs, fmt.Errorf("invalid cause %q", cause))
		}
	}
	for _, mismatch := range s.TypeMismatches {
		if !validTypeMismatch(mismatch) {
			errs = append(errs, fmt.Errorf("invalid type mismatch for field %q", mismatch.Field))
		}
	}

	return errors.Join(errs...)
}

// Summarize classifies a run without exposing raw errors as dimensions.
func (s Snapshot) Summarize(runErr error, panicked bool) Summary {
	summary := Summary{Counts: s.Counts}
	causes := slices.Clone(s.Causes)
	if panicked {
		causes = append(causes, CausePanic)
	}
	if s.Validate() != nil {
		causes = append(causes, CauseAccountingMismatch)
	}
	if cause := CauseForError(runErr); cause != CauseNone {
		// A typed timeout is authoritative. A generic returned error is only
		// the fallback when the collector did not record a more specific
		// bounded cause such as decode_error or missing_event_time.
		if cause == CauseTimeout || len(s.Causes) == 0 {
			causes = append(causes, cause)
		}
	}
	if len(s.TypeMismatches) > 0 {
		causes = append(causes, CauseMappingError)
	}
	if s.Counts.Dropped > 0 || s.Counts.Errored > 0 {
		if len(causes) == 0 {
			causes = append(causes, CauseAccountingMismatch)
		}
	}
	summary.Cause = highestPriorityCause(causes)

	if summary.Cause == CauseNone {
		if s.Counts.Fetched == 0 {
			summary.Result = ResultEmpty
		} else {
			summary.Result = ResultSuccess
		}
		return summary
	}

	if s.Counts.Emitted > 0 || s.Counts.Deduped > 0 || s.Counts.Filtered > 0 {
		summary.Result = ResultPartial
	} else {
		summary.Result = ResultFailure
	}
	return summary
}

// CauseForError maps only typed process-control errors to a special cause.
// Untyped source errors, including formatted HTTP status strings, remain
// source_error until their client exposes a typed error contract.
func CauseForError(err error) Cause {
	switch {
	case err == nil:
		return CauseNone
	case errors.Is(err, context.DeadlineExceeded), errors.Is(err, context.Canceled):
		return CauseTimeout
	default:
		return CauseSourceError
	}
}

func highestPriorityCause(causes []Cause) Cause {
	// This order is the stable status contract consumed by #292. It is
	// deliberately semantic rather than tied to the spelling of Cause values.
	for _, candidate := range []Cause{
		CausePanic,
		CauseTimeout,
		CauseAccountingMismatch,
		CausePermissionDenied,
		CauseSourceError,
		CauseDecodeError,
		CauseMappingError,
		CauseMissingEventTime,
	} {
		if slices.Contains(causes, candidate) {
			return candidate
		}
	}
	return CauseNone
}

func (r *Recorder) addCauseLocked(cause Cause) {
	if r.causes == nil {
		r.causes = make(map[Cause]struct{})
	}
	r.causes[cause] = struct{}{}
}

func outcomeCount(counts *Counts, outcome Outcome) *uint64 {
	switch outcome {
	case OutcomeFetched:
		return &counts.Fetched
	case OutcomeMapped:
		return &counts.Mapped
	case OutcomeEmitted:
		return &counts.Emitted
	case OutcomeDeduped:
		return &counts.Deduped
	case OutcomeFiltered:
		return &counts.Filtered
	case OutcomeDropped:
		return &counts.Dropped
	case OutcomeErrored:
		return &counts.Errored
	default:
		return nil
	}
}

func validCause(cause Cause) bool {
	switch cause {
	case CausePermissionDenied,
		CauseSourceError,
		CauseDecodeError,
		CauseMappingError,
		CauseMissingEventTime,
		CauseAccountingMismatch,
		CauseTimeout,
		CausePanic:
		return true
	default:
		return false
	}
}

func validTypeMismatch(mismatch TypeMismatch) bool {
	return mismatch.Field != "" &&
		mismatch.Count > 0 &&
		mismatch.ExpectedType != mismatch.ActualType &&
		validJSONType(mismatch.ExpectedType) &&
		validJSONType(mismatch.ActualType)
}

func validJSONType(jsonType string) bool {
	switch jsonType {
	case "null", "boolean", "number", "string", "array", "object":
		return true
	default:
		return false
	}
}

func checkedSum(values ...uint64) (uint64, bool) {
	var total uint64
	for _, value := range values {
		if math.MaxUint64-total < value {
			return total, false
		}
		total += value
	}
	return total, true
}

func compareString(a, b string) int {
	switch {
	case a < b:
		return -1
	case a > b:
		return 1
	default:
		return 0
	}
}
