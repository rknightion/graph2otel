package recordoutcome

import (
	"context"
	"errors"
	"reflect"
	"sync"
	"testing"
)

func TestRecorderCountsEveryBoundedOutcome(t *testing.T) {
	t.Parallel()

	r := NewRecorder()
	r.Add(OutcomeFetched, 21)
	r.Add(OutcomeMapped, 13)
	r.Add(OutcomeEmitted, 8)
	r.Add(OutcomeDeduped, 5)
	r.Add(OutcomeFiltered, 3)
	r.Add(OutcomeDropped, 2)
	r.Add(OutcomeErrored, 3)

	want := Counts{
		Fetched: 21, Mapped: 13, Emitted: 8, Deduped: 5,
		Filtered: 3, Dropped: 2, Errored: 3,
	}
	if got := r.Snapshot().Counts; got != want {
		t.Fatalf("Counts = %+v, want %+v", got, want)
	}
}

func TestRecorderRejectsUnboundedDimensions(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		act  func(*Recorder)
	}{
		{
			name: "unknown outcome",
			act:  func(r *Recorder) { r.Add(Outcome("raw backend error"), 1) },
		},
		{
			name: "unknown cause",
			act:  func(r *Recorder) { r.Cause(Cause("HTTP 403 for user@example.com")) },
		},
		{
			name: "unknown expected JSON type",
			act:  func(r *Recorder) { r.TypeMismatch("riskLevel", "integer", "string") },
		},
		{
			name: "unknown actual JSON type",
			act:  func(r *Recorder) { r.TypeMismatch("riskLevel", "number", "undefined") },
		},
		{
			name: "empty field",
			act:  func(r *Recorder) { r.TypeMismatch("", "number", "string") },
		},
		{
			name: "equal types are not a mismatch",
			act:  func(r *Recorder) { r.TypeMismatch("riskLevel", "string", "string") },
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			r := NewRecorder()
			tt.act(r)
			got := r.Snapshot()
			if !reflect.DeepEqual(got.Causes, []Cause{CauseAccountingMismatch}) {
				t.Fatalf("Causes = %v, want [%q]", got.Causes, CauseAccountingMismatch)
			}
			if len(got.TypeMismatches) != 0 {
				t.Fatalf("TypeMismatches = %+v, want none", got.TypeMismatches)
			}
		})
	}
}

func TestRecorderSnapshotIsImmutableAndDeterministic(t *testing.T) {
	t.Parallel()

	r := NewRecorder()
	r.Cause(CauseTimeout)
	r.Cause(CauseDecodeError)
	r.Cause(CauseTimeout)
	r.TypeMismatch("zeta", "array", "object")
	r.TypeMismatch("alpha", "number", "string")
	r.TypeMismatch("alpha", "number", "string")

	first := r.Snapshot()
	wantCauses := []Cause{CauseDecodeError, CauseTimeout}
	if !reflect.DeepEqual(first.Causes, wantCauses) {
		t.Fatalf("Causes = %v, want %v", first.Causes, wantCauses)
	}
	wantMismatches := []TypeMismatch{
		{Field: "alpha", ExpectedType: "number", ActualType: "string", Count: 2},
		{Field: "zeta", ExpectedType: "array", ActualType: "object", Count: 1},
	}
	if !reflect.DeepEqual(first.TypeMismatches, wantMismatches) {
		t.Fatalf("TypeMismatches = %+v, want %+v", first.TypeMismatches, wantMismatches)
	}

	first.Causes[0] = CausePanic
	first.TypeMismatches[0].Field = "mutated"
	second := r.Snapshot()
	if !reflect.DeepEqual(second.Causes, wantCauses) {
		t.Fatalf("mutating snapshot Causes changed recorder: %v", second.Causes)
	}
	if !reflect.DeepEqual(second.TypeMismatches, wantMismatches) {
		t.Fatalf("mutating snapshot TypeMismatches changed recorder: %+v", second.TypeMismatches)
	}
}

func TestRecorderIsConcurrencySafe(t *testing.T) {
	t.Parallel()

	const workers = 64
	r := NewRecorder()
	var wg sync.WaitGroup
	wg.Add(workers)
	for i := 0; i < workers; i++ {
		go func() {
			defer wg.Done()
			r.Add(OutcomeFetched, 2)
			r.Add(OutcomeMapped, 2)
			r.Add(OutcomeEmitted, 2)
			r.Cause(CauseTimeout)
			r.TypeMismatch("riskLevel", "number", "string")
			_ = r.Snapshot()
		}()
	}
	wg.Wait()

	got := r.Snapshot()
	want := uint64(workers * 2)
	if got.Counts.Fetched != want || got.Counts.Mapped != want || got.Counts.Emitted != want {
		t.Fatalf("Counts = %+v, want fetched=mapped=emitted=%d", got.Counts, want)
	}
	if !reflect.DeepEqual(got.Causes, []Cause{CauseTimeout}) {
		t.Fatalf("Causes = %v, want [%q]", got.Causes, CauseTimeout)
	}
	wantMismatches := []TypeMismatch{{
		Field: "riskLevel", ExpectedType: "number", ActualType: "string", Count: workers,
	}}
	if !reflect.DeepEqual(got.TypeMismatches, wantMismatches) {
		t.Fatalf("TypeMismatches = %+v, want %+v", got.TypeMismatches, wantMismatches)
	}
}

func TestNilRecorderIsSafe(t *testing.T) {
	t.Parallel()

	var r *Recorder
	r.Add(OutcomeFetched, 1)
	r.Cause(CauseTimeout)
	r.TypeMismatch("field", "number", "string")
	if got := r.Snapshot(); !reflect.DeepEqual(got, Snapshot{}) {
		t.Fatalf("Snapshot = %+v, want zero", got)
	}
}

func TestSnapshotValidateReconciliation(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		snap    Snapshot
		wantErr bool
	}{
		{
			name: "balanced emitted deduped filtered dropped and errored",
			snap: Snapshot{Counts: Counts{
				Fetched: 21, Mapped: 13, Emitted: 8, Deduped: 5,
				Filtered: 3, Dropped: 2, Errored: 3,
			}},
		},
		{
			name:    "fetched side mismatch",
			snap:    Snapshot{Counts: Counts{Fetched: 2, Mapped: 1}},
			wantErr: true,
		},
		{
			name:    "mapped side mismatch",
			snap:    Snapshot{Counts: Counts{Fetched: 1, Mapped: 1}},
			wantErr: true,
		},
		{
			name: "invalid cause",
			snap: Snapshot{
				Causes: []Cause{"raw error"},
			},
			wantErr: true,
		},
		{
			name: "invalid JSON type",
			snap: Snapshot{
				TypeMismatches: []TypeMismatch{{
					Field: "field", ExpectedType: "integer", ActualType: "string",
					Count: 1,
				}},
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			gotErr := tt.snap.Validate()
			if (gotErr != nil) != tt.wantErr {
				t.Fatalf("Validate() error = %v, wantErr %t", gotErr, tt.wantErr)
			}
		})
	}
}

func TestSnapshotSummarizeClassifiesRun(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		snap     Snapshot
		runErr   error
		panicked bool
		want     Summary
	}{
		{
			name: "clean empty source",
			want: Summary{Result: ResultEmpty},
		},
		{
			name: "all emitted",
			snap: Snapshot{Counts: Counts{Fetched: 2, Mapped: 2, Emitted: 2}},
			want: Summary{
				Result: ResultSuccess,
				Counts: Counts{Fetched: 2, Mapped: 2, Emitted: 2},
			},
		},
		{
			name: "all deduped is successful non-empty work",
			snap: Snapshot{Counts: Counts{Fetched: 2, Mapped: 2, Deduped: 2}},
			want: Summary{
				Result: ResultSuccess,
				Counts: Counts{Fetched: 2, Mapped: 2, Deduped: 2},
			},
		},
		{
			name: "all intentionally filtered is successful non-empty work",
			snap: Snapshot{Counts: Counts{Fetched: 2, Filtered: 2}},
			want: Summary{
				Result: ResultSuccess,
				Counts: Counts{Fetched: 2, Filtered: 2},
			},
		},
		{
			name: "useful progress plus source error is partial",
			snap: Snapshot{Counts: Counts{
				Fetched: 2, Mapped: 1, Emitted: 1, Errored: 1,
			}},
			runErr: errors.New("source failed after first page"),
			want: Summary{
				Result: ResultPartial, Cause: CauseSourceError,
				Counts: Counts{Fetched: 2, Mapped: 1, Emitted: 1, Errored: 1},
			},
		},
		{
			name:   "error without useful progress is failure",
			runErr: errors.New("source unavailable"),
			want:   Summary{Result: ResultFailure, Cause: CauseSourceError},
		},
		{
			name: "explicit cause is preserved",
			snap: Snapshot{
				Counts: Counts{Fetched: 1, Dropped: 1},
				Causes: []Cause{CauseMissingEventTime},
			},
			want: Summary{
				Result: ResultFailure, Cause: CauseMissingEventTime,
				Counts: Counts{Fetched: 1, Dropped: 1},
			},
		},
		{
			name: "accounting mismatch is failure",
			snap: Snapshot{Counts: Counts{Fetched: 1}},
			want: Summary{
				Result: ResultFailure, Cause: CauseAccountingMismatch,
				Counts: Counts{Fetched: 1},
			},
		},
		{
			name: "payload mismatch plus useful progress is partial",
			snap: Snapshot{
				Counts: Counts{Fetched: 1, Mapped: 1, Emitted: 1},
				TypeMismatches: []TypeMismatch{{
					Field: "riskLevel", ExpectedType: "number", ActualType: "string",
					Count: 1,
				}},
			},
			want: Summary{
				Result: ResultPartial, Cause: CauseMappingError,
				Counts: Counts{Fetched: 1, Mapped: 1, Emitted: 1},
			},
		},
		{
			name:     "panic without useful progress is failure",
			panicked: true,
			want:     Summary{Result: ResultFailure, Cause: CausePanic},
		},
		{
			name:     "panic after useful progress is partial",
			snap:     Snapshot{Counts: Counts{Fetched: 1, Mapped: 1, Emitted: 1}},
			panicked: true,
			want: Summary{
				Result: ResultPartial, Cause: CausePanic,
				Counts: Counts{Fetched: 1, Mapped: 1, Emitted: 1},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			if got := tt.snap.Summarize(tt.runErr, tt.panicked); got != tt.want {
				t.Fatalf("Summarize() = %+v, want %+v", got, tt.want)
			}
		})
	}
}

func TestSnapshotSummarizeUsesExplicitCausePrecedence(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		snap Snapshot
		err  error
		want Cause
	}{
		{
			name: "timeout outranks source and mapping errors",
			snap: Snapshot{Causes: []Cause{
				CauseMappingError, CauseSourceError, CauseTimeout,
			}},
			want: CauseTimeout,
		},
		{
			name: "accounting mismatch outranks permission",
			snap: Snapshot{
				Counts: Counts{Fetched: 1},
				Causes: []Cause{CausePermissionDenied},
			},
			want: CauseAccountingMismatch,
		},
		{
			name: "deadline error outranks recorded source error",
			snap: Snapshot{Causes: []Cause{CauseSourceError}},
			err:  context.DeadlineExceeded,
			want: CauseTimeout,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := tt.snap.Summarize(tt.err, false).Cause; got != tt.want {
				t.Fatalf("Summarize().Cause = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestCauseForErrorUsesOnlyTypedContextErrors(t *testing.T) {
	t.Parallel()

	if got := CauseForError(context.DeadlineExceeded); got != CauseTimeout {
		t.Fatalf("CauseForError(deadline) = %q, want %q", got, CauseTimeout)
	}
	if got := CauseForError(errors.New("status 403: forbidden")); got != CauseSourceError {
		t.Fatalf("CauseForError(untyped 403) = %q, want %q", got, CauseSourceError)
	}
	if got := CauseForError(nil); got != CauseNone {
		t.Fatalf("CauseForError(nil) = %q, want %q", got, CauseNone)
	}
}
