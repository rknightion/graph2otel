package outcomehelper

import (
	"context"
	"errors"
	"reflect"
	"testing"

	"github.com/rknightion/graph2otel/internal/recordoutcome"
)

func TestRecorderHelpersReconcileOneLogicalRecordOnce(t *testing.T) {
	t.Parallel()

	recorder := recordoutcome.NewRecorder()
	Emitted(recorder, 2)
	Filtered(recorder, 1)
	Dropped(recorder, 1, recordoutcome.CauseMappingError)
	Errored(recorder, 1, recordoutcome.CauseDecodeError)

	got := recorder.Snapshot()
	want := recordoutcome.Counts{
		Fetched: 5, Mapped: 2, Emitted: 2, Filtered: 1, Dropped: 1, Errored: 1,
	}
	if got.Counts != want {
		t.Fatalf("counts = %+v, want %+v", got.Counts, want)
	}
	if err := got.Validate(); err != nil {
		t.Fatalf("Validate() = %v", err)
	}
	if wantCauses := []recordoutcome.Cause{recordoutcome.CauseDecodeError, recordoutcome.CauseMappingError}; !reflect.DeepEqual(got.Causes, wantCauses) {
		t.Fatalf("causes = %v, want %v", got.Causes, wantCauses)
	}
}

func TestCauseForErrorIsBounded(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name string
		err  error
		want recordoutcome.Cause
	}{
		{name: "deadline", err: context.DeadlineExceeded, want: recordoutcome.CauseTimeout},
		{name: "untyped permission", err: errors.New("status 403: Forbidden"), want: recordoutcome.CauseSourceError},
		{name: "source", err: errors.New("boom"), want: recordoutcome.CauseSourceError},
		{name: "nil", want: recordoutcome.CauseNone},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if got := CauseForError(tc.err); got != tc.want {
				t.Fatalf("CauseForError() = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestSourceErrorClassifiesFailureWithoutInventingRecords(t *testing.T) {
	r := recordoutcome.NewRecorder()

	SourceError(r)

	got := r.Snapshot().Summarize(errors.New("fetch failed"), false)
	if got.Result != recordoutcome.ResultFailure {
		t.Fatalf("result = %q, want %q", got.Result, recordoutcome.ResultFailure)
	}
	if got.Cause != recordoutcome.CauseSourceError {
		t.Fatalf("cause = %q, want %q", got.Cause, recordoutcome.CauseSourceError)
	}
	if got.Counts != (recordoutcome.Counts{}) {
		t.Fatalf("counts = %+v, want zero", got.Counts)
	}
}
