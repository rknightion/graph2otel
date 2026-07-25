package o365pipeline

import (
	"context"
	"reflect"
	"testing"
	"time"

	"github.com/rknightion/graph2otel/internal/o365activityclient"
	"github.com/rknightion/graph2otel/internal/recordoutcome"
	"github.com/rknightion/graph2otel/internal/telemetry"
	"github.com/rknightion/graph2otel/internal/telemetrytest"
)

func TestCollectReconcilesRecordOutcomes(t *testing.T) {
	base := testBase()
	api := newFakeAPI(t, blobSpec{
		contentType: o365activityclient.ContentExchange,
		contentID:   "blob-outcomes",
		created:     base.Add(time.Hour),
		records: []map[string]any{
			rec("emitted", base.Add(50*time.Minute)),
			rec("emitted", base.Add(50*time.Minute)), // record-level duplicate
			rec("", base.Add(51*time.Minute)),        // undedupeable, still emitted
			rec("undateable", base.Add(52*time.Minute)),
		},
	})

	cfg := testConfig(o365activityclient.ContentExchange)
	cfg.Map = func(raw map[string]any) (string, telemetry.Event, bool) {
		id, ev, ok := mapAll(raw)
		if id == "undateable" {
			return id, telemetry.Event{}, false
		}
		return id, ev, ok
	}

	logs := telemetrytest.New()
	outcomes := recordoutcome.NewRecorder()
	c := New(api.client(t), newStore(t), cfg)
	if err := c.Collect(context.Background(), base, base.Add(2*time.Hour), logs.Emitter(), outcomes); err != nil {
		t.Fatalf("Collect: %v", err)
	}

	if got, want := bodies(logs.LogRecords()), []string{"emitted", ""}; !reflect.DeepEqual(got, want) {
		t.Fatalf("emitted bodies = %v, want %v", got, want)
	}
	if got, want := outcomes.Snapshot().Counts, (recordoutcome.Counts{
		Fetched:  4,
		Mapped:   3,
		Emitted:  2,
		Deduped:  1,
		Dropped:  1,
		Filtered: 0,
		Errored:  0,
	}); got != want {
		t.Fatalf("outcomes = %+v, want %+v", got, want)
	}
	if got, want := outcomes.Snapshot().Causes, []recordoutcome.Cause{
		recordoutcome.CauseMissingEventTime,
	}; !reflect.DeepEqual(got, want) {
		t.Fatalf("causes = %v, want %v", got, want)
	}
}

func TestCollectDoesNotCountContentOverlapAsFetchedOrDeduped(t *testing.T) {
	base := testBase()
	api := newFakeAPI(t, blobSpec{
		contentType: o365activityclient.ContentExchange,
		contentID:   "blob-overlap",
		created:     base.Add(time.Hour),
		records:     []map[string]any{rec("r1", base.Add(50*time.Minute))},
	})
	c := New(api.client(t), newStore(t), testConfig(o365activityclient.ContentExchange))

	if err := c.Collect(
		context.Background(), base, base.Add(2*time.Hour), telemetrytest.New().Emitter(), recordoutcome.NewRecorder(),
	); err != nil {
		t.Fatalf("initial Collect: %v", err)
	}

	outcomes := recordoutcome.NewRecorder()
	if err := c.Collect(
		context.Background(), base, base.Add(2*time.Hour), telemetrytest.New().Emitter(), outcomes,
	); err != nil {
		t.Fatalf("overlap Collect: %v", err)
	}
	if got, want := outcomes.Snapshot().Counts, (recordoutcome.Counts{}); got != want {
		t.Fatalf("overlap outcomes = %+v, want clean zero counts", got)
	}
	if got := api.recordedFetches(); !reflect.DeepEqual(got, []string{"blob-overlap"}) {
		t.Fatalf("fetches = %v, want overlap skipped before a second blob fetch", got)
	}
}

func TestCollectReportsCleanEmptyAsZeroRecordOutcomes(t *testing.T) {
	base := testBase()
	outcomes := recordoutcome.NewRecorder()
	c := New(
		newFakeAPI(t).client(t),
		newStore(t),
		testConfig(o365activityclient.ContentExchange),
	)

	if err := c.Collect(
		context.Background(), base, base.Add(2*time.Hour), telemetrytest.New().Emitter(), outcomes,
	); err != nil {
		t.Fatalf("Collect: %v", err)
	}
	got := outcomes.Snapshot()
	if got.Counts != (recordoutcome.Counts{}) || len(got.Causes) != 0 || len(got.TypeMismatches) != 0 {
		t.Fatalf("empty snapshot = %+v, want zero counts, causes, and mismatches", got)
	}
}

func TestCollectClassifiesCancellationAsTimeout(t *testing.T) {
	base := testBase()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	outcomes := recordoutcome.NewRecorder()
	c := New(
		newFakeAPI(t).client(t),
		newStore(t),
		testConfig(o365activityclient.ContentExchange),
	)

	if err := c.Collect(
		ctx, base, base.Add(2*time.Hour), telemetrytest.New().Emitter(), outcomes,
	); err == nil {
		t.Fatal("Collect error = nil, want cancellation")
	}
	got := outcomes.Snapshot().Causes
	if len(got) != 1 || got[0] != recordoutcome.CauseTimeout {
		t.Fatalf("causes = %v, want [%q]", got, recordoutcome.CauseTimeout)
	}
}

func TestCollectReportsPartialSourceFailureWithoutInventingARecord(t *testing.T) {
	base := testBase()
	api := newFakeAPI(t,
		blobSpec{
			contentType: o365activityclient.ContentExchange,
			contentID:   "blob-failed",
			created:     base.Add(time.Hour),
			errCode:     o365activityclient.CodeInvalidContentID,
		},
		blobSpec{
			contentType: o365activityclient.ContentSharePoint,
			contentID:   "blob-healthy",
			created:     base.Add(90 * time.Minute),
			records:     []map[string]any{rec("healthy", base.Add(80*time.Minute))},
		},
	)
	outcomes := recordoutcome.NewRecorder()
	c := New(
		api.client(t),
		newStore(t),
		testConfig(o365activityclient.ContentExchange, o365activityclient.ContentSharePoint),
	)

	err := c.Collect(
		context.Background(), base, base.Add(2*time.Hour), telemetrytest.New().Emitter(), outcomes,
	)
	if err == nil {
		t.Fatal("Collect returned nil error for a failed content blob")
	}
	got := outcomes.Snapshot()
	if want := (recordoutcome.Counts{Fetched: 1, Mapped: 1, Emitted: 1}); got.Counts != want {
		t.Fatalf("counts = %+v, want %+v; a failed blob is not an invented source record", got.Counts, want)
	}
	if want := []recordoutcome.Cause{recordoutcome.CauseSourceError}; !reflect.DeepEqual(got.Causes, want) {
		t.Fatalf("causes = %v, want %v", got.Causes, want)
	}
	if err := got.Validate(); err != nil {
		t.Fatalf("partial source failure did not reconcile: %v", err)
	}
}

func TestCollectMarksExpiredBlobAsPartialWithoutInventingARecord(t *testing.T) {
	base := testBase()
	api := newFakeAPI(t,
		blobSpec{
			contentType: o365activityclient.ContentExchange,
			contentID:   "blob-expired",
			created:     base.Add(time.Hour),
			errCode:     o365activityclient.CodeContentExpired,
		},
		blobSpec{
			contentType: o365activityclient.ContentExchange,
			contentID:   "blob-healthy",
			created:     base.Add(90 * time.Minute),
			records:     []map[string]any{rec("healthy", base.Add(80*time.Minute))},
		},
	)
	outcomes := recordoutcome.NewRecorder()
	c := New(api.client(t), newStore(t), testConfig(o365activityclient.ContentExchange))

	if err := c.Collect(
		context.Background(), base, base.Add(2*time.Hour), telemetrytest.New().Emitter(), outcomes,
	); err != nil {
		t.Fatalf("Collect: %v", err)
	}
	got := outcomes.Snapshot()
	if want := (recordoutcome.Counts{Fetched: 1, Mapped: 1, Emitted: 1}); got.Counts != want {
		t.Fatalf("counts = %+v, want %+v; an expired blob is not an invented source record", got.Counts, want)
	}
	if want := []recordoutcome.Cause{recordoutcome.CauseSourceError}; !reflect.DeepEqual(got.Causes, want) {
		t.Fatalf("causes = %v, want %v", got.Causes, want)
	}
	if got := got.Summarize(nil, false).Result; got != recordoutcome.ResultPartial {
		t.Fatalf("result = %q, want %q", got, recordoutcome.ResultPartial)
	}
}

func TestCollectContainsMapperPanicToOneErroredRecord(t *testing.T) {
	base := testBase()
	api := newFakeAPI(t, blobSpec{
		contentType: o365activityclient.ContentExchange,
		contentID:   "blob-mapper-panic",
		created:     base.Add(time.Hour),
		records: []map[string]any{
			rec("before", base.Add(49*time.Minute)),
			rec("panic", base.Add(50*time.Minute)),
			rec("after", base.Add(51*time.Minute)),
		},
	})
	cfg := testConfig(o365activityclient.ContentExchange)
	cfg.Map = func(raw map[string]any) (string, telemetry.Event, bool) {
		id, ev, ok := mapAll(raw)
		if id == "panic" {
			panic("record contents must not escape into telemetry")
		}
		return id, ev, ok
	}
	logs := telemetrytest.New()
	outcomes := recordoutcome.NewRecorder()

	if err := New(api.client(t), newStore(t), cfg).Collect(
		context.Background(), base, base.Add(2*time.Hour), logs.Emitter(), outcomes,
	); err != nil {
		t.Fatalf("Collect: %v", err)
	}
	if got, want := bodies(logs.LogRecords()), []string{"before", "after"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("emitted bodies = %v, want %v", got, want)
	}
	got := outcomes.Snapshot()
	if want := (recordoutcome.Counts{Fetched: 3, Mapped: 2, Emitted: 2, Errored: 1}); got.Counts != want {
		t.Fatalf("counts = %+v, want %+v", got.Counts, want)
	}
	if want := []recordoutcome.Cause{recordoutcome.CauseMappingError}; !reflect.DeepEqual(got.Causes, want) {
		t.Fatalf("causes = %v, want %v", got.Causes, want)
	}
	if err := got.Validate(); err != nil {
		t.Fatalf("mapper panic did not reconcile: %v", err)
	}
}
