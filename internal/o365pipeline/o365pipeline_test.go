package o365pipeline

import (
	"context"
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/rknightion/graph2otel/internal/checkpoint"
	"github.com/rknightion/graph2otel/internal/o365activityclient"
	"github.com/rknightion/graph2otel/internal/telemetry"
	"github.com/rknightion/graph2otel/internal/telemetrytest"
)

// testBase is a time inside the API's 7-day lookback bound. It must track real
// wall-clock time: the client's ListContent clamps a startTime older than
// MaxLookback using the real time.Now(), so a fabricated far-past base would be
// clamped forward and every listing would come back empty.
func testBase() time.Time {
	return time.Now().UTC().Truncate(time.Second).Add(-6 * time.Hour)
}

func testConfig(cts ...o365activityclient.ContentType) EndpointConfig {
	return EndpointConfig{
		CollectorName: "m365.activity",
		ContentTypes:  cts,
		CheckpointKey: "o365/activity",
		EventName:     "m365.audit",
		Map:           mapAll,
	}
}

// TestCollectEmitsEveryMappedRecord is the base case: two blobs, three records,
// all of them reach the emitter.
func TestCollectEmitsEveryMappedRecord(t *testing.T) {
	base := testBase()
	api := newFakeAPI(t,
		blobSpec{
			contentType: o365activityclient.ContentExchange,
			contentID:   "blob-1",
			created:     base.Add(1 * time.Hour),
			records:     []map[string]any{rec("r1", base.Add(50*time.Minute)), rec("r2", base.Add(55*time.Minute))},
		},
		blobSpec{
			contentType: o365activityclient.ContentExchange,
			contentID:   "blob-2",
			created:     base.Add(2 * time.Hour),
			records:     []map[string]any{rec("r3", base.Add(110*time.Minute))},
		},
	)

	rc := telemetrytest.New()
	c := New(api.client(t), newStore(t), testConfig(o365activityclient.ContentExchange))

	if err := c.Collect(context.Background(), base, base.Add(3*time.Hour), rc.Emitter()); err != nil {
		t.Fatalf("Collect: %v", err)
	}

	got := bodies(rc.LogRecords())
	want := []string{"r1", "r2", "r3"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("emitted bodies = %v, want %v", got, want)
	}
}

// TestCollectDedupesByContentID pins BLOB-level dedupe: a blob the overlap
// window re-lists on a later tick is not fetched again and its records are not
// re-emitted.
//
// It asserts the FETCH count, not just the emit count. That is the property
// unique to contentId dedupe — if only emissions were asserted, an
// implementation that dropped blob dedupe entirely would still pass on the
// strength of record-Id dedupe, and the wasted fetch (the whole point of
// checkpointing contentIds) would go unnoticed.
func TestCollectDedupesByContentID(t *testing.T) {
	base := testBase()
	api := newFakeAPI(t, blobSpec{
		contentType: o365activityclient.ContentExchange,
		contentID:   "blob-1",
		created:     base.Add(1 * time.Hour),
		records:     []map[string]any{rec("r1", base.Add(50*time.Minute)), rec("r2", base.Add(55*time.Minute))},
	})

	store := newStore(t)
	client := api.client(t)
	cfg := testConfig(o365activityclient.ContentExchange)

	// Two ticks over an overlapping window: the second re-lists the same blob.
	for i := range 2 {
		rc := telemetrytest.New()
		c := New(client, store, cfg)
		if err := c.Collect(context.Background(), base, base.Add(3*time.Hour), rc.Emitter()); err != nil {
			t.Fatalf("Collect %d: %v", i, err)
		}
		if i == 1 {
			if got := bodies(rc.LogRecords()); len(got) != 0 {
				t.Errorf("second tick re-emitted %v, want nothing (blob already consumed)", got)
			}
		}
	}

	if got := api.recordedFetches(); !reflect.DeepEqual(got, []string{"blob-1"}) {
		t.Errorf("fetches = %v, want blob-1 fetched exactly once — a re-listed blob must not be re-fetched", got)
	}
}

// TestCollectDedupesByRecordID pins RECORD-level dedupe, the defense contentId
// dedupe structurally cannot provide: the same record arriving inside two
// DIFFERENT blobs, which is explicitly allowed ("one content blob can contain
// actions and events that occurred prior to an earlier content blob").
//
// Both blobs are new, so both are fetched — asserted, so this test cannot pass
// by accident on blob dedupe. The shared record must still emit exactly once.
func TestCollectDedupesByRecordID(t *testing.T) {
	base := testBase()
	shared := rec("shared", base.Add(30*time.Minute))
	api := newFakeAPI(t,
		blobSpec{
			contentType: o365activityclient.ContentExchange,
			contentID:   "blob-1",
			created:     base.Add(1 * time.Hour),
			records:     []map[string]any{shared, rec("only-1", base.Add(40*time.Minute))},
		},
		blobSpec{
			contentType: o365activityclient.ContentExchange,
			contentID:   "blob-2",
			created:     base.Add(2 * time.Hour),
			records:     []map[string]any{shared, rec("only-2", base.Add(80*time.Minute))},
		},
	)

	rc := telemetrytest.New()
	c := New(api.client(t), newStore(t), testConfig(o365activityclient.ContentExchange))
	if err := c.Collect(context.Background(), base, base.Add(3*time.Hour), rc.Emitter()); err != nil {
		t.Fatalf("Collect: %v", err)
	}

	if got := api.recordedFetches(); len(got) != 2 {
		t.Fatalf("fetches = %v, want both blobs fetched — this test must exercise record dedupe, not blob dedupe", got)
	}
	got := bodies(rc.LogRecords())
	want := []string{"shared", "only-1", "only-2"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("emitted bodies = %v, want %v — a record in two blobs must emit once", got, want)
	}
}

// TestCollectAdvancesWatermarkToMaxProcessedNotTo pins the watermark to the
// newest blob actually consumed.
//
// It asserts EQUALITY with that blob's contentCreated rather than merely
// "before to". A weaker assertion would still pass for an implementation that
// advanced to `to` minus any constant — and advancing past what was actually
// consumed is exactly how a later tick silently skips data.
func TestCollectAdvancesWatermarkToMaxProcessedNotTo(t *testing.T) {
	base := testBase()
	newest := base.Add(2 * time.Hour)
	to := base.Add(5 * time.Hour)
	api := newFakeAPI(t,
		blobSpec{
			contentType: o365activityclient.ContentExchange,
			contentID:   "blob-1",
			created:     base.Add(1 * time.Hour),
			records:     []map[string]any{rec("r1", base.Add(50*time.Minute))},
		},
		blobSpec{
			contentType: o365activityclient.ContentExchange,
			contentID:   "blob-2",
			created:     newest,
			records:     []map[string]any{rec("r2", base.Add(110*time.Minute))},
		},
	)

	store := newStore(t)
	rc := telemetrytest.New()
	c := New(api.client(t), store, testConfig(o365activityclient.ContentExchange))
	if err := c.Collect(context.Background(), base, to, rc.Emitter()); err != nil {
		t.Fatalf("Collect: %v", err)
	}

	cp, err := store.Load(testTenantID, "o365/activity")
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if !cp.Watermark.Equal(newest) {
		t.Errorf("watermark = %s, want %s (the newest blob consumed); `to` was %s",
			cp.Watermark.Format(time.RFC3339Nano), newest.Format(time.RFC3339Nano), to.Format(time.RFC3339Nano))
	}
}

// TestCollectBoundsSeenSetsByOverlapWindow pins R4: both id sets are evicted to
// the overlap window rather than growing forever.
//
// It asserts BOTH directions — stale ids gone AND fresh ids retained. Asserting
// only that the stale ids were dropped would pass just as happily for an
// implementation that cleared the whole set, which would re-emit every record
// in the overlap window on the next tick.
func TestCollectBoundsSeenSetsByOverlapWindow(t *testing.T) {
	base := testBase()
	// Watermark lands on the newest blob (base+5h), so the eviction horizon is
	// base+3h. blob-old at base+1h falls outside it; blob-new at base+5h does not.
	api := newFakeAPI(t,
		blobSpec{
			contentType: o365activityclient.ContentExchange,
			contentID:   "blob-old",
			created:     base.Add(1 * time.Hour),
			records:     []map[string]any{rec("r-old", base.Add(50*time.Minute))},
		},
		blobSpec{
			contentType: o365activityclient.ContentExchange,
			contentID:   "blob-new",
			created:     base.Add(5 * time.Hour),
			records:     []map[string]any{rec("r-new", base.Add(290*time.Minute))},
		},
	)

	store := newStore(t)
	rc := telemetrytest.New()
	c := New(api.client(t), store, testConfig(o365activityclient.ContentExchange))
	if err := c.Collect(context.Background(), base, base.Add(6*time.Hour), rc.Emitter()); err != nil {
		t.Fatalf("Collect: %v", err)
	}

	cp, err := store.Load(testTenantID, "o365/activity")
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	horizon := cp.Watermark.Add(-DefaultOverlap)

	for _, id := range []string{"content:blob-old", "record:r-old"} {
		if cp.SeenIDs.Has(id) {
			t.Errorf("%q is still in the checkpoint; it predates the overlap horizon %s and must be evicted "+
				"(an unbounded set is the #138 failure)", id, horizon.Format(time.RFC3339))
		}
	}
	for _, id := range []string{"content:blob-new", "record:r-new"} {
		if !cp.SeenIDs.Has(id) {
			t.Errorf("%q was evicted but is INSIDE the overlap window (horizon %s); the next tick will re-emit it",
				id, horizon.Format(time.RFC3339))
		}
	}
}

// TestRecordIDsEvictedOnBlobTimeNotEventTime pins the subtlety that makes R4
// correct rather than merely bounded: a record id is retained on its BLOB's
// contentCreated, never on the record's own event time.
//
// Records can be far older than the blob carrying them. Keying eviction on
// event time would evict this record's id immediately — its event time is well
// outside the overlap window — while its blob is still inside that window and
// still re-listable, so the next tick would re-emit it. The observable here is
// that second tick: a NEW blob (so blob dedupe cannot help) re-delivers the same
// ancient record, and it must not emit twice.
func TestRecordIDsEvictedOnBlobTimeNotEventTime(t *testing.T) {
	base := testBase()
	// Event time is 5 hours before the blob that carries it — far outside the
	// 2h overlap window, but the blob itself is recent.
	ancient := rec("ancient", base.Add(-4*time.Hour))
	api := newFakeAPI(t,
		blobSpec{
			contentType: o365activityclient.ContentExchange,
			contentID:   "blob-1",
			created:     base.Add(1 * time.Hour),
			records:     []map[string]any{ancient},
		},
	)

	store := newStore(t)
	client := api.client(t)
	cfg := testConfig(o365activityclient.ContentExchange)

	rc1 := telemetrytest.New()
	if err := New(client, store, cfg).Collect(context.Background(), base, base.Add(2*time.Hour), rc1.Emitter()); err != nil {
		t.Fatalf("Collect 1: %v", err)
	}
	if got := bodies(rc1.LogRecords()); !reflect.DeepEqual(got, []string{"ancient"}) {
		t.Fatalf("first tick emitted %v, want [ancient]", got)
	}

	cp, err := store.Load(testTenantID, "o365/activity")
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if !cp.SeenIDs.Has("record:ancient") {
		t.Fatal("record:ancient was evicted after one tick — its id was bound to its EVENT time, " +
			"but its blob is inside the overlap window and will be re-listed")
	}

	// A DIFFERENT blob re-delivers the same record, so only record-Id dedupe can
	// suppress it.
	api.mu.Lock()
	api.blobs = append(api.blobs, blobSpec{
		contentType: o365activityclient.ContentExchange,
		contentID:   "blob-2",
		created:     base.Add(90 * time.Minute),
		records:     []map[string]any{ancient},
	})
	api.mu.Unlock()

	rc2 := telemetrytest.New()
	if err := New(client, store, cfg).Collect(context.Background(), base, base.Add(2*time.Hour), rc2.Emitter()); err != nil {
		t.Fatalf("Collect 2: %v", err)
	}
	if got := bodies(rc2.LogRecords()); len(got) != 0 {
		t.Errorf("second tick emitted %v, want nothing — the ancient record was already shipped", got)
	}
}

// TestCollectStartsSubscriptionsLazilyOncePerContentType pins the WRITE: every
// configured content type is subscribed on the first Collect, and not again on
// later ticks.
func TestCollectStartsSubscriptionsLazilyOncePerContentType(t *testing.T) {
	base := testBase()
	api := newFakeAPI(t)

	if got := api.recordedStarts(); len(got) != 0 {
		t.Fatalf("constructing the fake already started %v; the write must not happen before Collect", got)
	}

	client := api.client(t)
	cfg := testConfig(o365activityclient.ContentExchange, o365activityclient.ContentSharePoint)
	c := New(client, newStore(t), cfg)

	rc := telemetrytest.New()
	if err := c.Collect(context.Background(), base, base.Add(2*time.Hour), rc.Emitter()); err != nil {
		t.Fatalf("Collect 1: %v", err)
	}
	want := []string{"Audit.Exchange", "Audit.SharePoint"}
	if got := api.recordedStarts(); !reflect.DeepEqual(got, want) {
		t.Fatalf("starts after first Collect = %v, want %v", got, want)
	}

	if err := c.Collect(context.Background(), base, base.Add(2*time.Hour), rc.Emitter()); err != nil {
		t.Fatalf("Collect 2: %v", err)
	}
	if got := api.recordedStarts(); !reflect.DeepEqual(got, want) {
		t.Errorf("starts after second Collect = %v, want the same %v — the start is a WRITE and must not repeat per tick", got, want)
	}
}

// TestCollectRestartsSubscriptionAfterNoSubscription pins recovery from
// AF20022, the state an admin stopping the subscription leaves behind: start it
// again and retry the listing once, rather than failing the tick forever.
func TestCollectRestartsSubscriptionAfterNoSubscription(t *testing.T) {
	base := testBase()
	api := newFakeAPI(t, blobSpec{
		contentType: o365activityclient.ContentExchange,
		contentID:   "blob-1",
		created:     base.Add(1 * time.Hour),
		records:     []map[string]any{rec("r1", base.Add(50*time.Minute))},
	})

	client := api.client(t)
	cfg := testConfig(o365activityclient.ContentExchange)
	c := New(client, newStore(t), cfg)

	// First tick subscribes and drains normally.
	rc := telemetrytest.New()
	if err := c.Collect(context.Background(), base, base.Add(2*time.Hour), rc.Emitter()); err != nil {
		t.Fatalf("Collect 1: %v", err)
	}

	// An admin stops the subscription behind our back: listing now returns AF20022.
	api.blockSubscription(o365activityclient.ContentExchange)

	rc2 := telemetrytest.New()
	if err := c.Collect(context.Background(), base, base.Add(2*time.Hour), rc2.Emitter()); err != nil {
		t.Fatalf("Collect 2 should recover from AF20022, got: %v", err)
	}
	if got := api.recordedStarts(); len(got) != 2 {
		t.Errorf("starts = %v, want the subscription restarted after AF20022", got)
	}
}

// TestCollectSkipsExpiredBlob pins AF20051 handling: a blob that aged out
// between being listed and being fetched is a normal race. It is skipped, the
// tick still succeeds, and the rest of the window still ships.
func TestCollectSkipsExpiredBlob(t *testing.T) {
	base := testBase()
	api := newFakeAPI(t,
		blobSpec{
			contentType: o365activityclient.ContentExchange,
			contentID:   "blob-gone",
			created:     base.Add(1 * time.Hour),
			errCode:     o365activityclient.CodeContentExpired,
		},
		blobSpec{
			contentType: o365activityclient.ContentExchange,
			contentID:   "blob-ok",
			created:     base.Add(2 * time.Hour),
			records:     []map[string]any{rec("r1", base.Add(110*time.Minute))},
		},
	)

	rc := telemetrytest.New()
	c := New(api.client(t), newStore(t), testConfig(o365activityclient.ContentExchange))
	if err := c.Collect(context.Background(), base, base.Add(3*time.Hour), rc.Emitter()); err != nil {
		t.Fatalf("an expired blob must not fail the tick, got: %v", err)
	}
	if got := bodies(rc.LogRecords()); !reflect.DeepEqual(got, []string{"r1"}) {
		t.Errorf("emitted %v, want [r1] — the surviving blob must still ship", got)
	}
}

// TestCollectSurfacesThrottling pins that AF429 is NOT swallowed. CLAUDE.md is
// emphatic that a blanket status swallow is how a real bug hides: only the
// specific, documented, terminal conditions are absorbed.
//
// This test is deliberately slow (~5s): 429 is retryable, the client's retry
// transport cannot be disabled from outside its package, and serving a fake
// non-429 status alongside an AF429 body would test a wire shape that does not
// exist. Paying the real backoff once is worth more than a fiction that runs
// fast. It is the ONLY test here that serves a retryable status.
func TestCollectSurfacesThrottling(t *testing.T) {
	t.Parallel()

	base := testBase()
	api := newFakeAPI(t, blobSpec{
		contentType: o365activityclient.ContentExchange,
		contentID:   "blob-429",
		created:     base.Add(1 * time.Hour),
		errCode:     o365activityclient.CodeTooManyRequests,
		errStatus:   http.StatusTooManyRequests,
	})

	rc := telemetrytest.New()
	c := New(api.client(t), newStore(t), testConfig(o365activityclient.ContentExchange))
	err := c.Collect(context.Background(), base, base.Add(2*time.Hour), rc.Emitter())
	if err == nil {
		t.Fatal("Collect swallowed a throttle; it must surface")
	}
	if !o365activityclient.IsThrottled(err) {
		t.Errorf("error %v does not satisfy IsThrottled — the typed AF code must survive wrapping", err)
	}
}

// TestCollectSurfacesAMalformedRequestError pins the other half of "never
// blanket-swallow a status": AF20052 is a 400, exactly like the expired-content
// and no-subscription conditions that ARE absorbed, but it signals a real bug
// and must reach the caller. Swallowing every 400 is the trap CLAUDE.md names.
func TestCollectSurfacesAMalformedRequestError(t *testing.T) {
	base := testBase()
	api := newFakeAPI(t, blobSpec{
		contentType: o365activityclient.ContentExchange,
		contentID:   "blob-bad",
		created:     base.Add(1 * time.Hour),
		errCode:     o365activityclient.CodeInvalidContentID,
		errStatus:   http.StatusBadRequest,
	})

	rc := telemetrytest.New()
	c := New(api.client(t), newStore(t), testConfig(o365activityclient.ContentExchange))
	err := c.Collect(context.Background(), base, base.Add(2*time.Hour), rc.Emitter())
	if err == nil {
		t.Fatal("Collect swallowed AF20052; a malformed-request 400 must surface")
	}
	if !o365activityclient.HasCode(err, o365activityclient.CodeInvalidContentID) {
		t.Errorf("error %v lost its AF code through wrapping", err)
	}
}

// TestCollectDoesNotAdvanceWatermarkPastAnotherTypesFailedBlob pins the
// invariant that everything at or below the watermark has actually been
// consumed, ACROSS content types.
//
// The cross-type case is the only one where the guard can bite, and getting the
// test wrong here is easy: within a single content type the drain stops at the
// first failure, so nothing past the failed blob is ever consumed and the
// invariant holds for free — a same-type test passes with the guard deleted and
// proves nothing. Content types share one watermark but are drained
// independently, so Exchange failing at base+1h while SharePoint succeeds at
// base+2h is a real partial failure (and the plan's default config subscribes to
// exactly those two). A watermark of base+2h would slide past the Exchange blob
// and skip it forever once the overlap window moved on.
func TestCollectDoesNotAdvanceWatermarkPastAnotherTypesFailedBlob(t *testing.T) {
	base := testBase()
	failedAt := base.Add(1 * time.Hour)
	api := newFakeAPI(t,
		blobSpec{
			contentType: o365activityclient.ContentExchange,
			contentID:   "blob-bad",
			created:     failedAt,
			errCode:     o365activityclient.CodeInvalidContentID,
			errStatus:   http.StatusBadRequest,
		},
		blobSpec{
			contentType: o365activityclient.ContentSharePoint,
			contentID:   "blob-sp",
			created:     base.Add(2 * time.Hour),
			records:     []map[string]any{rec("r-sp", base.Add(110*time.Minute))},
		},
	)

	store := newStore(t)
	rc := telemetrytest.New()
	c := New(api.client(t), store, testConfig(o365activityclient.ContentExchange, o365activityclient.ContentSharePoint))
	if err := c.Collect(context.Background(), base, base.Add(3*time.Hour), rc.Emitter()); err == nil {
		t.Fatal("Collect must surface the fetch failure")
	}
	// The healthy content type still ships: one type's failure must not gate another's.
	if got := bodies(rc.LogRecords()); !reflect.DeepEqual(got, []string{"r-sp"}) {
		t.Errorf("emitted %v, want [r-sp] — a failing content type must not block a healthy one", got)
	}

	cp, err := store.Load(testTenantID, "o365/activity")
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if !cp.Watermark.Before(failedAt) {
		t.Errorf("watermark = %s, want strictly before the failed blob at %s — otherwise that blob is skipped forever",
			cp.Watermark.Format(time.RFC3339Nano), failedAt.Format(time.RFC3339Nano))
	}
}

// TestCollectEmitsEveryRecordTheMapperAccepts pins #112: the engine ships what
// the mapper yields and filters nothing of its own. Only the mapper's explicit
// ok=false drops a record.
func TestCollectEmitsEveryRecordTheMapperAccepts(t *testing.T) {
	base := testBase()
	api := newFakeAPI(t, blobSpec{
		contentType: o365activityclient.ContentExchange,
		contentID:   "blob-1",
		created:     base.Add(1 * time.Hour),
		records: []map[string]any{
			rec("keep-1", base.Add(50*time.Minute)),
			rec("drop", base.Add(51*time.Minute)),
			rec("keep-2", base.Add(52*time.Minute)),
		},
	})

	cfg := testConfig(o365activityclient.ContentExchange)
	cfg.Map = func(r map[string]any) (string, telemetry.Event, bool) {
		id, ev, _ := mapAll(r)
		return id, ev, id != "drop"
	}

	rc := telemetrytest.New()
	if err := New(api.client(t), newStore(t), cfg).Collect(
		context.Background(), base, base.Add(2*time.Hour), rc.Emitter()); err != nil {
		t.Fatalf("Collect: %v", err)
	}
	if got := bodies(rc.LogRecords()); !reflect.DeepEqual(got, []string{"keep-1", "keep-2"}) {
		t.Errorf("emitted %v, want [keep-1 keep-2]", got)
	}
}

// TestRecordsWithEmptyIDAreEmittedAndDoNotPoisonTheSeenSet pins the empty-id
// contract: an id-less record is UNDEDUPEABLE, not unusable, so it ships (#112).
// Dropping it would put a per-entity row into no pipeline at all.
//
// The second assertion is the one that matters, and it guards a real trap rather
// than a hypothetical. The engine guards BOTH dedupe branches on `id != ""`. Drop
// those guards and the first id-less record writes the bare key "record:" into
// the seen set, which then matches EVERY later id-less record — so record two
// onward vanish silently, forever, across every blob and every tick. Two id-less
// records in one blob is the cheapest fixture that catches it.
func TestRecordsWithEmptyIDAreEmittedAndDoNotPoisonTheSeenSet(t *testing.T) {
	base := testBase()
	api := newFakeAPI(t, blobSpec{
		contentType: o365activityclient.ContentExchange,
		contentID:   "blob-1",
		created:     base.Add(1 * time.Hour),
		records: []map[string]any{
			rec("has-id", base.Add(50*time.Minute)),
			rec("", base.Add(51*time.Minute)),
			rec("", base.Add(52*time.Minute)),
		},
	})

	cfg := testConfig(o365activityclient.ContentExchange)
	// Distinguish the two id-less records in the emitted output: mapAll uses the
	// id as the Body, which would make both empty and indistinguishable.
	cfg.Map = func(r map[string]any) (string, telemetry.Event, bool) {
		id, ev, ok := mapAll(r)
		if id == "" {
			ev.Body = "anon@" + r["CreationTime"].(string)
		}
		return id, ev, ok
	}

	store := newStore(t)
	rc := telemetrytest.New()
	if err := New(api.client(t), store, cfg).Collect(
		context.Background(), base, base.Add(2*time.Hour), rc.Emitter()); err != nil {
		t.Fatalf("Collect: %v", err)
	}

	want := []string{
		"has-id",
		"anon@" + base.Add(51*time.Minute).UTC().Format(recordTimeFormat),
		"anon@" + base.Add(52*time.Minute).UTC().Format(recordTimeFormat),
	}
	if got := bodies(rc.LogRecords()); !reflect.DeepEqual(got, want) {
		t.Errorf("emitted %v, want %v — an id-less record is undedupeable, not undesirable; "+
			"losing the second one means the empty id poisoned the seen set", got, want)
	}

	cp, err := store.Load(testTenantID, "o365/activity")
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cp.SeenIDs.Has(recordIDPrefix) {
		t.Errorf("the bare key %q was written to the seen set; it matches every future id-less "+
			"record and would silently drop all of them", recordIDPrefix)
	}
}

// TestCollectAppliesEventNameDefault pins that EndpointConfig.EventName fills in
// only where the mapper left Name empty, never overriding a mapper's choice.
func TestCollectAppliesEventNameDefault(t *testing.T) {
	base := testBase()
	api := newFakeAPI(t, blobSpec{
		contentType: o365activityclient.ContentExchange,
		contentID:   "blob-1",
		created:     base.Add(1 * time.Hour),
		records:     []map[string]any{rec("default", base.Add(50*time.Minute)), rec("explicit", base.Add(51*time.Minute))},
	})

	cfg := testConfig(o365activityclient.ContentExchange)
	cfg.Map = func(r map[string]any) (string, telemetry.Event, bool) {
		id, ev, ok := mapAll(r)
		if id == "explicit" {
			ev.Name = "m365.custom"
		}
		return id, ev, ok
	}

	rc := telemetrytest.New()
	if err := New(api.client(t), newStore(t), cfg).Collect(
		context.Background(), base, base.Add(2*time.Hour), rc.Emitter()); err != nil {
		t.Fatalf("Collect: %v", err)
	}

	got := map[string]string{}
	for _, r := range rc.LogRecords() {
		got[r.Body] = r.EventName
	}
	want := map[string]string{"default": "m365.audit", "explicit": "m365.custom"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("event names = %v, want %v", got, want)
	}
}

// TestCollectResumesFromWatermarkMinusOverlap pins that a warm start re-lists
// the overlap window rather than trusting the caller's `from`. In steady state
// the caller's from is roughly the last watermark, so honoring it would collapse
// the overlap to nothing and lose every late-arriving blob.
func TestCollectResumesFromWatermarkMinusOverlap(t *testing.T) {
	base := testBase()
	store := newStore(t)
	api := newFakeAPI(t, blobSpec{
		contentType: o365activityclient.ContentExchange,
		contentID:   "blob-1",
		created:     base.Add(4 * time.Hour),
		records:     []map[string]any{rec("r1", base.Add(230*time.Minute))},
	})

	client := api.client(t)
	cfg := testConfig(o365activityclient.ContentExchange)
	rc := telemetrytest.New()
	if err := New(client, store, cfg).Collect(context.Background(), base, base.Add(5*time.Hour), rc.Emitter()); err != nil {
		t.Fatalf("Collect 1: %v", err)
	}
	cp, err := store.Load(testTenantID, "o365/activity")
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	wantWatermark := base.Add(4 * time.Hour)
	if !cp.Watermark.Equal(wantWatermark) {
		t.Fatalf("watermark = %s, want %s", cp.Watermark, wantWatermark)
	}

	// Second tick: the caller passes a `from` at the watermark itself. The engine
	// must still reach back a full overlap window behind it.
	rc2 := telemetrytest.New()
	if err := New(client, store, cfg).Collect(context.Background(), cp.Watermark, base.Add(5*time.Hour), rc2.Emitter()); err != nil {
		t.Fatalf("Collect 2: %v", err)
	}

	last := api.lastListRange()
	wantStart := wantWatermark.Add(-DefaultOverlap).UTC().Format(apiTimeFormat)
	if last[0] != wantStart {
		t.Errorf("second tick listed from %q, want %q (watermark - %s)", last[0], wantStart, DefaultOverlap)
	}
}

// TestColdStartUsesCallerFromVerbatim pins that a cold start honors the
// scheduler's `from` exactly, inventing no window of its own.
//
// The scheduler already derived `from` from the collector's declared
// InitialLookback (collector.nextWindow). The engine holding its own lookback is
// the duplication this seam deliberately does not have: the two could disagree,
// and the engine would win silently.
func TestColdStartUsesCallerFromVerbatim(t *testing.T) {
	base := testBase()
	api := newFakeAPI(t)
	from := base.Add(90 * time.Minute)

	rc := telemetrytest.New()
	if err := New(api.client(t), newStore(t), testConfig(o365activityclient.ContentExchange)).Collect(
		context.Background(), from, base.Add(5*time.Hour), rc.Emitter()); err != nil {
		t.Fatalf("Collect: %v", err)
	}

	got := api.lastListRange()
	want := from.UTC().Format(apiTimeFormat)
	if got[0] != want {
		t.Errorf("cold start listed from %q, want the caller's from %q verbatim", got[0], want)
	}
}

// TestCheckpointSchemaTolerance pins that a checkpoint written by another
// version still loads: an unknown field is ignored (forward) and a missing one
// falls back (backward), mirroring what internal/checkpoint already guarantees.
func TestCheckpointSchemaTolerance(t *testing.T) {
	base := testBase()
	dir := t.TempDir()
	store := checkpoint.NewStore(dir)

	// A file from a FUTURE version: extra unknown field, and no seen_ids at all.
	seeded := &checkpoint.Checkpoint{
		Schema:        1,
		TenantID:      testTenantID,
		Endpoint:      "o365/activity",
		Watermark:     base.Add(1 * time.Hour),
		OverlapWindow: DefaultOverlap,
	}
	if err := store.Save(seeded); err != nil {
		t.Fatalf("Save: %v", err)
	}
	path := filepath.Join(dir, mustOnlyFile(t, dir))
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	var doc map[string]any
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	doc["some_future_field"] = "from a newer binary"
	delete(doc, "seen_ids")
	patched, err := json.Marshal(doc)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	if err := os.WriteFile(path, patched, 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	api := newFakeAPI(t, blobSpec{
		contentType: o365activityclient.ContentExchange,
		contentID:   "blob-1",
		created:     base.Add(2 * time.Hour),
		records:     []map[string]any{rec("r1", base.Add(110*time.Minute))},
	})
	rc := telemetrytest.New()
	c := New(api.client(t), store, testConfig(o365activityclient.ContentExchange))
	if err := c.Collect(context.Background(), base, base.Add(3*time.Hour), rc.Emitter()); err != nil {
		t.Fatalf("Collect over a foreign-schema checkpoint: %v", err)
	}
	if got := bodies(rc.LogRecords()); !reflect.DeepEqual(got, []string{"r1"}) {
		t.Errorf("emitted %v, want [r1]", got)
	}
}

func mustOnlyFile(t *testing.T, dir string) string {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("ReadDir: %v", err)
	}
	for _, e := range entries {
		if strings.HasSuffix(e.Name(), ".json") {
			return e.Name()
		}
	}
	t.Fatalf("no checkpoint file in %s", dir)
	return ""
}
