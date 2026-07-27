package servicehealth

import (
	"context"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/rknightion/graph2otel/internal/checkpoint"
	"github.com/rknightion/graph2otel/internal/recordoutcome"
	"github.com/rknightion/graph2otel/internal/semconv"
	"github.com/rknightion/graph2otel/internal/telemetrytest"
)

// postsFixture is a healthOverviews?$expand=issues response shaped after the
// LIVE-MEASURED wire (2026-07-27, #367, probed as graph2otel-poller against
// m7kni): exactly three keys on a post object (createdDateTime, description,
// postType), description.content is HTML, both postType values ("regular"
// and "quick") appear on the tenant. posts carries the args so each test can
// vary the post set without duplicating the issue scaffolding.
func postsFixture(posts string) string {
	return `{"value":[
	  {
	    "id": "Exchange",
	    "service": "Exchange Online",
	    "status": "serviceDegradation",
	    "issues": [
	      {
	        "id": "EX123", "title": "Mailbox access degraded",
	        "classification": "incident", "status": "serviceDegradation",
	        "service": "Exchange Online", "isResolved": false,
	        "startDateTime": "2026-07-18T09:00:00Z", "endDateTime": null,
	        "lastModifiedDateTime": "2026-07-18T14:00:00Z",
	        "posts": [` + posts + `]
	      }
	    ]
	  }
	]}`
}

func newPostsCollector(t *testing.T, g *fakeGraph, store *checkpoint.Store, tenantID string) *Collector {
	t.Helper()
	return New(g, store, tenantID, nil)
}

func newTestStore(t *testing.T) *checkpoint.Store {
	t.Helper()
	return checkpoint.NewStore(t.TempDir())
}

func postEvents(rec *telemetrytest.Recorder) []telemetrytest.LogRecord {
	var out []telemetrytest.LogRecord
	for _, l := range rec.LogRecords() {
		if l.EventName == eventPost {
			out = append(out, l)
		}
	}
	return out
}

// TestFirstRunPrimesServiceHealthPostsWithoutEmitting pins the priming
// requirement (#367): a cold start over 829 historical posts must not emit
// any of them (most are older than the backend's 7-day accept window and
// would either be silently discarded by the horizon guard or loudly
// rejected), it must only record the watermark.
func TestFirstRunPrimesServiceHealthPostsWithoutEmitting(t *testing.T) {
	body := postsFixture(`
	  {"createdDateTime": "2026-02-01T10:00:00Z", "postType": "regular",
	   "description": {"content": "<p>Old post from February.</p>", "contentType": "html"}},
	  {"createdDateTime": "2026-02-02T11:00:00Z", "postType": "quick",
	   "description": {"content": "<p>Another old post.</p>", "contentType": "html"}}
	`)
	g := &fakeGraph{bodies: map[string]string{overviewsURL: body}}
	store := newTestStore(t)
	rec := telemetrytest.New()

	if err := newPostsCollector(t, g, store, "tenant-a").Collect(context.Background(), rec.Emitter(), recordoutcome.NewRecorder()); err != nil {
		t.Fatalf("Collect: %v", err)
	}

	if got := postEvents(rec); len(got) != 0 {
		t.Fatalf("first run emitted %d service_health_post events, want 0 (priming must emit nothing)", len(got))
	}

	cp, err := store.Load("tenant-a", postsEndpoint)
	if err != nil {
		t.Fatalf("Load checkpoint: %v", err)
	}
	if cp.Watermark.IsZero() {
		t.Fatal("priming must record a non-zero watermark")
	}
	want := time.Date(2026, 2, 2, 11, 0, 0, 0, time.UTC)
	if !cp.Watermark.Equal(want) {
		t.Errorf("primed watermark = %v, want %v (the newest of the two posts)", cp.Watermark, want)
	}
}

// TestNewPostAfterPrimingEmitsPromptly is acceptance criterion 2: a new post
// on an issue that already has history must not be masked by the issue
// itself being otherwise unchanged.
func TestNewPostAfterPrimingEmitsPromptly(t *testing.T) {
	store := newTestStore(t)
	oldBody := postsFixture(`
	  {"createdDateTime": "2026-02-01T10:00:00Z", "postType": "regular",
	   "description": {"content": "<p>Old post.</p>", "contentType": "html"}}
	`)
	g1 := &fakeGraph{bodies: map[string]string{overviewsURL: oldBody}}
	if err := newPostsCollector(t, g1, store, "tenant-a").Collect(context.Background(), telemetrytest.New().Emitter(), recordoutcome.NewRecorder()); err != nil {
		t.Fatalf("priming Collect: %v", err)
	}

	newBody := postsFixture(`
	  {"createdDateTime": "2026-02-01T10:00:00Z", "postType": "regular",
	   "description": {"content": "<p>Old post.</p>", "contentType": "html"}},
	  {"createdDateTime": "2026-07-27T08:30:00Z", "postType": "regular",
	   "description": {"content": "<p>Brand new update.</p>", "contentType": "html"}}
	`)
	g2 := &fakeGraph{bodies: map[string]string{overviewsURL: newBody}}
	rec := telemetrytest.New()
	// A FRESH Collector instance over the SAME checkpoint dir/tenant: this is
	// the cold-restart case, where naive in-memory dedupe would fail.
	if err := newPostsCollector(t, g2, store, "tenant-a").Collect(context.Background(), rec.Emitter(), recordoutcome.NewRecorder()); err != nil {
		t.Fatalf("second Collect: %v", err)
	}

	got := postEvents(rec)
	if len(got) != 1 {
		t.Fatalf("second run emitted %d service_health_post events, want 1 (only the brand-new post)", len(got))
	}
	l := got[0]
	if l.Attrs[semconv.AttrIssueId] != "EX123" {
		t.Errorf("issue_id = %q, want EX123", l.Attrs[semconv.AttrIssueId])
	}
	if l.Attrs[semconv.AttrPostType] != "regular" {
		t.Errorf("post_type = %q, want regular", l.Attrs[semconv.AttrPostType])
	}
	want := time.Date(2026, 7, 27, 8, 30, 0, 0, time.UTC)
	if !l.Timestamp.Equal(want) {
		t.Errorf("timestamp = %v, want %v (the post's own createdDateTime, never arrival time)", l.Timestamp, want)
	}
}

// TestSamePostNeverReemitsAcrossRestarts is acceptance criterion 1, proven
// specifically across a process restart (fresh Collector, same checkpoint
// dir) — the case naive in-memory dedupe cannot survive.
func TestSamePostNeverReemitsAcrossRestarts(t *testing.T) {
	store := newTestStore(t)
	body := postsFixture(`
	  {"createdDateTime": "2026-02-01T10:00:00Z", "postType": "regular",
	   "description": {"content": "<p>Old post.</p>", "contentType": "html"}},
	  {"createdDateTime": "2026-07-27T08:30:00Z", "postType": "regular",
	   "description": {"content": "<p>Brand new update.</p>", "contentType": "html"}}
	`)
	g := &fakeGraph{bodies: map[string]string{overviewsURL: body}}

	// Run 1: primes (the Feb + the "new" post are both in the initial history).
	if err := newPostsCollector(t, g, store, "tenant-a").Collect(context.Background(), telemetrytest.New().Emitter(), recordoutcome.NewRecorder()); err != nil {
		t.Fatalf("run 1 (prime): %v", err)
	}

	// Run 2, 3, 4: fresh Collector instances each time (simulating a restart
	// between every poll), same unchanged fixture repeated. Must never emit.
	for i := 2; i <= 4; i++ {
		rec := telemetrytest.New()
		if err := newPostsCollector(t, g, store, "tenant-a").Collect(context.Background(), rec.Emitter(), recordoutcome.NewRecorder()); err != nil {
			t.Fatalf("run %d: %v", i, err)
		}
		if got := postEvents(rec); len(got) != 0 {
			t.Fatalf("run %d (fresh collector, same checkpoint dir) emitted %d events, want 0 (already primed)", i, len(got))
		}
	}
}

// TestPostWithUnparseableCreatedDateTimeIsDroppedAndCounted pins the
// never-stamp-arrival-time rule: a post whose event time cannot be
// determined must be dropped, not emitted with a fabricated "now" timestamp,
// and the drop must be counted on the bounded outcome recorder so it is
// alertable.
func TestPostWithUnparseableCreatedDateTimeIsDroppedAndCounted(t *testing.T) {
	store := newTestStore(t)
	// Prime on an empty set first so the second run is past the priming gate.
	empty := postsFixture(``)
	g0 := &fakeGraph{bodies: map[string]string{overviewsURL: empty}}
	if err := newPostsCollector(t, g0, store, "tenant-a").Collect(context.Background(), telemetrytest.New().Emitter(), recordoutcome.NewRecorder()); err != nil {
		t.Fatalf("priming run: %v", err)
	}

	body := postsFixture(`
	  {"createdDateTime": "", "postType": "regular",
	   "description": {"content": "<p>No timestamp.</p>", "contentType": "html"}},
	  {"createdDateTime": "2026-07-27T08:30:00Z", "postType": "regular",
	   "description": {"content": "<p>Valid post.</p>", "contentType": "html"}}
	`)
	g := &fakeGraph{bodies: map[string]string{overviewsURL: body}}
	rec := telemetrytest.New()
	outcomes := recordoutcome.NewRecorder()
	if err := newPostsCollector(t, g, store, "tenant-a").Collect(context.Background(), rec.Emitter(), outcomes); err != nil {
		t.Fatalf("Collect: %v", err)
	}

	got := postEvents(rec)
	if len(got) != 1 {
		t.Fatalf("emitted %d service_health_post events, want 1 (only the post with a parseable time)", len(got))
	}

	snap := outcomes.Snapshot()
	if snap.Counts.Dropped < 1 {
		t.Errorf("Dropped count = %d, want >= 1 (the unparseable-time post must be counted, not just logged)", snap.Counts.Dropped)
	}
	foundCause := false
	for _, c := range snap.Causes {
		if c == recordoutcome.CauseMissingEventTime {
			foundCause = true
		}
	}
	if !foundCause {
		t.Errorf("causes = %v, want CauseMissingEventTime present", snap.Causes)
	}
}

// TestPostBodyWithinCapIsCarriedRawAndUntruncated pins decision #1 (RAW HTML,
// no tag-stripping) and the untruncated half of decision #2.
func TestPostBodyWithinCapIsCarriedRawAndUntruncated(t *testing.T) {
	store := newTestStore(t)
	empty := postsFixture(``)
	g0 := &fakeGraph{bodies: map[string]string{overviewsURL: empty}}
	if err := newPostsCollector(t, g0, store, "tenant-a").Collect(context.Background(), telemetrytest.New().Emitter(), recordoutcome.NewRecorder()); err != nil {
		t.Fatalf("priming run: %v", err)
	}

	const rawHTML = `<p>Engineers have <strong>identified</strong> the root cause &amp; are deploying a fix.</p>`
	body := postsFixture(`
	  {"createdDateTime": "2026-07-27T08:30:00Z", "postType": "regular",
	   "description": {"content": ` + `"` + rawHTML + `"` + `, "contentType": "html"}}
	`)
	g := &fakeGraph{bodies: map[string]string{overviewsURL: body}}
	rec := telemetrytest.New()
	if err := newPostsCollector(t, g, store, "tenant-a").Collect(context.Background(), rec.Emitter(), recordoutcome.NewRecorder()); err != nil {
		t.Fatalf("Collect: %v", err)
	}

	got := postEvents(rec)
	if len(got) != 1 {
		t.Fatalf("emitted %d events, want 1", len(got))
	}
	l := got[0]
	if l.Attrs[semconv.AttrDescription] != rawHTML {
		t.Errorf("description = %q, want verbatim raw HTML %q (must not be tag-stripped)", l.Attrs[semconv.AttrDescription], rawHTML)
	}
	if l.Attrs[semconv.AttrContentType] != "html" {
		t.Errorf("content_type = %q, want html", l.Attrs[semconv.AttrContentType])
	}
	if l.Attrs[semconv.AttrBodyTruncated] != "false" {
		t.Errorf("body_truncated = %q, want false", l.Attrs[semconv.AttrBodyTruncated])
	}
	if _, present := l.Attrs[semconv.AttrDescriptionOriginalLength]; present {
		t.Errorf("description_original_length must be omitted when not truncated, got %v", l.Attrs[semconv.AttrDescriptionOriginalLength])
	}
}

// TestPostBodyExceedingCapIsTruncatedNotDropped pins decision #2: an
// oversized body degrades (truncate + flag), it is never dropped, because
// the post's identity/issue linkage/event time are all still correct.
func TestPostBodyExceedingCapIsTruncatedNotDropped(t *testing.T) {
	store := newTestStore(t)
	empty := postsFixture(``)
	g0 := &fakeGraph{bodies: map[string]string{overviewsURL: empty}}
	if err := newPostsCollector(t, g0, store, "tenant-a").Collect(context.Background(), telemetrytest.New().Emitter(), recordoutcome.NewRecorder()); err != nil {
		t.Fatalf("priming run: %v", err)
	}

	oversized := strings.Repeat("x", postBodyCapBytes+2000)
	body := postsFixture(`
	  {"createdDateTime": "2026-07-27T08:30:00Z", "postType": "regular",
	   "description": {"content": "` + oversized + `", "contentType": "html"}}
	`)
	g := &fakeGraph{bodies: map[string]string{overviewsURL: body}}
	rec := telemetrytest.New()
	if err := newPostsCollector(t, g, store, "tenant-a").Collect(context.Background(), rec.Emitter(), recordoutcome.NewRecorder()); err != nil {
		t.Fatalf("Collect: %v", err)
	}

	got := postEvents(rec)
	if len(got) != 1 {
		t.Fatalf("emitted %d events, want 1 (truncate, never drop)", len(got))
	}
	l := got[0]
	content := l.Attrs[semconv.AttrDescription]
	if len(content) > postBodyCapBytes {
		t.Errorf("emitted content is %d bytes, want <= %d (the cap)", len(content), postBodyCapBytes)
	}
	if l.Attrs[semconv.AttrBodyTruncated] != "true" {
		t.Errorf("body_truncated = %q, want true", l.Attrs[semconv.AttrBodyTruncated])
	}
	origLen, err := strconv.Atoi(l.Attrs[semconv.AttrDescriptionOriginalLength])
	if err != nil || origLen != len(oversized) {
		t.Errorf("description_original_length = %q, want %d", l.Attrs[semconv.AttrDescriptionOriginalLength], len(oversized))
	}
}

// TestPostDedupeKeyIncludesPostType pins the dedupe key composition: two
// posts sharing an issue and createdDateTime but differing in postType are
// distinct posts on the wire (there is no other field to distinguish them),
// so both must emit.
func TestPostDedupeKeyIncludesPostType(t *testing.T) {
	store := newTestStore(t)
	empty := postsFixture(``)
	g0 := &fakeGraph{bodies: map[string]string{overviewsURL: empty}}
	if err := newPostsCollector(t, g0, store, "tenant-a").Collect(context.Background(), telemetrytest.New().Emitter(), recordoutcome.NewRecorder()); err != nil {
		t.Fatalf("priming run: %v", err)
	}

	body := postsFixture(`
	  {"createdDateTime": "2026-07-27T08:30:00Z", "postType": "regular",
	   "description": {"content": "<p>Regular update.</p>", "contentType": "html"}},
	  {"createdDateTime": "2026-07-27T08:30:00Z", "postType": "quick",
	   "description": {"content": "<p>Quick update.</p>", "contentType": "html"}}
	`)
	g := &fakeGraph{bodies: map[string]string{overviewsURL: body}}
	rec := telemetrytest.New()
	if err := newPostsCollector(t, g, store, "tenant-a").Collect(context.Background(), rec.Emitter(), recordoutcome.NewRecorder()); err != nil {
		t.Fatalf("Collect: %v", err)
	}

	if got := postEvents(rec); len(got) != 2 {
		t.Fatalf("emitted %d events, want 2 (same createdDateTime, different postType is a distinct post)", len(got))
	}
}

// TestNoCheckpointStoreSkipsPostProcessing pins the "Store optional" contract
// every neighboring checkpointed collector follows (dlppolicies,
// epmelevationevents): a nil store must never dup-storm the backend, so it
// degrades to skipping post emission entirely rather than emitting
// unchecked. The existing gauge/twin behavior is unaffected.
func TestNoCheckpointStoreSkipsPostProcessing(t *testing.T) {
	body := postsFixture(`
	  {"createdDateTime": "2026-07-27T08:30:00Z", "postType": "regular",
	   "description": {"content": "<p>Update.</p>", "contentType": "html"}}
	`)
	g := &fakeGraph{bodies: map[string]string{overviewsURL: body}}
	rec := telemetrytest.New()
	if err := New(g, nil, "", nil).Collect(context.Background(), rec.Emitter(), recordoutcome.NewRecorder()); err != nil {
		t.Fatalf("Collect: %v", err)
	}
	if got := postEvents(rec); len(got) != 0 {
		t.Fatalf("emitted %d post events with no checkpoint store configured, want 0", len(got))
	}
}
