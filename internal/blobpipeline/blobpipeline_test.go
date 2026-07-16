package blobpipeline

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"strings"
	"testing"

	"github.com/rknightion/graph2otel/internal/checkpoint"
	"github.com/rknightion/graph2otel/internal/telemetry"
	"github.com/rknightion/graph2otel/internal/telemetrytest"
)

// fakeSource is an in-memory Source: a map of blob name to its full current
// content. Appending to a blob is just extending its string, which is exactly
// what Azure Monitor does to the real append blobs.
type fakeSource struct {
	blobs   map[string]string
	listErr error
	reads   []string // "name[offset:offset+count]" per ReadRange, to pin ranged reads
}

func (f *fakeSource) List(_ context.Context, _, prefix string) ([]BlobInfo, error) {
	if f.listErr != nil {
		return nil, f.listErr
	}
	var out []BlobInfo
	for name, content := range f.blobs {
		if strings.HasPrefix(name, prefix) {
			out = append(out, BlobInfo{Name: name, Size: int64(len(content))})
		}
	}
	return out, nil
}

func (f *fakeSource) ReadRange(_ context.Context, _, name string, offset, count int64) ([]byte, error) {
	content, ok := f.blobs[name]
	if !ok {
		return nil, fmt.Errorf("fakeSource: no blob %q", name)
	}
	if offset > int64(len(content)) {
		return nil, io.ErrUnexpectedEOF
	}
	end := offset + count
	if end > int64(len(content)) {
		end = int64(len(content))
	}
	f.reads = append(f.reads, fmt.Sprintf("%s[%d:%d]", name, offset, end))
	return []byte(content[offset:end]), nil
}

// rec builds one JSON-Lines record with the CRLF terminator the real blobs use.
func rec(id string) string {
	return fmt.Sprintf(`{"time":"2026-07-16T13:00:00Z","id":%q}`, id) + "\r\n"
}

// testConfig maps each record to an event named after its "id" field, so tests
// can assert exactly which records were emitted, in order.
func testConfig() ContainerConfig {
	return ContainerConfig{
		Container: "insights-logs-test",
		Prefix:    "tenantId=t1/",
		Map: func(r map[string]any) (telemetry.Event, bool) {
			id, _ := r["id"].(string)
			return telemetry.Event{Name: "test.event", Body: id}, true
		},
	}
}

func newCursor() *checkpoint.BlobCursor {
	return &checkpoint.BlobCursor{TenantID: "t1", Key: "insights-logs-test", Offsets: map[string]int64{}}
}

// bodies returns the emitted log bodies, which testConfig sets to each record's id.
func bodies(r *telemetrytest.Recorder) []string {
	var out []string
	for _, l := range r.LogRecords() {
		out = append(out, l.Body)
	}
	return out
}

func discardLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

func TestPollEmitsEveryRecordAndAdvancesTheCursor(t *testing.T) {
	src := &fakeSource{blobs: map[string]string{
		"tenantId=t1/y=2026/m=07/d=16/h=00/m=00/PT1H.json": rec("a") + rec("b"),
	}}
	r := telemetrytest.New()
	cur := newCursor()

	if err := Poll(context.Background(), testConfig(), cur, src, r.Emitter(), discardLogger(), nil); err != nil {
		t.Fatalf("Poll: %v", err)
	}

	got := bodies(r)
	want := []string{"a", "b"}
	if len(got) != len(want) {
		t.Fatalf("emitted %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("record %d = %q, want %q", i, got[i], want[i])
		}
	}

	name := "tenantId=t1/y=2026/m=07/d=16/h=00/m=00/PT1H.json"
	if cur.Offsets[name] != int64(len(rec("a")+rec("b"))) {
		t.Errorf("offset = %d, want %d (whole blob consumed)", cur.Offsets[name], len(rec("a")+rec("b")))
	}
}

// A blob that has not grown must cost nothing: no re-read, no re-emit. This is
// the property that makes re-checking all ~168 blobs every tick affordable.
func TestPollIsIdempotentWhenNothingGrew(t *testing.T) {
	src := &fakeSource{blobs: map[string]string{
		"tenantId=t1/y=2026/m=07/d=16/h=00/m=00/PT1H.json": rec("a"),
	}}
	r := telemetrytest.New()
	cur := newCursor()

	for i := 0; i < 3; i++ {
		if err := Poll(context.Background(), testConfig(), cur, src, r.Emitter(), discardLogger(), nil); err != nil {
			t.Fatalf("Poll %d: %v", i, err)
		}
	}

	if got := bodies(r); len(got) != 1 {
		t.Errorf("emitted %v across 3 polls, want exactly 1 record (no duplicates)", got)
	}
	if len(src.reads) != 1 {
		t.Errorf("ReadRange calls = %v, want exactly 1 (an unchanged blob must not be re-read)", src.reads)
	}
}

// The load-bearing case: Azure backfills history into a blob whose hour closed
// long ago. A consumer that walked forward and forgot would never see record
// "b". Only the NEW bytes may be read and emitted.
func TestPollReadsOnlyTheNewBytesWhenAClosedBlobGrows(t *testing.T) {
	name := "tenantId=t1/y=2026/m=07/d=16/h=00/m=00/PT1H.json"
	src := &fakeSource{blobs: map[string]string{name: rec("a")}}
	r := telemetrytest.New()
	cur := newCursor()

	if err := Poll(context.Background(), testConfig(), cur, src, r.Emitter(), discardLogger(), nil); err != nil {
		t.Fatalf("Poll 1: %v", err)
	}
	// Azure appends to the long-closed hour.
	src.blobs[name] = rec("a") + rec("b")
	if err := Poll(context.Background(), testConfig(), cur, src, r.Emitter(), discardLogger(), nil); err != nil {
		t.Fatalf("Poll 2: %v", err)
	}

	got := bodies(r)
	if len(got) != 2 || got[0] != "a" || got[1] != "b" {
		t.Fatalf("emitted %v, want [a b] — the growth must be picked up exactly once", got)
	}
	wantRead := fmt.Sprintf("%s[%d:%d]", name, len(rec("a")), len(rec("a")+rec("b")))
	if src.reads[1] != wantRead {
		t.Errorf("second read = %q, want %q (ranged read from the stored offset, not a re-read)", src.reads[1], wantRead)
	}
}

// A restart must resume from the persisted offset, not re-emit the blob.
func TestPollResumesFromAPersistedCursor(t *testing.T) {
	name := "tenantId=t1/y=2026/m=07/d=16/h=00/m=00/PT1H.json"
	src := &fakeSource{blobs: map[string]string{name: rec("a") + rec("b")}}
	r := telemetrytest.New()

	// Simulate a process that already consumed record "a" and restarted.
	cur := newCursor()
	cur.Offsets[name] = int64(len(rec("a")))

	if err := Poll(context.Background(), testConfig(), cur, src, r.Emitter(), discardLogger(), nil); err != nil {
		t.Fatalf("Poll: %v", err)
	}
	got := bodies(r)
	if len(got) != 1 || got[0] != "b" {
		t.Fatalf("emitted %v, want [b] only — record a was already consumed before the restart", got)
	}
}

// A chunk whose tail is a partial line must not emit that line, and must not
// advance the cursor past it: the rest of the record is still to be written.
func TestPollNeverEmitsOrSkipsAPartialTrailingLine(t *testing.T) {
	name := "tenantId=t1/y=2026/m=07/d=16/h=00/m=00/PT1H.json"
	partial := `{"time":"2026-07-16T13:00:00Z","id":"b`
	src := &fakeSource{blobs: map[string]string{name: rec("a") + partial}}
	r := telemetrytest.New()
	cur := newCursor()

	if err := Poll(context.Background(), testConfig(), cur, src, r.Emitter(), discardLogger(), nil); err != nil {
		t.Fatalf("Poll: %v", err)
	}
	if got := bodies(r); len(got) != 1 || got[0] != "a" {
		t.Fatalf("emitted %v, want [a] — the partial line must not be emitted", got)
	}
	if cur.Offsets[name] != int64(len(rec("a"))) {
		t.Fatalf("offset = %d, want %d — the cursor must stop at the last complete line",
			cur.Offsets[name], len(rec("a")))
	}

	// The record completes; the next poll picks it up whole, exactly once.
	src.blobs[name] = rec("a") + rec("b")
	if err := Poll(context.Background(), testConfig(), cur, src, r.Emitter(), discardLogger(), nil); err != nil {
		t.Fatalf("Poll 2: %v", err)
	}
	if got := bodies(r); len(got) != 2 || got[1] != "b" {
		t.Fatalf("emitted %v, want [a b] once the record completed", got)
	}
}

// The 7-day lifecycle rule deletes blobs. Their cursor entries must go too, or
// the cursor grows forever.
func TestPollPrunesCursorEntriesForDeletedBlobs(t *testing.T) {
	live := "tenantId=t1/y=2026/m=07/d=16/h=00/m=00/PT1H.json"
	src := &fakeSource{blobs: map[string]string{live: rec("a")}}
	r := telemetrytest.New()
	cur := newCursor()
	cur.Offsets["tenantId=t1/y=2026/m=07/d=01/h=00/m=00/PT1H.json"] = 500 // lifecycle-deleted

	if err := Poll(context.Background(), testConfig(), cur, src, r.Emitter(), discardLogger(), nil); err != nil {
		t.Fatalf("Poll: %v", err)
	}
	if _, ok := cur.Offsets["tenantId=t1/y=2026/m=07/d=01/h=00/m=00/PT1H.json"]; ok {
		t.Error("cursor still holds an offset for a blob that no longer exists; it would grow unboundedly")
	}
	if _, ok := cur.Offsets[live]; !ok {
		t.Error("pruning removed the live blob's offset")
	}
}

// An append blob cannot shrink, but a lifecycle delete followed by a backfill
// recreating the same name can present a smaller blob. Re-emitting that hour is
// the safe failure; silently skipping it forever is not.
func TestPollResetsWhenABlobIsSmallerThanTheStoredOffset(t *testing.T) {
	name := "tenantId=t1/y=2026/m=07/d=16/h=00/m=00/PT1H.json"
	src := &fakeSource{blobs: map[string]string{name: rec("a")}}
	r := telemetrytest.New()
	cur := newCursor()
	cur.Offsets[name] = 99999 // stale: far beyond the blob's current size

	if err := Poll(context.Background(), testConfig(), cur, src, r.Emitter(), discardLogger(), nil); err != nil {
		t.Fatalf("Poll: %v", err)
	}
	if got := bodies(r); len(got) != 1 || got[0] != "a" {
		t.Fatalf("emitted %v, want [a] — a shrunk blob must be re-read from 0, not skipped", got)
	}
	if cur.Offsets[name] != int64(len(rec("a"))) {
		t.Errorf("offset = %d, want %d", cur.Offsets[name], len(rec("a")))
	}
}

// MaxBytesPerTick paces a large blob across ticks; it must never drop records.
func TestPollPacesALargeBlobAcrossTicksWithoutLoss(t *testing.T) {
	name := "tenantId=t1/y=2026/m=07/d=16/h=00/m=00/PT1H.json"
	src := &fakeSource{blobs: map[string]string{name: rec("a") + rec("b") + rec("c")}}
	r := telemetrytest.New()
	cur := newCursor()
	cfg := testConfig()
	cfg.MaxBytesPerTick = int64(len(rec("a"))) + 5 // one record plus a partial second

	for i := 0; i < 3; i++ {
		if err := Poll(context.Background(), cfg, cur, src, r.Emitter(), discardLogger(), nil); err != nil {
			t.Fatalf("Poll %d: %v", i, err)
		}
	}
	got := bodies(r)
	if len(got) != 3 || got[0] != "a" || got[1] != "b" || got[2] != "c" {
		t.Fatalf("emitted %v across 3 paced polls, want [a b c]", got)
	}
}

// A Map that rejects a record (unmappable shape) must not stall the cursor: the
// bytes are still consumed, or the collector would re-read them forever.
func TestPollConsumesRecordsTheMapperRejects(t *testing.T) {
	name := "tenantId=t1/y=2026/m=07/d=16/h=00/m=00/PT1H.json"
	src := &fakeSource{blobs: map[string]string{name: rec("skip") + rec("a")}}
	r := telemetrytest.New()
	cur := newCursor()
	cfg := testConfig()
	cfg.Map = func(m map[string]any) (telemetry.Event, bool) {
		id, _ := m["id"].(string)
		if id == "skip" {
			return telemetry.Event{}, false
		}
		return telemetry.Event{Name: "test.event", Body: id}, true
	}

	if err := Poll(context.Background(), cfg, cur, src, r.Emitter(), discardLogger(), nil); err != nil {
		t.Fatalf("Poll: %v", err)
	}
	if got := bodies(r); len(got) != 1 || got[0] != "a" {
		t.Fatalf("emitted %v, want [a]", got)
	}
	if cur.Offsets[name] != int64(len(rec("skip")+rec("a"))) {
		t.Error("a rejected record left the cursor behind; the blob would be re-read forever")
	}
}

// A malformed line is a data defect, not a reason to stop: skip it, keep going,
// and consume it so the blob makes progress.
func TestPollSkipsAMalformedLineAndKeepsGoing(t *testing.T) {
	name := "tenantId=t1/y=2026/m=07/d=16/h=00/m=00/PT1H.json"
	src := &fakeSource{blobs: map[string]string{name: "{not json\r\n" + rec("a")}}
	r := telemetrytest.New()
	cur := newCursor()

	if err := Poll(context.Background(), testConfig(), cur, src, r.Emitter(), discardLogger(), nil); err != nil {
		t.Fatalf("Poll: %v", err)
	}
	if got := bodies(r); len(got) != 1 || got[0] != "a" {
		t.Fatalf("emitted %v, want [a] — the malformed line is skipped, the valid one still lands", got)
	}
}

// A List failure is the collector's failure: the scheduler must see it (so
// scrape.success drops) rather than a silent no-op tick.
func TestPollReturnsListErrors(t *testing.T) {
	src := &fakeSource{listErr: errors.New("boom")}
	r := telemetrytest.New()
	if err := Poll(context.Background(), testConfig(), newCursor(), src, r.Emitter(), discardLogger(), nil); err == nil {
		t.Fatal("Poll returned nil on a List failure; the tick would look successful")
	}
}

// Blobs are read oldest-first so the emitted stream is roughly time-ordered.
func TestPollReadsBlobsInChronologicalNameOrder(t *testing.T) {
	src := &fakeSource{blobs: map[string]string{
		"tenantId=t1/y=2026/m=07/d=16/h=13/m=00/PT1H.json": rec("later"),
		"tenantId=t1/y=2026/m=07/d=16/h=02/m=00/PT1H.json": rec("earlier"),
	}}
	r := telemetrytest.New()
	if err := Poll(context.Background(), testConfig(), newCursor(), src, r.Emitter(), discardLogger(), nil); err != nil {
		t.Fatalf("Poll: %v", err)
	}
	got := bodies(r)
	if len(got) != 2 || got[0] != "earlier" || got[1] != "later" {
		t.Errorf("emitted %v, want [earlier later] — the zero-padded layout sorts chronologically", got)
	}
}

// The cursor is saved as each blob advances, so a crash mid-tick re-reads only
// the blob in flight rather than every blob the tick had already drained.
func TestPollSavesTheCursorPerAdvancedBlob(t *testing.T) {
	src := &fakeSource{blobs: map[string]string{
		"tenantId=t1/y=2026/m=07/d=16/h=00/m=00/PT1H.json": rec("a"),
		"tenantId=t1/y=2026/m=07/d=16/h=01/m=00/PT1H.json": rec("b"),
	}}
	r := telemetrytest.New()
	saves := 0
	save := func(*checkpoint.BlobCursor) error { saves++; return nil }

	if err := Poll(context.Background(), testConfig(), newCursor(), src, r.Emitter(), discardLogger(), save); err != nil {
		t.Fatalf("Poll: %v", err)
	}
	if saves != 2 {
		t.Errorf("save called %d times, want 2 (once per advanced blob)", saves)
	}
}

// A save failure must not lose the emitted records' progress silently, but it
// also must not fail the tick: the next poll simply re-reads. It is logged.
func TestPollContinuesWhenTheCursorSaveFails(t *testing.T) {
	src := &fakeSource{blobs: map[string]string{
		"tenantId=t1/y=2026/m=07/d=16/h=00/m=00/PT1H.json": rec("a"),
		"tenantId=t1/y=2026/m=07/d=16/h=01/m=00/PT1H.json": rec("b"),
	}}
	r := telemetrytest.New()
	save := func(*checkpoint.BlobCursor) error { return errors.New("disk full") }

	if err := Poll(context.Background(), testConfig(), newCursor(), src, r.Emitter(), discardLogger(), save); err != nil {
		t.Fatalf("Poll: %v — a save failure must not fail the tick", err)
	}
	if got := bodies(r); len(got) != 2 {
		t.Errorf("emitted %v, want both records — a save failure must not stop draining", got)
	}
}
