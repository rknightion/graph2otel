package blobpipeline

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/rknightion/graph2otel/internal/checkpoint"
	"github.com/rknightion/graph2otel/internal/semconv"
	"github.com/rknightion/graph2otel/internal/telemetry"
	"github.com/rknightion/graph2otel/internal/telemetrytest"
	"github.com/rknightion/graph2otel/internal/wirecheck"
)

// fakeSource is an in-memory Source: a map of blob name to its full current
// content. Appending to a blob is just extending its string, which is exactly
// what Azure Monitor does to the real append blobs.
type fakeSource struct {
	blobs   map[string]string
	listErr error
	readErr map[string]error
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
	if err := f.readErr[name]; err != nil {
		return nil, err
	}
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
			ev := telemetry.Event{Name: "test.event", Body: id}
			if raw, ok := r["time"].(string); ok {
				ev.Timestamp, _ = time.Parse(time.RFC3339, raw)
			}
			return ev, true
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

	if err := Poll(context.Background(), testConfig(), cur, src, r.Emitter(), discardLogger(), nil, nil); err != nil {
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

// TestPollDropsUndatedRecords keeps #275's boundary before LogEvent. A blob
// record with neither its wire-derived mapper timestamp nor a mapper fallback
// must be consumed from the byte cursor but never emitted. Valid wire time and
// an intentional fallback still emit.
func TestPollDropsUndatedRecords(t *testing.T) {
	name := "tenantId=t1/y=2026/m=07/d=16/h=00/m=00/PT1H.json"
	from := time.Date(2026, 7, 25, 10, 0, 0, 0, time.UTC)
	fallback := from.Add(20 * time.Minute)
	src := &fakeSource{blobs: map[string]string{name: `{"id":"undated"}` + "\r\n" +
		`{"id":"malformed","time":"not-rfc3339"}` + "\r\n" +
		`{"id":"wire-time","time":"2026-07-25T10:10:00Z"}` + "\r\n" +
		`{"id":"mapper-fallback"}` + "\r\n",
	}}
	cfg := testConfig()
	cfg.CollectorName = "entra.test.undated"
	cfg.Derive = func(map[string]any, telemetry.Event) []MetricPoint { return nil }
	cfg.Map = func(record map[string]any) (telemetry.Event, bool) {
		id, _ := record["id"].(string)
		ev := telemetry.Event{Name: "test.event", Body: id}
		if id == "mapper-fallback" {
			ev.Timestamp = fallback
		}
		if raw, ok := record["time"].(string); ok {
			ev.Timestamp, _ = time.Parse(time.RFC3339, raw)
		}
		return ev, true
	}
	r := telemetrytest.New()
	cur := newCursor()

	if err := Poll(context.Background(), cfg, cur, src, r.Emitter(), discardLogger(), nil, nil); err != nil {
		t.Fatalf("Poll: %v", err)
	}
	if got, want := bodies(r), []string{"wire-time", "mapper-fallback"}; len(got) != len(want) || got[0] != want[0] || got[1] != want[1] {
		t.Fatalf("emitted %v, want %v", got, want)
	}
	logs := r.LogRecords()
	if got, want := logs[0].Timestamp, from.Add(10*time.Minute); !got.Equal(want) {
		t.Errorf("wire-time log timestamp = %v, want %v", got, want)
	}
	if got, want := logs[1].Timestamp, fallback; !got.Equal(want) {
		t.Errorf("mapper-fallback log timestamp = %v, want %v", got, want)
	}
	if got, want := cur.Offsets[name], int64(len(src.blobs[name])); got != want {
		t.Errorf("offset = %d, want %d: dropping a record must still consume its bytes", got, want)
	}
	if got := metricSum(r, metricRecordsDropped); got != 2 {
		t.Errorf("%s = %v, want 2", metricRecordsDropped, got)
	}
	points := r.MetricPoints(wirecheck.MetricUnexpected)
	if len(points) != 1 || points[0].Value != 2 || points[0].Attrs[semconv.AttrField] != "event_time" || points[0].Attrs[semconv.AttrKind] != wirecheck.KindMissingField {
		t.Errorf("undated watchdog = %+v, want two missing event_time findings", points)
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
		if err := Poll(context.Background(), testConfig(), cur, src, r.Emitter(), discardLogger(), nil, nil); err != nil {
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

	if err := Poll(context.Background(), testConfig(), cur, src, r.Emitter(), discardLogger(), nil, nil); err != nil {
		t.Fatalf("Poll 1: %v", err)
	}
	// Azure appends to the long-closed hour.
	src.blobs[name] = rec("a") + rec("b")
	if err := Poll(context.Background(), testConfig(), cur, src, r.Emitter(), discardLogger(), nil, nil); err != nil {
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

	if err := Poll(context.Background(), testConfig(), cur, src, r.Emitter(), discardLogger(), nil, nil); err != nil {
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

	if err := Poll(context.Background(), testConfig(), cur, src, r.Emitter(), discardLogger(), nil, nil); err != nil {
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
	if err := Poll(context.Background(), testConfig(), cur, src, r.Emitter(), discardLogger(), nil, nil); err != nil {
		t.Fatalf("Poll 2: %v", err)
	}
	if got := bodies(r); len(got) != 2 || got[1] != "b" {
		t.Fatalf("emitted %v, want [a b] once the record completed", got)
	}
}

// A short unfinished append is ordinary Azure behavior. It must stay pending
// without falsely failing the tick, then be consumed after the append completes.
func TestPollLeavesAShortPartialAppendPending(t *testing.T) {
	name := "tenantId=t1/y=2026/m=07/d=16/h=00/m=00/PT1H.json"
	partial := `{"time":"2026-07-16T13:00:00Z","id":"b`
	src := &fakeSource{blobs: map[string]string{name: partial}}
	r := telemetrytest.New()
	cur := newCursor()

	if err := Poll(context.Background(), testConfig(), cur, src, r.Emitter(), discardLogger(), nil, nil); err != nil {
		t.Fatalf("Poll: %v — a short unfinished append must remain pending", err)
	}
	if got := bodies(r); len(got) != 0 {
		t.Fatalf("emitted %v, want no partial record", got)
	}
	if got := cur.Offsets[name]; got != 0 {
		t.Fatalf("offset = %d, want 0 while the only record has no terminator", got)
	}
}

// A record that fills the configured chunk and still lacks a terminator cannot
// complete on a later byte in the same range: retrying it forever would leave
// the collector reporting healthy while permanently stuck.
func TestPollReturnsDegradedErrorForCapSizedNewlineFreeRecord(t *testing.T) {
	name := "tenantId=t1/y=2026/m=07/d=16/h=00/m=00/PT1H.json"
	src := &fakeSource{blobs: map[string]string{name: "0123456789"}}
	r := telemetrytest.New()
	cfg := testConfig()
	cfg.MaxBytesPerTick = 10

	err := Poll(context.Background(), cfg, newCursor(), src, r.Emitter(), discardLogger(), nil, nil)
	if err == nil {
		t.Fatal("Poll returned nil for a cap-sized newline-free record; it would retry forever as a healthy tick")
	}
	if !strings.Contains(err.Error(), "oversized record") || !strings.Contains(err.Error(), name) || !strings.Contains(err.Error(), cfg.Container) {
		t.Fatalf("Poll error = %q, want an oversized-record error naming %s and %s", err, cfg.Container, name)
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

	if err := Poll(context.Background(), testConfig(), cur, src, r.Emitter(), discardLogger(), nil, nil); err != nil {
		t.Fatalf("Poll: %v", err)
	}
	if _, ok := cur.Offsets["tenantId=t1/y=2026/m=07/d=01/h=00/m=00/PT1H.json"]; ok {
		t.Error("cursor still holds an offset for a blob that no longer exists; it would grow unboundedly")
	}
	if _, ok := cur.Offsets[live]; !ok {
		t.Error("pruning removed the live blob's offset")
	}
}

// A lifecycle deletion can be the only cursor mutation in a tick. Persisting
// it is necessary so a restart does not revive every deleted blob entry.
func TestPollSavesPruneOnlyCursorMutation(t *testing.T) {
	live := "tenantId=t1/y=2026/m=07/d=16/h=00/m=00/PT1H.json"
	deleted := "tenantId=t1/y=2026/m=07/d=01/h=00/m=00/PT1H.json"
	src := &fakeSource{blobs: map[string]string{live: rec("a")}}
	cur := newCursor()
	cur.Offsets[live] = int64(len(rec("a")))
	cur.Offsets[deleted] = 500
	var persisted *checkpoint.BlobCursor
	save := func(c *checkpoint.BlobCursor) error {
		persisted = &checkpoint.BlobCursor{TenantID: c.TenantID, Key: c.Key, Offsets: make(map[string]int64, len(c.Offsets))}
		for name, off := range c.Offsets {
			persisted.Offsets[name] = off
		}
		return nil
	}

	if err := Poll(context.Background(), testConfig(), cur, src, telemetrytest.New().Emitter(), discardLogger(), save, nil); err != nil {
		t.Fatalf("Poll: %v", err)
	}
	if persisted == nil {
		t.Fatal("prune-only cursor mutation was not persisted")
	}
	if _, ok := persisted.Offsets[deleted]; ok {
		t.Error("persisted cursor still contains the lifecycle-deleted blob")
	}
	if got := persisted.Offsets[live]; got != int64(len(rec("a"))) {
		t.Errorf("persisted live offset = %d, want %d", got, len(rec("a")))
	}
}

// An idle tick that neither advances nor prunes must not rewrite the cursor.
func TestPollDoesNotSaveAnUnchangedCursor(t *testing.T) {
	name := "tenantId=t1/y=2026/m=07/d=16/h=00/m=00/PT1H.json"
	src := &fakeSource{blobs: map[string]string{name: rec("a")}}
	cur := newCursor()
	cur.Offsets[name] = int64(len(rec("a")))
	saves := 0
	save := func(*checkpoint.BlobCursor) error { saves++; return nil }

	if err := Poll(context.Background(), testConfig(), cur, src, telemetrytest.New().Emitter(), discardLogger(), save, nil); err != nil {
		t.Fatalf("Poll: %v", err)
	}
	if saves != 0 {
		t.Errorf("save called %d times, want 0 for an unchanged cursor", saves)
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

	if err := Poll(context.Background(), testConfig(), cur, src, r.Emitter(), discardLogger(), nil, nil); err != nil {
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
		if err := Poll(context.Background(), cfg, cur, src, r.Emitter(), discardLogger(), nil, nil); err != nil {
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
		ev := telemetry.Event{Name: "test.event", Body: id}
		if raw, ok := m["time"].(string); ok {
			ev.Timestamp, _ = time.Parse(time.RFC3339, raw)
		}
		return ev, true
	}

	if err := Poll(context.Background(), cfg, cur, src, r.Emitter(), discardLogger(), nil, nil); err != nil {
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

	if err := Poll(context.Background(), testConfig(), cur, src, r.Emitter(), discardLogger(), nil, nil); err != nil {
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
	if err := Poll(context.Background(), testConfig(), newCursor(), src, r.Emitter(), discardLogger(), nil, nil); err == nil {
		t.Fatal("Poll returned nil on a List failure; the tick would look successful")
	}
}

// One unreadable blob must not prevent later blobs from emitting and
// checkpointing, but the scheduler still needs a degraded tick result.
func TestPollReturnsDegradedErrorAfterMixedReadFailure(t *testing.T) {
	broken := "tenantId=t1/y=2026/m=07/d=16/h=00/m=00/PT1H.json"
	healthy := "tenantId=t1/y=2026/m=07/d=16/h=01/m=00/PT1H.json"
	readErr := errors.New("storage reader denied")
	healthyRecord := tsRec(5*time.Minute, "healthy")
	src := &fakeSource{
		blobs:   map[string]string{broken: rec("broken"), healthy: healthyRecord},
		readErr: map[string]error{broken: readErr},
	}
	// Use the real bounded counter Derive path so this test also pins the
	// reportGate-before-degraded-return ordering. A healthy record must still
	// produce its gate metric when another blob makes the tick degraded.
	cfg := gatedConfig(time.Hour)
	r := telemetrytest.New()
	cur := newCursor()
	saves := 0
	save := func(*checkpoint.BlobCursor) error { saves++; return nil }

	err := Poll(context.Background(), cfg, cur, src, r.Emitter(), discardLogger(), save, nil)
	if !errors.Is(err, readErr) {
		t.Fatalf("Poll error = %v, want joined read failure %v", err, readErr)
	}
	if got := bodies(r); len(got) != 1 || got[0] != "healthy" {
		t.Fatalf("emitted %v, want the healthy blob despite the failed read", got)
	}
	if got := cur.Offsets[healthy]; got != int64(len(healthyRecord)) {
		t.Errorf("healthy offset = %d, want %d", got, len(healthyRecord))
	}
	if _, ok := cur.Offsets[broken]; ok {
		t.Error("failed blob advanced its cursor")
	}
	if saves != 1 {
		t.Errorf("save called %d times, want 1 for the healthy blob", saves)
	}
	if got := metricSum(r, "entra.test.count"); got != 1 {
		t.Errorf("entra.test.count = %v, want 1 from the healthy blob despite the degraded return", got)
	}
	if got := metricSum(r, metricEmitted); got != 1 {
		t.Errorf("%s = %v, want 1 despite the degraded return", metricEmitted, got)
	}
}

// A tick where every listed blob is unreadable must surface every underlying
// failure instead of looking like an idle successful scrape.
func TestPollReturnsDegradedErrorWhenAllReadsFail(t *testing.T) {
	first := "tenantId=t1/y=2026/m=07/d=16/h=00/m=00/PT1H.json"
	second := "tenantId=t1/y=2026/m=07/d=16/h=01/m=00/PT1H.json"
	firstErr := errors.New("first denied")
	secondErr := errors.New("second denied")
	src := &fakeSource{
		blobs:   map[string]string{first: rec("a"), second: rec("b")},
		readErr: map[string]error{first: firstErr, second: secondErr},
	}

	err := Poll(context.Background(), testConfig(), newCursor(), src, telemetrytest.New().Emitter(), discardLogger(), nil, nil)
	if !errors.Is(err, firstErr) || !errors.Is(err, secondErr) {
		t.Fatalf("Poll error = %v, want joined failures %v and %v", err, firstErr, secondErr)
	}
}

// Blobs are read oldest-first so the emitted stream is roughly time-ordered.
func TestPollReadsBlobsInChronologicalNameOrder(t *testing.T) {
	src := &fakeSource{blobs: map[string]string{
		"tenantId=t1/y=2026/m=07/d=16/h=13/m=00/PT1H.json": rec("later"),
		"tenantId=t1/y=2026/m=07/d=16/h=02/m=00/PT1H.json": rec("earlier"),
	}}
	r := telemetrytest.New()
	if err := Poll(context.Background(), testConfig(), newCursor(), src, r.Emitter(), discardLogger(), nil, nil); err != nil {
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

	if err := Poll(context.Background(), testConfig(), newCursor(), src, r.Emitter(), discardLogger(), save, nil); err != nil {
		t.Fatalf("Poll: %v", err)
	}
	if saves != 2 {
		t.Errorf("save called %d times, want 2 (once per advanced blob)", saves)
	}
}

// A save failure must not stop later blobs from emitting, but it must make the
// tick degraded: on restart every unsaved record may be emitted again.
func TestPollReturnsDegradedErrorWhenTheCursorSaveFails(t *testing.T) {
	src := &fakeSource{blobs: map[string]string{
		"tenantId=t1/y=2026/m=07/d=16/h=00/m=00/PT1H.json": rec("a"),
		"tenantId=t1/y=2026/m=07/d=16/h=01/m=00/PT1H.json": rec("b"),
	}}
	r := telemetrytest.New()
	saveErr := errors.New("disk full")
	save := func(*checkpoint.BlobCursor) error { return saveErr }

	err := Poll(context.Background(), testConfig(), newCursor(), src, r.Emitter(), discardLogger(), save, nil)
	if !errors.Is(err, saveErr) {
		t.Fatalf("Poll error = %v, want joined cursor save failure %v", err, saveErr)
	}
	if got := bodies(r); len(got) != 2 {
		t.Errorf("emitted %v, want both records — a save failure must not stop draining", got)
	}
}

// TestPollStampsBlobTransport pins that every record this engine emits names
// the transport that produced it (#141).
//
// This is the sharp case the attribute exists for. A blob-ingested sign-in and
// a Graph-polled one are byte-identical by design — one shared mapper, on
// purpose — so this stamp is the ONLY thing that tells an operator which lane a
// record arrived by, and the only way to attribute a duplicate to #138's
// at-least-once delivery rather than to both transports running at once.
func TestPollStampsBlobTransport(t *testing.T) {
	src := &fakeSource{blobs: map[string]string{
		"tenantId=t1/y=2026/m=07/d=16/h=00/m=00/PT1H.json": rec("a"),
	}}
	r := telemetrytest.New()

	if err := Poll(context.Background(), testConfig(), newCursor(), src, r.Emitter(), discardLogger(), nil, nil); err != nil {
		t.Fatalf("Poll: %v", err)
	}

	logs := r.LogRecords()
	if len(logs) != 1 {
		t.Fatalf("got %d log records, want 1", len(logs))
	}
	if got := logs[0].Attrs[semconv.AttrIngestTransport]; got != string(telemetry.TransportBlob) {
		t.Errorf("%s = %q, want %q", semconv.AttrIngestTransport, got, telemetry.TransportBlob)
	}
}

// --- exclude_self: dropping graph2otel's own polling exhaust (#154) ---

// recWithApp builds a record whose actor appId lives at properties.appId — the
// path the real MGAL and sign-in SelfAppID extractors read (#154). The record's
// "id" doubles as the emitted body (via selfTestConfig's Map), so tests can
// assert exactly which records survived the filter.
func recWithApp(id, appID string) string {
	return fmt.Sprintf(
		`{"time":"2026-07-16T13:00:00Z","id":%q,"properties":{"appId":%q}}`, id, appID,
	) + "\r\n"
}

// propsAppID reads properties.appId, mirroring the graphactivity/signins
// extractors. Used as the ContainerConfig.SelfAppID in these engine tests.
func propsAppID(rec map[string]any) string {
	p, _ := rec["properties"].(map[string]any)
	s, _ := p["appId"].(string)
	return s
}

// selfTestConfig is testConfig plus the exclude_self wiring, so a test controls
// ExcludeSelf/SelfClientID while the Map still names each event after its id.
func selfTestConfig(excludeSelf bool, selfClientID string, selfAppID func(map[string]any) string) ContainerConfig {
	cfg := testConfig()
	cfg.ExcludeSelf = excludeSelf
	cfg.SelfClientID = selfClientID
	cfg.SelfAppID = selfAppID
	cfg.CollectorName = "entra.graph_activity"
	return cfg
}

// TestPollExcludesSelfAuthoredRecordsButNotThirdParty is the #152/#154 guard: a
// record whose appId is the poller's proved authenticated application ID is
// dropped, and a third party's record — ANY other appId — always passes through
// untouched.
func TestPollExcludesSelfAuthoredRecordsButNotThirdParty(t *testing.T) {
	src := &fakeSource{blobs: map[string]string{
		"tenantId=t1/y=2026/m=07/d=16/h=00/m=00/PT1H.json": recWithApp("self", "POLLER") + recWithApp("other", "THIRDPARTY"),
	}}
	r := telemetrytest.New()
	cur := newCursor()
	cfg := selfTestConfig(true, "POLLER", propsAppID)

	if err := Poll(context.Background(), cfg, cur, src, r.Emitter(), discardLogger(), nil, nil); err != nil {
		t.Fatalf("Poll: %v", err)
	}

	got := bodies(r)
	if len(got) != 1 || got[0] != "other" {
		t.Fatalf("emitted %v, want only the third-party record [other]", got)
	}

	// The bytes are still consumed: the excluded record must not stall the cursor.
	name := "tenantId=t1/y=2026/m=07/d=16/h=00/m=00/PT1H.json"
	full := int64(len(recWithApp("self", "POLLER") + recWithApp("other", "THIRDPARTY")))
	if cur.Offsets[name] != full {
		t.Errorf("offset = %d, want %d (both records consumed, one filtered)", cur.Offsets[name], full)
	}
}

// TestPollDoesNotFilterWhenExcludeSelfIsOff is the default-off regression guard:
// with ExcludeSelf false, a self-authored record ships exactly as before.
func TestPollDoesNotFilterWhenExcludeSelfIsOff(t *testing.T) {
	src := &fakeSource{blobs: map[string]string{
		"tenantId=t1/y=2026/m=07/d=16/h=00/m=00/PT1H.json": recWithApp("self", "POLLER") + recWithApp("other", "THIRDPARTY"),
	}}
	r := telemetrytest.New()
	cfg := selfTestConfig(false, "POLLER", propsAppID)

	if err := Poll(context.Background(), cfg, newCursor(), src, r.Emitter(), discardLogger(), nil, nil); err != nil {
		t.Fatalf("Poll: %v", err)
	}

	got := bodies(r)
	if len(got) != 2 || got[0] != "self" || got[1] != "other" {
		t.Fatalf("emitted %v, want both records [self other] (filter off)", got)
	}
	if pts := r.MetricPoints(metricSelfExcluded); len(pts) != 0 {
		t.Errorf("self_excluded points = %d, want 0 with exclude_self off: %+v", len(pts), pts)
	}
}

// TestPollCountsEverySelfExclusionPerCollector pins the loud-drop contract: the
// self-obs counter increments once per excluded record, labeled with the
// collector, so a quieter dashboard is visible and alertable rather than looking
// like breakage (#154).
func TestPollCountsEverySelfExclusionPerCollector(t *testing.T) {
	src := &fakeSource{blobs: map[string]string{
		"tenantId=t1/y=2026/m=07/d=16/h=00/m=00/PT1H.json": recWithApp("s1", "POLLER") + recWithApp("other", "THIRDPARTY") + recWithApp("s2", "POLLER"),
	}}
	r := telemetrytest.New()
	cfg := selfTestConfig(true, "POLLER", propsAppID)

	if err := Poll(context.Background(), cfg, newCursor(), src, r.Emitter(), discardLogger(), nil, nil); err != nil {
		t.Fatalf("Poll: %v", err)
	}

	pts := r.MetricPoints(metricSelfExcluded)
	if len(pts) != 1 {
		t.Fatalf("self_excluded points = %d, want 1 series: %+v", len(pts), pts)
	}
	p := pts[0]
	if !p.Monotonic {
		t.Errorf("%s must be a monotonic counter", metricSelfExcluded)
	}
	if p.Value != 2 {
		t.Errorf("%s value = %v, want 2 (two self records dropped)", metricSelfExcluded, p.Value)
	}
	if p.Attrs[semconv.AttrCollector] != "entra.graph_activity" {
		t.Errorf("collector attr = %q, want entra.graph_activity; attrs=%v", p.Attrs[semconv.AttrCollector], p.Attrs)
	}
}

// TestPollNeverFiltersWhenSelfAppIDIsNil models a category with no appId field
// (e.g. AuditLogs): SelfAppID is nil, so nothing is filtered even with
// exclude_self on and a client id set.
func TestPollNeverFiltersWhenSelfAppIDIsNil(t *testing.T) {
	src := &fakeSource{blobs: map[string]string{
		"tenantId=t1/y=2026/m=07/d=16/h=00/m=00/PT1H.json": recWithApp("a", "POLLER") + recWithApp("b", "POLLER"),
	}}
	r := telemetrytest.New()
	cfg := selfTestConfig(true, "POLLER", nil)

	if err := Poll(context.Background(), cfg, newCursor(), src, r.Emitter(), discardLogger(), nil, nil); err != nil {
		t.Fatalf("Poll: %v", err)
	}
	if got := bodies(r); len(got) != 2 {
		t.Errorf("emitted %v, want both records (nil SelfAppID never filters)", got)
	}
	if pts := r.MetricPoints(metricSelfExcluded); len(pts) != 0 {
		t.Errorf("self_excluded points = %d, want 0 for a no-appId category", len(pts))
	}
}

// TestPollNeverFiltersWhenSelfClientIDIsEmpty guards the "self is unproved" case:
// when authenticated application ID proof is unavailable, an empty appId must
// not match as self — the filter no-ops instead.
func TestPollNeverFiltersWhenSelfClientIDIsEmpty(t *testing.T) {
	src := &fakeSource{blobs: map[string]string{
		// One record deliberately has an empty appId; it must NOT be treated as self.
		"tenantId=t1/y=2026/m=07/d=16/h=00/m=00/PT1H.json": recWithApp("a", "") + recWithApp("b", "THIRDPARTY"),
	}}
	r := telemetrytest.New()
	cfg := selfTestConfig(true, "", propsAppID)

	if err := Poll(context.Background(), cfg, newCursor(), src, r.Emitter(), discardLogger(), nil, nil); err != nil {
		t.Fatalf("Poll: %v", err)
	}
	if got := bodies(r); len(got) != 2 {
		t.Errorf("emitted %v, want both records (empty SelfClientID never filters)", got)
	}
	if pts := r.MetricPoints(metricSelfExcluded); len(pts) != 0 {
		t.Errorf("self_excluded points = %d, want 0 when SelfClientID is empty", len(pts))
	}
}
