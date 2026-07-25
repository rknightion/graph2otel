package jobpipeline

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/rknightion/graph2otel/internal/checkpoint"
	"github.com/rknightion/graph2otel/internal/semconv"
	"github.com/rknightion/graph2otel/internal/telemetry"
	"github.com/rknightion/graph2otel/internal/telemetrytest"
	"github.com/rknightion/graph2otel/internal/wirecheck"
)

// fakeJobClient is a scriptable JobClient. createErrs is returned (and consumed)
// by successive CreateQuery calls before the final success; statuses is the
// sequence of status values returned by successive QueryStatus calls; pages maps
// a page URL to its (records, nextLink).
type fakeJobClient struct {
	createErrs   []error
	createCalls  int
	createBodies [][]byte

	statuses    []string
	statusCalls int
	// statusErr, when non-nil, is returned by every QueryStatus call — used to
	// model a process that never gets its query to a terminal state.
	statusErr error
	// statusURLs records the query URL each status poll was made against, so a
	// test can prove WHICH job id was polled (adopted vs freshly created).
	statusURLs []string

	pages     map[string]fakePage
	pageCalls int
	// fetchPage, when set, replaces pages for a test that needs a dynamic
	// response sequence (such as a deliberately non-converging cursor walk).
	fetchPage func(context.Context, string) ([]map[string]any, string, error)
}

type fakePage struct {
	records []map[string]any
	next    string
}

func (f *fakeJobClient) CreateQuery(_ context.Context, _ string, body []byte) (string, string, error) {
	f.createBodies = append(f.createBodies, body)
	i := f.createCalls
	f.createCalls++
	if i < len(f.createErrs) && f.createErrs[i] != nil {
		return "", "", f.createErrs[i]
	}
	// Distinct id per create, so a test can tell an adopted job from a second one.
	return "query-" + strconv.Itoa(f.createCalls), StatusNotStarted, nil
}

func (f *fakeJobClient) QueryStatus(_ context.Context, queryURL string) (string, error) {
	f.statusURLs = append(f.statusURLs, queryURL)
	i := f.statusCalls
	f.statusCalls++
	if f.statusErr != nil {
		return "", f.statusErr
	}
	if i < len(f.statuses) {
		return f.statuses[i], nil
	}
	return StatusSucceeded, nil
}

func (f *fakeJobClient) FetchRecordsPage(ctx context.Context, pageURL string) ([]map[string]any, string, error) {
	f.pageCalls++
	if f.fetchPage != nil {
		return f.fetchPage(ctx, pageURL)
	}
	p := f.pages[pageURL]
	return p.records, p.next, nil
}

// noSleep is a Sleep that records how many times it was called but never waits,
// so backoff tests run instantly.
func noSleep(calls *int) func(context.Context, time.Duration) error {
	return func(context.Context, time.Duration) error { *calls++; return nil }
}

func mapByID(record map[string]any) (string, telemetry.Event) {
	id, _ := record["id"].(string)
	return id, telemetry.Event{Name: "test.event", Body: id, Attrs: telemetry.Attrs{"id": id}}
}

func newCheckpoint(tenantID, endpoint string) *checkpoint.Checkpoint {
	return &checkpoint.Checkpoint{TenantID: tenantID, Endpoint: endpoint, SeenIDs: checkpoint.NewSeenIDs()}
}

func baseConfig() QueryConfig {
	return QueryConfig{
		CreatePath: "/security/auditLog/queries",
		TimeField:  "createdDateTime",
		BuildRequest: func(from, to time.Time) ([]byte, error) {
			return []byte(`{"filterStartDateTime":"` + from.UTC().Format(time.RFC3339) + `"}`), nil
		},
		Map: mapByID,
	}
}

// TestRunDropsUndatedRecords keeps #275's boundary at the job engine. The
// query window's end is an ingest boundary, not an event time: it must never
// replace an absent timestamp. A valid wire time and mapper fallback still
// emit, while the completed query advances its checkpoint normally.
func TestRunDropsUndatedRecords(t *testing.T) {
	rec := telemetrytest.New()
	from := time.Date(2026, 7, 25, 10, 0, 0, 0, time.UTC)
	to := from.Add(time.Hour)
	fallback := from.Add(20 * time.Minute)
	cfg := baseConfig()
	cfg.CollectorName = "m365.test.undated"
	cfg.Map = func(record map[string]any) (string, telemetry.Event) {
		id, _ := record["id"].(string)
		ev := telemetry.Event{Name: "test.event", Body: id}
		if id == "mapper-fallback" {
			ev.Timestamp = fallback
		}
		return id, ev
	}
	page := recordsURL("query-1", DefaultPageSize)
	client := &fakeJobClient{
		statuses: []string{StatusSucceeded},
		pages: map[string]fakePage{page: {records: []map[string]any{
			{"id": "undated"},
			{"id": "malformed", "createdDateTime": "not-rfc3339"},
			{"id": "wire-time", "createdDateTime": from.Add(10 * time.Minute).Format(time.RFC3339)},
			{"id": "mapper-fallback"},
		}}},
	}
	cp := newCheckpoint("t1", cfg.CreatePath)

	hw, err := Run(context.Background(), cfg, cp, from, to, client, rec.Emitter())
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	logs := rec.LogRecords()
	if len(logs) != 2 {
		t.Fatalf("emitted %d logs, want 2 (wire time and mapper fallback only)", len(logs))
	}
	if got, want := logs[0].Timestamp, from.Add(10*time.Minute); !got.Equal(want) {
		t.Errorf("wire-time log timestamp = %v, want %v", got, want)
	}
	if got, want := logs[1].Timestamp, fallback; !got.Equal(want) {
		t.Errorf("mapper-fallback log timestamp = %v, want %v", got, want)
	}
	if cp.SeenIDs.Has("undated") {
		t.Error("undated record entered SeenIDs; a retry must be able to reprocess corrected data")
	}
	if cp.SeenIDs.Has("malformed") {
		t.Error("malformed-time record entered SeenIDs; a retry must be able to reprocess corrected data")
	}
	if got, want := hw, to.Add(-DefaultSafetyLag); !got.Equal(want) {
		t.Errorf("high-water = %v, want %v (fully drained query still advances to its safe boundary)", got, want)
	}
	points := rec.MetricPoints(wirecheck.MetricUnexpected)
	if len(points) != 1 || points[0].Value != 2 || points[0].Attrs[semconv.AttrField] != "event_time" || points[0].Attrs[semconv.AttrKind] != wirecheck.KindMissingField {
		t.Errorf("undated watchdog = %+v, want two missing event_time findings", points)
	}
}

// TestRun_EmptyIDRecordsAllEmitted proves #262: a record that maps to an empty
// id must never poison SeenIDs. Before the fix the first empty-id record was
// emitted and "" recorded in SeenIDs, so every later empty-id record in the
// window was silently deduped away — all-but-one of them lost, with nothing
// warning. Three empty-id records in one window must emit three events, "" must
// never enter the dedupe set, and the condition must surface on the
// graph2otel.api.unexpected watchdog rather than recover silently.
func TestRun_EmptyIDRecordsAllEmitted(t *testing.T) {
	rec := telemetrytest.New()
	from := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	to := from.Add(time.Hour)

	cfg := baseConfig()
	cfg.CollectorName = "m365.test"
	cfg.PageSize = 100

	page := "https://graph.microsoft.com/v1.0/security/auditLog/queries/query-1/records?$top=100"
	client := &fakeJobClient{
		statuses: []string{StatusSucceeded},
		pages: map[string]fakePage{
			// No "id" on any record: mapByID returns "" for each.
			page: {records: []map[string]any{
				{"createdDateTime": from.Add(1 * time.Minute).Format(time.RFC3339)},
				{"createdDateTime": from.Add(2 * time.Minute).Format(time.RFC3339)},
				{"createdDateTime": from.Add(3 * time.Minute).Format(time.RFC3339)},
			}},
		},
	}

	cp := newCheckpoint("t1", cfg.CreatePath)
	if _, err := Run(context.Background(), cfg, cp, from, to, client, rec.Emitter()); err != nil {
		t.Fatalf("Run: %v", err)
	}

	if logs := rec.LogRecords(); len(logs) != 3 {
		t.Fatalf("emitted %d log records, want 3 — an empty id must not dedupe later records away", len(logs))
	}
	if cp.SeenIDs.Has("") {
		t.Error(`"" entered SeenIDs — an empty id must never become a dedupe key`)
	}
	if pts := rec.MetricPoints(wirecheck.MetricUnexpected); len(pts) == 0 {
		t.Errorf("expected the %s watchdog counter to fire for the empty-id condition, got none", wirecheck.MetricUnexpected)
	}
}

// TestRun_SubmitPollPageEmits drives the whole cycle: create returns a query id,
// status runs notStarted→running→succeeded, then two record pages are drained
// via nextLink and every record is emitted once.
func TestRun_SubmitPollPageEmits(t *testing.T) {
	rec := telemetrytest.New()
	from := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	to := from.Add(time.Hour)

	sleeps := 0
	cfg := baseConfig()
	cfg.PageSize = 100
	cfg.Sleep = noSleep(&sleeps)

	page1 := "https://graph.microsoft.com/v1.0/security/auditLog/queries/query-1/records?$top=100"
	client := &fakeJobClient{
		statuses: []string{StatusNotStarted, StatusRunning, StatusSucceeded},
		pages: map[string]fakePage{
			page1: {records: []map[string]any{
				{"id": "a", "createdDateTime": from.Add(5 * time.Minute).Format(time.RFC3339)},
				{"id": "b", "createdDateTime": from.Add(6 * time.Minute).Format(time.RFC3339)},
			}, next: "https://next/page2"},
			"https://next/page2": {records: []map[string]any{
				{"id": "c", "createdDateTime": from.Add(7 * time.Minute).Format(time.RFC3339)},
			}},
		},
	}

	cp := newCheckpoint("t1", cfg.CreatePath)
	hw, err := Run(context.Background(), cfg, cp, from, to, client, rec.Emitter())
	if err != nil {
		t.Fatalf("Run: %v", err)
	}

	if logs := rec.LogRecords(); len(logs) != 3 {
		t.Fatalf("emitted %d log records, want 3 (a,b,c)", len(logs))
	}
	if client.statusCalls != 3 {
		t.Errorf("QueryStatus called %d times, want 3 (notStarted, running, succeeded)", client.statusCalls)
	}
	if client.pageCalls != 2 {
		t.Errorf("FetchRecordsPage called %d times, want 2 (nextLink drained)", client.pageCalls)
	}
	// Watermark advances to to-SafetyLag (window fully drained).
	wantHW := to.Add(-DefaultSafetyLag)
	if !hw.Equal(wantHW) {
		t.Errorf("high-water = %v, want %v (to - SafetyLag)", hw, wantHW)
	}
	if !cp.Watermark.Equal(wantHW) {
		t.Errorf("checkpoint watermark = %v, want %v", cp.Watermark, wantHW)
	}
}

// TestRun_RepeatedNextLinkFailsBeforeEmission pins #277's lossless failure
// mode: a query that points its nextLink back at a page already consumed must
// fail before the accumulated records can emit or the checkpoint can advance.
// Removing the URL-seen guard would make the fake's second fetch run and return
// its own error instead of the repeated-cursor error this test requires.
func TestRun_RepeatedNextLinkFailsBeforeEmission(t *testing.T) {
	rec := telemetrytest.New()
	from := time.Date(2026, 7, 25, 10, 0, 0, 0, time.UTC)
	to := from.Add(time.Hour)

	cfg := baseConfig()
	cfg.Now = fixedNow(to)
	pageURL := recordsURL("query-loop", DefaultPageSize)
	fetched := false
	client := &fakeJobClient{
		statuses: []string{StatusSucceeded},
		fetchPage: func(_ context.Context, got string) ([]map[string]any, string, error) {
			if got != pageURL {
				return nil, "", fmt.Errorf("fake fetch URL = %q, want %q", got, pageURL)
			}
			if fetched {
				return nil, "", errors.New("fake fetched repeated page")
			}
			fetched = true
			return []map[string]any{{
				"id":              "a",
				"createdDateTime": from.Add(time.Minute).Format(time.RFC3339),
			}}, pageURL, nil
		},
	}
	cp := newCheckpoint("t1", cfg.CreatePath)
	cp.InFlight = &checkpoint.InFlightJob{ID: "query-loop", CreatedAt: to.Add(-time.Minute), WindowFrom: from, WindowTo: to}

	_, err := Run(context.Background(), cfg, cp, from, to, client, rec.Emitter())
	if err == nil || !strings.Contains(err.Error(), "repeated records page") {
		t.Fatalf("Run error = %v, want repeated records page error", err)
	}
	if client.pageCalls != 1 {
		t.Errorf("FetchRecordsPage called %d times, want 1 — the repeated nextLink must be rejected before fetching it again", client.pageCalls)
	}
	if logs := rec.LogRecords(); len(logs) != 0 {
		t.Errorf("emitted %d records, want 0 before cursor failure", len(logs))
	}
	if !cp.Watermark.IsZero() || cp.InFlight == nil || cp.InFlight.ID != "query-loop" {
		t.Errorf("checkpoint changed after cursor failure: %+v", cp)
	}
}

// TestRun_RepeatedNextLinkAtPageCapReportsRepeat pins #277's precedence at the
// exact page-limit boundary. After maxRecordPages unique fetches, a nextLink
// that points back to page one has been observed twice and must report the
// repeated cursor, not the generic cap. Swapping the guards makes this fail.
func TestRun_RepeatedNextLinkAtPageCapReportsRepeat(t *testing.T) {
	rec := telemetrytest.New()
	from := time.Date(2026, 7, 25, 10, 0, 0, 0, time.UTC)
	to := from.Add(time.Hour)

	cfg := baseConfig()
	cfg.Now = fixedNow(to)
	firstPageURL := recordsURL("query-boundary-repeat", DefaultPageSize)
	client := &fakeJobClient{statuses: []string{StatusSucceeded}}
	client.fetchPage = func(_ context.Context, _ string) ([]map[string]any, string, error) {
		if client.pageCalls == maxRecordPages {
			return nil, firstPageURL, nil
		}
		return nil, "https://next/" + strconv.Itoa(client.pageCalls), nil
	}
	cp := newCheckpoint("t1", cfg.CreatePath)
	cp.InFlight = &checkpoint.InFlightJob{
		ID:         "query-boundary-repeat",
		CreatedAt:  to.Add(-time.Minute),
		WindowFrom: from,
		WindowTo:   to,
	}

	_, err := Run(context.Background(), cfg, cp, from, to, client, rec.Emitter())
	if err == nil || !strings.Contains(err.Error(), "repeated records page") {
		t.Fatalf("Run error = %v, want repeated records page error at the page-cap boundary", err)
	}
	if client.pageCalls != maxRecordPages {
		t.Errorf("FetchRecordsPage called %d times, want %d — the repeated cursor must be rejected before refetch", client.pageCalls, maxRecordPages)
	}
	if logs := rec.LogRecords(); len(logs) != 0 {
		t.Errorf("emitted %d records, want 0 before boundary cursor failure", len(logs))
	}
	if !cp.Watermark.IsZero() || cp.InFlight == nil || cp.InFlight.ID != "query-boundary-repeat" {
		t.Errorf("checkpoint changed after boundary cursor failure: %+v", cp)
	}
}

// TestRun_RecordPageCapFailsBeforeEmission prevents a non-converging walk with
// distinct cursors from growing the in-memory drain indefinitely. Removing the
// page cap lets the fake's pageLimit+1 fetch return its injected error instead
// of the guard error; neither case may emit or move the checkpoint.
func TestRun_RecordPageCapFailsBeforeEmission(t *testing.T) {
	const pageLimit = maxRecordPages

	rec := telemetrytest.New()
	from := time.Date(2026, 7, 25, 10, 0, 0, 0, time.UTC)
	to := from.Add(time.Hour)

	cfg := baseConfig()
	cfg.Now = fixedNow(to)
	client := &fakeJobClient{statuses: []string{StatusSucceeded}}
	client.fetchPage = func(_ context.Context, _ string) ([]map[string]any, string, error) {
		if client.pageCalls > pageLimit {
			return nil, "", errors.New("fake fetched beyond page cap")
		}
		return []map[string]any{{
			"id":              "record-" + strconv.Itoa(client.pageCalls),
			"createdDateTime": from.Add(time.Minute).Format(time.RFC3339),
		}}, "https://next/" + strconv.Itoa(client.pageCalls), nil
	}
	cp := newCheckpoint("t1", cfg.CreatePath)
	cp.InFlight = &checkpoint.InFlightJob{ID: "query-many-pages", CreatedAt: to.Add(-time.Minute), WindowFrom: from, WindowTo: to}

	_, err := Run(context.Background(), cfg, cp, from, to, client, rec.Emitter())
	if err == nil || !strings.Contains(err.Error(), "records pagination exceeded") {
		t.Fatalf("Run error = %v, want records pagination exceeded error", err)
	}
	if client.pageCalls != pageLimit {
		t.Errorf("FetchRecordsPage called %d times, want cap %d", client.pageCalls, pageLimit)
	}
	if logs := rec.LogRecords(); len(logs) != 0 {
		t.Errorf("emitted %d records, want 0 before page-cap failure", len(logs))
	}
	if !cp.Watermark.IsZero() || cp.InFlight == nil || cp.InFlight.ID != "query-many-pages" {
		t.Errorf("checkpoint changed after page-cap failure: %+v", cp)
	}
}

// TestRun_DedupesAcrossWindows verifies a record already in the checkpoint's
// SeenIDs (a prior overlapping window emitted it) is NOT re-emitted.
func TestRun_DedupesAcrossWindows(t *testing.T) {
	rec := telemetrytest.New()
	from := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	to := from.Add(time.Hour)
	sleeps := 0
	cfg := baseConfig()
	cfg.PageSize = DefaultPageSize
	cfg.Sleep = noSleep(&sleeps)

	pageURL := "https://graph.microsoft.com/v1.0/security/auditLog/queries/query-1/records?$top=" + strconv.Itoa(DefaultPageSize)
	client := &fakeJobClient{
		statuses: []string{StatusSucceeded},
		pages: map[string]fakePage{
			pageURL: {records: []map[string]any{
				{"id": "dup", "createdDateTime": from.Add(5 * time.Minute).Format(time.RFC3339)},
				{"id": "new", "createdDateTime": from.Add(6 * time.Minute).Format(time.RFC3339)},
			}},
		},
	}

	cp := newCheckpoint("t1", cfg.CreatePath)
	cp.OverlapWindow = cfg.Overlap
	cp.SeenIDs.Add("dup", from.Add(5*time.Minute)) // already emitted last window

	if _, err := Run(context.Background(), cfg, cp, from, to, client, rec.Emitter()); err != nil {
		t.Fatalf("Run: %v", err)
	}
	logs := rec.LogRecords()
	if len(logs) != 1 || logs[0].Attrs["id"] != "new" {
		t.Fatalf("emitted %v, want exactly the 'new' record (dup deduped)", logs)
	}
}

// TestRun_FailedStatusReturnsSentinel asserts a failed query surfaces
// ErrJobFailed and leaves the watermark unchanged (window retried next tick).
func TestRun_FailedStatusReturnsSentinel(t *testing.T) {
	rec := telemetrytest.New()
	from := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	to := from.Add(time.Hour)
	sleeps := 0
	cfg := baseConfig()
	cfg.Sleep = noSleep(&sleeps)

	client := &fakeJobClient{statuses: []string{StatusRunning, StatusFailed}}
	cp := newCheckpoint("t1", cfg.CreatePath)
	cp.Watermark = from // pre-existing watermark

	hw, err := Run(context.Background(), cfg, cp, from, to, client, rec.Emitter())
	if !errors.Is(err, ErrJobFailed) {
		t.Fatalf("err = %v, want ErrJobFailed", err)
	}
	if !hw.Equal(from) || !cp.Watermark.Equal(from) {
		t.Errorf("watermark advanced on failure: hw=%v cp=%v, want %v", hw, cp.Watermark, from)
	}
	if len(rec.LogRecords()) != 0 {
		t.Errorf("emitted records despite failed query")
	}
}

// TestRun_CancelledStatusReturnsSentinel asserts a cancelled query surfaces
// ErrJobCancelled.
func TestRun_CancelledStatusReturnsSentinel(t *testing.T) {
	rec := telemetrytest.New()
	from := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	to := from.Add(time.Hour)
	sleeps := 0
	cfg := baseConfig()
	cfg.Sleep = noSleep(&sleeps)

	client := &fakeJobClient{statuses: []string{StatusCancelled}}
	cp := newCheckpoint("t1", cfg.CreatePath)
	if _, err := Run(context.Background(), cfg, cp, from, to, client, rec.Emitter()); !errors.Is(err, ErrJobCancelled) {
		t.Fatalf("err = %v, want ErrJobCancelled", err)
	}
}

// TestRun_CreateRetriesOnErrorThenSucceeds asserts create-side backoff: two
// failed create calls (the documented rapid-submit 429) are retried and the
// third succeeds, with a Sleep between each retry.
func TestRun_CreateRetriesOnErrorThenSucceeds(t *testing.T) {
	rec := telemetrytest.New()
	from := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	to := from.Add(time.Hour)
	sleeps := 0
	cfg := baseConfig()
	cfg.CreateMaxRetries = 3
	cfg.Sleep = noSleep(&sleeps)

	throttle := errors.New("HTTP 429 Too Many Requests")
	pageURL := "https://graph.microsoft.com/v1.0/security/auditLog/queries/query-1/records?$top=" + strconv.Itoa(DefaultPageSize)
	client := &fakeJobClient{
		createErrs: []error{throttle, throttle, nil},
		statuses:   []string{StatusSucceeded},
		pages:      map[string]fakePage{pageURL: {}},
	}

	if _, err := Run(context.Background(), cfg, newCheckpoint("t1", cfg.CreatePath), from, to, client, rec.Emitter()); err != nil {
		t.Fatalf("Run: %v", err)
	}
	if client.createCalls != 3 {
		t.Errorf("CreateQuery called %d times, want 3 (2 throttled + 1 success)", client.createCalls)
	}
	if sleeps < 2 {
		t.Errorf("Sleep called %d times, want >= 2 (backoff between create retries)", sleeps)
	}
}

// TestRun_CreateGivesUpAfterMaxRetries asserts the create error surfaces after
// exhausting retries.
func TestRun_CreateGivesUpAfterMaxRetries(t *testing.T) {
	rec := telemetrytest.New()
	from := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	to := from.Add(time.Hour)
	sleeps := 0
	cfg := baseConfig()
	cfg.CreateMaxRetries = 2
	cfg.Sleep = noSleep(&sleeps)

	boom := errors.New("nope")
	client := &fakeJobClient{createErrs: []error{boom, boom, boom}}
	cp := newCheckpoint("t1", cfg.CreatePath)
	if _, err := Run(context.Background(), cfg, cp, from, to, client, rec.Emitter()); err == nil {
		t.Fatal("Run returned nil error after create exhausted retries")
	}
	if client.createCalls != 3 { // 1 + 2 retries
		t.Errorf("CreateQuery called %d times, want 3 (1 + CreateMaxRetries)", client.createCalls)
	}
}

// TestRunStampsAuditQueryTransport pins that every record this engine emits
// names the transport that produced it (#141).
func TestRunStampsAuditQueryTransport(t *testing.T) {
	rec := telemetrytest.New()
	from := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	to := from.Add(time.Hour)

	sleeps := 0
	cfg := baseConfig()
	cfg.PageSize = 100
	cfg.Sleep = noSleep(&sleeps)

	page1 := "https://graph.microsoft.com/v1.0/security/auditLog/queries/query-1/records?$top=100"
	client := &fakeJobClient{
		statuses: []string{StatusSucceeded},
		pages: map[string]fakePage{
			page1: {records: []map[string]any{
				{"id": "a", "createdDateTime": from.Add(5 * time.Minute).Format(time.RFC3339)},
			}},
		},
	}

	if _, err := Run(context.Background(), cfg, newCheckpoint("t1", cfg.CreatePath), from, to, client, rec.Emitter()); err != nil {
		t.Fatalf("Run: %v", err)
	}

	logs := rec.LogRecords()
	if len(logs) != 1 {
		t.Fatalf("got %d log records, want 1", len(logs))
	}
	if got := logs[0].Attrs[semconv.AttrIngestTransport]; got != string(telemetry.TransportAuditQuery) {
		t.Errorf("%s = %q, want %q", semconv.AttrIngestTransport, got, telemetry.TransportAuditQuery)
	}
}
