package jobpipeline

import (
	"context"
	"errors"
	"strconv"
	"testing"
	"time"

	"github.com/rknightion/graph2otel/internal/checkpoint"
	"github.com/rknightion/graph2otel/internal/semconv"
	"github.com/rknightion/graph2otel/internal/telemetry"
	"github.com/rknightion/graph2otel/internal/telemetrytest"
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

func (f *fakeJobClient) FetchRecordsPage(_ context.Context, pageURL string) ([]map[string]any, string, error) {
	f.pageCalls++
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
