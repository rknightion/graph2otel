package logpipeline

import (
	"context"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/rknightion/graph2otel/internal/checkpoint"
	"github.com/rknightion/graph2otel/internal/graphclient"
	"github.com/rknightion/graph2otel/internal/telemetry"
	"github.com/rknightion/graph2otel/internal/telemetrytest"
)

// pageFetcherFunc adapts a plain function to PageFetcher, so tests can drive
// Poll without a real Graph client.
type pageFetcherFunc func(ctx context.Context, pageURL string) ([]map[string]any, string, error)

func (f pageFetcherFunc) FetchPage(ctx context.Context, pageURL string) ([]map[string]any, string, error) {
	return f(ctx, pageURL)
}

// mapByID is a minimal EndpointConfig.Map: the record's "id" field is both
// the dedupe id and the sole log attribute.
func mapByID(record map[string]any) (string, telemetry.Event) {
	id, _ := record["id"].(string)
	return id, telemetry.Event{
		Name:  "test.event",
		Body:  id,
		Attrs: telemetry.Attrs{"id": id},
	}
}

func newCheckpoint(tenantID, endpoint string) *checkpoint.Checkpoint {
	return &checkpoint.Checkpoint{TenantID: tenantID, Endpoint: endpoint, SeenIDs: checkpoint.NewSeenIDs()}
}

// TestPollDrainsAllPagesViaNextLink verifies a two-page response is fully
// drained by following @odata.nextLink, and every record across both pages
// is emitted.
func TestPollDrainsAllPagesViaNextLink(t *testing.T) {
	rec := telemetrytest.New()
	cfg := EndpointConfig{
		Path:            "/auditLogs/signIns",
		TimeField:       "createdDateTime",
		Flavor:          FlavorGeLe,
		OrderByReliable: true,
		Map:             mapByID,
	}
	from := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	to := from.Add(time.Hour)

	calls := 0
	fetcher := pageFetcherFunc(func(_ context.Context, _ string) ([]map[string]any, string, error) {
		calls++
		switch calls {
		case 1:
			return []map[string]any{
				{"id": "a", "createdDateTime": from.Add(10 * time.Minute).Format(time.RFC3339)},
				{"id": "b", "createdDateTime": from.Add(20 * time.Minute).Format(time.RFC3339)},
			}, "https://graph.microsoft.com/v1.0/auditLogs/signIns?$skiptoken=page2", nil
		case 2:
			return []map[string]any{
				{"id": "c", "createdDateTime": from.Add(30 * time.Minute).Format(time.RFC3339)},
			}, "", nil
		default:
			t.Fatalf("unexpected page fetch #%d", calls)
			return nil, "", nil
		}
	})

	cp := newCheckpoint("t1", cfg.Path)
	if _, err := Poll(context.Background(), cfg, cp, from, to, fetcher, rec.Emitter()); err != nil {
		t.Fatalf("Poll: %v", err)
	}
	if calls != 2 {
		t.Fatalf("expected 2 page fetches (initial + one nextLink follow), got %d", calls)
	}
	logs := rec.LogRecords()
	if len(logs) != 3 {
		t.Fatalf("expected 3 emitted logs across both pages, got %d: %+v", len(logs), logs)
	}
}

// TestPollDedupesAcrossPollCycles verifies a record already recorded in
// SeenIDs (i.e. re-returned by Graph within the overlap window on a later
// poll) is emitted exactly once, not once per poll.
func TestPollDedupesAcrossPollCycles(t *testing.T) {
	rec := telemetrytest.New()
	cfg := EndpointConfig{
		Path:            "/auditLogs/signIns",
		TimeField:       "createdDateTime",
		Flavor:          FlavorGeLe,
		OrderByReliable: true,
		Map:             mapByID,
	}
	from := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	to := from.Add(time.Hour)

	fetcher := pageFetcherFunc(func(_ context.Context, _ string) ([]map[string]any, string, error) {
		return []map[string]any{
			{"id": "a", "createdDateTime": from.Add(10 * time.Minute).Format(time.RFC3339)},
		}, "", nil
	})

	cp := newCheckpoint("t1", cfg.Path)
	if _, err := Poll(context.Background(), cfg, cp, from, to, fetcher, rec.Emitter()); err != nil {
		t.Fatalf("Poll #1: %v", err)
	}
	if _, err := Poll(context.Background(), cfg, cp, from, to, fetcher, rec.Emitter()); err != nil {
		t.Fatalf("Poll #2: %v", err)
	}

	logs := rec.LogRecords()
	if len(logs) != 1 {
		t.Fatalf("expected record 'a' emitted exactly once across two poll cycles, got %d: %+v", len(logs), logs)
	}
}

// TestPollAdvancesWatermarkMinusSafetyLagAndPersists verifies the high-water
// mark returned by Poll is newest-drained-timestamp - SafetyLag, and that it
// round-trips through a real checkpoint.Store so a restart resumes from
// watermark - overlap.
func TestPollAdvancesWatermarkMinusSafetyLagAndPersists(t *testing.T) {
	rec := telemetrytest.New()
	store := checkpoint.NewStore(t.TempDir())

	cfg := EndpointConfig{
		Path:            "/auditLogs/signIns",
		TimeField:       "createdDateTime",
		Flavor:          FlavorGeLe,
		OrderByReliable: true,
		SafetyLag:       15 * time.Minute,
		Overlap:         2 * time.Hour,
		Map:             mapByID,
	}
	from := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	to := from.Add(time.Hour)
	newestEvent := from.Add(45 * time.Minute)

	fetcher := pageFetcherFunc(func(_ context.Context, _ string) ([]map[string]any, string, error) {
		return []map[string]any{
			{"id": "a", "createdDateTime": newestEvent.Format(time.RFC3339)},
		}, "", nil
	})

	cp, err := store.Load("tenant1", cfg.Path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	hw, err := Poll(context.Background(), cfg, cp, from, to, fetcher, rec.Emitter())
	if err != nil {
		t.Fatalf("Poll: %v", err)
	}
	wantHW := newestEvent.Add(-cfg.SafetyLag)
	if !hw.Equal(wantHW) {
		t.Fatalf("high water = %v, want %v", hw, wantHW)
	}
	if err := store.Save(cp); err != nil {
		t.Fatalf("Save: %v", err)
	}

	reloaded, err := store.Load("tenant1", cfg.Path)
	if err != nil {
		t.Fatalf("reload: %v", err)
	}
	if !reloaded.Watermark.Equal(wantHW) {
		t.Fatalf("reloaded watermark = %v, want %v", reloaded.Watermark, wantHW)
	}

	resumeFrom := reloaded.Watermark.Add(-reloaded.OverlapWindow)
	wantResume := wantHW.Add(-cfg.Overlap)
	if !resumeFrom.Equal(wantResume) {
		t.Fatalf("restart resume-from = %v, want watermark - overlap = %v", resumeFrom, wantResume)
	}
}

// TestPollCapturesLateArrivingEventInsideOverlap verifies an event whose
// timestamp is older than a prior poll's watermark, but which only shows up
// on a later poll (e.g. Graph indexed it late), is still captured as long as
// the caller re-queries the overlap window that contains it — dedupe is by
// id, never by "is this older than the watermark".
func TestPollCapturesLateArrivingEventInsideOverlap(t *testing.T) {
	rec := telemetrytest.New()
	cfg := EndpointConfig{
		Path:            "/auditLogs/signIns",
		TimeField:       "createdDateTime",
		Flavor:          FlavorGeLe,
		OrderByReliable: true,
		SafetyLag:       5 * time.Minute,
		Overlap:         2 * time.Hour,
		Map:             mapByID,
	}
	base := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	cp := newCheckpoint("t1", cfg.Path)

	fetch1 := pageFetcherFunc(func(_ context.Context, _ string) ([]map[string]any, string, error) {
		return []map[string]any{
			{"id": "a", "createdDateTime": base.Add(10 * time.Minute).Format(time.RFC3339)},
		}, "", nil
	})
	if _, err := Poll(context.Background(), cfg, cp, base, base.Add(30*time.Minute), fetch1, rec.Emitter()); err != nil {
		t.Fatalf("Poll cycle 1: %v", err)
	}

	// Cycle 2 re-queries back to `base` (the overlap window) and Graph now
	// also surfaces a late-arriving "z" event timestamped BEFORE cycle 1's
	// watermark, alongside the already-seen "a".
	fetch2 := pageFetcherFunc(func(_ context.Context, _ string) ([]map[string]any, string, error) {
		return []map[string]any{
			{"id": "z", "createdDateTime": base.Add(3 * time.Minute).Format(time.RFC3339)},
			{"id": "a", "createdDateTime": base.Add(10 * time.Minute).Format(time.RFC3339)},
		}, "", nil
	})
	if _, err := Poll(context.Background(), cfg, cp, base, base.Add(30*time.Minute), fetch2, rec.Emitter()); err != nil {
		t.Fatalf("Poll cycle 2: %v", err)
	}

	logs := rec.LogRecords()
	if len(logs) != 2 {
		t.Fatalf("expected 2 emitted logs total ('a' once, 'z' once), got %d: %+v", len(logs), logs)
	}
	seen := map[string]bool{}
	for _, l := range logs {
		seen[l.Attrs["id"]] = true
	}
	if !seen["z"] {
		t.Fatalf("expected late-arriving event 'z' to be captured, logs=%+v", logs)
	}
	if !seen["a"] {
		t.Fatalf("expected 'a' still present exactly once, logs=%+v", logs)
	}
}

// TestBuildFilterGeLe verifies the ge/le operator pair used for endpoints
// where $orderby asc is reliable (signIns, directoryAudits).
func TestBuildFilterGeLe(t *testing.T) {
	cfg := EndpointConfig{TimeField: "createdDateTime", Flavor: FlavorGeLe}
	from := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	to := time.Date(2026, 1, 1, 1, 0, 0, 0, time.UTC)

	got := buildFilter(cfg, from, to)
	want := "createdDateTime ge 2026-01-01T00:00:00Z and createdDateTime le 2026-01-01T01:00:00Z"
	if got != want {
		t.Fatalf("buildFilter(GeLe) = %q, want %q", got, want)
	}
}

// TestBuildFilterGtLt verifies the strict gt/lt operator pair used for
// endpoints where $orderby is unreliable (provisioning).
func TestBuildFilterGtLt(t *testing.T) {
	cfg := EndpointConfig{TimeField: "activityDateTime", Flavor: FlavorGtLt}
	from := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	to := time.Date(2026, 1, 1, 1, 0, 0, 0, time.UTC)

	got := buildFilter(cfg, from, to)
	want := "activityDateTime gt 2026-01-01T00:00:00Z and activityDateTime lt 2026-01-01T01:00:00Z"
	if got != want {
		t.Fatalf("buildFilter(GtLt) = %q, want %q", got, want)
	}
}

// TestBuildFilterAppendsFilterExtra verifies that a non-empty FilterExtra is
// ANDed onto the time-window clause (parenthesized), so an endpoint like the
// beta signInEventTypes-filtered sign-in streams can narrow the window query
// without re-implementing the time bounds.
func TestBuildFilterAppendsFilterExtra(t *testing.T) {
	cfg := EndpointConfig{
		TimeField:   "createdDateTime",
		Flavor:      FlavorGeLe,
		FilterExtra: "signInEventTypes/any(t: t eq 'nonInteractiveUser')",
	}
	from := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	to := time.Date(2026, 1, 1, 1, 0, 0, 0, time.UTC)

	got := buildFilter(cfg, from, to)
	want := "createdDateTime ge 2026-01-01T00:00:00Z and createdDateTime le 2026-01-01T01:00:00Z and (signInEventTypes/any(t: t eq 'nonInteractiveUser'))"
	if got != want {
		t.Fatalf("buildFilter(+FilterExtra) = %q, want %q", got, want)
	}
}

// TestBuildFirstURLBaseURLOverride verifies that BaseURLOverride replaces the
// default v1.0 service root for the first page (the beta signInEventTypes
// streams need /beta), while the path still carries cfg.Path so workload
// classification is unaffected.
func TestBuildFirstURLBaseURLOverride(t *testing.T) {
	cfg := EndpointConfig{
		Path:            "/auditLogs/signIns",
		TimeField:       "createdDateTime",
		Flavor:          FlavorGeLe,
		OrderByReliable: true,
		BaseURLOverride: "https://graph.microsoft.com/beta",
		PageSize:        100,
	}
	from := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	to := from.Add(time.Hour)

	raw := buildFirstURL(cfg, from, to)
	if !strings.HasPrefix(raw, "https://graph.microsoft.com/beta/auditLogs/signIns?") {
		t.Fatalf("built URL = %q, want it to start with the beta base + path", raw)
	}
	u, err := url.Parse(raw)
	if err != nil {
		t.Fatalf("url.Parse(%q): %v", raw, err)
	}
	// Beta prefix must not defeat workload classification (Contains-based).
	if workload := graphclient.ClassifyWorkload(u.Path); workload != graphclient.WorkloadReporting {
		t.Fatalf("ClassifyWorkload(%q) = %q, want %q even on the beta path", u.Path, workload, graphclient.WorkloadReporting)
	}
}

// TestBuildFirstURLOmitsFilterWhenNoServerFilter verifies that an endpoint
// flagged NoServerFilter (e.g. Intune troubleshootingEvents / autopilotEvents,
// which reject a server-side $filter on their time field) gets NO $filter query
// param — the window is bounded client-side in Poll instead. $top still applies,
// and $orderby only when the order is trusted.
func TestBuildFirstURLOmitsFilterWhenNoServerFilter(t *testing.T) {
	cfg := EndpointConfig{
		Path:           "/deviceManagement/autopilotEvents",
		TimeField:      "eventDateTime",
		Flavor:         FlavorGeLe,
		NoServerFilter: true,
		PageSize:       100,
	}
	from := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	to := from.Add(time.Hour)

	raw := buildFirstURL(cfg, from, to)
	u, err := url.Parse(raw)
	if err != nil {
		t.Fatalf("url.Parse(%q): %v", raw, err)
	}
	if got := u.Query().Get("$filter"); got != "" {
		t.Errorf("$filter = %q, want empty (NoServerFilter omits the server-side time filter)", got)
	}
	if got := u.Query().Get("$top"); got != "100" {
		t.Errorf("$top = %q, want 100 (page size still applies)", got)
	}
}

// TestPollClientSideWindowFiltersWhenNoServerFilter verifies that when the
// server-side $filter is omitted (NoServerFilter), Poll drops records outside
// [from, to] client-side — so an event newer than `to` (inside the SafetyLag
// tail) is not emitted early and does not push the watermark past to-SafetyLag,
// and an event older than `from` is not re-emitted.
func TestPollClientSideWindowFiltersWhenNoServerFilter(t *testing.T) {
	rec := telemetrytest.New()
	store := checkpoint.NewStore(t.TempDir())

	cfg := EndpointConfig{
		Path:           "/deviceManagement/troubleshootingEvents",
		TimeField:      "eventDateTime",
		Flavor:         FlavorGeLe,
		NoServerFilter: true,
		SafetyLag:      15 * time.Minute,
		Overlap:        2 * time.Hour,
		Map:            mapByID,
	}
	from := time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)
	to := from.Add(time.Hour)
	inWindow := from.Add(30 * time.Minute)
	beforeWindow := from.Add(-time.Hour)
	afterWindow := to.Add(30 * time.Minute)

	fetcher := pageFetcherFunc(func(_ context.Context, _ string) ([]map[string]any, string, error) {
		return []map[string]any{
			{"id": "before", "eventDateTime": beforeWindow.Format(time.RFC3339)},
			{"id": "in", "eventDateTime": inWindow.Format(time.RFC3339)},
			{"id": "after", "eventDateTime": afterWindow.Format(time.RFC3339)},
		}, "", nil
	})

	cp, err := store.Load("tenant1", cfg.Path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	hw, err := Poll(context.Background(), cfg, cp, from, to, fetcher, rec.Emitter())
	if err != nil {
		t.Fatalf("Poll: %v", err)
	}

	logs := rec.LogRecords()
	var ids []string
	for _, l := range logs {
		ids = append(ids, l.Attrs["id"])
	}
	if len(ids) != 1 || ids[0] != "in" {
		t.Fatalf("emitted ids = %v, want exactly [in] (before/after are outside the window)", ids)
	}
	// Watermark must reflect the in-window event, never the after-window one.
	wantHW := inWindow.Add(-cfg.SafetyLag)
	if !hw.Equal(wantHW) {
		t.Errorf("high water = %v, want in-window(%v) - safetyLag = %v", hw, inWindow, wantHW)
	}
}

// TestPollSortsClientSideWhenOrderByUnreliable verifies that for an endpoint
// flagged OrderByReliable=false, Poll sorts the drained window by event time
// before emitting rather than trusting server order, and that the returned
// high-water mark still reflects the true newest (post-sort) event.
func TestPollSortsClientSideWhenOrderByUnreliable(t *testing.T) {
	rec := telemetrytest.New()
	cfg := EndpointConfig{
		Path:            "/identityGovernance/provisioning/logs",
		TimeField:       "activityDateTime",
		Flavor:          FlavorGtLt,
		OrderByReliable: false,
		Map:             mapByID,
	}
	base := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)

	// Server returns records out of chronological order.
	fetcher := pageFetcherFunc(func(_ context.Context, _ string) ([]map[string]any, string, error) {
		return []map[string]any{
			{"id": "late", "activityDateTime": base.Add(50 * time.Minute).Format(time.RFC3339)},
			{"id": "early", "activityDateTime": base.Add(5 * time.Minute).Format(time.RFC3339)},
			{"id": "mid", "activityDateTime": base.Add(25 * time.Minute).Format(time.RFC3339)},
		}, "", nil
	})

	cp := newCheckpoint("t1", cfg.Path)
	hw, err := Poll(context.Background(), cfg, cp, base, base.Add(time.Hour), fetcher, rec.Emitter())
	if err != nil {
		t.Fatalf("Poll: %v", err)
	}

	logs := rec.LogRecords()
	if len(logs) != 3 {
		t.Fatalf("expected 3 logs, got %d", len(logs))
	}
	gotOrder := []string{logs[0].Attrs["id"], logs[1].Attrs["id"], logs[2].Attrs["id"]}
	wantOrder := []string{"early", "mid", "late"}
	for i := range wantOrder {
		if gotOrder[i] != wantOrder[i] {
			t.Fatalf("emission order = %v, want %v (client-side sort by event time, not server order)", gotOrder, wantOrder)
		}
	}

	wantHW := base.Add(50 * time.Minute).Add(-DefaultSafetyLag)
	if !hw.Equal(wantHW) {
		t.Fatalf("high water = %v, want %v", hw, wantHW)
	}
}

// TestBuildFirstURLPathMatchesConfigAndClassifiesWorkload documents and
// asserts that Poll's first-page URL carries cfg.Path verbatim, so the
// transport's path-based workload classification (graphclient.
// ClassifyWorkload) routes every request through the correct client-side
// rate limiter without this package doing any limiting itself.
func TestBuildFirstURLPathMatchesConfigAndClassifiesWorkload(t *testing.T) {
	cfg := EndpointConfig{
		Path:            "/auditLogs/signIns",
		TimeField:       "createdDateTime",
		Flavor:          FlavorGeLe,
		OrderByReliable: true,
		PageSize:        100,
	}
	from := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	to := from.Add(time.Hour)

	raw := buildFirstURL(cfg, from, to)
	u, err := url.Parse(raw)
	if err != nil {
		t.Fatalf("url.Parse(%q): %v", raw, err)
	}
	if !strings.Contains(u.Path, cfg.Path) {
		t.Fatalf("built URL path = %q, want it to contain EndpointConfig.Path %q", u.Path, cfg.Path)
	}
	if workload := graphclient.ClassifyWorkload(u.Path); workload != graphclient.WorkloadReporting {
		t.Fatalf("ClassifyWorkload(%q) = %q, want %q", u.Path, workload, graphclient.WorkloadReporting)
	}
}
