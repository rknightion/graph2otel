package logpipeline

import (
	"context"
	"testing"
	"time"

	"github.com/rknightion/graph2otel/internal/semconv"
	"github.com/rknightion/graph2otel/internal/telemetrytest"
)

// --- exclude_self on the Graph-polled transport (#176) ---
//
// These mirror the blobpipeline exclude_self guards one transport over: a record
// whose appId is the tenant's own poller client_id is dropped, a third party's
// record always passes, and every drop is loudly counted per collector.

const selfWindow = time.Hour

// flatAppID reads the top-level "appId" — the field the real signins mapper reads
// (str(rec, "appId")) for the service-principal stream. Used as SelfAppID here.
func flatAppID(rec map[string]any) string {
	s, _ := rec["appId"].(string)
	return s
}

// mapByIDApp is mapByID plus an appId carrier, so the record reaching Poll has
// both a dedupe id (also the body) and an appId for the self filter to read.
func selfRecord(id, appID string, at time.Time) map[string]any {
	return map[string]any{
		"id":              id,
		"appId":           appID,
		"createdDateTime": at.Format(time.RFC3339),
	}
}

func selfExcludeConfig(excludeSelf bool, selfClientID string, selfAppID func(map[string]any) string) EndpointConfig {
	return EndpointConfig{
		Path:            "/auditLogs/signIns",
		TimeField:       "createdDateTime",
		Flavor:          FlavorGeLe,
		OrderByReliable: true,
		Map:             mapByID,
		ExcludeSelf:     excludeSelf,
		SelfClientID:    selfClientID,
		SelfAppID:       selfAppID,
		CollectorName:   "entra.signins.service_principal",
	}
}

func onePageFetcher(recs []map[string]any) PageFetcher {
	return pageFetcherFunc(func(_ context.Context, _ string) ([]map[string]any, string, error) {
		return recs, "", nil
	})
}

// TestPollExcludesSelfSignInsButNotThirdParty is the #176 guard: a
// service-principal sign-in whose appId is the poller's own client_id is dropped,
// and any other appId always passes through.
func TestPollExcludesSelfSignInsButNotThirdParty(t *testing.T) {
	rec := telemetrytest.New()
	from := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	to := from.Add(selfWindow)
	recs := []map[string]any{
		selfRecord("self", "POLLER", from.Add(10*time.Minute)),
		selfRecord("other", "THIRDPARTY", from.Add(20*time.Minute)),
	}
	cfg := selfExcludeConfig(true, "POLLER", flatAppID)
	cp := newCheckpoint("t1", cfg.Path)
	if _, err := Poll(context.Background(), cfg, cp, from, to, onePageFetcher(recs), rec.Emitter()); err != nil {
		t.Fatalf("Poll: %v", err)
	}
	logs := rec.LogRecords()
	if len(logs) != 1 || logs[0].Body != "other" {
		t.Fatalf("emitted %+v, want only the third-party record [other]", logs)
	}
}

// TestPollDoesNotFilterWhenExcludeSelfIsOff is the default-off regression guard.
func TestPollDoesNotFilterWhenExcludeSelfIsOff(t *testing.T) {
	rec := telemetrytest.New()
	from := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	to := from.Add(selfWindow)
	recs := []map[string]any{
		selfRecord("self", "POLLER", from.Add(10*time.Minute)),
		selfRecord("other", "THIRDPARTY", from.Add(20*time.Minute)),
	}
	cfg := selfExcludeConfig(false, "POLLER", flatAppID)
	cp := newCheckpoint("t1", cfg.Path)
	if _, err := Poll(context.Background(), cfg, cp, from, to, onePageFetcher(recs), rec.Emitter()); err != nil {
		t.Fatalf("Poll: %v", err)
	}
	if logs := rec.LogRecords(); len(logs) != 2 {
		t.Fatalf("emitted %d logs, want both (filter off): %+v", len(logs), logs)
	}
	if pts := rec.MetricPoints(metricSelfExcluded); len(pts) != 0 {
		t.Errorf("self_excluded points = %d, want 0 with exclude_self off", len(pts))
	}
}

// TestPollCountsEverySelfExclusionPerCollector pins the loud-drop contract: one
// counter increment per excluded record, labeled with the collector.
func TestPollCountsEverySelfExclusionPerCollector(t *testing.T) {
	rec := telemetrytest.New()
	from := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	to := from.Add(selfWindow)
	recs := []map[string]any{
		selfRecord("s1", "POLLER", from.Add(10*time.Minute)),
		selfRecord("other", "THIRDPARTY", from.Add(20*time.Minute)),
		selfRecord("s2", "POLLER", from.Add(30*time.Minute)),
	}
	cfg := selfExcludeConfig(true, "POLLER", flatAppID)
	cp := newCheckpoint("t1", cfg.Path)
	if _, err := Poll(context.Background(), cfg, cp, from, to, onePageFetcher(recs), rec.Emitter()); err != nil {
		t.Fatalf("Poll: %v", err)
	}
	pts := rec.MetricPoints(metricSelfExcluded)
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
	if p.Attrs[semconv.AttrCollector] != "entra.signins.service_principal" {
		t.Errorf("collector attr = %q, want entra.signins.service_principal", p.Attrs[semconv.AttrCollector])
	}
}

// TestPollNeverFiltersWhenSelfAppIDIsNil models a stream whose records carry no
// appId (every other sign-in stream): nil SelfAppID never filters.
func TestPollNeverFiltersWhenSelfAppIDIsNil(t *testing.T) {
	rec := telemetrytest.New()
	from := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	to := from.Add(selfWindow)
	recs := []map[string]any{
		selfRecord("a", "POLLER", from.Add(10*time.Minute)),
		selfRecord("b", "POLLER", from.Add(20*time.Minute)),
	}
	cfg := selfExcludeConfig(true, "POLLER", nil)
	cp := newCheckpoint("t1", cfg.Path)
	if _, err := Poll(context.Background(), cfg, cp, from, to, onePageFetcher(recs), rec.Emitter()); err != nil {
		t.Fatalf("Poll: %v", err)
	}
	if logs := rec.LogRecords(); len(logs) != 2 {
		t.Errorf("emitted %d, want both (nil SelfAppID never filters)", len(logs))
	}
	if pts := rec.MetricPoints(metricSelfExcluded); len(pts) != 0 {
		t.Errorf("self_excluded points = %d, want 0 for a nil-SelfAppID stream", len(pts))
	}
}

// TestPollNeverFiltersWhenSelfClientIDIsEmpty guards "self is unknown": an empty
// client_id must not make an empty-appId record match as self.
func TestPollNeverFiltersWhenSelfClientIDIsEmpty(t *testing.T) {
	rec := telemetrytest.New()
	from := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	to := from.Add(selfWindow)
	recs := []map[string]any{
		selfRecord("a", "", from.Add(10*time.Minute)),
		selfRecord("b", "THIRDPARTY", from.Add(20*time.Minute)),
	}
	cfg := selfExcludeConfig(true, "", flatAppID)
	cp := newCheckpoint("t1", cfg.Path)
	if _, err := Poll(context.Background(), cfg, cp, from, to, onePageFetcher(recs), rec.Emitter()); err != nil {
		t.Fatalf("Poll: %v", err)
	}
	if logs := rec.LogRecords(); len(logs) != 2 {
		t.Errorf("emitted %d, want both (empty SelfClientID never filters)", len(logs))
	}
	if pts := rec.MetricPoints(metricSelfExcluded); len(pts) != 0 {
		t.Errorf("self_excluded points = %d, want 0 when SelfClientID is empty", len(pts))
	}
}
