package deleteditems

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/rknightion/graph2otel/internal/collectors"
	"github.com/rknightion/graph2otel/internal/semconv"
	"github.com/rknightion/graph2otel/internal/telemetrytest"
)

// fakeGraph maps request URLs to canned page bodies (or errors), satisfying
// collectors.GraphClient so Collect runs through collectors.GetAllValues with no
// live Graph call.
type fakeGraph struct {
	bodies map[string]string
	errs   map[string]error
}

func (f *fakeGraph) RawGet(ctx context.Context, url string) ([]byte, error) {
	return f.RawGetWithHeaders(ctx, url, nil)
}

func (f *fakeGraph) RawGetWithHeaders(_ context.Context, url string, _ map[string]string) ([]byte, error) {
	if err, ok := f.errs[url]; ok {
		return nil, err
	}
	return []byte(f.bodies[url]), nil
}

var _ collectors.GraphClient = (*fakeGraph)(nil)

func urlFor(segment, selectQ string) string {
	return base + "/directory/deletedItems/" + segment + "?$select=" + selectQ
}

const base = "https://graph.microsoft.com/v1.0"

// The five bodies below wrap VERBATIM /directory/deletedItems records read as
// graph2otel-poller on 2026-07-19 (#191), each fetched with the exact $select the
// collector uses. They are the real tombstones on m7kni — a #129 risk-synth user,
// a test group, the IntuneManager app deleted 44 days prior (still recoverable —
// see isNearPurge), a seed service principal, and a Cloud PC device.
// `[live-measured 2026-07-19, #191]`
const (
	liveUser  = `{"value":[{"id":"0242e69b-1c42-4b68-a439-b2165a66001f","displayName":"cloud 1","deletedDateTime":"2026-07-19T15:34:35Z","userPrincipalName":"0242e69b1c424b68a439b2165a66001fcloud1@m7kni.io"}]}`
	liveGroup = `{"value":[{"id":"22c4bfe4-e1b9-414c-be78-13e70c922644","displayName":"rmcf-test","deletedDateTime":"2026-07-15T19:21:28Z"}]}`
	liveApp   = `{"value":[{"id":"45e87078-3c93-4764-8a1a-7b28ef5b501c","displayName":"IntuneManager","deletedDateTime":"2026-06-05T17:54:57Z","appId":"d67d159b-3538-485e-a445-dafdd6f890f1"}]}`
	liveSP    = `{"value":[{"id":"31c44dcb-9fd3-4838-afbe-83df88fca7a0","displayName":"g2o-seed-temp","deletedDateTime":"2026-07-18T15:17:15Z","appId":"f5110a7d-8d15-449c-b11b-63fd0bc10a8c"}]}`
	liveDev   = `{"value":[{"id":"24c032ec-c819-4a91-b610-35756db39972","displayName":"CPC-rob-TDQ7UEM","deletedDateTime":"2026-07-19T16:11:31Z","deviceId":"8d6f24ec-0a02-453a-881f-23d6aac2019b"}]}`
)

func liveGraph() *fakeGraph {
	return &fakeGraph{bodies: map[string]string{
		urlFor("microsoft.graph.user", "id,displayName,deletedDateTime,userPrincipalName"): liveUser,
		urlFor("microsoft.graph.group", "id,displayName,deletedDateTime"):                  liveGroup,
		urlFor("microsoft.graph.application", "id,displayName,deletedDateTime,appId"):      liveApp,
		urlFor("microsoft.graph.servicePrincipal", "id,displayName,deletedDateTime,appId"): liveSP,
		urlFor("microsoft.graph.device", "id,displayName,deletedDateTime,deviceId"):        liveDev,
	}}
}

// probeTime is the poll instant used in tests: the moment the fixtures were read.
// At this instant only the IntuneManager app (deleted 44 days prior) is
// near-purge; every other tombstone is recent.
var probeTime = time.Date(2026, 7, 19, 18, 0, 0, 0, time.UTC)

func newCollector(g collectors.GraphClient) *Collector {
	c := New(g, nil)
	c.now = func() time.Time { return probeTime }
	return c
}

// TestCollectCensusGaugeAndTwinsEndToEnd drives all five live fixtures through
// Collect: one gauge point per type, and one log twin per object with the
// type-specific identifier mapped.
func TestCollectCensusGaugeAndTwinsEndToEnd(t *testing.T) {
	rec := telemetrytest.New()
	if err := newCollector(liveGraph()).Collect(context.Background(), rec.Emitter()); err != nil {
		t.Fatalf("Collect: %v", err)
	}

	pts := rec.MetricPoints(metricDeletedItems)
	if len(pts) != 5 {
		t.Fatalf("gauge points = %d, want 5 (one per object type): %+v", len(pts), pts)
	}
	byType := map[string]telemetrytest.MetricPoint{}
	for _, p := range pts {
		if p.Value != 1 {
			t.Errorf("%s value = %v, want 1", p.Attrs[semconv.AttrObjectType], p.Value)
		}
		byType[p.Attrs[semconv.AttrObjectType]] = p
	}
	for _, ty := range []string{"user", "group", "application", "servicePrincipal", "device"} {
		if _, ok := byType[ty]; !ok {
			t.Errorf("no gauge series for object_type=%q", ty)
		}
	}
	// Only the 44-day-old application is near-purge at probeTime.
	if got := byType["application"].Attrs[semconv.AttrNearPurge]; got != "true" {
		t.Errorf("application near_purge = %q, want true (deleted 44d ago)", got)
	}
	if got := byType["user"].Attrs[semconv.AttrNearPurge]; got != "false" {
		t.Errorf("user near_purge = %q, want false (deleted hours ago)", got)
	}

	logs := rec.LogRecords()
	if len(logs) != 5 {
		t.Fatalf("log twins = %d, want 5 (one per object)", len(logs))
	}
	twin := map[string]telemetrytest.LogRecord{}
	for _, l := range logs {
		if l.EventName != eventDeletedItem {
			t.Errorf("event name = %q, want %q", l.EventName, eventDeletedItem)
		}
		twin[l.Attrs[semconv.AttrObjectType]] = l
	}
	if got := twin["user"].Attrs[semconv.AttrUserPrincipalName]; got != "0242e69b1c424b68a439b2165a66001fcloud1@m7kni.io" {
		t.Errorf("user twin UPN = %q", got)
	}
	if got := twin["application"].Attrs[semconv.AttrAppId]; got != "d67d159b-3538-485e-a445-dafdd6f890f1" {
		t.Errorf("application twin app_id = %q", got)
	}
	if got := twin["device"].Attrs[semconv.AttrDeviceId]; got != "8d6f24ec-0a02-453a-881f-23d6aac2019b" {
		t.Errorf("device twin device_id = %q", got)
	}
	if got := twin["user"].Attrs[semconv.AttrDeletedDateTime]; got != "2026-07-19T15:34:35Z" {
		t.Errorf("user twin deleted_date_time = %q", got)
	}
}

// TestNearPurgeBoolOnTwin asserts the typed bool on the log Event directly
// (telemetrytest can't render bool attrs as strings): the application twin is
// near_purge=true, the user twin false.
func TestNearPurgeBoolOnTwin(t *testing.T) {
	appNear := isNearPurge("2026-06-05T17:54:57Z", probeTime)
	if !appNear {
		t.Errorf("application (44d) isNearPurge = false, want true")
	}
	// Direct emit check: the twin Attr must be a bool, not a string.
	ev := logTwin(deletedObject{ID: "x", DeletedDateTime: "2026-06-05T17:54:57Z"}, "application", appNear)
	if v, ok := ev.Attrs[semconv.AttrNearPurge].(bool); !ok || !v {
		t.Errorf("twin near_purge attr = %#v, want bool true", ev.Attrs[semconv.AttrNearPurge])
	}
}

// TestIsNearPurge pins the boundary math and the missing-timestamp guard.
func TestIsNearPurge(t *testing.T) {
	now := probeTime
	cases := []struct {
		name    string
		deleted string
		want    bool
	}{
		{"just deleted", now.Add(-time.Hour).Format(time.RFC3339), false},
		{"24 days old (under 25)", now.Add(-24 * 24 * time.Hour).Format(time.RFC3339), false},
		{"exactly 25 days old", now.Add(-25 * 24 * time.Hour).Format(time.RFC3339), true},
		{"44 days old (past nominal purge)", now.Add(-44 * 24 * time.Hour).Format(time.RFC3339), true},
		{"empty", "", false},
		{"garbage", "not-a-time", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := isNearPurge(tc.deleted, now); got != tc.want {
				t.Errorf("isNearPurge(%q) = %v, want %v", tc.deleted, got, tc.want)
			}
		})
	}
}

// TestEmptyBinEmitsNothing: an empty recycle bin (all types return []) produces
// no gauge series and no logs — the empty-snapshot convention.
func TestEmptyBinEmitsNothing(t *testing.T) {
	empty := &fakeGraph{bodies: map[string]string{}}
	for _, k := range kinds {
		empty.bodies[urlFor(k.segment, k.selectQ)] = `{"value":[]}`
	}
	rec := telemetrytest.New()
	if err := newCollector(empty).Collect(context.Background(), rec.Emitter()); err != nil {
		t.Fatalf("Collect: %v", err)
	}
	if pts := rec.MetricPoints(metricDeletedItems); len(pts) != 0 {
		t.Errorf("gauge points = %d, want 0 for an empty bin", len(pts))
	}
	if logs := rec.LogRecords(); len(logs) != 0 {
		t.Errorf("logs = %d, want 0 for an empty bin", len(logs))
	}
}

// TestOneTypeErrorDoesNotBlindTheRest: a fetch error on one object type is
// logged and joined, and the other types still emit — a missing scope on one cast
// must not blank the whole census.
func TestOneTypeErrorDoesNotBlindTheRest(t *testing.T) {
	g := liveGraph()
	g.errs = map[string]error{
		urlFor("microsoft.graph.device", "id,displayName,deletedDateTime,deviceId"): errors.New("403 Forbidden"),
	}
	rec := telemetrytest.New()
	err := newCollector(g).Collect(context.Background(), rec.Emitter())
	if err == nil {
		t.Fatalf("Collect err = nil, want the joined device error")
	}
	if pts := rec.MetricPoints(metricDeletedItems); len(pts) != 4 {
		t.Errorf("gauge points = %d, want 4 (device failed, four types remain)", len(pts))
	}
	if logs := rec.LogRecords(); len(logs) != 4 {
		t.Errorf("logs = %d, want 4 (device failed)", len(logs))
	}
}

// TestNoPerEntityMetricLabels is the #112 guard at the collector level: the gauge
// carries only object_type and near_purge — never an id/UPN/appId/deviceId.
func TestNoPerEntityMetricLabels(t *testing.T) {
	rec := telemetrytest.New()
	if err := newCollector(liveGraph()).Collect(context.Background(), rec.Emitter()); err != nil {
		t.Fatalf("Collect: %v", err)
	}
	banned := []string{semconv.AttrId, semconv.AttrUserPrincipalName, semconv.AttrAppId, semconv.AttrDeviceId, semconv.AttrDisplayName}
	for _, p := range rec.MetricPoints(metricDeletedItems) {
		for _, b := range banned {
			if _, ok := p.Attrs[b]; ok {
				t.Errorf("gauge carries per-entity label %q — must be log-twin only (#112)", b)
			}
		}
	}
}
