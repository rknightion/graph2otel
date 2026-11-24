package servicehealth

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/rknightion/graph2otel/internal/checkpoint"
	"github.com/rknightion/graph2otel/internal/collector"
	"github.com/rknightion/graph2otel/internal/collectors"
	"github.com/rknightion/graph2otel/internal/telemetrytest"
)

// Synthetic fixtures reconstructed from the redacted response shapes observed
// for #666. All incident IDs, times and post text are invented.
const openTeamsRow = `{
 "id":"TEST-1","service":"Microsoft Teams","title":"Example interruption","classification":"incident",
 "status":"serviceInterruption","isResolved":false,"startDateTime":"2026-11-24T09:00:00Z","endDateTime":null
}`

const closedTeamsRow = `{
 "id":"TEST-1","service":"Microsoft Teams","title":"Example interruption","classification":"incident",
 "status":"serviceRestored","isResolved":true,"startDateTime":"2026-11-24T09:00:00Z","endDateTime":"2026-11-24T13:04:53.0000002Z",
 "posts":[
   {"createdDateTime":"2026-11-24T13:15:00Z","postType":"regular","description":{"contentType":"html","content":"<p>Example final update</p>"}},
   {"createdDateTime":"2026-11-24T09:00:00Z","postType":"regular","description":{"contentType":"html","content":"<p>Example first update</p>"}}
 ]
}`

const emptyCollection = `{"value":[]}`

func newLifecycleCollector(t *testing.T, profiles collector.ProfileSet, g *fakeGraph, dir string) *Collector {
	t.Helper()
	for _, factory := range collectors.All() {
		c := factory(collectors.Deps{Graph: g, Profiles: profiles, Store: checkpoint.NewStore(dir), TenantID: "test-tenant"})
		if c.Name() == "m365.servicehealth" {
			health := c.(*Collector)
			health.now = func() time.Time { return time.Date(2026, 11, 24, 18, 0, 0, 0, time.UTC) }
			return health
		}
	}
	t.Fatal("service-health collector is not registered")
	return nil
}

func resolvedTwins(t *testing.T, c *Collector) []telemetrytest.LogRecord {
	t.Helper()
	r := telemetrytest.New()
	if err := c.Collect(t.Context(), r.Emitter(), nil); err != nil {
		t.Fatalf("Collect: %v", err)
	}
	return onlyResolutions(r.LogRecords())
}

func onlyResolutions(logs []telemetrytest.LogRecord) []telemetrytest.LogRecord {
	var resolved []telemetrytest.LogRecord
	for _, log := range logs {
		if log.EventName == "m365.service_health_issue" && log.Attrs["is_resolved"] == "true" {
			resolved = append(resolved, log)
		}
	}
	return resolved
}

func teamsOverview(row string) string {
	return `{"value":[{"service":"Microsoft Teams","issues":[` + row + `]}]}`
}

func TestTeamsResolutionSurvivesRestartWithoutReplay(t *testing.T) {
	g := &fakeGraph{bodies: map[string]string{overviewsURL: teamsOverview(openTeamsRow)}}
	dir := t.TempDir()
	restart := func() *Collector { return newLifecycleCollector(t, collector.ProfileTeams, g, dir) }
	if got := resolvedTwins(t, restart()); len(got) != 0 {
		t.Fatalf("open tick emitted resolutions: %+v", got)
	}

	g.bodies[overviewsURL] = teamsOverview(closedTeamsRow)
	c := restart()
	got := resolvedTwins(t, c)
	if len(got) != 1 {
		t.Fatalf("resolved tick after restart: got %d resolution records, want one", len(got))
	}
	wantAttrs := map[string]string{
		"id": "TEST-1", "service": "Microsoft Teams", "classification": "incident", "is_resolved": "true",
		"start_date_time": "2026-11-24T09:00:00Z", "end_date_time": "2026-11-24T13:04:53.0000002Z",
		"created_date_time": "2026-11-24T13:15:00Z", "description": "<p>Example final update</p>",
		"content_type": "html", "post_type": "regular",
	}
	for key, want := range wantAttrs {
		if value := got[0].Attrs[key]; value != want {
			t.Errorf("resolution %s = %q, want %q", key, value, want)
		}
	}
	wantTime, err := time.Parse(time.RFC3339Nano, wantAttrs["end_date_time"])
	if err != nil || !got[0].Timestamp.Equal(wantTime) {
		t.Errorf("resolution timestamp = %v, want %v (parse error: %v)", got[0].Timestamp, wantTime, err)
	}
	// The old open snapshot may reappear even while the issue list still says
	// resolved. Neither it nor retained resolved history may re-arm the issue.
	g.bodies[overviewsURL] = teamsOverview(openTeamsRow)
	if again := resolvedTwins(t, c); len(again) != 0 {
		t.Fatalf("repeat tick replayed resolution: %+v", again)
	}
	g.bodies[overviewsURL] = teamsOverview(closedTeamsRow)
	if again := resolvedTwins(t, restart()); len(again) != 0 {
		t.Fatalf("second restart replayed resolution: %+v", again)
	}
}

func TestTeamsResolutionRequiresPositiveEvidence(t *testing.T) {
	g := &fakeGraph{bodies: map[string]string{}}
	c := newLifecycleCollector(t, collector.ProfileTeams|collector.ProfileGraph, g, t.TempDir())
	poll := func(body string) []telemetrytest.LogRecord {
		g.bodies[overviewsURL] = body
		return resolvedTwins(t, c)
	}
	noResolution := func(label, body string) {
		t.Helper()
		if got := poll(body); len(got) != 0 {
			t.Fatalf("%s: fabricated resolutions: %+v", label, got)
		}
	}

	noResolution("cold retained history", teamsOverview(closedTeamsRow))
	noResolution("missing open flag", teamsOverview(strings.Replace(openTeamsRow, `"isResolved":false,`, "", 1)))
	noResolution("resolved after unknown flag", teamsOverview(closedTeamsRow))
	noResolution("explicit open", teamsOverview(openTeamsRow))
	noResolution("absent", emptyCollection)
	noResolution("non-Teams", teamsOverview(strings.Replace(closedTeamsRow, "Microsoft Teams", "Exchange Online", 1)))
	noResolution("missing resolved flag", teamsOverview(strings.Replace(closedTeamsRow, `"isResolved":true,`, "", 1)))
	noResolution("future end", teamsOverview(strings.Replace(closedTeamsRow, "2026-11-24T13:04:53.0000002Z", "2026-11-24T19:00:00Z", 1)))
	noResolution("bad end", teamsOverview(strings.Replace(closedTeamsRow, "2026-11-24T13:04:53.0000002Z", "not-a-time", 1)))
	noResolution("end before start", teamsOverview(strings.Replace(closedTeamsRow, "2026-11-24T13:04:53.0000002Z", "2026-11-24T00:00:00Z", 1)))
	noResolution("no end", teamsOverview(strings.Replace(closedTeamsRow, `"2026-11-24T13:04:53.0000002Z"`, "null", 1)))
	if got := poll(teamsOverview(closedTeamsRow)); len(got) != 1 || got[0].Attrs["id"] != "TEST-1" {
		t.Fatalf("valid evidence should still resolve the original open: %+v", got)
	}
}

func TestTeamsResolutionKeepsPresentIssuesAfterLongOutage(t *testing.T) {
	g := &fakeGraph{bodies: map[string]string{overviewsURL: teamsOverview(openTeamsRow)}}
	dir := t.TempDir()
	before := newLifecycleCollector(t, collector.ProfileTeams, g, dir)
	resolvedTwins(t, before)
	// The exporter was down longer than the absent-ID expiry interval,
	// but the issue ended recently and is still in the returned snapshot.
	now := before.now().Add(8 * 24 * time.Hour)
	end := now.Add(-time.Hour)
	g.bodies[overviewsURL] = teamsOverview(strings.Replace(closedTeamsRow, "2026-11-24T13:04:53.0000002Z", end.Format(time.RFC3339Nano), 1))
	after := newLifecycleCollector(t, collector.ProfileTeams, g, dir)
	after.now = func() time.Time { return now }
	got := resolvedTwins(t, after)
	if len(got) != 1 || got[0].Attrs["id"] != "TEST-1" || !got[0].Timestamp.Equal(end) {
		t.Fatalf("recent closure must survive downtime: %+v", got)
	}
}

func TestTeamsResolutionChecksRememberedStartWhenClosingRowOmitsIt(t *testing.T) {
	g := &fakeGraph{bodies: map[string]string{overviewsURL: teamsOverview(openTeamsRow)}}
	dir := t.TempDir()
	restart := func() *Collector { return newLifecycleCollector(t, collector.ProfileTeams, g, dir) }
	resolvedTwins(t, restart())
	withoutStart := strings.Replace(closedTeamsRow, `"startDateTime":"2026-11-24T09:00:00Z",`, "", 1)
	badEnd := strings.Replace(withoutStart, "2026-11-24T13:04:53.0000002Z", "2026-11-24T08:30:00Z", 1)
	g.bodies[overviewsURL] = teamsOverview(badEnd)
	if got := resolvedTwins(t, restart()); len(got) != 0 {
		t.Fatalf("end before remembered start must not emit a closure: %+v", got)
	}
	g.bodies[overviewsURL] = teamsOverview(withoutStart)
	if got := resolvedTwins(t, restart()); len(got) != 1 || got[0].Attrs["start_date_time"] != "2026-11-24T09:00:00Z" {
		t.Fatalf("valid correction must use remembered start and still emit: %+v", got)
	}
}

func TestTeamsResolutionKeepsValidEndWithoutAnUsableFinalPost(t *testing.T) {
	g := &fakeGraph{bodies: map[string]string{overviewsURL: teamsOverview(openTeamsRow)}}
	dir := t.TempDir()
	restart := func() *Collector { return newLifecycleCollector(t, collector.ProfileTeams, g, dir) }
	resolvedTwins(t, restart())
	g.bodies[overviewsURL] = teamsOverview(strings.Replace(closedTeamsRow, "<p>Example final update</p>", "", 1))
	got := resolvedTwins(t, restart())
	if len(got) != 1 || got[0].Attrs["id"] != "TEST-1" || got[0].Timestamp.IsZero() {
		t.Fatalf("valid closure with unavailable post must emit once: %+v", got)
	}
	if _, present := got[0].Attrs["description"]; present {
		t.Fatalf("must not substitute the older post: %+v", got[0].Attrs)
	}
	if again := resolvedTwins(t, restart()); len(again) != 0 {
		t.Fatalf("normal restart replayed a closure without a post: %+v", again)
	}
}

func TestTeamsResolutionCanReplayIfCheckpointSaveFailsAfterEmission(t *testing.T) {
	g := &fakeGraph{bodies: map[string]string{overviewsURL: teamsOverview(openTeamsRow)}}
	dir := t.TempDir()
	restart := func() *Collector { return newLifecycleCollector(t, collector.ProfileTeams, g, dir) }
	resolvedTwins(t, restart())
	paths, err := filepath.Glob(filepath.Join(dir, "*teams-lifecycle*.json"))
	if err != nil || len(paths) != 1 {
		t.Fatalf("locate lifecycle checkpoint: %v, %v", paths, err)
	}
	// Occupy the temp-file path so Store.Save cannot replace the open state.
	blocked := paths[0] + ".tmp"
	if err := os.Mkdir(blocked, 0o700); err != nil {
		t.Fatal(err)
	}
	g.bodies[overviewsURL] = teamsOverview(closedTeamsRow)
	r := telemetrytest.New()
	if err := restart().Collect(t.Context(), r.Emitter(), nil); err == nil || !strings.Contains(err.Error(), "save Teams service-health lifecycle") {
		t.Fatalf("expected lifecycle save error, got %v", err)
	}
	if got := onlyResolutions(r.LogRecords()); len(got) != 1 || got[0].Attrs["id"] != "TEST-1" {
		t.Fatalf("resolution should already have reached the emitter: %+v", got)
	}
	if err := os.Remove(blocked); err != nil {
		t.Fatal(err)
	}
	if got := resolvedTwins(t, restart()); len(got) != 1 || got[0].Attrs["id"] != "TEST-1" {
		t.Fatalf("uncheckpointed resolution should be retried: %+v", got)
	}
}

func TestGraphProfileKeepsOpenTwinsWithoutTeamsLifecycle(t *testing.T) {
	g := &fakeGraph{bodies: map[string]string{overviewsURL: teamsOverview(openTeamsRow)}}
	dir := t.TempDir()
	graph := newLifecycleCollector(t, collector.ProfileGraph, g, dir)
	r := telemetrytest.New()
	if err := graph.Collect(t.Context(), r.Emitter(), nil); err != nil {
		t.Fatal(err)
	}
	logs := r.LogRecords()
	if len(logs) != 1 || logs[0].EventName != "m365.service_health_issue" || logs[0].Attrs["is_resolved"] != "false" {
		t.Fatalf("Graph open twin changed: %+v", logs)
	}
	g.bodies[overviewsURL] = teamsOverview(closedTeamsRow)
	if got := resolvedTwins(t, graph); len(got) != 0 {
		t.Fatalf("Graph-only collection emitted Teams resolution: %+v", got)
	}
	if got := resolvedTwins(t, newLifecycleCollector(t, collector.ProfileTeams, g, dir)); len(got) != 0 {
		t.Fatalf("Graph-only observations must not arm Teams resolution: %+v", got)
	}
}

func TestTeamsLifecycleBoundsCheckpointAndExpiresAbsentIDs(t *testing.T) {
	g := &fakeGraph{bodies: map[string]string{}}
	dir := t.TempDir()
	c := newLifecycleCollector(t, collector.ProfileTeams, g, dir)
	now := time.Date(2026, 11, 24, 18, 0, 0, 0, time.UTC)
	c.now = func() time.Time { return now }
	var opens []string
	for n := range teamsLifecycleLimit + 1 {
		opens = append(opens, strings.Replace(openTeamsRow, "TEST-1", fmt.Sprintf("TEST-%04d", n), 1))
	}
	g.bodies[overviewsURL] = teamsOverview(strings.Join(opens, ","))
	resolvedTwins(t, c)
	load := func() *checkpoint.Checkpoint {
		t.Helper()
		cp, err := checkpoint.NewStore(dir).Load("test-tenant", teamsLifecycleEndpoint)
		if err != nil {
			t.Fatal(err)
		}
		return cp
	}
	if got := len(load().TeamsServiceHealth); got != teamsLifecycleLimit {
		t.Fatalf("persisted %d IDs, want capped at %d", got, teamsLifecycleLimit)
	}
	g.bodies[overviewsURL] = emptyCollection
	now = now.Add(teamsLifecycleRetention + time.Second)
	resolvedTwins(t, c)
	if got := len(load().TeamsServiceHealth); got != 0 {
		t.Fatalf("persisted %d expired IDs, want none", got)
	}
	g.bodies[overviewsURL] = teamsOverview(strings.Replace(closedTeamsRow, "TEST-1", "TEST-0000", 1))
	if got := resolvedTwins(t, c); len(got) != 0 {
		t.Fatalf("expired open must not emit resolution: %+v", got)
	}
}
