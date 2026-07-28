package directoryrecovery

import (
	"context"
	"errors"
	"log/slog"
	"os"
	"testing"
	"time"

	"github.com/rknightion/graph2otel/internal/collectors"
	"github.com/rknightion/graph2otel/internal/recordoutcome"
	"github.com/rknightion/graph2otel/internal/semconv"
	"github.com/rknightion/graph2otel/internal/telemetrytest"
	"github.com/rknightion/graph2otel/internal/wirecheck"
)

// fakeGraph maps request URLs to canned bodies (or errors) and records every
// URL asked for, so tests can assert on the exact request shape — notably
// that this collector never constructs a per-snapshot or restore-capable URL.
type fakeGraph struct {
	bodies map[string]string
	errs   map[string]error
	calls  []string
}

func (f *fakeGraph) RawGet(_ context.Context, url string) ([]byte, error) {
	f.calls = append(f.calls, url)
	if err, ok := f.errs[url]; ok {
		return nil, err
	}
	if body, ok := f.bodies[url]; ok {
		return []byte(body), nil
	}
	return []byte(`{"value": []}`), nil
}

func (f *fakeGraph) RawGetWithHeaders(ctx context.Context, url string, _ map[string]string) ([]byte, error) {
	return f.RawGet(ctx, url)
}

var _ collectors.GraphClient = (*fakeGraph)(nil)

const (
	base         = "https://graph.microsoft.com/v1.0"
	snapshotsURL = base + snapshotsPath
	jobsURL      = base + jobsPath
)

// pinnedNow is the clock every test runs against. It is an ABSOLUTE instant
// deliberately paired with the absolute dates in the live snapshots fixture,
// so the computed ages below are fixed forever. Leaving the collector on
// time.Now would make every age assertion drift with the calendar — the exact
// fixture-date time bomb that turned main red on 2026-07-28 when #367's
// hard-coded post dates aged past a 7-day horizon.
//
// The fixture's newest snapshot is 2026-07-27T22:00:00Z, so this pins the
// newest age at exactly 2h.
var pinnedNow = time.Date(2026, 7, 28, 0, 0, 0, 0, time.UTC)

func mustReadFile(t *testing.T, name string) string {
	t.Helper()
	b, err := os.ReadFile("testdata/" + name)
	if err != nil {
		t.Fatalf("read testdata/%s: %v", name, err)
	}
	return string(b)
}

func newTestCollector(g collectors.GraphClient) *Collector {
	return &Collector{
		g:       g,
		baseURL: base,
		logger:  slog.Default(),
		watch:   wirecheck.New(collectorName, nil),
		now:     func() time.Time { return pinnedNow },
	}
}

func collect(t *testing.T, g collectors.GraphClient) *telemetrytest.Recorder {
	t.Helper()
	rec := telemetrytest.New()
	c := newTestCollector(g)
	if err := c.Collect(context.Background(), rec.Emitter(), recordoutcome.NewRecorder()); err != nil {
		t.Fatalf("Collect: %v", err)
	}
	return rec
}

// recordsNamed filters captured log records by EventName.
func recordsNamed(rec *telemetrytest.Recorder, name string) []telemetrytest.LogRecord {
	var out []telemetrytest.LogRecord
	for _, r := range rec.LogRecords() {
		if r.EventName == name {
			out = append(out, r)
		}
	}
	return out
}

// liveGraph returns a fake serving the VERBATIM 2026-07-28 m7kni captures.
func liveGraph(t *testing.T) *fakeGraph {
	t.Helper()
	return &fakeGraph{bodies: map[string]string{
		snapshotsURL: mustReadFile(t, "snapshots.json"),
		jobsURL:      mustReadFile(t, "jobs.json"),
	}}
}

// TestLiveCaptureSnapshotCountAndAge drives the verbatim live capture through
// the real collector: 7 retained snapshots, newest 2h old against the pinned
// clock.
func TestLiveCaptureSnapshotCountAndAge(t *testing.T) {
	rec := collect(t, liveGraph(t))

	pts := rec.MetricPoints(snapshotsMetric)
	if len(pts) != 1 {
		t.Fatalf("snapshots metric: want 1 point, got %d", len(pts))
	}
	if pts[0].Value != 7 {
		t.Errorf("snapshot count = %v, want 7 (the live 7-day retention window)", pts[0].Value)
	}

	agePts := rec.MetricPoints(newestSnapshotAgeMetric)
	if len(agePts) != 1 {
		t.Fatalf("newest-age metric: want 1 point, got %d", len(agePts))
	}
	if want := (2 * time.Hour).Seconds(); agePts[0].Value != want {
		t.Errorf("newest snapshot age = %v, want %v", agePts[0].Value, want)
	}
}

// TestNewestAgeScansEveryRowNotJustTheFirst is the guard against trusting
// Graph's newest-first ordering. It feeds a REVERSED collection (oldest
// first) and requires the same 2h answer. A collector that read element 0
// would report seven days of staleness on a directory snapshotted two hours
// ago — and a recoverability alert that misreads freshness is worse than none.
func TestNewestAgeScansEveryRowNotJustTheFirst(t *testing.T) {
	reversed := `{"value":[
		{"id":"a","createdDateTime":"2026-07-21T22:00:00Z"},
		{"id":"b","createdDateTime":"2026-07-27T22:00:00Z"}
	]}`
	rec := collect(t, &fakeGraph{bodies: map[string]string{
		snapshotsURL: reversed, jobsURL: `{"value":[]}`,
	}})
	pts := rec.MetricPoints(newestSnapshotAgeMetric)
	if len(pts) != 1 {
		t.Fatalf("want 1 age point, got %d", len(pts))
	}
	if want := (2 * time.Hour).Seconds(); pts[0].Value != want {
		t.Errorf("age = %v, want %v — the newest row was not element 0", pts[0].Value, want)
	}
}

// TestNoSnapshotsEmitsNoAgeSeries pins that an empty collection produces a
// snapshot count of 0 and NO age series at all. A 0-second age would claim a
// snapshot had just been taken on a tenant that has none — the most dangerous
// possible reading from this collector.
func TestNoSnapshotsEmitsNoAgeSeries(t *testing.T) {
	rec := collect(t, &fakeGraph{bodies: map[string]string{
		snapshotsURL: `{"value":[]}`,
		jobsURL:      `{"value":[]}`,
	}})
	if pts := rec.MetricPoints(snapshotsMetric); len(pts) != 1 || pts[0].Value != 0 {
		t.Errorf("snapshot count: want a single measured 0, got %+v", pts)
	}
	if pts := rec.MetricPoints(newestSnapshotAgeMetric); len(pts) != 0 {
		t.Errorf("newest-age: want NO series on an empty collection, got %+v", pts)
	}
}

// TestUnparseableCreatedDateTimeEmitsNoAgeSeries is the sibling guard: a row
// exists but its timestamp cannot be parsed, so there is still no defensible
// age. Unparseable must behave like absent, not like zero.
func TestUnparseableCreatedDateTimeEmitsNoAgeSeries(t *testing.T) {
	rec := collect(t, &fakeGraph{bodies: map[string]string{
		snapshotsURL: `{"value":[{"id":"a","createdDateTime":"not-a-timestamp"}]}`,
		jobsURL:      `{"value":[]}`,
	}})
	if pts := rec.MetricPoints(snapshotsMetric); len(pts) != 1 || pts[0].Value != 1 {
		t.Errorf("snapshot count: want 1 (the row still exists), got %+v", pts)
	}
	if pts := rec.MetricPoints(newestSnapshotAgeMetric); len(pts) != 0 {
		t.Errorf("newest-age: want NO series for an unparseable timestamp, got %+v", pts)
	}
}

// TestAbsentTotalChangedObjectsEmitsNoKey is the absent-field guard.
//
// It asserts on the MAPPER'S OWN telemetry.Attrs, not on the recorder's
// rendered map[string]string. The recorder sits downstream of the emitter's
// lossy rendering, and this repo has twice shipped a guard that asserted one
// layer above the bug (#322's rendered-array join, #354's SetStrs empty
// filter). The absence of a numeric key is exactly that class of claim.
//
// totalChangedObjects is declared in the EDM and never sent (live-measured),
// so a bare int64 in the struct would publish a fabricated 0 meaning "nothing
// in the directory changed since the last snapshot" — a healthy-looking
// number Graph never reported.
func TestAbsentTotalChangedObjectsEmitsNoKey(t *testing.T) {
	ev := snapshotTwin(snapshot{ID: "a", CreatedDateTime: "2026-07-27T22:00:00Z"}, pinnedNow)
	if _, ok := ev.Attrs[semconv.AttrTotalChangedObjects]; ok {
		t.Fatalf("total_changed_objects must be ABSENT when the wire omits it, got %v",
			ev.Attrs[semconv.AttrTotalChangedObjects])
	}
}

// TestPresentTotalChangedObjectsIsEmitted is the other half of the pointer
// contract, and the reason the test above cannot stand alone: a mapper that
// dropped the field unconditionally would also pass it. A wire value of 0 is
// used specifically because 0 is what a fabricating implementation produces —
// so this pins that a REAL zero survives while a fabricated one never appears.
func TestPresentTotalChangedObjectsIsEmitted(t *testing.T) {
	zero := int64(0)
	ev := snapshotTwin(snapshot{ID: "a", CreatedDateTime: "2026-07-27T22:00:00Z", TotalChangedObjects: &zero}, pinnedNow)
	v, ok := ev.Attrs[semconv.AttrTotalChangedObjects]
	if !ok {
		t.Fatal("total_changed_objects must be PRESENT when the wire carries it")
	}
	if v != float64(0) {
		t.Errorf("total_changed_objects = %v, want a real 0", v)
	}
}

// TestLiveCaptureEmitsOneTwinPerSnapshot pins the one-twin-per-entity rule
// against the real fixture, and that none of them fabricated the absent field.
func TestLiveCaptureEmitsOneTwinPerSnapshot(t *testing.T) {
	rec := collect(t, liveGraph(t))
	recs := recordsNamed(rec, eventSnapshot)
	if len(recs) != 7 {
		t.Fatalf("want 7 snapshot twins, got %d", len(recs))
	}
	for _, r := range recs {
		if _, ok := r.Attrs[semconv.AttrTotalChangedObjects]; ok {
			t.Errorf("twin %v carries a fabricated total_changed_objects", r.Attrs[semconv.AttrId])
		}
		if r.Attrs[semconv.AttrSnapshotAgeSeconds] == "" {
			t.Errorf("twin %v is missing its age", r.Attrs[semconv.AttrId])
		}
	}
}

// TestEmptyJobsIsAMeasuredZeroNotAnAbsentSeries pins the two-gauge split. The
// jobs collection is empty in the healthy steady state, so the total must
// still report a measured 0 — otherwise "no restore has ever run" and "the
// collector is disabled" are the same absent series.
func TestEmptyJobsIsAMeasuredZeroNotAnAbsentSeries(t *testing.T) {
	rec := collect(t, liveGraph(t))
	pts := rec.MetricPoints(jobsMetric)
	if len(pts) != 1 || pts[0].Value != 0 {
		t.Errorf("jobs total: want a single measured 0, got %+v", pts)
	}
	if pts := rec.MetricPoints(jobsByStatusMetric); len(pts) != 0 {
		t.Errorf("jobs_by_status: want no points when no job exists, got %+v", pts)
	}
	if recs := recordsNamed(rec, eventJob); len(recs) != 0 {
		t.Errorf("want no job twins, got %d", len(recs))
	}
}

// TestJobStatusBuckets covers the populated job path the live tenant cannot
// exercise, including a status Microsoft has not defined.
func TestJobStatusBuckets(t *testing.T) {
	jobs := `{"value":[
		{"id":"j1","status":"failed"},
		{"id":"j2","status":"successful"},
		{"id":"j3","status":"someFutureState"}
	]}`
	rec := collect(t, &fakeGraph{bodies: map[string]string{
		snapshotsURL: `{"value":[]}`, jobsURL: jobs,
	}})

	if pts := rec.MetricPoints(jobsMetric); len(pts) != 1 || pts[0].Value != 3 {
		t.Errorf("jobs total: want 3, got %+v", pts)
	}

	got := map[string]float64{}
	for _, p := range rec.MetricPoints(jobsByStatusMetric) {
		got[p.Attrs[semconv.AttrStatus]] = p.Value
	}
	for k, v := range map[string]float64{"failed": 1, "successful": 1, "unknown": 1} {
		if got[k] != v {
			t.Errorf("jobs_by_status[%s] = %v, want %v (full: %+v)", k, got[k], v, got)
		}
	}
}

// TestJobTwinPointerFieldsAndDiscriminator asserts on the mapper's own Attrs
// for every claim about a field being absent — same reasoning as the
// totalChangedObjects guard above.
func TestJobTwinPointerFieldsAndDiscriminator(t *testing.T) {
	three := int64(3)

	withFailures := jobTwin(recoveryJob{
		ID: "j1", Status: "failed",
		ODataType:          "#microsoft.graph.entraRecoveryServices.recoveryJob",
		JobStartDateTime:   "2026-07-27T10:00:00Z",
		TotalFailedChanges: &three,
	})
	if v, ok := withFailures.Attrs[semconv.AttrTotalFailedChanges]; !ok || v != float64(3) {
		t.Errorf("total_failed_changes = %v (present=%v), want 3", v, ok)
	}
	if v := withFailures.Attrs[semconv.AttrIsPreview]; v != "false" {
		t.Errorf("is_preview = %v, want false for a real recoveryJob", v)
	}

	// A job carrying no totalFailedChanges must emit no key. A fabricated 0
	// here asserts a clean restore that Graph never reported.
	clean := jobTwin(recoveryJob{ID: "j2", Status: "successful", ODataType: previewODataType})
	if _, ok := clean.Attrs[semconv.AttrTotalFailedChanges]; ok {
		t.Error("total_failed_changes must be absent — a fabricated 0 asserts a clean restore")
	}
	if v := clean.Attrs[semconv.AttrIsPreview]; v != "true" {
		t.Errorf("is_preview = %v, want true for a recoveryPreviewJob", v)
	}

	// No @odata.type at all: is_preview must be absent rather than guessing
	// "not a preview" from a discriminator that never arrived.
	noType := jobTwin(recoveryJob{ID: "j3", Status: "someFutureState"})
	if _, ok := noType.Attrs[semconv.AttrIsPreview]; ok {
		t.Error("is_preview must be absent when @odata.type is absent")
	}
	// The unrecognized status is emitted VERBATIM on the twin even though the
	// gauge buckets it to "unknown" — the twin is what preserves a new enum
	// member for whoever investigates.
	if s := noType.Attrs[semconv.AttrStatus]; s != "someFutureState" {
		t.Errorf("status on twin = %v, want the raw wire value", s)
	}
}

// TestWirecheckFiresOnlyOnAnUnknownStatus pins the watchdog: a complete poll
// of known statuses must NOT increment it (a watchdog that fires on correct
// data trains the reader to ignore it), and an undeclared member must.
func TestWirecheckFiresOnlyOnAnUnknownStatus(t *testing.T) {
	rec := collect(t, &fakeGraph{bodies: map[string]string{
		snapshotsURL: `{"value":[]}`,
		jobsURL:      `{"value":[{"id":"j1","status":"successful"},{"id":"j2","status":"running"}]}`,
	}})
	if pts := rec.MetricPoints(wirecheck.MetricUnexpected); len(pts) != 0 {
		t.Errorf("watchdog fired on entirely known statuses: %+v", pts)
	}

	rec2 := collect(t, &fakeGraph{bodies: map[string]string{
		snapshotsURL: `{"value":[]}`,
		jobsURL:      `{"value":[{"id":"j1","status":"someFutureState"}]}`,
	}})
	if pts := rec2.MetricPoints(wirecheck.MetricUnexpected); len(pts) == 0 {
		t.Error("watchdog did not fire on an undeclared status member")
	}
}

// TestWatchedSetIsDerivedFromTheMappedSet is the anti-drift guard required by
// #233/#234: the wirecheck Enum must come from jobStatusBuckets' own keys, so
// adding a bucket cannot leave the watchdog watching a stale set. Asserted by
// requiring every mapped key to pass the enum, rather than by comparing two
// hand-written lists — which would itself be the restatement the rule forbids.
func TestWatchedSetIsDerivedFromTheMappedSet(t *testing.T) {
	for k := range jobStatusBuckets {
		if !knownJobStatuses.Has(k) {
			t.Errorf("status %q is bucketed but not watched — the sets have drifted", k)
		}
	}
}

// TestCollectorNeverConstructsARestoreCapableURL is the acceptance-criterion-3
// guard, asserted on the request log rather than by reading the source. The
// EDM binds cancel/getChanges/getFailedChanges to the job types and a
// snapshot id is not addressable at all, so exactly two collection URLs may
// ever be requested.
func TestCollectorNeverConstructsARestoreCapableURL(t *testing.T) {
	g := liveGraph(t)
	collect(t, g)
	if len(g.calls) != 2 {
		t.Fatalf("want exactly 2 requests, got %d: %v", len(g.calls), g.calls)
	}
	for _, u := range g.calls {
		if u != snapshotsURL && u != jobsURL {
			t.Errorf("unexpected URL requested: %s", u)
		}
	}
}

// TestFetchFailureEmitsNothing pins the all-or-nothing contract on both
// fetches. A partial walk would understate the snapshot count, which is
// exactly the alarm this collector exists to raise and must never raise
// falsely.
func TestFetchFailureEmitsNothing(t *testing.T) {
	for _, failing := range []string{snapshotsURL, jobsURL} {
		g := liveGraph(t)
		g.errs = map[string]error{failing: errors.New("boom")}
		rec := telemetrytest.New()
		c := newTestCollector(g)
		if err := c.Collect(context.Background(), rec.Emitter(), recordoutcome.NewRecorder()); err == nil {
			t.Fatalf("%s: want an error", failing)
		}
		if pts := rec.MetricPoints(snapshotsMetric); len(pts) != 0 {
			t.Errorf("%s: emitted a snapshot count despite a failed fetch: %+v", failing, pts)
		}
		if recs := recordsNamed(rec, eventSnapshot); len(recs) != 0 {
			t.Errorf("%s: emitted %d snapshot twins despite a failed fetch", failing, len(recs))
		}
	}
}

// TestPaginationFollowsNextLink pins the hand-rolled loop.
func TestPaginationFollowsNextLink(t *testing.T) {
	page2 := base + "/page2"
	rec := collect(t, &fakeGraph{bodies: map[string]string{
		snapshotsURL: `{"value":[{"id":"a","createdDateTime":"2026-07-27T22:00:00Z"}],"@odata.nextLink":"` + page2 + `"}`,
		page2:        `{"value":[{"id":"b","createdDateTime":"2026-07-26T22:00:00Z"}]}`,
		jobsURL:      `{"value":[]}`,
	}})
	if pts := rec.MetricPoints(snapshotsMetric); len(pts) != 1 || pts[0].Value != 2 {
		t.Errorf("snapshot count across 2 pages = %+v, want 2", pts)
	}
}

// TestRequiredPermissionIsTheGrantedOne pins the scope actually granted for
// #334 on 2026-07-28, so a future edit cannot quietly widen it.
func TestRequiredPermissionIsTheGrantedOne(t *testing.T) {
	perms := New(&fakeGraph{}, nil).RequiredPermissions()
	if len(perms) != 1 || perms[0] != "EntraBackup.Read.All" {
		t.Errorf("RequiredPermissions = %v, want exactly [EntraBackup.Read.All]", perms)
	}
}

// TestTargetsV1NotBeta pins the GA decision. The surface is identical in beta
// and v1.0 (live-measured), and per #183 Experimental is reserved for genuine
// beta — so a silent flip of the base URL to beta would mis-signal the
// collector's maturity to an operator.
func TestTargetsV1NotBeta(t *testing.T) {
	if got := New(&fakeGraph{}, nil).baseURL; got != "https://graph.microsoft.com/v1.0" {
		t.Errorf("baseURL = %q, want the v1.0 root", got)
	}
}

// TestSnapshotTwinIsStateStampedNotBackdated pins that twins carry a zero
// Timestamp so the emitter stamps them at poll time. Backdating a state twin
// to createdDateTime would push the oldest retained snapshot — exactly 7 days
// old at the retention edge — against the backend's 7-day accept horizon on
// every cycle.
func TestSnapshotTwinIsStateStampedNotBackdated(t *testing.T) {
	ev := snapshotTwin(snapshot{ID: "a", CreatedDateTime: "2026-07-21T22:00:00Z"}, pinnedNow)
	if !ev.Timestamp.IsZero() {
		t.Errorf("snapshot twin carries Timestamp %v; a state twin must be stamped at poll time", ev.Timestamp)
	}
}
