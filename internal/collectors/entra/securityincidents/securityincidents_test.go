package securityincidents

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/rknightion/graph2otel/internal/checkpoint"
	"github.com/rknightion/graph2otel/internal/collector"
	"github.com/rknightion/graph2otel/internal/collectors"
	"github.com/rknightion/graph2otel/internal/telemetry"
	"github.com/rknightion/graph2otel/internal/telemetrytest"
)

// recordingFetcher is a logpipeline.PageFetcher that returns a fixed set of
// records once and records every requested page URL, so a test can both drain
// records and assert the exact first-page URL the collector built.
type recordingFetcher struct {
	records  []map[string]any
	seenURLs []string
}

func (f *recordingFetcher) FetchPage(_ context.Context, pageURL string) ([]map[string]any, string, error) {
	f.seenURLs = append(f.seenURLs, pageURL)
	return f.records, "", nil
}

func depsWith(t *testing.T, f *recordingFetcher) collectors.WindowDeps {
	t.Helper()
	return collectors.WindowDeps{
		TenantID: "t1",
		Fetcher:  f,
		Store:    checkpoint.NewStore(t.TempDir()),
	}
}

// fullIncidentRecord returns the richest incident record this package has:
// every field mapIncident reads that the live collector can actually receive,
// plus the wire `tenantId` the mapper deliberately ignores (#143).
//
// Provenance, stated rather than assumed: this fixture is HAND-WRITTEN, NOT a
// live capture. "inc-1", "tenant-guid-1" and analyst@contoso.com are
// placeholders (contoso.com is Microsoft's example domain), the priorityScore of
// 87 is invented, and no captured /security/incidents record exists in this
// package's testdata. It is evidence about mapper wiring and about nothing else.
//
// `alerts` is deliberately ABSENT, which is why this is the richest record the
// collector can RECEIVE rather than the richest mapIncident can parse. The
// grouped-alert ids only exist under $expand=alerts, which this collector never
// sends (see the package doc), so a fixture carrying them would golden two
// attributes — alert_ids, alert_count — that no live poll can produce. That is
// the golden overstating instead of understating; TestMapIncidentExpandedAlerts
// keeps covering that forward-compatible path at the mapper, where it belongs.
//
// tenantId stays on the record ON PURPOSE — see TestWireTenantIDIsNotEmitted.
// Its presence is what proves the mapper IGNORES it rather than that a test
// forgot to set it. Do not remove it to "clean up" the fixture.
//
// Returned from a function rather than shared as a package-level var so no test
// can mutate the record another test reads.
func fullIncidentRecord() map[string]any {
	return map[string]any{
		"id":                 "inc-1",
		"createdDateTime":    "2026-07-01T10:00:00Z",
		"lastUpdateDateTime": "2026-07-01T12:30:00Z",
		"displayName":        "Impossible travel activity involving one user",
		"severity":           "high",
		"status":             "active",
		"classification":     "truePositive",
		"determination":      "compromisedAccount",
		"assignedTo":         "analyst@contoso.com",
		"tenantId":           "tenant-guid-1",
		"priorityScore":      float64(87),
		"tags":               []any{"Priority", "Ransomware"},
	}
}

// TestMapIncidentHighSeverity asserts a representative incident record maps to
// the expected composite dedupe id, event name, key attributes, priority score,
// tags slice, and that a "high" severity maps the log record's own Severity to
// Error.
func TestMapIncidentHighSeverity(t *testing.T) {
	rec := fullIncidentRecord()

	id, ev := mapIncident(rec)
	if id != "inc-1#2026-07-01T12:30:00Z" {
		t.Fatalf("dedupe id = %q, want composite id#lastUpdateDateTime", id)
	}
	if ev.Name != eventName {
		t.Fatalf("event name = %q, want %q", ev.Name, eventName)
	}
	if ev.Severity != telemetry.SeverityError {
		t.Errorf("severity for incident severity=high = %v, want SeverityError", ev.Severity)
	}

	// The clean incident id (not the composite) is what lands in attrs.
	if got := ev.Attrs["id"]; got != "inc-1" {
		t.Errorf("attr id = %v, want inc-1 (the clean incident id, not the composite dedupe id)", got)
	}
	wantStr := map[string]any{
		"display_name":     "Impossible travel activity involving one user",
		"severity":         "high",
		"status":           "active",
		"classification":   "truePositive",
		"determination":    "compromisedAccount",
		"assigned_to":      "analyst@contoso.com",
		"created_time":     "2026-07-01T10:00:00Z",
		"last_update_time": "2026-07-01T12:30:00Z",
	}
	for k, want := range wantStr {
		if got := ev.Attrs[k]; got != want {
			t.Errorf("attr %q = %v, want %v", k, got, want)
		}
	}
	if got := ev.Attrs["priority_score"]; got != 87 {
		t.Errorf("attr priority_score = %v (%T), want int 87", got, got)
	}
	tags, ok := ev.Attrs["tags"].([]string)
	if !ok || len(tags) != 2 || tags[0] != "Priority" || tags[1] != "Ransomware" {
		t.Errorf("attr tags = %v, want []string{Priority, Ransomware}", ev.Attrs["tags"])
	}
	if !strings.Contains(ev.Body, "Impossible travel") || !strings.Contains(ev.Body, "high") || !strings.Contains(ev.Body, "active") {
		t.Errorf("body = %q, want it to summarize displayName/severity/status", ev.Body)
	}
}

// TestMapIncidentMediumAndLowSeverityAreWarn asserts "medium"/"low" severities
// map to SeverityWarn, and that an incident with no assignedTo, tags, or
// priorityScore omits those attributes rather than emitting empty/zero ones.
func TestMapIncidentMediumAndLowSeverityAreWarn(t *testing.T) {
	for _, sev := range []string{"medium", "low"} {
		t.Run(sev, func(t *testing.T) {
			rec := map[string]any{
				"id":                 "inc-" + sev,
				"lastUpdateDateTime": "2026-07-01T10:00:00Z",
				"displayName":        "Suspicious connection",
				"severity":           sev,
				"status":             "active",
			}
			_, ev := mapIncident(rec)
			if ev.Severity != telemetry.SeverityWarn {
				t.Errorf("severity for incident severity=%s = %v, want SeverityWarn", sev, ev.Severity)
			}
			for _, k := range []string{"assigned_to", "tags", "priority_score", "alert_ids", "alert_count"} {
				if _, present := ev.Attrs[k]; present {
					t.Errorf("incident missing %s must not carry attr %q, attrs=%v", k, k, ev.Attrs)
				}
			}
		})
	}
}

// TestMapIncidentUnknownSeverityIsInfo asserts an informational/unrecognized
// severity defaults to SeverityInfo.
func TestMapIncidentUnknownSeverityIsInfo(t *testing.T) {
	for _, sev := range []string{"informational", "unknownFutureValue", ""} {
		rec := map[string]any{"id": "inc-i", "lastUpdateDateTime": "2026-07-01T10:00:00Z", "severity": sev}
		if _, ev := mapIncident(rec); ev.Severity != telemetry.SeverityInfo {
			t.Errorf("severity for incident severity=%q = %v, want SeverityInfo", sev, ev.Severity)
		}
	}
}

// TestCompositeIDReEmitsOnUpdate is the core update-aware-watermark contract:
// the SAME incident id observed with two different lastUpdateDateTime values
// yields two DISTINCT dedupe ids — so a status/assignment/tag change re-emits a
// log record rather than being deduped into silence. An identical
// re-observation (same id, same lastUpdateDateTime) yields the SAME dedupe id
// and is deduped.
func TestCompositeIDReEmitsOnUpdate(t *testing.T) {
	base := map[string]any{"id": "inc-42", "displayName": "Malware prevented", "severity": "low", "status": "active"}

	v1 := clone(base)
	v1["lastUpdateDateTime"] = "2026-07-01T10:00:00Z"
	v1["status"] = "active"

	v2 := clone(base)
	v2["lastUpdateDateTime"] = "2026-07-01T14:00:00Z" // reassigned / status changed later
	v2["status"] = "resolved"

	id1, _ := mapIncident(v1)
	id2, _ := mapIncident(v2)
	if id1 == id2 {
		t.Fatalf("updated incident produced the same dedupe id %q — an update would be deduped into silence", id1)
	}

	// Identical re-observation must be stable (deduped).
	id1again, _ := mapIncident(clone(v1))
	if id1again != id1 {
		t.Fatalf("identical incident produced different dedupe ids %q vs %q", id1, id1again)
	}
}

func clone(m map[string]any) map[string]any {
	out := make(map[string]any, len(m))
	for k, v := range m {
		out[k] = v
	}
	return out
}

// TestMapIncidentExpandedAlerts asserts that when $expand=alerts populates an
// `alerts` array, the grouped alert ids and their count surface as attributes
// (forward-compatibility; $expand is not sent by default).
func TestMapIncidentExpandedAlerts(t *testing.T) {
	rec := map[string]any{
		"id":                 "inc-9",
		"lastUpdateDateTime": "2026-07-01T10:00:00Z",
		"severity":           "medium",
		"status":             "active",
		"alerts": []any{
			map[string]any{"id": "alert-a"},
			map[string]any{"id": "alert-b"},
			map[string]any{"noid": true},
		},
	}
	_, ev := mapIncident(rec)
	ids, ok := ev.Attrs["alert_ids"].([]string)
	if !ok || len(ids) != 2 || ids[0] != "alert-a" || ids[1] != "alert-b" {
		t.Errorf("alert_ids = %v, want [alert-a alert-b]", ev.Attrs["alert_ids"])
	}
	if got := ev.Attrs["alert_count"]; got != 2 {
		t.Errorf("alert_count = %v, want 2", got)
	}
}

// TestEndpointAndQueryShape asserts the collector declares the read-only
// SecurityIncident.Read.All scope and queries /security/incidents on v1.0 with
// a lastUpdateDateTime $filter (server-side windowing) and NO $orderby (the
// endpoint doesn't support it).
func TestEndpointAndQueryShape(t *testing.T) {
	f := &recordingFetcher{records: []map[string]any{{"id": "inc", "lastUpdateDateTime": "2026-07-01T10:00:00Z"}}}
	c := newCollector(depsWith(t, f))

	if got := c.RequiredPermissions(); len(got) != 1 || got[0] != "SecurityIncident.Read.All" {
		t.Errorf("RequiredPermissions = %v, want [SecurityIncident.Read.All]", got)
	}

	from := time.Date(2026, 7, 1, 9, 0, 0, 0, time.UTC)
	if _, err := c.CollectWindow(context.Background(), from, from.Add(time.Hour), telemetrytest.New().Emitter()); err != nil {
		t.Fatalf("CollectWindow: %v", err)
	}
	if len(f.seenURLs) == 0 {
		t.Fatal("no page fetched")
	}
	u := f.seenURLs[0]
	if !strings.HasPrefix(u, "https://graph.microsoft.com/v1.0/security/incidents?") {
		t.Errorf("first-page URL = %q, want the v1.0 /security/incidents endpoint", u)
	}
	if !strings.Contains(u, "lastUpdateDateTime+gt+") || !strings.Contains(u, "lastUpdateDateTime+lt+") {
		t.Errorf("first-page URL = %q, want a lastUpdateDateTime gt/lt $filter window", u)
	}
	if strings.Contains(u, "orderby") {
		t.Errorf("first-page URL = %q, must NOT send $orderby (/security/incidents does not support it)", u)
	}
	// /security/incidents caps $top at 50 (live: $top=1000 -> HTTP 400 "The limit
	// of '50' for Top query has been exceeded"). The engine default is 1000, so
	// the collector must pin PageSize=50 or every live cycle 400s.
	if !strings.Contains(u, "top=50") {
		t.Errorf("first-page URL = %q, want $top=50 (/security/incidents caps $top at 50)", u)
	}
}

// TestCollectorReEmitsAcrossPolls is the integration pass proving re-emit on
// change end-to-end through Poll + a real checkpoint.Store: an incident seen at
// v1, then re-observed with an advanced lastUpdateDateTime, emits TWICE across
// two polls; a third poll with no change emits nothing new.
func TestCollectorReEmitsAcrossPolls(t *testing.T) {
	dir := t.TempDir()
	store := checkpoint.NewStore(dir)
	from := time.Date(2026, 7, 1, 0, 0, 0, 0, time.UTC)

	incV1 := map[string]any{"id": "inc-x", "lastUpdateDateTime": "2026-07-01T09:00:00Z", "displayName": "X", "severity": "medium", "status": "active"}
	f := &recordingFetcher{records: []map[string]any{incV1}}
	rec := telemetrytest.New()
	c := newCollector(collectors.WindowDeps{TenantID: "t1", Fetcher: f, Store: store})

	to := time.Date(2026, 7, 1, 10, 0, 0, 0, time.UTC)
	if _, err := c.CollectWindow(context.Background(), from, to, rec.Emitter()); err != nil {
		t.Fatalf("poll1: %v", err)
	}
	if got := len(rec.LogRecords()); got != 1 {
		t.Fatalf("poll1 emitted %d, want 1", got)
	}

	// Poll 2: the same incident now updated (lastUpdateDateTime advanced) — must
	// re-emit via the composite id. Use a later `to` so the advanced timestamp
	// falls inside the window.
	incV2 := map[string]any{"id": "inc-x", "lastUpdateDateTime": "2026-07-01T12:00:00Z", "displayName": "X", "severity": "medium", "status": "resolved"}
	f.records = []map[string]any{incV2}
	to2 := time.Date(2026, 7, 1, 13, 0, 0, 0, time.UTC)
	if _, err := c.CollectWindow(context.Background(), to, to2, rec.Emitter()); err != nil {
		t.Fatalf("poll2: %v", err)
	}
	if got := len(rec.LogRecords()); got != 2 {
		t.Fatalf("after poll2 total emitted %d, want 2 (re-emit on update)", got)
	}

	// Poll 3: no change — the identical incV2 is deduped, nothing new emitted.
	f.records = []map[string]any{clone(incV2)}
	to3 := time.Date(2026, 7, 1, 14, 0, 0, 0, time.UTC)
	if _, err := c.CollectWindow(context.Background(), to2, to3, rec.Emitter()); err != nil {
		t.Fatalf("poll3: %v", err)
	}
	if got := len(rec.LogRecords()); got != 2 {
		t.Fatalf("after poll3 total emitted %d, want still 2 (unchanged incident deduped)", got)
	}
}

// TestEmitsNoMetrics is the cardinality guard: this collector is a
// WindowCollector that emits ONLY logs. Draining incident records through it
// must produce log records and ZERO metrics — per-incident detail lives in log
// attributes, never as metric labels/series.
func TestEmitsNoMetrics(t *testing.T) {
	f := &recordingFetcher{records: []map[string]any{
		{"id": "inc-a", "lastUpdateDateTime": "2026-07-01T09:00:00Z", "severity": "high", "status": "active", "assignedTo": "a@b.com", "tags": []any{"t1"}},
		{"id": "inc-b", "lastUpdateDateTime": "2026-07-01T09:30:00Z", "severity": "low", "status": "resolved"},
	}}
	rec := telemetrytest.New()
	c := newCollector(depsWith(t, f))

	// Compile-time-ish assertion that this is a WindowCollector.
	var _ collector.WindowCollector = c

	from := time.Date(2026, 7, 1, 8, 0, 0, 0, time.UTC)
	if _, err := c.CollectWindow(context.Background(), from, from.Add(4*time.Hour), rec.Emitter()); err != nil {
		t.Fatalf("CollectWindow: %v", err)
	}
	if got := len(rec.LogRecords()); got != 2 {
		t.Fatalf("emitted %d log records, want 2", got)
	}
	if names := rec.MetricNames(); len(names) != 0 {
		t.Errorf("security-incidents emitted metrics %v, want none — per-incident detail must be log attributes, not metrics", names)
	}
}

// TestCollectorEmitsFullRecordEndToEnd drives the richest record this package
// has (fullIncidentRecord) through the real logpipeline engine into an emitter,
// rather than calling mapIncident directly the way TestMapIncidentHighSeverity
// does.
//
// It exists for #164, and the golden is the point. The signal gate
// (internal/signalcapture) records the union of what a package's tests EMIT.
// Every record that reached the emitter here was a minimal synthetic one
// (TestCollectorReEmitsAcrossPolls, TestEmitsNoMetrics), while the rich record
// only ever reached mapIncident. So testdata/signals.json missed four
// attributes the collector really ships — classification, determination,
// created_time, priority_score — and an attribute absent from the golden cannot
// drift: those four could be renamed or dropped without the gate noticing.
//
// tenant_id is deliberately NOT expected below, and its absence here is correct
// twice over. The mapper ignores the wire field (#143), and this Recorder's
// emitter is bare — telemetry.WithTenant wraps it in the real Scheduler, not
// here. The golden documents what the COLLECTOR emits; tenant_id is stamped
// above it. Do not wrap the emitter to force it into this golden.
func TestCollectorEmitsFullRecordEndToEnd(t *testing.T) {
	f := &recordingFetcher{records: []map[string]any{fullIncidentRecord()}}
	rec := telemetrytest.New()
	c := newCollector(depsWith(t, f))

	// The window must straddle lastUpdateDateTime, not createdDateTime: this
	// collector watermarks on the former (see the package doc's update-aware
	// watermark section) and the engine's gt/lt bounds are strict.
	from := time.Date(2026, 7, 1, 12, 0, 0, 0, time.UTC)
	if _, err := c.CollectWindow(context.Background(), from, from.Add(time.Hour), rec.Emitter()); err != nil {
		t.Fatalf("CollectWindow: %v", err)
	}

	logs := rec.LogRecords()
	if len(logs) != 1 {
		t.Fatalf("emitted %d records, want 1", len(logs))
	}
	got := logs[0]
	if got.EventName != eventName {
		t.Errorf("event name = %q, want %q", got.EventName, eventName)
	}

	// Checked at the EMITTER, not the mapper: every attribute must survive the
	// whole fetch -> map -> dedupe -> emit path, which is the other half of what
	// this test buys over TestMapIncidentHighSeverity.
	//
	// `id` is the CLEAN incident id even though the engine dedupes on the
	// composite "<id>#<lastUpdateDateTime>" — the composite is an engine-internal
	// key and must never reach the wire.
	wantAttrs := map[string]string{
		"id":               "inc-1",
		"display_name":     "Impossible travel activity involving one user",
		"severity":         "high",
		"status":           "active",
		"classification":   "truePositive",
		"determination":    "compromisedAccount",
		"assigned_to":      "analyst@contoso.com",
		"created_time":     "2026-07-01T10:00:00Z",
		"last_update_time": "2026-07-01T12:30:00Z",
	}
	for k, want := range wantAttrs {
		if v := got.Attrs[k]; v != want {
			t.Errorf("emitted attr %q = %q, want %q", k, v, want)
		}
	}

	// priority_score (int) and tags ([]string) are checked for PRESENCE only,
	// and their values are pinned at the mapper instead
	// (TestMapIncidentHighSeverity).
	//
	// Not an oversight, and do not "fix" it by asserting values: telemetrytest
	// .Recorder flattens every log attribute through log.Value.AsString(), which
	// yields "" for any non-string Kind. The recorder cannot represent an int or
	// a slice attribute's value — a limit of the test harness, not of the
	// emission.
	for _, k := range []string{"priority_score", "tags"} {
		if _, present := got.Attrs[k]; !present {
			t.Errorf("emitted attrs missing %q", k)
		}
	}

	// The #143 guard, at the emitter this time: mapIncident ignoring the wire
	// tenantId is asserted in TestWireTenantIDIsNotEmitted, but only this test
	// can show that nothing further down the path re-adds it.
	if v, present := got.Attrs["tenant_id"]; present {
		t.Errorf("emitted attr tenant_id = %q, want it ABSENT — telemetry.WithTenant owns that key (#143), and this bare emitter is not wrapped by it", v)
	}
}

// TestWireTenantIDIsNotEmitted pins the #143 delete. See the identically named
// test in entra/securityalerts for the live measurement and full reasoning: the
// record's `tenantId` is OUR tenant, telemetry.WithTenant already stamps it, and
// a second per-collector writer for a key the emitter owns is how the two would
// eventually disagree. The fixture still supplies tenantId on purpose.
func TestWireTenantIDIsNotEmitted(t *testing.T) {
	_, ev := mapIncident(map[string]any{
		"id":          "1",
		"displayName": "d",
		"severity":    "high",
		"status":      "active",
		"tenantId":    "tenant-guid-1",
	})
	if got, present := ev.Attrs["tenant_id"]; present {
		t.Errorf("mapIncident emitted tenant_id = %v from the wire record.\n"+
			"telemetry.WithTenant owns that key (#143). Do not re-add it.", got)
	}
}
