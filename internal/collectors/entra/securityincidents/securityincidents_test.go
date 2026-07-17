package securityincidents

import (
	"context"
	"encoding/json"
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

// liveIncidentRecord is a VERBATIM GET /security/incidents record from the m7kni
// tenant, read as graph2otel-poller on 2026-07-17 `[live-measured 2026-07-17,
// #165]`. It is the richest of the five incidents the tenant returned: the only
// one carrying a non-empty tag array, and one of only two whose createdDateTime
// and lastUpdateDateTime differ — so it pins both timestamp attributes apart
// from each other and keeps the composite dedupe id honest.
//
// It replaces a HAND-WRITTEN fixture ("inc-1", "tenant-guid-1",
// analyst@contoso.com, an invented priorityScore of 87) derived from Microsoft's
// resource doc, which could only ever confirm its author's beliefs (#165).
//
// Pinning it immediately paid, and the finding is why the fixture reads oddly:
// the wire has NO `tags` key. All five records carry `customTags` and
// `systemTags` instead, so mapIncident's old strSlice(rec, "tags") line was
// DEAD on this endpoint — the same defect as #142's `"platform": "windows"`
// and #153's invented `riskType`. #169 fixed the mapper to read the real
// fields (customTags -> custom_tags, systemTags -> system_tags);
// TestLiveRecordCarriesNoWireTagsKey pins both the wire-shape measurement and
// the fixed behavior.
//
// Trimmed of nothing, so it stays a faithful record of what the endpoint really
// returns. assignedTo, redirectIncidentId, resolvingComment and summary are null
// on the wire (nothing is assigned on this tenant), which is why the live record
// emits no assigned_to attribute. comments, description, incidentWebUrl and
// lastModifiedBy are real keys mapIncident reads nothing from.
//
// `alerts` is ABSENT and always will be: the grouped alert ids only exist under
// $expand=alerts, which this collector never sends (see the package doc), so a
// fixture carrying them would golden two attributes — alert_ids, alert_count —
// that no live poll can produce. That is the golden OVERSTATING rather than
// understating; TestMapIncidentExpandedAlerts keeps covering that
// forward-compatible path at the mapper, where it belongs.
//
// tenantId stays on the record ON PURPOSE and holds OUR tenant, not Microsoft's
// (#143) — see TestWireTenantIDIsNotEmitted. Its presence is what proves the
// mapper IGNORES it rather than that a test forgot to set it.
const liveIncidentRecord = `{
  "assignedTo": null,
  "classification": "unknown",
  "comments": [],
  "createdDateTime": "2026-07-13T19:41:59.3Z",
  "customTags": [],
  "description": "Malware and unwanted software are undesirable applications that perform annoying, disruptive, or harmful actions on affected machines. Some of these undesirable applications can replicate and spread from one machine to another. Others are able to receive commands from remote attackers and perform activities associated with cyber attacks.\n\nThis detection might indicate that the malware was stopped from delivering its payload. However, it is prudent to check the machine for signs of infection.",
  "determination": "unknown",
  "displayName": "'EICAR_Test_File' malware was prevented",
  "id": "14",
  "incidentWebUrl": "https://security.microsoft.com/incident2/14/overview?tid=4b8c18bd-2f9f-4227-af55-9f1061cf9c32",
  "lastModifiedBy": "Microsoft 365 Defender-IncidentCreation",
  "lastUpdateDateTime": "2026-07-13T19:42:19.98Z",
  "priorityScore": 3,
  "redirectIncidentId": null,
  "resolvingComment": null,
  "severity": "informational",
  "status": "active",
  "summary": null,
  "systemTags": [
    "Security Testing"
  ],
  "tenantId": "4b8c18bd-2f9f-4227-af55-9f1061cf9c32"
}`

// liveHighSeverityIncident is a second VERBATIM record from the same 2026-07-17
// m7kni read `[live-measured 2026-07-17, #165]` — the only one of the five with
// severity "high". It is pinned so the high -> SeverityError mapping is asserted
// against a severity string the endpoint really emits: the richest record above
// is "informational", and dropping this case rather than re-homing it would have
// quietly deleted the only coverage of the Error branch.
const liveHighSeverityIncident = `{
  "assignedTo": null,
  "classification": "unknown",
  "comments": [],
  "createdDateTime": "2026-07-16T23:08:53.59Z",
  "customTags": [],
  "description": "More than 28 logs from data source GENERIC_CEF have failed parsing in the last 25 hours.\nVerify that no changes were made to the export configuration of your GENERIC_CEF appliance and that the log format matches the expected format. Go to the governance log page for more details. For more information see https://docs.microsoft.com/en-us/cloud-app-security/troubleshooting-cloud-discovery.",
  "determination": "unknown",
  "displayName": "System alert: Cloud Discovery log-processing error",
  "id": "15",
  "incidentWebUrl": "https://security.microsoft.com/incident2/15/overview?tid=4b8c18bd-2f9f-4227-af55-9f1061cf9c32",
  "lastModifiedBy": "Microsoft 365 Defender-IncidentCreation",
  "lastUpdateDateTime": "2026-07-16T23:08:53.59Z",
  "priorityScore": 25,
  "redirectIncidentId": null,
  "resolvingComment": null,
  "severity": "high",
  "status": "active",
  "summary": null,
  "systemTags": [],
  "tenantId": "4b8c18bd-2f9f-4227-af55-9f1061cf9c32"
}`

// decodeLive unmarshals a pinned live record into the untyped shape the
// logpipeline engine hands to the mapper. Decoding rather than hand-building a
// map[string]any is the point: it reproduces the engine's own JSON decode, so
// priorityScore arrives as float64 and a null assignedTo as nil, exactly as they
// do in production.
//
// Returns a fresh map per call so no test can mutate the record another reads.
func decodeLive(t *testing.T, raw string) map[string]any {
	t.Helper()
	var rec map[string]any
	if err := json.Unmarshal([]byte(raw), &rec); err != nil {
		t.Fatalf("decode live record: %v", err)
	}
	return rec
}

// TestMapIncidentLiveRecord asserts the live incident record maps to the
// expected composite dedupe id, event name, key attributes and priority score.
//
// Every value below is the wire's, not an author's. The composite dedupe id uses
// lastUpdateDateTime (19:42:19.98Z), NOT createdDateTime (19:41:59.3Z) — this
// record is one of the two in the capture where the two timestamps actually
// differ, so confusing them here fails rather than passing by coincidence.
func TestMapIncidentLiveRecord(t *testing.T) {
	rec := decodeLive(t, liveIncidentRecord)

	id, ev := mapIncident(rec)
	if id != "14#2026-07-13T19:42:19.98Z" {
		t.Fatalf("dedupe id = %q, want composite id#lastUpdateDateTime", id)
	}
	if ev.Name != eventName {
		t.Fatalf("event name = %q, want %q", ev.Name, eventName)
	}
	// "informational" is the live severity, and it is the default branch: not
	// high (Error), not medium/low (Warn). TestMapIncidentHighSeverityIsError
	// covers the Error branch on the live "high" record.
	if ev.Severity != telemetry.SeverityInfo {
		t.Errorf("severity for incident severity=informational = %v, want SeverityInfo", ev.Severity)
	}

	// The clean incident id (not the composite) is what lands in attrs.
	if got := ev.Attrs["id"]; got != "14" {
		t.Errorf("attr id = %v, want 14 (the clean incident id, not the composite dedupe id)", got)
	}
	wantStr := map[string]any{
		"display_name":     "'EICAR_Test_File' malware was prevented",
		"severity":         "informational",
		"status":           "active",
		"classification":   "unknown",
		"determination":    "unknown",
		"created_time":     "2026-07-13T19:41:59.3Z",
		"last_update_time": "2026-07-13T19:42:19.98Z",
	}
	for k, want := range wantStr {
		if got := ev.Attrs[k]; got != want {
			t.Errorf("attr %q = %v, want %v", k, got, want)
		}
	}
	// 3, not the old hand-written 87. priorityScore decodes as float64 and must
	// still land as an int attribute.
	if got := ev.Attrs["priority_score"]; got != 3 {
		t.Errorf("attr priority_score = %v (%T), want int 3", got, got)
	}
	// This is the one live record with a non-empty systemTags (#169: Defender-set
	// tags map to system_tags). customTags is empty on it, so custom_tags must be
	// absent.
	systemTags, ok := ev.Attrs["system_tags"].([]string)
	if !ok || len(systemTags) != 1 || systemTags[0] != "Security Testing" {
		t.Errorf("attr system_tags = %v, want [Security Testing]", ev.Attrs["system_tags"])
	}
	if got, present := ev.Attrs["custom_tags"]; present {
		t.Errorf("attr custom_tags = %v, want ABSENT — customTags is empty on this live record", got)
	}
	// assignedTo is null on the wire (nothing is assigned on this tenant), so the
	// attribute must be omitted rather than emitted empty.
	if got, present := ev.Attrs["assigned_to"]; present {
		t.Errorf("attr assigned_to = %v, want it ABSENT — assignedTo is null on the wire", got)
	}
	if !strings.Contains(ev.Body, "EICAR_Test_File") || !strings.Contains(ev.Body, "informational") || !strings.Contains(ev.Body, "active") {
		t.Errorf("body = %q, want it to summarize displayName/severity/status", ev.Body)
	}
}

// TestMapIncidentHighSeverityIsError asserts a "high" severity maps the log
// record's own Severity to Error, driven by the live "high" record rather than a
// hand-written severity string.
func TestMapIncidentHighSeverityIsError(t *testing.T) {
	_, ev := mapIncident(decodeLive(t, liveHighSeverityIncident))

	if ev.Severity != telemetry.SeverityError {
		t.Errorf("severity for incident severity=high = %v, want SeverityError", ev.Severity)
	}
	if got := ev.Attrs["severity"]; got != "high" {
		t.Errorf("attr severity = %v, want high (kept verbatim from the wire)", got)
	}
	if got := ev.Attrs["id"]; got != "15" {
		t.Errorf("attr id = %v, want 15", got)
	}
	if got := ev.Attrs["priority_score"]; got != 25 {
		t.Errorf("attr priority_score = %v (%T), want int 25", got, got)
	}
	// Both customTags and systemTags are empty on this live record, so #169's new
	// custom_tags/system_tags attributes must both be absent.
	for _, k := range []string{"custom_tags", "system_tags"} {
		if got, present := ev.Attrs[k]; present {
			t.Errorf("attr %q = %v, want ABSENT — both tag arrays are empty on this live record", k, got)
		}
	}
}

// TestLiveRecordCarriesNoWireTagsKey pins the #165 measurement that the fixture
// swap found: /security/incidents does NOT send a `tags` key. All five records
// read from m7kni on 2026-07-17 carry `customTags` and `systemTags` instead, so
// mapIncident's strSlice(rec, "tags") is dead on this endpoint and the `tags`
// attribute is unreachable from any live poll.
//
// This test asserts the WIRE SHAPE, deliberately not a corrected mapper. It
// fails the day either the endpoint starts sending `tags` or the mapper is fixed
// to read the real keys — both of which are exactly when someone should be
// looking at this. Until then it stops the next reader concluding from the
// mapper source that `tags` is a thing this collector ships.
//
// The hand-written fixture it replaced asserted `tags: ["Priority","Ransomware"]`
// mapped through and was green for the life of the package. That is what a
// fixture written from documentation buys: it confirms the belief that wrote it.
// Same class as #142 and #153.
func TestLiveRecordCarriesNoWireTagsKey(t *testing.T) {
	cases := map[string]struct {
		raw            string
		wantSystemTags []string // nil means "must be absent"
	}{
		"richest": {liveIncidentRecord, []string{"Security Testing"}},
		"high":    {liveHighSeverityIncident, nil},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			rec := decodeLive(t, tc.raw)

			if _, present := rec["tags"]; present {
				t.Errorf("live record carries a `tags` key: %v.\n"+
					"The 2026-07-17 capture had none on any of 5 records. If the endpoint now "+
					"sends it, mapIncident's dead strSlice(rec, \"tags\") read would need reviving — retire this test.", rec["tags"])
			}
			for _, k := range []string{"customTags", "systemTags"} {
				if _, present := rec[k]; !present {
					t.Errorf("live record is missing the real wire key %q — re-capture before trusting this fixture", k)
				}
			}

			// `tags` stays unreachable — #169 mapped the REAL wire fields instead
			// (customTags -> custom_tags, systemTags -> system_tags) rather than
			// reviving the dead key.
			_, ev := mapIncident(rec)
			if got, present := ev.Attrs["tags"]; present {
				t.Errorf("mapIncident emitted tags = %v from a record with no wire `tags` key", got)
			}
			// customTags is empty on both live records, so custom_tags must stay
			// absent regardless of which fixture this is.
			if got, present := ev.Attrs["custom_tags"]; present {
				t.Errorf("attr custom_tags = %v, want ABSENT — customTags is empty on this live record", got)
			}
			if tc.wantSystemTags == nil {
				if got, present := ev.Attrs["system_tags"]; present {
					t.Errorf("attr system_tags = %v, want ABSENT — systemTags is empty on this live record", got)
				}
				return
			}
			gotSystemTags, ok := ev.Attrs["system_tags"].([]string)
			if !ok || len(gotSystemTags) != len(tc.wantSystemTags) {
				t.Fatalf("system_tags = %v, want %v", ev.Attrs["system_tags"], tc.wantSystemTags)
			}
			for i, want := range tc.wantSystemTags {
				if gotSystemTags[i] != want {
					t.Errorf("system_tags[%d] = %q, want %q", i, gotSystemTags[i], want)
				}
			}
		})
	}
}

// TestMapIncidentCustomAndSystemTags asserts mapIncident reads the wire's real
// tag fields — customTags (operator-set) and systemTags (Defender-set) — into
// custom_tags and system_tags respectively, each following the
// emit-when-non-empty convention (#169). Neither live record captured for this
// package carries a non-empty customTags, so this synthetic case is what
// exercises that branch at all; TestLiveRecordCarriesNoWireTagsKey covers the
// live systemTags branch.
func TestMapIncidentCustomAndSystemTags(t *testing.T) {
	rec := map[string]any{
		"id":                 "inc-tags",
		"lastUpdateDateTime": "2026-07-01T10:00:00Z",
		"severity":           "low",
		"status":             "active",
		"customTags":         []any{"VIP"},
		"systemTags":         []any{"Ransomware"},
	}
	_, ev := mapIncident(rec)

	custom, ok := ev.Attrs["custom_tags"].([]string)
	if !ok || len(custom) != 1 || custom[0] != "VIP" {
		t.Errorf("custom_tags = %v, want [VIP]", ev.Attrs["custom_tags"])
	}
	system, ok := ev.Attrs["system_tags"].([]string)
	if !ok || len(system) != 1 || system[0] != "Ransomware" {
		t.Errorf("system_tags = %v, want [Ransomware]", ev.Attrs["system_tags"])
	}

	// Empty wire arrays must omit the attribute, not emit an empty slice (#112).
	_, evEmpty := mapIncident(map[string]any{
		"id": "inc-empty-tags", "lastUpdateDateTime": "2026-07-01T10:00:00Z",
		"severity": "low", "status": "active",
		"customTags": []any{}, "systemTags": []any{},
	})
	for _, k := range []string{"custom_tags", "system_tags"} {
		if _, present := evEmpty.Attrs[k]; present {
			t.Errorf("attr %q present for empty wire array, want absent", k)
		}
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
			for _, k := range []string{"assigned_to", "tags", "custom_tags", "system_tags", "priority_score", "alert_ids", "alert_count"} {
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
		{"id": "inc-a", "lastUpdateDateTime": "2026-07-01T09:00:00Z", "severity": "high", "status": "active", "assignedTo": "a@b.com"},
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

// TestCollectorEmitsFullRecordEndToEnd drives the richest LIVE record this
// package has (liveIncidentRecord) through the real logpipeline engine into an
// emitter, rather than calling mapIncident directly the way
// TestMapIncidentLiveRecord does.
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
// #165 then replaced the rich record itself with a live capture, which is what
// makes this golden a measurement rather than a restatement of the fixture
// author's beliefs. Note what the live record does NOT emit: no `tags` (the
// wire has no such key — see TestLiveRecordCarriesNoWireTagsKey), no
// `custom_tags` (customTags is empty on this record — #169), and no
// `assigned_to` (null on the wire). `assigned_to` survives in
// testdata/signals.json ONLY because a hand-written record in TestEmitsNoMetrics
// still emits it; no live poll can. `tags` and `custom_tags` do NOT appear in
// the golden at all — no test, live or synthetic, emits either.
//
// tenant_id is deliberately NOT expected below, and its absence here is correct
// twice over. The mapper ignores the wire field (#143), and this Recorder's
// emitter is bare — telemetry.WithTenant wraps it in the real Scheduler, not
// here. The golden documents what the COLLECTOR emits; tenant_id is stamped
// above it. Do not wrap the emitter to force it into this golden.
func TestCollectorEmitsFullRecordEndToEnd(t *testing.T) {
	f := &recordingFetcher{records: []map[string]any{decodeLive(t, liveIncidentRecord)}}
	rec := telemetrytest.New()
	c := newCollector(depsWith(t, f))

	// The window must straddle lastUpdateDateTime (19:42:19.98Z), not
	// createdDateTime (19:41:59.3Z): this collector watermarks on the former (see
	// the package doc's update-aware watermark section) and the engine's gt/lt
	// bounds are strict. The live record is one of the two in the capture where
	// those two timestamps differ, so the distinction is load-bearing here.
	from := time.Date(2026, 7, 13, 19, 30, 0, 0, time.UTC)
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
		"id":               "14",
		"display_name":     "'EICAR_Test_File' malware was prevented",
		"severity":         "informational",
		"status":           "active",
		"classification":   "unknown",
		"determination":    "unknown",
		"created_time":     "2026-07-13T19:41:59.3Z",
		"last_update_time": "2026-07-13T19:42:19.98Z",
	}
	for k, want := range wantAttrs {
		if v := got.Attrs[k]; v != want {
			t.Errorf("emitted attr %q = %q, want %q", k, v, want)
		}
	}

	// priority_score (int) and system_tags ([]string) are checked for PRESENCE
	// only, and their values are pinned at the mapper instead
	// (TestMapIncidentLiveRecord).
	//
	// Not an oversight, and do not "fix" it by asserting the value: telemetrytest
	// .Recorder flattens every log attribute through log.Value.AsString(), which
	// yields "" for any non-string Kind. The recorder cannot represent an int or
	// a slice attribute's value — a limit of the test harness, not of the
	// emission.
	for _, k := range []string{"priority_score", "system_tags"} {
		if _, present := got.Attrs[k]; !present {
			t.Errorf("emitted attrs missing %q", k)
		}
	}

	// The attributes the live record proves are NOT reachable. `tags` is
	// unreachable for every record (/security/incidents sends
	// customTags/systemTags, never tags — TestLiveRecordCarriesNoWireTagsKey);
	// custom_tags is unreachable for THIS record only (customTags is empty on it
	// — #169); assigned_to is unreachable for THIS record only (assignedTo is
	// null — an assigned incident would emit it). Asserting their absence is
	// what stops the old hand-written expectations creeping back in.
	for _, k := range []string{"tags", "custom_tags", "assigned_to"} {
		if v, present := got.Attrs[k]; present {
			t.Errorf("emitted attr %q = %q, want it ABSENT — the live record carries no value for it", k, v)
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
