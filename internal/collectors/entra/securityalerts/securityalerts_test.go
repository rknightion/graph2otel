package securityalerts

import (
	"context"
	_ "embed"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/rknightion/graph2otel/internal/checkpoint"
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

// liveAlertJSON is a VERBATIM GET /security/alerts_v2 record from the m7kni
// tenant, read as graph2otel-poller on 2026-07-17 `[live-measured 2026-07-17,
// #165]`. It is the richest of the five rows the endpoint returned: 36 wire
// keys, 23 evidence entries, and the only row carrying a non-null
// determination/classification pair — every field mapAlert reads is populated
// on it.
//
// It is pinned, not hand-written, because the fixture it replaces was written
// from Microsoft's documentation and got the wire wrong in the one direction
// this package exists to avoid: it set `"status": "newAlert"`, which is the
// LEGACY /security/alerts enum. alerts_v2 does not use it — the five rows read
// `"new"` (x4) and `"resolved"` (x1), none `"newAlert"`. A test asserting
// alerts_v2 is never the legacy endpoint (TestEndpointIsAlertsV2NotLegacy) sat
// two screens below a fixture written in the legacy endpoint's schema. Same
// failure as #142's `"platform": "windows"` and #153's invented `riskType`.
//
// Trimmed of nothing, so it stays a faithful record of what the endpoint
// actually returns — real device names, UPNs, IPs and command lines included
// (this is a SIEM feed; #112 is a data-modeling rule, not a scrubbing one).
// It lives in testdata rather than inline because the record is 1224 lines;
// the riskdetections const it otherwise imitates is 30.
//
// Note the nulls: determination, classification, assignedTo, alertPolicyId,
// actorDisplayName, threatDisplayName and threatFamilyName arrive as JSON
// `null`, NOT absent. str()'s type assertion yields "" for them and setStr
// drops the attribute, so absent and null behave alike — but a mapper reaching
// into one as a nested object would panic.
//
// tenantId stays on the record ON PURPOSE — see TestWireTenantIDIsNotEmitted.
// Its presence is what proves the mapper IGNORES it rather than that a test
// forgot to set it. It is 4b8c18bd-…, byte-equal to the poller's own
// AZURE_TENANT_ID (#143). Do not remove it to "clean up" the fixture.
//
//go:embed testdata/live-alert.json
var liveAlertJSON string

// liveAlertRecord decodes the pinned live record into the untyped shape the
// logpipeline engine hands to the mapper.
//
// Returned from a function rather than shared as a package-level var so no test
// can mutate the record another test reads.
func liveAlertRecord(t *testing.T) map[string]any {
	t.Helper()
	var rec map[string]any
	if err := json.Unmarshal([]byte(liveAlertJSON), &rec); err != nil {
		t.Fatalf("decode live alert record: %v", err)
	}
	return rec
}

// TestMapAlertLiveRecord pins mapAlert against the live record: the dedupe id,
// event name, every attribute's real value, and the body summary.
//
// Every value below was read off the wire, so this test is the package's only
// claim about what alerts_v2 actually sends. The values it asserts are ugly on
// purpose — incident_id is "8", not a GUID; provider_alert_id is the alert id
// minus its two-character service prefix ("da" for Defender for Endpoint) — and
// that ugliness is the evidence. The fixture this replaced asserted eleven
// attributes and got TEN of them wrong; only `category` matched, by luck.
//
// It was TestMapAlertHighSeverity and asserted severity=high => SeverityError.
// No alert on this tenant is "high" — the five rows are medium and low — so
// that name described the fixture's fiction rather than a measured record. The
// severity ladder is mapper policy over an enum, not a claim about the wire, so
// it is pinned directly on severityFor by TestSeverityForLadder below.
func TestMapAlertLiveRecord(t *testing.T) {
	rec := liveAlertRecord(t)

	id, ev := mapAlert(rec)
	if id != "da7d9031bd-68b8-4a8b-9a0a-e3789eba907d_1" {
		t.Fatalf("dedupe id = %q, want the wire alert id", id)
	}
	if ev.Name != eventName {
		t.Fatalf("event name = %q, want %q", ev.Name, eventName)
	}
	if ev.Severity != telemetry.SeverityWarn {
		t.Errorf("severity for alert severity=low = %v, want SeverityWarn", ev.Severity)
	}

	wantAttrs := map[string]any{
		"id":                "da7d9031bd-68b8-4a8b-9a0a-e3789eba907d_1",
		"title":             "Suspicious OpenClaw Installation",
		"category":          "InitialAccess",
		"severity":          "low",
		"status":            "resolved",
		"service_source":    "microsoftDefenderForEndpoint",
		"detection_source":  "microsoftDefenderForEndpoint",
		"determination":     "confirmedActivity",
		"classification":    "informationalExpectedActivity",
		"provider_alert_id": "7d9031bd-68b8-4a8b-9a0a-e3789eba907d_1",
		"incident_id":       "8",
		// 23 real evidence entries: 21 processEvidence, 1 deviceEvidence, 1
		// userEvidence. The fixture this replaced stubbed a 2-item array of bare
		// {"@odata.type": …} objects, so evidence_count was only ever counting a
		// number the test itself chose. Real entries carry 10-30 keys each.
		"evidence_count": 23,
	}
	for k, want := range wantAttrs {
		if got := ev.Attrs[k]; got != want {
			t.Errorf("attr %q = %v, want %v", k, got, want)
		}
	}

	if !strings.Contains(ev.Body, "Suspicious OpenClaw Installation") || !strings.Contains(ev.Body, "low") || !strings.Contains(ev.Body, "resolved") {
		t.Errorf("body = %q, want it to summarize title/severity/status/serviceSource", ev.Body)
	}
}

// TestWireStatusIsNewNotNewAlert pins the measured alertStatus enum.
//
// alerts_v2 sends `"new"`; the LEGACY /security/alerts endpoint sends
// `"newAlert"`. The hand-written fixture #165 replaced used "newAlert" — the
// legacy schema's value — in a package whose sibling test asserts it never
// touches the legacy endpoint. Live-measured 2026-07-17 (#165): 5/5 rows on
// m7kni use the alerts_v2 spelling ("new" x4, "resolved" x1), none use
// "newAlert".
//
// The mapper passes status through verbatim, so this cannot fail on a mapper
// change alone — it guards the FIXTURE, which is the thing that was wrong.
func TestWireStatusIsNewNotNewAlert(t *testing.T) {
	rec := liveAlertRecord(t)
	if got := str(rec, "status"); got == "newAlert" {
		t.Errorf("live fixture status = %q — that is the legacy /security/alerts enum.\n"+
			"alerts_v2 sends \"new\". A fixture carrying it is docs-derived, not measured (#165).", got)
	}
}

// TestSeverityForLadder pins the severity mapping table directly.
//
// This is OUR policy over Microsoft's alertSeverity enum, not a claim about the
// wire, so a table is the honest shape for it — no fixture involved. It matters
// that this is separate: "high" and "informational" have never been observed on
// m7kni (5/5 rows are medium or low, live-measured 2026-07-17, #165), so those
// two rows are docs-derived enum values and are tagged as such rather than
// smuggled into a fixture that claims to be measured.
func TestSeverityForLadder(t *testing.T) {
	for _, tc := range []struct {
		alertSeverity string
		want          telemetry.Severity
	}{
		{"high", telemetry.SeverityError}, // docs-derived: not observed on m7kni
		{"medium", telemetry.SeverityWarn},
		{"low", telemetry.SeverityWarn},
		{"informational", telemetry.SeverityInfo}, // docs-derived: not observed on m7kni
		{"", telemetry.SeverityInfo},
		{"unknownFutureValue", telemetry.SeverityInfo},
	} {
		t.Run(tc.alertSeverity, func(t *testing.T) {
			if got := severityFor(tc.alertSeverity); got != tc.want {
				t.Errorf("severityFor(%q) = %v, want %v", tc.alertSeverity, got, tc.want)
			}
		})
	}
}

// TestMapAlertMediumAndLowSeverityAreWarn asserts "medium" and "low" alert
// severities map to SeverityWarn, and that an alert with no incidentId or
// evidence omits those attributes rather than emitting empty/zero ones.
func TestMapAlertMediumAndLowSeverityAreWarn(t *testing.T) {
	for _, sev := range []string{"medium", "low"} {
		t.Run(sev, func(t *testing.T) {
			rec := map[string]any{
				"id":              "a-" + sev,
				"createdDateTime": "2026-07-01T10:00:00Z",
				"title":           "Suspicious sign-in",
				"severity":        sev,
				"status":          "inProgress",
				"serviceSource":   "microsoftDefenderForCloudApps",
			}
			_, ev := mapAlert(rec)
			if ev.Severity != telemetry.SeverityWarn {
				t.Errorf("severity for alert severity=%s = %v, want SeverityWarn", sev, ev.Severity)
			}
			if _, present := ev.Attrs["incident_id"]; present {
				t.Errorf("alert with no incidentId must not carry incident_id, attrs=%v", ev.Attrs)
			}
			if _, present := ev.Attrs["evidence_count"]; present {
				t.Errorf("alert with no evidence array must not carry evidence_count, attrs=%v", ev.Attrs)
			}
		})
	}
}

// TestMapAlertUnknownSeverityIsInfo asserts an unrecognized/absent severity
// string defaults to SeverityInfo rather than erroring or defaulting to Warn.
func TestMapAlertUnknownSeverityIsInfo(t *testing.T) {
	rec := map[string]any{
		"id":              "a-info",
		"createdDateTime": "2026-07-01T10:00:00Z",
		"title":           "Informational alert",
		"severity":        "informational",
		"status":          "resolved",
		"serviceSource":   "microsoftDefenderForEndpoint",
	}
	_, ev := mapAlert(rec)
	if ev.Severity != telemetry.SeverityInfo {
		t.Errorf("severity for alert severity=informational = %v, want SeverityInfo", ev.Severity)
	}
}

// TestEndpointIsAlertsV2NotLegacy asserts the collector queries the current
// /security/alerts_v2 endpoint on v1.0, never the deprecated legacy
// /security/alerts path.
func TestEndpointIsAlertsV2NotLegacy(t *testing.T) {
	f := &recordingFetcher{records: []map[string]any{{"id": "a", "createdDateTime": "2026-07-01T10:00:00Z"}}}
	c := newCollector(depsWith(t, f))

	if got := c.RequiredPermissions(); len(got) != 1 || got[0] != "SecurityAlert.Read.All" {
		t.Errorf("RequiredPermissions = %v, want [SecurityAlert.Read.All]", got)
	}

	from := time.Date(2026, 7, 1, 9, 0, 0, 0, time.UTC)
	if _, err := c.CollectWindow(context.Background(), from, from.Add(time.Hour), telemetrytest.New().Emitter()); err != nil {
		t.Fatalf("CollectWindow: %v", err)
	}
	if len(f.seenURLs) == 0 {
		t.Fatal("no page fetched")
	}
	u := f.seenURLs[0]
	if !strings.HasPrefix(u, "https://graph.microsoft.com/v1.0/security/alerts_v2?") {
		t.Errorf("first-page URL = %q, want the v1.0 /security/alerts_v2 endpoint", u)
	}
	if strings.Contains(u, "/security/alerts?") || strings.Contains(u, "/security/alerts&") {
		t.Errorf("first-page URL = %q, must never hit the deprecated legacy /security/alerts endpoint", u)
	}
}

// TestCollectorDrainsEmitsAndPersistsWatermark is the integration pass: two
// records fetched through a fake PageFetcher against a real
// checkpoint.NewStore both emit as logs and advance + persist the watermark.
func TestCollectorDrainsEmitsAndPersistsWatermark(t *testing.T) {
	dir := t.TempDir()
	from := time.Date(2026, 7, 1, 9, 0, 0, 0, time.UTC)
	newest := "2026-07-01T09:45:00Z"

	f := &recordingFetcher{records: []map[string]any{
		{"id": "alert-a", "createdDateTime": "2026-07-01T09:10:00Z", "title": "Alert A", "severity": "low", "status": "newAlert", "serviceSource": "identityProtection"},
		{"id": "alert-b", "createdDateTime": newest, "title": "Alert B", "severity": "high", "status": "newAlert", "serviceSource": "identityProtection"},
	}}
	store := checkpoint.NewStore(dir)
	rec := telemetrytest.New()
	c := newCollector(collectors.WindowDeps{TenantID: "t1", Fetcher: f, Store: store})

	if _, err := c.CollectWindow(context.Background(), from, from.Add(time.Hour), rec.Emitter()); err != nil {
		t.Fatalf("CollectWindow: %v", err)
	}
	if got := len(rec.LogRecords()); got != 2 {
		t.Fatalf("emitted %d records, want 2", got)
	}

	cp, err := store.Load("t1", path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cp.Watermark.IsZero() {
		t.Fatal("watermark was not persisted")
	}
	wantHW := time.Date(2026, 7, 1, 9, 45, 0, 0, time.UTC).Add(-logpipelineDefaultSafetyLag)
	if !cp.Watermark.Equal(wantHW) {
		t.Errorf("watermark = %v, want newest(%s) - safetyLag = %v", cp.Watermark, newest, wantHW)
	}
}

// logpipelineDefaultSafetyLag mirrors logpipeline.DefaultSafetyLag (15m), the
// margin the engine trails the watermark by when EndpointConfig.SafetyLag is
// left at its default.
const logpipelineDefaultSafetyLag = 15 * time.Minute

// TestCollectorEmitsFullRecordEndToEnd drives the live record through the real
// logpipeline engine into an emitter, rather than calling mapAlert directly the
// way TestMapAlertLiveRecord does.
//
// It exists for #164, and the golden is the point. The signal gate
// (internal/signalcapture) records the union of what a package's tests EMIT.
// Every record that reached the emitter here was a minimal synthetic one — the
// six-field pair in TestCollectorDrainsEmitsAndPersistsWatermark — while the
// rich record only ever reached mapAlert. So testdata/signals.json claimed a
// 6-attribute surface for a collector that ships 12, and the six it missed are
// the SecOps-relevant half: category, classification, determination,
// detection_source, provider_alert_id, incident_id, evidence_count. An attribute
// absent from the golden cannot drift, so half this collector's surface could be
// renamed or dropped without the gate noticing.
//
// #165 then swapped the fixture under it: the record below is now a live
// capture, not a hand-written one. The golden's KEY SET is unchanged by that
// (13 either way — the hand-written record happened to populate the same eleven
// fields), which is exactly #165's thesis. A golden can be perfectly honest
// about what the mapper emits and still be produced by a shape Microsoft never
// sends. The gate counts keys; only the fixture's provenance decides whether
// those keys were ever real.
//
// tenant_id is deliberately NOT expected below, and its absence here is correct
// twice over. The mapper ignores the wire field (#143), and this Recorder's
// emitter is bare — telemetry.WithTenant wraps it in the real Scheduler, not
// here. The golden documents what the COLLECTOR emits; tenant_id is stamped
// above it. Do not wrap the emitter to force it into this golden.
func TestCollectorEmitsFullRecordEndToEnd(t *testing.T) {
	f := &recordingFetcher{records: []map[string]any{liveAlertRecord(t)}}
	rec := telemetrytest.New()
	c := newCollector(depsWith(t, f))

	// The window brackets the live record's real createdDateTime
	// (2026-05-02T19:45:31.48Z) rather than the synthetic July date the
	// hand-written fixture carried, so the engine sees a record its window
	// actually contains.
	from := time.Date(2026, 5, 2, 18, 0, 0, 0, time.UTC)
	if _, err := c.CollectWindow(context.Background(), from, from.Add(3*time.Hour), rec.Emitter()); err != nil {
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
	// this test buys over TestMapAlertLiveRecord.
	wantAttrs := map[string]string{
		"id":                "da7d9031bd-68b8-4a8b-9a0a-e3789eba907d_1",
		"title":             "Suspicious OpenClaw Installation",
		"category":          "InitialAccess",
		"severity":          "low",
		"status":            "resolved",
		"service_source":    "microsoftDefenderForEndpoint",
		"detection_source":  "microsoftDefenderForEndpoint",
		"determination":     "confirmedActivity",
		"classification":    "informationalExpectedActivity",
		"provider_alert_id": "7d9031bd-68b8-4a8b-9a0a-e3789eba907d_1",
		"incident_id":       "8",
	}
	for k, want := range wantAttrs {
		if v := got.Attrs[k]; v != want {
			t.Errorf("emitted attr %q = %q, want %q", k, v, want)
		}
	}

	// evidence_count is checked for PRESENCE only, and its value is pinned at
	// the mapper instead (TestMapAlertLiveRecord, where it is 23).
	//
	// Not an oversight, and do not "fix" it by asserting a value: it is an int
	// attribute, and telemetrytest.Recorder flattens every log attribute through
	// log.Value.AsString(), which yields "" for any non-string Kind. The recorder
	// cannot represent a non-string attribute's value — a limit of the test
	// harness, not of the emission.
	if _, present := got.Attrs["evidence_count"]; !present {
		t.Error("emitted attrs missing evidence_count")
	}

	// The #143 guard, at the emitter this time: mapAlert ignoring the wire
	// tenantId is asserted in TestWireTenantIDIsNotEmitted, but only this test
	// can show that nothing further down the path re-adds it.
	if v, present := got.Attrs["tenant_id"]; present {
		t.Errorf("emitted attr tenant_id = %q, want it ABSENT — telemetry.WithTenant owns that key (#143), and this bare emitter is not wrapped by it", v)
	}
}

// TestWireTenantIDIsNotEmitted pins the #143 delete.
//
// The Graph record carries its own `tenantId`, and this mapper used to pass it
// through as the `tenant_id` attribute. That field is not Microsoft's tenant or
// a third party's — it is OURS: live-measured 2026-07-17 (#143), every row from
// /security/alerts_v2 on m7kni carried tenantId byte-equal to the poller's own
// AZURE_TENANT_ID. telemetry.WithTenant now stamps exactly that key with exactly
// that value on every record leaving this Scheduler, so the wire field is a
// second, hand-rolled writer for a key the emitter owns.
//
// The fixture below still SUPPLIES tenantId, which is the point: it proves the
// mapper ignores it rather than that the test forgot to set it.
func TestWireTenantIDIsNotEmitted(t *testing.T) {
	_, ev := mapAlert(map[string]any{
		"id":       "alert-1",
		"title":    "t",
		"severity": "high",
		"status":   "newAlert",
		"tenantId": "tenant-guid-1",
	})
	if got, present := ev.Attrs["tenant_id"]; present {
		t.Errorf("mapAlert emitted tenant_id = %v from the wire record.\n"+
			"telemetry.WithTenant owns that key (#143); a per-collector writer for it is how the\n"+
			"two eventually disagree. Do not re-add it.", got)
	}
}
