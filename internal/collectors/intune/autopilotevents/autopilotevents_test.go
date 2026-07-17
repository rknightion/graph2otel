package autopilotevents

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/rknightion/graph2otel/internal/checkpoint"
	"github.com/rknightion/graph2otel/internal/collectors"
	"github.com/rknightion/graph2otel/internal/semconv"
	"github.com/rknightion/graph2otel/internal/telemetry"
	"github.com/rknightion/graph2otel/internal/telemetrytest"
)

// recordingFetcher is a logpipeline.PageFetcher that returns a fixed set of
// records once and records every requested page URL, mirroring the
// entra/signins reference test's fetcher.
type recordingFetcher struct {
	records  []map[string]any
	seenURLs []string
}

func (f *recordingFetcher) FetchPage(_ context.Context, pageURL string) ([]map[string]any, string, error) {
	f.seenURLs = append(f.seenURLs, pageURL)
	return f.records, "", nil
}

// --- shared fixtures ---
//
// Shared by the mapper tests and by TestCollectorEmitsFullRecordsEndToEnd so
// the two can never drift into describing different records, mirroring how
// entra/riskdetections shares one record between its mapper tests and its
// end-to-end test.
//
// They are SYNTHETIC, and that gap is worth stating rather than implying:
// unlike entra/riskdetections' liveRiskDetection, this tree pins no verbatim
// GET beta/deviceManagement/autopilotEvents response, so no field NAME here is
// evidence of wire shape — they are docs-level claims, and this endpoint is
// BETA, where an undocumented schema change is an expected risk (see #164, and
// CLAUDE.md on "platform": "windows", #142). autopilotEvents returned 0 rows —
// endpoint empty on tenant 2026-07-17 (#165) — so no live sample exists to pin.
//
// What the end-to-end test proves regardless of provenance: whatever
// mapAutopilotEvent sets survives the engine to the emitter — which is what
// makes testdata/signals.json honest, since the golden records attribute KEYS
// ONLY (internal/signalcapture) and a key set does not depend on whether the
// values a fixture carries are real.
//
// Each returns a fresh map so the engine can never mutate a shared literal.

// successfulAutopilotEvent is the richest single record here: every field
// mapAutopilotEvent reads except enrollmentFailureDetails, which by definition
// cannot appear on a success.
func successfulAutopilotEvent() map[string]any {
	return map[string]any{
		"id":                   "evt-1",
		"deviceId":             "device-guid",
		"deviceSerialNumber":   "SN12345",
		"enrollmentType":       "windowsAzureADJoin",
		"deploymentState":      "success",
		"deviceSetupStatus":    "success",
		"accountSetupStatus":   "success",
		"deploymentDuration":   "PT5M0S",
		"deviceSetupDuration":  "PT2M30S",
		"accountSetupDuration": "PT1M0S",
		"eventDateTime":        "2026-07-01T10:00:00Z",
	}
}

// failedAutopilotEvent is the only source of the enrollment_failure_details
// attribute.
//
// It composes two records this package's tests already had, and invents
// nothing: the id/deploymentState/enrollmentFailureDetails values are verbatim
// from TestMapAutopilotEventFailureIsError's record, and eventDateTime is the
// envelope field the engine requires — a failure record carrying one is
// likewise already in this file (TestCollectorDrainsEmitsAndPersistsWatermark's
// "evt-b"). The mapper test could omit eventDateTime because it never reaches
// the engine; the end-to-end test cannot, since this endpoint is NoServerFilter
// and the engine drops any record whose TimeField falls outside [from, to].
func failedAutopilotEvent() map[string]any {
	return map[string]any{
		"id":                       "evt-3",
		"deploymentState":          "failed",
		"enrollmentFailureDetails": "aadJoinFailed",
		"eventDateTime":            "2026-07-01T10:30:00Z",
	}
}

func TestMapAutopilotEventBasic(t *testing.T) {
	rec := successfulAutopilotEvent()
	id, ev := mapAutopilotEvent(rec)
	if id != "evt-1" {
		t.Fatalf("dedupe id = %q, want evt-1", id)
	}
	if ev.Name != eventName {
		t.Fatalf("event name = %q, want %q", ev.Name, eventName)
	}
	if ev.Severity != 0 { // SeverityInfo
		t.Errorf("successful event severity = %v, want Info", ev.Severity)
	}
	wantAttrs := map[string]any{
		"id":                             "evt-1",
		"device_id":                      "device-guid",
		"device_serial_number":           "SN12345",
		"enrollment_type":                "windowsAzureADJoin",
		"deployment_state":               "success",
		"device_setup_status":            "success",
		"account_setup_status":           "success",
		"deployment_duration_seconds":    300.0,
		"device_setup_duration_seconds":  150.0,
		"account_setup_duration_seconds": 60.0,
	}
	for k, want := range wantAttrs {
		if got := ev.Attrs[k]; got != want {
			t.Errorf("attr %q = %v (%T), want %v (%T)", k, got, got, want, want)
		}
	}
}

// #16 acceptance: keep deviceSetupStatus/accountSetupStatus/deploymentState
// as three DISTINCT attributes rather than collapsing them into one "phase"
// enum, since a device can e.g. succeed setup but fail account setup.
func TestMapAutopilotEventKeepsThreePhasesDistinct(t *testing.T) {
	rec := map[string]any{
		"id":                 "evt-2",
		"deploymentState":    "failed",
		"deviceSetupStatus":  "success",
		"accountSetupStatus": "failed",
	}
	_, ev := mapAutopilotEvent(rec)
	if ev.Attrs["deployment_state"] != "failed" {
		t.Errorf("deployment_state = %v, want failed", ev.Attrs["deployment_state"])
	}
	if ev.Attrs["device_setup_status"] != "success" {
		t.Errorf("device_setup_status = %v, want success", ev.Attrs["device_setup_status"])
	}
	if ev.Attrs["account_setup_status"] != "failed" {
		t.Errorf("account_setup_status = %v, want failed", ev.Attrs["account_setup_status"])
	}
}

func TestMapAutopilotEventFailureIsError(t *testing.T) {
	rec := failedAutopilotEvent()
	_, ev := mapAutopilotEvent(rec)
	if ev.Severity != 2 { // SeverityError
		t.Errorf("failed event severity = %v, want Error", ev.Severity)
	}
	if ev.Attrs["enrollment_failure_details"] != "aadJoinFailed" {
		t.Errorf("enrollment_failure_details = %v, want aadJoinFailed", ev.Attrs["enrollment_failure_details"])
	}
}

func TestMapAutopilotEventOmitsAbsentFailureDetails(t *testing.T) {
	rec := map[string]any{"id": "evt-4", "deploymentState": "success"}
	_, ev := mapAutopilotEvent(rec)
	if _, present := ev.Attrs["enrollment_failure_details"]; present {
		t.Errorf("enrollment_failure_details must be omitted when absent, attrs=%v", ev.Attrs)
	}
	if _, present := ev.Attrs["deployment_duration_seconds"]; present {
		t.Errorf("deployment_duration_seconds must be omitted when absent, attrs=%v", ev.Attrs)
	}
}

// #16 acceptance: clamp negative phase durations (client clock skew) to
// zero rather than emitting a negative duration.
func TestMapAutopilotEventNegativeDurationClampsToZero(t *testing.T) {
	rec := map[string]any{
		"id":                  "evt-5",
		"deploymentDuration":  "-PT5S",
		"deviceSetupDuration": "-PT1H",
	}
	_, ev := mapAutopilotEvent(rec)
	if got := ev.Attrs["deployment_duration_seconds"]; got != 0.0 {
		t.Errorf("clamped deployment_duration_seconds = %v, want 0", got)
	}
	if got := ev.Attrs["device_setup_duration_seconds"]; got != 0.0 {
		t.Errorf("clamped device_setup_duration_seconds = %v, want 0", got)
	}
}

// #16 acceptance: retry events (multiple per device) carry distinct ids and
// must both be emitted — a later success record must never erase an earlier
// failure record via the mapping.
func TestMapAutopilotEventRetryRecordsHaveDistinctIDs(t *testing.T) {
	failureRec := map[string]any{"id": "evt-attempt-1", "deploymentState": "failed"}
	successRec := map[string]any{"id": "evt-attempt-1-retry", "deploymentState": "success"}
	idFail, evFail := mapAutopilotEvent(failureRec)
	idSuccess, evSuccess := mapAutopilotEvent(successRec)
	if idFail == idSuccess {
		t.Fatalf("retry records must not share a dedupe id: %q == %q", idFail, idSuccess)
	}
	// Compare the named constants, not raw ints: telemetry.Severity (Info=0,
	// Warn=1, Error=2) and the OTEL wire scale (INFO=9, WARN=13, ERROR=17) are
	// different, and bare numbers are how that gets confused (#113).
	if evFail.Severity != telemetry.SeverityError {
		t.Errorf("first attempt (failed) severity = %v, want %v", evFail.Severity, telemetry.SeverityError)
	}
	if evSuccess.Severity != telemetry.SeverityInfo {
		t.Errorf("retry attempt (success) severity = %v, want %v", evSuccess.Severity, telemetry.SeverityInfo)
	}
}

func TestParseISO8601DurationSeconds(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want float64
		ok   bool
	}{
		{"minutes_seconds", "PT1M30S", 90, true},
		{"hours", "PT2H", 7200, true},
		{"zero", "PT0S", 0, true},
		{"negative_clamped", "-PT5S", 0, true},
		{"negative_hour_clamped", "-PT1H", 0, true},
		{"empty", "", 0, false},
		{"garbage", "not-a-duration", 0, false},
		{"bare_p", "P", 0, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			attrs := telemetry.Attrs{}
			telemetry.SetDurationSeconds(attrs, semconv.AttrDeploymentDurationSeconds, tc.in)
			got, ok := attrs[semconv.AttrDeploymentDurationSeconds]
			if ok != tc.ok {
				t.Fatalf("SetDurationSeconds(%q) set = %v, want %v", tc.in, ok, tc.ok)
			}
			if ok && got != tc.want {
				t.Errorf("SetDurationSeconds(%q) = %v, want %v", tc.in, got, tc.want)
			}
		})
	}
}

func depsWith(t *testing.T, f *recordingFetcher) collectors.WindowDeps {
	t.Helper()
	return collectors.WindowDeps{
		TenantID: "t1",
		Fetcher:  f,
		Store:    checkpoint.NewStore(t.TempDir()),
	}
}

func TestCollectorIsExperimentalAndUsesBetaEndpointWithNoServerFilter(t *testing.T) {
	f := &recordingFetcher{records: []map[string]any{{"id": "a", "eventDateTime": "2026-07-01T10:00:00Z"}}}
	c := newCollector(depsWith(t, f))

	if !c.Experimental() {
		t.Error("autopilot events collector must be Experimental (beta-only endpoint)")
	}
	perms := c.RequiredPermissions()
	if len(perms) != 1 || perms[0] != "DeviceManagementManagedDevices.Read.All" {
		t.Errorf("RequiredPermissions = %v, want [DeviceManagementManagedDevices.Read.All]", perms)
	}

	from := time.Date(2026, 7, 1, 9, 0, 0, 0, time.UTC)
	if _, err := c.CollectWindow(context.Background(), from, from.Add(time.Hour), telemetrytest.New().Emitter()); err != nil {
		t.Fatalf("CollectWindow: %v", err)
	}
	if len(f.seenURLs) == 0 {
		t.Fatal("no page fetched")
	}
	u := f.seenURLs[0]
	if !strings.HasPrefix(u, "https://graph.microsoft.com/beta/deviceManagement/autopilotEvents") {
		t.Errorf("first-page URL = %q, want the beta autopilotEvents endpoint", u)
	}
	if strings.Contains(u, "$filter=") {
		t.Errorf("first-page URL = %q, want NO $filter (NoServerFilter: no documented server-side filter)", u)
	}
}

// TestCollectorEmitsFullRecordsEndToEnd drives this package's two richest
// records through the real engine into an emitter, rather than calling
// mapAutopilotEvent directly like the tests above.
//
// It proves every attribute mapAutopilotEvent sets survives the whole path, and
// it is what makes testdata/signals.json honest: the signal gate goldens the
// union of what a package's tests EMIT, so with only the minimal synthetic
// records of the watermark test reaching the emitter, the golden recorded a
// 3-attribute surface (deployment_state, id, ingest_transport) for a collector
// that really ships 12 — understating the exact thing the golden exists to make
// reviewable (#164). Both records are needed: a success record cannot carry
// enrollment_failure_details.
func TestCollectorEmitsFullRecordsEndToEnd(t *testing.T) {
	f := &recordingFetcher{records: []map[string]any{
		successfulAutopilotEvent(),
		failedAutopilotEvent(),
	}}
	rec := telemetrytest.New()
	c := newCollector(collectors.WindowDeps{TenantID: "t1", Fetcher: f, Store: checkpoint.NewStore(t.TempDir())})

	// Both records' eventDateTime (10:00, 10:30) must fall inside [from, to]:
	// this endpoint is NoServerFilter, so the engine bounds the window
	// client-side and drops anything outside it.
	from := time.Date(2026, 7, 1, 9, 0, 0, 0, time.UTC)
	if _, err := c.CollectWindow(context.Background(), from, from.Add(2*time.Hour), rec.Emitter()); err != nil {
		t.Fatalf("CollectWindow: %v", err)
	}

	logs := rec.LogRecords()
	if len(logs) != 2 {
		t.Fatalf("emitted %d records, want 2", len(logs))
	}
	byID := map[string]map[string]string{}
	for _, got := range logs {
		if got.EventName != eventName {
			t.Errorf("event name = %q, want %q", got.EventName, eventName)
		}
		byID[got.Attrs["id"]] = got.Attrs
	}

	// String attributes checked at the emitter rather than the mapper.
	wantSuccess := map[string]string{
		"id":                   "evt-1",
		"device_id":            "device-guid",
		"device_serial_number": "SN12345",
		"enrollment_type":      "windowsAzureADJoin",
		"deployment_state":     "success",
		"device_setup_status":  "success",
		"account_setup_status": "success",
		// The transport stamp the engine applies at the emitter boundary (#141).
		"ingest_transport": "graph",
	}
	for k, want := range wantSuccess {
		if got := byID["evt-1"][k]; got != want {
			t.Errorf("evt-1 emitted attr %q = %q, want %q", k, got, want)
		}
	}
	if got := byID["evt-3"]["enrollment_failure_details"]; got != "aadJoinFailed" {
		t.Errorf("evt-3 emitted attr %q = %q, want %q", "enrollment_failure_details", got, "aadJoinFailed")
	}

	// The three phase durations are checked for PRESENCE only, and their values
	// are pinned at the mapper instead (TestMapAutopilotEventBasic).
	//
	// Not an oversight, and do not "fix" it by asserting values here: they are
	// emitted as OTLP doubles (telemetry.toLogKV maps float64 → log.Float64,
	// which is correct on the wire), but telemetrytest.Recorder flattens every
	// log attribute through log.Value.AsString(), which yields "" for any
	// non-string Kind. So the recorder cannot represent a float attribute's
	// value — a limitation of the test harness, not of the emission.
	for _, k := range []string{"deployment_duration_seconds", "device_setup_duration_seconds", "account_setup_duration_seconds"} {
		if _, present := byID["evt-1"][k]; !present {
			t.Errorf("evt-1 emitted attrs missing %q", k)
		}
	}
}

func TestCollectorDrainsEmitsAndPersistsWatermark(t *testing.T) {
	dir := t.TempDir()
	from := time.Date(2026, 7, 1, 9, 0, 0, 0, time.UTC)
	to := from.Add(time.Hour)
	newest := "2026-07-01T09:45:00Z"

	f := &recordingFetcher{records: []map[string]any{
		{"id": "evt-a", "eventDateTime": "2026-07-01T09:10:00Z", "deploymentState": "success"},
		{"id": "evt-b", "eventDateTime": newest, "deploymentState": "failed"},
	}}
	store := checkpoint.NewStore(dir)
	rec := telemetrytest.New()
	c := newCollector(collectors.WindowDeps{TenantID: "t1", Fetcher: f, Store: store})

	if _, err := c.CollectWindow(context.Background(), from, to, rec.Emitter()); err != nil {
		t.Fatalf("CollectWindow: %v", err)
	}
	if got := len(rec.LogRecords()); got != 2 {
		t.Fatalf("emitted %d records, want 2", got)
	}
	cp, err := store.Load("t1", autopilotEventsPath)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cp.Watermark.IsZero() {
		t.Fatal("watermark was not persisted")
	}
}
