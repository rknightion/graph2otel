package autopilotevents

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/rknightion/graph2otel/internal/checkpoint"
	"github.com/rknightion/graph2otel/internal/collectors"
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

func TestMapAutopilotEventBasic(t *testing.T) {
	rec := map[string]any{
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
	rec := map[string]any{
		"id":                       "evt-3",
		"deploymentState":          "failed",
		"enrollmentFailureDetails": "aadJoinFailed",
	}
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
	if evFail.Severity != 2 {
		t.Errorf("first attempt (failed) severity = %v, want Error", evFail.Severity)
	}
	if evSuccess.Severity != 0 {
		t.Errorf("retry attempt (success) severity = %v, want Info", evSuccess.Severity)
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
			got, ok := parseISO8601DurationSeconds(tc.in)
			if ok != tc.ok {
				t.Fatalf("parseISO8601DurationSeconds(%q) ok = %v, want %v", tc.in, ok, tc.ok)
			}
			if ok && got != tc.want {
				t.Errorf("parseISO8601DurationSeconds(%q) = %v, want %v", tc.in, got, tc.want)
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
