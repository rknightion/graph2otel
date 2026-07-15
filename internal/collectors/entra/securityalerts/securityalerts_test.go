package securityalerts

import (
	"context"
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

// TestMapAlertHighSeverity asserts a representative alerts_v2 record maps to
// the expected dedupe id, event name, key attributes, and that a "high"
// alert severity string maps the log record's own Severity to Error.
func TestMapAlertHighSeverity(t *testing.T) {
	rec := map[string]any{
		"id":              "alert-1",
		"createdDateTime": "2026-07-01T10:00:00Z",
		"title":           "Impossible travel activity",
		"category":        "InitialAccess",
		"severity":        "high",
		"status":          "newAlert",
		"serviceSource":   "identityProtection",
		"detectionSource": "identityProtection",
		"determination":   "unknownFutureValue",
		"classification":  "unknown",
		"providerAlertId": "provider-guid-1",
		"tenantId":        "tenant-guid-1",
		"incidentId":      "incident-1",
		"evidence":        []any{map[string]any{"@odata.type": "#microsoft.graph.security.userEvidence"}, map[string]any{"@odata.type": "#microsoft.graph.security.ipEvidence"}},
	}

	id, ev := mapAlert(rec)
	if id != "alert-1" {
		t.Fatalf("dedupe id = %q, want alert-1", id)
	}
	if ev.Name != eventName {
		t.Fatalf("event name = %q, want %q", ev.Name, eventName)
	}
	if ev.Severity != telemetry.SeverityError {
		t.Errorf("severity for alert severity=high = %v, want SeverityError", ev.Severity)
	}

	wantAttrs := map[string]any{
		"id":                "alert-1",
		"title":             "Impossible travel activity",
		"category":          "InitialAccess",
		"severity":          "high",
		"status":            "newAlert",
		"service_source":    "identityProtection",
		"detection_source":  "identityProtection",
		"determination":     "unknownFutureValue",
		"classification":    "unknown",
		"provider_alert_id": "provider-guid-1",
		"tenant_id":         "tenant-guid-1",
		"incident_id":       "incident-1",
		"evidence_count":    2,
	}
	for k, want := range wantAttrs {
		if got := ev.Attrs[k]; got != want {
			t.Errorf("attr %q = %v, want %v", k, got, want)
		}
	}

	if !strings.Contains(ev.Body, "Impossible travel activity") || !strings.Contains(ev.Body, "high") || !strings.Contains(ev.Body, "newAlert") {
		t.Errorf("body = %q, want it to summarize title/severity/status/serviceSource", ev.Body)
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
