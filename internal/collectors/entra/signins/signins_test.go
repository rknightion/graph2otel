package signins

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/rknightion/graph2otel/internal/checkpoint"
	"github.com/rknightion/graph2otel/internal/collectors"
	"github.com/rknightion/graph2otel/internal/license"
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

func specByName(t *testing.T, name string) spec {
	t.Helper()
	for _, s := range specs {
		if s.name == name {
			return s
		}
	}
	t.Fatalf("no spec named %q", name)
	return spec{}
}

func TestMapSignInUserSignInSuccess(t *testing.T) {
	rec := map[string]any{
		"id":                      "sign-in-1",
		"correlationId":           "corr-1",
		"createdDateTime":         "2026-07-01T10:00:00Z",
		"userPrincipalName":       "alice@contoso.com",
		"appId":                   "app-guid",
		"appDisplayName":          "Graph Explorer",
		"ipAddress":               "203.0.113.7",
		"clientAppUsed":           "Browser",
		"conditionalAccessStatus": "success",
		"location":                map[string]any{"countryOrRegion": "GB"},
		"signInEventTypes":        []any{"interactiveUser"},
		"status":                  map[string]any{"errorCode": float64(0)},
	}
	id, ev := mapSignIn(rec)
	if id != "sign-in-1" {
		t.Fatalf("dedupe id = %q, want sign-in-1", id)
	}
	if ev.Name != eventName {
		t.Fatalf("event name = %q, want %q", ev.Name, eventName)
	}
	if ev.Severity != 0 { // SeverityInfo
		t.Errorf("successful sign-in severity = %v, want Info", ev.Severity)
	}
	wantAttrs := map[string]any{
		"id":                         "sign-in-1",
		"correlation_id":             "corr-1",
		"user_principal_name":        "alice@contoso.com",
		"ip_address":                 "203.0.113.7",
		"conditional_access_status":  "success",
		"location_country_or_region": "GB",
		"status_error_code":          0,
	}
	for k, want := range wantAttrs {
		if got := ev.Attrs[k]; got != want {
			t.Errorf("attr %q = %v, want %v", k, got, want)
		}
	}
}

func TestMapSignInFailureIsWarn(t *testing.T) {
	rec := map[string]any{
		"id":                "s2",
		"userPrincipalName": "bob@contoso.com",
		"appDisplayName":    "Office",
		"status":            map[string]any{"errorCode": float64(50126), "failureReason": "Invalid credentials"},
	}
	_, ev := mapSignIn(rec)
	if ev.Severity != 1 { // SeverityWarn
		t.Errorf("failed sign-in severity = %v, want Warn", ev.Severity)
	}
	if ev.Attrs["status_error_code"] != 50126 {
		t.Errorf("status_error_code = %v, want 50126", ev.Attrs["status_error_code"])
	}
	if ev.Attrs["status_failure_reason"] != "Invalid credentials" {
		t.Errorf("status_failure_reason = %v", ev.Attrs["status_failure_reason"])
	}
	if !strings.Contains(ev.Body, "failure (50126)") {
		t.Errorf("body = %q, want it to mention the failure code", ev.Body)
	}
}

// #20 acceptance: a service-principal sign-in has no userPrincipalName — the
// attribute must be OMITTED, not emitted empty.
func TestMapSignInServicePrincipalOmitsUserPrincipalName(t *testing.T) {
	rec := map[string]any{
		"id":                   "sp1",
		"servicePrincipalId":   "sp-guid",
		"servicePrincipalName": "my-automation",
		"appId":                "app-guid",
		"resourceDisplayName":  "Microsoft Graph",
		"status":               map[string]any{"errorCode": float64(0)},
	}
	_, ev := mapSignIn(rec)
	if _, present := ev.Attrs["user_principal_name"]; present {
		t.Errorf("service-principal sign-in must not carry user_principal_name, attrs=%v", ev.Attrs)
	}
	if ev.Attrs["service_principal_id"] != "sp-guid" {
		t.Errorf("service_principal_id = %v, want sp-guid", ev.Attrs["service_principal_id"])
	}
	if ev.Attrs["service_principal_name"] != "my-automation" {
		t.Errorf("service_principal_name = %v", ev.Attrs["service_principal_name"])
	}
}

func TestInteractiveIsV1AndDefaultOn(t *testing.T) {
	f := &recordingFetcher{records: []map[string]any{{"id": "a", "createdDateTime": "2026-07-01T10:00:00Z"}}}
	c := newCollector(specByName(t, "entra.signins.interactive"), depsWith(t, f))

	if c.Experimental() {
		t.Error("interactive stream must not be Experimental (it is the v1.0 default slice)")
	}
	if c.RequiredCapability() != license.CapEntraP1 {
		t.Errorf("RequiredCapability = %q, want entra_p1", c.RequiredCapability())
	}

	from := time.Date(2026, 7, 1, 9, 0, 0, 0, time.UTC)
	if _, err := c.CollectWindow(context.Background(), from, from.Add(time.Hour), telemetrytest.New().Emitter()); err != nil {
		t.Fatalf("CollectWindow: %v", err)
	}
	if len(f.seenURLs) == 0 {
		t.Fatal("no page fetched")
	}
	u := f.seenURLs[0]
	if !strings.HasPrefix(u, "https://graph.microsoft.com/v1.0/auditLogs/signIns?") {
		t.Errorf("interactive first-page URL = %q, want the v1.0 signIns endpoint", u)
	}
	if strings.Contains(u, "signInEventTypes") {
		t.Errorf("interactive stream must not carry a signInEventTypes filter, URL=%q", u)
	}
}

func TestBetaStreamsUseBetaEndpointAndEventTypeFilter(t *testing.T) {
	cases := []struct {
		name      string
		eventType string
	}{
		{"entra.signins.non_interactive", "nonInteractiveUser"},
		{"entra.signins.service_principal", "servicePrincipal"},
		{"entra.signins.managed_identity", "managedIdentity"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := &recordingFetcher{records: []map[string]any{{"id": "a", "createdDateTime": "2026-07-01T10:00:00Z"}}}
			c := newCollector(specByName(t, tc.name), depsWith(t, f))
			if !c.Experimental() {
				t.Error("beta signInEventTypes stream must be Experimental (opt-in)")
			}
			from := time.Date(2026, 7, 1, 9, 0, 0, 0, time.UTC)
			if _, err := c.CollectWindow(context.Background(), from, from.Add(time.Hour), telemetrytest.New().Emitter()); err != nil {
				t.Fatalf("CollectWindow: %v", err)
			}
			u := f.seenURLs[0]
			if !strings.HasPrefix(u, "https://graph.microsoft.com/beta/auditLogs/signIns?") {
				t.Errorf("first-page URL = %q, want the BETA signIns endpoint", u)
			}
			if !strings.Contains(u, "signInEventTypes") || !strings.Contains(u, tc.eventType) {
				t.Errorf("first-page URL = %q, want it to filter signInEventTypes for %q", u, tc.eventType)
			}
		})
	}
}

// The four streams share /auditLogs/signIns but must keep independent
// checkpoints: the same sign-in id in each stream is a distinct event and all
// four must emit it (no cross-stream dedupe collision).
func TestStreamsHaveIndependentCheckpoints(t *testing.T) {
	store := checkpoint.NewStore(t.TempDir())
	rec := telemetrytest.New()
	from := time.Date(2026, 7, 1, 9, 0, 0, 0, time.UTC)

	for _, s := range specs {
		f := &recordingFetcher{records: []map[string]any{{"id": "shared", "createdDateTime": "2026-07-01T09:30:00Z"}}}
		d := collectors.WindowDeps{TenantID: "t1", Fetcher: f, Store: store}
		c := newCollector(s, d)
		if _, err := c.CollectWindow(context.Background(), from, from.Add(time.Hour), rec.Emitter()); err != nil {
			t.Fatalf("%s CollectWindow: %v", s.name, err)
		}
	}

	if got := len(rec.LogRecords()); got != len(specs) {
		t.Fatalf("expected %d emitted records (one per independent stream), got %d — streams collided on a shared checkpoint", len(specs), got)
	}
}

func TestCollectorDrainsEmitsAndPersistsWatermark(t *testing.T) {
	dir := t.TempDir()
	from := time.Date(2026, 7, 1, 9, 0, 0, 0, time.UTC)
	newest := "2026-07-01T09:45:00Z"

	f := &recordingFetcher{records: []map[string]any{
		{"id": "a", "createdDateTime": "2026-07-01T09:10:00Z", "userPrincipalName": "a@x.com"},
		{"id": "b", "createdDateTime": newest, "userPrincipalName": "b@x.com"},
	}}
	store := checkpoint.NewStore(dir)
	rec := telemetrytest.New()
	c := newCollector(specByName(t, "entra.signins.interactive"), collectors.WindowDeps{TenantID: "t1", Fetcher: f, Store: store})

	if _, err := c.CollectWindow(context.Background(), from, from.Add(time.Hour), rec.Emitter()); err != nil {
		t.Fatalf("CollectWindow: %v", err)
	}
	if got := len(rec.LogRecords()); got != 2 {
		t.Fatalf("emitted %d records, want 2", got)
	}
	// Checkpoint persisted under the interactive namespace.
	cp, err := store.Load("t1", signInsPath+"#interactive")
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
