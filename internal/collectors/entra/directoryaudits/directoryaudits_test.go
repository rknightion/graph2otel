package directoryaudits

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

func TestMapDirectoryAuditUserInitiatedSuccess(t *testing.T) {
	rec := map[string]any{
		"id":                  "audit-1",
		"activityDateTime":    "2026-07-01T10:00:00Z",
		"category":            "RoleManagement",
		"activityDisplayName": "Add member to role",
		"result":              "success",
		"resultReason":        "",
		"loggedByService":     "Core Directory",
		"correlationId":       "corr-1",
		"initiatedBy": map[string]any{
			"user": map[string]any{
				"userPrincipalName": "alice@contoso.com",
				"id":                "user-guid",
			},
		},
		"targetResources": []any{
			map[string]any{"displayName": "Bob User"},
			map[string]any{"displayName": "Global Administrator"},
		},
	}

	id, ev := mapDirectoryAudit(rec)
	if id != "audit-1" {
		t.Fatalf("dedupe id = %q, want audit-1", id)
	}
	if ev.Name != eventName {
		t.Fatalf("event name = %q, want %q", ev.Name, eventName)
	}
	if ev.Severity != telemetry.SeverityInfo {
		t.Errorf("successful audit severity = %v, want Info", ev.Severity)
	}
	wantBody := "RoleManagement: Add member to role (success)"
	if ev.Body != wantBody {
		t.Errorf("body = %q, want %q", ev.Body, wantBody)
	}

	wantAttrs := map[string]any{
		"id":                            "audit-1",
		"category":                      "RoleManagement",
		"activity_display_name":         "Add member to role",
		"result":                        "success",
		"logged_by_service":             "Core Directory",
		"correlation_id":                "corr-1",
		"initiator_user_principal_name": "alice@contoso.com",
		"initiator_user_id":             "user-guid",
		"target_resource_count":         2,
	}
	for k, want := range wantAttrs {
		if got := ev.Attrs[k]; got != want {
			t.Errorf("attr %q = %v, want %v", k, got, want)
		}
	}
	if _, present := ev.Attrs["result_reason"]; present {
		t.Errorf("empty result_reason must be omitted, attrs=%v", ev.Attrs)
	}
	if _, present := ev.Attrs["initiator_app_display_name"]; present {
		t.Errorf("user-initiated audit must not carry initiator_app_display_name, attrs=%v", ev.Attrs)
	}
	names, ok := ev.Attrs["target_display_names"].([]string)
	if !ok || len(names) != 2 || names[0] != "Bob User" || names[1] != "Global Administrator" {
		t.Errorf("target_display_names = %v, want [Bob User, Global Administrator]", ev.Attrs["target_display_names"])
	}
}

func TestMapDirectoryAuditAppInitiatedFailureIsWarn(t *testing.T) {
	rec := map[string]any{
		"id":                  "audit-2",
		"activityDateTime":    "2026-07-01T11:00:00Z",
		"category":            "ApplicationManagement",
		"activityDisplayName": "Update application",
		"result":              "failure",
		"resultReason":        "Insufficient privileges",
		"initiatedBy": map[string]any{
			"app": map[string]any{
				"displayName": "My Automation App",
				"appId":       "app-guid",
			},
		},
	}

	_, ev := mapDirectoryAudit(rec)
	if ev.Severity != telemetry.SeverityWarn {
		t.Errorf("failed audit severity = %v, want Warn", ev.Severity)
	}
	if ev.Attrs["initiator_app_display_name"] != "My Automation App" {
		t.Errorf("initiator_app_display_name = %v, want My Automation App", ev.Attrs["initiator_app_display_name"])
	}
	if ev.Attrs["initiator_app_id"] != "app-guid" {
		t.Errorf("initiator_app_id = %v, want app-guid", ev.Attrs["initiator_app_id"])
	}
	if ev.Attrs["result_reason"] != "Insufficient privileges" {
		t.Errorf("result_reason = %v, want Insufficient privileges", ev.Attrs["result_reason"])
	}
	if _, present := ev.Attrs["initiator_user_principal_name"]; present {
		t.Errorf("app-initiated audit must not carry initiator_user_principal_name, attrs=%v", ev.Attrs)
	}
	if _, present := ev.Attrs["target_resource_count"]; present {
		t.Errorf("record with no targetResources must not carry target_resource_count, attrs=%v", ev.Attrs)
	}
}

func TestNotExperimentalNoLicenseGate(t *testing.T) {
	f := &recordingFetcher{records: []map[string]any{{"id": "a", "activityDateTime": "2026-07-01T10:00:00Z"}}}
	c := newCollector(depsWith(t, f))

	if _, ok := any(c).(collectors.Experimental); ok {
		t.Error("directory-audits collector must not implement Experimental (v1.0, not beta)")
	}
	perms := c.RequiredPermissions()
	if len(perms) != 1 || perms[0] != "AuditLog.Read.All" {
		t.Errorf("RequiredPermissions = %v, want [AuditLog.Read.All]", perms)
	}
}

func TestFirstPageURLIsV1AndUsesActivityDateTime(t *testing.T) {
	f := &recordingFetcher{records: []map[string]any{{"id": "a", "activityDateTime": "2026-07-01T10:00:00Z"}}}
	c := newCollector(depsWith(t, f))

	from := time.Date(2026, 7, 1, 9, 0, 0, 0, time.UTC)
	if _, err := c.CollectWindow(context.Background(), from, from.Add(time.Hour), telemetrytest.New().Emitter()); err != nil {
		t.Fatalf("CollectWindow: %v", err)
	}
	if len(f.seenURLs) == 0 {
		t.Fatal("no page fetched")
	}
	u := f.seenURLs[0]
	if !strings.HasPrefix(u, "https://graph.microsoft.com/v1.0/auditLogs/directoryAudits?") {
		t.Errorf("first-page URL = %q, want the v1.0 directoryAudits endpoint", u)
	}
	if !strings.Contains(u, "activityDateTime") {
		t.Errorf("first-page URL = %q, want an activityDateTime filter", u)
	}
	if !strings.Contains(u, "%24orderby=activityDateTime+asc") {
		t.Errorf("first-page URL = %q, want $orderby activityDateTime asc", u)
	}
}

func TestCollectorDrainsEmitsAndPersistsWatermark(t *testing.T) {
	dir := t.TempDir()
	from := time.Date(2026, 7, 1, 9, 0, 0, 0, time.UTC)
	newest := "2026-07-01T09:45:00Z"

	f := &recordingFetcher{records: []map[string]any{
		{"id": "a", "activityDateTime": "2026-07-01T09:10:00Z", "category": "UserManagement", "activityDisplayName": "Reset password", "result": "success"},
		{"id": "b", "activityDateTime": newest, "category": "UserManagement", "activityDisplayName": "Reset password", "result": "success"},
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
