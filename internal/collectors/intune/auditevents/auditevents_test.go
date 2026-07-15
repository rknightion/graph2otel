package auditevents

import (
	"context"
	"fmt"
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

func TestMapAuditEventUserInitiatedSuccess(t *testing.T) {
	rec := map[string]any{
		"id":                    "audit-1",
		"activityDateTime":      "2026-07-01T10:00:00Z",
		"activity":              "Create",
		"activityType":          "deviceConfiguration",
		"activityOperationType": "Create",
		"activityResult":        "success",
		"category":              "DeviceConfiguration",
		"componentName":         "DeviceConfiguration",
		"displayName":           "Create deviceConfiguration",
		"correlationId":         "corr-1",
		"actor": map[string]any{
			"auditActorType":    "ItPro",
			"userPrincipalName": "alice@contoso.com",
			"userId":            "user-guid",
			"ipAddress":         "203.0.113.9",
		},
		"resources": []any{
			map[string]any{
				"auditResourceType": "deviceConfiguration",
				"displayName":       "Baseline Config",
				"modifiedProperties": []any{
					map[string]any{"displayName": "displayName", "oldValue": "\"Old Name\"", "newValue": "\"Baseline Config\""},
				},
			},
		},
	}

	id, ev := mapAuditEvent(rec)
	if id != "audit-1" {
		t.Fatalf("dedupe id = %q, want audit-1", id)
	}
	if ev.Name != eventName {
		t.Fatalf("event name = %q, want %q", ev.Name, eventName)
	}
	if ev.Severity != telemetry.SeverityInfo {
		t.Errorf("successful audit severity = %v, want Info", ev.Severity)
	}
	wantBody := "DeviceConfiguration: Create (success)"
	if ev.Body != wantBody {
		t.Errorf("body = %q, want %q", ev.Body, wantBody)
	}

	wantAttrs := map[string]any{
		"id":                        "audit-1",
		"activity":                  "Create",
		"activity_type":             "deviceConfiguration",
		"activity_operation_type":   "Create",
		"activity_result":           "success",
		"category":                  "DeviceConfiguration",
		"component_name":            "DeviceConfiguration",
		"display_name":              "Create deviceConfiguration",
		"correlation_id":            "corr-1",
		"actor_type":                "ItPro",
		"actor_user_principal_name": "alice@contoso.com",
		"actor_user_id":             "user-guid",
		"actor_ip_address":          "203.0.113.9",
	}
	for k, want := range wantAttrs {
		if got := ev.Attrs[k]; got != want {
			t.Errorf("attr %q = %v, want %v", k, got, want)
		}
	}

	resourceTypes, ok := ev.Attrs["resource_types"].([]string)
	if !ok || len(resourceTypes) != 1 || resourceTypes[0] != "deviceConfiguration" {
		t.Errorf("resource_types = %v, want [deviceConfiguration]", ev.Attrs["resource_types"])
	}
	resourceNames, ok := ev.Attrs["resource_display_names"].([]string)
	if !ok || len(resourceNames) != 1 || resourceNames[0] != "Baseline Config" {
		t.Errorf("resource_display_names = %v, want [Baseline Config]", ev.Attrs["resource_display_names"])
	}
	modifiedNames, ok := ev.Attrs["modified_property_names"].([]string)
	if !ok || len(modifiedNames) != 1 || modifiedNames[0] != "displayName" {
		t.Errorf("modified_property_names = %v, want [displayName]", ev.Attrs["modified_property_names"])
	}
}

func TestMapAuditEventFailureIsWarn(t *testing.T) {
	rec := map[string]any{
		"id":               "audit-2",
		"activityDateTime": "2026-07-01T11:00:00Z",
		"activity":         "Update",
		"activityResult":   "failure",
		"category":         "DeviceConfiguration",
		"actor": map[string]any{
			"applicationDisplayName": "My Automation App",
			"applicationId":          "app-guid",
		},
	}

	_, ev := mapAuditEvent(rec)
	if ev.Severity != telemetry.SeverityWarn {
		t.Errorf("failed audit severity = %v, want Warn", ev.Severity)
	}
	if ev.Attrs["actor_application_display_name"] != "My Automation App" {
		t.Errorf("actor_application_display_name = %v, want My Automation App", ev.Attrs["actor_application_display_name"])
	}
	if ev.Attrs["actor_application_id"] != "app-guid" {
		t.Errorf("actor_application_id = %v, want app-guid", ev.Attrs["actor_application_id"])
	}
	if _, present := ev.Attrs["actor_user_principal_name"]; present {
		t.Errorf("app-initiated audit must not carry actor_user_principal_name, attrs=%v", ev.Attrs)
	}
	if _, present := ev.Attrs["resource_types"]; present {
		t.Errorf("record with no resources must not carry resource_types, attrs=%v", ev.Attrs)
	}
}

// TestMapAuditEventNeverEmitsModifiedPropertyValues is the required PII/secret
// redaction guard: a modifiedProperties entry can carry a certificate or
// credential string in oldValue/newValue (or a UPN/IP in other audited
// fields). mapAuditEvent must emit only the changed property's NAME, never
// its value, so a secret that changed hands never reaches an OTLP attribute.
func TestMapAuditEventNeverEmitsModifiedPropertyValues(t *testing.T) {
	const secretOld = "MIIC-fake-old-certificate-blob-DO-NOT-LEAK"
	const secretNew = "MIIC-fake-new-certificate-blob-DO-NOT-LEAK"

	rec := map[string]any{
		"id":               "audit-3",
		"activityDateTime": "2026-07-01T12:00:00Z",
		"activity":         "Update",
		"activityResult":   "success",
		"category":         "Certificate",
		"resources": []any{
			map[string]any{
				"auditResourceType": "deviceConfiguration",
				"displayName":       "VPN Cert Profile",
				"modifiedProperties": []any{
					map[string]any{
						"displayName": "certificate",
						"oldValue":    secretOld,
						"newValue":    secretNew,
					},
				},
			},
		},
	}

	_, ev := mapAuditEvent(rec)

	// Scan every attribute's rendered form (covers string, []string, int,
	// etc.) for the secret values — they must never appear anywhere in the
	// emitted Event.
	for k, v := range ev.Attrs {
		rendered := fmt.Sprintf("%v", v)
		if strings.Contains(rendered, secretOld) || strings.Contains(rendered, secretNew) {
			t.Fatalf("attr %q = %v leaked a modifiedProperties value", k, v)
		}
	}
	if strings.Contains(ev.Body, secretOld) || strings.Contains(ev.Body, secretNew) {
		t.Fatalf("Body %q leaked a modifiedProperties value", ev.Body)
	}

	// The property NAME is expected to survive — only the value is redacted.
	names, ok := ev.Attrs["modified_property_names"].([]string)
	if !ok || len(names) != 1 || names[0] != "certificate" {
		t.Errorf("modified_property_names = %v, want [certificate]", ev.Attrs["modified_property_names"])
	}
}

func TestNotExperimentalNoLicenseGate(t *testing.T) {
	f := &recordingFetcher{records: []map[string]any{{"id": "a", "activityDateTime": "2026-07-01T10:00:00Z"}}}
	c := newCollector(depsWith(t, f))

	if _, ok := any(c).(collectors.Experimental); ok {
		t.Error("audit-events collector must not implement Experimental (v1.0, not beta)")
	}
	perms := c.RequiredPermissions()
	if len(perms) != 1 || perms[0] != "DeviceManagementApps.Read.All" {
		t.Errorf("RequiredPermissions = %v, want [DeviceManagementApps.Read.All]", perms)
	}
}

func TestFirstPageURLIsV1AndUsesActivityDateTimeNoOrderBy(t *testing.T) {
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
	if !strings.HasPrefix(u, "https://graph.microsoft.com/v1.0/deviceManagement/auditEvents?") {
		t.Errorf("first-page URL = %q, want the v1.0 auditEvents endpoint", u)
	}
	if !strings.Contains(u, "activityDateTime") {
		t.Errorf("first-page URL = %q, want an activityDateTime filter", u)
	}
	if strings.Contains(u, "%24orderby") || strings.Contains(u, "$orderby") {
		t.Errorf("first-page URL = %q, must NOT $orderby (server order is unreliable on this endpoint)", u)
	}
}

// TestCollectorSortsOutOfOrderArrivalsClientSide proves OrderByReliable=false
// is honored: records are returned out of activityDateTime order by the
// fetcher (as if the server's own ordering were unreliable), and the
// watermark still advances to the truly-newest record's time minus the
// safety lag, not to whichever record happened to arrive last.
func TestCollectorSortsOutOfOrderArrivalsClientSide(t *testing.T) {
	dir := t.TempDir()
	from := time.Date(2026, 7, 1, 9, 0, 0, 0, time.UTC)
	newest := "2026-07-01T09:45:00Z"

	// Deliberately out of chronological order.
	f := &recordingFetcher{records: []map[string]any{
		{"id": "b", "activityDateTime": newest, "activityResult": "success", "category": "DeviceConfiguration"},
		{"id": "a", "activityDateTime": "2026-07-01T09:10:00Z", "activityResult": "success", "category": "DeviceConfiguration"},
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

// TestCollectorDedupesByID drives two overlapping polls sharing one repeated
// id and asserts the repeated record emits only once, guarding the
// overlap-window dedupe model the issue's acceptance criteria calls for.
func TestCollectorDedupesByID(t *testing.T) {
	dir := t.TempDir()
	from := time.Date(2026, 7, 1, 9, 0, 0, 0, time.UTC)

	store := checkpoint.NewStore(dir)
	rec := telemetrytest.New()
	f := &recordingFetcher{records: []map[string]any{
		{"id": "dup-1", "activityDateTime": "2026-07-01T09:10:00Z", "activityResult": "success", "category": "DeviceConfiguration"},
	}}
	c := newCollector(collectors.WindowDeps{TenantID: "t1", Fetcher: f, Store: store})

	if _, err := c.CollectWindow(context.Background(), from, from.Add(time.Hour), rec.Emitter()); err != nil {
		t.Fatalf("CollectWindow (first poll): %v", err)
	}
	// Second, overlapping poll returns the SAME record again.
	if _, err := c.CollectWindow(context.Background(), from, from.Add(2*time.Hour), rec.Emitter()); err != nil {
		t.Fatalf("CollectWindow (second poll): %v", err)
	}

	if got := len(rec.LogRecords()); got != 1 {
		t.Fatalf("emitted %d records across two overlapping polls, want 1 (deduped by id)", got)
	}
}

// logpipelineDefaultSafetyLag mirrors logpipeline.DefaultSafetyLag (15m), the
// margin the engine trails the watermark by when EndpointConfig.SafetyLag is
// left at its default.
const logpipelineDefaultSafetyLag = 15 * time.Minute
