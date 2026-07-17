package directoryaudits

import (
	"context"
	"encoding/json"
	"reflect"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/rknightion/graph2otel/internal/checkpoint"
	"github.com/rknightion/graph2otel/internal/collectors"
	"github.com/rknightion/graph2otel/internal/telemetry"
	"github.com/rknightion/graph2otel/internal/telemetrytest"
)

// liveDirectoryAudit is a VERBATIM GET /auditLogs/directoryAudits record from
// the m7kni tenant, read as graph2otel-poller on 2026-07-17
// `[live-measured 2026-07-17, #165]`. It is the richest of the five records the
// window returned: an Intune compliance flip on a real device, so it exercises
// the app-initiator branch, a populated additionalDetails, and a
// targetResources entry carrying modifiedProperties — the nested paths a
// degenerate record leaves untouched.
//
// It replaces a hand-written fixture whose values were Microsoft's own
// documentation placeholders (`alice@contoso.com`, `Bob User`, `audit-1`),
// because a hand-written fixture cannot fail: it encodes the author's belief of
// the wire and then confirms it, which is how #142's `"platform": "windows"`
// and #153's invented `riskType` stayed green for the life of the project.
//
// Trimmed of nothing. Note what this record proves about the app initiator:
// `initiatedBy.app.appId` is null while `servicePrincipalId` carries the only
// identifier present — see TestLiveDirectoryAuditAppInitiatorHasNoAppID.
const liveDirectoryAudit = `{
  "activityDateTime": "2026-07-17T13:48:10.9301252Z",
  "activityDisplayName": "Update device",
  "additionalDetails": [
    {
      "key": "DeviceId",
      "value": "8c42f011-6105-4269-a64b-6eabc71b2006"
    },
    {
      "key": "DeviceOSType",
      "value": "MacMDM"
    },
    {
      "key": "DeviceTrustType",
      "value": "AzureAd"
    }
  ],
  "category": "Device",
  "correlationId": "3b267148-9777-40a3-8f35-4adf76967557",
  "id": "Directory_3b267148-9777-40a3-8f35-4adf76967557_6LPVG_73478882",
  "initiatedBy": {
    "app": {
      "appId": null,
      "displayName": "Intune Compliance Client Prod",
      "servicePrincipalId": "8ab73e2f-f11f-4bf3-a693-7a9d37bd5b49",
      "servicePrincipalName": null
    },
    "user": null
  },
  "loggedByService": "Core Directory",
  "operationType": "Update",
  "result": "success",
  "resultReason": "",
  "targetResources": [
    {
      "displayName": "Rob’s MacBook Pro",
      "groupType": null,
      "id": "101b82ba-75ef-45d3-8b66-63672be4fbb4",
      "modifiedProperties": [
        {
          "displayName": "IsCompliant",
          "newValue": "[true]",
          "oldValue": "[false]"
        },
        {
          "displayName": "Included Updated Properties",
          "newValue": "\"IsCompliant\"",
          "oldValue": null
        },
        {
          "displayName": "TargetId.DeviceId",
          "newValue": "\"8c42f011-6105-4269-a64b-6eabc71b2006\"",
          "oldValue": null
        },
        {
          "displayName": "TargetId.DeviceOSType",
          "newValue": "\"MacMDM\"",
          "oldValue": null
        },
        {
          "displayName": "TargetId.DeviceTrustType",
          "newValue": "\"AzureAd\"",
          "oldValue": null
        }
      ],
      "type": "Device",
      "userPrincipalName": null
    }
  ]
}`

// decodeLive unmarshals a pinned live record into the untyped shape the
// logpipeline engine hands to the mapper.
func decodeLive(t *testing.T, raw string) map[string]any {
	t.Helper()
	var rec map[string]any
	if err := json.Unmarshal([]byte(raw), &rec); err != nil {
		t.Fatalf("decode live record: %v", err)
	}
	return rec
}

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

// TestLiveDirectoryAuditAppInitiatorHasNoAppID pins a WIRE fact, independent of
// any mapper behavior: on a real app-initiated directory audit,
// `initiatedBy.app.appId` is NULL, and `servicePrincipalId` carries the only
// identifier the record has for the initiator.
//
// All five records the live window returned agree, across two distinct apps
// (Intune Compliance Client Prod, Azure AD Cloud Sync) — so this is not a
// one-record accident. The package's docs-derived fixture asserts the opposite
// (`"appId": "app-guid"`), which is the shape Microsoft's documentation shows.
//
// This test asserts the wire only. What the mapper should do about it is #165's
// question, not this test's.
func TestLiveDirectoryAuditAppInitiatorHasNoAppID(t *testing.T) {
	app := nested(nested(decodeLive(t, liveDirectoryAudit), "initiatedBy"), "app")
	if app == nil {
		t.Fatal("live record has no initiatedBy.app")
	}
	if v, present := app["appId"]; present && v != nil {
		t.Fatalf("initiatedBy.app.appId = %#v; this record was captured with it null, and "+
			"initiator_app_id's mapping assumes otherwise", v)
	}
	if got := str(app, "servicePrincipalId"); got != "8ab73e2f-f11f-4bf3-a693-7a9d37bd5b49" {
		t.Errorf("initiatedBy.app.servicePrincipalId = %q, want the initiator's object id — "+
			"the only identifier on this record", got)
	}
}

// TestMapDirectoryAuditMapsServicePrincipalID is the #168 fix: the mapper must
// surface initiatedBy.app.servicePrincipalId as a distinct attribute,
// initiator_service_principal_id, since appId is structurally null on every
// app-initiated record this project has captured (see the test above) and
// servicePrincipalId is the only identifier left. This is a NEW attribute,
// not a repurposing of initiator_app_id — that one keeps mapping appId, for
// the rare case a future record populates it.
func TestMapDirectoryAuditMapsServicePrincipalID(t *testing.T) {
	_, ev := mapDirectoryAudit(decodeLive(t, liveDirectoryAudit))

	want := "8ab73e2f-f11f-4bf3-a693-7a9d37bd5b49"
	if got := ev.Attrs["initiator_service_principal_id"]; got != want {
		t.Errorf("initiator_service_principal_id = %v, want %v", got, want)
	}
	if _, present := ev.Attrs["initiator_app_id"]; present {
		t.Errorf("initiator_app_id must stay absent when appId is null, attrs=%v", ev.Attrs)
	}
}

// TestMapDirectoryAuditAgainstLiveRecord pins the EXACT attribute set the mapper
// produces from a real record. Exact-set equality is the point: it fails on a
// missing attribute (a dropped field) AND on an unexpected one (a fabricated
// field), which is the pair of mistakes #142/#153/#165 are made of.
//
// The set is deliberately smaller than the mapper's full vocabulary. Absent
// here, and why:
//   - result_reason — the record's resultReason is "" (setStr omits it)
//   - initiator_user_* — the record is app-initiated; initiatedBy.user is null
//   - initiator_app_id — appId is null on the wire (see the test above);
//     initiator_service_principal_id is what this record carries instead (#168)
//
// Do not "fix" this list by driving the docs-derived fixtures into the emitter
// to pad it out. #165: driving a docs-derived fixture end-to-end just goldens
// fiction more thoroughly.
func TestMapDirectoryAuditAgainstLiveRecord(t *testing.T) {
	id, ev := mapDirectoryAudit(decodeLive(t, liveDirectoryAudit))

	if id != "Directory_3b267148-9777-40a3-8f35-4adf76967557_6LPVG_73478882" {
		t.Errorf("dedupe id = %q, want the record's immutable audit id", id)
	}
	if ev.Severity != telemetry.SeverityInfo {
		t.Errorf("successful audit severity = %v, want Info", ev.Severity)
	}
	if want := "Device: Update device (success)"; ev.Body != want {
		t.Errorf("body = %q, want %q", ev.Body, want)
	}

	wantKeys := []string{
		"activity_display_name",
		"category",
		"correlation_id",
		"id",
		"initiator_app_display_name",
		"initiator_service_principal_id",
		"logged_by_service",
		"result",
		"target_display_names",
		"target_resource_count",
	}
	gotKeys := make([]string, 0, len(ev.Attrs))
	for k := range ev.Attrs {
		gotKeys = append(gotKeys, k)
	}
	sort.Strings(gotKeys)
	if !reflect.DeepEqual(gotKeys, wantKeys) {
		t.Errorf("attribute key set mismatch\n got: %v\nwant: %v", gotKeys, wantKeys)
	}

	wantScalars := map[string]any{
		"id":                             "Directory_3b267148-9777-40a3-8f35-4adf76967557_6LPVG_73478882",
		"category":                       "Device",
		"activity_display_name":          "Update device",
		"result":                         "success",
		"logged_by_service":              "Core Directory",
		"correlation_id":                 "3b267148-9777-40a3-8f35-4adf76967557",
		"initiator_app_display_name":     "Intune Compliance Client Prod",
		"initiator_service_principal_id": "8ab73e2f-f11f-4bf3-a693-7a9d37bd5b49",
		"target_resource_count":          1,
	}
	for k, want := range wantScalars {
		if got := ev.Attrs[k]; got != want {
			t.Errorf("attr %q = %v, want %v", k, got, want)
		}
	}

	names, ok := ev.Attrs["target_display_names"].([]string)
	if !ok || len(names) != 1 || names[0] != "Rob’s MacBook Pro" {
		t.Errorf("target_display_names = %#v, want [Rob’s MacBook Pro]", ev.Attrs["target_display_names"])
	}
}

// TestMapDirectoryAuditUserInitiatedSuccess covers the user-initiator branch,
// which the live sample does not exercise (its record is app-initiated).
//
// The fixture is DOCS-DERIVED — `alice@contoso.com` is Microsoft's own example
// domain, `audit-1` and `user-guid` are invented — and is kept only for that
// branch coverage. It is NOT this package's authority on the wire:
// liveDirectoryAudit is (#165). Do not grow it, and do not read an assertion
// here as evidence Graph sends this shape.
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

// TestMapDirectoryAuditAppInitiatedFailureIsWarn covers two branches the live
// sample cannot: result == "failure" (every captured record succeeded) and a
// non-empty resultReason.
//
// The fixture is DOCS-DERIVED — `app-guid`, `audit-2` and `My Automation App`
// are invented, and its `"appId": "app-guid"` is contradicted by the wire (see
// TestLiveDirectoryAuditAppInitiatorHasNoAppID). Kept for the severity and
// result_reason branches only; liveDirectoryAudit is this package's authority
// on record shape (#165).
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

// TestCollectorEmitsLiveRecordEndToEnd drives the live record through the engine
// into an emitter, rather than calling the mapper directly like the tests above.
//
// It is what makes testdata/signals.json honest: the signal gate goldens the
// union of what a package's tests EMIT, so with only minimal synthetic fixtures
// reaching the emitter, the golden recorded a 5-attribute surface for a
// collector that ships 10 on one real record — understating the exact thing the
// golden exists to make reviewable (#164). #140 reads that golden to generate
// docs/collectors.md's signal columns, so a thin one publishes as a measurement.
func TestCollectorEmitsLiveRecordEndToEnd(t *testing.T) {
	f := &recordingFetcher{records: []map[string]any{decodeLive(t, liveDirectoryAudit)}}
	rec := telemetrytest.New()
	c := newCollector(depsWith(t, f))

	from := time.Date(2026, 7, 17, 13, 0, 0, 0, time.UTC)
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

	// Checked at the emitter rather than the mapper: these are the attributes
	// that only a real record produces, and they must survive the whole path.
	wantAttrs := map[string]string{
		"id":                             "Directory_3b267148-9777-40a3-8f35-4adf76967557_6LPVG_73478882",
		"category":                       "Device",
		"activity_display_name":          "Update device",
		"result":                         "success",
		"logged_by_service":              "Core Directory",
		"correlation_id":                 "3b267148-9777-40a3-8f35-4adf76967557",
		"initiator_app_display_name":     "Intune Compliance Client Prod",
		"initiator_service_principal_id": "8ab73e2f-f11f-4bf3-a693-7a9d37bd5b49",
	}
	for k, want := range wantAttrs {
		if v := got.Attrs[k]; v != want {
			t.Errorf("emitted attr %q = %q, want %q", k, v, want)
		}
	}

	// target_resource_count is an int and target_display_names a []string;
	// telemetrytest.Recorder flattens every log attribute through
	// log.Value.AsString(), which yields "" for any non-string Kind. So these are
	// checked for PRESENCE here and their values pinned at the mapper instead
	// (TestMapDirectoryAuditAgainstLiveRecord). Not an oversight — a limitation
	// of the test harness, not of the emission.
	for _, k := range []string{"target_resource_count", "target_display_names"} {
		if _, present := got.Attrs[k]; !present {
			t.Errorf("emitted attrs missing %q", k)
		}
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
