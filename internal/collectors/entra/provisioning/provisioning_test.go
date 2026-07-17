package provisioning

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

// liveProvisioning is a VERBATIM GET /auditLogs/provisioning record from the
// m7kni tenant, read as graph2otel-poller on 2026-07-17
// `[live-measured 2026-07-17, #165]`. It is the richest of the 5 rows the
// endpoint returned: a SCIM group sync through the "Grafana PS" enterprise app,
// with all four provisioningSteps and a populated targetIdentity.id.
//
// It CORRECTS #165's own body, which assumed this endpoint "needs SCIM
// app-provisioning configured; likely empty here" and proposed marking the
// package docs-derived on that basis. The tenant returned 66 rows. The
// assumption was wrong and the collector has always had real data to be tested
// against — so the honest outcome is a pinned live record, not a tagged
// docs-derived one.
//
// Every value is as the wire sent it, including the real group names, job id,
// service principal GUIDs and tenantId. Nothing is scrubbed: per CLAUDE.md's
// cardinality section this project exports per-entity detail to a trusted sink
// by design, and a "tidied" fixture is a docs-derived fixture with extra steps.
//
// Two wire facts this record pins, both contradicting the Graph resource doc
// the mapper was written from (see TestLiveProvisioningServicePrincipalIsSingleObject):
//   - servicePrincipal is a single OBJECT, not a collection.
//   - its name field is "displayName", not "name".
//
// Note `provisioningStatusInfo.errorInformation`: it is JSON null on a
// non-failure record — present as a key, but not an object. A mapper that type
// asserts to map[string]any tolerates this; one that checks only for the key's
// presence would not.
const liveProvisioning = `{
  "activityDateTime": "2026-07-17T12:31:10Z",
  "changeId": "e228f043-cf65-4929-bc3f-87749ad75644",
  "cycleId": "b85c7c8e-c3c5-49e0-a57e-a8a6ba9a7595",
  "durationInMilliseconds": 630,
  "id": "a3f2b676-f27c-832e-6757-be2d5ed806ba",
  "initiatedBy": {
    "displayName": "Azure AD Provisioning Service",
    "id": "",
    "initiatorType": "system"
  },
  "jobId": "scim.4b8c18bd2f9f4227af559f1061cf9c32.4ba261ce-287a-459c-93eb-7047bab3cfb9",
  "modifiedProperties": [],
  "provisioningAction": "other",
  "provisioningStatusInfo": {
    "errorInformation": null,
    "status": "skipped"
  },
  "provisioningSteps": [
    {
      "description": "Received Group 'ae0c9dc4-faba-477f-952c-423c67237700' change of type (Update) from Microsoft Entra ID",
      "details": {
        "objectId": "ae0c9dc4-faba-477f-952c-423c67237700"
      },
      "name": "EntryImportUpdate",
      "provisioningStepType": "import",
      "status": "success"
    },
    {
      "description": "Retrieved  'macos-servers-dynamic' from customappsso",
      "details": {
        "displayName": "macos-servers-dynamic",
        "externalId": "ae0c9dc4-faba-477f-952c-423c67237700",
        "id": "ffsdj2g8zwtfkd"
      },
      "name": "EntryImport",
      "provisioningStepType": "matching",
      "status": "success"
    },
    {
      "description": "Determine if Group in scope by evaluating against each scoping filter",
      "details": {
        "Active in the source system": "True",
        "Assigned to the application": "True",
        "Group has the required role": "True",
        "ScopeEvaluationResult": "{}",
        "Scoping filter evaluation passed": "True"
      },
      "name": "EntrySynchronizationScoping",
      "provisioningStepType": "scoping",
      "status": "success"
    },
    {
      "description": "The state of the entry in both the source and target systems already match. No change to the Group 'ae0c9dc4-faba-477f-952c-423c67237700' currently needs to be made.",
      "details": {
        "ReportableIdentifier": "ae0c9dc4-faba-477f-952c-423c67237700",
        "SkipReason": "RedundantExport"
      },
      "name": "EntrySynchronizationSkip",
      "provisioningStepType": "export",
      "status": "skipped"
    }
  ],
  "servicePrincipal": {
    "displayName": "Grafana PS",
    "id": "e7e9d06f-8673-4759-bfed-67d499095d2f"
  },
  "sourceIdentity": {
    "details": {
      "DisplayName": "macos-servers-dynamic",
      "id": "ae0c9dc4-faba-477f-952c-423c67237700",
      "odatatype": "Group"
    },
    "displayName": "macos-servers-dynamic",
    "id": "ae0c9dc4-faba-477f-952c-423c67237700",
    "identityType": "Group"
  },
  "sourceSystem": {
    "details": {},
    "displayName": "Microsoft Entra ID",
    "id": "e156568c-b65b-40a1-82ca-8afd5500c140"
  },
  "targetIdentity": {
    "details": {},
    "displayName": "",
    "id": "ffsdj2g8zwtfkd",
    "identityType": "urn:ietf:params:scim:schemas:core:2.0:Group"
  },
  "targetSystem": {
    "details": {
      "ApplicationId": "8adf8e6e-67b2-4cf2-a259-e3dc5476c621",
      "ServicePrincipalDisplayName": "Grafana PS",
      "ServicePrincipalId": "e7e9d06f-8673-4759-bfed-67d499095d2f"
    },
    "displayName": "customappsso",
    "id": "ed85458d-2a0d-4119-ba5f-bd264973c1af"
  },
  "tenantId": "4b8c18bd-2f9f-4227-af55-9f1061cf9c32"
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

// TestLiveProvisioningServicePrincipalIsSingleObject pins the WIRE FACT behind
// this package's headline mapping defect, independent of any mapper behavior.
//
// provisioning.go's `firstNested(rec, "servicePrincipal")` call site is
// commented "servicePrincipal is a COLLECTION on provisioningObjectSummary (per
// the Graph resource doc)". The wire disagrees, and the doc-derived belief costs
// two attributes:
//
//  1. SHAPE: servicePrincipal is a single JSON object, not an array. firstNested
//     type asserts to []any, which fails, returns nil, and the mapper skips the
//     whole block — so service_principal_id and service_principal_name are NEVER
//     emitted from a real record, on any of the 5 rows captured.
//  2. FIELD NAME: the object's name field is "displayName", not "name". So even
//     once the shape is fixed, str(sp, "name") returns "" and setStr drops
//     service_principal_name. Two independent defects on the same two attributes.
//
// The old hand-written fixture encoded BOTH mistakes as `"servicePrincipal":
// []any{map[string]any{"id": "sp-guid", "name": "ServiceNow"}}` and asserted
// they mapped — a fixture confirming its author's belief rather than the wire.
// Exactly #142's `"platform": "windows"` and #153's invented `riskType`.
//
// This test is deliberately about the RECORD, not the mapper: it stays true and
// keeps failing-if-wrong regardless of how provisioning.go is later fixed.
func TestLiveProvisioningServicePrincipalIsSingleObject(t *testing.T) {
	rec := decodeLive(t, liveProvisioning)

	raw, present := rec["servicePrincipal"]
	if !present {
		t.Fatal("live record has no servicePrincipal key at all")
	}
	if arr, isArray := raw.([]any); isArray {
		t.Fatalf("servicePrincipal is an array (%d elems); provisioning.go:115's "+
			"\"COLLECTION per the Graph resource doc\" comment would be correct and this test is stale", len(arr))
	}
	sp, isObject := raw.(map[string]any)
	if !isObject {
		t.Fatalf("servicePrincipal = %#v, want a single JSON object", raw)
	}

	if got := str(sp, "id"); got != "e7e9d06f-8673-4759-bfed-67d499095d2f" {
		t.Errorf("servicePrincipal.id = %q, want the Grafana PS service principal GUID", got)
	}
	if got := str(sp, "displayName"); got != "Grafana PS" {
		t.Errorf("servicePrincipal.displayName = %q, want \"Grafana PS\"", got)
	}
	if v, present := sp["name"]; present {
		t.Errorf("servicePrincipal.name = %v; the mapper reads \"name\", and this test "+
			"asserts the wire carries only \"displayName\" — if this fires, defect (2) is stale", v)
	}

	// The consequence, pinned so it cannot be lost: firstNested — the accessor
	// the mapper actually uses — returns nil for this record.
	if got := firstNested(rec, "servicePrincipal"); got != nil {
		t.Errorf("firstNested(servicePrincipal) = %v, want nil "+
			"(it type asserts to []any, which a JSON object fails)", got)
	}
}

// TestMapProvisioningAgainstLiveRecord pins the EXACT attribute set the mapper
// produces from a real provisioning record. Exact-set equality is the point: it
// fails on a missing attribute (a dropped field) and on an unexpected one (a
// fabricated field) — the pair of mistakes #165 exists to catch.
//
// READ THIS BEFORE "FIXING" THE ASSERTION: service_principal_id and
// service_principal_name are absent from wantKeys, and that is a DEFECT being
// recorded, not a behavior being blessed. See
// TestLiveProvisioningServicePrincipalIsSingleObject for the wire facts and the
// two stacked causes. This set is what the collector ships TODAY; when the
// mapper is fixed, both attributes join this list and the golden grows.
//
// target_identity_display_name is likewise absent, but for a legitimate reason:
// the wire carries `"displayName": ""` on targetIdentity for a SCIM group, and
// setStr correctly omits empty values rather than emitting an empty attribute.
func TestMapProvisioningAgainstLiveRecord(t *testing.T) {
	id, ev := mapProvisioning(decodeLive(t, liveProvisioning))

	if id != "a3f2b676-f27c-832e-6757-be2d5ed806ba" {
		t.Errorf("dedupe id = %q, want the record's immutable activity id", id)
	}
	if ev.Name != eventName {
		t.Errorf("event name = %q, want %q", ev.Name, eventName)
	}
	// status is "skipped", not "failure", so severity stays Info.
	if ev.Severity != telemetry.SeverityInfo {
		t.Errorf("skipped provisioning severity = %v, want Info", ev.Severity)
	}
	if want := "provisioning other: skipped"; ev.Body != want {
		t.Errorf("body = %q, want %q", ev.Body, want)
	}

	wantKeys := []string{
		"change_id",
		"cycle_id",
		"id",
		"job_id",
		"provisioning_action",
		"source_identity_display_name",
		"source_identity_id",
		"status",
		"target_identity_id",
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
		"id":                           "a3f2b676-f27c-832e-6757-be2d5ed806ba",
		"job_id":                       "scim.4b8c18bd2f9f4227af559f1061cf9c32.4ba261ce-287a-459c-93eb-7047bab3cfb9",
		"cycle_id":                     "b85c7c8e-c3c5-49e0-a57e-a8a6ba9a7595",
		"change_id":                    "e228f043-cf65-4929-bc3f-87749ad75644",
		"provisioning_action":          "other",
		"status":                       "skipped",
		"source_identity_id":           "ae0c9dc4-faba-477f-952c-423c67237700",
		"source_identity_display_name": "macos-servers-dynamic",
		"target_identity_id":           "ffsdj2g8zwtfkd",
	}
	for k, want := range wantScalars {
		if got := ev.Attrs[k]; got != want {
			t.Errorf("attr %q = %v, want %v", k, got, want)
		}
	}
}

// TestMapProvisioningToleratesNullErrorInformation pins the wire shape a
// non-failure record carries: provisioningStatusInfo.errorInformation is present
// as a key but holds JSON null, on all 5 captured rows.
//
// nested() type asserts to map[string]any, which a nil interface fails, so the
// block is skipped and no empty status_info/status_error_code is emitted. A
// mapper that gated on key presence instead would emit two empty attributes on
// every successful record.
func TestMapProvisioningToleratesNullErrorInformation(t *testing.T) {
	rec := decodeLive(t, liveProvisioning)

	statusInfo := nested(rec, "provisioningStatusInfo")
	if statusInfo == nil {
		t.Fatal("live record has no provisioningStatusInfo object")
	}
	raw, present := statusInfo["errorInformation"]
	if !present {
		t.Fatal("live record's provisioningStatusInfo has no errorInformation key; this test's premise is stale")
	}
	if raw != nil {
		t.Fatalf("errorInformation = %#v, want JSON null on a non-failure record", raw)
	}

	_, ev := mapProvisioning(rec)
	for _, k := range []string{"status_info", "status_error_code"} {
		if v, present := ev.Attrs[k]; present {
			t.Errorf("attr %q = %#v, want the attribute omitted entirely when errorInformation is null", k, v)
		}
	}
}

// TestCollectorEmitsLiveRecordEndToEnd drives the live record through the
// logpipeline engine into an emitter, rather than calling the mapper directly
// like the tests above.
//
// This is what makes testdata/signals.json honest: the signal gate goldens the
// union of what a package's tests EMIT, so while only the minimal synthetic
// fixtures reached the emitter, the golden recorded a 3-attribute surface
// (id, ingest_transport, provisioning_action) for a collector that really ships
// 10 — understating the exact thing the golden exists to make reviewable. Same
// defect #164 fixed for entra/graphactivity and entra/riskdetections.
//
// Only the LIVE record is driven end-to-end, deliberately. The docs-derived
// fixtures below stay mapper-only so they cannot contribute invented attribute
// keys to the golden — #165's core concern, since #140 wants to generate
// docs/collectors.md's signal columns from these goldens.
func TestCollectorEmitsLiveRecordEndToEnd(t *testing.T) {
	f := &recordingFetcher{records: []map[string]any{decodeLive(t, liveProvisioning)}}
	rec := telemetrytest.New()
	c := newCollector(depsWith(t, f))

	from := time.Date(2026, 7, 17, 12, 0, 0, 0, time.UTC)
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

	// Checked at the emitter rather than the mapper: these survive the whole
	// path, including the engine's dedupe and the transport stamp.
	wantAttrs := map[string]string{
		"id":                           "a3f2b676-f27c-832e-6757-be2d5ed806ba",
		"job_id":                       "scim.4b8c18bd2f9f4227af559f1061cf9c32.4ba261ce-287a-459c-93eb-7047bab3cfb9",
		"cycle_id":                     "b85c7c8e-c3c5-49e0-a57e-a8a6ba9a7595",
		"change_id":                    "e228f043-cf65-4929-bc3f-87749ad75644",
		"provisioning_action":          "other",
		"status":                       "skipped",
		"source_identity_id":           "ae0c9dc4-faba-477f-952c-423c67237700",
		"source_identity_display_name": "macos-servers-dynamic",
		"target_identity_id":           "ffsdj2g8zwtfkd",
	}
	for k, want := range wantAttrs {
		if v := got.Attrs[k]; v != want {
			t.Errorf("emitted attr %q = %q, want %q", k, v, want)
		}
	}

	// The defect, asserted at the emitter too: a real record ships no service
	// principal attribution at all. Delete these two checks as part of fixing
	// the mapper — not before.
	for _, k := range []string{"service_principal_id", "service_principal_name"} {
		if v, present := got.Attrs[k]; present {
			t.Errorf("emitted attr %q = %q; if this fires the mapper has been fixed — "+
				"update this test, TestMapProvisioningAgainstLiveRecord's wantKeys, and the golden", k, v)
		}
	}
}

// TestMapProvisioningSuccess covers the mapper's plumbing on a DOCS-DERIVED
// synthetic record.
//
// PROVENANCE: docs-derived, NOT measured. Every value here is invented
// ("prov-1", "src-guid", "Alice Source") and the servicePrincipal shape it
// asserts — an array, with a "name" field — is one the endpoint has never been
// observed to send. See TestLiveProvisioningServicePrincipalIsSingleObject.
//
// It is kept, rather than deleted, because it is the only test covering the
// service principal block at all, and it documents the shape the mapper is
// currently written for. Its assertions are therefore a record of the mapper's
// intent, not of the wire. The authority on this record's shape is
// liveProvisioning; when the mapper is fixed to the real shape, this fixture
// must change with it. It is deliberately NOT driven through the emitter, so
// its invented attribute keys stay out of testdata/signals.json.
func TestMapProvisioningSuccess(t *testing.T) {
	rec := map[string]any{
		"id":                 "prov-1",
		"activityDateTime":   "2026-07-01T10:00:00Z",
		"jobId":              "job-1",
		"cycleId":            "cycle-1",
		"changeId":           "change-1",
		"provisioningAction": "create",
		"provisioningStatusInfo": map[string]any{
			"status": "success",
		},
		"sourceIdentity": map[string]any{
			"id":          "src-guid",
			"displayName": "Alice Source",
		},
		"targetIdentity": map[string]any{
			"id":          "tgt-guid",
			"displayName": "Alice Target",
		},
		"servicePrincipal": []any{
			map[string]any{"id": "sp-guid", "name": "ServiceNow"},
		},
	}

	id, ev := mapProvisioning(rec)
	if id != "prov-1" {
		t.Fatalf("dedupe id = %q, want prov-1", id)
	}
	if ev.Name != eventName {
		t.Fatalf("event name = %q, want %q", ev.Name, eventName)
	}
	if ev.Severity != telemetry.SeverityInfo {
		t.Errorf("successful provisioning severity = %v, want Info", ev.Severity)
	}
	wantBody := "provisioning create: success"
	if ev.Body != wantBody {
		t.Errorf("body = %q, want %q", ev.Body, wantBody)
	}

	wantAttrs := map[string]any{
		"id":                           "prov-1",
		"job_id":                       "job-1",
		"cycle_id":                     "cycle-1",
		"change_id":                    "change-1",
		"provisioning_action":          "create",
		"status":                       "success",
		"source_identity_id":           "src-guid",
		"source_identity_display_name": "Alice Source",
		"target_identity_id":           "tgt-guid",
		"target_identity_display_name": "Alice Target",
		"service_principal_id":         "sp-guid",
		"service_principal_name":       "ServiceNow",
	}
	for k, want := range wantAttrs {
		if got := ev.Attrs[k]; got != want {
			t.Errorf("attr %q = %v, want %v", k, got, want)
		}
	}
	if _, present := ev.Attrs["status_info"]; present {
		t.Errorf("successful event with no errorInformation must not carry status_info, attrs=%v", ev.Attrs)
	}
	if _, present := ev.Attrs["status_error_code"]; present {
		t.Errorf("successful event with no errorInformation must not carry status_error_code, attrs=%v", ev.Attrs)
	}
}

func TestMapProvisioningFailureIsWarn(t *testing.T) {
	rec := map[string]any{
		"id":                 "prov-2",
		"activityDateTime":   "2026-07-01T11:00:00Z",
		"provisioningAction": "update",
		"provisioningStatusInfo": map[string]any{
			"status": "failure",
			"errorInformation": map[string]any{
				"errorCode": "MissingRequiredAttribute",
				"reason":    "The target attribute is required but empty",
			},
		},
	}

	_, ev := mapProvisioning(rec)
	if ev.Severity != telemetry.SeverityWarn {
		t.Errorf("failed provisioning severity = %v, want Warn", ev.Severity)
	}
	if ev.Attrs["status"] != "failure" {
		t.Errorf("status = %v, want failure", ev.Attrs["status"])
	}
	if ev.Attrs["status_info"] != "The target attribute is required but empty" {
		t.Errorf("status_info = %v, want the error reason", ev.Attrs["status_info"])
	}
	if ev.Attrs["status_error_code"] != "MissingRequiredAttribute" {
		t.Errorf("status_error_code = %v, want MissingRequiredAttribute", ev.Attrs["status_error_code"])
	}
	wantBody := "provisioning update: failure"
	if ev.Body != wantBody {
		t.Errorf("body = %q, want %q", ev.Body, wantBody)
	}
}

// A record with no servicePrincipal, sourceIdentity, or targetIdentity (all
// optional per the provisioningObjectSummary resource doc) must omit those
// attributes entirely rather than emitting them empty/zero.
func TestMapProvisioningOmitsAbsentNestedFields(t *testing.T) {
	rec := map[string]any{
		"id":                 "prov-3",
		"activityDateTime":   "2026-07-01T12:00:00Z",
		"provisioningAction": "disable",
	}
	_, ev := mapProvisioning(rec)
	for _, k := range []string{
		"source_identity_id", "source_identity_display_name",
		"target_identity_id", "target_identity_display_name",
		"service_principal_id", "service_principal_name",
		"status", "status_info", "status_error_code",
		"job_id", "cycle_id", "change_id",
	} {
		if _, present := ev.Attrs[k]; present {
			t.Errorf("attr %q must be omitted when the source field is absent, attrs=%v", k, ev.Attrs)
		}
	}
}

func TestNotExperimentalNoLicenseGate(t *testing.T) {
	f := &recordingFetcher{records: []map[string]any{{"id": "a", "activityDateTime": "2026-07-01T10:00:00Z"}}}
	c := newCollector(depsWith(t, f))

	if _, ok := any(c).(collectors.Experimental); ok {
		t.Error("provisioning collector must not implement Experimental (v1.0, not beta)")
	}
	perms := c.RequiredPermissions()
	if len(perms) != 1 || perms[0] != "AuditLog.Read.All" {
		t.Errorf("RequiredPermissions = %v, want [AuditLog.Read.All]", perms)
	}
}

// #23 acceptance: the emitted $filter must use strict gt/lt, never the
// inclusive ge/le the other audit streams use, because provisioning's
// $orderby is unreliable and boundary events are caught by the overlap
// window + id-dedupe instead.
func TestFirstPageURLUsesStrictGtLt(t *testing.T) {
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
	if !strings.HasPrefix(u, "https://graph.microsoft.com/v1.0/auditLogs/provisioning?") {
		t.Errorf("first-page URL = %q, want the v1.0 provisioning endpoint", u)
	}
	if !strings.Contains(u, "activityDateTime+gt+") {
		t.Errorf("first-page URL = %q, want a strict activityDateTime gt bound", u)
	}
	if !strings.Contains(u, "activityDateTime+lt+") {
		t.Errorf("first-page URL = %q, want a strict activityDateTime lt bound", u)
	}
	if strings.Contains(u, "activityDateTime+ge+") || strings.Contains(u, "activityDateTime+le+") {
		t.Errorf("first-page URL = %q, must not use the inclusive ge/le operators", u)
	}
	if strings.Contains(u, "%24orderby") {
		t.Errorf("first-page URL = %q, must not carry $orderby ($orderby is unreliable on provisioning)", u)
	}
}

func TestCollectorDrainsEmitsAndPersistsWatermark(t *testing.T) {
	dir := t.TempDir()
	from := time.Date(2026, 7, 1, 9, 0, 0, 0, time.UTC)
	newest := "2026-07-01T09:45:00Z"

	f := &recordingFetcher{records: []map[string]any{
		{"id": "a", "activityDateTime": "2026-07-01T09:10:00Z", "provisioningAction": "create"},
		{"id": "b", "activityDateTime": newest, "provisioningAction": "update"},
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

// The engine must sort the drained window client-side by activityDateTime
// before computing the new high-water mark, since $orderby is unreliable on
// provisioning: even when the server returns records out of time order, the
// persisted watermark must reflect the true newest event time.
func TestCollectorSortsClientSideOnUnreliableOrder(t *testing.T) {
	dir := t.TempDir()
	from := time.Date(2026, 7, 1, 9, 0, 0, 0, time.UTC)
	newest := "2026-07-01T09:45:00Z"

	// Server returns the newer record FIRST, violating $orderby asc.
	f := &recordingFetcher{records: []map[string]any{
		{"id": "b", "activityDateTime": newest, "provisioningAction": "update"},
		{"id": "a", "activityDateTime": "2026-07-01T09:10:00Z", "provisioningAction": "create"},
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
	wantHW := time.Date(2026, 7, 1, 9, 45, 0, 0, time.UTC).Add(-logpipelineDefaultSafetyLag)
	if !cp.Watermark.Equal(wantHW) {
		t.Errorf("watermark = %v, want newest(%s) - safetyLag = %v (client-side sort must find the true newest record)", cp.Watermark, newest, wantHW)
	}
}

// logpipelineDefaultSafetyLag mirrors logpipeline.DefaultSafetyLag (15m), the
// margin the engine trails the watermark by when EndpointConfig.SafetyLag is
// left at its default.
const logpipelineDefaultSafetyLag = 15 * time.Minute
