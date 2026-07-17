package auditevents

import (
	"context"
	"encoding/json"
	"fmt"
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

// liveAuditEvent is a VERBATIM GET /deviceManagement/auditEvents record from the
// m7kni tenant, read as graph2otel-poller on 2026-07-17
// `[live-measured 2026-07-17, #165]`. It is the richest of the five rows
// captured that day: two resources (one with an EMPTY modifiedProperties array,
// one with seven) and an actor carrying BOTH a user and an application identity
// at once — so a single real record exercises the mapper's resources[] loop and
// every actor_* branch, which the docs fixtures below could only cover by
// splitting across two hand-written records.
//
// It is the emitter/golden authority for this package because a hand-written
// fixture cannot fail: it encodes the author's belief about the wire and then
// confirms it. That is the exact failure class of #142 ("platform":"windows",
// never on the wire) and #153 (an invented riskType key that kept a dead mapper
// line green for the life of the project). The docs-derived fixtures this record
// replaces used Microsoft's own documentation placeholders — alice@contoso.com
// and 203.0.113.9 (TEST-NET-3) — and are kept below ONLY as mapper-level
// branch coverage, never driven into the golden.
//
// Wire facts this record establishes that no docs fixture would have guessed
// (see TestMapAuditEventAgainstLiveRecord, which pins the exact emitted set):
//   - actor.ipAddress is null and the top-level activity field is null on all
//     five captured rows, so actor_ip_address and activity are NOT in this
//     record's emitted attribute set.
//   - a resource's displayName can be the LITERAL string "<null>" (not JSON
//     null); the mapper treats it as a present name and emits it verbatim in
//     resource_display_names.
//   - modifiedProperties can be an empty array on one resource of a
//     multi-resource record.
//   - the modifiedProperties newValues here are benign config strings, but the
//     mapper still emits only the property NAMES — the one content exclusion in
//     graph2otel holds on real data, not just on the synthetic secret fixture.
const liveAuditEvent = `{
  "activity": null,
  "activityDateTime": "2025-09-12T16:02:46.1164804Z",
  "activityOperationType": "Create",
  "activityResult": "Success",
  "activityType": "Create DeviceManagementConfigurationPolicyAssignment",
  "actor": {
    "applicationDisplayName": "Microsoft Intune portal extension",
    "applicationId": "5926fc8e-304e-4f59-8bed-58ca97cc39a4",
    "auditActorType": "ItPro",
    "ipAddress": null,
    "servicePrincipalName": null,
    "userId": "bbcfc3c5-0b93-4135-9ef9-18477a9fb504",
    "userPermissions": [
      "*"
    ],
    "userPrincipalName": "rob@m7kni.com"
  },
  "category": "DeviceConfiguration",
  "componentName": "DeviceConfiguration",
  "correlationId": "e785a76a-b122-44d2-9438-32d87da0e217",
  "displayName": "Create device configuration assignment 2.0 (beta)",
  "id": "a7c4ee76-621e-4795-aaf4-3dae19f03c35",
  "resources": [
    {
      "auditResourceType": "DeviceManagementConfigurationPolicy",
      "displayName": "MacOS Updates",
      "modifiedProperties": [],
      "resourceId": "867a3c3f-b8c1-493b-8934-8c613c585cb9"
    },
    {
      "auditResourceType": "DeviceManagementConfigurationPolicyAssignment",
      "displayName": "<null>",
      "modifiedProperties": [
        {
          "displayName": "Target.Type",
          "newValue": "AllDevicesAssignmentTarget",
          "oldValue": null
        },
        {
          "displayName": "Target.DeviceAndAppManagementAssignmentFilterId",
          "newValue": "<null>",
          "oldValue": null
        },
        {
          "displayName": "Target.DeviceAndAppManagementAssignmentFilterType",
          "newValue": "None",
          "oldValue": null
        },
        {
          "displayName": "Id",
          "newValue": "867a3c3f-b8c1-493b-8934-8c613c585cb9_adadadad-808e-44e2-905a-0b7873a8a531",
          "oldValue": null
        },
        {
          "displayName": "Source",
          "newValue": "Direct",
          "oldValue": null
        },
        {
          "displayName": "SourceId",
          "newValue": "867a3c3f-b8c1-493b-8934-8c613c585cb9",
          "oldValue": null
        },
        {
          "displayName": "DeviceManagementAPIVersion",
          "newValue": "5025-06-03",
          "oldValue": null
        }
      ],
      "resourceId": "867a3c3f-b8c1-493b-8934-8c613c585cb9_adadadad-808e-44e2-905a-0b7873a8a531"
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

// --- docs-derived synthetic fixtures, kept for MAPPER branch coverage only ---
//
// These are NOT wire records — they carry Microsoft's documentation placeholder
// values (alice@contoso.com, 203.0.113.9) and are the shape #164/#165 warn about:
// no field NAME here is evidence of wire shape. They are retained, per #165's
// "mark, don't invent" guidance, ONLY because each exercises a branch the five
// captured live rows cannot, and each is driven through mapAuditEvent DIRECTLY
// (never into a Recorder), so none of their keys reach testdata/signals.json —
// the golden is the live record's witnessed surface alone.
//
// Each is a func returning a fresh map so the engine can never mutate a literal
// shared across tests.

// secretOld and secretNew are the stand-in credential values that must never
// reach an OTLP attribute. See TestMapAuditEventNeverEmitsModifiedPropertyValues.
const (
	secretOld = "MIIC-fake-old-certificate-blob-DO-NOT-LEAK"
	secretNew = "MIIC-fake-new-certificate-blob-DO-NOT-LEAK"
)

// userInitiatedAuditEvent is a successful ItPro-actor policy change. Docs-derived,
// kept for branch coverage of actor_ip_address and a populated top-level
// activity field — both null on all five live rows, so the live record's emitted
// set carries neither. Mapper-only; never reaches the golden.
func userInitiatedAuditEvent() map[string]any {
	return map[string]any{
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
}

// appInitiatedFailureAuditEvent is an application-actor failure. Docs-derived,
// kept for branch coverage of the failure→Warn severity path: all five captured
// live rows are activityResult "Success". Mapper-only; never reaches the golden.
func appInitiatedFailureAuditEvent() map[string]any {
	return map[string]any{
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
}

// secretBearingAuditEvent is a certificate change whose modifiedProperties carry
// a credential in oldValue/newValue. Docs-derived, kept for branch coverage of
// the ONE content exclusion in graph2otel: no captured live row carries a secret
// in modifiedProperties, so proving the redaction requires a fixture that does.
// This is the only synthetic driven end-to-end, so the redaction can be asserted
// at the EMITTER, not just at the mapper.
func secretBearingAuditEvent() map[string]any {
	return map[string]any{
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
}

// TestMapAuditEventAgainstLiveRecord pins the EXACT attribute set the mapper
// produces from the richest real record this project has captured. Exact-set
// equality is the point (mirroring entra/riskdetections'
// TestMapRiskDetectionAgainstLiveRecord): it fails on a dropped field AND on a
// fabricated one — the pair of mistakes #142/#153 are made of — and it is the
// authority that testdata/signals.json's log key set is checked against.
func TestMapAuditEventAgainstLiveRecord(t *testing.T) {
	id, ev := mapAuditEvent(decodeLive(t, liveAuditEvent))

	if id != "a7c4ee76-621e-4795-aaf4-3dae19f03c35" {
		t.Errorf("dedupe id = %q, want the record's immutable audit id", id)
	}
	if ev.Name != eventName {
		t.Fatalf("event name = %q, want %q", ev.Name, eventName)
	}
	if ev.Severity != telemetry.SeverityInfo {
		t.Errorf("Success activityResult severity = %v, want Info", ev.Severity)
	}

	// #172 regression guard: Body must render from displayName, not the
	// top-level activity field — activity is null on every live-captured row,
	// which used to render every Body with an empty middle
	// ("DeviceConfiguration:  (Success)").
	wantBody := "DeviceConfiguration: Create device configuration assignment 2.0 (beta) (Success)"
	if ev.Body != wantBody {
		t.Errorf("body = %q, want %q", ev.Body, wantBody)
	}

	// The exact emitted key set. activity and actor_ip_address are DELIBERATELY
	// absent: the wire carries both as null on all five captured rows.
	wantKeys := []string{
		"activity_operation_type",
		"activity_result",
		"activity_type",
		"actor_application_display_name",
		"actor_application_id",
		"actor_type",
		"actor_user_id",
		"actor_user_principal_name",
		"category",
		"component_name",
		"correlation_id",
		"display_name",
		"id",
		"modified_property_names",
		"resource_display_names",
		"resource_types",
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
		"id":                             "a7c4ee76-621e-4795-aaf4-3dae19f03c35",
		"activity_type":                  "Create DeviceManagementConfigurationPolicyAssignment",
		"activity_operation_type":        "Create",
		"activity_result":                "Success",
		"category":                       "DeviceConfiguration",
		"component_name":                 "DeviceConfiguration",
		"display_name":                   "Create device configuration assignment 2.0 (beta)",
		"correlation_id":                 "e785a76a-b122-44d2-9438-32d87da0e217",
		"actor_type":                     "ItPro",
		"actor_user_principal_name":      "rob@m7kni.com",
		"actor_user_id":                  "bbcfc3c5-0b93-4135-9ef9-18477a9fb504",
		"actor_application_display_name": "Microsoft Intune portal extension",
		"actor_application_id":           "5926fc8e-304e-4f59-8bed-58ca97cc39a4",
	}
	for k, want := range wantScalars {
		if got := ev.Attrs[k]; got != want {
			t.Errorf("attr %q = %v, want %v", k, got, want)
		}
	}

	// Slice attributes: both resources contribute their type; the literal
	// "<null>" resource displayName is emitted verbatim; only the SECOND
	// resource has modifiedProperties (the first's array is empty).
	wantSlices := map[string][]string{
		"resource_types": {
			"DeviceManagementConfigurationPolicy",
			"DeviceManagementConfigurationPolicyAssignment",
		},
		"resource_display_names": {"MacOS Updates", "<null>"},
		"modified_property_names": {
			"Target.Type",
			"Target.DeviceAndAppManagementAssignmentFilterId",
			"Target.DeviceAndAppManagementAssignmentFilterType",
			"Id",
			"Source",
			"SourceId",
			"DeviceManagementAPIVersion",
		},
	}
	for k, want := range wantSlices {
		got, ok := ev.Attrs[k].([]string)
		if !ok {
			t.Errorf("attr %q = %#v, want []string", k, ev.Attrs[k])
			continue
		}
		if !reflect.DeepEqual(got, want) {
			t.Errorf("attr %q = %v, want %v", k, got, want)
		}
	}

	// The secrets rule, checked on REAL data: the property NAMES are emitted,
	// but no modifiedProperties VALUE (newValue/oldValue) may appear in any
	// attribute. These four are newValues that are not also legitimate attribute
	// values elsewhere on the record ("<null>" is excluded from this check
	// precisely because it is ALSO a real resource displayName above).
	forbiddenValues := []string{
		"AllDevicesAssignmentTarget",
		"Direct",
		"5025-06-03",
		"867a3c3f-b8c1-493b-8934-8c613c585cb9_adadadad-808e-44e2-905a-0b7873a8a531",
	}
	for k, v := range ev.Attrs {
		rendered := fmt.Sprintf("%v", v)
		for _, forbidden := range forbiddenValues {
			if strings.Contains(rendered, forbidden) {
				t.Errorf("attr %q = %v leaked a modifiedProperties value %q", k, v, forbidden)
			}
		}
	}
}

// TestMapAuditEventUserInitiatedSuccess is docs-derived (see the fixture): it
// keeps mapper-level coverage of actor_ip_address and a populated top-level
// activity, both of which the live record leaves null. It drives the mapper
// directly, so its placeholder values never reach the golden.
func TestMapAuditEventUserInitiatedSuccess(t *testing.T) {
	rec := userInitiatedAuditEvent()

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
	wantBody := "DeviceConfiguration: Create deviceConfiguration (success)"
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
	rec := appInitiatedFailureAuditEvent()

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
	rec := secretBearingAuditEvent()

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

// TestCollectorEmitsFullRecordsEndToEnd drives the live record and the
// secret-bearing synthetic through the real engine into an emitter, rather than
// calling mapAuditEvent directly like the tests above.
//
// Two things depend on it. First, it proves every attribute mapAuditEvent sets
// survives the whole path — including the secret redaction, which is asserted
// here at the EMITTER, not just at the mapper: an exclusion that holds in
// mapAuditEvent but leaked downstream would still ship the credential.
//
// Second, it is what makes testdata/signals.json honest. The signal gate
// goldens the union of what a package's tests EMIT, so with only the minimal
// synthetic records of the watermark/dedupe tests reaching the emitter, the
// golden recorded a 4-attribute surface for a collector that really ships its
// full audit surface — understating the exact thing the golden exists to make
// reviewable (#164). The live record supplies that full surface with REAL values
// (#165); the docs synthetics stay mapper-only so nothing fictional reaches the
// golden. secretBearing is driven here (and nowhere else in the emitter path)
// solely to prove the redaction end-to-end — no live row carries a secret.
func TestCollectorEmitsFullRecordsEndToEnd(t *testing.T) {
	f := &recordingFetcher{records: []map[string]any{
		decodeLive(t, liveAuditEvent),
		secretBearingAuditEvent(),
	}}
	rec := telemetrytest.New()
	c := newCollector(collectors.WindowDeps{TenantID: "t1", Fetcher: f, Store: checkpoint.NewStore(t.TempDir())})

	// Wide enough to span the live record (2025-09) and the secret synthetic
	// (2026-07); this endpoint is server-filtered, so the fetcher's records are
	// emitted regardless of the window bounds.
	from := time.Date(2025, 9, 1, 0, 0, 0, 0, time.UTC)
	if _, err := c.CollectWindow(context.Background(), from, time.Date(2026, 8, 1, 0, 0, 0, 0, time.UTC), rec.Emitter()); err != nil {
		t.Fatalf("CollectWindow: %v", err)
	}

	logs := rec.LogRecords()
	if len(logs) != 2 {
		t.Fatalf("emitted %d records, want 2", len(logs))
	}
	for _, got := range logs {
		if got.EventName != eventName {
			t.Errorf("event name = %q, want %q", got.EventName, eventName)
		}
	}

	// THE content exclusion, checked at the emitter: a modifiedProperties
	// old/new value must never appear in ANY attribute or body of ANY emitted
	// record. For a credential change the value IS the credential (CLAUDE.md:
	// the one content exclusion in graph2otel, about secrets, not PII). Both the
	// synthetic secret AND the live record's real newValues are checked.
	forbidden := []string{
		secretOld, secretNew,
		"AllDevicesAssignmentTarget", "Direct", "5025-06-03",
		"867a3c3f-b8c1-493b-8934-8c613c585cb9_adadadad-808e-44e2-905a-0b7873a8a531",
	}
	for _, got := range logs {
		for k, v := range got.Attrs {
			for _, bad := range forbidden {
				if strings.Contains(v, bad) {
					t.Fatalf("emitted attr %q = %q leaked a modifiedProperties value %q", k, v, bad)
				}
			}
		}
		for _, bad := range forbidden {
			if strings.Contains(got.Body, bad) {
				t.Fatalf("emitted body %q leaked a modifiedProperties value %q", got.Body, bad)
			}
		}
	}

	byID := map[string]map[string]string{}
	for _, got := range logs {
		byID[got.Attrs["id"]] = got.Attrs
	}

	// The property NAME survives to the emitter — only the value is excluded.
	if got := byID["audit-3"]["modified_property_names"]; got != "certificate" {
		t.Errorf("audit-3 modified_property_names = %q, want %q", got, "certificate")
	}

	// The live record's full surface at the emitter. []string attrs arrive
	// comma-joined (telemetry.toLogKV), which is the shape on the wire. This one
	// real record carries BOTH the user actor and the application actor, and the
	// full resources[] surface — what the old docs fixtures needed two separate
	// records to cover.
	live := byID["a7c4ee76-621e-4795-aaf4-3dae19f03c35"]
	wantLive := map[string]string{
		"id":                             "a7c4ee76-621e-4795-aaf4-3dae19f03c35",
		"activity_type":                  "Create DeviceManagementConfigurationPolicyAssignment",
		"activity_operation_type":        "Create",
		"activity_result":                "Success",
		"category":                       "DeviceConfiguration",
		"component_name":                 "DeviceConfiguration",
		"display_name":                   "Create device configuration assignment 2.0 (beta)",
		"correlation_id":                 "e785a76a-b122-44d2-9438-32d87da0e217",
		"actor_type":                     "ItPro",
		"actor_user_principal_name":      "rob@m7kni.com",
		"actor_user_id":                  "bbcfc3c5-0b93-4135-9ef9-18477a9fb504",
		"actor_application_display_name": "Microsoft Intune portal extension",
		"actor_application_id":           "5926fc8e-304e-4f59-8bed-58ca97cc39a4",
		"resource_types":                 "DeviceManagementConfigurationPolicy,DeviceManagementConfigurationPolicyAssignment",
		"resource_display_names":         "MacOS Updates,<null>",
		"modified_property_names":        "Target.Type,Target.DeviceAndAppManagementAssignmentFilterId,Target.DeviceAndAppManagementAssignmentFilterType,Id,Source,SourceId,DeviceManagementAPIVersion",
	}
	for k, want := range wantLive {
		if got := live[k]; got != want {
			t.Errorf("live record emitted attr %q = %q, want %q", k, got, want)
		}
	}

	// actor_ip_address and activity are null on the wire, so they must NOT be on
	// the emitted live record — the exact thing that keeps the golden honest.
	for _, k := range []string{"actor_ip_address", "activity"} {
		if v, present := live[k]; present && v != "" {
			t.Errorf("live record emitted %q = %q, want it absent (null on the wire)", k, v)
		}
	}

	// The transport stamp the engine applies at the emitter boundary (#141).
	if got := live["ingest_transport"]; got != "graph" {
		t.Errorf("ingest_transport = %q, want graph", got)
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
