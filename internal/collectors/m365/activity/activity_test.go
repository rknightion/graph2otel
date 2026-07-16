package activity

import (
	"encoding/json"
	"fmt"
	"maps"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/rknightion/graph2otel/internal/checkpoint"
	"github.com/rknightion/graph2otel/internal/collectors"
	"github.com/rknightion/graph2otel/internal/o365activityclient"
)

// liveRecord returns a representative Office 365 Management Activity API
// record in the shape measured live on m7kni (#100): the classic O365 schema
// served RAW at the top level, with RecordType/UserType as INTS.
//
// Numbers are float64 because that is what encoding/json produces for a JSON
// number decoded into map[string]any — the engine's decode path. A fixture
// using int here would test a shape that never reaches the mapper.
func liveRecord() map[string]any {
	return map[string]any{
		"CreationTime":                  "2026-07-16T09:15:00",
		"Id":                            "rec-abc-123",
		"Operation":                     "Add app role assignment to service principal.",
		"OrganizationId":                "org-guid-1",
		"RecordType":                    float64(8),
		"ResultStatus":                  "Success",
		"UserKey":                       "user-key-1",
		"UserType":                      float64(4),
		"Version":                       float64(1),
		"Workload":                      "AzureActiveDirectory",
		"ObjectId":                      "obj-42",
		"UserId":                        "alice@contoso.com",
		"ClientIP":                      "203.0.113.7",
		"AzureActiveDirectoryEventType": float64(1),
		"ExtendedProperties": []any{
			map[string]any{"Name": "additionalDetails", "Value": `{"appId":"app-guid"}`},
			map[string]any{"Name": "extendedAuditEventCategory", "Value": "ServicePrincipal"},
		},
		// Both OldValue and NewValue are deliberately NON-EMPTY. An empty
		// OldValue would let a mutant that smuggles values out under a new key
		// slip past TestLogAttrKeySetIsExact, because the smuggled attribute
		// would come out empty and be skipped — found by mutation-testing this
		// very fixture.
		"ModifiedProperties": []any{
			map[string]any{
				"Name":     "AppRole.Value",
				"NewValue": "MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQC-PRIVATE-KEY",
				"OldValue": "prior-approle-value",
			},
		},
		"Actor": []any{
			map[string]any{"ID": "alice@contoso.com", "Type": float64(5)},
			map[string]any{"ID": "actor-guid-1", "Type": float64(3)},
		},
	}
}

// TestEventNameConvergesWithUnifiedAudit pins Trap 1 as a literal rather than
// via the const: the Management API record IS the query API's auditData
// sub-object, so the two sources are drop-in equivalents and MUST emit the same
// event name. A rename of the const alone would otherwise sail through green
// while silently forking the signal in two.
//
// See internal/collectors/m365/unifiedaudit/unifiedaudit.go's eventName.
func TestEventNameConvergesWithUnifiedAudit(t *testing.T) {
	_, ev, ok := mapRecord(liveRecord())
	if !ok {
		t.Fatal("mapRecord returned ok=false for a well-formed record")
	}
	if ev.Name != "m365.audit" {
		t.Errorf("event name = %q, want %q — m365.activity and m365.unified_audit are the same signal from two transports and must share one event name", ev.Name, "m365.audit")
	}
}

// TestDedupeIDIsTheRecordID pins that the dedupe id is the record's own
// immutable Id — the same id m365.unified_audit emits, which is what makes the
// two sources dedupe-able downstream while both are enabled (the plan's R3).
func TestDedupeIDIsTheRecordID(t *testing.T) {
	id, ev, ok := mapRecord(liveRecord())
	if !ok {
		t.Fatal("mapRecord returned ok=false for a well-formed record")
	}
	if id != "rec-abc-123" {
		t.Errorf("dedupe id = %q, want rec-abc-123", id)
	}
	if ev.Attrs["id"] != "rec-abc-123" {
		t.Errorf("id attr = %v, want rec-abc-123 (the id must reach the log, not only the engine)", ev.Attrs["id"])
	}
}

// TestMapRecordConvergesWithUnifiedAudit is THE contract test for Trap 2.
//
// The expected values are exactly what internal/collectors/m365/unifiedaudit's
// mapRecord emits for the SAME underlying event arriving via the Graph audit
// query API. They are pinned as literals because unifiedaudit.mapRecord is
// unexported and cannot be called across the package boundary; each line below
// is annotated with the query-API field it must agree with.
//
// If any of these diverge, one event emits two different values depending on
// which transport produced it, and downstream correlation breaks SILENTLY —
// there is no error, just two populations that will not join.
func TestMapRecordConvergesWithUnifiedAudit(t *testing.T) {
	_, ev, ok := mapRecord(liveRecord())
	if !ok {
		t.Fatal("mapRecord returned ok=false for a well-formed record")
	}

	want := map[string]any{
		// RecordType 8 (int) must converge to the PascalCase string the query
		// API returns in auditLogRecordType. The 8 <-> "AzureActiveDirectory"
		// pair is a REAL live capture (#98).
		"record_type": "AzureActiveDirectory",
		// UserType 4 (int) must converge to the query API's userType string.
		// "System" is live-captured in the same #98 record.
		"user_type": "System",
		// ClientIP (PascalCase here) vs clientIp (camelCase there).
		"client_ip": "203.0.113.7",
		// Workload is top-level here, nested under auditData there.
		"workload": "AzureActiveDirectory",
		// `service` is ABSENT on this API. The query API emits it, and on the
		// live #98 record it was byte-identical to auditData.Workload, so it is
		// sourced from Workload to keep the attribute present on both.
		"service":       "AzureActiveDirectory",
		"operation":     "Add app role assignment to service principal.",
		"result_status": "Success",
		"user_id":       "alice@contoso.com",
		"object_id":     "obj-42",
		"id":            "rec-abc-123",
	}
	for k, v := range want {
		if ev.Attrs[k] != v {
			t.Errorf("attr %q = %v (%T), want %v (%T) — diverges from m365.unified_audit for the same event", k, ev.Attrs[k], ev.Attrs[k], v, v)
		}
	}
}

// TestRecordTypeIntConvergesToQueryAPIName table-tests the int -> PascalCase
// convergence across every RecordType observed live on m7kni plus the ones
// Microsoft's own documentation example pins.
//
// Provenance of each expectation is in the `src` field — this table is the
// load-bearing artifact of the whole collector, so each row says where it came
// from rather than trusting one source.
func TestRecordTypeIntConvergesToQueryAPIName(t *testing.T) {
	for _, tc := range []struct {
		in   float64
		want string
		src  string
	}{
		{8, "AzureActiveDirectory", "#98 LIVE capture: auditLogRecordType=AzureActiveDirectory paired with auditData.RecordType=8"},
		{9, "AzureActiveDirectoryAccountLogon", "Microsoft doc example, mirrored in o365activityclient/content_test.go:421"},
		{63, "DLPEndpoint", "#100 LIVE: RecordType 63 x3865, Workload=Endpoint; #98 LIVE member DLPEndpoint"},
		{52, "DataInsightsRestApiAudit", "#100 LIVE: RecordType 52 x97, Workload=SecurityComplianceCenter; #98 LIVE member"},
		{295, "AuditSearch", "#100 LIVE: RecordType 295 x68, Workload=SecurityComplianceCenter"},
		{57, "MicrosoftTeamsAdmin", "#100 LIVE: RecordType 57 x3, Workload=MicrosoftTeams; #98 LIVE member"},
		{1, "ExchangeAdmin", "#98 LIVE member; the recordTypeFilters doc pair exchangeAdmin <-> ExchangeAdmin"},
		{50, "ExchangeItemAggregated", "#98 LIVE member"},
		{6, "SharePointFileOperation", "#98 LIVE member"},
		{14, "SharePointSharingOperation", "#98 LIVE member"},
		{36, "SharePointListOperation", "#98 LIVE member"},
		{56, "SharePointFieldOperation", "#98 LIVE member"},
		{25, "MicrosoftTeams", "#98 LIVE member"},
		{15, "AzureActiveDirectoryStsLogon", "#98 LIVE member"},
		{18, "SecurityComplianceCenterEOPCmdlet", "#98 LIVE member"},
		{157, "MipLabelAnalyticsAuditRecord", "#98 LIVE member"},
		{235, "MicrosoftDefenderForIdentityAudit", "#98 LIVE member"},
		{304, "URBACEnableState", "#98 LIVE member"},
	} {
		t.Run(fmt.Sprint(int(tc.in)), func(t *testing.T) {
			rec := liveRecord()
			rec["RecordType"] = tc.in
			_, ev, ok := mapRecord(rec)
			if !ok {
				t.Fatal("mapRecord returned ok=false")
			}
			if ev.Attrs["record_type"] != tc.want {
				t.Errorf("RecordType %v -> record_type %v, want %q\n  provenance: %s",
					tc.in, ev.Attrs["record_type"], tc.want, tc.src)
			}
			if want := fmt.Sprint(int64(tc.in)); ev.Attrs["record_type_id"] != want {
				t.Errorf("record_type_id = %v (%T), want %q", ev.Attrs["record_type_id"], ev.Attrs["record_type_id"], want)
			}
		})
	}
}

// TestRecordTypeUnknownIntKeepsTheIntAndOmitsTheName pins the behavior on a
// RecordType this build cannot name.
//
// This is NOT a hypothetical edge case: RecordType 117 (Workload=AppGovernance)
// was measured live on m7kni (#100) and is absent from Microsoft's published
// AuditLogRecordType table. Six of the 22 record types #98 observed live on this
// same tenant are likewise unpublished (UAMOperation, MSDEIndicatorsSettings,
// MSDEResponseActions, MSDEGeneralSettings, MAPGRemediation, AgentAdminActivity),
// so ~27% of this tenant's record-type surface lands here on day one.
//
// The rule: never guess a name (a wrong name is a silent convergence break, the
// exact failure this collector exists to avoid), and never drop the datum
// either (#112). The int always survives on record_type_id; record_type is
// simply absent, which is visibly "unknown" rather than quietly wrong.
func TestRecordTypeUnknownIntKeepsTheIntAndOmitsTheName(t *testing.T) {
	rec := liveRecord()
	rec["RecordType"] = float64(117)

	_, ev, ok := mapRecord(rec)
	if !ok {
		t.Fatal("an unknown RecordType must still emit the record, not drop it")
	}
	if v, present := ev.Attrs["record_type"]; present {
		t.Errorf("unknown RecordType 117 emitted record_type = %v; want the attribute omitted — a guessed name silently breaks convergence with m365.unified_audit", v)
	}
	if ev.Attrs["record_type_id"] != "117" {
		t.Errorf("record_type_id = %v, want \"117\" — the int is the only lossless record-type datum for an unpublished type and must not be dropped (#112)", ev.Attrs["record_type_id"])
	}
}

// TestUserTypeIntConvergesToQueryAPIName table-tests the UserType int -> the
// query API's userType string, over the full published AuditLogUserType enum.
func TestUserTypeIntConvergesToQueryAPIName(t *testing.T) {
	for _, tc := range []struct {
		in   float64
		want string
	}{
		{0, "Regular"}, // the value the Management API returns live (#100)
		{1, "Reserved"},
		{2, "Admin"},
		{3, "DCAdmin"},
		{4, "System"}, // #98 LIVE capture: query API returned userType "System"
		{5, "Application"},
		{6, "ServicePrincipal"},
		{7, "CustomPolicy"},
		{8, "SystemPolicy"},
		{9, "PartnerTechnician"},
		{10, "Guest"},
	} {
		t.Run(tc.want, func(t *testing.T) {
			rec := liveRecord()
			rec["UserType"] = tc.in
			_, ev, ok := mapRecord(rec)
			if !ok {
				t.Fatal("mapRecord returned ok=false")
			}
			if ev.Attrs["user_type"] != tc.want {
				t.Errorf("UserType %v -> user_type %v, want %q", tc.in, ev.Attrs["user_type"], tc.want)
			}
		})
	}
}

// TestUserTypeUnknownIntKeepsTheIntAndOmitsTheName mirrors the RecordType rule
// on UserType: Microsoft may add a member, and a guessed name is worse than an
// absent one.
func TestUserTypeUnknownIntKeepsTheIntAndOmitsTheName(t *testing.T) {
	rec := liveRecord()
	rec["UserType"] = float64(99)

	_, ev, ok := mapRecord(rec)
	if !ok {
		t.Fatal("an unknown UserType must still emit the record")
	}
	if v, present := ev.Attrs["user_type"]; present {
		t.Errorf("unknown UserType 99 emitted user_type = %v; want the attribute omitted", v)
	}
	if ev.Attrs["user_type_id"] != "99" {
		t.Errorf("user_type_id = %v, want \"99\"", ev.Attrs["user_type_id"])
	}
}

// TestRecordTypeIsReadAsANumberNotAString is the #89 type-trap guard, aimed at
// the specific failure mode that produced it: a field whose type differs
// between two sources (or two levels of one record).
//
// RecordType is an int on this API and a string on the query API. A mapper that
// type-asserted .(string) would emit NOTHING for every record ever, silently.
// A mapper that type-asserted .(int) would emit nothing too, because
// encoding/json decodes every JSON number into map[string]any as float64.
func TestRecordTypeIsReadAsANumberNotAString(t *testing.T) {
	// Decode from real JSON bytes rather than hand-building the map, so the
	// test exercises the engine's actual decode path.
	var rec map[string]any
	raw := `{"CreationTime":"2015-06-29T20:03:19","Id":"80c76bd2","Operation":"PasswordLogonInitialAuthUsingPassword","RecordType":9,"UserType":0,"Workload":"AzureActiveDirectory","ClientIP":"134.170.188.221","UserId":"admin@contoso.onmicrosoft.com"}`
	if err := json.Unmarshal([]byte(raw), &rec); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if _, isFloat := rec["RecordType"].(float64); !isFloat {
		t.Fatalf("fixture precondition: encoding/json should decode RecordType to float64, got %T", rec["RecordType"])
	}

	_, ev, ok := mapRecord(rec)
	if !ok {
		t.Fatal("mapRecord returned ok=false for Microsoft's own documented example record")
	}
	if ev.Attrs["record_type"] != "AzureActiveDirectoryAccountLogon" {
		t.Errorf("record_type = %v, want AzureActiveDirectoryAccountLogon", ev.Attrs["record_type"])
	}
	if ev.Attrs["user_type"] != "Regular" {
		t.Errorf("user_type = %v, want Regular", ev.Attrs["user_type"])
	}
}

// TestRecordTypeToleratesNumericTypeFlips defends the convergence against the
// #89 lesson that Microsoft's field types are not stable: the same field is a
// string at one level and an int at another, on the same record. If RecordType
// ever arrives as a JSON string, or the decoder is switched to json.Number, the
// mapper must still resolve it rather than silently emitting nothing.
func TestRecordTypeToleratesNumericTypeFlips(t *testing.T) {
	for name, v := range map[string]any{
		"float64":     float64(63),
		"int":         int(63),
		"int64":       int64(63),
		"json.Number": json.Number("63"),
		"string":      "63",
	} {
		t.Run(name, func(t *testing.T) {
			rec := liveRecord()
			rec["RecordType"] = v
			_, ev, ok := mapRecord(rec)
			if !ok {
				t.Fatal("mapRecord returned ok=false")
			}
			if ev.Attrs["record_type"] != "DLPEndpoint" {
				t.Errorf("RecordType as %s: record_type = %v, want DLPEndpoint", name, ev.Attrs["record_type"])
			}
		})
	}
}

// --- SECURITY ---

// TestMapRecordNeverEmitsModifiedPropertyValues is the security test for
// CLAUDE.md's ONE genuine content exclusion, and it is about SECRETS, not PII.
//
// ModifiedProperties[].OldValue/NewValue carry whatever the changed property
// held — for a credential or certificate change, that is the credential itself.
// The NAMES are emitted; the values never are.
//
// It asserts the PROPERTY ("the secret is in no attribute value, anywhere")
// rather than a symptom ("the modified_property_values key is absent"), so it
// still fails if the value is smuggled out under a different key, folded into
// the Body, or nested inside a []string.
func TestMapRecordNeverEmitsModifiedPropertyValues(t *testing.T) {
	const secret = "MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQC-PRIVATE-KEY"
	const oldSecret = "previous-client-secret-value"

	rec := liveRecord()
	rec["ModifiedProperties"] = []any{
		map[string]any{"Name": "KeyDescription", "NewValue": secret, "OldValue": oldSecret},
		map[string]any{"Name": "ConsentContext.IsAdminConsent", "NewValue": "True", "OldValue": "False"},
	}

	_, ev, ok := mapRecord(rec)
	if !ok {
		t.Fatal("mapRecord returned ok=false")
	}

	for _, banned := range []string{secret, oldSecret} {
		for k, v := range ev.Attrs {
			for _, s := range flattenAttr(v) {
				if strings.Contains(s, banned) {
					t.Errorf("attr %q leaked a modifiedProperties value: %q contains %q — old/new values can carry credentials and certificates and must NEVER be emitted", k, s, banned)
				}
			}
		}
		if strings.Contains(ev.Body, banned) {
			t.Errorf("Body leaked a modifiedProperties value: %q contains %q", ev.Body, banned)
		}
	}

	// The other half of the rule: the NAMES must still be emitted. Excluding
	// the values must not become "drop the whole field" (#112) — an operator
	// still needs to know WHICH property changed.
	names, isSlice := ev.Attrs["modified_property_names"].([]string)
	if !isSlice {
		t.Fatalf("modified_property_names = %v (%T), want []string — the property names must survive the value exclusion", ev.Attrs["modified_property_names"], ev.Attrs["modified_property_names"])
	}
	if !slices.Contains(names, "KeyDescription") || !slices.Contains(names, "ConsentContext.IsAdminConsent") {
		t.Errorf("modified_property_names = %v, want both changed property names", names)
	}
}

// TestMapRecordEmitsExtendedPropertyValues pins the OPPOSITE of
// ModifiedProperties, deliberately.
//
// A first pass withheld these values too, reasoning that the Value is a
// JSON-ENCODED STRING — a nested document inside a string field (#100) — of
// unbounded, workload-defined shape. That is an argument about being awkward to
// model, not about being unsafe, and CLAUDE.md is explicit that reading the
// secret exclusion as general caution is what produced #110 and #111. Live,
// these carry additionalDetails ({"User-Agent":…,"AppId":…}),
// extendedAuditEventCategory, and LoginError (";PP_E_BAD_PASSWORD;…") — the
// anomalous-client and failed-logon signal a SIEM builds detections on.
// Withholding it would be #83 exactly: fetch a per-entity row, judge it too
// messy to keep, and it reaches no pipeline at all.
//
// The line: ModifiedProperties values are excluded because they can BE a
// credential. Nothing else is. If a workload is ever observed putting a secret
// in an ExtendedProperties value, this test is the place that changes — on
// evidence, not on the shape of the field.
func TestMapRecordEmitsExtendedPropertyValues(t *testing.T) {
	const payload = `{"User-Agent":"Mozilla/5.0 Chrome/151","AppId":"app-guid"}`

	rec := liveRecord()
	rec["ExtendedProperties"] = []any{
		map[string]any{"Name": "additionalDetails", "Value": payload},
		map[string]any{"Name": "extendedAuditEventCategory", "Value": "ServicePrincipal"},
	}

	_, ev, ok := mapRecord(rec)
	if !ok {
		t.Fatal("mapRecord returned ok=false")
	}

	names, isSlice := ev.Attrs["extended_property_names"].([]string)
	if !isSlice || !slices.Contains(names, "additionalDetails") {
		t.Errorf("extended_property_names = %v, want it to contain additionalDetails", ev.Attrs["extended_property_names"])
	}

	values, isSlice := ev.Attrs["extended_property_values"].([]string)
	if !isSlice {
		t.Fatalf("extended_property_values = %v (%T), want []string — these are event metadata and must reach a pipeline (#112)", ev.Attrs["extended_property_values"], ev.Attrs["extended_property_values"])
	}
	if !slices.Contains(values, payload) {
		t.Errorf("extended_property_values = %v, want it to carry the additionalDetails payload verbatim", values)
	}

	// Index alignment is the whole contract of two parallel slices: names[i]
	// must describe values[i], or the pair is worse than useless.
	if len(names) != len(values) {
		t.Fatalf("extended_property_names (%d) and extended_property_values (%d) must be index-aligned", len(names), len(values))
	}
	if i := slices.Index(names, "extendedAuditEventCategory"); i < 0 || values[i] != "ServicePrincipal" {
		t.Errorf("names/values are not index-aligned: %v vs %v", names, values)
	}
}

// flattenAttr renders any attribute value to the set of strings it contributes
// to the wire, so a leak check cannot be fooled by a []string or a non-string
// scalar.
func flattenAttr(v any) []string {
	switch t := v.(type) {
	case string:
		return []string{t}
	case []string:
		return t
	default:
		return []string{fmt.Sprint(t)}
	}
}

// --- #112 cardinality / attribute discipline ---

// TestEmitsNoMetricsOnlyLogs pins the collector's half of the cardinality rule
// at its source. This signal is per-entity audit records — sign-ins, admin
// changes, file operations — every field of which (record id, UPN, client IP,
// object id) is unbounded. It is a LOGS-only collector by construction, exactly
// like its m365.unified_audit sibling: the mapper's only output is a
// telemetry.Event, so there is no path by which a per-entity value could become
// a metric label.
//
// The guard is structural rather than behavioral because there is nothing to
// observe: mapRecord cannot reach an Emitter. If a metric is ever added to this
// package, this test's premise is what has changed, and the reviewer must
// re-derive the bounded-dimension argument from scratch.
func TestEmitsNoMetricsOnlyLogs(t *testing.T) {
	_, ev, ok := mapRecord(liveRecord())
	if !ok {
		t.Fatal("mapRecord returned ok=false")
	}
	if ev.Name == "" {
		t.Error("mapper produced no log event")
	}
}

// TestLogAttrKeySetIsExact is the #112 discipline guard, in the shape
// intune/appinstallreport's TestMetricCarriesOnlyBoundedDimensions uses:
// assert the EXACT key set, never a denylist, so ANY newly introduced
// attribute trips it rather than only the ones a denylist anticipated.
//
// For a logs-only collector the risk this guards is inverted from the metric
// collectors': unbounded per-entity detail BELONGS here, so the danger is not
// cardinality but an attribute being added silently — in particular one
// carrying a modifiedProperties/extendedProperties VALUE. Any change to this
// list is a deliberate contract change and must be reviewed as one.
func TestLogAttrKeySetIsExact(t *testing.T) {
	_, ev, ok := mapRecord(liveRecord())
	if !ok {
		t.Fatal("mapRecord returned ok=false")
	}

	want := []string{
		"actor_ids",
		"azure_ad_event_type",
		"client_ip",
		"extended_property_names",
		"extended_property_values",
		"id",
		"modified_property_names",
		"object_id",
		"operation",
		"organization_id",
		"record_type",
		"record_type_id",
		"result_status",
		"service",
		"user_id",
		"user_key",
		"user_type",
		"user_type_id",
		"version",
		"workload",
	}
	got := slices.Sorted(maps.Keys(ev.Attrs))
	if !slices.Equal(got, want) {
		t.Errorf("attribute key set changed.\n got: %v\nwant: %v\nAdding or removing an attribute is a contract change: a new key must be checked against the modifiedProperties/extendedProperties value exclusion, and a removed key against #112 (data reaching no pipeline is a bug).", got, want)
	}
}

// TestEveryAttrIsAStringOrStringSlice pins the attribute VALUE types.
//
// This is not stylistic. A log attribute becomes Loki structured metadata, which
// is string-valued, so an int64 attribute gains nothing downstream — and it
// actively costs, because telemetrytest cannot render a log.Int64 ("AsString:
// invalid Kind: Int64"). An int-valued attribute therefore reads as EMPTY from
// LogRecord.Attrs, so a recorder-based test asserting on it would pass while
// measuring nothing. RecordType/UserType/Version arrive as JSON numbers and are
// the obvious candidates to emit as ints, which is exactly why this exists.
func TestEveryAttrIsAStringOrStringSlice(t *testing.T) {
	_, ev, ok := mapRecord(liveRecord())
	if !ok {
		t.Fatal("mapRecord returned ok=false")
	}
	for k, v := range ev.Attrs {
		switch v.(type) {
		case string, []string:
		default:
			t.Errorf("attr %q is %T, want string or []string — a non-string log attribute renders as empty in telemetrytest and gains nothing in Loki structured metadata", k, v)
		}
	}
}

// --- timestamps ---

// TestTimestampComesFromCreationTime pins the event time to the record's own
// CreationTime.
//
// THE trap: CreationTime is NOT RFC3339 on the wire — it carries no Z and no
// offset ("2015-06-29T20:03:19"), though the schema documents it as UTC.
// time.Parse(time.RFC3339, ...) FAILS on it outright, so a mapper written to
// the obvious layout drops every record. Verified against Microsoft's own
// documented example, mirrored in o365activityclient/content_test.go:421.
func TestTimestampComesFromCreationTime(t *testing.T) {
	for _, tc := range []struct {
		in   string
		want time.Time
	}{
		// The real wire shape: zone-less, documented UTC.
		{"2015-06-29T20:03:19", time.Date(2015, 6, 29, 20, 3, 19, 0, time.UTC)},
		// Zone-less with fractional seconds.
		{"2026-07-16T09:15:00.123", time.Date(2026, 7, 16, 9, 15, 0, 123000000, time.UTC)},
		// Defensive: if Microsoft ever starts sending a Z, it must still parse
		// to the same instant rather than regress.
		{"2026-07-16T09:15:00Z", time.Date(2026, 7, 16, 9, 15, 0, 0, time.UTC)},
		{"2026-07-16T09:15:00.5Z", time.Date(2026, 7, 16, 9, 15, 0, 500000000, time.UTC)},
	} {
		t.Run(tc.in, func(t *testing.T) {
			rec := liveRecord()
			rec["CreationTime"] = tc.in
			_, ev, ok := mapRecord(rec)
			if !ok {
				t.Fatalf("mapRecord returned ok=false for CreationTime %q", tc.in)
			}
			if !ev.Timestamp.Equal(tc.want) {
				t.Errorf("Timestamp = %s, want %s", ev.Timestamp.Format(time.RFC3339Nano), tc.want.Format(time.RFC3339Nano))
			}
		})
	}
}

// TestTimestampNeverFallsBackToNow is the #135 regression guard. A record whose
// time cannot be resolved is DROPPED, never stamped with "now": a wrong
// timestamp surfaces as nothing at all, while a skipped record surfaces as a
// skip. There is deliberately no fallback.
func TestTimestampNeverFallsBackToNow(t *testing.T) {
	for _, bad := range []any{
		nil,
		"",
		"not-a-time",
		"29/06/2015 20:03",
		float64(1435608199), // a unix epoch, not the documented string form
	} {
		t.Run(fmt.Sprint(bad), func(t *testing.T) {
			rec := liveRecord()
			if bad == nil {
				delete(rec, "CreationTime")
			} else {
				rec["CreationTime"] = bad
			}
			_, ev, ok := mapRecord(rec)
			if ok {
				t.Errorf("CreationTime %v: ok=true with Timestamp %s — an unparseable event time must drop the record, not guess one (#135)", bad, ev.Timestamp)
			}
		})
	}
}

// TestRecordWithoutIDIsStillEmitted pins the #112 side of the id contract, and
// it encodes a correction: dropping an id-less record looks defensible (it
// cannot be deduped, and this API re-delivers) but it discards a per-entity row,
// which #112 calls a bug outright. o365pipeline's EndpointConfig.Map contract
// agrees — an empty id is honored and the record still ships.
//
// This path should never fire: Id is mandatory in the Common Schema. The rule
// matters anyway, because the failure it prevents is silent data loss.
func TestRecordWithoutIDIsStillEmitted(t *testing.T) {
	rec := liveRecord()
	delete(rec, "Id")

	id, ev, ok := mapRecord(rec)
	if !ok {
		t.Fatal("a record with no Id must still be emitted with an empty dedupe id, not dropped (#112)")
	}
	if id != "" {
		t.Errorf("dedupe id = %q, want empty", id)
	}
	if v, present := ev.Attrs["id"]; present {
		t.Errorf("id attr = %v, want the attribute omitted entirely", v)
	}
	// The rest of the record must survive intact — the point is that the data
	// still reaches the pipeline.
	if ev.Attrs["record_type"] != "AzureActiveDirectory" {
		t.Errorf("record_type = %v, want AzureActiveDirectory", ev.Attrs["record_type"])
	}
}

// --- severity, body, sparse records ---

// TestSeverityEscalatesOnFailure pins severity to the same predicate
// m365.unified_audit uses, so the same event does not arrive INFO from one
// transport and WARN from the other. This API's ResultStatus vocabulary spans
// both "Failed" (classic) and "Failure" (Entra), hence both.
func TestSeverityEscalatesOnFailure(t *testing.T) {
	for _, tc := range []struct {
		status string
		want   string
	}{
		{"Success", "INFO"},
		{"Succeeded", "INFO"},
		{"PartiallySucceeded", "INFO"},
		{"Failed", "WARN"},
		{"Failure", "WARN"},
	} {
		t.Run(tc.status, func(t *testing.T) {
			rec := liveRecord()
			rec["ResultStatus"] = tc.status
			_, ev, ok := mapRecord(rec)
			if !ok {
				t.Fatal("mapRecord returned ok=false")
			}
			if got := ev.Severity.String(); got != tc.want {
				t.Errorf("ResultStatus %q -> severity %s, want %s", tc.status, got, tc.want)
			}
		})
	}
}

// TestMapOmitsAbsentAttrs asserts a sparse record omits absent attributes
// rather than emitting empty ones — the setStr rule the sibling collectors
// share. The fixture is the minimum viable record: an id and a time.
func TestMapOmitsAbsentAttrs(t *testing.T) {
	rec := map[string]any{
		"CreationTime": "2026-07-16T09:15:00",
		"Id":           "rec-sparse-1",
	}
	_, ev, ok := mapRecord(rec)
	if !ok {
		t.Fatal("a record with an id and a time must map, however sparse")
	}
	for _, k := range []string{
		"operation", "workload", "service", "result_status", "user_id", "user_key",
		"client_ip", "object_id", "organization_id", "record_type", "record_type_id",
		"user_type", "user_type_id", "actor_ids", "modified_property_names",
		"extended_property_names", "azure_ad_event_type", "version",
	} {
		if v, present := ev.Attrs[k]; present {
			t.Errorf("absent field produced attr %q = %v, want the attribute omitted entirely", k, v)
		}
	}
	if ev.Attrs["id"] != "rec-sparse-1" {
		t.Errorf("id = %v, want rec-sparse-1", ev.Attrs["id"])
	}
}

// TestActorIDsAreEmitted: Actor[] is per-entity identity data with no query-API
// twin. #112's hard rule means it must still reach a pipeline rather than the
// floor, and a log attribute is where per-entity data belongs.
func TestActorIDsAreEmitted(t *testing.T) {
	_, ev, ok := mapRecord(liveRecord())
	if !ok {
		t.Fatal("mapRecord returned ok=false")
	}
	got, isSlice := ev.Attrs["actor_ids"].([]string)
	if !isSlice {
		t.Fatalf("actor_ids = %v (%T), want []string", ev.Attrs["actor_ids"], ev.Attrs["actor_ids"])
	}
	if !slices.Equal(got, []string{"alice@contoso.com", "actor-guid-1"}) {
		t.Errorf("actor_ids = %v, want [alice@contoso.com actor-guid-1]", got)
	}
}

// TestMalformedNestedShapesDoNotPanic: every nested collection on this API is
// untyped JSON, and a mapper that panics takes the scheduler goroutine with it.
func TestMalformedNestedShapesDoNotPanic(t *testing.T) {
	rec := liveRecord()
	rec["ModifiedProperties"] = "not-an-array"
	rec["ExtendedProperties"] = []any{"not-an-object", float64(3), nil}
	rec["Actor"] = []any{map[string]any{"ID": float64(7)}, nil}
	rec["Workload"] = float64(42)

	_, ev, ok := mapRecord(rec)
	if !ok {
		t.Fatal("a record with malformed nested shapes should still map on its scalar fields")
	}
	if ev.Attrs["id"] != "rec-abc-123" {
		t.Errorf("id = %v, want rec-abc-123", ev.Attrs["id"])
	}
}

// --- factory / registration ---

// TestCollectorIsNotExperimental pins the entire point of #100: m365.activity
// exists to retire a BETA dependency, so shipping it opt-in would defeat it.
// m365.unified_audit is Experimental because POST /security/auditLog/queries is
// beta-only on a real tenant; this transport is v1.0 stable, so it is default-on.
//
// Asserted structurally — the composition root gates on a type assertion to
// collectors.Experimental, so the collector must NOT satisfy that interface at
// all. A method returning false would still be a behavior change away from
// opt-in, and this asserts the property the root actually reads.
func TestCollectorIsNotExperimental(t *testing.T) {
	c := newCollector(collectors.O365Deps{TenantID: "t1", Store: checkpoint.NewStore(t.TempDir())})
	if _, isExperimental := any(c).(collectors.Experimental); isExperimental {
		t.Error("m365.activity must NOT implement collectors.Experimental — dropping the beta dependency is the whole point of #100, and an Experimental collector is default-OFF")
	}
}

// TestFactoryWiresCollector pins the name, the declared scope, and the schedule
// bounds the composition root reads.
func TestFactoryWiresCollector(t *testing.T) {
	c := newCollector(collectors.O365Deps{TenantID: "t1", Store: checkpoint.NewStore(t.TempDir())})

	if c.Name() != "m365.activity" {
		t.Errorf("Name() = %q, want m365.activity", c.Name())
	}
	// ActivityFeed.Read, and ONLY that. It authorizes the read feed AND
	// POST /subscriptions/start — no ReadWrite variant is needed, which is what
	// keeps this write narrower than the Intune export-job one. ReadDlp is
	// deliberately absent: DLP.All is not a default content type.
	perms := c.RequiredPermissions()
	if len(perms) != 1 || perms[0] != "ActivityFeed.Read" {
		t.Errorf("RequiredPermissions() = %v, want [ActivityFeed.Read]", perms)
	}
	if c.DefaultInterval() <= 0 {
		t.Errorf("DefaultInterval() = %v, want positive", c.DefaultInterval())
	}
	if c.Lag() <= 0 {
		t.Errorf("Lag() = %v, want positive — the feed must never be queried up to 'now'", c.Lag())
	}
}

// TestDefaultContentTypesExcludeTheExpensiveOnes pins the plan's frozen scope
// decision, which is a COST decision on other operators' behalf rather than a
// technical one: graph2otel is public OSS and this API has no server-side
// filtering, so every subscribed content type is fetched in full.
//
//   - Audit.General is 95.8% endpoint-DLP noise on the live tenant (3,865 of
//     4,035 records, #100) — the exact record type #98 already decided to
//     exclude as "high volume, low signal".
//   - Audit.AzureActiveDirectory duplicates entra.directory_audits AND
//     entra.signins.interactive (a live blob held 8 UserLoggedIn records of 20).
//     Both are logs-only, so enabling it alongside them ships dupes.
//   - DLP.All needs the ActivityFeed.ReadDlp role this collector does not
//     declare, and had zero content live.
func TestDefaultContentTypesExcludeTheExpensiveOnes(t *testing.T) {
	for _, banned := range []o365activityclient.ContentType{
		o365activityclient.ContentGeneral,
		o365activityclient.ContentAzureActiveDirectory,
		o365activityclient.ContentDLPAll,
	} {
		if slices.Contains(defaultContentTypes, banned) {
			t.Errorf("defaultContentTypes must not include %q by default", banned)
		}
	}
	if !slices.Contains(defaultContentTypes, o365activityclient.ContentExchange) ||
		!slices.Contains(defaultContentTypes, o365activityclient.ContentSharePoint) {
		t.Errorf("defaultContentTypes = %v, want Audit.Exchange + Audit.SharePoint", defaultContentTypes)
	}
	for _, ct := range defaultContentTypes {
		if !ct.Valid() {
			t.Errorf("defaultContentTypes contains %q, which the API would reject with AF20020", ct)
		}
	}
}

// TestBodyIsHumanReadable pins the body to the same shape m365.unified_audit
// builds, so the two transports read identically in a log pane.
func TestBodyIsHumanReadable(t *testing.T) {
	_, ev, ok := mapRecord(liveRecord())
	if !ok {
		t.Fatal("mapRecord returned ok=false")
	}
	want := "Add app role assignment to service principal. by alice@contoso.com [AzureActiveDirectory]"
	if ev.Body != want {
		t.Errorf("Body = %q, want %q", ev.Body, want)
	}
}
