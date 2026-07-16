package graphactivity

import (
	"encoding/json"
	"testing"

	"github.com/rknightion/graph2otel/internal/telemetry"
)

// realRecord is a verbatim MicrosoftGraphActivityLogs record pulled from the
// live m7kni storage account on 2026-07-16, with the tenant's identifiers left
// intact (they are Rob's own) — the point of pinning a real one is that this
// shape is not documented anywhere and every field below was verified to exist
// across a 335-record sample.
const realRecord = `{
  "time": "2026-07-16T02:00:45.0159703Z",
  "resourceId": "/TENANTS/4B8C18BD-2F9F-4227-AF55-9F1061CF9C32/PROVIDERS/MICROSOFT.AADIAM",
  "operationName": "Microsoft Graph Activity",
  "operationVersion": "beta",
  "category": "MicrosoftGraphActivityLogs",
  "resultSignature": "200",
  "durationMs": "497815",
  "callerIpAddress": "172.165.241.127",
  "correlationId": "8a566ebb-77a1-4f60-9855-d4eb4019e562",
  "level": "Informational",
  "location": "UK South",
  "properties": {
    "__UDI_RequiredFields_TenantId": "4b8c18bd-2f9f-4227-af55-9f1061cf9c32",
    "timeGenerated": "2026-07-16T02:00:45.0159703Z",
    "location": "UK South",
    "requestId": "8a566ebb-77a1-4f60-9855-d4eb4019e562",
    "operationId": "8a566ebb-77a1-4f60-9855-d4eb4019e562",
    "clientRequestId": "513747a0-3cdf-4806-ada0-ac1b8c36d1d1",
    "apiVersion": "beta",
    "requestMethod": "POST",
    "responseStatusCode": 200,
    "tenantId": "4b8c18bd-2f9f-4227-af55-9f1061cf9c32",
    "durationMs": 497815,
    "responseSizeBytes": 0,
    "signInActivityId": "OPD3UZnmTkud24wRw6ATAA",
    "roles": "Device.Read.All GroupMember.Read.All User.Read.All",
    "appId": "c98e5057-edde-4666-b301-186a01b4dc58",
    "UserPrincipalObjectID": "87d30957-9758-4040-949e-9e9fe9c7cfcf",
    "scopes": "",
    "identityProvider": "https://sts.windows.net/4b8c18bd-2f9f-4227-af55-9f1061cf9c32/",
    "clientAuthMethod": "2",
    "wids": "0997a1d0-0d1d-4acb-b408-d5ca73121e90",
    "isReplay": false,
    "C_Idtyp": "app",
    "ipAddress": "172.165.241.127",
    "userAgent": "DelphiAC-Mac",
    "requestUri": "https://graph.microsoft.com/beta/users/rob@m7kni.io/informationProtection/batchClassifyAndEvaluate",
    "policyEvaluated": false,
    "servicePrincipalId": "87d30957-9758-4040-949e-9e9fe9c7cfcf",
    "tokenIssuedAt": "2026-07-16T01:04:37.0000000Z"
  },
  "tenantId": "4b8c18bd-2f9f-4227-af55-9f1061cf9c32"
}`

func decode(t *testing.T, s string) map[string]any {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal([]byte(s), &m); err != nil {
		t.Fatalf("decoding fixture: %v", err)
	}
	return m
}

func mapRealRecord(t *testing.T) telemetry.Event {
	t.Helper()
	ev, ok := mapActivity(decode(t, realRecord))
	if !ok {
		t.Fatal("mapActivity rejected a real, verbatim MicrosoftGraphActivityLogs record")
	}
	return ev
}

func TestMapActivitySetsEventNameAndTimestamp(t *testing.T) {
	ev := mapRealRecord(t)
	if ev.Name != eventName {
		t.Errorf("Name = %q, want %q", ev.Name, eventName)
	}
	if ev.Timestamp.IsZero() {
		t.Error("Timestamp is zero; the record's event time must survive, or every record lands at ingest time")
	}
	if got := ev.Timestamp.UTC().Format("2006-01-02T15:04:05"); got != "2026-07-16T02:00:45" {
		t.Errorf("Timestamp = %s, want the record's own time field", got)
	}
}

func TestMapActivityCarriesTheRequestDetail(t *testing.T) {
	attrs := mapRealRecord(t).Attrs
	for _, tc := range []struct {
		key  string
		want any
	}{
		{"request_id", "8a566ebb-77a1-4f60-9855-d4eb4019e562"},
		{"correlation_id", "8a566ebb-77a1-4f60-9855-d4eb4019e562"},
		{"client_request_id", "513747a0-3cdf-4806-ada0-ac1b8c36d1d1"},
		{"request_method", "POST"},
		{"request_uri", "https://graph.microsoft.com/beta/users/rob@m7kni.io/informationProtection/batchClassifyAndEvaluate"},
		{"api_version", "beta"},
		{"response_status_code", 200},
		{"response_size_bytes", 0},
		{"duration_ms", 497815},
		{"app_id", "c98e5057-edde-4666-b301-186a01b4dc58"},
		{"service_principal_id", "87d30957-9758-4040-949e-9e9fe9c7cfcf"},
		{"identity_type", "app"},
		{"caller_ip_address", "172.165.241.127"},
		{"user_agent", "DelphiAC-Mac"},
		{"location", "UK South"},
		{"is_replay", false},
	} {
		if got := attrs[tc.key]; got != tc.want {
			t.Errorf("attrs[%q] = %#v, want %#v", tc.key, got, tc.want)
		}
	}
}

// durationMs is a STRING at the top level ("497815") and an INT inside
// properties (497815) on the very same record. Binding to the top-level field
// yields a string where a number is wanted, silently.
func TestMapActivityTakesDurationFromPropertiesNotTheTopLevelString(t *testing.T) {
	attrs := mapRealRecord(t).Attrs
	if got, ok := attrs["duration_ms"].(int); !ok || got != 497815 {
		t.Errorf("duration_ms = %#v (%T), want int 497815 — the top-level field is a string on the same record",
			attrs["duration_ms"], attrs["duration_ms"])
	}
}

// roles/scopes/wids arrive space-separated in one string. A single blob of
// scopes is unqueryable; the list is what an investigator filters on.
func TestMapActivitySplitsSpaceSeparatedRoleLists(t *testing.T) {
	attrs := mapRealRecord(t).Attrs
	roles, ok := attrs["roles"].([]string)
	if !ok {
		t.Fatalf("roles = %#v (%T), want []string", attrs["roles"], attrs["roles"])
	}
	want := []string{"Device.Read.All", "GroupMember.Read.All", "User.Read.All"}
	if len(roles) != len(want) {
		t.Fatalf("roles = %v, want %v", roles, want)
	}
	for i := range want {
		if roles[i] != want[i] {
			t.Errorf("roles[%d] = %q, want %q", i, roles[i], want[i])
		}
	}
	if _, present := attrs["scopes"]; present {
		t.Error("scopes was empty on this record but still emitted; absent fields must not become empty attributes")
	}
}

// level is "Informational" on EVERY record, including the 500s (verified across
// a 335-record sample spanning 200/201/204/400/401/403/404/500). Deriving
// severity from it would mark a server error INFO forever.
func TestMapActivityDerivesSeverityFromStatusCodeNotLevel(t *testing.T) {
	for _, tc := range []struct {
		status int
		want   telemetry.Severity
	}{
		{200, telemetry.SeverityInfo},
		{201, telemetry.SeverityInfo},
		{204, telemetry.SeverityInfo},
		{400, telemetry.SeverityWarn},
		{401, telemetry.SeverityWarn},
		{403, telemetry.SeverityWarn},
		{404, telemetry.SeverityWarn},
		{500, telemetry.SeverityError},
	} {
		rec := decode(t, realRecord)
		props, _ := rec["properties"].(map[string]any)
		props["responseStatusCode"] = float64(tc.status)
		rec["level"] = "Informational" // as it always is, even on a 500

		ev, ok := mapActivity(rec)
		if !ok {
			t.Fatalf("status %d: mapActivity rejected the record", tc.status)
		}
		if ev.Severity != tc.want {
			t.Errorf("status %d: Severity = %v, want %v", tc.status, ev.Severity, tc.want)
		}
	}
}

func TestMapActivityBodySummarisesTheCall(t *testing.T) {
	ev := mapRealRecord(t)
	want := "POST /beta/users/rob@m7kni.io/informationProtection/batchClassifyAndEvaluate -> 200 (497815ms)"
	if ev.Body != want {
		t.Errorf("Body = %q, want %q", ev.Body, want)
	}
}

// The __UDI_RequiredFields_* keys are Microsoft's internal ingestion plumbing.
// Shipping them would cost storage on every record and mean nothing to anyone.
func TestMapActivityDropsMicrosoftInternalPlumbing(t *testing.T) {
	attrs := mapRealRecord(t).Attrs
	for key := range attrs {
		if len(key) > 5 && key[:5] == "__udi" {
			t.Errorf("attrs carries internal plumbing key %q", key)
		}
	}
	if _, ok := attrs["__UDI_RequiredFields_TenantId"]; ok {
		t.Error("attrs carries __UDI_RequiredFields_TenantId")
	}
}

// A delegated (user) call carries userId instead of servicePrincipalId. Both
// shapes are real — 290 of 335 sampled records were app, 45 were user.
func TestMapActivityHandlesADelegatedUserCall(t *testing.T) {
	rec := decode(t, realRecord)
	props, _ := rec["properties"].(map[string]any)
	delete(props, "servicePrincipalId")
	props["userId"] = "de342dab-62a6-46e6-af34-56d7e66e00cf"
	props["C_Idtyp"] = "user"

	ev, ok := mapActivity(rec)
	if !ok {
		t.Fatal("mapActivity rejected a delegated-call record")
	}
	if got := ev.Attrs["user_id"]; got != "de342dab-62a6-46e6-af34-56d7e66e00cf" {
		t.Errorf("user_id = %#v, want the delegated caller's id", got)
	}
	if _, ok := ev.Attrs["service_principal_id"]; ok {
		t.Error("service_principal_id emitted for a delegated call that has none")
	}
	if got := ev.Attrs["identity_type"]; got != "user" {
		t.Errorf("identity_type = %#v, want \"user\"", got)
	}
}

// A record with no properties object is not something we can say anything about.
// Dropping it must not stall the cursor — blobpipeline consumes rejected records.
func TestMapActivityRejectsARecordWithNoProperties(t *testing.T) {
	if _, ok := mapActivity(map[string]any{"time": "2026-07-16T02:00:45Z"}); ok {
		t.Error("mapActivity accepted a record with no properties object")
	}
}

// An unparseable time must not silently become "now": that would backdate
// nothing and misplace the record on every dashboard. Emit it with a zero
// timestamp is wrong too, so the record is still emitted but the event time is
// taken from properties.timeGenerated as the fallback the records actually carry.
func TestMapActivityFallsBackToTimeGeneratedWhenTimeIsUnparseable(t *testing.T) {
	rec := decode(t, realRecord)
	rec["time"] = "not-a-timestamp"

	ev, ok := mapActivity(rec)
	if !ok {
		t.Fatal("mapActivity rejected a record whose top-level time was unparseable")
	}
	if ev.Timestamp.IsZero() {
		t.Fatal("Timestamp is zero; properties.timeGenerated carries the same instant and should be used")
	}
	if got := ev.Timestamp.UTC().Format("2006-01-02T15:04:05"); got != "2026-07-16T02:00:45" {
		t.Errorf("Timestamp = %s, want the timeGenerated fallback", got)
	}
}
