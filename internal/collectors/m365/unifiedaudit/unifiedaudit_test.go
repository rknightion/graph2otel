package unifiedaudit

import (
	"context"
	"encoding/json"
	"log/slog"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/rknightion/graph2otel/internal/checkpoint"
	"github.com/rknightion/graph2otel/internal/collector"
	"github.com/rknightion/graph2otel/internal/collectors"
	"github.com/rknightion/graph2otel/internal/jobpipeline"
	"github.com/rknightion/graph2otel/internal/semconv"
	"github.com/rknightion/graph2otel/internal/telemetrytest"
	"github.com/rknightion/graph2otel/internal/wirecheck"
)

// TestBuildRequest asserts the window [from, to] becomes the exact JSON body
// the Purview Audit query endpoint expects: RFC3339 UTC start/end plus the
// curated Exchange/SharePoint/OneDrive/Teams recordTypeFilters include-list
// (and nothing else — DLPEndpoint etc. are deliberately excluded).
func TestBuildRequest(t *testing.T) {
	from := time.Date(2026, 7, 16, 9, 0, 0, 0, time.UTC)
	to := from.Add(30 * time.Minute)

	body, err := buildRequest(from, to)
	if err != nil {
		t.Fatalf("buildRequest: %v", err)
	}

	var got struct {
		FilterStartDateTime string   `json:"filterStartDateTime"`
		FilterEndDateTime   string   `json:"filterEndDateTime"`
		RecordTypeFilters   []string `json:"recordTypeFilters"`
	}
	if err := json.Unmarshal(body, &got); err != nil {
		t.Fatalf("unmarshal body: %v (body=%s)", err, body)
	}

	if got.FilterStartDateTime != "2026-07-16T09:00:00Z" {
		t.Errorf("filterStartDateTime = %q, want 2026-07-16T09:00:00Z", got.FilterStartDateTime)
	}
	if got.FilterEndDateTime != "2026-07-16T09:30:00Z" {
		t.Errorf("filterEndDateTime = %q, want 2026-07-16T09:30:00Z", got.FilterEndDateTime)
	}
	if !reflect.DeepEqual(got.RecordTypeFilters, recordTypeFilters) {
		t.Errorf("recordTypeFilters = %v, want %v", got.RecordTypeFilters, recordTypeFilters)
	}

	// The include-list must NOT contain the high-volume/low-signal DLPEndpoint
	// record type (#98's 3,003 FileDeleted noise storm) nor AzureActiveDirectory
	// (already covered by the sign-in/audit collectors).
	for _, rt := range recordTypeFilters {
		if rt == "dlpEndpoint" || rt == "azureActiveDirectory" {
			t.Errorf("recordTypeFilters must not include %q", rt)
		}
	}
}

// --- live fixtures ---
//
// The four records below are VERBATIM rows from a POST /security/auditLog/
// queries result set, read as graph2otel-poller against the m7kni tenant on
// 2026-07-17 `[live-measured 2026-07-17, #165]`. Nothing is trimmed, renamed or
// rounded: the GUIDs, the PUIDs, the UPN and the timestamps are what the wire
// sent.
//
// Provenance is per-fact here, which is the whole reason this package was worth
// recapturing (#165). Two facts, two different histories:
//
//   - The field NAMES and the crossed user-field semantics were ALREADY
//     live-verified before this change — 500/500 records on m7kni, #100/#151.
//     That half was never in doubt.
//   - The VALUES were not. Until #165 they were Microsoft's documentation
//     placeholders — alice@contoso.com (contoso.com is Microsoft's own example
//     domain), 203.0.113.7 (TEST-NET-3), "rec-abc-123", "obj-42", "user-guid-1".
//     A hand-written value cannot fail: it encodes the author's belief and then
//     confirms it, which is exactly how #142's `"platform": "windows"` and #153's
//     invented `riskType` key stayed green for the life of the project.
//
// Two things the capture changed, both of which a placeholder had hidden:
//
//   - `clientIp` is null on the wire. See TestTopLevelClientIPIsNull.
//   - The crossing is now demonstrated instead of asserted. `auditData` carries
//     the CLASSIC O365 schema's field names, so each record proves the crossing
//     against itself: top-level `userId` == `auditData.UserKey` and top-level
//     `userPrincipalName` == `auditData.UserId`, on 500/500 of the captured rows.
//     No cross-signal correlation needed — the wire argues with its own envelope.
//
// Known limit, stated rather than papered over: NONE of the 500 captured rows is
// of a record type in this collector's recordTypeFilters include-list. The
// window held only DLPEndpoint (468), DataInsightsRestApiAudit (18), AuditSearch
// (6), AzureActiveDirectoryStsLogon (6) and AzureActiveDirectory (2) — the
// tenant emitted no Exchange/SharePoint/Teams audit records in it, and the
// capturing query was unfiltered. So these fixtures are real rows of the query
// API's ENVELOPE (which is what mapRecord reads, and which is uniform across
// record types), but they are not rows this collector's own filter would return.
// A record type in the include-list is still unmeasured here.

// liveUserLoggedInRecord is the richest captured row: every top-level field
// mapRecord reads is populated except `clientIp`, and its two user fields carry
// clearly different values — an opaque GUID UserKey against a real UPN — which
// is what makes the crossed mapping legible.
const liveUserLoggedInRecord = `{
  "id": "d87d2977-96b6-4c65-aa44-032f7e314400",
  "createdDateTime": "2026-07-17T08:28:17Z",
  "auditLogRecordType": "AzureActiveDirectoryStsLogon",
  "operation": "UserLoggedIn",
  "organizationId": "4b8c18bd-2f9f-4227-af55-9f1061cf9c32",
  "userType": "Regular",
  "userId": "bbcfc3c5-0b93-4135-9ef9-18477a9fb504",
  "service": "AzureActiveDirectory",
  "objectId": "00000002-0000-0000-c000-000000000000",
  "userPrincipalName": "rob@m7kni.io",
  "clientIp": null,
  "administrativeUnits": [
    ""
  ],
  "auditData": {
    "@odata.type": "#microsoft.graph.security.defaultAuditData",
    "CreationTime": "2026-07-17T08:28:17Z",
    "Id": "d87d2977-96b6-4c65-aa44-032f7e314400",
    "Operation": "UserLoggedIn",
    "OrganizationId": "4b8c18bd-2f9f-4227-af55-9f1061cf9c32",
    "RecordType@odata.type": "#Int64",
    "RecordType": 15,
    "ResultStatus": "Success",
    "UserKey": "bbcfc3c5-0b93-4135-9ef9-18477a9fb504",
    "UserType@odata.type": "#Int64",
    "UserType": 0,
    "Version@odata.type": "#Int64",
    "Version": 1,
    "Workload": "AzureActiveDirectory",
    "ClientIP": "2001:db8::1038",
    "ObjectId": "00000002-0000-0000-c000-000000000000",
    "UserId": "rob@m7kni.io",
    "AzureActiveDirectoryEventType@odata.type": "#Int64",
    "AzureActiveDirectoryEventType": 1,
    "ActorContextId": "4b8c18bd-2f9f-4227-af55-9f1061cf9c32",
    "ActorIpAddress": "2001:db8::1038",
    "InterSystemsId": "7e6ddcaf-16a1-4605-a1db-31d339c6c71b",
    "IntraSystemId": "d87d2977-96b6-4c65-aa44-032f7e314400",
    "SupportTicketId": "",
    "TargetContextId": "4b8c18bd-2f9f-4227-af55-9f1061cf9c32",
    "ApplicationId": "80ccca67-54bd-44ab-8625-4b79c4dc7775",
    "ErrorNumber": "0",
    "ExtendedProperties@odata.type": "#Collection(microsoft.graph.security.defaultAuditData)",
    "ExtendedProperties": [
      {
        "Name": "ResultStatusDetail",
        "Value": "Success"
      },
      {
        "Name": "UserAgent",
        "Value": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/151.0.0.0 Safari/537.36"
      },
      {
        "Name": "RequestType",
        "Value": "OAuth2:Authorize"
      }
    ],
    "ModifiedProperties@odata.type": "#Collection(microsoft.graph.security.defaultAuditData)",
    "ModifiedProperties": [],
    "Actor@odata.type": "#Collection(microsoft.graph.security.defaultAuditData)",
    "Actor": [
      {
        "ID": "bbcfc3c5-0b93-4135-9ef9-18477a9fb504",
        "Type@odata.type": "#Int64",
        "Type": 0
      },
      {
        "ID": "rob@m7kni.io",
        "Type@odata.type": "#Int64",
        "Type": 5
      }
    ],
    "Target@odata.type": "#Collection(microsoft.graph.security.defaultAuditData)",
    "Target": [
      {
        "ID": "00000002-0000-0000-c000-000000000000",
        "Type@odata.type": "#Int64",
        "Type": 0
      }
    ],
    "DeviceProperties@odata.type": "#Collection(microsoft.graph.security.defaultAuditData)",
    "DeviceProperties": [
      {
        "Name": "OS",
        "Value": "MacOs"
      },
      {
        "Name": "BrowserType",
        "Value": "Chrome"
      },
      {
        "Name": "IsCompliant",
        "Value": "False"
      },
      {
        "Name": "IsCompliantAndManaged",
        "Value": "False"
      },
      {
        "Name": "SessionId",
        "Value": "009ce429-40c2-14b7-a6c2-73f53f4e8d22"
      }
    ]
  }
}`

// liveGUIDUserIDRecord is a captured row whose classic UserId is a bare GUID
// (the user's directory object id) and whose UserKey is a bare PUID. Both wire
// fields are non-UPN-shaped, so a reader who trusted the name
// `userPrincipalName` here gets a GUID.
const liveGUIDUserIDRecord = `{
  "id": "30e16c03-f0f0-4d99-a41d-08dee38e05ea",
  "createdDateTime": "2026-07-16T23:00:25Z",
  "auditLogRecordType": "DataInsightsRestApiAudit",
  "operation": "Search",
  "organizationId": "4b8c18bd-2f9f-4227-af55-9f1061cf9c32",
  "userType": "Regular",
  "userId": "10032005000C4421",
  "service": "SecurityComplianceCenter",
  "objectId": null,
  "userPrincipalName": "bbcfc3c5-0b93-4135-9ef9-18477a9fb504",
  "clientIp": null,
  "administrativeUnits": [
    ""
  ],
  "auditData": {
    "@odata.type": "#microsoft.graph.security.defaultAuditData",
    "CreationTime": "2026-07-16T23:00:25Z",
    "Id": "30e16c03-f0f0-4d99-a41d-08dee38e05ea",
    "Operation": "Search",
    "OrganizationId": "4b8c18bd-2f9f-4227-af55-9f1061cf9c32",
    "RecordType@odata.type": "#Int64",
    "RecordType": 52,
    "UserKey": "10032005000C4421",
    "UserType@odata.type": "#Int64",
    "UserType": 0,
    "Version@odata.type": "#Int64",
    "Version": 1,
    "Workload": "SecurityComplianceCenter",
    "UserId": "bbcfc3c5-0b93-4135-9ef9-18477a9fb504",
    "AadAppId": "80ccca67-54bd-44ab-8625-4b79c4dc7775",
    "DataType": "TrialOffer",
    "DatabaseType": "Directory",
    "RelativeUrl": "/DataInsights/DataInsightsService.svc/Find/TrialOffer?tenantid=4b8c18bd-2f9f-4227-af55-9f1061cf9c32&Filter=Sku%20eq%205c403172-39ec-4bd1-8ec3-efe39e64afb9",
    "ResultCount": "1"
  }
}`

// liveNotAvailableUserIDRecord is a captured row whose classic UserId is the
// literal sentinel "Not Available".
const liveNotAvailableUserIDRecord = `{
  "id": "9b8c866e-3596-445c-b1a3-9fc5b3553700",
  "createdDateTime": "2026-07-16T11:27:24Z",
  "auditLogRecordType": "AzureActiveDirectoryStsLogon",
  "operation": "UserLoggedIn",
  "organizationId": "4b8c18bd-2f9f-4227-af55-9f1061cf9c32",
  "userType": "System",
  "userId": "de342dab-62a6-46e6-af34-56d7e66e00cf",
  "service": "AzureActiveDirectory",
  "objectId": "797f4846-ba00-4fd7-ba43-dac1f8f63013",
  "userPrincipalName": "Not Available",
  "clientIp": null,
  "administrativeUnits": [
    ""
  ],
  "auditData": {
    "@odata.type": "#microsoft.graph.security.defaultAuditData",
    "CreationTime": "2026-07-16T11:27:24Z",
    "Id": "9b8c866e-3596-445c-b1a3-9fc5b3553700",
    "Operation": "UserLoggedIn",
    "OrganizationId": "4b8c18bd-2f9f-4227-af55-9f1061cf9c32",
    "RecordType@odata.type": "#Int64",
    "RecordType": 15,
    "ResultStatus": "Success",
    "UserKey": "de342dab-62a6-46e6-af34-56d7e66e00cf",
    "UserType@odata.type": "#Int64",
    "UserType": 4,
    "Version@odata.type": "#Int64",
    "Version": 1,
    "Workload": "AzureActiveDirectory",
    "ClientIP": "2001:db8::1038",
    "ObjectId": "797f4846-ba00-4fd7-ba43-dac1f8f63013",
    "UserId": "Not Available",
    "AzureActiveDirectoryEventType@odata.type": "#Int64",
    "AzureActiveDirectoryEventType": 1,
    "ActorContextId": "39307a09-1fd5-481d-88d7-854919f289fd",
    "ActorIpAddress": "2001:db8::1038",
    "InterSystemsId": "019f6aae-536e-78cb-9f5b-6285759e2c7a",
    "IntraSystemId": "9b8c866e-3596-445c-b1a3-9fc5b3553700",
    "SupportTicketId": "",
    "TargetContextId": "4b8c18bd-2f9f-4227-af55-9f1061cf9c32",
    "ApplicationId": "c44b4083-3bb0-49c1-b47d-974e53cbdf3c",
    "ErrorNumber": "0",
    "ExtendedProperties@odata.type": "#Collection(microsoft.graph.security.defaultAuditData)",
    "ExtendedProperties": [
      {
        "Name": "ResultStatusDetail",
        "Value": "Success"
      },
      {
        "Name": "UserAgent",
        "Value": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/151.0.0.0 Safari/537.36"
      },
      {
        "Name": "RequestType",
        "Value": "SAS:EndAuth"
      }
    ],
    "ModifiedProperties@odata.type": "#Collection(microsoft.graph.security.defaultAuditData)",
    "ModifiedProperties": [],
    "Actor@odata.type": "#Collection(microsoft.graph.security.defaultAuditData)",
    "Actor": [
      {
        "ID": "de342dab-62a6-46e6-af34-56d7e66e00cf",
        "Type@odata.type": "#Int64",
        "Type": 0
      }
    ],
    "Target@odata.type": "#Collection(microsoft.graph.security.defaultAuditData)",
    "Target": [
      {
        "ID": "797f4846-ba00-4fd7-ba43-dac1f8f63013",
        "Type@odata.type": "#Int64",
        "Type": 0
      }
    ]
  }
}`

// liveNullSentinelUserKeyRecord is a captured row whose classic UserKey is the
// literal sentinel "__NULL__" — a string, not a JSON null, so it is non-empty
// and IS emitted as user_key. Its classic UserId is a bare GUID: the object id
// of the app that ran the query (graph2otel-poller auditing its own audit
// search).
const liveNullSentinelUserKeyRecord = `{
  "id": "391be9d4-1b0f-408e-b570-d9b6e87b0cd8",
  "createdDateTime": "2026-07-16T20:46:00Z",
  "auditLogRecordType": "AuditSearch",
  "operation": "AuditSearchCompleted",
  "organizationId": "4b8c18bd-2f9f-4227-af55-9f1061cf9c32",
  "userType": "System",
  "userId": "__NULL__",
  "service": "SecurityComplianceCenter",
  "objectId": null,
  "userPrincipalName": "2c92ce28-126c-47c1-82b0-410b64502989",
  "clientIp": null,
  "administrativeUnits": [
    ""
  ],
  "auditData": {
    "@odata.type": "#microsoft.graph.security.defaultAuditData",
    "SearchJobId": "59ddb974-d5c0-4cf9-b73c-0370966eda30",
    "SearchSource": "App",
    "IsInternalServiceRequest": "false",
    "SearchFilters": "{\"SearchName\":null,\"Id\":\"59ddb974-d5c0-4cf9-b73c-0370966eda30\",\"RequestType\":\"AuditSearch\",\"StartDateUtc\":\"2026-07-16T14:12:06Z\",\"EndDateUtc\":\"2026-07-16T19:44:42Z\",\"RecordType\":null,\"RecordTypes\":[1,50,6,36,56,14,25,57],\"Workload\":null,\"Workloads\":[],\"WorkloadsToInclude\":[],\"WorkloadsToExclude\":[],\"ScopedWorkloadSearchEnabled\":true,\"Operations\":null,\"Users\":null,\"ObjectIds\":null,\"RecordIds\":[],\"UserKeys\":[],\"UserTypes\":[],\"IsGraphSearch\":true,\"ExportRequest\":null,\"IPAddresses\":null,\"SiteIds\":null,\"AssociatedAdminUnits\":null,\"FreeText\":null,\"ResultSize\":0,\"TimeoutInSeconds\":86400,\"ScopedAdminWithoutAdminUnits\":false}",
    "CompletionStatus": "Succeeded",
    "ResultsCount@odata.type": "#Int64",
    "ResultsCount": 0,
    "UserId": "2c92ce28-126c-47c1-82b0-410b64502989",
    "Id": "391be9d4-1b0f-408e-b570-d9b6e87b0cd8",
    "RecordType@odata.type": "#Int64",
    "RecordType": 295,
    "CreationTime": "2026-07-16T20:46:00Z",
    "Operation": "AuditSearchCompleted",
    "OrganizationId": "4b8c18bd-2f9f-4227-af55-9f1061cf9c32",
    "UserType@odata.type": "#Int64",
    "UserType": 4,
    "UserKey": "__NULL__",
    "Workload": "SecurityComplianceCenter",
    "Version@odata.type": "#Int64",
    "Version": 1
  }
}`

// decodeLive unmarshals a pinned live record into the untyped shape the
// jobpipeline engine hands to the mapper.
func decodeLive(t *testing.T, raw string) map[string]any {
	t.Helper()
	var rec map[string]any
	if err := json.Unmarshal([]byte(raw), &rec); err != nil {
		t.Fatalf("decode live record: %v", err)
	}
	return rec
}

// fullAuditRecord returns the richest auditLogRecord this package has: a
// verbatim live row (liveUserLoggedInRecord) carrying every field mapRecord
// reads except the always-null clientIp.
//
// Returned from a function rather than shared as a package-level var so no test
// can mutate the record another test reads.
func fullAuditRecord(t *testing.T) map[string]any {
	t.Helper()
	return decodeLive(t, liveUserLoggedInRecord)
}

// TestMap maps the richest captured auditLogRecord to its dedupe id and
// per-record log attributes, and confirms per-entity detail (the classic UserId,
// object id) lands as LOG attributes.
func TestMap(t *testing.T) {
	rec := fullAuditRecord(t)

	id, ev := mapRecord(rec)
	if id != "d87d2977-96b6-4c65-aa44-032f7e314400" {
		t.Fatalf("dedupe id = %q, want d87d2977-96b6-4c65-aa44-032f7e314400", id)
	}
	if ev.Name != eventName {
		t.Errorf("event name = %q, want %q", ev.Name, eventName)
	}

	want := map[string]any{
		"id":          "d87d2977-96b6-4c65-aa44-032f7e314400",
		"operation":   "UserLoggedIn",
		"record_type": "AzureActiveDirectoryStsLogon",
		"service":     "AzureActiveDirectory",
		"user_type":   "Regular",
		// The two wire field names are CROSSED relative to the attributes, and
		// that is deliberate — each attribute is named for what it contains, not
		// for the field it came from. See TestTopLevelUserIDIsTheClassicUserKey.
		//
		//	wire userId            -> user_key (classic UserKey)
		//	wire userPrincipalName -> user_id  (classic UserId)
		"user_key":      "bbcfc3c5-0b93-4135-9ef9-18477a9fb504",
		"user_id":       "rob@m7kni.io",
		"object_id":     "00000002-0000-0000-c000-000000000000",
		"workload":      "AzureActiveDirectory",
		"result_status": "Success",
		// From auditData.ClientIP, not the envelope's (always-null) clientIp —
		// see TestTopLevelClientIPIsNull (#170).
		"client_ip": "2001:db8::1038",
	}
	for k, v := range want {
		if ev.Attrs[k] != v {
			t.Errorf("attr %q = %v, want %v", k, ev.Attrs[k], v)
		}
	}
}

// TestTopLevelUserIDIsTheClassicUserKey is the semantic guard for #151, and the
// single most counter-intuitive assertion in this package: the two user fields
// are CROSSED between wire and attribute.
//
//	wire userId            -> attr user_key   (it holds the classic UserKey)
//	wire userPrincipalName -> attr user_id    (it holds the classic UserId)
//
// The query API's top-level `userId` field is the classic O365 schema's UserKey,
// NOT the classic UserId. Its name is a Microsoft misnomer. Live-verified on
// m7kni, 500/500 records over the same tenant and window as the m365.activity
// twin (2026-07-17, #100/#151):
//
//	queryAPI.userId            == classic UserKey : 500/500
//	queryAPI.userPrincipalName == classic UserId  : 500/500  (byte-identical)
//
// Since #165 the fixture DEMONSTRATES that rather than restating it. `auditData`
// carries the classic schema's own field names, so the record contradicts its
// own envelope in a single object, and the first two assertions below read the
// proof straight off the wire: the envelope's `userId` is `auditData.UserKey`;
// the envelope's `userPrincipalName` is `auditData.UserId`.
//
// Taking the wire name at face value is exactly what produced #151: `user_id`
// meant UserKey here and UserId on m365.activity — one attribute, two meanings,
// with nothing on the record saying which. The mapper must translate each field
// to what it CONTAINS, not to what Microsoft calls it. The crossover looks like a
// bug on every reading; it is the fix.
//
// `user_principal_name` is the name `user_id` used to carry here, and it must not
// return: the value is the classic UserId, which is not always UPN-shaped — see
// TestUserIDIsNotAlwaysUPNShaped, which drives three captured rows where it is
// not.
func TestTopLevelUserIDIsTheClassicUserKey(t *testing.T) {
	rec := fullAuditRecord(t)

	// The wire's own proof, read out of the same record: auditData speaks the
	// CLASSIC schema, the envelope speaks Microsoft's misnomer. If a future
	// fixture ever loses this property it stops being evidence for the crossing,
	// so fail loudly rather than assert the mapping against nothing.
	data, ok := rec["auditData"].(map[string]any)
	if !ok {
		t.Fatal("live record has no auditData object — the fixture can no longer prove the crossing")
	}
	if got, want := rec["userId"], data["UserKey"]; got != want {
		t.Fatalf("fixture: envelope userId = %v but auditData.UserKey = %v — pick a fixture where they match, or the crossing is unproven", got, want)
	}
	if got, want := rec["userPrincipalName"], data["UserId"]; got != want {
		t.Fatalf("fixture: envelope userPrincipalName = %v but auditData.UserId = %v — pick a fixture where they match, or the crossing is unproven", got, want)
	}

	_, ev := mapRecord(rec)

	if got := ev.Attrs["user_key"]; got != "bbcfc3c5-0b93-4135-9ef9-18477a9fb504" {
		t.Errorf("user_key = %v, want %q — the query API's top-level userId IS the classic UserKey (live 500/500, #151; and auditData.UserKey on this very record says so) and must be emitted under the name of what it contains, NOT as user_id",
			got, "bbcfc3c5-0b93-4135-9ef9-18477a9fb504")
	}
	if got := ev.Attrs["user_id"]; got != "rob@m7kni.io" {
		t.Errorf("user_id = %v, want %q — it must come from the wire's userPrincipalName, which IS the classic UserId (live 500/500, byte-identical, #151; and auditData.UserId on this very record says so). Sourcing user_id from the wire's `userId` field instead would make it mean UserKey here and UserId on m365.activity: one attribute, two meanings.",
			got, "rob@m7kni.io")
	}
	if got, present := ev.Attrs["user_principal_name"]; present {
		t.Errorf("user_principal_name = %v, want the attribute ABSENT — it was renamed to user_id because the value is the classic UserId, which is not always UPN-shaped (see TestUserIDIsNotAlwaysUPNShaped). Emitting both would rebuild #151: two attributes set from one variable, identical by construction.", got)
	}
}

// TestUserIDIsNotAlwaysUPNShaped drives the captured rows where the classic
// UserId is NOT an email address, so the "usually a UPN, sometimes anything
// else" claim in docs/signals.md is exercised rather than merely written down.
//
// It is the reason `user_principal_name` was renamed to `user_id` (#163): the
// old name promised a shape the value does not have. 13 of the 500 captured rows
// (2.6%) carry a non-UPN-shaped classic UserId — a bare GUID (10) or the literal
// "Not Available" (3). #151's wider measurement puts it around 9%; whichever
// figure holds for a given tenant and window, the shape is not guaranteed, and
// the mapper must emit the value verbatim with no shape gate rather than
// normalizing or dropping what it does not recognize.
//
// `ServicePrincipal_<guid>` and display-name forms are documented in
// docs/signals.md from #151's measurement but do not appear in this capture, so
// they are not fixtured here — a shape nobody has a row for does not get an
// invented row.
func TestUserIDIsNotAlwaysUPNShaped(t *testing.T) {
	cases := []struct {
		name        string
		raw         string
		wantUserKey string
		wantUserID  string
	}{
		{
			// Both fields non-UPN-shaped: the classic UserId is the user's
			// directory object id, the UserKey a bare PUID.
			name:        "classic UserId is a bare GUID",
			raw:         liveGUIDUserIDRecord,
			wantUserKey: "10032005000C4421",
			wantUserID:  "bbcfc3c5-0b93-4135-9ef9-18477a9fb504",
		},
		{
			name:        "classic UserId is the sentinel Not Available",
			raw:         liveNotAvailableUserIDRecord,
			wantUserKey: "de342dab-62a6-46e6-af34-56d7e66e00cf",
			wantUserID:  "Not Available",
		},
		{
			// The sentinel is on the OTHER field here: "__NULL__" is a string,
			// not a JSON null, so setStr sees a non-empty value and emits it.
			name:        "classic UserKey is the sentinel __NULL__",
			raw:         liveNullSentinelUserKeyRecord,
			wantUserKey: "__NULL__",
			wantUserID:  "2c92ce28-126c-47c1-82b0-410b64502989",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rec := decodeLive(t, tc.raw)

			// Same self-proof as TestTopLevelUserIDIsTheClassicUserKey: the
			// crossing holds on these rows too, which is what makes them
			// evidence rather than decoration.
			data, ok := rec["auditData"].(map[string]any)
			if !ok {
				t.Fatal("live record has no auditData object")
			}
			if got, want := rec["userId"], data["UserKey"]; got != want {
				t.Fatalf("fixture: envelope userId = %v but auditData.UserKey = %v", got, want)
			}
			if got, want := rec["userPrincipalName"], data["UserId"]; got != want {
				t.Fatalf("fixture: envelope userPrincipalName = %v but auditData.UserId = %v", got, want)
			}

			_, ev := mapRecord(rec)

			if got := ev.Attrs["user_key"]; got != tc.wantUserKey {
				t.Errorf("user_key = %v, want %q", got, tc.wantUserKey)
			}
			if got := ev.Attrs["user_id"]; got != tc.wantUserID {
				t.Errorf("user_id = %v, want %q — emit the classic UserId verbatim; it is not always UPN-shaped and must not be shape-gated, normalized or dropped", got, tc.wantUserID)
			}
			if strings.Contains(tc.wantUserID, "@") {
				t.Fatalf("test bug: %q is UPN-shaped, so this case proves nothing", tc.wantUserID)
			}
		})
	}
}

// TestTopLevelClientIPIsNull pins a live fact the old hand-written fixture had
// hidden behind a plausible placeholder: the query API's ENVELOPE does not
// carry the client IP. `clientIp` was null on 500/500 captured rows, while
// `auditData.ClientIP` held a real address on 474 of them (#170). The
// placeholder said otherwise: it set `"clientIp": "203.0.113.7"` (TEST-NET-3,
// a documentation address) at the top level, which made the old
// envelope-reading mapper line look exercised and its attribute look like a
// shipped signal. Same shape of defect as #153's invented `riskType` key and
// #142's `"platform": "windows"`.
//
// mapRecord now reads auditData.ClientIP instead (#170), so this test asserts
// both halves per captured record: the envelope's clientIp stays null (a
// non-null value here would mean the fixture was edited), and client_ip is
// populated from auditData.ClientIP when that field is present there, and
// absent when it is not — two of the four captures have it (both AAD
// sign-ins), two don't (DataInsights, AuditSearch).
//
// Scope of the claim, deliberately narrow: all four fixtures below are record
// types this collector's recordTypeFilters EXCLUDE (the 2026-07-17 capture's
// window held no Exchange/SharePoint/Teams audit records). Whether an
// exchangeItemAggregated or sharePointFileOperation row populates
// auditData.ClientIP the same way is UNMEASURED here —
// TestClientIPFromAuditDataReachesEmitterForInScopeRecord exercises the fixed
// path on an in-scope record type instead, with a synthetic (not live) address.
func TestTopLevelClientIPIsNull(t *testing.T) {
	cases := []struct {
		name         string
		raw          string
		wantClientIP string // "" means the attribute must be absent
	}{
		{"AAD sign-in (rich record): auditData.ClientIP present", liveUserLoggedInRecord, "2001:db8::1038"},
		{"DataInsights search: auditData has no ClientIP", liveGUIDUserIDRecord, ""},
		{"AAD sign-in (Not Available user): auditData.ClientIP present", liveNotAvailableUserIDRecord, "2001:db8::1038"},
		{"AuditSearch: auditData has no ClientIP", liveNullSentinelUserKeyRecord, ""},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rec := decodeLive(t, tc.raw)

			if got, present := rec["clientIp"]; present && got != nil {
				t.Fatalf("captured record %v has clientIp = %v — live it was null on 500/500; a non-null value here means the fixture was edited", rec["id"], got)
			}

			_, ev := mapRecord(rec)
			got, present := ev.Attrs["client_ip"]
			if tc.wantClientIP == "" {
				if present {
					t.Errorf("client_ip = %v, want the attribute ABSENT — this record's auditData carries no ClientIP", got)
				}
				return
			}
			if !present || got != tc.wantClientIP {
				t.Errorf("client_ip = %v (present=%v), want %q — must come from auditData.ClientIP; the envelope's clientIp is always null", got, present, tc.wantClientIP)
			}
		})
	}
}

// syntheticInScopeClientIPRecord is a hand-built minimal envelope of a record
// type THIS COLLECTOR'S recordTypeFilters actually returns
// (sharePointFileOperation), carrying an auditData.ClientIP. None of the four
// live captures above are an in-scope record type (see the package-level
// comment above them), so nothing above proves the #170 fix works on a record
// this collector would really be asked to map — this fixture closes that gap.
// The address is RFC 5737 TEST-NET-2 documentation space, not a real one: no
// live capture of an in-scope record type with clientIp populated exists yet.
const syntheticInScopeClientIPRecord = `{
  "id": "rec-sp-clientip-1",
  "createdDateTime": "2026-07-16T09:25:00Z",
  "auditLogRecordType": "SharePointFileOperation",
  "operation": "FileAccessed",
  "service": "SharePoint",
  "auditData": {
    "Workload": "SharePoint",
    "ResultStatus": "Success",
    "ClientIP": "198.51.100.42"
  }
}`

// TestClientIPFromAuditDataReachesEmitterForInScopeRecord drives
// syntheticInScopeClientIPRecord through the real jobpipeline engine into an
// emitter (create -> poll -> page -> emit), the same shape of proof
// TestCollectorEmitsFullRecordEndToEnd gives the user-field crossing, but for
// an in-scope record type — the AAD sign-in captures the other client_ip
// tests use are all types this collector's recordTypeFilters would never
// return.
func TestClientIPFromAuditDataReachesEmitterForInScopeRecord(t *testing.T) {
	rec := telemetrytest.New()
	fake := &fakeJobClient{
		statuses: []string{jobpipeline.StatusSucceeded},
		records:  []map[string]any{decodeLive(t, syntheticInScopeClientIPRecord)},
	}
	c := newCollector(deps(t, fake))

	from := time.Date(2026, 7, 16, 9, 0, 0, 0, time.UTC)
	to := time.Date(2026, 7, 16, 9, 30, 0, 0, time.UTC)
	if _, err := c.CollectWindow(context.Background(), from, to, rec.Emitter()); err != nil {
		t.Fatalf("CollectWindow: %v", err)
	}

	logs := rec.LogRecords()
	if len(logs) != 1 {
		t.Fatalf("emitted %d records, want 1", len(logs))
	}
	got := logs[0]
	if got.Attrs["record_type"] != "SharePointFileOperation" {
		t.Fatalf("record_type = %v, want an in-scope type (SharePointFileOperation) — this test exists to prove the fix on a type the collector actually returns", got.Attrs["record_type"])
	}
	if got.Attrs["client_ip"] != "198.51.100.42" {
		t.Errorf("client_ip = %v, want 198.51.100.42 — must reach the emitter from auditData.ClientIP for an in-scope record type", got.Attrs["client_ip"])
	}
}

// TestMapOmitsAbsentAttrs asserts a sparse record omits absent attributes rather
// than emitting empty strings.
//
// This record is deliberately SYNTHETIC and claims nothing about the wire: it is
// a hand-built minimal envelope, used because every one of the 500 captured rows
// carries both user fields, so no live row exercises their absence. It tests
// mapRecord's omission behavior, not Microsoft's record shape. (The live rows
// DO cover two real absences — see TestTopLevelClientIPIsNull for clientIp, and
// liveGUIDUserIDRecord's null objectId.)
func TestMapOmitsAbsentAttrs(t *testing.T) {
	rec := map[string]any{
		"id":                 "rec-sp-1",
		"createdDateTime":    "2026-07-16T09:20:00Z",
		"auditLogRecordType": "SharePointFileOperation",
		"operation":          "FileAccessed",
		"service":            "SharePoint",
	}
	_, ev := mapRecord(rec)
	for _, k := range []string{"user_id", "client_ip", "object_id", "user_key"} {
		if _, ok := ev.Attrs[k]; ok {
			t.Errorf("absent field produced attr %q = %v", k, ev.Attrs[k])
		}
	}
	if ev.Attrs["record_type"] != "SharePointFileOperation" {
		t.Errorf("record_type = %v, want SharePointFileOperation", ev.Attrs["record_type"])
	}

	// A live row proves the same omission for object_id: the envelope's objectId
	// is null on the DataInsights rows.
	_, live := mapRecord(decodeLive(t, liveGUIDUserIDRecord))
	if got, present := live.Attrs["object_id"]; present {
		t.Errorf("object_id = %v, want ABSENT — the captured row's objectId is null", got)
	}
}

// --- quarantine records (#233) ---

// liveQuarantineReleaseRecord is a VERBATIM row from a POST /security/auditLog/
// queries result set, read as graph2otel-poller against the m7kni tenant on
// 2026-07-23 `[live-measured 2026-07-23, #233]`. Nothing is trimmed, renamed or
// rounded. It is the first fixture in this package of a record type the
// include-list actually selects (see the "Known limit" note above the 2026-07-17
// captures — none of those four is an in-scope type).
//
// The load-bearing wire fact, and the reason no code here switches on a typed
// subtype: `auditData.@odata.type` is `#microsoft.graph.security.
// defaultAuditData` — the GENERIC subtype — even though Graph's beta metadata
// declares a dedicated `quarantineAuditRecord` type. The typed subtype is NOT
// what the wire returns, so a mapper that dispatched on it would never fire on a
// real record. Wire over docs `[live-measured 2026-07-23, #233]`.
//
// Second fact worth stating: this record's `userPrincipalName` is the string
// "System release", not a UPN. That is the same reality the `user_id` attribute
// comment covers (the classic UserId is UPN-shaped on only ~91% of live
// records), so nothing below shape-gates it.
const liveQuarantineReleaseRecord = `{
  "id": "d63edfc3-4460-4da0-031c-08dee7de0398",
  "createdDateTime": "2026-07-22T10:43:06Z",
  "auditLogRecordType": "Quarantine",
  "operation": "QuarantineReleaseMessage",
  "organizationId": "4b8c18bd-2f9f-4227-af55-9f1061cf9c32",
  "userType": "System",
  "userId": "Quarantine",
  "service": "Quarantine",
  "objectId": null,
  "userPrincipalName": "System release",
  "clientIp": null,
  "administrativeUnits": [
    ""
  ],
  "auditData": {
    "@odata.type": "#microsoft.graph.security.defaultAuditData",
    "CreationTime": "2026-07-22T10:43:06Z",
    "Id": "d63edfc3-4460-4da0-031c-08dee7de0398",
    "Operation": "QuarantineReleaseMessage",
    "OrganizationId": "4b8c18bd-2f9f-4227-af55-9f1061cf9c32",
    "RecordType@odata.type": "#Int64",
    "RecordType": 65,
    "ResultStatus": "Successful",
    "UserKey": "Quarantine",
    "UserType@odata.type": "#Int64",
    "UserType": 4,
    "Version@odata.type": "#Int64",
    "Version": 1,
    "Workload": "Quarantine",
    "UserId": "System release",
    "NetworkMessageId": "80aa9dda-c565-45a0-6133-08dee7cf4a7a",
    "ReleaseTo": "rob@m7kni.io",
    "RequestType@odata.type": "#Int64",
    "RequestType": 2
  }
}`

// TestQuarantineRecordTypesAreIncluded asserts the four quarantine record types
// are in the curated include-list AND that buildRequest serializes them into the
// request body — the filter is what makes the records arrive at all, so a
// constant that never reaches the wire is no coverage.
//
// All four were live-verified ACCEPTED by the API on m7kni on 2026-07-23: a
// query carrying all four in recordTypeFilters returned HTTP 201 and completed,
// returning real records `[live-measured 2026-07-23, #233]`.
func TestQuarantineRecordTypesAreIncluded(t *testing.T) {
	want := []string{"quarantine", "quarantineMetadata", "teamsQuarantineMetadata", "updateQuarantineMetadata"}

	inFilters := make(map[string]bool, len(recordTypeFilters))
	for _, rt := range recordTypeFilters {
		inFilters[rt] = true
	}
	for _, rt := range want {
		if !inFilters[rt] {
			t.Errorf("recordTypeFilters is missing %q — without it the quarantine audit trail (message held/released/previewed/deleted, and quarantine policy changes) is never returned (#233)", rt)
		}
	}

	// The include-list is only coverage if it reaches the create body.
	body, err := buildRequest(time.Date(2026, 7, 22, 10, 0, 0, 0, time.UTC), time.Date(2026, 7, 22, 11, 0, 0, 0, time.UTC))
	if err != nil {
		t.Fatalf("buildRequest: %v", err)
	}
	var got struct {
		RecordTypeFilters []string `json:"recordTypeFilters"`
	}
	if err := json.Unmarshal(body, &got); err != nil {
		t.Fatalf("unmarshal body: %v (body=%s)", err, body)
	}
	serialized := make(map[string]bool, len(got.RecordTypeFilters))
	for _, rt := range got.RecordTypeFilters {
		serialized[rt] = true
	}
	for _, rt := range want {
		if !serialized[rt] {
			t.Errorf("create body recordTypeFilters is missing %q (got %v)", rt, got.RecordTypeFilters)
		}
	}
}

// TestMapQuarantineRecord maps the pinned live quarantine row and asserts the
// three quarantine-specific fields the generic mapper used to drop, alongside
// the generic envelope fields that must keep working on this record type.
//
// network_message_id is the point: it is the join key from a quarantine audit
// record to defender.email / defender.email_post_delivery / defender.email_url,
// all of which key on the same id. Without it a release event cannot be tied to
// the message it released.
func TestMapQuarantineRecord(t *testing.T) {
	rec := decodeLive(t, liveQuarantineReleaseRecord)

	id, ev := mapRecord(rec)
	if id != "d63edfc3-4460-4da0-031c-08dee7de0398" {
		t.Fatalf("dedupe id = %q, want d63edfc3-4460-4da0-031c-08dee7de0398", id)
	}
	if ev.Name != eventName {
		t.Errorf("event name = %q, want %q", ev.Name, eventName)
	}

	want := map[string]any{
		// The quarantine payload (#233).
		"network_message_id": "80aa9dda-c565-45a0-6133-08dee7cf4a7a",
		"release_to":         "rob@m7kni.io",
		// RequestType is an UNDOCUMENTED integer enum — Microsoft publishes no
		// member list — so it is emitted as the raw number, not a guessed label.
		// telemetry.SetNum stores the JSON number as a float64.
		"request_type": float64(2),
		// The generic envelope must keep working on this record type.
		"id":          "d63edfc3-4460-4da0-031c-08dee7de0398",
		"operation":   "QuarantineReleaseMessage",
		"record_type": "Quarantine",
		"service":     "Quarantine",
		"user_type":   "System",
		// Crossed as always: wire userId -> user_key, wire userPrincipalName ->
		// user_id. Here the classic UserId is "System release", which is not
		// UPN-shaped and must not be shape-gated.
		"user_key":      "Quarantine",
		"user_id":       "System release",
		"workload":      "Quarantine",
		"result_status": "Successful",
	}
	for k, v := range want {
		if ev.Attrs[k] != v {
			t.Errorf("attr %q = %v (%T), want %v (%T)", k, ev.Attrs[k], ev.Attrs[k], v, v)
		}
	}

	// objectId is null on this row, and clientIp is null as ever.
	for _, k := range []string{"object_id", "client_ip"} {
		if got, present := ev.Attrs[k]; present {
			t.Errorf("attr %q = %v, want ABSENT on this record", k, got)
		}
	}
}

// TestQuarantineAttrsAbsentOnNonQuarantineRecords asserts the three new
// attributes are stamped only where the wire carries them: the fields live in
// auditData on quarantine records and nowhere else, and telemetry.SetStr/SetNum
// omit an absent value, so no record-type branch is needed in mapRecord.
//
// liveUserLoggedInRecord is the sharpest of the four: its auditData DOES contain
// the string "RequestType" — as the Name of an ExtendedProperties entry, not as
// a top-level auditData key. A mapper that went looking for the name rather than
// reading the field would stamp "OAuth2:Authorize" here.
func TestQuarantineAttrsAbsentOnNonQuarantineRecords(t *testing.T) {
	cases := []struct {
		name string
		raw  string
	}{
		{"AAD sign-in (has a RequestType inside ExtendedProperties)", liveUserLoggedInRecord},
		{"DataInsights search", liveGUIDUserIDRecord},
		{"AAD sign-in (Not Available user)", liveNotAvailableUserIDRecord},
		{"AuditSearch", liveNullSentinelUserKeyRecord},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, ev := mapRecord(decodeLive(t, tc.raw))
			for _, k := range []string{"network_message_id", "release_to", "request_type"} {
				if got, present := ev.Attrs[k]; present {
					t.Errorf("attr %q = %v, want ABSENT — it is a quarantine-record field and this row carries none", k, got)
				}
			}
		})
	}
}

// TestQuarantineFieldsReachEmitterEndToEnd drives the pinned live quarantine row
// through the real jobpipeline engine into an emitter (create -> poll -> page ->
// emit), so the three new attribute keys are in what this package's tests EMIT
// and therefore in testdata/signals.json.
//
// Same reason TestCollectorEmitsFullRecordEndToEnd exists (#164): the signal
// gate records the union of emitted attributes, and a golden that has never seen
// an attribute cannot notice that attribute drifting. A mapper-only test does
// not reach the emitter and so contributes nothing to the golden.
func TestQuarantineFieldsReachEmitterEndToEnd(t *testing.T) {
	rec := telemetrytest.New()
	fake := &fakeJobClient{
		statuses: []string{jobpipeline.StatusSucceeded},
		records:  []map[string]any{decodeLive(t, liveQuarantineReleaseRecord)},
	}
	c := newCollector(deps(t, fake))

	// The window brackets the captured record's real createdDateTime
	// (2026-07-22T10:43:06Z).
	from := time.Date(2026, 7, 22, 10, 0, 0, 0, time.UTC)
	to := time.Date(2026, 7, 22, 11, 0, 0, 0, time.UTC)
	if _, err := c.CollectWindow(context.Background(), from, to, rec.Emitter()); err != nil {
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
	if got.Attrs["record_type"] != "Quarantine" {
		t.Fatalf("record_type = %q, want Quarantine — this test exists to prove the quarantine payload on a quarantine record", got.Attrs["record_type"])
	}

	// LogRecord.Attrs is flattened to strings, so the raw RequestType number
	// arrives as "2" here rather than float64(2) — the mapper-level assertion in
	// TestMapQuarantineRecord is the one that pins the type.
	wantAttrs := map[string]string{
		"network_message_id": "80aa9dda-c565-45a0-6133-08dee7cf4a7a",
		"release_to":         "rob@m7kni.io",
		"request_type":       "2",
		"operation":          "QuarantineReleaseMessage",
		"user_key":           "Quarantine",
		"user_id":            "System release",
		"workload":           "Quarantine",
		"result_status":      "Successful",
	}
	for k, want := range wantAttrs {
		if v := got.Attrs[k]; v != want {
			t.Errorf("emitted attr %q = %q, want %q", k, v, want)
		}
	}
}

// --- factory + end-to-end wiring ---

func deps(t *testing.T, client jobpipeline.JobClient) collectors.WindowDeps {
	t.Helper()
	return collectors.WindowDeps{
		TenantID:  "t1",
		JobClient: client,
		Store:     checkpoint.NewStore(t.TempDir()),
		// Discarded, not defaulted: the wire-assumption tests below deliberately
		// trip the watchdog, and its one-shot WARN would otherwise print a wall of
		// alarming text on a passing run (#234).
		Logger: slog.New(slog.DiscardHandler),
	}
}

// TestFactoryWiresJobCollector asserts newCollector returns a JobCollector
// carrying deps.JobClient + a checkpoint store, the right name/experimental
// flag, and the declared scope.
func TestFactoryWiresJobCollector(t *testing.T) {
	fake := &fakeJobClient{}
	c := newCollector(deps(t, fake))

	if c.Name() != name {
		t.Errorf("Name() = %q, want %q", c.Name(), name)
	}
	if !c.Experimental() {
		t.Error("collector must be Experimental (opt-in)")
	}
	if c.Client != jobpipeline.JobClient(fake) {
		t.Error("collector not wired with deps.JobClient")
	}
	if c.Store == nil {
		t.Error("collector not wired with a checkpoint store")
	}
	perms := c.RequiredPermissions()
	if len(perms) != 1 || perms[0] != "AuditLogsQuery.Read.All" {
		t.Errorf("RequiredPermissions() = %v, want [AuditLogsQuery.Read.All]", perms)
	}
}

// TestCollectWindowEndToEnd drives a full submit→poll→page→emit cycle through
// the real jobpipeline engine against a fake JobClient, proving the QueryConfig
// is wired correctly (the create body carries the filters, records are emitted
// as logs, checkpoint advances).
//
// The two records are deliberately SYNTHETIC scaffolding and assert nothing
// about record shape: this test is about the engine emitting one log per record
// and the create body carrying the filters, so the records are minimal on
// purpose. Their record types are include-list members that the 2026-07-17
// capture happened not to contain — plausible, unmeasured, and load-bearing for
// nothing here. TestCollectorEmitsFullRecordEndToEnd is the test that drives a
// real row.
func TestCollectWindowEndToEnd(t *testing.T) {
	rec := telemetrytest.New()
	fake := &fakeJobClient{
		statuses: []string{jobpipeline.StatusSucceeded},
		records: []map[string]any{
			{"id": "rec-1", "createdDateTime": "2026-07-16T09:05:00Z", "auditLogRecordType": "MicrosoftTeams", "operation": "MessageSent", "service": "MicrosoftTeams"},
			{"id": "rec-2", "createdDateTime": "2026-07-16T09:06:00Z", "auditLogRecordType": "SharePointSharingOperation", "operation": "SharingSet", "service": "SharePoint"},
		},
	}
	c := newCollector(deps(t, fake))

	from := time.Date(2026, 7, 16, 8, 0, 0, 0, time.UTC)
	to := time.Date(2026, 7, 16, 9, 30, 0, 0, time.UTC)
	if _, err := c.CollectWindow(context.Background(), from, to, rec.Emitter()); err != nil {
		t.Fatalf("CollectWindow: %v", err)
	}

	logs := rec.LogRecords()
	if len(logs) != 2 {
		t.Fatalf("emitted %d logs, want 2", len(logs))
	}
	// The create body must carry our recordTypeFilters.
	if len(fake.createBodies) == 0 {
		t.Fatal("no create body captured")
	}
	var parsed struct {
		RecordTypeFilters []string `json:"recordTypeFilters"`
	}
	if err := json.Unmarshal(fake.createBodies[0], &parsed); err != nil {
		t.Fatalf("unmarshal create body: %v", err)
	}
	if !reflect.DeepEqual(parsed.RecordTypeFilters, recordTypeFilters) {
		t.Errorf("create body recordTypeFilters = %v, want %v", parsed.RecordTypeFilters, recordTypeFilters)
	}
	// The audit query API is beta-only on this tenant (live: POST /v1.0/... -> 404,
	// POST /beta/... -> 201). The create URL must target the beta service root.
	if got := fake.createURLs[0]; !strings.HasPrefix(got, "https://graph.microsoft.com/beta/security/auditLog/queries") {
		t.Errorf("create URL = %q, want the /beta service root (audit query API is beta-only)", got)
	}
}

// TestCollectorEmitsFullRecordEndToEnd drives the richest record this package
// has (fullAuditRecord — a verbatim live row since #165) through the real
// jobpipeline engine into an emitter, rather than calling mapRecord directly the
// way TestMap does.
//
// It exists for #164, and the golden is the point. The signal gate
// (internal/signalcapture) records the union of what a package's tests EMIT, so
// the only records it ever saw here were TestCollectWindowEndToEnd's two
// four-field synthetic ones. testdata/signals.json therefore claimed
// [id, ingest_transport, operation, record_type, service] — and NO user
// attribute at all — for a collector that ships eleven.
//
// That understatement had a live cost, not a theoretical one: the
// user_principal_name -> user_id rename (#163, fa3395f) could not have tripped
// this package's drift gate, because no user attribute was in its golden to
// drift. m365/activity — same m365.audit event name, same signal, opposite
// coverage — caught it. A golden that has never seen an attribute cannot notice
// that attribute changing.
//
// So the assertions below are deliberately weighted to user_key/user_id: they
// are what #164 requires the golden to cover, and they are the pair the rename
// moved.
func TestCollectorEmitsFullRecordEndToEnd(t *testing.T) {
	rec := telemetrytest.New()
	fake := &fakeJobClient{
		statuses: []string{jobpipeline.StatusSucceeded},
		records:  []map[string]any{fullAuditRecord(t)},
	}
	c := newCollector(deps(t, fake))

	// The window brackets the captured record's real createdDateTime
	// (2026-07-17T08:28:17Z) — the fixture's timestamp is the wire's, so the
	// window moves to it rather than the record being re-dated to the window.
	from := time.Date(2026, 7, 17, 8, 0, 0, 0, time.UTC)
	to := time.Date(2026, 7, 17, 9, 0, 0, 0, time.UTC)
	if _, err := c.CollectWindow(context.Background(), from, to, rec.Emitter()); err != nil {
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

	// Checked at the EMITTER, not the mapper: every attribute must survive the
	// whole create -> poll -> page -> emit path, which is the other half of what
	// this test buys over TestMap.
	//
	// The user pair stays crossed here exactly as it is in mapRecord — wire
	// userId -> user_key, wire userPrincipalName -> user_id. See
	// TestTopLevelUserIDIsTheClassicUserKey for why that is the fix and not a bug.
	wantAttrs := map[string]string{
		"id":            "d87d2977-96b6-4c65-aa44-032f7e314400",
		"operation":     "UserLoggedIn",
		"record_type":   "AzureActiveDirectoryStsLogon",
		"service":       "AzureActiveDirectory",
		"user_type":     "Regular",
		"user_key":      "bbcfc3c5-0b93-4135-9ef9-18477a9fb504",
		"user_id":       "rob@m7kni.io",
		"object_id":     "00000002-0000-0000-c000-000000000000",
		"workload":      "AzureActiveDirectory",
		"result_status": "Success",
		// From auditData.ClientIP; the envelope's own clientIp is always
		// null (#170) and must not be what reaches the emitter.
		"client_ip": "2001:db8::1038",
	}
	for k, want := range wantAttrs {
		if v := got.Attrs[k]; v != want {
			t.Errorf("emitted attr %q = %q, want %q", k, v, want)
		}
	}

	// The renamed attribute must not come back at the emitter either — the
	// mapper-level guard in TestTopLevelUserIDIsTheClassicUserKey cannot see a
	// re-add that happens further down the path.
	if v, present := got.Attrs["user_principal_name"]; present {
		t.Errorf("emitted attr user_principal_name = %q, want it ABSENT — it was renamed to user_id (#163)", v)
	}
}

// --- fake JobClient ---

type fakeJobClient struct {
	createBodies [][]byte
	createURLs   []string
	statuses     []string
	statusCalls  int
	records      []map[string]any // returned on the first records page regardless of URL
	served       bool
}

func (f *fakeJobClient) CreateQuery(_ context.Context, createURL string, body []byte) (string, string, error) {
	f.createBodies = append(f.createBodies, body)
	f.createURLs = append(f.createURLs, createURL)
	return "query-1", jobpipeline.StatusNotStarted, nil
}

func (f *fakeJobClient) QueryStatus(_ context.Context, _ string) (string, error) {
	i := f.statusCalls
	f.statusCalls++
	if i < len(f.statuses) {
		return f.statuses[i], nil
	}
	return jobpipeline.StatusSucceeded, nil
}

func (f *fakeJobClient) FetchRecordsPage(_ context.Context, _ string) ([]map[string]any, string, error) {
	if f.served {
		return nil, "", nil
	}
	f.served = true
	return f.records, "", nil
}

// Compile-time: the fake satisfies the engine seam.
var _ jobpipeline.JobClient = (*fakeJobClient)(nil)

// Compile-time: the collector satisfies the window seam.
var _ collector.WindowCollector = (*collectorImpl)(nil)

// --- wire-assumption watchdog (#234) -------------------------------------
//
// Every assumption covered here came from ONE capture and is then trusted
// forever, and every one fails silently. The value sets this collector does NOT
// declare — RequestType above all — are argued in the package doc.

// collectRecords drives the real engine over the given raw records and returns
// the recorder, so a finding is asserted where it is actually emitted. The
// mapper alone cannot report anything: it is handed no emitter (see watcher).
func collectRecords(t *testing.T, raws ...string) *telemetrytest.Recorder {
	t.Helper()
	recs := make([]map[string]any, 0, len(raws))
	for _, raw := range raws {
		recs = append(recs, decodeLive(t, raw))
	}
	rec := telemetrytest.New()
	fake := &fakeJobClient{statuses: []string{jobpipeline.StatusSucceeded}, records: recs}
	c := newCollector(deps(t, fake))
	// The window brackets every captured record's createdDateTime.
	from := time.Date(2026, 7, 1, 0, 0, 0, 0, time.UTC)
	to := time.Date(2026, 8, 1, 0, 0, 0, 0, time.UTC)
	if _, err := c.CollectWindow(context.Background(), from, to, rec.Emitter()); err != nil {
		t.Fatalf("CollectWindow: %v", err)
	}
	return rec
}

// findings totals the watchdog counter by "<kind>/<field>", the same shape
// defender.quarantine's tests use.
func findings(rec *telemetrytest.Recorder) map[string]float64 {
	out := map[string]float64{}
	for _, p := range rec.MetricPoints(wirecheck.MetricUnexpected) {
		out[p.Attrs[semconv.AttrKind]+"/"+p.Attrs[semconv.AttrField]] += p.Value
	}
	return out
}

// mutateLive decodes a pinned record, applies fn to the whole envelope, and
// re-encodes it — so each case starts from the real wire shape and changes
// exactly one thing.
func mutateLive(t *testing.T, raw string, fn func(rec map[string]any)) string {
	t.Helper()
	rec := decodeLive(t, raw)
	fn(rec)
	out, err := json.Marshal(rec)
	if err != nil {
		t.Fatalf("re-encoding the mutated record: %v", err)
	}
	return string(out)
}

// The two records of an IN-SCOPE record type are the steady state. If either
// produces a finding, the watchdog cries wolf on correct data and nobody will
// read it again.
func TestInScopeLiveRecordsReportNothingUnexpected(t *testing.T) {
	for name, raw := range map[string]string{
		"quarantine release (live)":      liveQuarantineReleaseRecord,
		"SharePoint file op (synthetic)": syntheticInScopeClientIPRecord,
	} {
		t.Run(name, func(t *testing.T) {
			if got := findings(collectRecords(t, raw)); len(got) != 0 {
				t.Errorf("an in-scope record produced findings %v, want none", got)
			}
		})
	}
}

// The include-list is the only thing keeping this collector off the tenant's
// firehose, and that it filters SERVER-SIDE has never been measured — #98
// verified the other half, that each entry is accepted and returns records.
//
// The four fixtures below are the evidence: real rows, of record types this
// collector never asks for, captured from an UNFILTERED query. If one of these
// types ever arrives from a filtered one, the filter has stopped filtering.
func TestExcludedRecordTypeIsReportedAsAFilterBreak(t *testing.T) {
	for name, raw := range map[string]string{
		"AzureActiveDirectoryStsLogon": liveUserLoggedInRecord,
		"DataInsightsRestApiAudit":     liveGUIDUserIDRecord,
		"AuditSearch":                  liveNullSentinelUserKeyRecord,
	} {
		t.Run(name, func(t *testing.T) {
			rec := collectRecords(t, raw)
			key := wirecheck.KindInvariant + "/" + ruleRecordTypeFilter
			if got := findings(rec)[key]; got != 1 {
				t.Errorf("findings[%s] = %v, want 1; all=%v", key, got, findings(rec))
			}
			// Report-only: an unasked-for record type is still emitted. Dropping
			// it here would hide the volume problem rather than announce it.
			if got := len(rec.LogRecords()); got != 1 {
				t.Errorf("emitted %d records, want 1 — a filter break must never drop the record", got)
			}
		})
	}

	// DLPEndpoint was 78% of the unfiltered window and is the reason the
	// include-list exists, but no DLPEndpoint row is pinned in this package — the
	// type name comes from the 2026-07-17 census. Assert on the record type alone
	// so the most consequential member is still covered.
	t.Run("DLPEndpoint (census, no pinned row)", func(t *testing.T) {
		raw := mutateLive(t, liveQuarantineReleaseRecord, func(rec map[string]any) {
			rec["auditLogRecordType"] = "DLPEndpoint"
		})
		key := wirecheck.KindInvariant + "/" + ruleRecordTypeFilter
		if got := findings(collectRecords(t, raw))[key]; got != 1 {
			t.Errorf("findings[%s] = %v, want 1", key, got)
		}
	})
}

// auditData arrives as a plain nested object on this transport, not the
// doubly-JSON-encoded string entra/riskdetections' additionalInfo is. If that
// flips, nested() returns nil and six attributes vanish at once.
func TestAuditDataAsAStringIsReportedAsAnInvariantBreak(t *testing.T) {
	raw := mutateLive(t, liveQuarantineReleaseRecord, func(rec map[string]any) {
		encoded, err := json.Marshal(rec["auditData"])
		if err != nil {
			t.Fatalf("re-encoding auditData: %v", err)
		}
		rec["auditData"] = string(encoded)
	})
	rec := collectRecords(t, raw)
	key := wirecheck.KindInvariant + "/" + ruleAuditDataObject
	if got := findings(rec)[key]; got != 1 {
		t.Errorf("findings[%s] = %v, want 1; all=%v", key, got, findings(rec))
	}
	// The record still emits, carrying only its envelope fields — which is
	// exactly the silent degradation this check exists to announce.
	logs := rec.LogRecords()
	if len(logs) != 1 {
		t.Fatalf("emitted %d records, want 1", len(logs))
	}
	if got, present := logs[0].Attrs["workload"]; present {
		t.Errorf("workload = %q, want it ABSENT — this is the loss the finding reports", got)
	}
}

// A record with no auditData at all is the normal case (see TestMapOmitsAbsentAttrs),
// so absence must never be mistaken for a type change.
func TestAbsentAuditDataIsNotAnInvariantBreak(t *testing.T) {
	for name, set := range map[string]func(rec map[string]any){
		"absent": func(rec map[string]any) { delete(rec, "auditData") },
		"null":   func(rec map[string]any) { rec["auditData"] = nil },
	} {
		t.Run(name, func(t *testing.T) {
			raw := mutateLive(t, liveQuarantineReleaseRecord, set)
			key := wirecheck.KindInvariant + "/" + ruleAuditDataObject
			if got := findings(collectRecords(t, raw))[key]; got != 0 {
				t.Errorf("findings[%s] = %v, want 0 — absent auditData is normal, not a type change", key, got)
			}
		})
	}
}

// The crossing was measured 500/500 and getting it wrong IS #151. Each record
// carries the classic O365 names inside auditData, so it argues with its own
// envelope — no remembered measurement needed.
func TestUserFieldCrossingBreakIsReported(t *testing.T) {
	for name, set := range map[string]func(rec map[string]any){
		"userId no longer holds the classic UserKey": func(rec map[string]any) {
			rec["userId"] = "someone-else"
		},
		"userPrincipalName no longer holds the classic UserId": func(rec map[string]any) {
			rec["userPrincipalName"] = "someone-else"
		},
	} {
		t.Run(name, func(t *testing.T) {
			raw := mutateLive(t, liveQuarantineReleaseRecord, set)
			rec := collectRecords(t, raw)
			key := wirecheck.KindInvariant + "/" + ruleUserFieldCrossing
			if got := findings(rec)[key]; got != 1 {
				t.Errorf("findings[%s] = %v, want 1; all=%v", key, got, findings(rec))
			}
			if got := len(rec.LogRecords()); got != 1 {
				t.Errorf("emitted %d records, want 1 — a crossing break must never drop the record", got)
			}
		})
	}
}

// Only compared when BOTH sides are populated. A record whose auditData carries
// no UserKey/UserId is not evidence the crossing broke.
func TestAbsentUserFieldsAreNotACrossingBreak(t *testing.T) {
	raw := mutateLive(t, liveQuarantineReleaseRecord, func(rec map[string]any) {
		data, _ := rec["auditData"].(map[string]any)
		delete(data, "UserKey")
		delete(data, "UserId")
	})
	key := wirecheck.KindInvariant + "/" + ruleUserFieldCrossing
	if got := findings(collectRecords(t, raw))[key]; got != 0 {
		t.Errorf("findings[%s] = %v, want 0 — an absent classic field proves nothing about the crossing", key, got)
	}
}

// An empty dedupe id is not merely undedupeable: jobpipeline adds "" to SeenIDs
// on the first such record, and every later one is then silently deduped away.
func TestMissingRecordIDIsReported(t *testing.T) {
	for name, set := range map[string]func(rec map[string]any){
		"absent": func(rec map[string]any) { delete(rec, "id") },
		"null":   func(rec map[string]any) { rec["id"] = nil },
		"empty":  func(rec map[string]any) { rec["id"] = "" },
	} {
		t.Run(name, func(t *testing.T) {
			raw := mutateLive(t, liveQuarantineReleaseRecord, set)
			rec := collectRecords(t, raw)
			key := wirecheck.KindMissingField + "/" + semconv.AttrId
			if got := findings(rec)[key]; got != 1 {
				t.Errorf("findings[%s] = %v, want 1; all=%v", key, got, findings(rec))
			}
			if got := len(rec.LogRecords()); got != 1 {
				t.Errorf("emitted %d records, want 1 — a missing id must never drop the record", got)
			}
		})
	}
}
