package unifiedaudit

import (
	"context"
	"encoding/json"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/rknightion/graph2otel/internal/checkpoint"
	"github.com/rknightion/graph2otel/internal/collector"
	"github.com/rknightion/graph2otel/internal/collectors"
	"github.com/rknightion/graph2otel/internal/jobpipeline"
	"github.com/rknightion/graph2otel/internal/telemetrytest"
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

// fullAuditRecord returns the richest auditLogRecord this package has: every
// field mapRecord reads, in the #98 live shape.
//
// Provenance, stated rather than assumed: this is HAND-WRITTEN in the live
// shape — it is NOT a live capture. The field NAMES and the crossed user-field
// semantics behind them are live-verified (500/500 on m7kni, 2026-07-17,
// #100/#151); the VALUES are placeholders — contoso.com is Microsoft's example
// domain, 203.0.113.7 is TEST-NET-3, "rec-abc-123" and "obj-42" are invented.
// No captured auditLogRecord exists in this package's testdata. So this fixture
// is evidence about field names and mapper wiring, and evidence about nothing
// else: #142's `"platform": "windows"` was also a plausible value that was never
// on the wire.
//
// Returned from a function rather than shared as a package-level var so no test
// can mutate the record another test reads.
func fullAuditRecord() map[string]any {
	return map[string]any{
		"id":                 "rec-abc-123",
		"createdDateTime":    "2026-07-16T09:15:00Z",
		"auditLogRecordType": "ExchangeItemAggregated",
		"operation":          "MailItemsAccessed",
		"service":            "Exchange",
		"userType":           "Regular",
		"userId":             "user-guid-1",
		"userPrincipalName":  "alice@contoso.com",
		"clientIp":           "203.0.113.7",
		"objectId":           "obj-42",
		"auditData": map[string]any{
			"@odata.type":  "#microsoft.graph.security.defaultAuditData",
			"RecordType":   float64(2),
			"Workload":     "Exchange",
			"ResultStatus": "Succeeded",
			"Operation":    "MailItemsAccessed",
		},
	}
}

// TestMap maps a representative auditLogRecord (the #98 live shape) to its
// dedupe id and per-record log attributes, and confirms per-entity detail
// (UPN, IP, object id) lands as LOG attributes.
func TestMap(t *testing.T) {
	rec := fullAuditRecord()

	id, ev := mapRecord(rec)
	if id != "rec-abc-123" {
		t.Fatalf("dedupe id = %q, want rec-abc-123", id)
	}
	if ev.Name != eventName {
		t.Errorf("event name = %q, want %q", ev.Name, eventName)
	}

	want := map[string]any{
		"id":          "rec-abc-123",
		"operation":   "MailItemsAccessed",
		"record_type": "ExchangeItemAggregated",
		"service":     "Exchange",
		"user_type":   "Regular",
		// The two wire field names are CROSSED relative to the attributes, and
		// that is deliberate — each attribute is named for what it contains, not
		// for the field it came from. See TestTopLevelUserIDIsTheClassicUserKey.
		//
		//	wire userId            -> user_key (classic UserKey)
		//	wire userPrincipalName -> user_id  (classic UserId)
		"user_key":      "user-guid-1",
		"user_id":       "alice@contoso.com",
		"client_ip":     "203.0.113.7",
		"object_id":     "obj-42",
		"workload":      "Exchange",
		"result_status": "Succeeded",
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
// Taking the wire name at face value is exactly what produced #151: `user_id`
// meant UserKey here and UserId on m365.activity — one attribute, two meanings,
// with nothing on the record saying which. The mapper must translate each field
// to what it CONTAINS, not to what Microsoft calls it. The crossover looks like a
// bug on every reading; it is the fix.
//
// `user_principal_name` is the name `user_id` used to carry here, and it must not
// return: the value is the classic UserId, which is UPN-shaped on only ~91% of
// live records.
func TestTopLevelUserIDIsTheClassicUserKey(t *testing.T) {
	rec := map[string]any{
		"id":                 "rec-key-1",
		"createdDateTime":    "2026-07-16T09:15:00Z",
		"auditLogRecordType": "AzureActiveDirectory",
		"operation":          "UserLoggedIn",
		"service":            "AzureActiveDirectory",
		// Live shape: the two fields carry DIFFERENT values, which is the whole
		// point — userId is an opaque key, userPrincipalName is the UPN.
		"userId":            "10037FFE8E38C3F1",
		"userPrincipalName": "rob@m7kni.io",
	}

	_, ev := mapRecord(rec)

	if got := ev.Attrs["user_key"]; got != "10037FFE8E38C3F1" {
		t.Errorf("user_key = %v, want %q — the query API's top-level userId IS the classic UserKey (live 500/500, #151) and must be emitted under the name of what it contains, NOT as user_id",
			got, "10037FFE8E38C3F1")
	}
	if got := ev.Attrs["user_id"]; got != "rob@m7kni.io" {
		t.Errorf("user_id = %v, want %q — it must come from the wire's userPrincipalName, which IS the classic UserId (live 500/500, byte-identical, #151). Sourcing user_id from the wire's `userId` field instead would make it mean UserKey here and UserId on m365.activity: one attribute, two meanings.",
			got, "rob@m7kni.io")
	}
	if got, present := ev.Attrs["user_principal_name"]; present {
		t.Errorf("user_principal_name = %v, want the attribute ABSENT — it was renamed to user_id because the value is the classic UserId, which is UPN-shaped on only ~91%% of live records. Emitting both would rebuild #151: two attributes set from one variable, identical by construction.", got)
	}
}

// TestMapOmitsAbsentAttrs asserts a sparse record (SharePoint file op with no
// UPN) omits absent attributes rather than emitting empty strings.
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
}

// --- factory + end-to-end wiring ---

func deps(t *testing.T, client jobpipeline.JobClient) collectors.WindowDeps {
	t.Helper()
	return collectors.WindowDeps{
		TenantID:  "t1",
		JobClient: client,
		Store:     checkpoint.NewStore(t.TempDir()),
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
// has (fullAuditRecord) through the real jobpipeline engine into an emitter,
// rather than calling mapRecord directly the way TestMap does.
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
		records:  []map[string]any{fullAuditRecord()},
	}
	c := newCollector(deps(t, fake))

	from := time.Date(2026, 7, 16, 8, 0, 0, 0, time.UTC)
	to := time.Date(2026, 7, 16, 9, 30, 0, 0, time.UTC)
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
		"id":            "rec-abc-123",
		"operation":     "MailItemsAccessed",
		"record_type":   "ExchangeItemAggregated",
		"service":       "Exchange",
		"user_type":     "Regular",
		"user_key":      "user-guid-1",
		"user_id":       "alice@contoso.com",
		"client_ip":     "203.0.113.7",
		"object_id":     "obj-42",
		"workload":      "Exchange",
		"result_status": "Succeeded",
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
