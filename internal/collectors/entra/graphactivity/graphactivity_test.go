package graphactivity

import (
	"bytes"
	"context"
	"encoding/json"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/rknightion/graph2otel/internal/blobpipeline"
	"github.com/rknightion/graph2otel/internal/checkpoint"
	"github.com/rknightion/graph2otel/internal/collectors"
	"github.com/rknightion/graph2otel/internal/telemetry"
	"github.com/rknightion/graph2otel/internal/telemetrytest"
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

// TestCallerAppIDMatchesTheEmittedAppID ties the exclude_self extractor (#154) to
// the mapper: callerAppID must read the SAME properties.appId that mapActivity
// labels the record with, so the self-filter can never compare a different field
// than the one shipped. Sourced from mapActivity's app_id attribute (line ~117).
func TestCallerAppIDMatchesTheEmittedAppID(t *testing.T) {
	rec := decode(t, realRecord)
	got := callerAppID(rec)
	if got == "" {
		t.Fatal("callerAppID returned empty for a record with properties.appId set")
	}
	if want := mapRealRecord(t).Attrs["app_id"]; got != want {
		t.Errorf("callerAppID = %q, want %q (the appId the mapper emits)", got, want)
	}
	if got != "c98e5057-edde-4666-b301-186a01b4dc58" {
		t.Errorf("callerAppID = %q, want the record's properties.appId", got)
	}
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

// staticSource is a blobpipeline.Source serving one in-memory blob, so the
// collector can be driven end-to-end without Azure.
type staticSource struct {
	name string
	data []byte
}

func (s *staticSource) List(_ context.Context, _, prefix string) ([]blobpipeline.BlobInfo, error) {
	if !strings.HasPrefix(s.name, prefix) {
		return nil, nil
	}
	return []blobpipeline.BlobInfo{{Name: s.name, Size: int64(len(s.data))}}, nil
}

func (s *staticSource) ReadRange(_ context.Context, _, _ string, offset, count int64) ([]byte, error) {
	end := min(offset+count, int64(len(s.data)))
	if offset >= end {
		return nil, nil
	}
	return s.data[offset:end], nil
}

// compactJSON strips the pinned record's formatting, since a JSON Lines record
// is one line by definition.
func compactJSON(t *testing.T, raw string) string {
	t.Helper()
	var buf bytes.Buffer
	if err := json.Compact(&buf, []byte(raw)); err != nil {
		t.Fatalf("compacting the pinned record: %v", err)
	}
	return buf.String()
}

// TestCollectorEmitsLiveRecordEndToEnd drives the pinned live record through the
// real blob engine into an emitter, rather than calling mapActivity directly
// like the tests above.
//
// Two things depend on it. First, it proves the mapped fields survive the whole
// path — it would catch a collector wired to the wrong container prefix, which no
// unit test of mapActivity can see. Second, it is what makes testdata/signals.json
// honest: the signal gate goldens the union of what a package's tests EMIT, and
// before this test NOTHING in this package reached an emitter at all, so the
// golden recorded `"Logs": null` — a zero-attribute surface — for a collector
// that really ships 22 attributes. It understated the exact thing the golden
// exists to make reviewable (#164).
func TestCollectorEmitsLiveRecordEndToEnd(t *testing.T) {
	// The tenant the pinned record was captured from: it must match, because the
	// listing prefix is built from it (blobPrefix) and a mismatch lists zero blobs.
	const tenant = "4b8c18bd-2f9f-4227-af55-9f1061cf9c32"
	src := &staticSource{
		// The real layout: tenantId=<guid>/ … /PT1H.json, CRLF-terminated.
		name: "tenantId=" + tenant + "/y=2026/m=07/d=16/h=02/m=00/PT1H.json",
		data: []byte(compactJSON(t, realRecord) + "\r\n"),
	}
	rec := telemetrytest.New()
	c := newCollector(collectors.BlobDeps{
		TenantID: tenant,
		Source:   src,
		Store:    checkpoint.NewStore(t.TempDir()),
		Logger:   slog.New(slog.DiscardHandler),
	})

	if err := c.Collect(context.Background(), rec.Emitter()); err != nil {
		t.Fatalf("Collect: %v", err)
	}

	logs := rec.LogRecords()
	if len(logs) != 1 {
		t.Fatalf("emitted %d records, want 1 — check the tenantId= listing prefix", len(logs))
	}
	got := logs[0]
	if got.EventName != eventName {
		t.Errorf("event name = %q, want %q", got.EventName, eventName)
	}

	// The record's own event time must survive the engine: these records are
	// routinely backfilled hours late, so a lost timestamp silently lands every
	// record at ingest time.
	want := time.Date(2026, 7, 16, 2, 0, 45, 15970300, time.UTC)
	if !got.Timestamp.Equal(want) {
		t.Errorf("emitted timestamp = %s, want %s (the record's own time field)",
			got.Timestamp.Format(time.RFC3339Nano), want.Format(time.RFC3339Nano))
	}

	// A representative spread checked at the EMITTER rather than the mapper: the
	// caller identity, the permission list, and the two fields the record carries
	// in two conflicting types (duration_ms is a string at the top level and an
	// int in properties on this very record).
	wantAttrs := map[string]string{
		"request_id":        "8a566ebb-77a1-4f60-9855-d4eb4019e562",
		"request_method":    "POST",
		"app_id":            "c98e5057-edde-4666-b301-186a01b4dc58",
		"identity_type":     "app",
		"user_agent":        "DelphiAC-Mac",
		"caller_ip_address": "172.165.241.127",
		"location":          "UK South",
	}
	for k, want := range wantAttrs {
		if v := got.Attrs[k]; v != want {
			t.Errorf("emitted attr %q = %q, want %q", k, v, want)
		}
	}

	// blobpipeline stamps the transport at the emitter boundary (#141). A blob
	// record claiming `graph` would misattribute every duplicate this path's
	// at-least-once delivery produces.
	if v := got.Attrs["ingest_transport"]; v != "blob" {
		t.Errorf("ingest_transport = %q, want %q", v, "blob")
	}

	// Non-string attributes are checked for PRESENCE only, and their values are
	// pinned at the mapper instead (TestMapActivityCarriesTheRequestDetail).
	//
	// Not an oversight: telemetrytest.Recorder flattens every log attribute
	// through log.Value.AsString(), which yields "" for any non-string Kind, so
	// the recorder cannot represent an int or a slice attribute's value. That is
	// a limitation of the test harness, not of the emission.
	for _, k := range []string{"response_status_code", "duration_ms", "response_size_bytes", "roles", "wids", "is_replay"} {
		if _, present := got.Attrs[k]; !present {
			t.Errorf("emitted attrs missing %q", k)
		}
	}
}
