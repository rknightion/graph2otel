package identityinfo

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
	"github.com/rknightion/graph2otel/internal/semconv"
	"github.com/rknightion/graph2otel/internal/telemetrytest"
)

// liveRecord is a real IdentityInfo envelope captured off the m7kni storage
// account as graph2otel-poller (cert on camden, 2026-07-18, #106) — a seed test
// account with an EntraRiskChanged identity snapshot.
const liveRecord = `{
 "time": "2026-07-18T15:00:41.1610575Z",
 "tenantId": "4b8c18bd-2f9f-4227-af55-9f1061cf9c32",
 "operationName": "Publish",
 "category": "AdvancedHunting-IdentityInfo",
 "_TimeReceivedBySvc": "2026-07-18T15:00:41.1230000Z",
 "properties": {
  "Timestamp": "2026-07-18T15:00:40.115438Z",
  "ReportId": "5b57ca0e-23ca-41db-8ed9-40757a5f0cf4",
  "IdentityId": "User_4b8c18bd-2f9f-4227-af55-9f1061cf9c32_b6c65b35-8595-4423-a639-0f0a21c1817f",
  "AccountName": "g2o seed test",
  "AccountDomain": "m7knio.onmicrosoft.com",
  "AccountUpn": "g2o-seed-test@m7knio.onmicrosoft.com",
  "AccountObjectId": "0a85025c-4238-4148-978f-587a8dd7960e",
  "AccountDisplayName": "g2o seed test",
  "GivenName": null,
  "Surname": null,
  "Department": null,
  "JobTitle": null,
  "EmailAddress": null,
  "Manager": null,
  "Address": null,
  "City": null,
  "Country": null,
  "Phone": null,
  "CreatedDateTime": "2026-07-18T14:53:12Z",
  "DistinguishedName": null,
  "OnPremSid": null,
  "CloudSid": "S-1-12-1-176489052-1095254584-2052624279-244766605",
  "IsAccountEnabled": true,
  "SourceProvider": "AzureActiveDirectory",
  "ChangeSource": "EntraRiskChanged",
  "BlastRadius": null,
  "CompanyName": null,
  "DeletedDateTime": null,
  "EmployeeId": null,
  "OtherMailAddresses": null,
  "RiskLevel": "High",
  "RiskLevelDetails": "Admin confirmed user compromised",
  "State": null,
  "Tags": [],
  "UserAccountControl": null,
  "SourceProviders": [
   "AzureActiveDirectory"
  ],
  "IdentityEnvironment": "Cloud",
  "CriticalityLevel": 4,
  "OnPremObjectId": null,
  "PrivilegedEntraPimRoles": null,
  "SipProxyAddress": "",
  "Type": "User"
 },
 "Tenant": "DefaultTenant"
}`

func decode(t *testing.T, body string) map[string]any {
	t.Helper()
	var rec map[string]any
	if err := json.Unmarshal([]byte(body), &rec); err != nil {
		t.Fatalf("decode: %v", err)
	}
	return rec
}

func TestMapRecordEmitsIdentityInfo(t *testing.T) {
	ev, ok := mapRecord(decode(t, liveRecord))
	if !ok {
		t.Fatal("mapRecord dropped a valid record")
	}
	if ev.Name != eventName {
		t.Errorf("event name = %q, want %q", ev.Name, eventName)
	}

	// Timestamp bound to properties.Timestamp, as an instant — NOT the envelope
	// `time` or `_TimeReceivedBySvc`.
	wantTS, _ := time.Parse(time.RFC3339Nano, "2026-07-18T15:00:40.115438Z")
	if !ev.Timestamp.Equal(wantTS) {
		t.Errorf("timestamp = %v, want %v (bound to properties.Timestamp)", ev.Timestamp, wantTS)
	}

	want := map[string]string{
		semconv.AttrAccountUpn:         "g2o-seed-test@m7knio.onmicrosoft.com",
		semconv.AttrAccountDisplayName: "g2o seed test",
		semconv.AttrRiskLevel:          "High",
		semconv.AttrSourceProvider:     "AzureActiveDirectory",
	}
	for k, v := range want {
		got, _ := ev.Attrs[k].(string)
		if got != v {
			t.Errorf("attr %q = %q, want %q", k, got, v)
		}
	}

	// Bools are stamped as strings; IsAccountEnabled is a JSON bool present as
	// `true`.
	if got, _ := ev.Attrs[semconv.AttrIsAccountEnabled].(string); got != "true" {
		t.Errorf("is_account_enabled = %q, want \"true\"", got)
	}

	// CriticalityLevel is numeric.
	if got, _ := ev.Attrs[semconv.AttrCriticalityLevel].(float64); got != 4 {
		t.Errorf("criticality_level = %v, want 4", got)
	}

	// ReportId is a GUID string on this table, not a number.
	if got, _ := ev.Attrs[semconv.AttrReportId].(string); got != "5b57ca0e-23ca-41db-8ed9-40757a5f0cf4" {
		t.Errorf("report_id = %q, want the GUID string", got)
	}

	// Tags is an empty native array on this record and must be omitted, not an
	// empty-but-present list.
	if _, present := ev.Attrs[semconv.AttrTags]; present {
		t.Error("tags should be omitted when the array is empty")
	}

	// SourceProviders is a single-element native array and must survive as
	// []string.
	gotProviders, _ := ev.Attrs[semconv.AttrSourceProviders].([]string)
	if len(gotProviders) != 1 || gotProviders[0] != "AzureActiveDirectory" {
		t.Errorf("source_providers = %v, want [AzureActiveDirectory]", gotProviders)
	}

	// Null string columns (GivenName/Surname/... on this record) are omitted,
	// not emitted blank.
	for _, k := range []string{semconv.AttrGivenName, semconv.AttrSurname, semconv.AttrDepartment, semconv.AttrBlastRadius, semconv.AttrState} {
		if _, present := ev.Attrs[k]; present {
			t.Errorf("attr %q should be omitted when null", k)
		}
	}

	// SipProxyAddress is an empty string on this record and must be omitted,
	// not emitted blank.
	if _, present := ev.Attrs[semconv.AttrSipProxyAddress]; present {
		t.Error("sip_proxy_address should be omitted when empty")
	}

	if !strings.Contains(ev.Body, "g2o-seed-test@m7knio.onmicrosoft.com") {
		t.Errorf("body = %q, want it to mention the account UPN", ev.Body)
	}
}

func TestMapRecordDropsMalformed(t *testing.T) {
	// No properties → dropped.
	if _, ok := mapRecord(map[string]any{"time": "2026-07-18T15:00:41Z"}); ok {
		t.Error("record with no properties should be dropped")
	}
	// Unparseable Timestamp → dropped, never mis-dated (no fallback to envelope time).
	if _, ok := mapRecord(decode(t, `{"properties":{"IdentityId":"i","Timestamp":"not-a-time"}}`)); ok {
		t.Error("record with unparseable Timestamp should be dropped")
	}
	// Missing Timestamp → dropped.
	if _, ok := mapRecord(decode(t, `{"properties":{"IdentityId":"i"}}`)); ok {
		t.Error("record with no Timestamp should be dropped")
	}
}

// staticSource is a blobpipeline.Source serving one in-memory blob, so the
// collector runs end-to-end without Azure.
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

func compactJSON(t *testing.T, raw string) string {
	t.Helper()
	var buf bytes.Buffer
	if err := json.Compact(&buf, []byte(raw)); err != nil {
		t.Fatalf("compacting the pinned record: %v", err)
	}
	return buf.String()
}

// TestCollectorEmitsLiveRecordEndToEnd drives the whole collector over the
// pinned live record — JSON Lines with the CRLF terminators Azure writes — and
// asserts what reaches the emitter. It is also what makes the signals golden
// substantive (#164): the golden captures the attributes THIS drives into the
// Recorder.
func TestCollectorEmitsLiveRecordEndToEnd(t *testing.T) {
	const tenant = "4b8c18bd-2f9f-4227-af55-9f1061cf9c32"
	src := &staticSource{
		name: "tenantId=" + tenant + "/y=2026/m=07/d=18/h=15/m=00/PT1H.json",
		data: []byte(compactJSON(t, liveRecord) + "\r\n"),
	}
	rec := telemetrytest.New()
	c := newBlobCollector(collectors.BlobDeps{
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
	if logs[0].EventName != eventName {
		t.Errorf("event name = %q, want %q", logs[0].EventName, eventName)
	}
	wantTS, _ := time.Parse(time.RFC3339Nano, "2026-07-18T15:00:40.115438Z")
	if !logs[0].Timestamp.Equal(wantTS) {
		t.Errorf("timestamp = %s, want %s", logs[0].Timestamp, wantTS)
	}
	if got := logs[0].Attrs[semconv.AttrAccountUpn]; got != "g2o-seed-test@m7knio.onmicrosoft.com" {
		t.Errorf("account_upn attr = %q, want the seed UPN", got)
	}

	// Cursor persisted: a second tick over the unchanged blob emits nothing new.
	if err := c.Collect(context.Background(), rec.Emitter()); err != nil {
		t.Fatalf("second Collect: %v", err)
	}
	if got := len(rec.LogRecords()); got != 1 {
		t.Errorf("after a second tick over an unchanged blob: %d records, want 1", got)
	}
}
