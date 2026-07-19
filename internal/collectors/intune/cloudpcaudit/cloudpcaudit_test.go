package cloudpcaudit

import (
	"bytes"
	"context"
	"encoding/json"
	"log/slog"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/rknightion/graph2otel/internal/blobpipeline"
	"github.com/rknightion/graph2otel/internal/checkpoint"
	"github.com/rknightion/graph2otel/internal/collectors"
	"github.com/rknightion/graph2otel/internal/semconv"
	"github.com/rknightion/graph2otel/internal/telemetry"
	"github.com/rknightion/graph2otel/internal/telemetrytest"
)

// Verbatim records captured live from insights-logs-windows365auditlogs as
// graph2otel-poller (2026-07-19, #198) — never hand-authored (#142). Each is one
// line of the hourly PT1H.json blob.
const (
	recCreateUserSetting = `{"time": "2026-07-19T15:07:16.0166130Z", "properties": {"ComponentName": "UserSettingControllerV1", "ServiceName": "CloudPC Service", "ApplicationName": "auditFunction", "ResourceExtendedProperties": "", "CallerExtendedProperties": "", "OtherExtendedProperties": "operationType:Create,category:CloudPC,activityDateTime:7/19/2026 3:07:15 PM,auditEvenId:092fef57-88a0-457f-8bbe-f6bf28a91b38,correlationId:cb028e4c-d66b-4412-b47d-8485d0c09422,shoeboxCategory:Windows365AuditLogs,resources:[{DisplayName:user, Type:CloudPcUserSetting, ResourceId:2968d991-9ce5-4b3e-a586-050f00b5df51, ModifiedProperty:[{Name:Id, OldValue:, NewValue:2968d991-9ce5-4b3e-a586-050f00b5df51}, {Name:DisplayName, OldValue:, NewValue:user}, {Name:SelfServiceEnabled, OldValue:, NewValue:False}, {Name:LocalAdminEnabled, OldValue:, NewValue:True}, {Name:ResetEnabled, OldValue:, NewValue:True}, {Name:RestorePointSetting.FrequencyInHours, OldValue:, NewValue:12}, {Name:LastModifiedDateTime, OldValue:, NewValue:7/19/2026 3:07:15 PM}, {Name:DeviceManagementAPIVersion, OldValue:, NewValue:1.0}]}],"}, "operationName": "Create CloudPcUserSetting", "resultType": "Success", "identity": {"TenantId": [{"Identity": "4b8c18bd-2f9f-4227-af55-9f1061cf9c32"}], "UPN": [{"Identity": "rob@m7kni.io"}], "ObjectID": [{"Identity": "bbcfc3c5-0b93-4135-9ef9-18477a9fb504"}], "ApplicationID": [{"Identity": "69cc3193-b6c4-4172-98e5-ed0f38ab3ff8"}], "Other": [{"Identity": "{\"Type\":1,\"UserPermission\":[\"CloudPC.ReadWrite.All User.Read.All\"],\"ApplicationDisplayName\":\"Windows 365 Ibiza Extension\"}", "Description": "OtherProperties"}]}, "tenantId": "4b8c18bd-2f9f-4227-af55-9f1061cf9c32", "category": "Windows365AuditLogs"}`

	// AssignToGroups packs a nested-JSON array into a ModifiedProperty NewValue
	// (`assignments`), the adversarial case for the names-only parser: the value
	// contains braces, commas and colons but must not disturb Name extraction.
	recAssignToGroups = `{"time": "2026-07-19T15:11:53.3134110Z", "properties": {"ComponentName": "ProvisionPolicyControllerV1", "OtherExtendedProperties": "operationType:Action,category:CloudPC,activityDateTime:7/19/2026 3:11:53 PM,auditEvenId:94f53496-e40d-4998-ae78-2e5209a62c6a,correlationId:7a79dc0d-2a4b-4c20-8cba-838850767d35,shoeboxCategory:Windows365AuditLogs,resources:[{DisplayName:main, Type:CloudPcProvisioningPolicy, ResourceId:696ce712-2615-4099-87df-4560335cfa44, ModifiedProperty:[{Name:assignments, OldValue:[], NewValue:[{\"id\":\"\",\"target\":{\"groupId\":\"c118ea33-87b7-4c8a-9bb3-e72b80bb75dd\",\"servicePlanId\":null}}]}, {Name:DeviceManagementAPIVersion, OldValue:, NewValue:1.0}]}],"}, "operationName": "AssignToGroups CloudPcProvisioningPolicy", "resultType": "Success", "identity": {"UPN": [{"Identity": "rob@m7kni.io"}], "ObjectID": [{"Identity": "bbcfc3c5-0b93-4135-9ef9-18477a9fb504"}], "ApplicationID": [{"Identity": "69cc3193-b6c4-4172-98e5-ed0f38ab3ff8"}]}, "tenantId": "4b8c18bd-2f9f-4227-af55-9f1061cf9c32", "category": "Windows365AuditLogs"}`

	// Delete carries an empty DisplayName — resource_display_names must omit it.
	recDelete = `{"time": "2026-07-19T15:46:25.0136170Z", "properties": {"ComponentName": "ProvisionPolicyControllerV1", "OtherExtendedProperties": "operationType:Delete,category:CloudPC,activityDateTime:7/19/2026 3:46:24 PM,auditEvenId:7f1d77d4-f15e-4f8e-bba2-a462a99035e5,correlationId:15eeac68-92c0-44bc-9165-be3c2abfae38,shoeboxCategory:Windows365AuditLogs,resources:[{DisplayName:, Type:CloudPcProvisioningPolicy, ResourceId:696ce712-2615-4099-87df-4560335cfa44, ModifiedProperty:[{Name:DeviceManagementAPIVersion, OldValue:, NewValue:1.0}]}],"}, "operationName": "Delete CloudPcProvisioningPolicy", "resultType": "Success", "identity": {"UPN": [{"Identity": "rob@m7kni.io"}], "ObjectID": [{"Identity": "bbcfc3c5-0b93-4135-9ef9-18477a9fb504"}], "ApplicationID": [{"Identity": "69cc3193-b6c4-4172-98e5-ed0f38ab3ff8"}]}, "tenantId": "4b8c18bd-2f9f-4227-af55-9f1061cf9c32", "category": "Windows365AuditLogs"}`
)

func decode(t *testing.T, raw string) map[string]any {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal([]byte(raw), &m); err != nil {
		t.Fatalf("decode fixture: %v", err)
	}
	return m
}

func TestMapRecordCreateUserSetting(t *testing.T) {
	ev, ok := mapRecord(decode(t, recCreateUserSetting))
	if !ok {
		t.Fatal("mapRecord returned ok=false for a valid record")
	}
	if ev.Name != eventName {
		t.Errorf("Name = %q, want %q", ev.Name, eventName)
	}
	want := time.Date(2026, 7, 19, 15, 7, 15, 0, time.UTC)
	if !ev.Timestamp.Equal(want) {
		t.Errorf("Timestamp = %s, want %s (inner activityDateTime, not envelope time)", ev.Timestamp, want)
	}
	if ev.Severity != telemetry.SeverityInfo {
		t.Errorf("Severity = %v, want Info for a Success result", ev.Severity)
	}
	strWant := map[string]string{
		semconv.AttrId:                     "092fef57-88a0-457f-8bbe-f6bf28a91b38",
		semconv.AttrActivity:               "Create CloudPcUserSetting",
		semconv.AttrActivityOperationType:  "Create",
		semconv.AttrActivityResult:         "Success",
		semconv.AttrCategory:               "CloudPC",
		semconv.AttrCorrelationId:          "cb028e4c-d66b-4412-b47d-8485d0c09422",
		semconv.AttrComponentName:          "UserSettingControllerV1",
		semconv.AttrActorUserPrincipalName: "rob@m7kni.io",
		semconv.AttrActorUserId:            "bbcfc3c5-0b93-4135-9ef9-18477a9fb504",
		semconv.AttrActorApplicationId:     "69cc3193-b6c4-4172-98e5-ed0f38ab3ff8",
	}
	for k, w := range strWant {
		if got, _ := ev.Attrs[k].(string); got != w {
			t.Errorf("attr %q = %q, want %q", k, got, w)
		}
	}
	assertStrs(t, ev.Attrs, semconv.AttrResourceTypes, []string{"CloudPcUserSetting"})
	assertStrs(t, ev.Attrs, semconv.AttrResourceDisplayNames, []string{"user"})
	assertStrs(t, ev.Attrs, semconv.AttrResourceIds, []string{"2968d991-9ce5-4b3e-a586-050f00b5df51"})
	// modified-property NAMES only, deduped + sorted; never OldValue/NewValue (#112).
	assertStrs(t, ev.Attrs, semconv.AttrModifiedPropertyNames, []string{
		"DeviceManagementAPIVersion", "DisplayName", "Id", "LastModifiedDateTime",
		"LocalAdminEnabled", "ResetEnabled", "RestorePointSetting.FrequencyInHours", "SelfServiceEnabled",
	})
	// The secret boundary: no NewValue must ever leak into any attribute.
	for k, v := range ev.Attrs {
		if s, ok := v.(string); ok && s == "True" {
			t.Errorf("attr %q leaked a modifiedProperty NewValue %q", k, s)
		}
	}
}

func TestMapRecordAssignToGroupsNestedJSON(t *testing.T) {
	ev, ok := mapRecord(decode(t, recAssignToGroups))
	if !ok {
		t.Fatal("mapRecord returned ok=false")
	}
	if got, _ := ev.Attrs[semconv.AttrActivity].(string); got != "AssignToGroups CloudPcProvisioningPolicy" {
		t.Errorf("activity = %q", got)
	}
	// The nested-JSON NewValue on `assignments` must not corrupt name extraction.
	assertStrs(t, ev.Attrs, semconv.AttrModifiedPropertyNames, []string{"DeviceManagementAPIVersion", "assignments"})
	assertStrs(t, ev.Attrs, semconv.AttrResourceIds, []string{"696ce712-2615-4099-87df-4560335cfa44"})
	// No groupId value must leak.
	for k, v := range ev.Attrs {
		if s, ok := v.(string); ok && s == "c118ea33-87b7-4c8a-9bb3-e72b80bb75dd" {
			t.Errorf("attr %q leaked a nested NewValue", k)
		}
	}
}

func TestMapRecordDeleteEmptyDisplayName(t *testing.T) {
	ev, ok := mapRecord(decode(t, recDelete))
	if !ok {
		t.Fatal("mapRecord returned ok=false")
	}
	if got, _ := ev.Attrs[semconv.AttrActivityOperationType].(string); got != "Delete" {
		t.Errorf("operation_type = %q, want Delete", got)
	}
	// DisplayName is "" on this record → resource_display_names must be omitted.
	if _, present := ev.Attrs[semconv.AttrResourceDisplayNames]; present {
		t.Errorf("resource_display_names should be omitted when the only DisplayName is empty")
	}
	assertStrs(t, ev.Attrs, semconv.AttrResourceTypes, []string{"CloudPcProvisioningPolicy"})
}

func TestMapRecordDropsUnparseable(t *testing.T) {
	// No properties → drop.
	if _, ok := mapRecord(map[string]any{"operationName": "x"}); ok {
		t.Error("expected drop when properties absent")
	}
	// No OtherExtendedProperties → drop (no event time to bind).
	if _, ok := mapRecord(map[string]any{"properties": map[string]any{}}); ok {
		t.Error("expected drop when OtherExtendedProperties absent")
	}
}

func assertStrs(t *testing.T, attrs telemetry.Attrs, key string, want []string) {
	t.Helper()
	got, ok := attrs[key].([]string)
	if !ok {
		t.Errorf("attr %q = %v (%T), want []string %v", key, attrs[key], attrs[key], want)
		return
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("attr %q = %v, want %v", key, got, want)
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

// TestCollectorEmitsLiveRecordEndToEnd drives the whole collector over the pinned
// live record — JSON Lines with the CRLF terminators Azure writes — and asserts
// what reaches the emitter. It is also what makes the signals golden substantive
// (#164): the golden captures the attributes THIS drives into the Recorder.
func TestCollectorEmitsLiveRecordEndToEnd(t *testing.T) {
	const tenant = "4b8c18bd-2f9f-4227-af55-9f1061cf9c32"
	src := &staticSource{
		name: "tenantId=" + tenant + "/y=2026/m=07/d=19/h=15/m=00/PT1H.json",
		data: []byte(compactJSON(t, recCreateUserSetting) + "\r\n"),
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
	if got := logs[0].Attrs[semconv.AttrActivity]; got != "Create CloudPcUserSetting" {
		t.Errorf("activity = %q", got)
	}

	// Cursor persisted: a second tick over the unchanged blob emits nothing new.
	if err := c.Collect(context.Background(), rec.Emitter()); err != nil {
		t.Fatalf("second Collect: %v", err)
	}
	if got := len(rec.LogRecords()); got != 1 {
		t.Errorf("after a second tick over an unchanged blob: %d records, want 1", got)
	}
}
