package behaviorentities

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

// liveUser is a real BehaviorEntities envelope captured off the m7kni storage
// account as graph2otel-poller (2026-07-23, #241): the impacted User row of an
// ImpossibleTravelActivity behavior.
const liveUser = `{
 "time": "2026-07-23T12:41:50.5944646Z",
 "tenantId": "4b8c18bd-2f9f-4227-af55-9f1061cf9c32",
 "operationName": "Publish",
 "category": "AdvancedHunting-BehaviorEntities",
 "_TimeReceivedBySvc": "2026-07-23T12:41:07.9520000Z",
 "properties": {
  "Timestamp": "2026-07-23T12:41:07.952Z",
  "BehaviorId": "oa4e429c5c782180ae5aeafb5a7c2cff29b62c458a000a84206ca5d548a72f1ff3",
  "ActionType": "ImpossibleTravelActivity",
  "Categories": "[\"InitialAccess\"]",
  "ServiceSource": "Microsoft Cloud App Security",
  "DetectionSource": "Cloud App Security",
  "DataSources": "[\"Microsoft Cloud App Security\"]",
  "EntityType": "User",
  "EntityRole": "Impacted",
  "DetailedEntityRole": null,
  "RemoteIP": null,
  "AccountName": "gadmin",
  "AccountDomain": "rob-knight.com",
  "AccountUpn": "gadmin@rob-knight.com",
  "AdditionalFields": "{\"Type\":\"account\",\"Name\":\"gadmin\",\"Role\":0}"
 },
 "Tenant": "DefaultTenant"
}`

// liveCloudApp is the CloudApplication row of the same behavior — it carries the
// numeric ApplicationId this table serializes as a JSON number.
const liveCloudApp = `{
 "time": "2026-07-23T12:41:50.5945697Z",
 "tenantId": "4b8c18bd-2f9f-4227-af55-9f1061cf9c32",
 "operationName": "Publish",
 "category": "AdvancedHunting-BehaviorEntities",
 "_TimeReceivedBySvc": "2026-07-23T12:41:07.9520000Z",
 "properties": {
  "Timestamp": "2026-07-23T12:41:07.952Z",
  "BehaviorId": "oa4e429c5c782180ae5aeafb5a7c2cff29b62c458a000a84206ca5d548a72f1ff3",
  "ActionType": "ImpossibleTravelActivity",
  "Categories": "[\"InitialAccess\"]",
  "ServiceSource": "Microsoft Cloud App Security",
  "DetectionSource": "Cloud App Security",
  "DataSources": "[\"Microsoft Cloud App Security\"]",
  "EntityType": "CloudApplication",
  "EntityRole": "Impacted",
  "Application": "Google Cloud Platform",
  "ApplicationId": 22110,
  "AdditionalFields": "{\"Type\":\"cloud-application\",\"AppId\":22110,\"Name\":\"Google Cloud Platform\",\"Role\":0}"
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

func TestMapRecordEmitsUserEntity(t *testing.T) {
	ev, ok := mapRecord(decode(t, liveUser))
	if !ok {
		t.Fatal("mapRecord dropped a valid record")
	}
	if ev.Name != eventName {
		t.Errorf("event name = %q, want %q", ev.Name, eventName)
	}

	wantTS, _ := time.Parse(time.RFC3339Nano, "2026-07-23T12:41:07.952Z")
	if !ev.Timestamp.Equal(wantTS) {
		t.Errorf("timestamp = %v, want %v (bound to properties.Timestamp)", ev.Timestamp, wantTS)
	}

	want := map[string]string{
		semconv.AttrBehaviorId:  "oa4e429c5c782180ae5aeafb5a7c2cff29b62c458a000a84206ca5d548a72f1ff3",
		semconv.AttrEntityType:  "User",
		semconv.AttrEntityRole:  "Impacted",
		semconv.AttrAccountName: "gadmin",
		semconv.AttrAccountUpn:  "gadmin@rob-knight.com",
	}
	for k, v := range want {
		got, _ := ev.Attrs[k].(string)
		if got != v {
			t.Errorf("attr %q = %q, want %q", k, got, v)
		}
	}

	// DetailedEntityRole is null → omitted, never emitted empty.
	if _, present := ev.Attrs[semconv.AttrDetailedEntityRole]; present {
		t.Error("detailed_entity_role should be omitted when null")
	}
}

func TestMapRecordEmitsNumericApplicationId(t *testing.T) {
	ev, ok := mapRecord(decode(t, liveCloudApp))
	if !ok {
		t.Fatal("mapRecord dropped a valid record")
	}
	// ApplicationId is a JSON number on this table (not a string as on
	// AlertEvidence) → stamped as a float64.
	if id, ok := ev.Attrs[semconv.AttrApplicationId].(float64); !ok || id != 22110 {
		t.Errorf("application_id = %v, want float64(22110)", ev.Attrs[semconv.AttrApplicationId])
	}
	if got, _ := ev.Attrs[semconv.AttrApplication].(string); got != "Google Cloud Platform" {
		t.Errorf("application = %q, want %q", got, "Google Cloud Platform")
	}
}

func TestMapRecordDropsMalformed(t *testing.T) {
	if _, ok := mapRecord(map[string]any{"time": "2026-07-23T12:41:50Z"}); ok {
		t.Error("record with no properties should be dropped")
	}
	if _, ok := mapRecord(decode(t, `{"properties":{"BehaviorId":"b","Timestamp":"not-a-time"}}`)); ok {
		t.Error("record with unparseable Timestamp should be dropped")
	}
	if _, ok := mapRecord(decode(t, `{"properties":{"BehaviorId":"b"}}`)); ok {
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

// TestCollectorEmitsLiveRecordsEndToEnd drives the whole collector over both
// pinned live rows (User + CloudApplication) — JSON Lines with the CRLF
// terminators Azure writes — and asserts both reach the emitter. This is also
// what makes the signals golden substantive (#164).
func TestCollectorEmitsLiveRecordsEndToEnd(t *testing.T) {
	const tenant = "4b8c18bd-2f9f-4227-af55-9f1061cf9c32"
	blob := compactJSON(t, liveUser) + "\r\n" + compactJSON(t, liveCloudApp) + "\r\n"
	src := &staticSource{
		name: "tenantId=" + tenant + "/y=2026/m=07/d=23/h=12/m=00/PT1H.json",
		data: []byte(blob),
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
	if len(logs) != 2 {
		t.Fatalf("emitted %d records, want 2 — check the tenantId= listing prefix", len(logs))
	}
	if logs[0].EventName != eventName {
		t.Errorf("event name = %q, want %q", logs[0].EventName, eventName)
	}
	if got := logs[0].Attrs[semconv.AttrEntityType]; got != "User" {
		t.Errorf("first record entity_type = %q, want %q", got, "User")
	}

	if err := c.Collect(context.Background(), rec.Emitter()); err != nil {
		t.Fatalf("second Collect: %v", err)
	}
	if got := len(rec.LogRecords()); got != 2 {
		t.Errorf("after a second tick over an unchanged blob: %d records, want 2", got)
	}
}
