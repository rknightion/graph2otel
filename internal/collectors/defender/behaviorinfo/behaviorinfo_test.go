package behaviorinfo

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

// liveRecord is a real BehaviorInfo envelope captured off the m7kni storage
// account as graph2otel-poller (2026-07-23, #241): an ImpossibleTravelActivity
// behavior raised by Defender for Cloud Apps for a named account.
const liveRecord = `{
 "time": "2026-07-23T12:41:41.1578311Z",
 "tenantId": "4b8c18bd-2f9f-4227-af55-9f1061cf9c32",
 "operationName": "Publish",
 "category": "AdvancedHunting-BehaviorInfo",
 "_TimeReceivedBySvc": "2026-07-23T12:41:07.9520000Z",
 "properties": {
  "Timestamp": "2026-07-23T12:41:07.952Z",
  "BehaviorId": "oa4e429c5c782180ae5aeafb5a7c2cff29b62c458a000a84206ca5d548a72f1ff3",
  "ActionType": "ImpossibleTravelActivity",
  "Description": "The user gadmin@rob-knight.com was involved in an impossible travel incident.",
  "Categories": "[\"InitialAccess\"]",
  "AttackTechniques": "[\"Valid Accounts (T1078)\",\"Cloud Accounts (T1078.004)\"]",
  "ServiceSource": "Microsoft Cloud App Security",
  "DetectionSource": "Cloud App Security",
  "DataSources": "[\"Microsoft Cloud App Security\"]",
  "DeviceId": null,
  "AccountUpn": "gadmin@rob-knight.com",
  "AccountObjectId": null,
  "StartTime": "2026-07-23T10:24:31.932Z",
  "EndTime": "2026-07-23T12:09:57.387Z",
  "AdditionalFields": "{}"
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

func TestMapRecordEmitsBehaviorFields(t *testing.T) {
	ev, ok := mapRecord(decode(t, liveRecord))
	if !ok {
		t.Fatal("mapRecord dropped a valid record")
	}
	if ev.Name != eventName {
		t.Errorf("event name = %q, want %q", ev.Name, eventName)
	}

	// Timestamp bound to properties.Timestamp, NOT the envelope clocks.
	wantTS, _ := time.Parse(time.RFC3339Nano, "2026-07-23T12:41:07.952Z")
	if !ev.Timestamp.Equal(wantTS) {
		t.Errorf("timestamp = %v, want %v (bound to properties.Timestamp)", ev.Timestamp, wantTS)
	}

	want := map[string]string{
		semconv.AttrBehaviorId:       "oa4e429c5c782180ae5aeafb5a7c2cff29b62c458a000a84206ca5d548a72f1ff3",
		semconv.AttrActionType:       "ImpossibleTravelActivity",
		semconv.AttrServiceSource:    "Microsoft Cloud App Security",
		semconv.AttrCategories:       `["InitialAccess"]`,
		semconv.AttrAttackTechniques: `["Valid Accounts (T1078)","Cloud Accounts (T1078.004)"]`,
		semconv.AttrAccountUpn:       "gadmin@rob-knight.com",
		semconv.AttrStartTime:        "2026-07-23T10:24:31.932Z",
		semconv.AttrEndTime:          "2026-07-23T12:09:57.387Z",
	}
	for k, v := range want {
		got, _ := ev.Attrs[k].(string)
		if got != v {
			t.Errorf("attr %q = %q, want %q", k, got, v)
		}
	}

	// Null columns are omitted, never emitted empty.
	if _, present := ev.Attrs[semconv.AttrDeviceId]; present {
		t.Error("device_id should be omitted when null")
	}
	if _, present := ev.Attrs[semconv.AttrAccountObjectId]; present {
		t.Error("account_object_id should be omitted when null")
	}
}

func TestMapRecordDropsMalformed(t *testing.T) {
	if _, ok := mapRecord(map[string]any{"time": "2026-07-23T12:41:41Z"}); ok {
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

// TestCollectorEmitsLiveRecordEndToEnd drives the whole collector over the pinned
// live record and asserts what reaches the emitter — this is also what makes the
// signals golden substantive (#164).
func TestCollectorEmitsLiveRecordEndToEnd(t *testing.T) {
	const tenant = "4b8c18bd-2f9f-4227-af55-9f1061cf9c32"
	src := &staticSource{
		name: "tenantId=" + tenant + "/y=2026/m=07/d=23/h=12/m=00/PT1H.json",
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
	if got := logs[0].Attrs[semconv.AttrActionType]; got != "ImpossibleTravelActivity" {
		t.Errorf("action_type = %q, want %q", got, "ImpossibleTravelActivity")
	}

	if err := c.Collect(context.Background(), rec.Emitter()); err != nil {
		t.Fatalf("second Collect: %v", err)
	}
	if got := len(rec.LogRecords()); got != 1 {
		t.Errorf("after a second tick over an unchanged blob: %d records, want 1", got)
	}
}
