package cloudapp

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

// liveRecord is a real CloudAppEvents envelope captured off the m7kni storage
// account as graph2otel-poller (cert on camden, 2026-07-18, #106): a Google
// Workspace (Gmail) OAuth activity routed through Defender for Cloud Apps'
// app connector, with a nested RawEventData payload (the underlying Google
// admin-report event) and an AdditionalFields object. DeviceType, OSPlatform,
// UserAgent, ObjectName/Type/Id, OAuthAppId, UserAgentTags, and SessionData
// are all JSON null on this record — the full "mostly absent" shape a mapper
// must handle without emitting empty strings.
const liveRecord = `{
  "time": "2026-07-18T17:00:07.0526253Z",
  "tenantId": "4b8c18bd-2f9f-4227-af55-9f1061cf9c32",
  "operationName": "Publish",
  "category": "AdvancedHunting-CloudAppEvents",
  "_TimeReceivedBySvc": "2026-07-18T16:57:49.2390000Z",
  "properties": {
   "ActionType": "activity",
   "ApplicationId": 11770,
   "AccountDisplayName": "Rob Knight",
   "AccountObjectId": "bbcfc3c5-0b93-4135-9ef9-18477a9fb504",
   "AccountId": "bbcfc3c5-0b93-4135-9ef9-18477a9fb504",
   "DeviceType": null,
   "OSPlatform": null,
   "IPAddress": "52.252.113.251",
   "IsAnonymousProxy": false,
   "CountryCode": "US",
   "City": "boydton",
   "ISP": "Microsoft Azure",
   "UserAgent": null,
   "IsAdminOperation": false,
   "ActivityObjects": [
    {
     "Type": "User",
     "Role": "Actor",
     "Name": "Rob Knight",
     "Id": "bbcfc3c5-0b93-4135-9ef9-18477a9fb504",
     "ApplicationId": 11161,
     "ApplicationInstance": 0
    }
   ],
   "AdditionalFields": {
    "IsSatelliteProvider": false
   },
   "ActivityType": "Basic",
   "ObjectName": null,
   "ObjectType": null,
   "ObjectId": null,
   "AppInstanceId": 0,
   "AccountType": "Admin",
   "IsExternalUser": false,
   "IsImpersonated": false,
   "IPTags": [
    "Microsoft Azure"
   ],
   "IPCategory": "Cloud provider",
   "UserAgentTags": null,
   "RawEventData": {
    "actor": {
     "email": "rob@rob-knight.com",
     "profileId": "113743468328235846806"
    },
    "etag": "\"MuBF61fZ6eIjI81hoRhKEXyx1naL3QsylnH3YakomIY/7ELyXqXc9f6Q_Bd14tLeBngL0Wo\"",
    "events": [
     {
      "name": "activity",
      "parameters": [
       {
        "name": "api_name",
        "value": "gmail"
       },
       {
        "name": "method_name",
        "value": "gmail.users.history.list"
       },
       {
        "name": "client_id",
        "value": "77377267392-9l01lg5gpscp40cc30cc5gke03n6uu3b.apps.googleusercontent.com"
       },
       {
        "intValue": 5,
        "name": "num_response_bytes"
       },
       {
        "name": "product_bucket",
        "value": "GMAIL"
       },
       {
        "name": "app_name",
        "value": "OpenAI"
       },
       {
        "name": "client_type",
        "value": "WEB"
       }
      ],
      "type": "auth"
     }
    ],
    "id": {
     "applicationName": "token",
     "customerId": "C015ajidn",
     "time": {
      "dateOnly": false,
      "timeZoneShift": 0,
      "value": 1784393869239
     },
     "uniqueQualifier": -640236721980338696
    },
    "ipAddress": "52.252.113.251",
    "kind": "admin#reports#activity",
    "networkInfo": {
     "ipAsn": [
      8075
     ],
     "regionCode": "US",
     "subdivisionCode": "US-VA"
    }
   },
   "UncommonForUser": [],
   "LastSeenForUser": {
    "ActionType": 0,
    "ISP": 0,
    "IPAddress": 0,
    "Application": 0
   },
   "SessionData": null,
   "AuditSource": "Defender for Cloud Apps app connector",
   "OAuthAppId": null,
   "ReportId": "d87bb92a1ffaaa19f57bdfd48b78af0127742d2a46244dd4dbaeba64521af829_11770",
   "Timestamp": "2026-07-18T16:57:49.239Z",
   "Application": "Google Workspace"
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

func TestMapRecordEmitsCloudAppActivity(t *testing.T) {
	ev, ok := mapRecord(decode(t, liveRecord))
	if !ok {
		t.Fatal("mapRecord dropped a valid record")
	}
	if ev.Name != eventName {
		t.Errorf("event name = %q, want %q", ev.Name, eventName)
	}

	// Timestamp bound to properties.Timestamp, as an instant — NOT the envelope
	// `time` or `_TimeReceivedBySvc`.
	wantTS, _ := time.Parse(time.RFC3339Nano, "2026-07-18T16:57:49.239Z")
	if !ev.Timestamp.Equal(wantTS) {
		t.Errorf("timestamp = %v, want %v (bound to properties.Timestamp)", ev.Timestamp, wantTS)
	}

	want := map[string]string{
		semconv.AttrActionType:         "activity",
		semconv.AttrActivityType:       "Basic",
		semconv.AttrApplication:        "Google Workspace",
		semconv.AttrAccountDisplayName: "Rob Knight",
		semconv.AttrAccountObjectId:    "bbcfc3c5-0b93-4135-9ef9-18477a9fb504",
		semconv.AttrIpAddress:          "52.252.113.251",
		semconv.AttrCountryCode:        "US",
		semconv.AttrCity:               "boydton",
		semconv.AttrIsp:                "Microsoft Azure",
		semconv.AttrAccountType:        "Admin",
		semconv.AttrIpCategory:         "Cloud provider",
		semconv.AttrAuditSource:        "Defender for Cloud Apps app connector",
		semconv.AttrReportId:           "d87bb92a1ffaaa19f57bdfd48b78af0127742d2a46244dd4dbaeba64521af829_11770",
	}
	for k, v := range want {
		got, _ := ev.Attrs[k].(string)
		if got != v {
			t.Errorf("attr %q = %q, want %q", k, got, v)
		}
	}

	// Numeric fields land as numbers, not strings.
	if id, ok := ev.Attrs[semconv.AttrApplicationId].(float64); !ok || id != 11770 {
		t.Errorf("application_id = %v, want float64(11770)", ev.Attrs[semconv.AttrApplicationId])
	}

	// Bool fields are stamped as the string "false"/"true".
	if got, _ := ev.Attrs[semconv.AttrIsAdminOperation].(string); got != "false" {
		t.Errorf("is_admin_operation = %q, want \"false\"", got)
	}

	// The object-shaped columns re-marshal to non-empty JSON strings.
	raw, _ := ev.Attrs[semconv.AttrRawEventData].(string)
	if raw == "" {
		t.Fatal("raw_event_data should be present and non-empty")
	}
	if !strings.Contains(raw, "gmail.users.history.list") {
		t.Errorf("raw_event_data = %q, want it to contain the nested Google event payload", raw)
	}
	if got, _ := ev.Attrs[semconv.AttrAdditionalFields].(string); got == "" {
		t.Error("additional_fields should be present and non-empty")
	}
	if got, _ := ev.Attrs[semconv.AttrActivityObjects].(string); got == "" {
		t.Error("activity_objects should be present and non-empty")
	}
	if got, _ := ev.Attrs[semconv.AttrLastSeenForUser].(string); got == "" {
		t.Error("last_seen_for_user should be present and non-empty")
	}

	// The native-array column (non-empty) lands as a string list.
	if tags, ok := ev.Attrs[semconv.AttrIpTags].([]string); !ok || len(tags) != 1 || tags[0] != "Microsoft Azure" {
		t.Errorf("ip_tags = %v, want []string{\"Microsoft Azure\"}", ev.Attrs[semconv.AttrIpTags])
	}

	// Null/empty columns are omitted, never emitted as empty/zero values.
	for _, k := range []string{
		semconv.AttrDeviceType, semconv.AttrOsPlatform, semconv.AttrUserAgent,
		semconv.AttrObjectName, semconv.AttrObjectType, semconv.AttrObjectId,
		semconv.AttrOauthAppId, semconv.AttrUserAgentTags, semconv.AttrSessionData,
		semconv.AttrUncommonForUser,
	} {
		if _, present := ev.Attrs[k]; present {
			t.Errorf("attr %q should be omitted (null/empty source), got %v", k, ev.Attrs[k])
		}
	}
}

func TestMapRecordDropsMalformed(t *testing.T) {
	// No properties → dropped.
	if _, ok := mapRecord(map[string]any{"time": "2026-07-18T17:00:07Z"}); ok {
		t.Error("record with no properties should be dropped")
	}
	// Unparseable Timestamp → dropped, never mis-dated (no fallback to envelope time).
	if _, ok := mapRecord(decode(t, `{"properties":{"ActionType":"activity","Timestamp":"not-a-time"}}`)); ok {
		t.Error("record with unparseable Timestamp should be dropped")
	}
	// Missing Timestamp → dropped.
	if _, ok := mapRecord(decode(t, `{"properties":{"ActionType":"activity"}}`)); ok {
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
// pinned live record — JSON Lines with the CRLF terminators Azure writes —
// and asserts what reaches the emitter. It is also what makes the signals
// golden substantive (#164): the golden captures the attributes THIS drives
// into the Recorder.
func TestCollectorEmitsLiveRecordEndToEnd(t *testing.T) {
	const tenant = "4b8c18bd-2f9f-4227-af55-9f1061cf9c32"
	src := &staticSource{
		name: "tenantId=" + tenant + "/y=2026/m=07/d=18/h=17/m=00/PT1H.json",
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
	wantTS, _ := time.Parse(time.RFC3339Nano, "2026-07-18T16:57:49.239Z")
	if !logs[0].Timestamp.Equal(wantTS) {
		t.Errorf("timestamp = %s, want %s", logs[0].Timestamp, wantTS)
	}
	if got := logs[0].Attrs[semconv.AttrApplication]; got != "Google Workspace" {
		t.Errorf("application attr = %q, want Google Workspace", got)
	}

	// Cursor persisted: a second tick over the unchanged blob emits nothing new.
	if err := c.Collect(context.Background(), rec.Emitter()); err != nil {
		t.Fatalf("second Collect: %v", err)
	}
	if got := len(rec.LogRecords()); got != 1 {
		t.Errorf("after a second tick over an unchanged blob: %d records, want 1", got)
	}
}
