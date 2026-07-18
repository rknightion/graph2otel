package riskdetections

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/rknightion/graph2otel/internal/semconv"
)

// blobUserRiskEvent is a UserRiskEvents diagnostic-settings envelope captured
// live off m7kni (2026-07-18, #135) — the #129 synthesized detection. The inner
// `properties` object is the riskDetection resource mapRiskDetection already
// reads; it additionally carries `riskType` (blob-only, a duplicate of
// riskEventType — CLAUDE.md), which must not perturb the mapping.
const blobUserRiskEvent = `{
  "time": "7/18/2026 2:03:03 PM",
  "category": "UserRiskEvents",
  "operationName": "User Risk Detection",
  "tenantId": "4b8c18bd-2f9f-4227-af55-9f1061cf9c32",
  "properties": {
    "id": "a3f515c85e608499eed7b9ae5aab006a53c56bebe75d2ed800f5d8ad632f93d7",
    "riskType": "maliciousIPAddress",
    "riskEventType": "maliciousIPAddress",
    "riskState": "atRisk",
    "riskLevel": "high",
    "riskDetail": "none",
    "source": "IdentityProtection",
    "detectionTimingType": "offline",
    "activity": "signin",
    "ipAddress": "2001:67c:e60:c0c:192:42:116:55",
    "location": {
      "city": "Camperduin",
      "state": "Noord-Holland",
      "countryOrRegion": "NL",
      "geoCoordinates": { "latitude": 52.733, "longitude": 4.65 }
    },
    "activityDateTime": "2026-07-17T10:07:37.729Z",
    "detectedDateTime": "2026-07-18T13:45:09.533Z",
    "userId": "5289e9c7-3945-4ffd-8fd3-d56124baf45d",
    "userDisplayName": "RISK SYNTH - DELETE ME (graph2otel #129)",
    "userPrincipalName": "risk-synth-DELETE-ME@m7kni.io",
    "additionalInfo": "[{\"Key\":\"userAgent\",\"Value\":\"Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:140.0) Gecko/20100101 Firefox/140.0\"},{\"Key\":\"mitreTechniques\",\"Value\":\"T1078\"}]",
    "tokenIssuerType": "AzureAD"
  }
}`

func decodeRec(t *testing.T, body string) map[string]any {
	t.Helper()
	var rec map[string]any
	if err := json.Unmarshal([]byte(body), &rec); err != nil {
		t.Fatalf("decode: %v", err)
	}
	return rec
}

// TestMapBlobRiskDetectionReusesMapperAndBindsTimestamp is the load-bearing test:
// the blob adapter unwraps properties, delegates to the SAME mapRiskDetection the
// polled collector uses (so both transports emit the identical record), and binds
// the timestamp to properties.detectedDateTime as a parsed instant.
func TestMapBlobRiskDetectionReusesMapperAndBindsTimestamp(t *testing.T) {
	rec := decodeRec(t, blobUserRiskEvent)
	ev, ok := mapBlobRiskDetection(rec)
	if !ok {
		t.Fatal("mapBlobRiskDetection dropped a valid record")
	}
	if ev.Name != eventName {
		t.Errorf("event name = %q, want %q", ev.Name, eventName)
	}

	// Same record the polled path would produce (delegation, not a second mapper).
	props := nested(rec, "properties")
	_, want := mapRiskDetection(props)
	if ev.Attrs[semconv.AttrRiskEventType] != want.Attrs[semconv.AttrRiskEventType] ||
		ev.Attrs[semconv.AttrRiskEventType] != "maliciousIPAddress" {
		t.Errorf("risk_event_type = %v, want maliciousIPAddress (delegated to mapRiskDetection)", ev.Attrs[semconv.AttrRiskEventType])
	}
	if ev.Attrs[semconv.AttrUserPrincipalName] != "risk-synth-DELETE-ME@m7kni.io" {
		t.Errorf("user_principal_name = %v, want the synth UPN", ev.Attrs[semconv.AttrUserPrincipalName])
	}

	// Timestamp bound to detectedDateTime, as an instant.
	wantTS, _ := time.Parse(time.RFC3339Nano, "2026-07-18T13:45:09.533Z")
	if !ev.Timestamp.Equal(wantTS) {
		t.Errorf("timestamp = %v, want %v (bound to detectedDateTime)", ev.Timestamp, wantTS)
	}
	if ev.Timestamp.IsZero() {
		t.Error("timestamp is zero — the adapter must set it, the engine no longer does")
	}
}

// A record with no parseable detectedDateTime is dropped, never stamped with
// arrival time (CLAUDE.md: misdated is wrong, only wrong justifies a drop).
func TestMapBlobRiskDetectionDropsUndatedRecord(t *testing.T) {
	rec := decodeRec(t, `{"category":"UserRiskEvents","properties":{"id":"x","riskEventType":"none"}}`)
	if _, ok := mapBlobRiskDetection(rec); ok {
		t.Error("record with no detectedDateTime should be dropped, not stamped")
	}
}

// A record with no properties envelope is dropped.
func TestMapBlobRiskDetectionDropsEnvelopeless(t *testing.T) {
	rec := decodeRec(t, `{"category":"UserRiskEvents"}`)
	if _, ok := mapBlobRiskDetection(rec); ok {
		t.Error("record with no properties should be dropped")
	}
}
