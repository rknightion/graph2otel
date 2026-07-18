package risk

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/rknightion/graph2otel/internal/semconv"
	"github.com/rknightion/graph2otel/internal/telemetrytest"
)

// blobRiskyUser is a RiskyUsers diagnostic-settings envelope captured live off
// m7kni (2026-07-18, #135). The inner `properties` object uses the same field
// names as the Graph riskyUser resource, so it decodes into riskyEntity and
// renders through the same logTwin the polled path uses.
const blobRiskyUser = `{
  "time": "7/18/2026 3:01:38 PM",
  "category": "RiskyUsers",
  "operationName": "Risky user",
  "tenantId": "4b8c18bd-2f9f-4227-af55-9f1061cf9c32",
  "properties": {
    "id": "0a85025c-4238-4148-978f-587a8dd7960e",
    "userDisplayName": "g2o seed test",
    "userPrincipalName": "g2o-seed-test@m7knio.onmicrosoft.com",
    "riskLastUpdatedDateTime": "2026-07-18T15:01:38.240Z",
    "riskState": "remediated",
    "riskDetail": "userPerformedSecuredPasswordReset",
    "riskLevel": "none",
    "isDeleted": false,
    "isProcessing": false
  }
}`

func decodeBlobRec(t *testing.T, body string) map[string]any {
	t.Helper()
	var rec map[string]any
	if err := json.Unmarshal([]byte(body), &rec); err != nil {
		t.Fatalf("decode: %v", err)
	}
	return rec
}

// TestMapBlobRiskyUserReusesLogTwinAndBindsTimestamp: the blob adapter delegates
// to the SAME logTwin the polled collector uses (identical record), and stamps
// the event time from riskLastUpdatedDateTime (NOT "now" — the blob is an
// append-only stream, each record emitted once).
func TestMapBlobRiskyUserReusesLogTwinAndBindsTimestamp(t *testing.T) {
	ev, ok := mapBlobRiskyUser(decodeBlobRec(t, blobRiskyUser))
	if !ok {
		t.Fatal("mapBlobRiskyUser dropped a valid record")
	}
	if ev.Name != eventRiskyUser {
		t.Errorf("event name = %q, want %q", ev.Name, eventRiskyUser)
	}
	if ev.Attrs[semconv.AttrUserPrincipalName] != "g2o-seed-test@m7knio.onmicrosoft.com" {
		t.Errorf("upn = %v", ev.Attrs[semconv.AttrUserPrincipalName])
	}
	if ev.Attrs[semconv.AttrRiskState] != "remediated" {
		t.Errorf("risk_state = %v, want remediated", ev.Attrs[semconv.AttrRiskState])
	}
	wantTS, _ := time.Parse(time.RFC3339Nano, "2026-07-18T15:01:38.240Z")
	if !ev.Timestamp.Equal(wantTS) {
		t.Errorf("timestamp = %v, want %v (riskLastUpdatedDateTime, not now)", ev.Timestamp, wantTS)
	}
}

func TestMapBlobRiskyUserDropsUndated(t *testing.T) {
	rec := decodeBlobRec(t, `{"category":"RiskyUsers","properties":{"id":"x","riskLevel":"high"}}`)
	if _, ok := mapBlobRiskyUser(rec); ok {
		t.Error("record with no riskLastUpdatedDateTime should be dropped, not stamped now")
	}
}

func TestMapBlobRiskyUserDropsEnvelopeless(t *testing.T) {
	if _, ok := mapBlobRiskyUser(decodeBlobRec(t, `{"category":"RiskyUsers"}`)); ok {
		t.Error("record with no properties should be dropped")
	}
}

// TestSuppressedTwinKeepsGaugeDropsLog is the load-bearing guard test (#135-C):
// with the risky_user twin suppressed (a blob collector owns it), the polled
// collector still emits its bounded gauge but NOT the per-entity log — so the
// record is never double-shipped, and the count is unaffected.
func TestSuppressedTwinKeepsGaugeDropsLog(t *testing.T) {
	rec := telemetrytest.New()
	c := New(liveFixture(), bothCaps(), nil)
	c.suppressedTwins = map[string]bool{eventRiskyUser: true}
	if err := c.Collect(context.Background(), rec.Emitter()); err != nil {
		t.Fatalf("Collect: %v", err)
	}

	// Gauge is unaffected — the entity is still counted.
	if pts := rec.MetricPoints(metricRiskyUsers); len(pts) == 0 {
		t.Errorf("%s gauge must still emit when the twin is suppressed", metricRiskyUsers)
	}
	// But no risky_user per-entity log twin.
	for _, l := range rec.LogRecords() {
		if l.EventName == eventRiskyUser {
			t.Errorf("emitted a %s log twin despite suppression — the blob owns it", eventRiskyUser)
		}
	}
}

// Without suppression (the default), the polled twin still emits — the guard is
// opt-in and does not change default behavior.
func TestUnsuppressedTwinStillEmits(t *testing.T) {
	rec := telemetrytest.New()
	c := New(liveFixture(), bothCaps(), nil) // suppressedTwins nil
	if err := c.Collect(context.Background(), rec.Emitter()); err != nil {
		t.Fatalf("Collect: %v", err)
	}
	saw := false
	for _, l := range rec.LogRecords() {
		if l.EventName == eventRiskyUser {
			saw = true
		}
	}
	if !saw {
		t.Error("default (no suppression) must still emit the risky_user twin")
	}
}
