package directoryaudits

import (
	"encoding/json"
	"testing"
	"time"
)

// blobAuditRecord is a diagnostic-settings AuditLogs envelope shaped after a
// live m7kni sample (2026-07-18, #135): the top-level envelope `time` differs
// from properties.activityDateTime only in serialization (7-digit-frac Z vs
// 6-digit +00:00) — the same instant — and the inner `properties` object is the
// Graph directoryAudit resource mapDirectoryAudit already reads.
const blobAuditRecord = `{
  "time": "2026-07-18T10:55:48.8287460Z",
  "category": "AuditLogs",
  "properties": {
    "id": "Sync_abc_1234",
    "category": "ProvisioningManagement",
    "activityDisplayName": "Execution",
    "activityDateTime": "2026-07-18T10:55:48.828746+00:00",
    "result": "success",
    "loggedByService": "Account Provisioning",
    "correlationId": "11111111-2222-3333-4444-555555555555",
    "initiatedBy": {"app": {"displayName": "Azure AD Cloud Sync"}},
    "targetResources": [{"displayName": "Grafana PS"}]
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

// TestMapBlobDirectoryAuditReusesMapperAndBindsTimestamp is the load-bearing
// test: the blob adapter unwraps properties, delegates to the SAME
// mapDirectoryAudit the polled collector uses (so both transports emit the
// identical record), and binds the timestamp to properties.activityDateTime as
// a parsed instant.
func TestMapBlobDirectoryAuditReusesMapperAndBindsTimestamp(t *testing.T) {
	rec := decodeRec(t, blobAuditRecord)
	ev, ok := mapBlobDirectoryAudit(rec)
	if !ok {
		t.Fatal("mapBlobDirectoryAudit dropped a valid record")
	}
	if ev.Name != eventName {
		t.Errorf("event name = %q, want %q", ev.Name, eventName)
	}

	// Same record the polled path would produce (delegation, not a second mapper).
	props := nested(rec, "properties")
	_, want := mapDirectoryAudit(props)
	if ev.Attrs["id"] != want.Attrs["id"] || ev.Attrs["id"] != "Sync_abc_1234" {
		t.Errorf("id attr = %q, want %q (delegated to mapDirectoryAudit)", ev.Attrs["id"], want.Attrs["id"])
	}
	if ev.Attrs["category"] != "ProvisioningManagement" {
		t.Errorf("category attr = %q, want ProvisioningManagement", ev.Attrs["category"])
	}

	// Timestamp bound to properties.activityDateTime, as an instant.
	wantTS, _ := time.Parse(time.RFC3339Nano, "2026-07-18T10:55:48.828746+00:00")
	if !ev.Timestamp.Equal(wantTS) {
		t.Errorf("timestamp = %v, want %v (bound to activityDateTime)", ev.Timestamp, wantTS)
	}
	// It must NOT be stamped from the differently-serialized envelope `time`
	// string, though for AuditLogs both are the same instant — assert the
	// instant, never the string form.
	if ev.Timestamp.IsZero() {
		t.Error("timestamp is zero — the adapter must set it, the engine no longer does")
	}
}

func TestMapBlobDirectoryAuditDropsMalformed(t *testing.T) {
	// No properties envelope → dropped.
	if _, ok := mapBlobDirectoryAudit(map[string]any{"time": "2026-07-18T10:55:48Z"}); ok {
		t.Error("record with no properties should be dropped")
	}
	// Unparseable activityDateTime → dropped, never mis-dated (no fallback).
	bad := `{"properties":{"id":"x","activityDateTime":"not-a-time"}}`
	if _, ok := mapBlobDirectoryAudit(decodeRec(t, bad)); ok {
		t.Error("record with unparseable activityDateTime should be dropped, not mis-dated")
	}
	// Missing activityDateTime → dropped.
	none := `{"properties":{"id":"x"}}`
	if _, ok := mapBlobDirectoryAudit(decodeRec(t, none)); ok {
		t.Error("record with no activityDateTime should be dropped")
	}
}
