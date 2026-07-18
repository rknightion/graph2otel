package provisioning

import (
	"encoding/json"
	"reflect"
	"testing"
	"time"
)

// blobProvisioningRecord is a diagnostic-settings ProvisioningLogs envelope
// shaped after a live m7kni sample (2026-07-18, #135): the inner `properties`
// object carries the full Graph provisioning resource mapProvisioning reads.
const blobProvisioningRecord = `{
  "time": "2026-07-17T13:03:13.4270244Z",
  "category": "ProvisioningLogs",
  "properties": {
    "id": "prov-0001",
    "jobId": "job-abc",
    "cycleId": "cycle-xyz",
    "changeId": "chg-1",
    "activityDateTime": "2026-07-17T13:03:13.4270244Z",
    "provisioningAction": "create",
    "provisioningStatusInfo": {"status": "success"},
    "sourceIdentity": {"id": "src-1", "displayName": "Source User"},
    "targetIdentity": {"id": "tgt-1", "displayName": "Target User"},
    "servicePrincipal": {"id": "sp-1", "displayName": "Provisioning App"},
    "modifiedProperties": [{"displayName": "accountEnabled"}]
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

// TestMapBlobProvisioningReusesMapperAndBindsTimestamp: the blob adapter unwraps
// properties, delegates to the SAME mapProvisioning the polled collector uses
// (asserted by DeepEqual on the attribute set), and binds the timestamp to
// properties.activityDateTime as a parsed instant.
func TestMapBlobProvisioningReusesMapperAndBindsTimestamp(t *testing.T) {
	rec := decodeRec(t, blobProvisioningRecord)
	ev, ok := mapBlobProvisioning(rec)
	if !ok {
		t.Fatal("mapBlobProvisioning dropped a valid record")
	}
	if ev.Name != eventName {
		t.Errorf("event name = %q, want %q", ev.Name, eventName)
	}

	props := nested(rec, "properties")
	_, want := mapProvisioning(props)
	if !reflect.DeepEqual(ev.Attrs, want.Attrs) {
		t.Errorf("blob attrs != polled attrs (delegation broken):\n blob=%v\n want=%v", ev.Attrs, want.Attrs)
	}

	wantTS, _ := time.Parse(time.RFC3339Nano, "2026-07-17T13:03:13.4270244Z")
	if !ev.Timestamp.Equal(wantTS) {
		t.Errorf("timestamp = %v, want %v (bound to activityDateTime)", ev.Timestamp, wantTS)
	}
}

func TestMapBlobProvisioningDropsMalformed(t *testing.T) {
	if _, ok := mapBlobProvisioning(map[string]any{"time": "2026-07-17T13:03:13Z"}); ok {
		t.Error("record with no properties should be dropped")
	}
	if _, ok := mapBlobProvisioning(decodeRec(t, `{"properties":{"id":"x","activityDateTime":"nope"}}`)); ok {
		t.Error("record with unparseable activityDateTime should be dropped")
	}
}
