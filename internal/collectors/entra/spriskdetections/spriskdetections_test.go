package spriskdetections

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/rknightion/graph2otel/internal/checkpoint"
	"github.com/rknightion/graph2otel/internal/collectors"
	"github.com/rknightion/graph2otel/internal/telemetry"
	"github.com/rknightion/graph2otel/internal/telemetrytest"
)

// liveSPRiskDetection is a VERBATIM GET /identityProtection/servicePrincipalRiskDetections
// record from m7kni, read as graph2otel-poller on 2026-07-19. It is the detection
// #133 synthesized by admin-confirming compromise of a throwaway service principal
// — the ONLY real servicePrincipalRiskDetection this project has observed, since
// the collection is empty on a healthy tenant. Mapping against it (not the docs)
// settles the field set: servicePrincipalId is present, servicePrincipalDisplayName
// / appId / ipAddress / location are null on this admin-confirmed type, and
// additionalInfo is a doubly-encoded string (here `[{"Key":"alertUrl","Value":null}]`)
// deliberately left undecoded. `[live-measured 2026-07-19, #133]`
const liveSPRiskDetection = `{
	"id": "f8a18e4f6139a9c5d4c3a9fcbd311498e0b5ec7c1291fa98862a26e09f3ab71f",
	"requestId": null,
	"correlationId": null,
	"riskEventType": "adminConfirmedServicePrincipalCompromised",
	"riskState": "confirmedCompromised",
	"riskLevel": "high",
	"riskDetail": "adminConfirmedServicePrincipalCompromised",
	"source": null,
	"detectionTimingType": "notDefined",
	"activity": "servicePrincipal",
	"tokenIssuerType": "AzureAD",
	"ipAddress": null,
	"activityDateTime": "2026-07-19T18:18:57.9138385Z",
	"detectedDateTime": "2026-07-19T18:18:57.9138385Z",
	"lastUpdatedDateTime": "2026-07-19T18:20:48.7934674Z",
	"servicePrincipalId": "108e1411-1451-4f7d-970a-26bd3c6f67e5",
	"servicePrincipalDisplayName": null,
	"appId": null,
	"keyIds": [],
	"additionalInfo": "[{\"Key\":\"alertUrl\",\"Value\":null}]",
	"location": null
}`

func decodeLive(t *testing.T, raw string) map[string]any {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal([]byte(raw), &m); err != nil {
		t.Fatalf("decode live record: %v", err)
	}
	return m
}

// TestMapAgainstLiveRecord pins the mapper's output against the verbatim row: the
// present fields map, and the null fields (servicePrincipalDisplayName, appId,
// ipAddress) are omitted rather than emitted empty.
func TestMapAgainstLiveRecord(t *testing.T) {
	id, ev := mapSPRiskDetection(decodeLive(t, liveSPRiskDetection))
	if id != "f8a18e4f6139a9c5d4c3a9fcbd311498e0b5ec7c1291fa98862a26e09f3ab71f" {
		t.Errorf("id = %q", id)
	}
	want := map[string]string{
		"risk_event_type":       "adminConfirmedServicePrincipalCompromised",
		"risk_state":            "confirmedCompromised",
		"risk_level":            "high",
		"risk_detail":           "adminConfirmedServicePrincipalCompromised",
		"detection_timing_type": "notDefined",
		"activity":              "servicePrincipal",
		"token_issuer_type":     "AzureAD",
		"service_principal_id":  "108e1411-1451-4f7d-970a-26bd3c6f67e5",
	}
	for k, v := range want {
		if got, _ := ev.Attrs[k].(string); got != v {
			t.Errorf("attr %q = %q, want %q", k, got, v)
		}
	}
	// Null fields must be OMITTED, not emitted empty.
	for _, k := range []string{"service_principal_name", "app_id", "ip_address", "source", "request_id", "correlation_id"} {
		if _, present := ev.Attrs[k]; present {
			t.Errorf("attr %q present, want omitted (null on the wire)", k)
		}
	}
	if ev.Severity != telemetry.SeverityError {
		t.Errorf("severity = %v, want Error (high risk_level)", ev.Severity)
	}
}

// recordingFetcher is a logpipeline.PageFetcher returning a fixed record set.
type recordingFetcher struct{ records []map[string]any }

func (f *recordingFetcher) FetchPage(_ context.Context, _ string) ([]map[string]any, string, error) {
	return f.records, "", nil
}

// TestCollectorEmitsLiveRecordEndToEnd drives the verbatim record through the
// collector into a Recorder — the #164 shape (drive the live fixture end-to-end,
// not just into the mapper) so the golden reflects the real emission.
func TestCollectorEmitsLiveRecordEndToEnd(t *testing.T) {
	f := &recordingFetcher{records: []map[string]any{decodeLive(t, liveSPRiskDetection)}}
	rec := telemetrytest.New()
	c := newCollector(collectors.WindowDeps{TenantID: "t1", Fetcher: f, Store: checkpoint.NewStore(t.TempDir())})

	from := time.Date(2026, 7, 19, 18, 0, 0, 0, time.UTC)
	if _, err := c.CollectWindow(context.Background(), from, from.Add(time.Hour), rec.Emitter()); err != nil {
		t.Fatalf("CollectWindow: %v", err)
	}
	logs := rec.LogRecords()
	if len(logs) != 1 {
		t.Fatalf("emitted %d records, want 1", len(logs))
	}
	got := logs[0]
	if got.EventName != eventName {
		t.Errorf("event name = %q, want %q", got.EventName, eventName)
	}
	if got.Attrs["service_principal_id"] != "108e1411-1451-4f7d-970a-26bd3c6f67e5" {
		t.Errorf("service_principal_id = %q", got.Attrs["service_principal_id"])
	}
	if got.Attrs["risk_event_type"] != "adminConfirmedServicePrincipalCompromised" {
		t.Errorf("risk_event_type = %q", got.Attrs["risk_event_type"])
	}
}

// TestPermissionsAndName pins the least-privilege scope and stable name.
func TestPermissionsAndName(t *testing.T) {
	c := newCollector(collectors.WindowDeps{TenantID: "t1"})
	if c.Name() != collectorName {
		t.Errorf("name = %q, want %q", c.Name(), collectorName)
	}
	perms := c.RequiredPermissions()
	if len(perms) != 1 || perms[0] != "IdentityRiskyServicePrincipal.Read.All" {
		t.Errorf("permissions = %v, want [IdentityRiskyServicePrincipal.Read.All]", perms)
	}
}
