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
// the collection is empty on a healthy tenant. This is the ENRICHED form captured
// ~25min after synthesis (the detection populated fields over time: the first read
// had source/detectionTimingType/servicePrincipalDisplayName/appId null and no
// mitreTechniques). Mapping against the richest live form (#164) settles the field
// set: servicePrincipalId/servicePrincipalDisplayName/appId present, ipAddress and
// location null, and additionalInfo is a doubly-encoded string of {Key,Value}
// pairs carrying the MITRE technique. `[live-measured 2026-07-19, #133]`
const liveSPRiskDetection = `{
	"id": "f8a18e4f6139a9c5d4c3a9fcbd311498e0b5ec7c1291fa98862a26e09f3ab71f",
	"requestId": null,
	"correlationId": null,
	"riskEventType": "adminConfirmedServicePrincipalCompromised",
	"riskState": "confirmedCompromised",
	"riskLevel": "high",
	"riskDetail": "adminConfirmedServicePrincipalCompromised",
	"source": "IdentityProtection",
	"detectionTimingType": "offline",
	"activity": "servicePrincipal",
	"tokenIssuerType": "AzureAD",
	"ipAddress": null,
	"activityDateTime": "2026-07-19T18:18:57.9138385Z",
	"detectedDateTime": "2026-07-19T18:18:57.9138385Z",
	"lastUpdatedDateTime": "2026-07-19T18:20:48.7934674Z",
	"servicePrincipalId": "108e1411-1451-4f7d-970a-26bd3c6f67e5",
	"servicePrincipalDisplayName": "g2o-sprisk-synth-DELETE-ME",
	"appId": "0abab089-1400-471e-b44c-e94a3963e5d4",
	"keyIds": [],
	"additionalInfo": "[{\"Key\":\"alertUrl\",\"Value\":null},{\"Key\":\"mitreTechniques\",\"Value\":\"T1078\"}]",
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
		"risk_event_type":        "adminConfirmedServicePrincipalCompromised",
		"risk_state":             "confirmedCompromised",
		"risk_level":             "high",
		"risk_detail":            "adminConfirmedServicePrincipalCompromised",
		"detection_timing_type":  "offline",
		"activity":               "servicePrincipal",
		"token_issuer_type":      "AzureAD",
		"source":                 "IdentityProtection",
		"service_principal_id":   "108e1411-1451-4f7d-970a-26bd3c6f67e5",
		"service_principal_name": "g2o-sprisk-synth-DELETE-ME",
		"app_id":                 "0abab089-1400-471e-b44c-e94a3963e5d4",
	}
	for k, v := range want {
		if got, _ := ev.Attrs[k].(string); got != v {
			t.Errorf("attr %q = %q, want %q", k, got, v)
		}
	}
	// The MITRE technique behind the detection, decoded from the doubly-encoded
	// additionalInfo. Asserted on the Event directly ([]string, not renderable via
	// the recorder's AsString flattening).
	tech, ok := ev.Attrs["mitre_techniques"].([]string)
	if !ok || len(tech) != 1 || tech[0] != "T1078" {
		t.Errorf("mitre_techniques = %#v, want [T1078]", ev.Attrs["mitre_techniques"])
	}
	// Still-null fields must be OMITTED, not emitted empty.
	for _, k := range []string{"ip_address", "request_id", "correlation_id"} {
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
