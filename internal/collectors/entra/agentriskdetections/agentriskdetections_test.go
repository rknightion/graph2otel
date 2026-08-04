package agentriskdetections

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/rknightion/graph2otel/internal/checkpoint"
	"github.com/rknightion/graph2otel/internal/collectors"
	"github.com/rknightion/graph2otel/internal/recordoutcome"
	"github.com/rknightion/graph2otel/internal/telemetry"
	"github.com/rknightion/graph2otel/internal/telemetrytest"
)

// liveAgentRiskDetection is a VERBATIM GET /beta/identityProtection/agentRiskDetections
// record from m7kni, read as graph2otel-poller on 2026-07-20. It is the detection
// #133 synthesized by admin-confirming compromise of the "testagent" Entra Agent
// ID identity (Agent 365 trial) — the ONLY real agentRiskDetection this project
// has observed, since the collection is empty on a healthy tenant. This is the
// ENRICHED form captured ~3min after synthesis: the first read had displayName/
// agentDisplayName empty, detectionTimingType "notDefined", source null and no
// mitreTechniques; they populated over time. Mapping against the richest live
// form (#164) settles the field set — additionalInfo is a doubly-encoded string
// of {Key,Value} pairs carrying the MITRE technique, identical to the SP and user
// detections. `[live-measured 2026-07-20, #133]`
const liveAgentRiskDetection = `{
	"id": "57351803f2c982e317214ec26c3760c8f5512f3f036e442e470aa37e1005e744",
	"identityType": "agentIdentity",
	"blueprintId": null,
	"identityId": "7d5472af-9f94-4b62-bbc2-bfbecbd2aad8",
	"agentId": "7d5472af-9f94-4b62-bbc2-bfbecbd2aad8",
	"displayName": "testagent",
	"agentDisplayName": "testagent",
	"activityDateTime": "2026-07-20T18:31:02.5229451Z",
	"detectedDateTime": "2026-07-20T18:31:02.5229451Z",
	"detectionTimingType": "offline",
	"lastModifiedDateTime": "2026-07-20T18:33:49.3467482Z",
	"riskDetail": "adminConfirmedAgentCompromised",
	"riskLevel": "high",
	"riskState": "confirmedCompromised",
	"riskEventType": "adminConfirmedAgentCompromised",
	"riskEvidence": "Admin confirmed agent compromised",
	"additionalInfo": "[{\"Key\":\"alertUrl\",\"Value\":null},{\"Key\":\"mitreTechniques\",\"Value\":\"T1078\"}]",
	"signInCorrelationId": null,
	"signInClientDisplayName": null,
	"clientSessionId": null,
	"signInRequestId": null,
	"source": "IdentityProtection"
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
// present fields map, and the null fields (the signIn* correlation ids) are
// omitted rather than emitted empty.
func TestMapAgainstLiveRecord(t *testing.T) {
	id, ev := mapAgentRiskDetection(decodeLive(t, liveAgentRiskDetection))
	if id != "57351803f2c982e317214ec26c3760c8f5512f3f036e442e470aa37e1005e744" {
		t.Errorf("id = %q", id)
	}
	want := map[string]string{
		"risk_event_type":       "adminConfirmedAgentCompromised",
		"risk_state":            "confirmedCompromised",
		"risk_level":            "high",
		"risk_detail":           "adminConfirmedAgentCompromised",
		"risk_evidence":         "Admin confirmed agent compromised",
		"detection_timing_type": "offline",
		"source":                "IdentityProtection",
		"identity_type":         "agentIdentity",
		"agent_id":              "7d5472af-9f94-4b62-bbc2-bfbecbd2aad8",
		"agent_display_name":    "testagent",
	}
	for k, v := range want {
		if got, _ := ev.Attrs[k].(string); got != v {
			t.Errorf("attr %q = %q, want %q", k, got, v)
		}
	}
	// The MITRE technique behind the detection, decoded from the doubly-encoded
	// additionalInfo. Asserted on the Event directly ([]string).
	tech, ok := ev.Attrs["mitre_techniques"].([]string)
	if !ok || len(tech) != 1 || tech[0] != "T1078" {
		t.Errorf("mitre_techniques = %#v, want [T1078]", ev.Attrs["mitre_techniques"])
	}
	// Null / blueprint-absent fields must be OMITTED, not emitted empty.
	for _, k := range []string{"blueprint_id", "sign_in_correlation_id", "client_session_id"} {
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
// collector into a Recorder (#164) so the golden reflects the real emission.
func TestCollectorEmitsLiveRecordEndToEnd(t *testing.T) {
	f := &recordingFetcher{records: []map[string]any{decodeLive(t, liveAgentRiskDetection)}}
	rec := telemetrytest.New()
	c := newCollector(collectors.WindowDeps{TenantID: "t1", Fetcher: f, Store: checkpoint.NewStore(t.TempDir())})

	from := time.Date(2026, 7, 20, 18, 0, 0, 0, time.UTC)
	if _, err := c.CollectWindow(context.Background(), from, from.Add(time.Hour), rec.Emitter(), nil); err != nil {
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
	if got.Attrs["agent_id"] != "7d5472af-9f94-4b62-bbc2-bfbecbd2aad8" {
		t.Errorf("agent_id = %q", got.Attrs["agent_id"])
	}
	if got.Attrs["risk_event_type"] != "adminConfirmedAgentCompromised" {
		t.Errorf("risk_event_type = %q", got.Attrs["risk_event_type"])
	}
}

// forbiddenFetcher returns the VERBATIM 403 body m7kni's poller received on
// 2026-08-04, once the tenant lost the agent-risk preview entitlement.
type forbiddenFetcher struct{ calls int }

func (f *forbiddenFetcher) FetchPage(_ context.Context, _ string) ([]map[string]any, string, error) {
	f.calls++
	return nil, "", errors.New(
		"graphclient: GET https://graph.microsoft.com/beta/identityProtection/agentRiskDetections?%24top=500: " +
			`status 403: {"error":{"code":"Forbidden","message":"Your tenant is not licensed for this feature."}}`,
	)
}

// TestCollectWindowDeclinesOn403 pins #408: agentRiskDetections is a beta preview
// a tenant may simply not be licensed for, exactly like its sibling
// entra.risky_agents. A 403 is a permanent tenant fact, so the collector declines
// the window — records permission_denied, returns nil, and does not advance the
// watermark — rather than returning an error every 30 minutes forever.
func TestCollectWindowDeclinesOn403(t *testing.T) {
	f := &forbiddenFetcher{}
	rec := telemetrytest.New()
	c := newCollector(collectors.WindowDeps{TenantID: "t1", Fetcher: f, Store: checkpoint.NewStore(t.TempDir())})

	outcomes := recordoutcome.NewRecorder()
	from := time.Date(2026, 8, 4, 17, 0, 0, 0, time.UTC)
	to := from.Add(time.Hour)
	got, err := c.CollectWindow(context.Background(), from, to, rec.Emitter(), outcomes)
	if err != nil {
		t.Fatalf("CollectWindow on a 403 = %v, want nil (declined, not failed)", err)
	}
	if got != from {
		t.Errorf("watermark = %v, want it left at %v — a declined window consumed nothing", got, from)
	}
	// Assert on the SUMMARIZED cause, not the raw list: the engine also records
	// source_error on the failed fetch, and the summary's priority order is what
	// the scheduler actually reads to decide whether to ratchet staleness.
	if got := outcomes.Snapshot().Summarize(nil, false).Cause; got != recordoutcome.CausePermissionDenied {
		t.Errorf("summarized cause = %q, want permission_denied", got)
	}
	if n := len(rec.LogRecords()); n != 0 {
		t.Errorf("emitted %d records on a 403, want 0", n)
	}
}

// TestPermissionsAndName pins the least-privilege scope and stable name.
func TestPermissionsAndName(t *testing.T) {
	c := newCollector(collectors.WindowDeps{TenantID: "t1"})
	if c.Name() != collectorName {
		t.Errorf("name = %q, want %q", c.Name(), collectorName)
	}
	if !c.Experimental() {
		t.Error("Experimental() = false, want true (beta endpoint)")
	}
	perms := c.RequiredPermissions()
	if len(perms) != 1 || perms[0] != "IdentityRiskyAgent.Read.All" {
		t.Errorf("permissions = %v, want [IdentityRiskyAgent.Read.All]", perms)
	}
}
