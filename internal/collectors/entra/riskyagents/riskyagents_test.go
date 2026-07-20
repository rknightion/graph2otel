package riskyagents

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/rknightion/graph2otel/internal/collectors"
	"github.com/rknightion/graph2otel/internal/telemetrytest"
)

// fakeGraph maps request URLs to canned page bodies (or errors), satisfying
// collectors.GraphClient so Collector can be driven without a live Graph call.
type fakeGraph struct {
	bodies map[string]string
	errs   map[string]error
}

func (f *fakeGraph) RawGet(ctx context.Context, url string) ([]byte, error) {
	return f.RawGetWithHeaders(ctx, url, nil)
}

func (f *fakeGraph) RawGetWithHeaders(_ context.Context, url string, _ map[string]string) ([]byte, error) {
	if err, ok := f.errs[url]; ok {
		return nil, err
	}
	return []byte(f.bodies[url]), nil
}

var _ collectors.GraphClient = (*fakeGraph)(nil)

const agentsURL = betaBaseURL + riskyAgentsPath

// liveRiskyAgent wraps a VERBATIM GET /beta/identityProtection/riskyAgents record
// from m7kni, read as graph2otel-poller on 2026-07-20 `[live-measured 2026-07-20,
// #133]`. It is the risky agent #133 synthesized by admin-confirming compromise
// of the "testagent" Entra Agent ID identity (Agent 365 trial) — the only real
// one this project has observed, since riskyAgents is empty on a healthy tenant.
// It settles the field set: agentDisplayName carries the name (not displayName),
// riskLastModifiedDateTime is the assessment time (not riskLastUpdatedDateTime as
// on riskyUsers), blueprintId is null, and isEnabled/isDeleted/isProcessing are
// real booleans.
const liveRiskyAgentBody = `{"value":[
	{
		"@odata.type": "#microsoft.graph.riskyAgentIdentity",
		"id": "7d5472af-9f94-4b62-bbc2-bfbecbd2aad8",
		"identityType": "agentIdentity",
		"blueprintId": null,
		"agentDisplayName": "testagent",
		"isDeleted": false,
		"isEnabled": true,
		"isProcessing": false,
		"riskLastModifiedDateTime": "2026-07-20T18:33:49.7699442Z",
		"riskState": "confirmedCompromised",
		"riskLevel": "high",
		"riskDetail": "adminConfirmedAgentCompromised"
	}
]}`

func liveFixture() *fakeGraph {
	return &fakeGraph{bodies: map[string]string{agentsURL: liveRiskyAgentBody}}
}

// TestCollectEmitsBoundedGauge pins the (risk_level, risk_state) gauge against
// the verbatim row.
func TestCollectEmitsBoundedGauge(t *testing.T) {
	rec := telemetrytest.New()
	if err := New(liveFixture(), nil).Collect(context.Background(), rec.Emitter()); err != nil {
		t.Fatalf("Collect: %v", err)
	}
	pts := rec.MetricPoints(metricRiskyAgents)
	if len(pts) != 1 {
		t.Fatalf("got %d gauge series, want 1: %v", len(pts), pts)
	}
	p := pts[0]
	if p.Value != 1 || p.Attrs["risk_level"] != "high" || p.Attrs["risk_state"] != "confirmedCompromised" {
		t.Errorf("gauge point = %v attrs=%v, want value 1 high/confirmedCompromised", p.Value, p.Attrs)
	}
}

// TestCollectNoPerEntitySeries is the #112 metric-boundary check: no per-entity
// id / display name may reach a metric attribute.
func TestCollectNoPerEntitySeries(t *testing.T) {
	rec := telemetrytest.New()
	if err := New(liveFixture(), nil).Collect(context.Background(), rec.Emitter()); err != nil {
		t.Fatalf("Collect: %v", err)
	}
	for _, p := range rec.MetricPoints(metricRiskyAgents) {
		for k := range p.Attrs {
			if k != "risk_level" && k != "risk_state" {
				t.Errorf("metric attr %q present — only risk_level/risk_state are bounded", k)
			}
		}
	}
}

// TestCollectEmitsRiskyAgentLogTwin pins the per-entity twin against the row.
func TestCollectEmitsRiskyAgentLogTwin(t *testing.T) {
	rec := telemetrytest.New()
	if err := New(liveFixture(), nil).Collect(context.Background(), rec.Emitter()); err != nil {
		t.Fatalf("Collect: %v", err)
	}
	var twin *telemetrytest.LogRecord
	for i, r := range rec.LogRecords() {
		if r.EventName == eventRiskyAgent {
			twin = &rec.LogRecords()[i]
			break
		}
	}
	if twin == nil {
		t.Fatalf("no %s log twin emitted", eventRiskyAgent)
	}
	// String attributes as seen through the recorder (which stringifies only
	// string-kind attrs; bools are asserted on the Event directly below).
	want := map[string]string{
		"id":                 "7d5472af-9f94-4b62-bbc2-bfbecbd2aad8",
		"identity_type":      "agentIdentity",
		"agent_display_name": "testagent",
		"risk_level":         "high",
		"risk_state":         "confirmedCompromised",
		"risk_detail":        "adminConfirmedAgentCompromised",
		"risk_last_updated":  "2026-07-20T18:33:49.7699442Z",
	}
	for k, v := range want {
		if got := twin.Attrs[k]; got != v {
			t.Errorf("twin attr %q = %q, want %q", k, got, v)
		}
	}
}

// TestLogTwinBoolFlagsAndOmittedBlueprint asserts the three bool flags on the
// Event directly (the recorder cannot stringify a Bool kind) and that a null
// blueprintId is omitted, not emitted empty.
func TestLogTwinBoolFlagsAndOmittedBlueprint(t *testing.T) {
	var item riskyAgent
	// A single-object slice of the verbatim body's value[0].
	var wrap struct {
		Value []json.RawMessage `json:"value"`
	}
	if err := json.Unmarshal([]byte(liveRiskyAgentBody), &wrap); err != nil {
		t.Fatalf("decode body: %v", err)
	}
	if err := json.Unmarshal(wrap.Value[0], &item); err != nil {
		t.Fatalf("decode agent: %v", err)
	}
	// The *bool decode is under test: false must survive as the bool false, not nil.
	if item.IsEnabled == nil || item.IsDeleted == nil || item.IsProcessing == nil {
		t.Fatalf("a bool flag decoded to nil from a live record that carries it: enabled=%v deleted=%v processing=%v",
			item.IsEnabled, item.IsDeleted, item.IsProcessing)
	}
	ev := logTwin(item)
	for k, want := range map[string]bool{"is_enabled": true, "is_deleted": false, "is_processing": false} {
		got, ok := ev.Attrs[k]
		if !ok {
			t.Errorf("attr %q absent, want bool %v", k, want)
			continue
		}
		if got != want {
			t.Errorf("attr %q = %#v, want the bool %v (not a string)", k, got, want)
		}
	}
	// blueprintId was null on the wire → omitted, not emitted empty.
	if _, present := ev.Attrs["blueprint_id"]; present {
		t.Errorf("blueprint_id present, want omitted (null on the wire)")
	}
}

// TestForbiddenIsGracefulSkip verifies a 403 (agent-risk feature not enabled)
// yields no error and no emission, not a hard failure.
func TestForbiddenIsGracefulSkip(t *testing.T) {
	g := &fakeGraph{errs: map[string]error{agentsURL: errForbidden{}}}
	rec := telemetrytest.New()
	if err := New(g, nil).Collect(context.Background(), rec.Emitter()); err != nil {
		t.Fatalf("Collect returned error on 403, want graceful skip: %v", err)
	}
	if len(rec.MetricPoints(metricRiskyAgents)) != 0 || len(rec.LogRecords()) != 0 {
		t.Errorf("expected no emission on 403 skip")
	}
}

// errForbidden mimics the raw-REST transport's 403 error string.
type errForbidden struct{}

func (errForbidden) Error() string { return "graphclient: GET ...: status 403: forbidden" }

// TestPermissionsNameAndBeta pins scope, stable name, and the Experimental gate.
func TestPermissionsNameAndBeta(t *testing.T) {
	c := New(liveFixture(), nil)
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
