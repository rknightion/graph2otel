// Package agentriskdetections is the Entra Identity Protection agent
// risk-detections log source: a single WindowCollector over
// GET /beta/identityProtection/agentRiskDetections, emitting one OTLP log
// record per Entra Agent ID risk detection through the generic logpipeline
// engine (#13). It is the AI-agent analog of entra.risk_detections (user risk
// events) and entra.service_principal_risk_detections (workload-identity risk
// events) — same detection-event shape, a third principal kind (#133).
//
// # A genuinely new attack surface
//
// Entra ID Protection now scores AI agent identities (Agent 365 / Entra Agent
// ID) for compromise risk. graph2otel is a SIEM feed, and an emerging identity
// attack surface with zero coverage is exactly the gap worth closing early.
// This collector is the detection EVENT stream (WHY an agent was flagged);
// entra.risky_agents is the current-STATE gauge + twin (WHICH agents are risky
// now). Together they are the agent equivalent of entra.risk +
// entra.risk_detections.
//
// # Beta-only, Experimental, IPC workload
//
// The agentRiskDetections resource exists only under
// https://graph.microsoft.com/beta (v1.0 has no agent surface), so
// EndpointConfig.BaseURLOverride points at beta and the collector implements
// collectors.Experimental — an operator opts in explicitly. Treat its shape as
// unstable. It lives on the Identity Protection (IPC) workload: 1 request/second
// per tenant shared across ALL IPC callers, no Retry-After; the transport
// classifies the Path onto WorkloadIPC and serializes it through the shared
// per-tenant limiter, so this collector wires no limiter itself and polls
// slowly. Identity Protection caps $top at 500 (the engine's 1000 default 400s),
// so PageSize is 500.
//
// No documented server-side $filter exists for this beta endpoint, so
// NoServerFilter is set: the engine drains the (retention-bounded, and on a
// healthy tenant near-empty) collection every poll and bounds the window
// CLIENT-SIDE on detectedDateTime. $orderby is undocumented too, so
// OrderByReliable is false and the engine sorts the drained window client-side.
//
// # Cardinality (LOGS)
//
// Per-entity detail — the detection id, the agent identity id, agentDisplayName
// — is structured log attributes, never a metric label; this package emits no
// metrics, so #112 holds by construction.
//
// # Mapped against a real row
//
// The field set is pinned from a VERBATIM detection synthesized on m7kni
// (admin-confirmed compromise of the "testagent" Entra Agent ID identity, #133)
// rather than the docs — see liveAgentRiskDetection in the test. It is the
// ENRICHED form (the detection populated displayName/detectionTimingType/source
// and the mitreTechniques over ~3 min, exactly like the SP-risk synthesis did).
// additionalInfo is the SAME doubly-encoded [{Key,Value}] string as on the user
// and SP detections (decode twice, #142); it carried the MITRE technique
// (T1078 — Valid Accounts). Fields null on the wire (the signIn* correlation
// ids, clientSessionId) are mapped via omit-empty accessors so a detection type
// that populates them carries them, without asserting them when absent.
package agentriskdetections

import (
	"encoding/json"
	"strings"
	"time"

	"github.com/rknightion/graph2otel/internal/collector"
	"github.com/rknightion/graph2otel/internal/collectors"
	"github.com/rknightion/graph2otel/internal/logpipeline"
	"github.com/rknightion/graph2otel/internal/semconv"
	"github.com/rknightion/graph2otel/internal/telemetry"
)

const (
	// agentRiskDetectionsPath is the Graph beta path this collector polls.
	agentRiskDetectionsPath = "/identityProtection/agentRiskDetections"
	// betaBaseURL is the Graph beta service root — this resource has no v1.0 form.
	betaBaseURL = "https://graph.microsoft.com/beta"
	// collectorName is the stable collector key.
	collectorName = "entra.agent_risk_detections"
	// eventName is the OTLP LogRecord EventName every detection carries.
	eventName = "entra.agent_risk_detection"
)

// Schedule tuning mirrors the other IPC risk-detection streams: 1 req/s per
// tenant shared across every IPC caller, so this polls slowly and pages sparingly.
const (
	interval        = 30 * time.Minute
	lag             = 15 * time.Minute
	initialLookback = time.Hour
	maxWindow       = 24 * time.Hour
)

// collectorImpl is the agent risk-detections WindowCollector: the generic
// LogCollector plus the Experimental opt-in gate the composition root checks
// before scheduling a beta-endpoint collector.
type collectorImpl struct {
	*logpipeline.LogCollector
}

// RequiredPermissions declares the least-privilege Graph application scope.
func (c *collectorImpl) RequiredPermissions() []string {
	return []string{"IdentityRiskyAgent.Read.All"}
}

// Experimental marks this collector as beta/opt-in: agentRiskDetections exists
// only on the Graph beta endpoint, with no v1.0 fallback.
func (c *collectorImpl) Experimental() bool { return true }

// newCollector builds the agent risk-detections WindowCollector. Its Path is
// distinct from every other IPC stream's, so it needs no CheckpointKey override.
func newCollector(d collectors.WindowDeps) *collectorImpl {
	cfg := logpipeline.EndpointConfig{
		Path:            agentRiskDetectionsPath,
		BaseURLOverride: betaBaseURL,
		TimeField:       "detectedDateTime",
		Flavor:          logpipeline.FlavorGeLe,
		OrderByReliable: false, // $orderby undocumented on this beta endpoint; sort client-side
		NoServerFilter:  true,  // no documented $filter; bound the window client-side
		// Identity Protection caps $top at 500 (the engine's 1000 default 400s on IPC).
		PageSize: 500,
		Map:      mapAgentRiskDetection,
	}
	lc := logpipeline.NewLogCollector(collectorName, interval, lag, d.TenantID, cfg, d.Fetcher, d.Store)
	return &collectorImpl{LogCollector: lc}
}

// mapAgentRiskDetection turns one raw agentRiskDetection record into its dedupe
// id (the immutable detection id) and the OTLP log Event. Only present fields
// are set (omit-empty accessors), so a detection type missing an optional field
// simply omits that attribute.
func mapAgentRiskDetection(rec map[string]any) (string, telemetry.Event) {
	id := str(rec, "id")
	riskEventType := str(rec, "riskEventType")
	riskLevel := str(rec, "riskLevel")

	// agentId and identityId are the same Entra Agent ID identity id on the
	// observed row; prefer agentId and fall back to identityId.
	agentID := str(rec, "agentId")
	if agentID == "" {
		agentID = str(rec, "identityId")
	}
	// agentDisplayName and displayName both carried the agent's name on the
	// observed row; prefer agentDisplayName and fall back to displayName.
	agentName := str(rec, "agentDisplayName")
	if agentName == "" {
		agentName = str(rec, "displayName")
	}

	attrs := telemetry.Attrs{}
	telemetry.SetStr(attrs, semconv.AttrId, id)
	telemetry.SetStr(attrs, semconv.AttrRiskEventType, riskEventType)
	telemetry.SetStr(attrs, semconv.AttrRiskLevel, riskLevel)
	telemetry.SetStr(attrs, semconv.AttrRiskState, str(rec, "riskState"))
	telemetry.SetStr(attrs, semconv.AttrRiskDetail, str(rec, "riskDetail"))
	telemetry.SetStr(attrs, semconv.AttrRiskEvidence, str(rec, "riskEvidence"))
	telemetry.SetStr(attrs, semconv.AttrDetectionTimingType, str(rec, "detectionTimingType"))
	telemetry.SetStr(attrs, semconv.AttrSource, str(rec, "source"))
	telemetry.SetStr(attrs, semconv.AttrIdentityType, str(rec, "identityType"))
	telemetry.SetStr(attrs, semconv.AttrAgentId, agentID)
	telemetry.SetStr(attrs, semconv.AttrAgentDisplayName, agentName)
	telemetry.SetStr(attrs, semconv.AttrBlueprintId, str(rec, "blueprintId"))

	// additionalInfo is the SAME doubly-encoded [{Key,Value}] string as on the
	// user and SP detections (a JSON string of pairs — decode twice, #142). It
	// carried the MITRE ATT&CK technique behind the compromise (T1078 — Valid
	// Accounts) on the observed row, the same high-value SIEM field the user and
	// SP twins extract. alertUrl was null and has no bounded semconv key, so it is
	// left undecoded.
	if pairs := additionalInfoPairs(rec); len(pairs) > 0 {
		if techniques := mitreTechniques(pairs); len(techniques) > 0 {
			attrs[semconv.AttrMitreTechniques] = techniques
		}
	}

	return id, telemetry.Event{
		Name:     eventName,
		Body:     detectionBody(agentName, agentID, riskEventType, riskLevel),
		Severity: severityFor(riskLevel),
		Attrs:    attrs,
	}
}

// detectionBody builds a short human-readable summary line.
func detectionBody(agentName, agentID, riskEventType, riskLevel string) string {
	who := agentName
	if who == "" {
		who = agentID
	}
	if who == "" {
		who = "unknown agent"
	}
	return "agent risk detection " + riskEventType + " (" + riskLevel + ") for " + who
}

// severityFor maps risk level onto the telemetry (not OTEL-wire) severity scale
// (#113): high → Error, medium → Warn, everything else → Info.
func severityFor(riskLevel string) telemetry.Severity {
	switch riskLevel {
	case "high":
		return telemetry.SeverityError
	case "medium":
		return telemetry.SeverityWarn
	default:
		return telemetry.SeverityInfo
	}
}

func str(m map[string]any, key string) string {
	s, _ := m[key].(string)
	return s
}

// additionalInfoPairs decodes a detection's additionalInfo — a JSON-encoded
// STRING holding an array of {"Key","Value"} pairs, so it is unmarshalled twice
// (the #142 trap: a mapper written against a plain object shape finds nothing
// and reports success forever). Every failure mode returns nil: the payload is
// undocumented and varies by riskEventType, so a missing/malformed one is
// normal, not a fault. First occurrence of a duplicate Key wins.
func additionalInfoPairs(rec map[string]any) map[string]string {
	raw := str(rec, "additionalInfo")
	if raw == "" {
		return nil
	}
	var pairs []struct {
		Key   string `json:"Key"`
		Value string `json:"Value"`
	}
	if err := json.Unmarshal([]byte(raw), &pairs); err != nil {
		return nil
	}
	out := make(map[string]string, len(pairs))
	for _, p := range pairs {
		if _, dup := out[p.Key]; !dup {
			out[p.Key] = p.Value
		}
	}
	return out
}

// mitreTechniques splits the comma-separated MITRE ATT&CK technique ids out of a
// decoded additionalInfo payload, returning nil when it carries none.
func mitreTechniques(pairs map[string]string) []string {
	var out []string
	for _, t := range strings.Split(pairs["mitreTechniques"], ",") {
		if t = strings.TrimSpace(t); t != "" {
			out = append(out, t)
		}
	}
	return out
}

func init() {
	collectors.RegisterWindow(func(d collectors.WindowDeps) collectors.RegisteredWindow {
		return collectors.RegisteredWindow{
			Collector:       newCollector(d),
			InitialLookback: initialLookback,
			MaxWindow:       maxWindow,
		}
	})
}

// Compile-time checks that the collector satisfies every interface the
// composition root type-asserts on.
var (
	_ collector.WindowCollector = (*collectorImpl)(nil)
	_ collectors.Experimental   = (*collectorImpl)(nil)
)
