// Package riskyagents is the Entra Identity Protection current-agent-risk
// collector: the "how many agent identities are risky right now" state
// snapshot over GET /beta/identityProtection/riskyAgents. It is the AI-agent
// analog of entra.risk's risky-users / risky-service-principals halves (#133) —
// the STATE feed. The agent risk-detection EVENTS stream is a separate
// log-pipeline collector, entra.agent_risk_detections, not this one.
//
// # Both sides of the cardinality boundary, from one fetch
//
// Each cycle emits TWO things from a single paged fetch:
//
//   - a bounded GAUGE entra.risky_agents.total counted by risk_level x
//     risk_state — the aggregate;
//   - one LOG record per risky agent (entra.risky_agent) carrying the
//     per-entity detail: id, agentDisplayName, riskDetail, riskState/level, the
//     enabled/deleted/processing flags, and riskLastModifiedDateTime.
//
// Per-entity identity must never become a metric label (a series per agent grows
// with the risky-agent population and bills as active series), but "not a metric
// label" means "log twin", NOT "dropped" (#114). This is a STATE feed: a risky
// agent is re-emitted every cycle for as long as it stays risky, which is what
// makes "which agent was risky at 14:00" answerable — so the twin timestamp is
// left at poll time and the assessment time rides the risk_last_updated
// attribute (the same reasoning as entra.risk).
//
// # Beta-only, Experimental, IPC workload, NO license gate
//
// The riskyAgents resource exists only under https://graph.microsoft.com/beta,
// so this collector points baseURL at beta and implements
// collectors.Experimental — an operator opts in explicitly. It lives on the
// Identity Protection (IPC) workload (1 request/second per tenant, shared,
// no Retry-After), so it polls slowly.
//
// It is deliberately NOT license-gated, following the same reasoning that fixed
// entra.risk's risky-SP half (#133): a capability flag that is a false negative
// on a live tenant would permanently hide this collector where it actually
// works. It polls unconditionally and degrades gracefully — a tenant that lacks
// the feature returns 200/empty (nothing emitted) or 403 (a WARN-free info skip,
// checkpoint irrelevant here since it is a snapshot), never a hard failure.
//
// # Mapped against a real row
//
// The field set is pinned from a VERBATIM riskyAgent record synthesized on m7kni
// (admin-confirmed compromise of the "testagent" Entra Agent ID identity, #133) —
// see liveRiskyAgent in the test. blueprintId was null on the observed row and is
// mapped via omit-empty so a blueprint-scoped agent carries it. isDeleted is
// emitted as observed on the wire; unlike riskyUsers.isDeleted (a known lie
// requiring a deleted-items reconciliation, #155), there is no evidence the agent
// field lies and no reconciliation path, so it is not second-guessed.
package riskyagents

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/rknightion/graph2otel/internal/collector"
	"github.com/rknightion/graph2otel/internal/collectors"
	"github.com/rknightion/graph2otel/internal/graphclient"
	"github.com/rknightion/graph2otel/internal/semconv"
	"github.com/rknightion/graph2otel/internal/telemetry"
)

// collectorName is the stable key used for config, self-observability, and the
// admin status page.
const collectorName = "entra.risky_agents"

// metricRiskyAgents is the bounded gauge this collector emits. Its cardinality is
// bounded by risk_level x risk_state, never by the agent population size.
const metricRiskyAgents = "entra.risky_agents.total"

// eventRiskyAgent is the log EventName carrying the per-entity detail the gauge
// cannot — one record per risky agent per cycle.
const eventRiskyAgent = "entra.risky_agent"

// betaBaseURL is the Graph beta service root — this resource has no v1.0 form.
const betaBaseURL = "https://graph.microsoft.com/beta"

// riskyAgentsPath is the beta path this collector polls.
const riskyAgentsPath = "/identityProtection/riskyAgents"

// Collector polls the Identity Protection current-agent-risk endpoint.
type Collector struct {
	g       collectors.GraphClient
	baseURL string
	logger  *slog.Logger
}

// New builds the risky-agents collector. A nil logger falls back to
// slog.Default().
func New(g collectors.GraphClient, logger *slog.Logger) *Collector {
	if logger == nil {
		logger = slog.Default()
	}
	return &Collector{g: g, baseURL: betaBaseURL, logger: logger}
}

// Name implements collector.Collector.
func (c *Collector) Name() string { return collectorName }

// DefaultInterval implements collector.Collector. The endpoint shares Identity
// Protection's low throttle bucket (1 req/s per tenant, shared, no Retry-After),
// and current agent-risk state is not a sub-minute signal, so a conservative
// interval keeps this a negligible share of that budget.
func (c *Collector) DefaultInterval() time.Duration { return 15 * time.Minute }

// Experimental marks this collector as beta/opt-in: riskyAgents exists only on
// the Graph beta endpoint, with no v1.0 fallback.
func (c *Collector) Experimental() bool { return true }

// RequiredPermissions declares the least-privilege Graph application scope.
func (c *Collector) RequiredPermissions() []string {
	return []string{"IdentityRiskyAgent.Read.All"}
}

// riskyAgent is the riskyAgentIdentity list-response shape. RiskLevel/RiskState
// bucket the gauge; everything else is per-entity and goes to the log twin only.
type riskyAgent struct {
	ID                       string `json:"id"`
	IdentityType             string `json:"identityType"`
	BlueprintID              string `json:"blueprintId"`
	AgentDisplayName         string `json:"agentDisplayName"`
	RiskLevel                string `json:"riskLevel"`
	RiskState                string `json:"riskState"`
	RiskDetail               string `json:"riskDetail"`
	RiskLastModifiedDateTime string `json:"riskLastModifiedDateTime"`

	// The three bool flags are POINTERS so "the wire said false" is distinct from
	// "the wire said nothing": false is a real answer (settled/enabled/live) worth
	// emitting, nil omits the attribute rather than asserting a fact Microsoft
	// never stated.
	IsEnabled    *bool `json:"isEnabled"`
	IsDeleted    *bool `json:"isDeleted"`
	IsProcessing *bool `json:"isProcessing"`
}

// Collect fetches the current risky-agents collection and emits BOTH sides of
// the cardinality boundary from that single fetch: the bounded
// (riskLevel, riskState) GaugeSnapshot, and one log record per risky agent. A
// 403 is a graceful info-skip (the tenant lacks the agent-risk feature), not a
// failure.
func (c *Collector) Collect(ctx context.Context, e telemetry.Emitter) error {
	raws, err := collectors.GetAllValues(ctx, c.g, c.baseURL+riskyAgentsPath, nil)
	if err != nil {
		if isForbidden(err) {
			c.logger.Info("skipping risky agents: endpoint returned 403 (agent-risk feature not enabled on this tenant)",
				"collector", collectorName, "error", graphclient.FormatODataError(err))
			return nil
		}
		return err
	}

	counts := map[[2]string]int64{}
	for _, raw := range raws {
		var item riskyAgent
		if err := json.Unmarshal(raw, &item); err != nil {
			return fmt.Errorf("decode %s: %w", riskyAgentsPath, err)
		}
		counts[[2]string{item.RiskLevel, item.RiskState}]++
		e.LogEvent(logTwin(item))
	}

	points := make([]telemetry.GaugePoint, 0, len(counts))
	for k, v := range counts {
		points = append(points, telemetry.GaugePoint{
			Value: float64(v),
			Attrs: telemetry.Attrs{semconv.AttrRiskLevel: k[0], semconv.AttrRiskState: k[1]},
		})
	}
	e.GaugeSnapshot(metricRiskyAgents, "{agent}",
		"Current count of risky Entra agent identities, by risk level and risk state.", points)
	return nil
}

// isForbidden reports whether err is a Graph 403 — the signal that this tenant
// may not use the endpoint (agent-risk feature not enabled), which is a graceful
// skip rather than a collection failure. The raw-REST path embeds the status in
// the error string ("status 403"); the OData path codes it Authorization_RequestDenied.
func isForbidden(err error) bool {
	if err == nil {
		return false
	}
	if strings.Contains(err.Error(), "status 403") {
		return true
	}
	if code, _, ok := graphclient.UnwrapODataError(err); ok {
		return code == "Authorization_RequestDenied"
	}
	return false
}

// logTwin renders one risky agent as an OTLP log record. Timestamp is left zero
// ("now", poll time), not riskLastModifiedDateTime: this is a STATE feed and the
// same agent re-emits every cycle, so stamping the assessment time would pile
// every repeat onto one instant and make "which agent was risky at 14:00"
// unanswerable. The assessment time rides the risk_last_updated attribute.
func logTwin(item riskyAgent) telemetry.Event {
	attrs := telemetry.Attrs{}
	telemetry.SetStr(attrs, semconv.AttrId, item.ID)
	telemetry.SetStr(attrs, semconv.AttrIdentityType, item.IdentityType)
	telemetry.SetStr(attrs, semconv.AttrBlueprintId, item.BlueprintID)
	telemetry.SetStr(attrs, semconv.AttrAgentDisplayName, item.AgentDisplayName)
	telemetry.SetStr(attrs, semconv.AttrRiskLevel, item.RiskLevel)
	telemetry.SetStr(attrs, semconv.AttrRiskState, item.RiskState)
	telemetry.SetStr(attrs, semconv.AttrRiskDetail, item.RiskDetail)
	telemetry.SetStr(attrs, semconv.AttrRiskLastUpdated, item.RiskLastModifiedDateTime)

	// The three flags are emitted whenever the wire carried them, including false
	// — false is an answer, not an absence (see riskyAgent). nil omits.
	if item.IsEnabled != nil {
		attrs[semconv.AttrIsEnabled] = *item.IsEnabled
	}
	if item.IsDeleted != nil {
		attrs[semconv.AttrIsDeleted] = *item.IsDeleted
	}
	if item.IsProcessing != nil {
		attrs[semconv.AttrIsProcessing] = *item.IsProcessing
	}

	// Only "high" escalates: the other risk levels are routine background state,
	// and warning on them would make the severity dimension useless for filtering.
	sev := telemetry.SeverityInfo
	if strings.EqualFold(item.RiskLevel, "high") {
		sev = telemetry.SeverityWarn
	}

	return telemetry.Event{
		Name:     eventRiskyAgent,
		Body:     fmt.Sprintf("risky agent %s: risk_level=%s risk_state=%s", displayOf(item), item.RiskLevel, item.RiskState),
		Severity: sev,
		Attrs:    attrs,
	}
}

// displayOf picks the most human-readable identifier the agent carries.
func displayOf(item riskyAgent) string {
	if item.AgentDisplayName != "" {
		return item.AgentDisplayName
	}
	if item.ID != "" {
		return item.ID
	}
	return "unknown"
}

func init() {
	collectors.Register(func(d collectors.Deps) collector.SnapshotCollector {
		return New(d.Graph, d.Logger)
	})
}

// Compile-time checks that the collector satisfies every interface the
// composition root type-asserts on.
var (
	_ collector.SnapshotCollector = (*Collector)(nil)
	_ collectors.Experimental     = (*Collector)(nil)
)
