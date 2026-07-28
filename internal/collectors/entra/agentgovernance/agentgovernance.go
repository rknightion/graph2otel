// Package agentgovernance is the Entra Agent ID governance collector (#333):
// an inventory of agent-identity BLUEPRINTS (the reusable definition an admin
// authors, e.g. in Copilot Studio) and the AGENT identities minted from them,
// their blueprint lineage, and the two governance gaps that matter for an
// autonomous, non-human identity — no sponsor, no owner.
//
// # There is no dedicated entity set — it's an OData type cast (live-measured 2026-07-28)
//
// The issue's own premise was wrong: `/directory/agentIdentityBlueprints` and
// every sibling path the issue names return HTTP 400 "Resource not found for
// the segment", on BOTH v1.0 and beta. `agentIdentity`,
// `agentIdentityBlueprint` and `agentIdentityBlueprintPrincipal` are DERIVED
// TYPES in the Graph EDM (BaseType="graph.servicePrincipal" /
// "graph.application", confirmed against $metadata) — reached by an OData
// type cast on the BASE collection, not a dedicated path:
//
//	GET /applications/microsoft.graph.agentIdentityBlueprint
//	GET /servicePrincipals/microsoft.graph.agentIdentityBlueprintPrincipal
//	GET /servicePrincipals/microsoft.graph.agentIdentity
//
// All three are v1.0 GA under the poller's existing Application.Read.All —
// nothing here is Experimental (that is reserved for genuine Graph *beta*
// surfaces, #183) and nothing is HighVolume (agent count is bounded by
// tenant configuration, not by traffic). Anyone who goes back to the
// documented-looking paths above will hit the same 400 this package's
// author hit; that is the whole reason this comment exists.
//
// # $expand accepts exactly ONE property per request (live-measured 400)
//
// `?$expand=sponsors,owners` on the agentIdentity cast returns HTTP 400
// "Only one property can be expanded in a single query." So sponsors and
// owners cost two separate requests over the SAME collection — a fixed 4
// requests total (blueprints, blueprint principals, agents+sponsors,
// agents+owners), never a per-agent fan-out. The two agent responses are
// joined on the agent's `id`, never by list position — Graph does not
// promise the two requests return agents in the same order, and a fixture
// that happened to agree would hide exactly that bug.
//
// # Only id/displayName/@odata.type are decoded from an expanded sponsor or owner
//
// Graph's $expand=sponsors/owners returns the FULL directoryObject payload —
// live-measured 2026-07-28, a sponsor's entry carried business phone, mobile
// phone, mail and UPN alongside dozens of other user properties nobody asked
// for. Decoding or emitting any of that under a collector about agent
// GOVERNANCE would ship a user's directory record sight-unseen (#112's
// per-entity-never-a-label rule extends here to "never even read the rest of
// the object"). Only @odata.type, id and displayName are decoded; every other
// field on the wire is simply not a member of the Go struct.
//
// # Bounded gauges, log twins, the two alertable gaps
//
// blueprints.total / blueprint_principals / agents are bounded gauges keyed
// by fixed enumerated attributes (never by an id or a name). The lineage a
// gauge cannot carry — which blueprint an agent was minted from, who its
// sponsors/owners ARE — rides one log twin per entity (#114):
// entra.agent_blueprint, entra.agent_blueprint_principal,
// entra.agent_identity.
//
// agents.without_sponsor and agents.without_owner are separate plain-count
// gauges, deliberately NOT folded into a `count by` over the joint `agents`
// gauge: "an agent nobody owns" is the alertable governance gap this
// collector exists to surface, and it deserves a series an operator can
// alert on directly.
//
// # Absent is not false, and "unknown" is not "false" either
//
// accountEnabled, appRoleAssignmentRequired and disabledByMicrosoftStatus are
// documented-optional; they decode as pointers and are OMITTED from a log
// twin when the wire didn't carry them — a plain bool would fabricate
// `false` for a value Graph never sent (this project has been bitten by
// exactly this before). The bounded gauges cannot omit a labeling dimension
// the same way, so a nil pointer becomes the metric label "unknown" — a
// third value, never "false" — so an absent measurement can never be
// mistaken for a measured governance gap. This choice is NOT dictated by
// #333's brief; every live row happens to carry both fields, so it is
// currently unexercised by any live tenant and is recorded here as a
// decision, not a backlog item.
//
// Independent degradation: each of the four fetches can fail without losing
// the others. If the sponsors fetch fails, `has_sponsor` is emitted as
// "unknown" (never "false") for every agent, the sponsor_ids/sponsor_count/
// sponsors_truncated twin fields are omitted entirely, and
// agents.without_sponsor is not emitted at all that cycle — a total outage
// of a governance signal must never look like "governance is fine" (a
// fabricated 0) or "everyone is ungoverned" (a fabricated false). Same
// treatment, symmetrically, for owners.
//
// # wirecheck: sign_in_audience left UNWATCHED
//
// sign_in_audience is a metric label keyed off a Graph-documented enum,
// which is ordinarily exactly what internal/wirecheck watches for a new
// member. It is deliberately left unwatched here: only two of the
// documented values (AzureADMyOrg, AzureADMultipleOrgs) have ever been
// observed, across two rows, on one tenant. CLAUDE.md's rule is explicit
// that one tenant's observed values are not a value set; add wirecheck
// coverage once a second tenant or a third value has been seen live, not
// before.
package agentgovernance

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/rknightion/graph2otel/internal/collector"
	"github.com/rknightion/graph2otel/internal/collectors"
	entraoutcome "github.com/rknightion/graph2otel/internal/outcomehelper"
	"github.com/rknightion/graph2otel/internal/recordoutcome"
	"github.com/rknightion/graph2otel/internal/semconv"
	"github.com/rknightion/graph2otel/internal/telemetry"
)

// collectorName is the stable key used for config (enable/interval),
// self-observability, and the admin status page.
const collectorName = "entra.agent_governance"

// Metric names this collector emits.
const (
	metricBlueprintsTotal      = "entra.agent_governance.blueprints.total"
	metricBlueprintPrincipals  = "entra.agent_governance.blueprint_principals"
	metricAgents               = "entra.agent_governance.agents"
	metricAgentsWithoutSponsor = "entra.agent_governance.agents.without_sponsor"
	metricAgentsWithoutOwner   = "entra.agent_governance.agents.without_owner"
)

// The three log EventNames this collector emits. All LOG-ONLY (#112): none of
// the identifiers/names below ever become a metric label.
const (
	eventBlueprint          = "entra.agent_blueprint"
	eventBlueprintPrincipal = "entra.agent_blueprint_principal"
	eventAgentIdentity      = "entra.agent_identity"
)

// defaultBaseURL is the Graph v1.0 root. Every route here is v1.0 GA — see the
// package doc for why none of it is Experimental.
const defaultBaseURL = "https://graph.microsoft.com/v1.0"

// The four fetch paths (see package doc for the OData-cast discovery and the
// one-property $expand limit that makes sponsors/owners two requests, not one).
const (
	blueprintsPath     = "/applications/microsoft.graph.agentIdentityBlueprint"
	principalsPath     = "/servicePrincipals/microsoft.graph.agentIdentityBlueprintPrincipal"
	agentsSponsorsPath = "/servicePrincipals/microsoft.graph.agentIdentity?$expand=sponsors"
	agentsOwnersPath   = "/servicePrincipals/microsoft.graph.agentIdentity?$expand=owners"
)

// maxPrincipalIdentifiers bounds every sponsor/owner/tag identifier array this
// collector emits. Admin-configured, bounded by tenant configuration rather
// than tenant population — the live-measured max cleared 2026-07-28 is 1 (a
// single sponsor or owner per agent); the cap is a defensive backstop against
// a pathological tenant, the same role authmethodspolicy's
// maxTargetIdentifiers plays there.
const maxPrincipalIdentifiers = 50

// unknownBool is the metric-label value for a pointer field Graph omitted —
// deliberately distinct from "true"/"false" so an absent measurement can
// never be mistaken for a measured governance gap. See the package doc's
// "absent is not false" section.
const unknownBool = "unknown"

// principalRef is the only shape this collector decodes out of an expanded
// sponsor or owner: enough to identify WHO, never the rest of the directory
// object Graph's $expand returns (see package doc).
type principalRef struct {
	ODataType   string `json:"@odata.type"`
	ID          string `json:"id"`
	DisplayName string `json:"displayName"`
}

// blueprint mirrors the subset of an agentIdentityBlueprint (the
// applications cast) this collector reads.
type blueprint struct {
	ID              string `json:"id"`
	AppID           string `json:"appId"`
	DisplayName     string `json:"displayName"`
	CreatedDateTime string `json:"createdDateTime"`
	CreatedByAppID  string `json:"createdByAppId"`
	PublisherDomain string `json:"publisherDomain"`
	SignInAudience  string `json:"signInAudience"`
}

// blueprintPrincipal mirrors the subset of an agentIdentityBlueprintPrincipal
// (the servicePrincipals cast) this collector reads.
type blueprintPrincipal struct {
	ID                     string   `json:"id"`
	AppID                  string   `json:"appId"`
	AppDisplayName         string   `json:"appDisplayName"`
	DisplayName            string   `json:"displayName"`
	AccountEnabled         *bool    `json:"accountEnabled"`
	AppOwnerOrganizationID string   `json:"appOwnerOrganizationId"`
	SignInAudience         string   `json:"signInAudience"`
	ServicePrincipalType   string   `json:"servicePrincipalType"`
	Tags                   []string `json:"tags"`
}

// agentIdentity mirrors the subset of an agentIdentity (the servicePrincipals
// cast) this collector reads. Sponsors/Owners are populated from TWO separate
// fetches (see package doc) and joined onto this struct by id after both
// decode — never read directly from one response's own field for both.
type agentIdentity struct {
	ID                        string `json:"id"`
	DisplayName               string `json:"displayName"`
	AgentIdentityBlueprintID  string `json:"agentIdentityBlueprintId"`
	CreatedDateTime           string `json:"createdDateTime"`
	AccountEnabled            *bool  `json:"accountEnabled"`
	AppRoleAssignmentRequired *bool  `json:"appRoleAssignmentRequired"`
	CreatedByAppID            string `json:"createdByAppId"`
	// DisabledByMicrosoftStatus is a pointer to a pointer's worth of nothing
	// more than "string or absent/null" — Graph documents this field as a
	// nullable string, always null in every live capture (2026-07-28).
	DisabledByMicrosoftStatus *string  `json:"disabledByMicrosoftStatus"`
	ServicePrincipalType      string   `json:"servicePrincipalType"`
	Tags                      []string `json:"tags"`

	Sponsors []principalRef `json:"sponsors"`
	Owners   []principalRef `json:"owners"`
}

// Collector polls Entra Agent ID blueprints, blueprint principals, and agent
// identities (with their sponsor/owner lineage).
type Collector struct {
	g       collectors.GraphClient
	baseURL string
	logger  *slog.Logger
}

// New builds the agent-governance collector. A nil logger falls back to the
// slog default.
func New(g collectors.GraphClient, logger *slog.Logger) *Collector {
	if logger == nil {
		logger = slog.Default()
	}
	return &Collector{g: g, baseURL: defaultBaseURL, logger: logger}
}

// Name implements collector.Collector.
func (c *Collector) Name() string { return collectorName }

// DefaultInterval implements collector.Collector. Blueprint/agent inventory
// and sponsorship are configuration, not an event stream — fifteen minutes is
// ample and cheap on the directory throttle bucket.
func (c *Collector) DefaultInterval() time.Duration { return 15 * time.Minute }

// RequiredPermissions declares the single scope every fetch here shares — the
// same OData-cast collections read under the application's existing
// Application.Read.All grant.
func (c *Collector) RequiredPermissions() []string { return []string{"Application.Read.All"} }

// Collect fetches blueprints, blueprint principals, and agent identities
// (sponsors and owners via two separate $expand requests, joined by id), and
// emits the bounded gauges, the two governance-gap counts, and one log twin
// per entity. Each of the four fetches degrades independently — see the
// package doc for exactly what "unknown" means when sponsors or owners
// couldn't be fetched.
func (c *Collector) Collect(ctx context.Context, e telemetry.Emitter, outcomes *recordoutcome.Recorder) error {
	var errs []error

	if err := c.collectBlueprints(ctx, e, outcomes); err != nil {
		entraoutcome.SourceError(outcomes)
		errs = append(errs, fmt.Errorf("agentIdentityBlueprint: %w", err))
	}
	if err := c.collectBlueprintPrincipals(ctx, e, outcomes); err != nil {
		entraoutcome.SourceError(outcomes)
		errs = append(errs, fmt.Errorf("agentIdentityBlueprintPrincipal: %w", err))
	}
	if err := c.collectAgents(ctx, e, outcomes); err != nil {
		entraoutcome.SourceError(outcomes)
		errs = append(errs, fmt.Errorf("agentIdentity: %w", err))
	}

	return errors.Join(errs...)
}

func (c *Collector) collectBlueprints(ctx context.Context, e telemetry.Emitter, outcomes *recordoutcome.Recorder) error {
	raws, err := collectors.GetAllValuesRecorded(ctx, c.g, c.baseURL+blueprintsPath, nil, outcomes)
	if err != nil {
		return err
	}
	for i, raw := range raws {
		var bp blueprint
		if err := json.Unmarshal(raw, &bp); err != nil {
			entraoutcome.Errored(outcomes, uint64(len(raws))-uint64(i), recordoutcome.CauseDecodeError)
			return fmt.Errorf("decode agentIdentityBlueprint: %w", err)
		}
		e.LogEvent(blueprintTwin(bp))
		entraoutcome.Emitted(outcomes, 1)
	}
	e.Gauge(metricBlueprintsTotal, "{blueprint}", "Count of Entra Agent ID blueprint applications.", float64(len(raws)), nil)
	return nil
}

func (c *Collector) collectBlueprintPrincipals(ctx context.Context, e telemetry.Emitter, outcomes *recordoutcome.Recorder) error {
	raws, err := collectors.GetAllValuesRecorded(ctx, c.g, c.baseURL+principalsPath, nil, outcomes)
	if err != nil {
		return err
	}
	counts := map[[2]string]int64{}
	for i, raw := range raws {
		var p blueprintPrincipal
		if err := json.Unmarshal(raw, &p); err != nil {
			entraoutcome.Errored(outcomes, uint64(len(raws))-uint64(i), recordoutcome.CauseDecodeError)
			return fmt.Errorf("decode agentIdentityBlueprintPrincipal: %w", err)
		}
		counts[[2]string{boolPtrStr(p.AccountEnabled), p.SignInAudience}]++
		e.LogEvent(blueprintPrincipalTwin(p))
		entraoutcome.Emitted(outcomes, 1)
	}
	points := make([]telemetry.GaugePoint, 0, len(counts))
	for k, v := range counts {
		points = append(points, telemetry.GaugePoint{
			Value: float64(v),
			Attrs: telemetry.Attrs{semconv.AttrAccountEnabled: k[0], semconv.AttrSignInAudience: k[1]},
		})
	}
	e.GaugeSnapshot(metricBlueprintPrincipals, "{principal}", "Agent ID blueprint principals, by account-enabled state and sign-in audience.", points)
	return nil
}

// collectAgents fetches agent identities twice — once with $expand=sponsors,
// once with $expand=owners (Graph rejects both in one request, live-measured
// 400) — and joins the two responses by id. The sponsors fetch supplies the
// base agent record (every field but owners); a missing owners fetch degrades
// only the owner-shaped signals, and vice versa.
func (c *Collector) collectAgents(ctx context.Context, e telemetry.Emitter, outcomes *recordoutcome.Recorder) error {
	sponsorRaws, sponsorsErr := collectors.GetAllValuesRecorded(ctx, c.g, c.baseURL+agentsSponsorsPath, nil, outcomes)
	ownerRaws, ownersErr := collectors.GetAllValuesRecorded(ctx, c.g, c.baseURL+agentsOwnersPath, nil, outcomes)

	if sponsorsErr != nil && ownersErr != nil {
		entraoutcome.SourceError(outcomes)
		return errors.Join(fmt.Errorf("sponsors expand: %w", sponsorsErr), fmt.Errorf("owners expand: %w", ownersErr))
	}

	agents := map[string]*agentIdentity{}
	var order []string

	if sponsorsErr == nil {
		for i, raw := range sponsorRaws {
			var a agentIdentity
			if err := json.Unmarshal(raw, &a); err != nil {
				entraoutcome.Errored(outcomes, uint64(len(sponsorRaws))-uint64(i), recordoutcome.CauseDecodeError)
				return fmt.Errorf("decode agentIdentity (sponsors): %w", err)
			}
			cp := a
			agents[cp.ID] = &cp
			order = append(order, cp.ID)
		}
	} else {
		c.logger.Warn("agentgovernance: sponsors expand failed, has_sponsor reported as unknown", "collector", collectorName, "error", sponsorsErr)
	}

	// The owners response is the base agent record when the sponsors fetch
	// failed; otherwise it only contributes Owners, joined onto the sponsors
	// response's records BY ID — never by list position (see package doc).
	if ownersErr == nil {
		for i, raw := range ownerRaws {
			var a agentIdentity
			if err := json.Unmarshal(raw, &a); err != nil {
				entraoutcome.Errored(outcomes, uint64(len(ownerRaws))-uint64(i), recordoutcome.CauseDecodeError)
				return fmt.Errorf("decode agentIdentity (owners): %w", err)
			}
			if existing, ok := agents[a.ID]; ok {
				existing.Owners = a.Owners
				continue
			}
			cp := a
			agents[cp.ID] = &cp
			order = append(order, cp.ID)
		}
	} else {
		c.logger.Warn("agentgovernance: owners expand failed, has_owner reported as unknown", "collector", collectorName, "error", ownersErr)
	}

	counts := map[[4]string]int64{}
	withoutSponsor, withoutOwner := int64(0), int64(0)
	for _, id := range order {
		a := agents[id]

		hasSponsor := unknownBool
		if sponsorsErr == nil {
			hasSponsor = boolStr(len(a.Sponsors) > 0)
			if len(a.Sponsors) == 0 {
				withoutSponsor++
			}
		}
		hasOwner := unknownBool
		if ownersErr == nil {
			hasOwner = boolStr(len(a.Owners) > 0)
			if len(a.Owners) == 0 {
				withoutOwner++
			}
		}

		counts[[4]string{boolPtrStr(a.AccountEnabled), hasSponsor, hasOwner, boolPtrStr(a.AppRoleAssignmentRequired)}]++
		e.LogEvent(agentTwin(*a, sponsorsErr == nil, ownersErr == nil))
		entraoutcome.Emitted(outcomes, 1)
	}

	points := make([]telemetry.GaugePoint, 0, len(counts))
	for k, v := range counts {
		points = append(points, telemetry.GaugePoint{
			Value: float64(v),
			Attrs: telemetry.Attrs{
				semconv.AttrAccountEnabled:            k[0],
				semconv.AttrHasSponsor:                k[1],
				semconv.AttrHasOwner:                  k[2],
				semconv.AttrAppRoleAssignmentRequired: k[3],
			},
		})
	}
	e.GaugeSnapshot(metricAgents, "{agent}", "Agent identities, by account-enabled state, sponsor/owner presence, and app-role-assignment requirement.", points)

	// A fetch failure means "unknown", never a fabricated zero — the gap
	// gauges are only emitted when their underlying fetch actually succeeded.
	if sponsorsErr == nil {
		e.Gauge(metricAgentsWithoutSponsor, "{agent}", "Count of agent identities with zero sponsors.", float64(withoutSponsor), nil)
	}
	if ownersErr == nil {
		e.Gauge(metricAgentsWithoutOwner, "{agent}", "Count of agent identities with zero owners.", float64(withoutOwner), nil)
	}

	// A single-sided failure still emits a fully valid, deliberately degraded
	// inventory above — but the failure itself must still be surfaced to the
	// scheduler (self-obs, the run's outcome summary), never silently
	// absorbed just because the other half covered for it.
	var degradeErrs []error
	if sponsorsErr != nil {
		entraoutcome.SourceError(outcomes)
		degradeErrs = append(degradeErrs, fmt.Errorf("sponsors expand: %w", sponsorsErr))
	}
	if ownersErr != nil {
		entraoutcome.SourceError(outcomes)
		degradeErrs = append(degradeErrs, fmt.Errorf("owners expand: %w", ownersErr))
	}
	return errors.Join(degradeErrs...)
}

// capStrings caps vals at maxPrincipalIdentifiers, reporting whether it had
// to. Never mutates vals — the returned slice on the truncated path is a
// fresh subslice header, not vals itself, matching authmethodspolicy's
// capStrings.
func capStrings(vals []string, max int) (out []string, truncated bool) {
	if len(vals) > max {
		return vals[:max:max], true
	}
	return vals, false
}

// setPrincipalRefs renders a []principalRef as a bounded id array, its TRUE
// (uncapped) count, and a truncated flag — count and truncated are always
// set, even at zero, because "this agent has zero owners" is a governance
// fact this collector's whole purpose is to make visible, unlike
// authmethodspolicy's setTargetIDs (which treats "no targets configured" as
// pure absence). Only the id array itself is omitted when empty.
func setPrincipalRefs(attrs telemetry.Attrs, idsKey, countKey, truncatedKey string, refs []principalRef) {
	ids := make([]string, 0, len(refs))
	for _, r := range refs {
		if r.ID != "" {
			ids = append(ids, r.ID)
		}
	}
	capped, truncated := capStrings(ids, maxPrincipalIdentifiers)
	if len(capped) > 0 {
		telemetry.SetStrs(attrs, idsKey, capped)
	}
	attrs[countKey] = float64(len(refs))
	telemetry.SetBool(attrs, truncatedKey, truncated)
}

// setTags renders a tags array as a bounded string list, omitted entirely
// when empty (unlike setPrincipalRefs's count, an empty tags array carries no
// governance signal worth a zero-count series).
func setTags(attrs telemetry.Attrs, tags []string) {
	if len(tags) == 0 {
		return
	}
	capped, truncated := capStrings(tags, maxPrincipalIdentifiers)
	telemetry.SetStrs(attrs, semconv.AttrTags, capped)
	if truncated {
		telemetry.SetBool(attrs, semconv.AttrTagsTruncated, truncated)
	}
}

// blueprintTwin renders one agentIdentityBlueprint as one entra.agent_blueprint
// log record.
func blueprintTwin(bp blueprint) telemetry.Event {
	attrs := telemetry.Attrs{}
	telemetry.SetStr(attrs, semconv.AttrId, bp.ID)
	telemetry.SetStr(attrs, semconv.AttrAppId, bp.AppID)
	telemetry.SetStr(attrs, semconv.AttrDisplayName, bp.DisplayName)
	telemetry.SetStr(attrs, semconv.AttrCreatedDateTime, bp.CreatedDateTime)
	telemetry.SetStr(attrs, semconv.AttrCreatedByAppId, bp.CreatedByAppID)
	telemetry.SetStr(attrs, semconv.AttrPublisherDomain, bp.PublisherDomain)
	telemetry.SetStr(attrs, semconv.AttrSignInAudience, bp.SignInAudience)

	return telemetry.Event{
		Name:     eventBlueprint,
		Body:     fmt.Sprintf("agent identity blueprint %s (%s)", bp.DisplayName, bp.AppID),
		Severity: telemetry.SeverityInfo,
		Attrs:    attrs,
	}
}

// blueprintPrincipalTwin renders one agentIdentityBlueprintPrincipal as one
// entra.agent_blueprint_principal log record.
func blueprintPrincipalTwin(p blueprintPrincipal) telemetry.Event {
	attrs := telemetry.Attrs{}
	telemetry.SetStr(attrs, semconv.AttrId, p.ID)
	telemetry.SetStr(attrs, semconv.AttrAppId, p.AppID)
	telemetry.SetStr(attrs, semconv.AttrAppDisplayName, p.AppDisplayName)
	telemetry.SetStr(attrs, semconv.AttrDisplayName, p.DisplayName)
	if p.AccountEnabled != nil {
		telemetry.SetBool(attrs, semconv.AttrAccountEnabled, *p.AccountEnabled)
	}
	telemetry.SetStr(attrs, semconv.AttrAppOwnerOrganizationId, p.AppOwnerOrganizationID)
	telemetry.SetStr(attrs, semconv.AttrSignInAudience, p.SignInAudience)
	telemetry.SetStr(attrs, semconv.AttrServicePrincipalType, p.ServicePrincipalType)
	setTags(attrs, p.Tags)

	return telemetry.Event{
		Name:     eventBlueprintPrincipal,
		Body:     fmt.Sprintf("agent identity blueprint principal %s (%s)", p.DisplayName, p.AppID),
		Severity: telemetry.SeverityInfo,
		Attrs:    attrs,
	}
}

// agentTwin renders one agentIdentity as one entra.agent_identity log record
// — the blueprint lineage (blueprint_id) plus the sponsor/owner identifiers
// #333 asks for, bounded. sponsorsKnown/ownersKnown say whether that half's
// fetch succeeded this cycle; when false, that half's fields (including the
// count) are omitted entirely rather than reported as zero — see the package
// doc's independent-degradation section.
func agentTwin(a agentIdentity, sponsorsKnown, ownersKnown bool) telemetry.Event {
	attrs := telemetry.Attrs{}
	telemetry.SetStr(attrs, semconv.AttrId, a.ID)
	telemetry.SetStr(attrs, semconv.AttrDisplayName, a.DisplayName)
	telemetry.SetStr(attrs, semconv.AttrBlueprintId, a.AgentIdentityBlueprintID)
	telemetry.SetStr(attrs, semconv.AttrCreatedDateTime, a.CreatedDateTime)
	telemetry.SetStr(attrs, semconv.AttrCreatedByAppId, a.CreatedByAppID)
	if a.AccountEnabled != nil {
		telemetry.SetBool(attrs, semconv.AttrAccountEnabled, *a.AccountEnabled)
	}
	if a.AppRoleAssignmentRequired != nil {
		telemetry.SetBool(attrs, semconv.AttrAppRoleAssignmentRequired, *a.AppRoleAssignmentRequired)
	}
	if a.DisabledByMicrosoftStatus != nil {
		telemetry.SetStr(attrs, semconv.AttrDisabledByMicrosoftStatus, *a.DisabledByMicrosoftStatus)
	}
	telemetry.SetStr(attrs, semconv.AttrServicePrincipalType, a.ServicePrincipalType)
	setTags(attrs, a.Tags)

	if sponsorsKnown {
		setPrincipalRefs(attrs, semconv.AttrSponsorIds, semconv.AttrSponsorCount, semconv.AttrSponsorsTruncated, a.Sponsors)
	}
	if ownersKnown {
		setPrincipalRefs(attrs, semconv.AttrOwnerIds, semconv.AttrOwnerCount, semconv.AttrOwnersTruncated, a.Owners)
	}

	sev := telemetry.SeverityInfo
	if (sponsorsKnown && len(a.Sponsors) == 0) || (ownersKnown && len(a.Owners) == 0) {
		sev = telemetry.SeverityWarn
	}

	return telemetry.Event{
		Name:     eventAgentIdentity,
		Body:     fmt.Sprintf("agent identity %s: sponsors=%d owners=%d", displayOr(a.DisplayName, a.ID), len(a.Sponsors), len(a.Owners)),
		Severity: sev,
		Attrs:    attrs,
	}
}

func displayOr(name, fallback string) string {
	if name != "" {
		return name
	}
	if fallback != "" {
		return fallback
	}
	return "unknown"
}

// boolStr renders a plain bool as the bounded "true"/"false" metric-label
// value.
func boolStr(b bool) string {
	if b {
		return "true"
	}
	return "false"
}

// boolPtrStr renders an optional bool as a bounded metric-label value:
// "true"/"false" when present, unknownBool when the wire omitted it. See the
// package doc's "absent is not false" section for why a metric label cannot
// simply omit the dimension the way a log twin omits the attribute.
func boolPtrStr(b *bool) string {
	if b == nil {
		return unknownBool
	}
	return boolStr(*b)
}

func init() {
	collectors.Register(func(d collectors.Deps) collector.SnapshotCollector {
		return New(d.Graph, d.Logger)
	})
}
