// Package agreements is the Entra Terms of Use collector: tenant-wide
// agreement count plus per-agreement acceptance counts (accepted vs
// declined), emitted as two correctly-bounded aggregate gauges. Terms of Use
// is an Entra ID P1 feature; this Collector implements
// license.CapabilityRequirer so the composition root skips it entirely for a
// tenant that lacks P1, rather than degrading inside Collect.
//
// # Premise deviations found validating against current Microsoft Graph docs
//
// Two things in issue #73's premise do not match the current v1.0 docs
// (fetched 2026-07-15):
//
//  1. State enum. The issue's telemetry model asks for
//     entra.agreements.acceptances.total{agreement,state} with
//     state ∈ {accepted, pending}. The actual microsoft.graph.agreementAcceptance
//     resource (https://learn.microsoft.com/en-us/graph/api/resources/agreementacceptance)
//     documents only two state values: "accepted" and "declined". There is no
//     "pending" acceptance record at all -- a user who has not yet responded
//     to an agreement simply has no acceptance object; the acceptances
//     endpoint never returns a placeholder for them. Computing a true
//     "pending" count would require knowing the agreement's target audience
//     size (all users, or a specific included/excluded group scope), which
//     this endpoint does not expose and which is out of this issue's scope
//     to compute. This collector therefore emits the two states Graph
//     actually returns (accepted, declined) instead of inventing a synthetic
//     pending count.
//
//  2. Application-permission support is undocumented for these exact
//     endpoints. The general permissions reference lists application-permission
//     GUIDs for both Agreement.Read.All and AgreementAcceptance.Read.All (so
//     they exist as assignable app roles), but the specific "List agreements"
//     (https://learn.microsoft.com/en-us/graph/api/termsofusecontainer-list-agreements)
//     and "List acceptances"
//     (https://learn.microsoft.com/en-us/graph/api/agreement-list-acceptances)
//     method docs both mark their permissions table "Application: Not
//     supported" -- only delegated work-or-school access (with a Security
//     Reader-or-above Entra role on the signed-in user) is listed as
//     supported. graph2otel is application-permission-only (client
//     credentials via azidentity.DefaultAzureCredential, never a signed-in
//     user), so this is worth flagging loudly: it is possible these
//     endpoints do not actually work under this exporter's app-only auth
//     model in a live tenant, despite the app roles existing. This collector
//     is implemented per the issue's explicit scope table (application
//     permissions, both endpoints) since the app-role GUIDs do exist and
//     community reports of app-only Terms of Use access are mixed; live-tenant
//     verification before shipping is strongly recommended.
package agreements

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/rknightion/graph2otel/internal/collector"
	"github.com/rknightion/graph2otel/internal/collectors"
	"github.com/rknightion/graph2otel/internal/license"
	"github.com/rknightion/graph2otel/internal/semconv"
	"github.com/rknightion/graph2otel/internal/telemetry"
)

// collectorName is the stable key used for config (enable/interval),
// self-observability, and the admin status page.
const collectorName = "entra.agreements"

// Metric names this collector emits.
const (
	agreementsMetricName  = "entra.agreements.total"
	acceptancesMetricName = "entra.agreements.acceptances.total"
)

// defaultBaseURL is the Graph v1.0 root.
const defaultBaseURL = "https://graph.microsoft.com/v1.0"

// acceptanceStates is the fixed, documented microsoft.graph.agreementAcceptance
// state enum (see the package doc's premise-deviation note). Every
// successfully-fetched agreement is zero-filled across both states, so
// cardinality of the acceptances metric is always exactly
// len(agreements) x len(acceptanceStates), never per-user.
var acceptanceStates = []string{"accepted", "declined"}

// agreement mirrors only the field this collector reads off a Graph
// agreement object. displayName and every other property are deliberately
// never decoded here -- they add nothing this collector's bounded aggregates
// need.
type agreement struct {
	ID string `json:"id"`
}

// agreementAcceptance mirrors only the field this collector reads off a
// Graph agreementAcceptance object. Every per-user field (userId,
// userPrincipalName, userDisplayName, userEmail, deviceId, ...) is not
// decoded here, and this collector deliberately has NO log twin.
//
// That is a real decision, not the #112 framing bug, so do not "fix" it by
// adding one: the cardinality rule requires a log twin for per-entity data a
// metric cannot carry (see CLAUDE.md), and every other snapshot collector that
// was dropping such data got one in #114. This collector is the audited
// exception. "Which users have not accepted the terms of use" is a legal/HR/
// compliance question — it indicates no compromise, misuse, or active threat —
// and a per-user twin here would scale with tenant size to answer a question
// graph2otel is not the tool for. Reconsider only if ToU acceptance becomes a
// security signal for someone.
type agreementAcceptance struct {
	State string `json:"state"`
}

// Collector polls the terms-of-use agreements and their acceptance counts.
type Collector struct {
	g       collectors.GraphClient
	baseURL string
	logger  *slog.Logger
}

// New builds the agreements collector. A nil logger falls back to the slog
// default.
func New(g collectors.GraphClient, logger *slog.Logger) *Collector {
	if logger == nil {
		logger = slog.Default()
	}
	return &Collector{g: g, baseURL: defaultBaseURL, logger: logger}
}

// Name implements collector.Collector.
func (c *Collector) Name() string { return collectorName }

// DefaultInterval implements collector.Collector. Agreements and their
// acceptance posture drift slowly and there is no delta query for either
// endpoint (a full read every cycle), so a longer interval matches this
// exporter's other slow-drifting P1 governance collectors (e.g. conditional
// access).
func (c *Collector) DefaultInterval() time.Duration { return 15 * time.Minute }

// RequiredPermissions declares the least-privilege Graph application scopes:
// Agreement.Read.All to list agreements, AgreementAcceptance.Read.All to
// read each agreement's acceptance records. See the package doc for the
// application-permission-support caveat found validating against current
// Graph docs.
func (c *Collector) RequiredPermissions() []string {
	return []string{"Agreement.Read.All", "AgreementAcceptance.Read.All"}
}

// RequiredCapability implements license.CapabilityRequirer. Terms of Use is
// an Entra ID P1 feature; the composition root uses this to skip the whole
// collector, and show the skip reason on the admin page, for a tenant that
// lacks P1.
func (c *Collector) RequiredCapability() license.Capability { return license.CapEntraP1 }

// Collect fetches the tenant's agreements, emits their total count, then
// fetches each agreement's acceptances and emits a zero-filled
// (agreement, state) count snapshot. A failure listing agreements at all is
// fatal for this tick (there is nothing to iterate), but a failure fetching
// one agreement's acceptances is logged and that agreement is dropped from
// the acceptances snapshot while every other agreement -- and the
// agreements.total gauge -- still emits; the aggregated error is returned so
// the partial failure is visible in scrape self-observability without hiding
// the data that did succeed.
func (c *Collector) Collect(ctx context.Context, e telemetry.Emitter) error {
	rawAgreements, err := collectors.GetAllValues(ctx, c.g, c.baseURL+"/identityGovernance/termsOfUse/agreements", nil)
	if err != nil {
		c.logger.Warn("agreements: fetch agreements failed", "collector", collectorName, "error", err)
		return fmt.Errorf("fetch agreements: %w", err)
	}

	ids := make([]string, 0, len(rawAgreements))
	for _, raw := range rawAgreements {
		var a agreement
		if err := json.Unmarshal(raw, &a); err != nil {
			c.logger.Warn("agreements: skipping unparseable agreement", "collector", collectorName, "error", err)
			continue
		}
		if a.ID == "" {
			c.logger.Warn("agreements: skipping agreement with empty id", "collector", collectorName)
			continue
		}
		ids = append(ids, a.ID)
	}

	e.Gauge(agreementsMetricName, "{agreement}",
		"Total Entra terms-of-use agreements configured for the tenant.",
		float64(len(ids)), nil)

	var errs []error
	points := make([]telemetry.GaugePoint, 0, len(ids)*len(acceptanceStates))
	for _, id := range ids {
		acceptancePoints, err := c.collectAcceptances(ctx, id)
		if err != nil {
			c.logger.Warn("agreements: fetch acceptances failed", "collector", collectorName, "agreement", id, "error", err)
			errs = append(errs, fmt.Errorf("agreement %s acceptances: %w", id, err))
			continue
		}
		points = append(points, acceptancePoints...)
	}
	e.GaugeSnapshot(acceptancesMetricName, "{acceptance}",
		"Entra terms-of-use acceptance counts, by agreement and acceptance state (accepted/declined).",
		points)

	return errors.Join(errs...)
}

// collectAcceptances fetches one agreement's acceptances and returns its
// zero-filled (agreement, state) gauge points. An acceptance with an
// unrecognized state (a future Graph addition beyond accepted/declined) is
// logged and excluded from the count, never mapped to some catch-all bucket.
func (c *Collector) collectAcceptances(ctx context.Context, agreementID string) ([]telemetry.GaugePoint, error) {
	raw, err := collectors.GetAllValues(ctx, c.g, c.baseURL+"/identityGovernance/termsOfUse/agreements/"+agreementID+"/acceptances", nil)
	if err != nil {
		return nil, err
	}

	counts := make(map[string]int64, len(acceptanceStates))
	for _, s := range acceptanceStates {
		counts[s] = 0
	}

	for _, r := range raw {
		var acc agreementAcceptance
		if err := json.Unmarshal(r, &acc); err != nil {
			c.logger.Warn("agreements: skipping unparseable acceptance", "collector", collectorName, "agreement", agreementID, "error", err)
			continue
		}
		if _, ok := counts[acc.State]; !ok {
			c.logger.Warn("agreements: skipping acceptance with unrecognized state", "collector", collectorName, "agreement", agreementID, "state", acc.State)
			continue
		}
		counts[acc.State]++
	}

	points := make([]telemetry.GaugePoint, 0, len(acceptanceStates))
	for _, s := range acceptanceStates {
		points = append(points, telemetry.GaugePoint{
			Value: float64(counts[s]),
			Attrs: telemetry.Attrs{semconv.AttrAgreement: agreementID, semconv.AttrState: s},
		})
	}
	return points, nil
}

func init() {
	collectors.Register(func(d collectors.Deps) collector.SnapshotCollector {
		return New(d.Graph, d.Logger)
	})
}
