// Package authstrength is the Entra authentication-strength-policy collector
// (#322): GET /policies/authenticationStrengthPolicies, a small tenant-wide
// collection (no delta query; live-measured 2026-07-28: 3 built-in policies,
// no @odata.nextLink) naming which authentication-method COMBINATIONS
// satisfy each policy's requirement level.
//
// This is distinct from entra/conditionalaccess: a Conditional Access policy
// can REFERENCE an authentication-strength policy by id (the
// grantControls.authenticationStrength relationship), but the CA aggregates
// do not inventory which strength policies exist or what combinations they
// allow. Without this collector there is no visibility into whether a
// "phishing-resistant MFA" policy exists at all, or whether a custom policy
// has been configured to allow a weak combination.
//
// # One bounded gauge, one log twin per policy
//
// entra.auth_strength.policies buckets policy COUNT by the tuple
// (policy_type, requirements_satisfied) — both are Entra's own small,
// documented enums (policyType: builtIn/custom; requirementsSatisfied:
// mfa/none), so the series count is bounded by that enum product, never by
// tenant configuration. Only buckets actually present in the response are
// emitted (telemetry.GaugeSnapshot's per-cycle replacement semantics — see
// its doc comment), never a fabricated zero for a combination the response
// didn't return.
//
// Everything a 2-label gauge cannot express — which policy this is, its
// display name and description, and above all which method combinations it
// allows — rides the entra.auth_strength_policy log twin, one per policy
// returned (#114's "not a metric label means log twin, never dropped" rule).
// Policy ids and names are LOG-ONLY and must never become metric labels
// (#112).
//
// # allowedCombinations: verbatim strings, never split
//
// A combination such as "password,microsoftAuthenticatorPush" is Graph's
// wire representation of ONE conjunction — "both of these together satisfy
// the policy" — not two independent methods. Splitting it on the comma would
// silently turn a conjunction into a disjunction, changing what the policy
// actually says. This collector therefore emits each allowedCombinations
// entry VERBATIM as one array element, in wire order, never parsed or
// normalized. The array is capped at maxAllowedCombinations (see its own
// comment for the live headroom this leaves), with the true uncapped count
// and a truncated flag riding alongside so a capped array never silently
// understates how many combinations a policy allows.
//
// # combinationConfigurations: count only, evidence-gated
//
// combinationConfigurations is empty on every one of the three live-measured
// policies (2026-07-28) — Graph's mechanism for restricting a combination
// further (e.g. a FIDO2 AAGUID allow-list scoped to just this policy) is
// unconfigured on the source tenant. Per this repo's binding rule that
// mappers are written against live samples and never against unseen data
// (the same discipline entra/tenantpolicy applies to its own empty
// scoped-policy collections, #142/#165), this collector emits ONLY the
// entry COUNT — no field mapper, no child twin. Unblock condition: a tenant
// with at least one combinationConfigurations entry actually configured (a
// FIDO2 AAGUID restriction is the documented example), captured live and
// used to extend this mapper with evidence.
//
// # wirecheck: policy_type and requirements_satisfied left UNWATCHED
//
// Both are metric label value sets keyed off Graph-supplied enums, which
// would ordinarily be exactly what internal/wirecheck watches for a new
// member. They are deliberately left unwatched here because only one value
// of each has ever been observed live (policyType="builtIn",
// requirementsSatisfied="mfa") — CLAUDE.md's rule is explicit that one
// observed value is not a value set, and a watchdog that fires on the first
// legitimate second value (a tenant's own custom strength policy, or a
// future "none" requirement level) is worse than no watchdog at all. Add
// wirecheck coverage once a second value has been seen on the wire, not
// before.
package authstrength

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
const collectorName = "entra.auth_strength"

// metricPolicies is the bounded (policy_type, requirements_satisfied) count
// gauge. See the package doc for why this pair is bounded.
const metricPolicies = "entra.auth_strength.policies"

// eventPolicy is the per-policy log twin's OTEL EventName. LOG-ONLY — never a
// metric label.
const eventPolicy = "entra.auth_strength_policy"

// defaultBaseURL is the Graph v1.0 root.
const defaultBaseURL = "https://graph.microsoft.com/v1.0"

// policyPath lists the tenant's authentication-strength policies.
const policyPath = "/policies/authenticationStrengthPolicies"

// maxAllowedCombinations bounds the allowedCombinations array every policy
// twin carries. The live-measured 2026-07-28 capture's largest policy (the
// built-in "Multifactor authentication" policy) carries 19 entries, so this
// cap leaves wide headroom for a tenant with several custom policies each
// adding a handful of combinations, while still being a defensive backstop
// against a pathological one — the same role maxTargetIdentifiers plays in
// entra/authmethodspolicy.
const maxAllowedCombinations = 100

// authStrengthPolicy mirrors the subset of a Graph authenticationStrengthPolicy
// this collector reads. AllowedCombinations is decoded as raw strings —
// never split or normalized, see the package doc.
// CombinationConfigurations is decoded only to be counted (its element shape
// is unmapped, see the package doc's evidence-gated-gap section).
type authStrengthPolicy struct {
	ID                        string            `json:"id"`
	CreatedDateTime           string            `json:"createdDateTime"`
	ModifiedDateTime          string            `json:"modifiedDateTime"`
	DisplayName               string            `json:"displayName"`
	Description               string            `json:"description"`
	PolicyType                string            `json:"policyType"`
	RequirementsSatisfied     string            `json:"requirementsSatisfied"`
	AllowedCombinations       []string          `json:"allowedCombinations"`
	CombinationConfigurations []json.RawMessage `json:"combinationConfigurations"`
}

// gaugeBucket is the (policy_type, requirements_satisfied) key the bounded
// gauge counts by.
type gaugeBucket struct {
	policyType            string
	requirementsSatisfied string
}

// Collector polls GET /policies/authenticationStrengthPolicies.
type Collector struct {
	g       collectors.GraphClient
	baseURL string
	logger  *slog.Logger
}

// New builds the authentication-strength-policy collector. A nil logger
// falls back to the slog default.
func New(g collectors.GraphClient, logger *slog.Logger) *Collector {
	if logger == nil {
		logger = slog.Default()
	}
	return &Collector{g: g, baseURL: defaultBaseURL, logger: logger}
}

// Name implements collector.Collector.
func (c *Collector) Name() string { return collectorName }

// DefaultInterval implements collector.Collector. This is tenant policy
// configuration, not an event stream — it changes rarely, so fifteen minutes
// is ample and cheap on the directory/policy throttle bucket.
func (c *Collector) DefaultInterval() time.Duration { return 15 * time.Minute }

// RequiredPermissions declares the application scope this endpoint was
// probed under (live-measured 2026-07-28, graph2otel-poller).
func (c *Collector) RequiredPermissions() []string {
	return []string{"Policy.Read.All"}
}

// Collect fetches every authentication-strength policy and emits both the
// bounded (policy_type, requirements_satisfied) count gauge and one log twin
// per policy. GetAllValuesRecorded follows @odata.nextLink itself, though the
// live tenant returns all three policies on one page. A per-policy decode
// failure is skipped with its error aggregated rather than taking the whole
// poll down; an empty collection is a legitimate steady state, not an error.
func (c *Collector) Collect(ctx context.Context, e telemetry.Emitter, outcomes *recordoutcome.Recorder) error {
	raws, err := collectors.GetAllValuesRecorded(ctx, c.g, c.baseURL+policyPath, nil, outcomes)
	if err != nil {
		entraoutcome.SourceError(outcomes)
		return fmt.Errorf("authstrength: fetch authenticationStrengthPolicies: %w", err)
	}

	buckets := map[gaugeBucket]int64{}
	var errs []error
	for _, raw := range raws {
		var p authStrengthPolicy
		if err := json.Unmarshal(raw, &p); err != nil {
			entraoutcome.Errored(outcomes, 1, recordoutcome.CauseDecodeError)
			errs = append(errs, fmt.Errorf("authstrength: decode authenticationStrengthPolicy: %w", err))
			continue
		}
		buckets[gaugeBucket{policyType: p.PolicyType, requirementsSatisfied: p.RequirementsSatisfied}]++
		e.LogEvent(policyTwin(p))
		entraoutcome.Emitted(outcomes, 1)
	}

	points := make([]telemetry.GaugePoint, 0, len(buckets))
	for b, n := range buckets {
		points = append(points, telemetry.GaugePoint{
			Value: float64(n),
			Attrs: telemetry.Attrs{
				semconv.AttrPolicyType:            b.policyType,
				semconv.AttrRequirementsSatisfied: b.requirementsSatisfied,
			},
		})
	}
	e.GaugeSnapshot(metricPolicies, "{policy}",
		"Entra authentication-strength policies configured for the tenant, by policy type and requirements satisfied.",
		points)

	return errors.Join(errs...)
}

// capStrings caps vals at max, reporting whether it had to. Never mutates
// vals — the returned slice on the truncated path is a fresh subslice
// header, not vals itself, so callers can't accidentally reuse the full
// backing array past the cap. Mirrors entra/authmethodspolicy's helper of
// the same name.
func capStrings(vals []string, max int) (out []string, truncated bool) {
	if len(vals) > max {
		return vals[:max:max], true
	}
	return vals, false
}

// policyTwin renders one authenticationStrengthPolicy as one
// entra.auth_strength_policy log record. Every field is fixed and typed; see
// the package doc for why allowedCombinations is verbatim/unsplit and why
// combinationConfigurations is a count only.
func policyTwin(p authStrengthPolicy) telemetry.Event {
	attrs := telemetry.Attrs{}
	telemetry.SetStr(attrs, semconv.AttrId, p.ID)
	telemetry.SetStr(attrs, semconv.AttrDisplayName, p.DisplayName)
	telemetry.SetStr(attrs, semconv.AttrDescription, p.Description)
	telemetry.SetStr(attrs, semconv.AttrPolicyType, p.PolicyType)
	telemetry.SetStr(attrs, semconv.AttrRequirementsSatisfied, p.RequirementsSatisfied)
	telemetry.SetStr(attrs, semconv.AttrCreatedDateTime, p.CreatedDateTime)
	telemetry.SetStr(attrs, semconv.AttrModifiedDateTime, p.ModifiedDateTime)

	capped, truncated := capStrings(p.AllowedCombinations, maxAllowedCombinations)
	telemetry.SetStrs(attrs, semconv.AttrAllowedCombinations, capped)
	attrs[semconv.AttrAllowedCombinationCount] = float64(len(p.AllowedCombinations))
	telemetry.SetBool(attrs, semconv.AttrAllowedCombinationsTruncated, truncated)

	// combinationConfigurations: COUNT ONLY, deliberately — see the package
	// doc. No field mapper is written against an array this collector has
	// never observed non-empty.
	attrs[semconv.AttrCombinationConfigurationCount] = float64(len(p.CombinationConfigurations))

	return telemetry.Event{
		Name:     eventPolicy,
		Body:     fmt.Sprintf("authentication strength policy %s (%s): requirementsSatisfied=%s, %d allowed combinations", p.ID, p.PolicyType, p.RequirementsSatisfied, len(p.AllowedCombinations)),
		Severity: telemetry.SeverityInfo,
		Attrs:    attrs,
	}
}

func init() {
	collectors.Register(func(d collectors.Deps) collector.SnapshotCollector {
		return New(d.Graph, d.Logger)
	})
}
