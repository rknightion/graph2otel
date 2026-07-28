// Package conditionalaccess is the Entra Conditional Access posture
// collector: policy counts by enforcement state and named-location counts by
// type/trust, emitted as two correctly-bounded aggregate gauges. Both
// resources live under /identity/conditionalAccess, share the Entra ID P1
// license gate, and share the same very-low Identity Protection / CA throttle
// bucket (1 request/second per tenant across all apps, with no Retry-After —
// see internal/collectors.GraphClient's rate-limited transport), so they are
// merged into one collector per issue #58.
//
// Conditional Access is a whole-collector, Entra ID P1-gated feature: this
// Collector implements license.CapabilityRequirer so the composition root
// skips it entirely for a tenant that lacks P1, rather than degrading inside
// Collect.
//
// # Log twins (#318)
//
// Both fetches ALSO emit one log record per returned entity —
// entra.conditional_access_policy and entra.named_location — alongside the
// gauges above, which stay exactly as they are. This is the same rule as
// entra/risk: "not a metric label" means "log twin", never dropped (see
// CLAUDE.md). Per-policy configuration (conditions, grant/session controls)
// and per-location detail (CIDR ranges, countries) were discarded before
// #318; they now land as typed fixed attributes and arrays on the ONE record
// for that entity — never a per-target or per-condition child record, which
// the maintainer explicitly rejected as a normalised alternative.
//
// The one wire trap both twins must preserve: a countryNamedLocation never
// carries an isTrusted key at all, while an ipNamedLocation always does. The
// aggregate gauge (namedLocationPoints) is allowed to keep collapsing that
// absence to is_trusted=false for bucketing purposes; the log twin
// (namedLocationLogEvent) is not — it must omit the attribute entirely for a
// country location, never assert a value the wire never sent. See
// TestNamedLocationLogTwinCountryOmitsIsTrusted.
package conditionalaccess

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
	entraoutcome "github.com/rknightion/graph2otel/internal/outcomehelper"
	"github.com/rknightion/graph2otel/internal/recordoutcome"
	"github.com/rknightion/graph2otel/internal/semconv"
	"github.com/rknightion/graph2otel/internal/telemetry"
	"github.com/rknightion/graph2otel/internal/wirecheck"
)

// collectorName is the stable key used for config (enable/interval),
// self-observability, and the admin status page.
const collectorName = "entra.conditional_access"

// Metric names this collector emits.
const (
	policiesMetricName       = "entra.ca.policies.total"
	namedLocationsMetricName = "entra.named_locations.total"
)

// The two log EventNames carrying the per-entity detail the gauges above
// cannot — one record per returned policy / named location per cycle,
// added alongside the gauges by #318 (never replacing them; see the package
// doc and CLAUDE.md's "metrics carry aggregates, logs carry entities" rule).
const (
	eventPolicy        = "entra.conditional_access_policy"
	eventNamedLocation = "entra.named_location"
)

// maxArrayAttr bounds every array-valued log attribute this collector emits
// (target id lists, control lists, condition value lists, CIDR ranges) so a
// pathologically large policy or location can never grow one log record's
// attribute set without limit. Graph itself already bounds most of these by
// construction (a tenant hand-configures conditions/targets), but this is the
// defensive backstop — same pattern as intune/certificates' maxCertProfileNames
// and intune/certinventoryreport's maxIssuerNames. A record whose truncation
// trips this cap sets semconv.AttrArraysTruncated so the loss is visible in
// the record itself, never silent.
const maxArrayAttr = 50

// defaultBaseURL is the Graph v1.0 root.
const defaultBaseURL = "https://graph.microsoft.com/v1.0"

// policyState pairs a conditionalAccessPolicy.state raw Graph value (per the
// v1.0 resource docs: https://learn.microsoft.com/en-us/graph/api/resources/conditionalaccesspolicy)
// with its bounded, emitted `state` attribute value. This is the fixed,
// exhaustive set — cardinality of the policies metric is always exactly
// len(policyStates), zero-filled every tick regardless of how many policies
// exist or which states are actually in use.
type policyState struct {
	graphValue string
	attr       string
}

var policyStates = []policyState{
	{"enabled", "enabled"},
	{"disabled", "disabled"},
	{"enabledForReportingButNotEnforced", "enabled_for_reporting_but_not_enforced"},
}

// locKey is the bounded (type, is_trusted) dimension pair for named
// locations. Cardinality is at most 4: {ip,country} x {true,false}.
type locKey struct {
	typ     string
	trusted bool
}

// conditionalAccessPolicy mirrors the fields this collector reads off a Graph
// conditionalAccessPolicy. State alone feeds the bounded aggregate gauge
// (policyPoints); everything else here is per-policy detail that was
// discarded before #318 and now feeds ONLY the entra.conditional_access_policy
// log twin (policyLogEvent) — never a metric label, per CLAUDE.md's
// "metrics carry aggregates, logs carry entities" rule.
type conditionalAccessPolicy struct {
	ID               string        `json:"id"`
	DisplayName      string        `json:"displayName"`
	State            string        `json:"state"`
	CreatedDateTime  string        `json:"createdDateTime"`
	ModifiedDateTime string        `json:"modifiedDateTime"`
	TemplateID       string        `json:"templateId"`
	Conditions       *caConditions `json:"conditions"`

	// GrantControls and SessionControls are POINTERS, deliberately. Both are
	// null on the wire for a real policy (grantControls is null on a
	// report-only-with-no-requirement policy; sessionControls is null on the
	// majority of policies in this project's own live capture, #318). A
	// pointer field decodes a JSON null to a nil Go pointer — never to a
	// zero-value struct that would make "there is no grantControls at all"
	// indistinguishable from "grantControls is present with an empty
	// operator". See policyLogEvent's has_grant_controls/has_session_controls.
	GrantControls   *caGrantControls `json:"grantControls"`
	SessionControls *caSessionMarker `json:"sessionControls"`
}

// caConditions mirrors the subset of conditionalAccessPolicy.conditions this
// collector maps into typed array attributes. Every field here is a Microsoft
// Graph condition VALUE (a client-app-type, a risk level, a target id) — never
// a per-condition child record; see the package doc's #318 note.
type caConditions struct {
	ClientAppTypes   []string     `json:"clientAppTypes"`
	SignInRiskLevels []string     `json:"signInRiskLevels"`
	UserRiskLevels   []string     `json:"userRiskLevels"`
	Users            *caUsers     `json:"users"`
	Locations        *caLocations `json:"locations"`
}

// caUsers mirrors conditions.users' six target-id arrays. Each becomes one
// flat array ATTRIBUTE on the policy's single log record — not a per-target
// child record (the maintainer-rejected normalised alternative, #318).
// Members are object ids or the literal sentinels Graph itself uses ("All",
// "None", "GuestsOrExternalUsers"); this collector does not resolve them.
type caUsers struct {
	IncludeUsers  []string `json:"includeUsers"`
	ExcludeUsers  []string `json:"excludeUsers"`
	IncludeGroups []string `json:"includeGroups"`
	ExcludeGroups []string `json:"excludeGroups"`
	IncludeRoles  []string `json:"includeRoles"`
	ExcludeRoles  []string `json:"excludeRoles"`
}

// caLocations mirrors conditions.locations' two target-id arrays. A value
// here (other than the "All"/"AllTrusted" sentinels) is a named-location id —
// a natural join key onto this same collector's entra.named_location twin.
type caLocations struct {
	IncludeLocations []string `json:"includeLocations"`
	ExcludeLocations []string `json:"excludeLocations"`
}

// caGrantControls mirrors grantControls. AuthenticationStrength is itself a
// pointer for the same null-vs-zero-value reason as GrantControls/
// SessionControls above: most policies in the live capture carry
// "authenticationStrength": null even when grantControls itself is present.
type caGrantControls struct {
	Operator               string                    `json:"operator"`
	BuiltInControls        []string                  `json:"builtInControls"`
	AuthenticationStrength *caAuthenticationStrength `json:"authenticationStrength"`
}

// caAuthenticationStrength mirrors only the one human-readable field this
// collector reads off grantControls.authenticationStrength. The nested
// object's own id/description/allowedCombinations are deliberately left
// unmapped — pulling them in would grow this twin into a second child
// record, which #318 rejected.
type caAuthenticationStrength struct {
	DisplayName string `json:"displayName"`
}

// caSessionMarker is sessionControls decoded ONLY far enough to distinguish
// "present" from "null" — this collector's twin reports has_session_controls
// as a presence flag, not the full session-control configuration (persistent
// browser mode, sign-in frequency, ...), which would again be per-condition
// detail #318's schema decision rejected growing into. A pointer to an empty
// struct is enough: decoding succeeds for any object shape sessionControls
// takes, and a JSON null still decodes to a nil pointer.
type caSessionMarker struct{}

// namedLocation mirrors the fields this collector reads off a Graph
// namedLocation, either subtype. @odata.type distinguishes ipNamedLocation
// from countryNamedLocation. IsTrusted is a pointer because it is only ever
// present on ipNamedLocation — countryNamedLocation has no trust concept in
// Graph at all (verified against the v1.0 namedLocation resource docs), so a
// missing/absent field (nil) is treated as untrusted for the AGGREGATE GAUGE
// (namedLocationPoints), never as a parse error. The log twin
// (namedLocationLogEvent) must NOT make that same collapse — see #318 and
// TestNamedLocationLogTwinCountryOmitsIsTrusted: a twin emitting
// is_trusted=false for a country location would claim the wire said
// something it never said.
//
// IncludeUnknownCountriesAndRegions is likewise a pointer: it is a real
// countryNamedLocation-only field (false is a genuine configured fact,
// distinct from absence on an ipNamedLocation, which has no such property at
// all).
type namedLocation struct {
	ID                                string        `json:"id"`
	DisplayName                       string        `json:"displayName"`
	Type                              string        `json:"@odata.type"`
	CreatedDateTime                   string        `json:"createdDateTime"`
	ModifiedDateTime                  string        `json:"modifiedDateTime"`
	IsTrusted                         *bool         `json:"isTrusted"`
	IPRanges                          []ipCidrRange `json:"ipRanges"`
	CountriesAndRegions               []string      `json:"countriesAndRegions"`
	CountryLookupMethod               string        `json:"countryLookupMethod"`
	IncludeUnknownCountriesAndRegions *bool         `json:"includeUnknownCountriesAndRegions"`
}

// ipCidrRange mirrors one element of an ipNamedLocation's ipRanges array.
// @odata.type is the ONE thing this collector cares about beyond the address
// itself: it is the discriminator between an IPv4CidrRange and an
// IPv6CidrRange, and #318 requires both to survive into the twin as
// separately typed arrays (see namedLocationLogEvent) rather than one mixed
// list that loses which was which.
type ipCidrRange struct {
	Type    string `json:"@odata.type"`
	Address string `json:"cidrAddress"`
}

const (
	odataTypeIPNamedLocation      = "#microsoft.graph.ipNamedLocation"
	odataTypeCountryNamedLocation = "#microsoft.graph.countryNamedLocation"

	odataTypeIPv4CidrRange = "#microsoft.graph.iPv4CidrRange"
	odataTypeIPv6CidrRange = "#microsoft.graph.iPv6CidrRange"
)

// namedLocationTypes maps each namedLocation @odata.type discriminator this
// collector understands to its bounded `type` attribute value. It is the single
// list of subtypes: the lookup, the metric's zero-filled dimension, and the
// watched Enum below all derive from it, so none of the three can drift apart.
var namedLocationTypes = map[string]string{
	odataTypeIPNamedLocation:      "ip",
	odataTypeCountryNamedLocation: "country",
}

// The wire assumptions this collector watches at runtime (#233/#234).
//
// Both fields are METRIC LABELS, and both do something worse than bucket to
// "unknown": an unrecognized value is SKIPPED, so the policy or location leaves
// the total entirely. A Microsoft subtype addition therefore does not move a
// series — it silently makes one smaller, which reads exactly like a tenant
// that deleted something. Nothing else in the emitted signal says otherwise.
//
// Each Enum is derived from the mapping the collector actually keys on — the
// namedLocationTypes map and the policyStates table — rather than restated from
// Microsoft's documentation, so the watched set is by construction the set this
// collector maps: it fires when, and only when, the mapping has a hole. Same
// reasoning as intune.autopilot's three bucket-map Enums.
var (
	knownNamedLocationTypes = func() wirecheck.Enum {
		keys := make([]string, 0, len(namedLocationTypes))
		for k := range namedLocationTypes {
			keys = append(keys, k)
		}
		return wirecheck.NewEnum(keys...)
	}()

	knownPolicyStates = func() wirecheck.Enum {
		values := make([]string, 0, len(policyStates))
		for _, ps := range policyStates {
			values = append(values, ps.graphValue)
		}
		return wirecheck.NewEnum(values...)
	}()
)

// Collector polls Conditional Access policies and named locations.
type Collector struct {
	g       collectors.GraphClient
	baseURL string
	logger  *slog.Logger
	watch   *wirecheck.Reporter
}

// New builds the Conditional Access collector. A nil logger falls back to the
// slog default.
func New(g collectors.GraphClient, logger *slog.Logger) *Collector {
	if logger == nil {
		logger = slog.Default()
	}
	return &Collector{g: g, baseURL: defaultBaseURL, logger: logger, watch: wirecheck.New(collectorName, logger)}
}

// Name implements collector.Collector.
func (c *Collector) Name() string { return collectorName }

// DefaultInterval implements collector.Collector. CA policy and named
// location configuration drifts slowly and neither resource supports delta
// queries (a full read every cycle), so a longer interval matches this
// exporter's other slow-drifting config collectors (e.g. licensing). It also
// keeps this collector's contribution to the shared 1 request/second
// Identity Protection / CA throttle bucket small.
func (c *Collector) DefaultInterval() time.Duration { return 15 * time.Minute }

// RequiredPermissions declares the least-privilege Graph application scope.
// Per current Microsoft Graph docs, Policy.Read.All is the least-privileged
// application permission for both GET /identity/conditionalAccess/policies
// and GET /identity/conditionalAccess/namedLocations.
func (c *Collector) RequiredPermissions() []string { return []string{"Policy.Read.All"} }

// RequiredCapability implements license.CapabilityRequirer. Conditional
// Access (both policies and named locations) is an Entra ID P1 feature; the
// composition root uses this to skip the whole collector, and show the skip
// reason on the admin page, for a tenant that lacks P1.
func (c *Collector) RequiredCapability() license.Capability { return license.CapEntraP1 }

// Collect fetches CA policies and named locations independently and emits
// each as its own atomic gauge snapshot. A failure fetching one resource is
// logged and that resource's metric is left un-emitted this tick (the SDK's
// observable-gauge, precomputed-last-value aggregation simply reports nothing
// new for it), but the other resource still emits; the aggregated error is
// returned so the partial failure is visible in scrape self-observability
// without hiding the data that did succeed.
func (c *Collector) Collect(ctx context.Context, e telemetry.Emitter, outcomes *recordoutcome.Recorder) error {
	var errs []error

	rawPolicies, err := collectors.GetAllValuesRecorded(ctx, c.g, c.baseURL+"/identity/conditionalAccess/policies", nil, outcomes)
	if err != nil {
		entraoutcome.SourceError(outcomes)
		c.logger.Warn("conditional access: fetch policies failed", "collector", collectorName, "error", err)
		errs = append(errs, fmt.Errorf("fetch policies: %w", err))
	} else {
		e.GaugeSnapshot(policiesMetricName, "{policy}",
			"Entra Conditional Access policies, by enforcement state.",
			c.policyPoints(rawPolicies, e, outcomes))
	}

	rawLocations, err := collectors.GetAllValuesRecorded(ctx, c.g, c.baseURL+"/identity/conditionalAccess/namedLocations", nil, outcomes)
	if err != nil {
		entraoutcome.SourceError(outcomes)
		c.logger.Warn("conditional access: fetch named locations failed", "collector", collectorName, "error", err)
		errs = append(errs, fmt.Errorf("fetch named locations: %w", err))
	} else {
		e.GaugeSnapshot(namedLocationsMetricName, "{location}",
			"Entra Conditional Access named locations, by type and trust.",
			c.namedLocationPoints(rawLocations, e, outcomes))
	}

	return errors.Join(errs...)
}

// policyStateAttr resolves a raw Graph state value to its bounded attribute
// value. ok is false for any value outside the documented enum (e.g. a future
// state Microsoft adds later), so Collect can skip it rather than either
// crash or silently grow the label set.
func policyStateAttr(graphValue string) (attr string, ok bool) {
	for _, ps := range policyStates {
		if ps.graphValue == graphValue {
			return ps.attr, true
		}
	}
	return "", false
}

// policyPoints tallies raw policy JSON into the fixed, zero-filled set of
// per-state counts and returns them as gauge points. A policy with an
// unparseable body or an unrecognized state is logged and excluded from the
// count, never mapped to some catch-all series — and an unrecognized state is
// also reported to wirecheck, because in the metric alone the exclusion looks
// exactly like a tenant that deleted a policy.
func (c *Collector) policyPoints(raw []json.RawMessage, e telemetry.Emitter, outcomes *recordoutcome.Recorder) []telemetry.GaugePoint {
	counts := make(map[string]int, len(policyStates))
	for _, ps := range policyStates {
		counts[ps.attr] = 0
	}

	for _, r := range raw {
		var p conditionalAccessPolicy
		if err := json.Unmarshal(r, &p); err != nil {
			entraoutcome.Errored(outcomes, 1, recordoutcome.CauseDecodeError)
			c.logger.Warn("conditional access: skipping unparseable policy", "collector", collectorName, "error", err)
			continue
		}
		// The log twin is emitted for EVERY successfully-decoded policy,
		// regardless of whether its state matches the bounded enum below
		// (#318): "one entra.conditional_access_policy record per returned
		// policy" is unconditional, unlike the gauge's skip-on-unrecognized
		// behavior — a policy with a state Microsoft adds tomorrow still
		// deserves its detail recorded even though it cannot yet bucket into
		// the aggregate.
		e.LogEvent(policyLogEvent(p))

		attr, ok := policyStateAttr(p.State)
		if !ok {
			entraoutcome.Dropped(outcomes, 1, recordoutcome.CauseMappingError)
			c.watch.Value(e, semconv.AttrState, p.State, knownPolicyStates)
			c.logger.Warn("conditional access: skipping policy with unrecognized state", "collector", collectorName, "state", p.State)
			continue
		}
		counts[attr]++
		entraoutcome.Emitted(outcomes, 1)
	}

	points := make([]telemetry.GaugePoint, 0, len(policyStates))
	for _, ps := range policyStates {
		points = append(points, telemetry.GaugePoint{
			Value: float64(counts[ps.attr]),
			Attrs: telemetry.Attrs{semconv.AttrState: ps.attr},
		})
	}
	return points
}

// namedLocationType resolves a namedLocation's @odata.type discriminator to
// its bounded `type` attribute value. ok is false for any subtype outside the
// two Graph defines today, so Collect can skip it rather than grow the label
// set on a future Microsoft addition — and report it, since a skip is
// invisible in the metric (see knownNamedLocationTypes).
func namedLocationType(odataType string) (typ string, ok bool) {
	typ, ok = namedLocationTypes[odataType]
	return typ, ok
}

// namedLocationPoints tallies raw named-location JSON into the fixed,
// zero-filled set of per-(type, is_trusted) counts and returns them as gauge
// points. countryNamedLocation has no isTrusted property in Graph at all
// (trust is an IP-range-only concept), so every country location counts as
// is_trusted=false — never a parse error, never a third "unknown" bucket.
//
// A location of an unrecognized subtype is skipped as before AND reported to
// wirecheck: skipping is the right emission (a guessed bucket would be worse),
// but on its own it shrinks the total with nothing saying why.
func (c *Collector) namedLocationPoints(raw []json.RawMessage, e telemetry.Emitter, outcomes *recordoutcome.Recorder) []telemetry.GaugePoint {
	counts := make(map[locKey]int, 2*len(namedLocationTypes))
	for _, typ := range namedLocationTypes {
		counts[locKey{typ, true}] = 0
		counts[locKey{typ, false}] = 0
	}

	for _, r := range raw {
		var l namedLocation
		if err := json.Unmarshal(r, &l); err != nil {
			entraoutcome.Errored(outcomes, 1, recordoutcome.CauseDecodeError)
			c.logger.Warn("conditional access: skipping unparseable named location", "collector", collectorName, "error", err)
			continue
		}
		typ, ok := namedLocationType(l.Type)
		// The log twin is emitted for EVERY successfully-decoded location,
		// regardless of whether its @odata.type matches a known subtype
		// (#318): unlike the gauge, which must skip an unrecognized subtype
		// to avoid growing its bounded dimension, the twin has no such
		// bound to protect. twinType falls back to the raw wire value so an
		// unrecognized future subtype still gets its detail recorded rather
		// than losing the record entirely.
		twinType := l.Type
		if ok {
			twinType = typ
		}
		e.LogEvent(namedLocationLogEvent(l, twinType))
		if !ok {
			entraoutcome.Dropped(outcomes, 1, recordoutcome.CauseMappingError)
			c.watch.Value(e, semconv.AttrType, l.Type, knownNamedLocationTypes)
			c.logger.Warn("conditional access: skipping named location with unrecognized @odata.type", "collector", collectorName, "type", l.Type)
			continue
		}
		trusted := l.IsTrusted != nil && *l.IsTrusted
		counts[locKey{typ, trusted}]++
		entraoutcome.Emitted(outcomes, 1)
	}

	points := make([]telemetry.GaugePoint, 0, len(counts))
	for k, n := range counts {
		points = append(points, telemetry.GaugePoint{
			Value: float64(n),
			Attrs: telemetry.Attrs{semconv.AttrType: k.typ, semconv.AttrIsTrusted: k.trusted},
		})
	}
	return points
}

// capStrings returns at most max entries from items (the first max, in
// order) plus whether truncation happened. Called by setCappedStrs below for
// every array attribute this collector emits; see maxArrayAttr.
func capStrings(items []string, max int) (capped []string, truncated bool) {
	if len(items) <= max {
		return items, false
	}
	return items[:max], true
}

// setCappedStrs sets attrs[key] to a maxArrayAttr-bounded copy of items when
// non-empty (an empty slice omits the attribute, same convention as
// telemetry.SetStrs), and reports whether it had to truncate — callers OR
// this into a per-record "did anything on this record get capped" flag
// (semconv.AttrArraysTruncated) rather than emitting a companion
// "<field>_truncated" flag per array.
func setCappedStrs(attrs telemetry.Attrs, key string, items []string) (truncated bool) {
	if len(items) == 0 {
		return false
	}
	capped, truncated := capStrings(items, maxArrayAttr)
	attrs[key] = capped
	return truncated
}

// displayOfPolicy picks the most human-readable identifier a policy carries,
// falling back to its id — same pattern as entra/risk's displayOf.
func displayOfPolicy(p conditionalAccessPolicy) string {
	if p.DisplayName != "" {
		return p.DisplayName
	}
	if p.ID != "" {
		return p.ID
	}
	return "unknown"
}

// policyLogEvent renders one Conditional Access policy as the
// entra.conditional_access_policy OTLP log record (#318). This is a STATE
// feed like entra/risk's twins: the timestamp is left zero ("now", i.e. poll
// time), because a policy is re-emitted every cycle for as long as it exists,
// not just when it changes.
func policyLogEvent(p conditionalAccessPolicy) telemetry.Event {
	attrs := telemetry.Attrs{}
	telemetry.SetStr(attrs, semconv.AttrId, p.ID)
	telemetry.SetStr(attrs, semconv.AttrDisplayName, p.DisplayName)
	telemetry.SetStr(attrs, semconv.AttrState, p.State)
	telemetry.SetStr(attrs, semconv.AttrCreatedDateTime, p.CreatedDateTime)
	telemetry.SetStr(attrs, semconv.AttrLastModifiedDateTime, p.ModifiedDateTime)
	telemetry.SetStr(attrs, semconv.AttrTemplateId, p.TemplateID)

	var truncated bool
	if p.Conditions != nil {
		truncated = setCappedStrs(attrs, semconv.AttrClientAppTypes, p.Conditions.ClientAppTypes) || truncated
		truncated = setCappedStrs(attrs, semconv.AttrSignInRiskLevels, p.Conditions.SignInRiskLevels) || truncated
		truncated = setCappedStrs(attrs, semconv.AttrUserRiskLevels, p.Conditions.UserRiskLevels) || truncated
		if p.Conditions.Users != nil {
			truncated = setCappedStrs(attrs, semconv.AttrIncludeUsers, p.Conditions.Users.IncludeUsers) || truncated
			truncated = setCappedStrs(attrs, semconv.AttrExcludeUsers, p.Conditions.Users.ExcludeUsers) || truncated
			truncated = setCappedStrs(attrs, semconv.AttrIncludeGroups, p.Conditions.Users.IncludeGroups) || truncated
			truncated = setCappedStrs(attrs, semconv.AttrExcludeGroups, p.Conditions.Users.ExcludeGroups) || truncated
			truncated = setCappedStrs(attrs, semconv.AttrIncludeRoles, p.Conditions.Users.IncludeRoles) || truncated
			truncated = setCappedStrs(attrs, semconv.AttrExcludeRoles, p.Conditions.Users.ExcludeRoles) || truncated
		}
		if p.Conditions.Locations != nil {
			truncated = setCappedStrs(attrs, semconv.AttrIncludeLocations, p.Conditions.Locations.IncludeLocations) || truncated
			truncated = setCappedStrs(attrs, semconv.AttrExcludeLocations, p.Conditions.Locations.ExcludeLocations) || truncated
		}
	}

	// has_grant_controls/has_session_controls are ALWAYS emitted (true or
	// false, never omitted): a null grantControls/sessionControls is a real
	// configured fact, and omitting the flag when false would make it
	// indistinguishable from "this record predates the flag" rather than
	// "this policy has none". See the GrantControls/SessionControls doc on
	// conditionalAccessPolicy.
	attrs[semconv.AttrHasGrantControls] = p.GrantControls != nil
	if p.GrantControls != nil {
		telemetry.SetStr(attrs, semconv.AttrGrantControlsOperator, p.GrantControls.Operator)
		truncated = setCappedStrs(attrs, semconv.AttrBuiltInControls, p.GrantControls.BuiltInControls) || truncated
		if p.GrantControls.AuthenticationStrength != nil {
			telemetry.SetStr(attrs, semconv.AttrAuthenticationStrengthDisplayName, p.GrantControls.AuthenticationStrength.DisplayName)
		}
	}
	attrs[semconv.AttrHasSessionControls] = p.SessionControls != nil

	if truncated {
		attrs[semconv.AttrArraysTruncated] = true
	}

	return telemetry.Event{
		Name:     eventPolicy,
		Body:     fmt.Sprintf("conditional access policy %s: state=%s", displayOfPolicy(p), p.State),
		Severity: telemetry.SeverityInfo,
		Attrs:    attrs,
	}
}

// displayOfLocation picks the most human-readable identifier a named
// location carries, falling back to its id.
func displayOfLocation(l namedLocation) string {
	if l.DisplayName != "" {
		return l.DisplayName
	}
	if l.ID != "" {
		return l.ID
	}
	return "unknown"
}

// namedLocationLogEvent renders one named location as the
// entra.named_location OTLP log record (#318). typ is the caller-resolved
// `type` attribute value: the bounded "ip"/"country" bucket when the
// @odata.type discriminator is recognized, or the raw wire value as a
// fallback for a future subtype this collector does not yet map (see
// Collect's twinType) — the twin never drops a record just because the
// aggregate gauge had to skip it.
//
// This is the one place the absent-field-is-not-a-sentinel rule is
// load-bearing: IsTrusted and IncludeUnknownCountriesAndRegions are only
// ever emitted when the wire actually carried the key, using the pointer's
// presence, never a computed default.
func namedLocationLogEvent(l namedLocation, typ string) telemetry.Event {
	attrs := telemetry.Attrs{}
	telemetry.SetStr(attrs, semconv.AttrId, l.ID)
	telemetry.SetStr(attrs, semconv.AttrDisplayName, l.DisplayName)
	telemetry.SetStr(attrs, semconv.AttrType, typ)
	telemetry.SetStr(attrs, semconv.AttrCreatedDateTime, l.CreatedDateTime)
	telemetry.SetStr(attrs, semconv.AttrLastModifiedDateTime, l.ModifiedDateTime)

	// is_trusted: emitted only when the wire carried the key at all — never
	// computed from absence. A countryNamedLocation never has this key
	// (isTrusted stays nil after decode), so this branch is simply never
	// taken for one; an ipNamedLocation always carries it, true or false.
	if l.IsTrusted != nil {
		attrs[semconv.AttrIsTrusted] = *l.IsTrusted
	}

	var truncated bool
	if len(l.IPRanges) > 0 {
		var v4, v6 []string
		for _, r := range l.IPRanges {
			switch r.Type {
			case odataTypeIPv4CidrRange:
				v4 = append(v4, r.Address)
			case odataTypeIPv6CidrRange:
				v6 = append(v6, r.Address)
			}
		}
		truncated = setCappedStrs(attrs, semconv.AttrIPv4CidrRanges, v4) || truncated
		truncated = setCappedStrs(attrs, semconv.AttrIPv6CidrRanges, v6) || truncated
	}

	truncated = setCappedStrs(attrs, semconv.AttrCountries, l.CountriesAndRegions) || truncated
	telemetry.SetStr(attrs, semconv.AttrCountryLookupMethod, l.CountryLookupMethod)
	if l.IncludeUnknownCountriesAndRegions != nil {
		attrs[semconv.AttrIncludeUnknownCountriesAndRegions] = *l.IncludeUnknownCountriesAndRegions
	}

	if truncated {
		attrs[semconv.AttrArraysTruncated] = true
	}

	return telemetry.Event{
		Name:     eventNamedLocation,
		Body:     fmt.Sprintf("named location %s: type=%s", displayOfLocation(l), typ),
		Severity: telemetry.SeverityInfo,
		Attrs:    attrs,
	}
}

func init() {
	collectors.Register(func(d collectors.Deps) collector.SnapshotCollector {
		return New(d.Graph, d.Logger)
	})
}
