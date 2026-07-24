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

// conditionalAccessPolicy mirrors only the field this collector reads off a
// Graph conditionalAccessPolicy: the enforcement state. Everything else
// (displayName, conditions, grantControls, ...) is per-policy detail that
// belongs in the directory-audit log stream (M3), never a metric label.
type conditionalAccessPolicy struct {
	State string `json:"state"`
}

// namedLocation mirrors only the fields this collector reads off a Graph
// namedLocation, either subtype. @odata.type distinguishes ipNamedLocation
// from countryNamedLocation. IsTrusted is a pointer because it is only ever
// present on ipNamedLocation — countryNamedLocation has no trust concept in
// Graph at all (verified against the v1.0 namedLocation resource docs), so a
// missing/absent field (nil) is treated as untrusted, never as a parse error.
type namedLocation struct {
	Type      string `json:"@odata.type"`
	IsTrusted *bool  `json:"isTrusted"`
}

const (
	odataTypeIPNamedLocation      = "#microsoft.graph.ipNamedLocation"
	odataTypeCountryNamedLocation = "#microsoft.graph.countryNamedLocation"
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
func (c *Collector) Collect(ctx context.Context, e telemetry.Emitter) error {
	var errs []error

	rawPolicies, err := collectors.GetAllValues(ctx, c.g, c.baseURL+"/identity/conditionalAccess/policies", nil)
	if err != nil {
		c.logger.Warn("conditional access: fetch policies failed", "collector", collectorName, "error", err)
		errs = append(errs, fmt.Errorf("fetch policies: %w", err))
	} else {
		e.GaugeSnapshot(policiesMetricName, "{policy}",
			"Entra Conditional Access policies, by enforcement state.",
			c.policyPoints(rawPolicies, e))
	}

	rawLocations, err := collectors.GetAllValues(ctx, c.g, c.baseURL+"/identity/conditionalAccess/namedLocations", nil)
	if err != nil {
		c.logger.Warn("conditional access: fetch named locations failed", "collector", collectorName, "error", err)
		errs = append(errs, fmt.Errorf("fetch named locations: %w", err))
	} else {
		e.GaugeSnapshot(namedLocationsMetricName, "{location}",
			"Entra Conditional Access named locations, by type and trust.",
			c.namedLocationPoints(rawLocations, e))
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
func (c *Collector) policyPoints(raw []json.RawMessage, e telemetry.Emitter) []telemetry.GaugePoint {
	counts := make(map[string]int, len(policyStates))
	for _, ps := range policyStates {
		counts[ps.attr] = 0
	}

	for _, r := range raw {
		var p conditionalAccessPolicy
		if err := json.Unmarshal(r, &p); err != nil {
			c.logger.Warn("conditional access: skipping unparseable policy", "collector", collectorName, "error", err)
			continue
		}
		attr, ok := policyStateAttr(p.State)
		if !ok {
			c.watch.Value(e, semconv.AttrState, p.State, knownPolicyStates)
			c.logger.Warn("conditional access: skipping policy with unrecognized state", "collector", collectorName, "state", p.State)
			continue
		}
		counts[attr]++
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
func (c *Collector) namedLocationPoints(raw []json.RawMessage, e telemetry.Emitter) []telemetry.GaugePoint {
	counts := make(map[locKey]int, 2*len(namedLocationTypes))
	for _, typ := range namedLocationTypes {
		counts[locKey{typ, true}] = 0
		counts[locKey{typ, false}] = 0
	}

	for _, r := range raw {
		var l namedLocation
		if err := json.Unmarshal(r, &l); err != nil {
			c.logger.Warn("conditional access: skipping unparseable named location", "collector", collectorName, "error", err)
			continue
		}
		typ, ok := namedLocationType(l.Type)
		if !ok {
			c.watch.Value(e, semconv.AttrType, l.Type, knownNamedLocationTypes)
			c.logger.Warn("conditional access: skipping named location with unrecognized @odata.type", "collector", collectorName, "type", l.Type)
			continue
		}
		trusted := l.IsTrusted != nil && *l.IsTrusted
		counts[locKey{typ, trusted}]++
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

func init() {
	collectors.Register(func(d collectors.Deps) collector.SnapshotCollector {
		return New(d.Graph, d.Logger)
	})
}
