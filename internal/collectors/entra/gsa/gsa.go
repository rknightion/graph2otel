// Package gsa is the Entra Global Secure Access (GSA) posture collector (#239,
// piece 1): the tenant's GSA onboarding state, its traffic-forwarding profiles,
// filtering policies, remote-network count, and the two data-plane signaling /
// packet-tagging posture flags. It answers "is Global Secure Access onboarded,
// and how is it configured" on the same dashboards and alert rules as the rest
// of the telemetry, without a human opening the entra portal.
//
// # Six independent beta fetches, one non-fatal aggregate
//
// Everything lives only under https://graph.microsoft.com/beta/networkAccess,
// so this is a PURE-BETA collector: baseURL points at beta and it implements
// collectors.Experimental (an operator opts in explicitly). It issues six
// independent GETs; a failure in any one is logged and folded into a non-fatal
// errors.Join, and the other five still emit — so a single throttled endpoint
// never blanks the whole posture picture. tenantStatus / conditionalAccess /
// crossTenantAccess are single-object endpoints (decoded directly, no `value`
// array); forwardingProfiles / filteringPolicies / remoteNetworks are
// collections walked via collectors.GetAllValues.
//
// # Both sides of the cardinality boundary (#114)
//
//   - bounded GAUGES: the numeric onboarding-status enum, profile counts by
//     (traffic_forwarding_type, state), policy counts by action, the remote-
//     network count, and the two 0/1 posture flags (data-plane signaling,
//     network packet tagging);
//   - LOG TWINS: one entra.gsa_forwarding_profile per profile and one
//     entra.gsa_filtering_policy per policy, carrying the per-entity config
//     detail (id, name, version, priority, custom flag, fallback action,
//     association count) a metric label must never hold. "Not a metric label"
//     means log twin, not dropped (#114).
//
// # Scope and what is NOT built
//
// This is posture only. The GSA traffic-logs half of #239 is grant-blocked and
// deliberately out of scope. The remote-networks endpoint returns an EMPTY
// collection on m7kni (`live-measured 2026-07-23`), so this collector emits only
// the remote-network COUNT gauge and does NOT twin individual remote networks —
// there was no live remote-network row to map a per-network twin against
// (#142/#165: never map a shape from docs alone). Everything else is mapped
// against verbatim live samples captured as graph2otel-poller on 2026-07-23.
package gsa

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/rknightion/graph2otel/internal/collector"
	"github.com/rknightion/graph2otel/internal/collectors"
	"github.com/rknightion/graph2otel/internal/semconv"
	"github.com/rknightion/graph2otel/internal/telemetry"
)

// collectorName is the stable key used for config (enable/interval),
// self-observability, and the admin status page.
const collectorName = "entra.gsa"

// betaBaseURL is the Graph beta service root — every networkAccess resource
// this collector reads exists only under beta, with no v1.0 form.
const betaBaseURL = "https://graph.microsoft.com/beta"

// The six beta paths, all under /networkAccess.
const (
	pathTenantStatus       = "/networkAccess/tenantStatus"
	pathForwardingProfiles = "/networkAccess/forwardingProfiles"
	pathFilteringPolicies  = "/networkAccess/filteringPolicies"
	pathConditionalAccess  = "/networkAccess/settings/conditionalAccess"
	pathCrossTenantAccess  = "/networkAccess/settings/crossTenantAccess"
	pathRemoteNetworks     = "/networkAccess/connectivity/remoteNetworks"
)

// Metric names emitted by this collector.
const (
	metricOnboardingStatus     = "entra.gsa.onboarding_status"
	metricForwardingProfiles   = "entra.gsa.forwarding_profiles"
	metricFilteringPolicies    = "entra.gsa.filtering_policies"
	metricRemoteNetworks       = "entra.gsa.remote_networks"
	metricSignalingEnabled     = "entra.gsa.signaling_enabled"
	metricPacketTaggingEnabled = "entra.gsa.packet_tagging_enabled"
)

// Log-twin event names carrying the per-entity detail the gauges cannot.
const (
	eventForwardingProfile = "entra.gsa_forwarding_profile"
	eventFilteringPolicy   = "entra.gsa_filtering_policy"
)

// statusEnum maps a networkAccess onboardingStatus value to a numeric severity
// ladder for the entra.gsa.onboarding_status gauge: 0 = onboarded (healthy),
// 1 = a transition in progress, 2 = an error or offboarded (bad), -1 = an
// unmapped/unknown status (so a new Microsoft enum value shows as -1 rather than
// silently bucketing as healthy). Documented in docs/signals.md (the main thread
// adds the row); do NOT add a companion string-label metric.
var statusEnum = map[string]float64{
	"onboarded":             0,
	"onboardingInProgress":  1,
	"offboardingInProgress": 1,
	"onboardingError":       2,
	"offboarded":            2,
}

// statusValue returns the numeric enum for an onboarding status, -1 when
// unmapped.
func statusValue(status string) float64 {
	if v, ok := statusEnum[status]; ok {
		return v
	}
	return -1
}

// Collector polls the Global Secure Access posture surface.
type Collector struct {
	g       collectors.GraphClient
	baseURL string
	logger  *slog.Logger
}

// New builds the GSA collector. A nil logger falls back to slog.Default().
func New(g collectors.GraphClient, logger *slog.Logger) *Collector {
	if logger == nil {
		logger = slog.Default()
	}
	return &Collector{g: g, baseURL: betaBaseURL, logger: logger}
}

// Name implements collector.Collector.
func (c *Collector) Name() string { return collectorName }

// DefaultInterval implements collector.Collector. This is posture/config, not an
// event stream — GSA onboarding and its profiles change on the order of
// hours-to-days, so a six-hourly poll is ample and trivially cheap.
func (c *Collector) DefaultInterval() time.Duration { return 6 * time.Hour }

// Experimental marks this collector beta/opt-in: every networkAccess resource it
// reads exists only on the Graph beta endpoint, with no v1.0 fallback.
func (c *Collector) Experimental() bool { return true }

// RequiredPermissions declares the least-privilege Graph scope all six endpoints
// share (live-verified 200 with exactly this, #239).
func (c *Collector) RequiredPermissions() []string { return []string{"Policy.Read.All"} }

// Collect issues the six independent fetches. Each is guarded on its own: a
// failure is logged and folded into a non-fatal aggregated error, and never
// prevents the others from emitting.
func (c *Collector) Collect(ctx context.Context, e telemetry.Emitter) error {
	var errs []error

	steps := []struct {
		name string
		fn   func(context.Context, telemetry.Emitter) error
	}{
		{"tenant status", c.collectTenantStatus},
		{"forwarding profiles", c.collectForwardingProfiles},
		{"filtering policies", c.collectFilteringPolicies},
		{"conditional access settings", c.collectConditionalAccess},
		{"cross-tenant access settings", c.collectCrossTenantAccess},
		{"remote networks", c.collectRemoteNetworks},
	}
	for _, s := range steps {
		if err := s.fn(ctx, e); err != nil {
			c.logger.Warn("GSA fetch failed", "collector", collectorName, "step", s.name, "error", err)
			errs = append(errs, fmt.Errorf("%s: %w", s.name, err))
		}
	}
	return errors.Join(errs...)
}

// tenantStatus is the single-object /networkAccess/tenantStatus response.
type tenantStatus struct {
	OnboardingStatus       string `json:"onboardingStatus"`
	OnboardingErrorMessage string `json:"onboardingErrorMessage"`
}

// collectTenantStatus emits the numeric onboarding-status enum gauge.
func (c *Collector) collectTenantStatus(ctx context.Context, e telemetry.Emitter) error {
	body, err := c.g.RawGet(ctx, c.baseURL+pathTenantStatus)
	if err != nil {
		return err
	}
	var ts tenantStatus
	if err := json.Unmarshal(body, &ts); err != nil {
		return fmt.Errorf("decode tenantStatus: %w", err)
	}
	e.Gauge(metricOnboardingStatus, "1",
		"Global Secure Access onboarding status (0 = onboarded, 1 = in progress, 2 = error/offboarded, -1 = unmapped). See docs/signals.md.",
		statusValue(ts.OnboardingStatus), nil)
	return nil
}

// forwardingProfile is the subset of a networkAccess forwardingProfile this
// collector aggregates and twins. traffic_forwarding_type and state bucket the
// gauge; everything else is per-entity and goes to the log twin only.
// Associations is decoded only to count its length (association_count) — the
// per-association detail is not read.
type forwardingProfile struct {
	ID                    string            `json:"id"`
	Name                  string            `json:"name"`
	State                 string            `json:"state"`
	Version               string            `json:"version"`
	TrafficForwardingType string            `json:"trafficForwardingType"`
	Priority              int64             `json:"priority"`
	IsCustomProfile       bool              `json:"isCustomProfile"`
	ClientFallbackAction  string            `json:"clientFallbackAction"`
	Associations          []json.RawMessage `json:"associations"`
}

// collectForwardingProfiles emits the profile-count gauge keyed by
// (traffic_forwarding_type, state) and one twin per profile.
func (c *Collector) collectForwardingProfiles(ctx context.Context, e telemetry.Emitter) error {
	raws, err := collectors.GetAllValues(ctx, c.g, c.baseURL+pathForwardingProfiles, nil)
	if err != nil {
		return err
	}
	counts := map[[2]string]int64{}
	for _, raw := range raws {
		var p forwardingProfile
		if err := json.Unmarshal(raw, &p); err != nil {
			return fmt.Errorf("decode forwardingProfile: %w", err)
		}
		counts[[2]string{p.TrafficForwardingType, p.State}]++
		e.LogEvent(forwardingProfileTwin(p))
	}
	points := make([]telemetry.GaugePoint, 0, len(counts))
	for k, n := range counts {
		points = append(points, telemetry.GaugePoint{
			Value: float64(n),
			Attrs: telemetry.Attrs{semconv.AttrTrafficForwardingType: k[0], semconv.AttrState: k[1]},
		})
	}
	e.GaugeSnapshot(metricForwardingProfiles, "{profile}",
		"Count of Global Secure Access traffic-forwarding profiles, by traffic type and state.", points)
	return nil
}

// forwardingProfileTwin renders one forwarding profile as a log record. Emitted
// at Info: a disabled default profile is the norm on a tenant that has not
// rolled GSA out, so there is no bad state to flag here. Timestamp is left zero
// (poll time): this is a snapshot re-emitted every cycle.
func forwardingProfileTwin(p forwardingProfile) telemetry.Event {
	attrs := telemetry.Attrs{}
	telemetry.SetStr(attrs, semconv.AttrId, p.ID)
	telemetry.SetStr(attrs, semconv.AttrName, p.Name)
	telemetry.SetStr(attrs, semconv.AttrTrafficForwardingType, p.TrafficForwardingType)
	telemetry.SetStr(attrs, semconv.AttrState, p.State)
	telemetry.SetStr(attrs, semconv.AttrVersion, p.Version)
	attrs[semconv.AttrPriority] = p.Priority
	telemetry.SetBool(attrs, semconv.AttrIsCustomProfile, p.IsCustomProfile)
	telemetry.SetStr(attrs, semconv.AttrClientFallbackAction, p.ClientFallbackAction)
	attrs[semconv.AttrAssociationCount] = int64(len(p.Associations))

	name := p.Name
	if name == "" {
		name = p.ID
	}
	if name == "" {
		name = "unknown"
	}
	return telemetry.Event{
		Name:     eventForwardingProfile,
		Body:     fmt.Sprintf("GSA forwarding profile %s: type=%s state=%s", name, p.TrafficForwardingType, p.State),
		Severity: telemetry.SeverityInfo,
		Attrs:    attrs,
	}
}

// filteringPolicy is the subset of a networkAccess filteringPolicy this
// collector aggregates and twins. action buckets the gauge; the rest is
// per-entity and goes to the log twin only.
type filteringPolicy struct {
	ID      string `json:"id"`
	Name    string `json:"name"`
	Action  string `json:"action"`
	Version string `json:"version"`
}

// collectFilteringPolicies emits the policy-count gauge keyed by action and one
// twin per policy.
func (c *Collector) collectFilteringPolicies(ctx context.Context, e telemetry.Emitter) error {
	raws, err := collectors.GetAllValues(ctx, c.g, c.baseURL+pathFilteringPolicies, nil)
	if err != nil {
		return err
	}
	byAction := map[string]int64{}
	for _, raw := range raws {
		var p filteringPolicy
		if err := json.Unmarshal(raw, &p); err != nil {
			return fmt.Errorf("decode filteringPolicy: %w", err)
		}
		byAction[p.Action]++
		e.LogEvent(filteringPolicyTwin(p))
	}
	points := make([]telemetry.GaugePoint, 0, len(byAction))
	for action, n := range byAction {
		points = append(points, telemetry.GaugePoint{
			Value: float64(n),
			Attrs: telemetry.Attrs{semconv.AttrAction: action},
		})
	}
	e.GaugeSnapshot(metricFilteringPolicies, "{policy}",
		"Count of Global Secure Access filtering policies, by action.", points)
	return nil
}

// filteringPolicyTwin renders one filtering policy as a log record, at Info (a
// filtering policy is configuration, not an alertable state).
func filteringPolicyTwin(p filteringPolicy) telemetry.Event {
	attrs := telemetry.Attrs{}
	telemetry.SetStr(attrs, semconv.AttrId, p.ID)
	telemetry.SetStr(attrs, semconv.AttrName, p.Name)
	telemetry.SetStr(attrs, semconv.AttrAction, p.Action)
	telemetry.SetStr(attrs, semconv.AttrVersion, p.Version)

	name := p.Name
	if name == "" {
		name = p.ID
	}
	if name == "" {
		name = "unknown"
	}
	return telemetry.Event{
		Name:     eventFilteringPolicy,
		Body:     fmt.Sprintf("GSA filtering policy %s: action=%s", name, p.Action),
		Severity: telemetry.SeverityInfo,
		Attrs:    attrs,
	}
}

// conditionalAccessSettings is the single-object
// /networkAccess/settings/conditionalAccess response.
type conditionalAccessSettings struct {
	SignalingStatus           string `json:"signalingStatus"`
	DataPlaneSignalingOptions string `json:"dataPlaneSignalingOptions"`
}

// collectConditionalAccess emits the 0/1 data-plane-signaling posture flag.
func (c *Collector) collectConditionalAccess(ctx context.Context, e telemetry.Emitter) error {
	body, err := c.g.RawGet(ctx, c.baseURL+pathConditionalAccess)
	if err != nil {
		return err
	}
	var s conditionalAccessSettings
	if err := json.Unmarshal(body, &s); err != nil {
		return fmt.Errorf("decode conditionalAccess settings: %w", err)
	}
	e.Gauge(metricSignalingEnabled, "{setting}",
		"Whether Global Secure Access data-plane signaling to Conditional Access is enabled (1) or not (0).",
		boolTo01(s.SignalingStatus == "enabled"), nil)
	return nil
}

// crossTenantAccessSettings is the single-object
// /networkAccess/settings/crossTenantAccess response.
type crossTenantAccessSettings struct {
	NetworkPacketTaggingStatus string `json:"networkPacketTaggingStatus"`
	DataPlaneTaggingOptions    string `json:"dataPlaneTaggingOptions"`
}

// collectCrossTenantAccess emits the 0/1 network-packet-tagging posture flag.
func (c *Collector) collectCrossTenantAccess(ctx context.Context, e telemetry.Emitter) error {
	body, err := c.g.RawGet(ctx, c.baseURL+pathCrossTenantAccess)
	if err != nil {
		return err
	}
	var s crossTenantAccessSettings
	if err := json.Unmarshal(body, &s); err != nil {
		return fmt.Errorf("decode crossTenantAccess settings: %w", err)
	}
	e.Gauge(metricPacketTaggingEnabled, "{setting}",
		"Whether Global Secure Access cross-tenant network packet tagging is enabled (1) or not (0).",
		boolTo01(s.NetworkPacketTaggingStatus == "enabled"), nil)
	return nil
}

// collectRemoteNetworks emits the remote-network count gauge. m7kni has none
// (empty collection, live 2026-07-23), so no per-network twin is emitted — the
// count is the whole signal, and a twin has no live shape to map against.
func (c *Collector) collectRemoteNetworks(ctx context.Context, e telemetry.Emitter) error {
	raws, err := collectors.GetAllValues(ctx, c.g, c.baseURL+pathRemoteNetworks, nil)
	if err != nil {
		return err
	}
	e.Gauge(metricRemoteNetworks, "{network}",
		"Count of Global Secure Access remote networks configured for the tenant.",
		float64(len(raws)), nil)
	return nil
}

// boolTo01 maps a posture flag to the 0/1 the gauge carries.
func boolTo01(b bool) float64 {
	if b {
		return 1
	}
	return 0
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
