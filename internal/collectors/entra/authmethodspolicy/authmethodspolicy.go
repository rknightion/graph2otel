// Package authmethodspolicy is the Entra authentication-methods policy
// collector: GET /policies/authenticationMethodsPolicy (a tenant-wide
// singleton, no pagination or delta query) emitted as a bounded per-method
// enabled/disabled gauge plus a convenience "legacy methods enabled" count.
//
// This is config posture, not per-entity data: which authentication methods
// (FIDO2, Microsoft Authenticator, SMS, voice, ...) are switched on
// tenant-wide, distinct from the registration *report* that counts users
// (covered by a separate collector).
//
// Deviation from the tracking issue (#72): the issue's API table lists
// `Policy.Read.All` as the primary application permission with
// `Policy.Read.AuthenticationMethod` as a parenthetical alternative. Current
// Microsoft Graph docs (learn.microsoft.com/en-us/graph/api/
// authenticationmethodspolicy-get, verified 2026-07-15) show the opposite:
// `Policy.Read.AuthenticationMethod` is the least-privileged application
// permission; `Policy.Read.All` is listed as a higher-privileged alternative.
// Per the M2 guide's own rule (prefer the specific scope over a blanket one
// unless the issue demands the blanket one), this collector declares
// Policy.Read.AuthenticationMethod.
package authmethodspolicy

import (
	"context"
	"encoding/json"
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
const collectorName = "entra.auth_methods_policy"

// Metric names this collector emits.
const (
	// methodEnabledMetric is the per-method-type 0/1 posture gauge.
	methodEnabledMetric = "entra.auth_methods_policy.method.enabled"
	// legacyEnabledMetric is the convenience count of enabled legacy methods
	// (SMS, voice) — "legacy method still enabled tenant-wide" is a direct
	// compliance signal, worth its own alertable series.
	legacyEnabledMetric = "entra.auth_methods_policy.legacy_enabled.total"
)

// defaultBaseURL is the Graph v1.0 root.
const defaultBaseURL = "https://graph.microsoft.com/v1.0"

// policyPath is the singleton policy resource path.
const policyPath = "/policies/authenticationMethodsPolicy"

// stateEnabled is the Graph-documented "on" value for a method
// configuration's state property; anything else (disabled, or an unexpected
// value) is treated as off.
const stateEnabled = "enabled"

// knownMethod pairs a bounded `method` attribute value with the Graph
// authenticationMethodConfiguration id it corresponds to, and whether it
// counts toward the legacy-enabled convenience total.
type knownMethod struct {
	id     string // Graph's authenticationMethodConfigurations[].id
	attr   string // bounded "method" attribute value emitted
	legacy bool
}

// knownMethods is the fixed, bounded catalog of built-in method
// configurations documented for the v1.0 authenticationMethodsPolicy
// resource. Cardinality of methodEnabledMetric is exactly len(knownMethods).
//
// Deliberately NOT included: "external" authentication method configurations
// (custom OIDC providers a tenant can add). Graph gives those an arbitrary
// GUID id rather than a fixed type, so emitting one per configuration would
// make the metric's cardinality grow with tenant configuration instead of
// staying bounded by the method catalog — the exact violation the M2 guide's
// cardinality rule forbids. Any authenticationMethodConfigurations entry
// whose id isn't in this catalog is silently skipped.
var knownMethods = []knownMethod{
	{id: "Fido2", attr: "fido2"},
	{id: "MicrosoftAuthenticator", attr: "microsoftAuthenticator"},
	{id: "Sms", attr: "sms", legacy: true},
	{id: "Voice", attr: "voice", legacy: true},
	{id: "TemporaryAccessPass", attr: "temporaryAccessPass"},
	{id: "HardwareOath", attr: "hardwareOath"},
	{id: "SoftwareOath", attr: "softwareOath"},
	{id: "Email", attr: "email"},
	{id: "X509Certificate", attr: "x509Certificate"},
}

// methodConfig mirrors the subset of a Graph authenticationMethodConfiguration
// this collector reads. Every concrete method-configuration type (fido2,
// microsoftAuthenticator, sms, ...) shares these two fields at minimum.
type methodConfig struct {
	ID    string `json:"id"`
	State string `json:"state"`
}

// authenticationMethodsPolicy mirrors the subset of the Graph
// authenticationMethodsPolicy resource this collector reads.
type authenticationMethodsPolicy struct {
	AuthenticationMethodConfigurations []methodConfig `json:"authenticationMethodConfigurations"`
}

// Collector polls GET /policies/authenticationMethodsPolicy.
type Collector struct {
	g       collectors.GraphClient
	baseURL string
	logger  *slog.Logger
}

// New builds the authentication-methods-policy collector. A nil logger falls
// back to the slog default.
func New(g collectors.GraphClient, logger *slog.Logger) *Collector {
	if logger == nil {
		logger = slog.Default()
	}
	return &Collector{g: g, baseURL: defaultBaseURL, logger: logger}
}

// Name implements collector.Collector.
func (c *Collector) Name() string { return collectorName }

// DefaultInterval implements collector.Collector. This is tenant-wide policy
// config, not an event stream — it changes rarely, so fifteen minutes is
// ample and cheap on the directory/policy throttle bucket.
func (c *Collector) DefaultInterval() time.Duration { return 15 * time.Minute }

// RequiredPermissions declares the least-privilege Graph application scope.
// See the package doc for why this differs from the tracking issue's table.
func (c *Collector) RequiredPermissions() []string {
	return []string{"Policy.Read.AuthenticationMethod"}
}

// Collect fetches the tenant's single authentication-methods policy object
// and emits the bounded per-method enabled gauge plus the legacy-enabled
// convenience count. There is no pagination or delta query on this
// singleton resource — a plain RawGet is the right tool, not
// collectors.GetAllValues (a "value"-wrapped collection helper) or
// collectors.Count ($count only).
func (c *Collector) Collect(ctx context.Context, e telemetry.Emitter) error {
	body, err := c.g.RawGet(ctx, c.baseURL+policyPath)
	if err != nil {
		return fmt.Errorf("authmethodspolicy: fetch authenticationMethodsPolicy: %w", err)
	}

	var policy authenticationMethodsPolicy
	if err := json.Unmarshal(body, &policy); err != nil {
		return fmt.Errorf("authmethodspolicy: decode authenticationMethodsPolicy: %w", err)
	}

	states := make(map[string]bool, len(policy.AuthenticationMethodConfigurations))
	for _, mc := range policy.AuthenticationMethodConfigurations {
		states[mc.ID] = mc.State == stateEnabled
	}

	points := make([]telemetry.GaugePoint, 0, len(knownMethods))
	legacyEnabled := 0
	for _, m := range knownMethods {
		enabled, present := states[m.id]
		if !present {
			// Not present in this tenant's response (e.g. an older
			// policyVersion missing a newer method type). Skip rather than
			// fabricate a 0 for a method Graph didn't report on.
			c.logger.Debug("authmethodspolicy: method configuration absent from response", "collector", collectorName, "method", m.attr)
			continue
		}
		val := 0.0
		if enabled {
			val = 1
			if m.legacy {
				legacyEnabled++
			}
		}
		points = append(points, telemetry.GaugePoint{
			Value: val,
			Attrs: telemetry.Attrs{semconv.AttrMethod: m.attr},
		})
	}

	e.GaugeSnapshot(methodEnabledMetric, semconv.UnitDimensionless,
		"1 if the authentication method is enabled tenant-wide, else 0, per bounded method type.",
		points)
	e.Gauge(legacyEnabledMetric, "{method}",
		"Count of legacy authentication methods (SMS, voice) currently enabled tenant-wide.",
		float64(legacyEnabled), nil)

	return nil
}

func init() {
	collectors.Register(func(d collectors.Deps) collector.SnapshotCollector {
		return New(d.Graph, d.Logger)
	})
}
