// Package authmethodspolicy is the Entra authentication-methods policy
// collector: GET /policies/authenticationMethodsPolicy (a tenant-wide
// singleton, no pagination or delta query) emitted as a bounded per-method
// enabled/disabled gauge plus a convenience "legacy methods enabled" count,
// PLUS (#317) two log twins carrying the per-entity detail those bounded
// gauges cannot.
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
//
// # Log twins (#317) — the binding Option A contract
//
// The two gauges above are bounded by a fixed method catalog, so they can
// answer "is FIDO2 enabled tenant-wide" but never "which groups are
// targeted, with what key restrictions". #317's decision-gate comment
// (2026-07-28, binding, not open for reinterpretation on this pass) settled
// the shape as ONE entra.auth_methods_policy event for the singleton and ONE
// entra.auth_method_configuration event per entry in
// authenticationMethodConfigurations — never a per-target child event
// (Option B, considered and rejected: it would expand record cardinality per
// target for no acceptance-criteria benefit).
//
// Every attribute on both events is a FIXED, TYPED field — never raw
// configuration JSON. Include/exclude targets become bounded identifier
// arrays (see maxTargetIdentifiers), not the nested target objects Graph
// returns. A KNOWN configuration subtype (one of the seven the
// live-measured 2026-07-17 fixture, #165, returns — fido2,
// microsoftAuthenticator, sms, voice, x509Certificate,
// verifiableCredentials, qrCodePin) gets its observed subtype-specific
// scalar fields preserved; anything not in that set is UNKNOWN and its twin
// carries ONLY id, state and @odata.type — nothing else, not even the
// include/exclude target arrays every known subtype gets. This is the
// load-bearing half of the decision, not a shortcut: an unseen provider
// subtype could carry a field nobody has reviewed, and emitting it
// (raw or typed) would ship it sight-unseen. A new subtype therefore
// arrives deliberately under-described until someone captures it and this
// mapper is extended with evidence — the log-twin analog of
// internal/wirecheck's report-only, evidence-gated philosophy for metric
// label value sets.
package authmethodspolicy

import (
	"context"
	"encoding/json"
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

// The two log EventNames this collector emits (#317) — see the package doc
// for the full contract. Both are LOG-ONLY: neither becomes a metric label.
const (
	eventPolicy = "entra.auth_methods_policy"
	eventConfig = "entra.auth_method_configuration"
)

// maxTargetIdentifiers bounds every target/aaGuid/passkeyProfile identifier
// array this collector emits. These are admin-configured collections
// (groups targeted by a policy, hardware key models allow-listed, passkey
// profiles defined), bounded by tenant configuration rather than tenant
// population, but the cap is still a defensive backstop against a
// pathological tenant — the same role maxCertProfileNames /
// maxIssuerNames play elsewhere in this project.
const maxTargetIdentifiers = 50

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

// targetRef mirrors the one field every Graph include/exclude target object
// carries that this collector preserves: its identifier. targetType,
// isRegistrationRequired, allowedPasskeyProfiles and every other per-target
// field Graph attaches are deliberately NOT decoded — the #317 contract is
// "bounded arrays of target IDENTIFIERS", not per-target config, and a
// nested per-target struct here would start re-growing the raw-JSON surface
// the decision exists to close off. Shared by the policy-level registration
// campaign's includeTargets/excludeTargets and every known configuration's
// own includeTargets/excludeTargets — Graph uses the same shape in both
// places.
type targetRef struct {
	ID string `json:"id"`
}

// keyRestrictions mirrors a Fido2 configuration's keyRestrictions object.
// aaGuids are hardware authenticator MODEL identifiers (not secrets, not
// per-user data) — observed live 2026-07-28.
type keyRestrictions struct {
	// IsEnforced is a POINTER: a plain bool would fabricate `false` for a
	// tenant/subtype where this key is simply absent from the response,
	// asserting Graph said something it never said. Same reasoning as
	// entra/risk's IsProcessing field.
	IsEnforced      *bool    `json:"isEnforced"`
	EnforcementType string   `json:"enforcementType"`
	AaGuids         []string `json:"aaGuids"`
}

// passkeyProfile mirrors one entry of a Fido2 configuration's top-level
// passkeyProfiles array. Only the id is decoded — attestationEnforcement and
// the profile's own nested keyRestrictions are exactly the kind of deep,
// per-profile config the #317 contract's "identifiers only" rule keeps out
// of a fixed typed schema.
type passkeyProfile struct {
	ID string `json:"id"`
}

// methodConfig mirrors the subset of a Graph authenticationMethodConfiguration
// this collector reads. Every concrete method-configuration type (fido2,
// microsoftAuthenticator, sms, ...) shares ID/State/ODataType/
// IncludeTargets/ExcludeTargets. The fields below that are UNION members
// across the seven known subtypes (see knownConfigMethods) decode to their
// zero value (nil pointer, empty slice, empty string) for any configuration
// whose JSON doesn't carry that key — never a fabricated non-zero value —
// which is why configTwin can read them unconditionally for a known subtype
// without a type switch: entra/risk's riskyEntity uses the identical
// union-decode pattern for the same reason.
type methodConfig struct {
	ID        string `json:"id"`
	State     string `json:"state"`
	ODataType string `json:"@odata.type"`

	IncludeTargets []targetRef `json:"includeTargets"`
	ExcludeTargets []targetRef `json:"excludeTargets"`

	// fido2AuthenticationMethodConfiguration only.
	IsSelfServiceRegistrationAllowed *bool            `json:"isSelfServiceRegistrationAllowed"`
	IsAttestationEnforced            *bool            `json:"isAttestationEnforced"`
	DefaultPasskeyProfile            string           `json:"defaultPasskeyProfile"`
	KeyRestrictions                  *keyRestrictions `json:"keyRestrictions"`
	PasskeyProfiles                  []passkeyProfile `json:"passkeyProfiles"`

	// microsoftAuthenticatorAuthenticationMethodConfiguration only.
	IsSoftwareOathEnabled *bool `json:"isSoftwareOathEnabled"`

	// voiceAuthenticationMethodConfiguration only.
	IsOfficePhoneAllowed *bool `json:"isOfficePhoneAllowed"`

	// qrCodePinAuthenticationMethodConfiguration only.
	PinLength                    *int64 `json:"pinLength"`
	StandardQRCodeLifetimeInDays *int64 `json:"standardQRCodeLifetimeInDays"`
}

// registrationCampaign mirrors
// registrationEnforcement.authenticationMethodsRegistrationCampaign.
type registrationCampaign struct {
	State                string      `json:"state"`
	SnoozeDurationInDays *int64      `json:"snoozeDurationInDays"`
	IncludeTargets       []targetRef `json:"includeTargets"`
	ExcludeTargets       []targetRef `json:"excludeTargets"`
}

// registrationEnforcement mirrors the policy's registrationEnforcement
// object. AuthenticationMethodsRegistrationCampaign is a pointer because the
// whole sub-object is absent on a tenant that has never configured a
// registration campaign, not merely empty.
type registrationEnforcement struct {
	AuthenticationMethodsRegistrationCampaign *registrationCampaign `json:"authenticationMethodsRegistrationCampaign"`
}

// authenticationMethodsPolicy mirrors the subset of the Graph
// authenticationMethodsPolicy resource this collector reads.
type authenticationMethodsPolicy struct {
	ID                   string `json:"id"`
	DisplayName          string `json:"displayName"`
	Description          string `json:"description"`
	LastModifiedDateTime string `json:"lastModifiedDateTime"`
	PolicyVersion        string `json:"policyVersion"`
	// PolicyMigrationState is a pointer: observed null on the wire
	// (2026-07-28), and a plain string cannot distinguish "the wire said
	// null" from "the wire said empty string" from "the field was absent".
	// All three collapse to omitted-from-the-twin, which is the only
	// non-fabricating choice for any of them.
	PolicyMigrationState               *string                  `json:"policyMigrationState"`
	RegistrationEnforcement            *registrationEnforcement `json:"registrationEnforcement"`
	AuthenticationMethodConfigurations []methodConfig           `json:"authenticationMethodConfigurations"`
}

// knownConfigMethods maps a configuration's @odata.type to the bounded
// short method name used both as the log twin's `method` attribute and (via
// knownMethods above) the metric label — restricted to exactly the seven
// subtypes the live-measured 2026-07-17 fixture (#165) returns. Any
// @odata.type not in this map is UNKNOWN: its twin carries only id/state/
// @odata.type. See the package doc for why that restriction is deliberate,
// not a gap to be widened without new evidence.
// #nosec G101 -- these are Microsoft Graph @odata.type discriminator strings
// for authentication METHOD kinds; gosec matches on "Authentication" in the
// type name. No credential appears anywhere in this package: the whole point
// of #317's contract is that only policy metadata is emitted.
var knownConfigMethods = map[string]string{
	"#microsoft.graph.fido2AuthenticationMethodConfiguration":                  "fido2",
	"#microsoft.graph.microsoftAuthenticatorAuthenticationMethodConfiguration": "microsoftAuthenticator",
	"#microsoft.graph.smsAuthenticationMethodConfiguration":                    "sms",
	"#microsoft.graph.voiceAuthenticationMethodConfiguration":                  "voice",
	"#microsoft.graph.x509CertificateAuthenticationMethodConfiguration":        "x509Certificate",
	"#microsoft.graph.verifiableCredentialsAuthenticationMethodConfiguration":  "verifiableCredentials",
	"#microsoft.graph.qrCodePinAuthenticationMethodConfiguration":              "qrCodePin",
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
func (c *Collector) Collect(ctx context.Context, e telemetry.Emitter, outcomes *recordoutcome.Recorder) error {
	body, err := c.g.RawGet(ctx, c.baseURL+policyPath)
	if err != nil {
		entraoutcome.SourceError(outcomes)
		return fmt.Errorf("authmethodspolicy: fetch authenticationMethodsPolicy: %w", err)
	}

	var policy authenticationMethodsPolicy
	if err := json.Unmarshal(body, &policy); err != nil {
		entraoutcome.Errored(outcomes, 1, recordoutcome.CauseDecodeError)
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

	// Log twins (#317): the singleton policy event plus one configuration
	// event per RETURNED entry — every entry, not just the ones the gauge's
	// bounded catalog tracks, since a log twin is answering a different
	// question ("what does this configuration look like") than the gauge
	// ("is this bounded, known method type on"). One source object (the
	// policy fetch) maps to 1+len(configurations) emitted records.
	e.LogEvent(policyTwin(policy))
	for _, mc := range policy.AuthenticationMethodConfigurations {
		e.LogEvent(configTwin(mc))
	}
	entraoutcome.Emitted(outcomes, uint64(1+len(policy.AuthenticationMethodConfigurations)))

	return nil
}

// capStrings caps vals at maxTargetIdentifiers, reporting whether it had to.
// Never mutates vals — the returned slice on the truncated path is a fresh
// subslice header, not vals itself, so callers can't accidentally reuse the
// full backing array past the cap.
func capStrings(vals []string, max int) (out []string, truncated bool) {
	if len(vals) > max {
		return vals[:max:max], true
	}
	return vals, false
}

// setTargetIDs renders a []targetRef as a bounded id array plus its true
// (uncapped) count and a truncated flag, all three keyed off idsKey/countKey/
// truncatedKey so the same helper serves both the policy event's campaign
// targets and a configuration event's own include/exclude targets. An empty
// input omits all three attributes — "no targets configured" is absence, not
// a measured empty array, matching this collector's existing "absent means
// absent" convention for the method-enabled gauge.
func setTargetIDs(attrs telemetry.Attrs, idsKey, countKey, truncatedKey string, targets []targetRef) {
	if len(targets) == 0 {
		return
	}
	ids := make([]string, 0, len(targets))
	for _, t := range targets {
		if t.ID != "" {
			ids = append(ids, t.ID)
		}
	}
	capped, truncated := capStrings(ids, maxTargetIdentifiers)
	telemetry.SetStrs(attrs, idsKey, capped)
	attrs[countKey] = float64(len(targets))
	telemetry.SetBool(attrs, truncatedKey, truncated)
}

// policyTwin renders the singleton authenticationMethodsPolicy object as one
// entra.auth_methods_policy log record (#317). Every field is fixed and
// typed; the registration campaign's targets are bounded id arrays via
// setTargetIDs, never the nested target objects Graph returns.
func policyTwin(p authenticationMethodsPolicy) telemetry.Event {
	attrs := telemetry.Attrs{}
	telemetry.SetStr(attrs, semconv.AttrId, p.ID)
	telemetry.SetStr(attrs, semconv.AttrDisplayName, p.DisplayName)
	telemetry.SetStr(attrs, semconv.AttrDescription, p.Description)
	telemetry.SetStr(attrs, semconv.AttrLastModifiedDateTime, p.LastModifiedDateTime)
	telemetry.SetStr(attrs, semconv.AttrPolicyVersion, p.PolicyVersion)
	if p.PolicyMigrationState != nil {
		telemetry.SetStr(attrs, semconv.AttrPolicyMigrationState, *p.PolicyMigrationState)
	}

	if p.RegistrationEnforcement != nil && p.RegistrationEnforcement.AuthenticationMethodsRegistrationCampaign != nil {
		camp := p.RegistrationEnforcement.AuthenticationMethodsRegistrationCampaign
		telemetry.SetStr(attrs, semconv.AttrState, camp.State)
		if camp.SnoozeDurationInDays != nil {
			attrs[semconv.AttrSnoozeDurationInDays] = float64(*camp.SnoozeDurationInDays)
		}
		setTargetIDs(attrs, semconv.AttrIncludeTargetIds, semconv.AttrIncludeTargetCount, semconv.AttrIncludeTargetsTruncated, camp.IncludeTargets)
		setTargetIDs(attrs, semconv.AttrExcludeTargetIds, semconv.AttrExcludeTargetCount, semconv.AttrExcludeTargetsTruncated, camp.ExcludeTargets)
	}

	return telemetry.Event{
		Name:     eventPolicy,
		Body:     fmt.Sprintf("authentication methods policy %s: policyVersion=%s", p.ID, p.PolicyVersion),
		Severity: telemetry.SeverityInfo,
		Attrs:    attrs,
	}
}

// configTwin renders one authenticationMethodConfigurations entry as one
// entra.auth_method_configuration log record (#317). An UNKNOWN @odata.type
// (not in knownConfigMethods) returns immediately after id/state/odata_type
// — the load-bearing restriction from the package doc: even the
// include/exclude target arrays every known subtype gets are withheld,
// because an unreviewed field on an unseen subtype could be sensitive.
func configTwin(mc methodConfig) telemetry.Event {
	attrs := telemetry.Attrs{}
	telemetry.SetStr(attrs, semconv.AttrId, mc.ID)
	telemetry.SetStr(attrs, semconv.AttrState, mc.State)
	telemetry.SetStr(attrs, semconv.AttrOdataType, mc.ODataType)

	method, known := knownConfigMethods[mc.ODataType]
	if !known {
		return telemetry.Event{
			Name:     eventConfig,
			Body:     fmt.Sprintf("authentication method configuration %s: unrecognized subtype %s", mc.ID, mc.ODataType),
			Severity: telemetry.SeverityInfo,
			Attrs:    attrs,
		}
	}
	telemetry.SetStr(attrs, semconv.AttrMethod, method)

	setTargetIDs(attrs, semconv.AttrIncludeTargetIds, semconv.AttrIncludeTargetCount, semconv.AttrIncludeTargetsTruncated, mc.IncludeTargets)
	setTargetIDs(attrs, semconv.AttrExcludeTargetIds, semconv.AttrExcludeTargetCount, semconv.AttrExcludeTargetsTruncated, mc.ExcludeTargets)

	// Subtype-specific fields below are all null-safe reads of methodConfig's
	// union members (see its doc comment): a subtype that doesn't define a
	// given field simply leaves the pointer/slice/string at its zero value,
	// so these checks are naturally no-ops for the other six known subtypes.
	if mc.IsSelfServiceRegistrationAllowed != nil {
		telemetry.SetBool(attrs, semconv.AttrIsSelfServiceRegistrationAllowed, *mc.IsSelfServiceRegistrationAllowed)
	}
	if mc.IsAttestationEnforced != nil {
		telemetry.SetBool(attrs, semconv.AttrIsAttestationEnforced, *mc.IsAttestationEnforced)
	}
	telemetry.SetStr(attrs, semconv.AttrDefaultPasskeyProfileId, mc.DefaultPasskeyProfile)
	if mc.KeyRestrictions != nil {
		if mc.KeyRestrictions.IsEnforced != nil {
			telemetry.SetBool(attrs, semconv.AttrKeyRestrictionEnforced, *mc.KeyRestrictions.IsEnforced)
		}
		telemetry.SetStr(attrs, semconv.AttrKeyRestrictionEnforcementType, mc.KeyRestrictions.EnforcementType)
		if len(mc.KeyRestrictions.AaGuids) > 0 {
			capped, truncated := capStrings(mc.KeyRestrictions.AaGuids, maxTargetIdentifiers)
			telemetry.SetStrs(attrs, semconv.AttrKeyRestrictionAaguids, capped)
			telemetry.SetBool(attrs, semconv.AttrKeyRestrictionAaguidsTruncated, truncated)
		}
	}
	if len(mc.PasskeyProfiles) > 0 {
		ids := make([]string, 0, len(mc.PasskeyProfiles))
		for _, p := range mc.PasskeyProfiles {
			if p.ID != "" {
				ids = append(ids, p.ID)
			}
		}
		capped, truncated := capStrings(ids, maxTargetIdentifiers)
		telemetry.SetStrs(attrs, semconv.AttrPasskeyProfileIds, capped)
		telemetry.SetBool(attrs, semconv.AttrPasskeyProfileIdsTruncated, truncated)
	}
	if mc.IsSoftwareOathEnabled != nil {
		telemetry.SetBool(attrs, semconv.AttrIsSoftwareOathEnabled, *mc.IsSoftwareOathEnabled)
	}
	if mc.IsOfficePhoneAllowed != nil {
		telemetry.SetBool(attrs, semconv.AttrIsOfficePhoneAllowed, *mc.IsOfficePhoneAllowed)
	}
	if mc.PinLength != nil {
		attrs[semconv.AttrPinLength] = float64(*mc.PinLength)
	}
	if mc.StandardQRCodeLifetimeInDays != nil {
		attrs[semconv.AttrStandardQrCodeLifetimeInDays] = float64(*mc.StandardQRCodeLifetimeInDays)
	}

	return telemetry.Event{
		Name:     eventConfig,
		Body:     fmt.Sprintf("authentication method configuration %s (%s): state=%s", mc.ID, method, mc.State),
		Severity: telemetry.SeverityInfo,
		Attrs:    attrs,
	}
}

func init() {
	collectors.Register(func(d collectors.Deps) collector.SnapshotCollector {
		return New(d.Graph, d.Logger)
	})
}
