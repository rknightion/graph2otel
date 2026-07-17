// Package signins is the Entra sign-in log source: four WindowCollectors over
// GET /auditLogs/signIns, one per signInEventTypes slice, each emitting one
// OTLP log record per sign-in through the generic logpipeline engine (#13).
//
// Four separate collectors are required because Microsoft Graph cannot combine
// user and servicePrincipal/managedIdentity event types in a single
// signInEventTypes $filter, and each stream wants its own watermark + volume
// isolation (non-interactive user sign-ins alone are, for most tenants, the
// bulk of all sign-in traffic). They share the sign-in record mapping (this
// file's mapSignIn) but register independently.
//
// v1.0 vs beta (verified live 2026-07-15): the DEFAULT /auditLogs/signIns
// collection on v1.0 returns interactive user sign-ins, so the interactive
// collector runs on v1.0 and is enabled by default. The three
// signInEventTypes-filtered streams are BETA-ONLY — v1.0 returns HTTP 400
// "Could not find a property named 'signInEventTypes' on type
// 'microsoft.graph.signIn'" — so they target the beta endpoint via
// EndpointConfig.BaseURLOverride and are marked Experimental (opt-in): a
// default deployment gets interactive sign-ins on the stable API, and an
// operator explicitly opts into the beta streams for the full picture.
//
// Cardinality note (INVERTED from the metric collectors): these are LOGS, so
// per-entity detail — userPrincipalName, ipAddress, correlationId, the sign-in
// id — belongs here as structured log attributes. That same data must NEVER
// become a metric label; this package emits no metrics, only logs.
//
// See GitHub issues #18 (interactive), #19 (non-interactive user), #20
// (service principal), #21 (managed identity).
package signins

import (
	"fmt"
	"time"

	"github.com/rknightion/graph2otel/internal/collector"
	"github.com/rknightion/graph2otel/internal/collectors"
	"github.com/rknightion/graph2otel/internal/license"
	"github.com/rknightion/graph2otel/internal/logpipeline"
	"github.com/rknightion/graph2otel/internal/semconv"
	"github.com/rknightion/graph2otel/internal/telemetry"
)

const (
	// signInsPath is the shared Graph path for all four streams.
	signInsPath = "/auditLogs/signIns"
	// betaBaseURL is the Graph beta service root the signInEventTypes-filtered
	// streams require (the filter is beta-only; v1.0 400s on it).
	betaBaseURL = "https://graph.microsoft.com/beta"
	// eventName is the OTLP LogRecord EventName every sign-in record carries.
	eventName = "entra.signin"
)

// Schedule tuning shared by all four sign-in streams. Sign-in logs need P1
// regardless of slice, poll cheaply, and trail "now" by a safety margin so a
// still-landing record is not missed.
const (
	interval        = 5 * time.Minute
	lag             = 15 * time.Minute
	initialLookback = time.Hour
	maxWindow       = 24 * time.Hour
)

// spec describes one sign-in stream: its stable collector name, the beta
// signInEventTypes predicate (empty = the v1.0 default interactive slice), and
// whether it is a beta/opt-in stream.
type spec struct {
	name       string // stable collector key, e.g. "entra.signins.non_interactive"
	eventType  string // signInEventTypes value, e.g. "nonInteractiveUser"; "" = default interactive
	beta       bool   // beta endpoint + Experimental opt-in
	checkpoint string // checkpoint namespace suffix (streams share signInsPath)
}

// specs is the fixed set of four sign-in streams.
var specs = []spec{
	{name: "entra.signins.interactive", eventType: "", beta: false, checkpoint: "interactive"},
	{name: "entra.signins.non_interactive", eventType: "nonInteractiveUser", beta: true, checkpoint: "nonInteractiveUser"},
	{name: "entra.signins.service_principal", eventType: "servicePrincipal", beta: true, checkpoint: "servicePrincipal"},
	{name: "entra.signins.managed_identity", eventType: "managedIdentity", beta: true, checkpoint: "managedIdentity"},
}

// collectorImpl is one sign-in WindowCollector: the generic LogCollector plus
// the license and beta-opt-in declarations the composition root gates on.
type collectorImpl struct {
	*logpipeline.LogCollector
	beta bool
}

// RequiredCapability declares that every sign-in stream needs Entra ID P1 (the
// sign-in logs are unavailable on Free); the composition root skips the
// collector on an insufficient tier. Implements license.CapabilityRequirer.
func (c *collectorImpl) RequiredCapability() license.Capability { return license.CapEntraP1 }

// RequiredPermissions declares the hard Graph scope. Policy.Read.All is a SOFT
// dependency (without it the appliedConditionalAccessPolicies sub-object is
// silently omitted, not an error), so it is not listed as required here.
func (c *collectorImpl) RequiredPermissions() []string { return []string{"AuditLog.Read.All"} }

// Experimental marks the three signInEventTypes-filtered (beta) streams as
// opt-in; the interactive (v1.0) stream returns false and stays default-on.
func (c *collectorImpl) Experimental() bool { return c.beta }

// newCollector builds one sign-in stream's WindowCollector from its spec.
func newCollector(s spec, d collectors.WindowDeps) *collectorImpl {
	cfg := logpipeline.EndpointConfig{
		Path:            signInsPath,
		CheckpointKey:   signInsPath + "#" + s.checkpoint,
		TimeField:       "createdDateTime",
		Flavor:          logpipeline.FlavorGeLe,
		OrderByReliable: true, // $orderby createdDateTime asc is reliable on signIns
		Map:             mapSignIn,
	}
	if s.eventType != "" {
		cfg.BaseURLOverride = betaBaseURL
		cfg.FilterExtra = fmt.Sprintf("signInEventTypes/any(t: t eq '%s')", s.eventType)
	}
	lc := logpipeline.NewLogCollector(s.name, interval, lag, d.TenantID, cfg, d.Fetcher, d.Store)
	return &collectorImpl{LogCollector: lc, beta: s.beta}
}

// mapSignIn turns one raw signIn record into its dedupe id (the immutable
// sign-in id) and the OTLP log Event. It sets only the attributes actually
// present, so a service-principal or managed-identity sign-in (no
// userPrincipalName) simply omits that attribute rather than emitting an empty
// one. The same signIn resource shape serves all four streams.
func mapSignIn(rec map[string]any) (string, telemetry.Event) {
	id := str(rec, "id")

	attrs := telemetry.Attrs{}
	telemetry.SetStr(attrs, semconv.AttrId, id)
	telemetry.SetStr(attrs, semconv.AttrCorrelationId, str(rec, "correlationId"))
	telemetry.SetStr(attrs, semconv.AttrUserPrincipalName, str(rec, "userPrincipalName"))
	telemetry.SetStr(attrs, semconv.AttrUserId, str(rec, "userId"))
	telemetry.SetStr(attrs, semconv.AttrAppId, str(rec, "appId"))
	telemetry.SetStr(attrs, semconv.AttrAppDisplayName, str(rec, "appDisplayName"))
	telemetry.SetStr(attrs, semconv.AttrResourceDisplayName, str(rec, "resourceDisplayName"))
	telemetry.SetStr(attrs, semconv.AttrResourceId, str(rec, "resourceId"))
	telemetry.SetStr(attrs, semconv.AttrServicePrincipalId, str(rec, "servicePrincipalId"))
	telemetry.SetStr(attrs, semconv.AttrServicePrincipalName, str(rec, "servicePrincipalName"))
	telemetry.SetStr(attrs, semconv.AttrIpAddress, str(rec, "ipAddress"))
	telemetry.SetStr(attrs, semconv.AttrClientAppUsed, str(rec, "clientAppUsed"))
	telemetry.SetStr(attrs, semconv.AttrConditionalAccessStatus, str(rec, "conditionalAccessStatus"))
	telemetry.SetStr(attrs, semconv.AttrRiskLevelDuringSignIn, str(rec, "riskLevelDuringSignIn"))
	telemetry.SetStr(attrs, semconv.AttrRiskState, str(rec, "riskState"))

	if loc := nested(rec, "location"); loc != nil {
		telemetry.SetStr(attrs, semconv.AttrLocationCountryOrRegion, str(loc, "countryOrRegion"))
	}
	if types := strSlice(rec, "signInEventTypes"); len(types) > 0 {
		attrs[semconv.AttrSignInEventTypes] = types
	}

	// status is a nested object with a numeric errorCode; 0 means success.
	errorCode := 0
	sev := telemetry.SeverityInfo
	if st := nested(rec, "status"); st != nil {
		if f, ok := st["errorCode"].(float64); ok {
			errorCode = int(f)
			attrs[semconv.AttrStatusErrorCode] = errorCode
		}
		telemetry.SetStr(attrs, semconv.AttrStatusFailureReason, str(st, "failureReason"))
		if errorCode != 0 {
			sev = telemetry.SeverityWarn
		}
	}

	return id, telemetry.Event{
		Name:     eventName,
		Body:     signInBody(rec, errorCode),
		Severity: sev,
		Attrs:    attrs,
	}
}

// signInBody builds a short human-readable summary line for a sign-in record.
func signInBody(rec map[string]any, errorCode int) string {
	who := str(rec, "userPrincipalName")
	if who == "" {
		who = str(rec, "servicePrincipalName")
	}
	if who == "" {
		who = "unknown principal"
	}
	app := str(rec, "appDisplayName")
	if app == "" {
		app = str(rec, "resourceDisplayName")
	}
	result := "success"
	if errorCode != 0 {
		result = fmt.Sprintf("failure (%d)", errorCode)
	}
	return fmt.Sprintf("sign-in by %s to %s: %s", who, app, result)
}

// --- small defensive accessors for untyped Graph JSON ---

func str(m map[string]any, key string) string {
	s, _ := m[key].(string)
	return s
}

func nested(m map[string]any, key string) map[string]any {
	n, _ := m[key].(map[string]any)
	return n
}

func strSlice(m map[string]any, key string) []string {
	raw, ok := m[key].([]any)
	if !ok {
		return nil
	}
	out := make([]string, 0, len(raw))
	for _, v := range raw {
		if s, ok := v.(string); ok {
			out = append(out, s)
		}
	}
	return out
}

func init() {
	for _, s := range specs {
		collectors.RegisterWindow(func(d collectors.WindowDeps) collectors.RegisteredWindow {
			return collectors.RegisteredWindow{
				Collector:       newCollector(s, d),
				InitialLookback: initialLookback,
				MaxWindow:       maxWindow,
			}
		})
	}
}

// Compile-time checks that the sign-in collector satisfies every interface the
// composition root type-asserts on.
var (
	_ collector.WindowCollector  = (*collectorImpl)(nil)
	_ license.CapabilityRequirer = (*collectorImpl)(nil)
	_ collectors.Experimental    = (*collectorImpl)(nil)
)
