// Package spriskdetections is the Entra Identity Protection service-principal
// risk-detections log source: a single WindowCollector over
// GET /identityProtection/servicePrincipalRiskDetections, emitting one OTLP log
// record per workload-identity risk detection through the generic logpipeline
// engine (#13). It is the WORKLOAD-identity analog of entra.risk_detections
// (which covers USER risk detections) — same detection-event shape, different
// principal (#133).
//
// # Why this closes "half a signal"
//
// entra.risk already ships the risky-service-principal STATE gauge
// (riskyServicePrincipals: how many SPs are risky right now, by level/state).
// But that is a gauge with no evidence behind it — it says a service principal
// is risky, never WHY. servicePrincipalRiskDetections is the detection-level
// detail (leaked credentials, anomalous SP activity, admin-confirmed compromise,
// suspicious API traffic, …), and nothing polled it. This collector is that
// evidence stream — the detection EVENT, not the current state — so it is
// log-shaped like entra.risk_detections, NOT a second gauge.
//
// # IPC workload + why there is NO license gate
//
// This endpoint lives on the Identity Protection (IPC) workload: 1 request/second
// per tenant, shared across ALL IPC callers, no Retry-After. graph2otel's
// transport classifies the Path onto WorkloadIPC and serializes it through the
// shared per-tenant limiter — this collector wires no limiter itself and polls
// slowly.
//
// It is deliberately NOT gated on CapWorkloadIdentitiesPremium, unlike entra.risk's
// riskyServicePrincipals half. That was the first design and it was WRONG:
// live-verified 2026-07-19, m7kni's license detection reports NO Workload
// Identities Premium (entra.risk internally skips its SP half there), yet
// GET /identityProtection/servicePrincipalRiskDetections returns 200 with real
// detections. A capability gate would permanently hide this collector on the exact
// tenant where it works and has data. So it polls unconditionally and degrades
// gracefully: a tenant that genuinely lacks the feature returns 200/empty (nothing
// emitted) or 403 (surfaced as a WARN with the checkpoint unchanged, like every
// other logpipeline collector). The endpoint is v1.0 and stable, so it is
// default-on, not Experimental.
//
// # Cardinality (LOGS)
//
// Per-entity detail — id, servicePrincipalId, appId, ipAddress — is structured
// log attributes, never a metric label; this package emits no metrics, so #112
// holds by construction.
//
// # Mapped against a real row
//
// The field set is pinned from a VERBATIM detection synthesized on m7kni
// (admin-confirmed compromise of a throwaway SP, #133) rather than the docs —
// see liveSPRiskDetection in the test. Fields observed null on that row
// (servicePrincipalDisplayName, appId, ipAddress, location) are mapped via the
// omit-empty accessors so a populated detection type carries them, but the
// undocumented additionalInfo/keyIds shapes are NOT decoded blind: they were
// empty on the only observed row, and inventing their structure is the #142 trap.
package spriskdetections

import (
	"time"

	"github.com/rknightion/graph2otel/internal/collector"
	"github.com/rknightion/graph2otel/internal/collectors"
	"github.com/rknightion/graph2otel/internal/logpipeline"
	"github.com/rknightion/graph2otel/internal/semconv"
	"github.com/rknightion/graph2otel/internal/telemetry"
)

const (
	// spRiskDetectionsPath is the Graph v1.0 path this collector polls.
	spRiskDetectionsPath = "/identityProtection/servicePrincipalRiskDetections"
	// collectorName is the stable collector key.
	collectorName = "entra.service_principal_risk_detections"
	// eventName is the OTLP LogRecord EventName every detection carries.
	eventName = "entra.service_principal_risk_detection"
)

// Schedule tuning mirrors entra.risk_detections: the IPC workload is 1 req/s per
// tenant shared across every IPC caller, so this polls slowly and pages sparingly.
const (
	interval        = 30 * time.Minute
	lag             = 15 * time.Minute
	initialLookback = time.Hour
	maxWindow       = 24 * time.Hour
)

// collectorImpl is the SP risk-detections WindowCollector.
type collectorImpl struct {
	*logpipeline.LogCollector
}

// RequiredPermissions declares the least-privilege Graph application scope.
func (c *collectorImpl) RequiredPermissions() []string {
	return []string{"IdentityRiskyServicePrincipal.Read.All"}
}

// newCollector builds the SP risk-detections WindowCollector. Its Path is
// distinct from every other IPC stream's, so it needs no CheckpointKey override
// (unlike the four sign-in streams that share one path).
func newCollector(d collectors.WindowDeps) *collectorImpl {
	cfg := logpipeline.EndpointConfig{
		Path:            spRiskDetectionsPath,
		TimeField:       "detectedDateTime",
		Flavor:          logpipeline.FlavorGeLe,
		OrderByReliable: false, // $orderby weak/unverified here; sort client-side
		// Identity Protection caps $top at 500 (the engine's 1000 default 400s on
		// IPC — verified live on risk_detections).
		PageSize: 500,
		Map:      mapSPRiskDetection,
	}
	lc := logpipeline.NewLogCollector(collectorName, interval, lag, d.TenantID, cfg, d.Fetcher, d.Store)
	return &collectorImpl{LogCollector: lc}
}

// mapSPRiskDetection turns one raw servicePrincipalRiskDetection record into its
// dedupe id (the immutable detection id) and the OTLP log Event. Only present
// fields are set (omit-empty accessors), so a detection type missing an optional
// field simply omits that attribute.
func mapSPRiskDetection(rec map[string]any) (string, telemetry.Event) {
	id := str(rec, "id")
	riskEventType := str(rec, "riskEventType")
	riskLevel := str(rec, "riskLevel")

	attrs := telemetry.Attrs{}
	telemetry.SetStr(attrs, semconv.AttrId, id)
	telemetry.SetStr(attrs, semconv.AttrRiskEventType, riskEventType)
	telemetry.SetStr(attrs, semconv.AttrRiskLevel, riskLevel)
	telemetry.SetStr(attrs, semconv.AttrRiskState, str(rec, "riskState"))
	telemetry.SetStr(attrs, semconv.AttrRiskDetail, str(rec, "riskDetail"))
	telemetry.SetStr(attrs, semconv.AttrDetectionTimingType, str(rec, "detectionTimingType"))
	telemetry.SetStr(attrs, semconv.AttrActivity, str(rec, "activity"))
	telemetry.SetStr(attrs, semconv.AttrTokenIssuerType, str(rec, "tokenIssuerType"))
	telemetry.SetStr(attrs, semconv.AttrSource, str(rec, "source"))
	telemetry.SetStr(attrs, semconv.AttrIpAddress, str(rec, "ipAddress"))
	telemetry.SetStr(attrs, semconv.AttrCorrelationId, str(rec, "correlationId"))
	telemetry.SetStr(attrs, semconv.AttrRequestId, str(rec, "requestId"))
	// The workload identity the detection is about. servicePrincipalId is the SP
	// object id; appId and servicePrincipalDisplayName were null on the observed
	// admin-confirmed row but populate on other detection types.
	telemetry.SetStr(attrs, semconv.AttrServicePrincipalId, str(rec, "servicePrincipalId"))
	telemetry.SetStr(attrs, semconv.AttrServicePrincipalName, str(rec, "servicePrincipalDisplayName"))
	telemetry.SetStr(attrs, semconv.AttrAppId, str(rec, "appId"))

	return id, telemetry.Event{
		Name:     eventName,
		Body:     detectionBody(rec, riskEventType, riskLevel),
		Severity: severityFor(riskLevel),
		Attrs:    attrs,
	}
}

// detectionBody builds a short human-readable summary line.
func detectionBody(rec map[string]any, riskEventType, riskLevel string) string {
	who := str(rec, "servicePrincipalDisplayName")
	if who == "" {
		who = str(rec, "servicePrincipalId")
	}
	if who == "" {
		who = "unknown service principal"
	}
	return "service principal risk detection " + riskEventType + " (" + riskLevel + ") for " + who
}

// severityFor maps risk level onto the telemetry (not OTEL-wire) severity scale
// (#113): high → Error, medium → Warn, everything else → Info.
func severityFor(riskLevel string) telemetry.Severity {
	switch riskLevel {
	case "high":
		return telemetry.SeverityError
	case "medium":
		return telemetry.SeverityWarn
	default:
		return telemetry.SeverityInfo
	}
}

func str(m map[string]any, key string) string {
	s, _ := m[key].(string)
	return s
}

func init() {
	collectors.RegisterWindow(func(d collectors.WindowDeps) collectors.RegisteredWindow {
		return collectors.RegisteredWindow{
			Collector:       newCollector(d),
			InitialLookback: initialLookback,
			MaxWindow:       maxWindow,
		}
	})
}

// Compile-time check that the collector satisfies the WindowCollector interface
// the composition root type-asserts on. No license.CapabilityRequirer — this
// collector is deliberately ungated (see the package doc).
var _ collector.WindowCollector = (*collectorImpl)(nil)
