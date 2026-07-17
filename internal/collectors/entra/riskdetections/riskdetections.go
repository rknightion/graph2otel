// Package riskdetections is the Entra Identity Protection risk-detections log
// source: a single WindowCollector over GET /identityProtection/riskDetections,
// emitting one OTLP log record per detection (anonymous IP, impossible
// travel, leaked credentials, etc.) through the generic logpipeline engine
// (#13).
//
// This endpoint lives on the Identity Protection (IPC) workload: 1
// request/second per tenant, shared across ALL apps and ALL IPC-classified
// endpoints (risky users, risky service principals, Conditional Access
// policies/named locations), with no Retry-After. graph2otel's transport
// (internal/graphclient) already classifies this Path onto WorkloadIPC and
// serializes it through the shared per-tenant limiter — this collector does
// NOT wire any rate limiter itself, it just polls slowly (see the interval
// below) so the limiter rarely has to queue it.
//
// $orderby support on this endpoint is weak/unverified, so
// EndpointConfig.OrderByReliable is false: the engine drains the whole window
// via nextLink, then sorts client-side by detectedDateTime before emitting,
// rather than trusting server order.
//
// License gate: risk detections need Entra ID P2 for full detail (P1
// downgrades every detection to a generic riskEventType/riskDetail with the
// specifics withheld) — RequiredCapability declares CapEntraP2 so the
// composition root skips this collector below P2 rather than emitting
// degraded/misleading detail.
//
// Cardinality note (LOGS, inverted from the metric collectors): per-entity
// detail — id, correlationId, ipAddress, userPrincipalName, userDisplayName,
// userAgent, geo coordinates — belongs here as structured log attributes. That
// same data must NEVER become a metric label; this package emits no metrics,
// only logs, so #112 holds by construction and every field on the record is
// mapped rather than bucketed away (#159).
//
// See GitHub issue #24.
package riskdetections

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/rknightion/graph2otel/internal/collector"
	"github.com/rknightion/graph2otel/internal/collectors"
	"github.com/rknightion/graph2otel/internal/license"
	"github.com/rknightion/graph2otel/internal/logpipeline"
	"github.com/rknightion/graph2otel/internal/semconv"
	"github.com/rknightion/graph2otel/internal/telemetry"
)

const (
	// riskDetectionsPath is the Graph v1.0 path this collector polls.
	riskDetectionsPath = "/identityProtection/riskDetections"
	// collectorName is the stable collector key.
	collectorName = "entra.risk_detections"
	// eventName is the OTLP LogRecord EventName every risk-detection record
	// carries.
	eventName = "entra.risk_detection"
)

// Schedule tuning. The IPC workload is 1 req/s per tenant shared across every
// IPC caller (risky users, risky SPs, Conditional Access, ...), so this
// collector polls slowly and pages sparingly — a short interval would just
// queue behind the shared limiter for no operational benefit.
const (
	interval        = 30 * time.Minute
	lag             = 15 * time.Minute
	initialLookback = time.Hour
	maxWindow       = 24 * time.Hour
)

// collectorImpl is the risk-detections WindowCollector: the generic
// LogCollector plus the license declaration the composition root gates on.
type collectorImpl struct {
	*logpipeline.LogCollector
}

// RequiredCapability declares that this collector needs Entra ID P2 (full
// risk-detection detail): P1 downgrades every detection to generic-only, so
// the composition root skips this collector below P2 rather than run it
// degraded. Implements license.CapabilityRequirer.
func (c *collectorImpl) RequiredCapability() license.Capability { return license.CapEntraP2 }

// RequiredPermissions declares the Graph application permission scope this
// collector needs.
func (c *collectorImpl) RequiredPermissions() []string { return []string{"IdentityRiskEvent.Read.All"} }

// newCollector builds the risk-detections WindowCollector.
func newCollector(d collectors.WindowDeps) *collectorImpl {
	cfg := logpipeline.EndpointConfig{
		Path:            riskDetectionsPath,
		TimeField:       "detectedDateTime",
		Flavor:          logpipeline.FlavorGeLe,
		OrderByReliable: false, // $orderby is weak/unverified here; sort client-side
		// The Identity Protection endpoint caps $top at 500 (HTTP 400
		// "Invalid page size specified: '1000'. Must be between 1 and 500
		// inclusive." — verified live). The engine's 1000 default is rejected,
		// so pin the max this endpoint accepts.
		PageSize: 500,
		Map:      mapRiskDetection,
	}
	lc := logpipeline.NewLogCollector(collectorName, interval, lag, d.TenantID, cfg, d.Fetcher, d.Store)
	return &collectorImpl{LogCollector: lc}
}

// mapRiskDetection turns one raw riskDetection record into its dedupe id
// (the immutable detection id) and the OTLP log Event. It sets only the
// attributes actually present, so a record missing an optional field (e.g.
// requestId, activity) simply omits that attribute rather than emitting an
// empty one.
func mapRiskDetection(rec map[string]any) (string, telemetry.Event) {
	id := str(rec, "id")
	riskEventType := str(rec, "riskEventType")
	riskLevel := str(rec, "riskLevel")
	userPrincipalName := str(rec, "userPrincipalName")

	// No risk_type attribute is emitted, and one must not be re-added here.
	//
	// The Graph v1.0 riskDetection resource has NO riskType field — the complete
	// live key set is pinned in liveRiskDetection (riskdetections_test.go)
	// `[live-measured 2026-07-17, #129/#153]`. The line that used to sit here read
	// it anyway; setStr skips empty values, so it emitted nothing for the life of
	// the project while looking like a working mapping (#153).
	//
	// The UserRiskEvents *blob* category does carry riskType, and it is a
	// duplicate of riskEventType (both "anonymizedIPAddress"), so nothing is lost
	// by dropping it. Reinstating it as a blob-only attribute would be worse than
	// useless on both counts it could serve:
	//
	//   - the VALUE is already published, on every transport, as risk_event_type;
	//   - the PROVENANCE is already published, on every log record, as
	//     semconv.AttrIngestTransport (#141, landed) — so an attribute that exists
	//     only on blob-sourced records adds nothing but a second, implicit, and
	//     silently transport-dependent way to ask the same question.
	//
	// It would also make any `risk_type=...` SIEM rule match one transport only,
	// while looking like it matched both.
	//
	// Note this is where risk records DIVERGE from sign-ins across transports:
	// signins can share one mapper because its blob `properties` object IS the
	// Graph resource field-for-field, which is not true here. #141 and #138 both
	// reason from the sign-in case; this is the counter-example.
	attrs := telemetry.Attrs{}
	telemetry.SetStr(attrs, semconv.AttrId, id)
	telemetry.SetStr(attrs, semconv.AttrRiskEventType, riskEventType)
	telemetry.SetStr(attrs, semconv.AttrRiskLevel, riskLevel)
	telemetry.SetStr(attrs, semconv.AttrRiskState, str(rec, "riskState"))
	telemetry.SetStr(attrs, semconv.AttrRiskDetail, str(rec, "riskDetail"))
	telemetry.SetStr(attrs, semconv.AttrDetectionTimingType, str(rec, "detectionTimingType"))
	telemetry.SetStr(attrs, semconv.AttrSource, str(rec, "source"))
	telemetry.SetStr(attrs, semconv.AttrIpAddress, str(rec, "ipAddress"))
	telemetry.SetStr(attrs, semconv.AttrUserPrincipalName, userPrincipalName)
	telemetry.SetStr(attrs, semconv.AttrUserId, str(rec, "userId"))
	telemetry.SetStr(attrs, semconv.AttrUserDisplayName, str(rec, "userDisplayName"))
	telemetry.SetStr(attrs, semconv.AttrCorrelationId, str(rec, "correlationId"))
	telemetry.SetStr(attrs, semconv.AttrRequestId, str(rec, "requestId"))
	telemetry.SetStr(attrs, semconv.AttrActivity, str(rec, "activity"))
	// tokenIssuerType ("AzureAD" live) separates cloud-issued from federated
	// tokens on a risk event — the pivot for "is our federated IdP the one
	// producing these" (#159). Bounded vocabulary, but log-only like everything
	// else here: this package emits no metrics.
	telemetry.SetStr(attrs, semconv.AttrTokenIssuerType, str(rec, "tokenIssuerType"))

	if loc := nested(rec, "location"); loc != nil {
		telemetry.SetStr(attrs, semconv.AttrLocationCity, str(loc, "city"))
		telemetry.SetStr(attrs, semconv.AttrLocationState, str(loc, "state"))
		telemetry.SetStr(attrs, semconv.AttrLocationCountryOrRegion, str(loc, "countryOrRegion"))

		// geoCoordinates feed impossible-travel and geofencing rules, which
		// cannot work off city/country strings (#159).
		//
		// Presence-gated, NOT value-gated, unlike every setStr above: 0 is a
		// real coordinate — the Gulf of Guinea, and the canonical output of a
		// failed geo-IP lookup, which is itself worth alerting on — but it is
		// also float64's zero value, so a "skip the empty value" guard would
		// drop exactly the records worth seeing.
		//
		// Only latitude/longitude are mapped. The Graph docs also list an
		// altitude on geoCoordinates; it is NOT on the live record, so it is
		// unverified and stays unmapped rather than invented (#142).
		if geo := nested(loc, "geoCoordinates"); geo != nil {
			telemetry.SetNum(attrs, semconv.AttrLocationLatitude, geo, "latitude")
			telemetry.SetNum(attrs, semconv.AttrLocationLongitude, geo, "longitude")
		}
	}

	// additionalInfo carries the two highest-value SIEM fields on the record,
	// and it is decoded ONCE here for both — it is a doubly-encoded payload
	// (see additionalInfoPairs), so a second parser would be a second place to
	// get that wrong.
	//
	// Both are LOG attributes only. mitre_techniques' id combinations are
	// per-detection and unbounded, and user_agent is famously unbounded, so
	// neither may ever become a metric label (#112) — this package emits no
	// metrics, so that holds by construction.
	if pairs := additionalInfoPairs(rec); len(pairs) > 0 {
		// The MITRE ATT&CK technique ids (#153). On the live sample this is
		// "T1090.003,T1078" — Multi-hop Proxy + Valid Accounts — which named
		// the Tor sign-in #129 synthesized more precisely than riskEventType did.
		if techniques := mitreTechniques(pairs); len(techniques) > 0 {
			attrs[semconv.AttrMitreTechniques] = techniques
		}
		// The client string behind the detection (#159): a first-order pivot
		// for "what was this", and the join key onto the sign-in logs.
		telemetry.SetStr(attrs, semconv.AttrUserAgent, pairs["userAgent"])
	}

	return id, telemetry.Event{
		Name:     eventName,
		Body:     fmt.Sprintf("risk detection %s (%s) for %s", riskEventType, riskLevel, userPrincipalName),
		Severity: severityFor(riskLevel),
		Attrs:    attrs,
	}
}

// additionalInfoPairs decodes a detection's additionalInfo into its Key→Value
// pairs, returning nil when the record carries none or the payload is unusable.
//
// THE trap on this path, and the reason this is written against a live sample
// rather than the docs (#142): additionalInfo is not an object. It is a
// JSON-encoded STRING holding an array of {"Key","Value"} pairs, so the whole
// thing must be unmarshalled twice — once out of the record as a string, then
// again as JSON. Verbatim from the wire on 2026-07-17:
//
//	"additionalInfo": "[{\"Key\":\"userAgent\",\"Value\":\"Mozilla/5.0 …\"},
//	                    {\"Key\":\"mitreTechniques\",\"Value\":\"T1090.003,T1078\"}]"
//
// A mapper written against the intuitive `{"mitreTechniques": "..."}` object
// shape compiles, runs, finds nothing, and reports success forever — invisible,
// because the risk collection is empty on a healthy tenant anyway (#153). That
// is exactly why this decode is shared rather than copied per field: it is the
// one place to get it right, and every consumer inherits the fix.
//
// Every failure mode returns nil (attributes omitted) rather than an error: the
// contents of additionalInfo are undocumented and vary by riskEventType, so a
// record missing any given pair is the NORMAL case, not a fault. A malformed
// payload must not sink an otherwise good detection record.
//
// First occurrence of a duplicated Key wins, matching the wire order.
func additionalInfoPairs(rec map[string]any) map[string]string {
	raw := str(rec, "additionalInfo")
	if raw == "" {
		return nil
	}

	var pairs []struct {
		Key   string `json:"Key"`
		Value string `json:"Value"`
	}
	if err := json.Unmarshal([]byte(raw), &pairs); err != nil {
		return nil
	}

	out := make(map[string]string, len(pairs))
	for _, p := range pairs {
		if _, dup := out[p.Key]; !dup {
			out[p.Key] = p.Value
		}
	}
	return out
}

// mitreTechniques splits the comma-separated MITRE ATT&CK technique ids out of
// a decoded additionalInfo payload, returning nil when it carries none.
func mitreTechniques(pairs map[string]string) []string {
	var out []string
	for _, t := range strings.Split(pairs["mitreTechniques"], ",") {
		if t = strings.TrimSpace(t); t != "" {
			out = append(out, t)
		}
	}
	return out
}

// severityFor maps a riskDetection's riskLevel to a log Severity: "high" is
// an Error, "medium" is a Warn, everything else (low, hidden, none,
// unknownFutureValue) stays Info.
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

// --- small defensive accessors for untyped Graph JSON ---

func str(m map[string]any, key string) string {
	s, _ := m[key].(string)
	return s
}

func nested(m map[string]any, key string) map[string]any {
	n, _ := m[key].(map[string]any)
	return n
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

// Compile-time checks that the risk-detections collector satisfies every
// interface the composition root type-asserts on.
var (
	_ collector.WindowCollector  = (*collectorImpl)(nil)
	_ license.CapabilityRequirer = (*collectorImpl)(nil)
)
