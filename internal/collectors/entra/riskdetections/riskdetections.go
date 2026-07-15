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
// detail — id, correlationId, ipAddress, userPrincipalName — belongs here as
// structured log attributes. That same data must NEVER become a metric
// label; this package emits no metrics, only logs.
//
// See GitHub issue #24.
package riskdetections

import (
	"fmt"
	"time"

	"github.com/rknightion/graph2otel/internal/collector"
	"github.com/rknightion/graph2otel/internal/collectors"
	"github.com/rknightion/graph2otel/internal/license"
	"github.com/rknightion/graph2otel/internal/logpipeline"
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

	attrs := telemetry.Attrs{}
	setStr(attrs, "id", id)
	setStr(attrs, "risk_event_type", riskEventType)
	setStr(attrs, "risk_type", str(rec, "riskType"))
	setStr(attrs, "risk_level", riskLevel)
	setStr(attrs, "risk_state", str(rec, "riskState"))
	setStr(attrs, "risk_detail", str(rec, "riskDetail"))
	setStr(attrs, "detection_timing_type", str(rec, "detectionTimingType"))
	setStr(attrs, "source", str(rec, "source"))
	setStr(attrs, "ip_address", str(rec, "ipAddress"))
	setStr(attrs, "user_principal_name", userPrincipalName)
	setStr(attrs, "user_id", str(rec, "userId"))
	setStr(attrs, "correlation_id", str(rec, "correlationId"))
	setStr(attrs, "request_id", str(rec, "requestId"))
	setStr(attrs, "activity", str(rec, "activity"))

	if loc := nested(rec, "location"); loc != nil {
		setStr(attrs, "location_city", str(loc, "city"))
		setStr(attrs, "location_country_or_region", str(loc, "countryOrRegion"))
	}

	return id, telemetry.Event{
		Name:     eventName,
		Body:     fmt.Sprintf("risk detection %s (%s) for %s", riskEventType, riskLevel, userPrincipalName),
		Severity: severityFor(riskLevel),
		Attrs:    attrs,
	}
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

// setStr adds key=val only when val is non-empty, so absent fields don't
// emit empty attributes.
func setStr(attrs telemetry.Attrs, key, val string) {
	if val != "" {
		attrs[key] = val
	}
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
