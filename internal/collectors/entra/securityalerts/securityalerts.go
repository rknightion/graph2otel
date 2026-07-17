// Package securityalerts is the Entra security-alerts log source: a single
// WindowCollector over GET /security/alerts_v2, emitting one OTLP log record
// per alert through the generic logpipeline engine (#13).
//
// alerts_v2 is the unified, current-schema security alert stream — it
// aggregates identity-related alerts surfaced from Entra ID Protection and
// Microsoft Defender products. The legacy /security/alerts endpoint is
// deprecated and deliberately avoided (see the issue's "Scope"). The endpoint
// is read-only via SecurityAlert.Read.All and carries no license gate: the
// underlying detection products (e.g. Entra ID Protection P2) may gate which
// alerts actually populate the stream, but the endpoint itself is available
// on any tier and a tenant with fewer enabled Defender products simply yields
// fewer alerts, not a hard failure. It also polls the security workload
// (moderate throttle limits), not the Identity Protection 1 req/s bucket that
// risk detections uses — the transport's ClassifyWorkload already routes
// /security/alerts* accordingly, so this collector wires no dedicated
// limiter.
//
// Cardinality note (INVERTED from the metric collectors): these are LOGS, so
// per-entity detail — the alert id, providerAlertId, incident id, evidence —
// belongs here as structured log attributes. That same data must NEVER
// become a metric label; this package emits no metrics.
//
// See GitHub issue #25.
package securityalerts

import (
	"fmt"
	"time"

	"github.com/rknightion/graph2otel/internal/collector"
	"github.com/rknightion/graph2otel/internal/collectors"
	"github.com/rknightion/graph2otel/internal/logpipeline"
	"github.com/rknightion/graph2otel/internal/semconv"
	"github.com/rknightion/graph2otel/internal/telemetry"
)

const (
	// path is the Graph v1.0 path this collector polls — the CURRENT alerts
	// endpoint, not the deprecated legacy /security/alerts.
	path = "/security/alerts_v2"
	// name is the stable collector key.
	name = "entra.security_alerts"
	// eventName is the OTLP LogRecord EventName every security alert record
	// carries.
	eventName = "entra.security_alert"
)

// Schedule tuning: security alerts poll cheaply and trail "now" by a safety
// margin so a still-landing alert is not missed.
const (
	interval        = 10 * time.Minute
	lag             = 15 * time.Minute
	initialLookback = time.Hour
	maxWindow       = 24 * time.Hour
)

// collectorImpl is the security-alerts WindowCollector: the generic
// LogCollector plus the permission declaration the composition root's
// preflight check reads. No license gate — the endpoint itself needs only
// SecurityAlert.Read.All regardless of which Defender products are enabled,
// and this is not a beta endpoint.
type collectorImpl struct {
	*logpipeline.LogCollector
}

// RequiredPermissions declares the least-privilege Graph application scope.
func (c *collectorImpl) RequiredPermissions() []string { return []string{"SecurityAlert.Read.All"} }

// newCollector builds the security-alerts WindowCollector.
func newCollector(d collectors.WindowDeps) *collectorImpl {
	cfg := logpipeline.EndpointConfig{
		Path:            path,
		TimeField:       "createdDateTime",
		Flavor:          logpipeline.FlavorGeLe,
		OrderByReliable: true, // $orderby createdDateTime asc is reliable on alerts_v2
		Map:             mapAlert,
	}
	lc := logpipeline.NewLogCollector(name, interval, lag, d.TenantID, cfg, d.Fetcher, d.Store)
	return &collectorImpl{LogCollector: lc}
}

// mapAlert turns one raw security.alert (alerts_v2) record into its dedupe id
// (the immutable alert id) and the OTLP log Event. It sets only the
// attributes actually present, so an alert with no incidentId or evidence
// simply omits those attributes rather than emitting empty/zero ones.
func mapAlert(rec map[string]any) (string, telemetry.Event) {
	id := str(rec, "id")
	title := str(rec, "title")
	severity := str(rec, "severity")
	status := str(rec, "status")
	serviceSource := str(rec, "serviceSource")

	attrs := telemetry.Attrs{}
	telemetry.SetStr(attrs, semconv.AttrId, id)
	telemetry.SetStr(attrs, semconv.AttrTitle, title)
	telemetry.SetStr(attrs, semconv.AttrCategory, str(rec, "category"))
	telemetry.SetStr(attrs, semconv.AttrSeverity, severity)
	telemetry.SetStr(attrs, semconv.AttrStatus, status)
	telemetry.SetStr(attrs, semconv.AttrServiceSource, serviceSource)
	telemetry.SetStr(attrs, semconv.AttrDetectionSource, str(rec, "detectionSource"))
	telemetry.SetStr(attrs, semconv.AttrDetermination, str(rec, "determination"))
	telemetry.SetStr(attrs, semconv.AttrClassification, str(rec, "classification"))
	telemetry.SetStr(attrs, semconv.AttrProviderAlertId, str(rec, "providerAlertId"))
	telemetry.SetStr(attrs, semconv.AttrIncidentId, str(rec, "incidentId"))

	// The record's own `tenantId` is deliberately NOT emitted (#143).
	//
	// It is not Microsoft's tenant or a third party's — it is OURS. Live-measured
	// 2026-07-17 (#143): every row from /security/alerts_v2 on m7kni carried
	// tenantId byte-equal to the poller's own AZURE_TENANT_ID (10/10 rows across
	// alerts_v2 and incidents; n is small and the tenant is single, so treat
	// "always equals ours" as strong rather than proven). That is exactly what
	// telemetry.WithTenant now stamps on every record from this Scheduler, so
	// mapping the wire field would emit the same key with the same value from a
	// second, hand-rolled writer.
	//
	// Dropping it therefore loses no information — this is not a #114 "bucketed
	// the count and discarded the entity" drop. Do not re-add it: a per-collector
	// writer for a key the emitter owns is how the two would eventually disagree.

	if evidence, ok := rec["evidence"].([]any); ok {
		attrs[semconv.AttrEvidenceCount] = len(evidence)
	}

	return id, telemetry.Event{
		Name:     eventName,
		Body:     fmt.Sprintf("%s [%s/%s]: %s", title, severity, status, serviceSource),
		Severity: severityFor(severity),
		Attrs:    attrs,
	}
}

// severityFor maps the alert's own severity string (an attribute value, kept
// verbatim in attrs["severity"]) to the OTLP log record's Severity: "high"
// alerts are errors, "medium"/"low" are warnings, anything else (including
// "informational" and "unknown") stays Info.
func severityFor(alertSeverity string) telemetry.Severity {
	switch alertSeverity {
	case "high":
		return telemetry.SeverityError
	case "medium", "low":
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

func init() {
	collectors.RegisterWindow(func(d collectors.WindowDeps) collectors.RegisteredWindow {
		return collectors.RegisteredWindow{
			Collector:       newCollector(d),
			InitialLookback: initialLookback,
			MaxWindow:       maxWindow,
		}
	})
}

// Compile-time checks that the security-alerts collector satisfies every
// interface the composition root type-asserts on.
var (
	_ collector.WindowCollector = (*collectorImpl)(nil)
)
