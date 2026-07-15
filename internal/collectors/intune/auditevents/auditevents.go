// Package auditevents is the Intune change-audit log source: a single
// WindowCollector over GET /deviceManagement/auditEvents, emitting one OTLP
// log record per audit event through the generic logpipeline engine (#13).
//
// This is the Graph equivalent of the Intune portal audit log / the
// AuditLogs diagnostic-settings category: every admin/service change
// (policy create/update/delete, assignment change, remote action,
// enrollment-config edit) lands here with actor, target resource, and
// before/after values. It is the highest-volume Intune log source and,
// unlike most Intune signals, needs no diagnostic-settings → Event
// Hub/Log Analytics pipeline configured — Graph retains it directly for
// ~1 year.
//
// $orderby support on this endpoint is unverified (the v1.0 List page
// documents no OData options at all), so EndpointConfig.OrderByReliable is
// false: the engine drains the whole window via nextLink, then sorts
// client-side by activityDateTime before emitting, rather than trusting
// server order. $filter on activityDateTime does work empirically and is
// what the watermark relies on.
//
// PII/secret redaction: a resource's modifiedProperties[] can carry
// credential/certificate values, UPNs, or IPs in its oldValue/newValue
// fields. mapAuditEvent NEVER emits those values — only the changed
// property NAMES — so a secret that changed hands never lands in an OTLP
// attribute.
//
// Cardinality note (INVERTED from the metric collectors): these are LOGS,
// so per-entity detail — the record id, correlationId, actor identifiers,
// resource ids — belongs here as structured log attributes. That same data
// must NEVER become a metric label; this package emits no metrics.
//
// License gate: none declared. RequiredPermissions'
// DeviceManagementApps.Read.All is a surprising scope for an audit endpoint
// per Microsoft's docs (likely a docs artifact — flagged for live
// verification, see the issue) and no CapabilityRequirer is declared here;
// a tenant lacking an active Intune license surfaces as a fetch error from
// the engine, which the scheduler skips-and-logs rather than crashing on.
//
// See GitHub issue #14.
package auditevents

import (
	"fmt"
	"time"

	"github.com/rknightion/graph2otel/internal/collector"
	"github.com/rknightion/graph2otel/internal/collectors"
	"github.com/rknightion/graph2otel/internal/logpipeline"
	"github.com/rknightion/graph2otel/internal/telemetry"
)

const (
	// path is the Graph v1.0 path this collector polls.
	path = "/deviceManagement/auditEvents"
	// collectorName is the stable collector key.
	collectorName = "intune.audit_events"
	// eventName is the OTLP LogRecord EventName every audit event record
	// carries.
	eventName = "intune.audit_event"
)

// Schedule tuning: audit events are the highest-volume Intune log source but
// still poll on a moderate cadence and trail "now" by a safety margin so a
// still-landing record is not missed.
const (
	interval        = 15 * time.Minute
	lag             = 15 * time.Minute
	initialLookback = time.Hour
	maxWindow       = 24 * time.Hour
)

// collectorImpl is the audit-events WindowCollector: the generic
// LogCollector plus the permission declaration the composition root's
// preflight check reads. No license gate declared — see the package doc for
// why.
type collectorImpl struct {
	*logpipeline.LogCollector
}

// RequiredPermissions declares the Graph application scope this collector
// needs. DeviceManagementApps.Read.All is the documented scope for this
// endpoint despite being a surprising name for an audit log — verify live
// against a real tenant before relying on it.
func (c *collectorImpl) RequiredPermissions() []string {
	return []string{"DeviceManagementApps.Read.All"}
}

// newCollector builds the audit-events WindowCollector.
func newCollector(d collectors.WindowDeps) *collectorImpl {
	cfg := logpipeline.EndpointConfig{
		Path:            path,
		TimeField:       "activityDateTime",
		Flavor:          logpipeline.FlavorGeLe,
		OrderByReliable: false, // $orderby is unverified here; sort client-side
		Map:             mapAuditEvent,
	}
	lc := logpipeline.NewLogCollector(collectorName, interval, lag, d.TenantID, cfg, d.Fetcher, d.Store)
	return &collectorImpl{LogCollector: lc}
}

// mapAuditEvent turns one raw auditEvent record into its dedupe id (the
// immutable record id) and the OTLP log Event. It sets only the attributes
// actually present, and it NEVER emits a modifiedProperties old/new value —
// only the changed property's name — since those values can carry
// credentials, certificates, UPNs, or IPs.
func mapAuditEvent(rec map[string]any) (string, telemetry.Event) {
	id := str(rec, "id")
	activityType := str(rec, "activityType")
	activityOperationType := str(rec, "activityOperationType")
	activityResult := str(rec, "activityResult")
	category := str(rec, "category")
	activity := str(rec, "activity")

	attrs := telemetry.Attrs{}
	setStr(attrs, "id", id)
	setStr(attrs, "activity", activity)
	setStr(attrs, "activity_type", activityType)
	setStr(attrs, "activity_operation_type", activityOperationType)
	setStr(attrs, "activity_result", activityResult)
	setStr(attrs, "category", category)
	setStr(attrs, "component_name", str(rec, "componentName"))
	setStr(attrs, "display_name", str(rec, "displayName"))
	setStr(attrs, "correlation_id", str(rec, "correlationId"))

	if actor := nested(rec, "actor"); actor != nil {
		setStr(attrs, "actor_type", str(actor, "auditActorType"))
		setStr(attrs, "actor_user_principal_name", str(actor, "userPrincipalName"))
		setStr(attrs, "actor_user_id", str(actor, "userId"))
		setStr(attrs, "actor_application_display_name", str(actor, "applicationDisplayName"))
		setStr(attrs, "actor_application_id", str(actor, "applicationId"))
		setStr(attrs, "actor_ip_address", str(actor, "ipAddress"))
	}

	if resources, ok := rec["resources"].([]any); ok {
		var resourceTypes, resourceDisplayNames, modifiedPropertyNames []string
		for _, r := range resources {
			res, ok := r.(map[string]any)
			if !ok {
				continue
			}
			if rt := str(res, "auditResourceType"); rt != "" {
				resourceTypes = append(resourceTypes, rt)
			}
			if dn := str(res, "displayName"); dn != "" {
				resourceDisplayNames = append(resourceDisplayNames, dn)
			}
			// Deliberately extract ONLY the property name below — never
			// oldValue/newValue, which can carry secrets/PII.
			if mp, ok := res["modifiedProperties"].([]any); ok {
				for _, p := range mp {
					prop, ok := p.(map[string]any)
					if !ok {
						continue
					}
					if name := str(prop, "displayName"); name != "" {
						modifiedPropertyNames = append(modifiedPropertyNames, name)
					}
				}
			}
		}
		if len(resourceTypes) > 0 {
			attrs["resource_types"] = resourceTypes
		}
		if len(resourceDisplayNames) > 0 {
			attrs["resource_display_names"] = resourceDisplayNames
		}
		if len(modifiedPropertyNames) > 0 {
			attrs["modified_property_names"] = modifiedPropertyNames
		}
	}

	sev := telemetry.SeverityInfo
	if activityResult == "failure" {
		sev = telemetry.SeverityWarn
	}

	return id, telemetry.Event{
		Name:     eventName,
		Body:     fmt.Sprintf("%s: %s (%s)", category, activity, activityResult),
		Severity: sev,
		Attrs:    attrs,
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

// Compile-time checks that the audit-events collector satisfies every
// interface the composition root type-asserts on.
var (
	_ collector.WindowCollector = (*collectorImpl)(nil)
)
