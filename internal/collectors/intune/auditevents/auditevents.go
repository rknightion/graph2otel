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
// remoteActionAudits is intentionally NOT a separate collector (#95, live-
// verified 2026-07-16). Device remote actions already land here: a live scan of
// 6000 auditEvents rows found syncDevice (as activityType "syncDevice
// ManagedDevice", op "Action"), wipe, retire, rebootNow, and shutDown all
// present in the "Device" category. /deviceManagement/remoteActionAudits (beta)
// is real and returns rows, but its only data auditEvents lacks is the action
// lifecycle STATE (actionState pending→done) and hardware ids (deviceIMEI,
// bulkDeviceActionId) — niche, and the action-occurred signal (the security-
// relevant part) is fully covered here. A dedicated collector would duplicate
// that coverage, so it was closed as redundant rather than built.
//
// $orderby support on this endpoint is unverified (the v1.0 List page
// documents no OData options at all), so EndpointConfig.OrderByReliable is
// false: the engine drains the whole window via nextLink, then sorts
// client-side by activityDateTime before emitting, rather than trusting
// server order. $filter on activityDateTime does work empirically and is
// what the watermark relies on.
//
// Secret redaction — the ONE genuine content exclusion in graph2otel, and it is
// about SECRETS, not PII: a resource's modifiedProperties[] carries arbitrary
// oldValue/newValue payloads, which for a credential or certificate change is
// the credential itself. mapAuditEvent NEVER emits those values — only the
// changed property NAMES — so a secret that changed hands never lands in an
// OTLP attribute. Do not "fix" this by emitting values: no SIEM framing
// justifies shipping a private key to a log backend.
//
// PII is emphatically NOT excluded here, and must not be: this collector emits
// the actor's UPN, user id, and IP address as attributes by design (see
// mapAuditEvent). Those same modifiedProperties values may also contain UPNs or
// IPs, but that is not why they are dropped — the actor identity is already
// right there in the attribute set.
//
// Cardinality note (INVERTED from the metric collectors): these are LOGS,
// so per-entity detail — the record id, correlationId, actor identifiers,
// resource ids — belongs here as structured log attributes. That same data
// must NEVER become a metric label; this package emits no metrics. See
// CLAUDE.md: the boundary is a data-modeling rule, not a privacy control.
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
	"github.com/rknightion/graph2otel/internal/semconv"
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
// only the changed property's name — since those values carry whatever the
// changed property held, which for a credential/certificate change is the
// secret itself. See the package doc: that exclusion is about secrets, not
// PII — actor UPN/id/IP are emitted here deliberately.
func mapAuditEvent(rec map[string]any) (string, telemetry.Event) {
	id := str(rec, "id")
	activityType := str(rec, "activityType")
	activityOperationType := str(rec, "activityOperationType")
	activityResult := str(rec, "activityResult")
	category := str(rec, "category")
	// activity is null on every live-captured row (#172, live-measured
	// 2026-07-17) — telemetry.SetStr already omits it here when empty, so this is a
	// no-op on real data today. Kept (not removed) because a non-empty
	// activity is plausible on some activityType this project hasn't
	// captured yet; do not "fix" the gap by inventing a fixture value for
	// it — that's the exact regression #172 documents.
	activity := str(rec, "activity")

	attrs := telemetry.Attrs{}
	telemetry.SetStr(attrs, semconv.AttrId, id)
	telemetry.SetStr(attrs, semconv.AttrActivity, activity)
	telemetry.SetStr(attrs, semconv.AttrActivityType, activityType)
	telemetry.SetStr(attrs, semconv.AttrActivityOperationType, activityOperationType)
	telemetry.SetStr(attrs, semconv.AttrActivityResult, activityResult)
	telemetry.SetStr(attrs, semconv.AttrCategory, category)
	telemetry.SetStr(attrs, semconv.AttrComponentName, str(rec, "componentName"))
	telemetry.SetStr(attrs, semconv.AttrDisplayName, str(rec, "displayName"))
	telemetry.SetStr(attrs, semconv.AttrCorrelationId, str(rec, "correlationId"))

	if actor := nested(rec, "actor"); actor != nil {
		telemetry.SetStr(attrs, semconv.AttrActorType, str(actor, "auditActorType"))
		telemetry.SetStr(attrs, semconv.AttrActorUserPrincipalName, str(actor, "userPrincipalName"))
		telemetry.SetStr(attrs, semconv.AttrActorUserId, str(actor, "userId"))
		telemetry.SetStr(attrs, semconv.AttrActorApplicationDisplayName, str(actor, "applicationDisplayName"))
		telemetry.SetStr(attrs, semconv.AttrActorApplicationId, str(actor, "applicationId"))
		telemetry.SetStr(attrs, semconv.AttrActorIpAddress, str(actor, "ipAddress"))
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
			attrs[semconv.AttrResourceTypes] = resourceTypes
		}
		if len(resourceDisplayNames) > 0 {
			attrs[semconv.AttrResourceDisplayNames] = resourceDisplayNames
		}
		if len(modifiedPropertyNames) > 0 {
			attrs[semconv.AttrModifiedPropertyNames] = modifiedPropertyNames
		}
	}

	sev := telemetry.SeverityInfo
	if activityResult == "failure" {
		sev = telemetry.SeverityWarn
	}

	// Body uses displayName, not the top-level activity field: activity is
	// null on every live-captured row (#172), which rendered every Body with
	// an empty middle ("DeviceConfiguration:  (Success)"). displayName is the
	// populated, human-readable one-line summary ("Create device
	// configuration assignment 2.0 (beta)"). The activity ATTRIBUTE mapping
	// above is unchanged — telemetry.SetStr already omits it when empty — this only
	// changes what the log Body renders from.
	return id, telemetry.Event{
		Name:     eventName,
		Body:     fmt.Sprintf("%s: %s (%s)", category, str(rec, "displayName"), activityResult),
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
