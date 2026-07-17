// Package directoryaudits is the Entra directory audit log source: a single
// WindowCollector over GET /auditLogs/directoryAudits, emitting one OTLP log
// record per audit event through the generic logpipeline engine (#13).
//
// The directory audit log is the tenant's config-change trail: role
// assignments, policy changes, application creation, password resets (SSPR
// events land here too, under the user-management categories, since there is
// no dedicated SSPR event API). Unlike sign-ins it is readable on Entra ID
// Free (shorter retention only), so this collector declares no license gate.
//
// Cardinality note (INVERTED from the metric collectors): these are LOGS, so
// per-entity detail — the record id, correlationId, initiator/target
// identifiers — belongs here as structured log attributes. That same data
// must NEVER become a metric label; this package emits no metrics.
//
// See GitHub issue #22.
package directoryaudits

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
	path = "/auditLogs/directoryAudits"
	// name is the stable collector key.
	name = "entra.directory_audits"
	// eventName is the OTLP LogRecord EventName every directory audit record
	// carries.
	eventName = "entra.directory_audit"
)

// Schedule tuning: directory audits poll cheaply and trail "now" by a safety
// margin so a still-landing record is not missed.
const (
	interval        = 5 * time.Minute
	lag             = 15 * time.Minute
	initialLookback = time.Hour
	maxWindow       = 24 * time.Hour
)

// collectorImpl is the directory-audits WindowCollector: the generic
// LogCollector plus the permission declaration the composition root's
// preflight check reads. No license gate — directory audits are available on
// Entra ID Free (shorter retention only), and this is not a beta endpoint.
type collectorImpl struct {
	*logpipeline.LogCollector
}

// RequiredPermissions declares the least-privilege Graph application scope.
func (c *collectorImpl) RequiredPermissions() []string { return []string{"AuditLog.Read.All"} }

// newCollector builds the directory-audits WindowCollector.
func newCollector(d collectors.WindowDeps) *collectorImpl {
	cfg := logpipeline.EndpointConfig{
		Path:            path,
		TimeField:       "activityDateTime",
		Flavor:          logpipeline.FlavorGeLe,
		OrderByReliable: true, // $orderby activityDateTime asc is reliable on directoryAudits
		Map:             mapDirectoryAudit,
	}
	lc := logpipeline.NewLogCollector(name, interval, lag, d.TenantID, cfg, d.Fetcher, d.Store)
	return &collectorImpl{LogCollector: lc}
}

// mapDirectoryAudit turns one raw directoryAudit record into its dedupe id
// (the immutable record id) and the OTLP log Event. It sets only the
// attributes actually present: an audit initiated by an application (rather
// than a user) has no initiatedBy.user, and a record with no targetResources
// entries carries none of the target attributes.
func mapDirectoryAudit(rec map[string]any) (string, telemetry.Event) {
	id := str(rec, "id")
	category := str(rec, "category")
	activityDisplayName := str(rec, "activityDisplayName")
	result := str(rec, "result")

	attrs := telemetry.Attrs{}
	telemetry.SetStr(attrs, semconv.AttrId, id)
	telemetry.SetStr(attrs, semconv.AttrCategory, category)
	telemetry.SetStr(attrs, semconv.AttrActivityDisplayName, activityDisplayName)
	telemetry.SetStr(attrs, semconv.AttrResult, result)
	telemetry.SetStr(attrs, semconv.AttrResultReason, str(rec, "resultReason"))
	telemetry.SetStr(attrs, semconv.AttrLoggedByService, str(rec, "loggedByService"))
	telemetry.SetStr(attrs, semconv.AttrCorrelationId, str(rec, "correlationId"))

	if initiatedBy := nested(rec, "initiatedBy"); initiatedBy != nil {
		if user := nested(initiatedBy, "user"); user != nil {
			telemetry.SetStr(attrs, semconv.AttrInitiatorUserPrincipalName, str(user, "userPrincipalName"))
			telemetry.SetStr(attrs, semconv.AttrInitiatorUserId, str(user, "id"))
		}
		if app := nested(initiatedBy, "app"); app != nil {
			telemetry.SetStr(attrs, semconv.AttrInitiatorAppDisplayName, str(app, "displayName"))
			telemetry.SetStr(attrs, semconv.AttrInitiatorAppId, str(app, "appId"))
			// appId is null on every app-initiated record this project has
			// captured live; servicePrincipalId is the only identifier left
			// on those records, so it is mapped as its own distinct
			// attribute rather than folded into initiator_app_id (#168).
			telemetry.SetStr(attrs, semconv.AttrInitiatorServicePrincipalId, str(app, "servicePrincipalId"))
		}
	}

	if targets, ok := rec["targetResources"].([]any); ok {
		attrs[semconv.AttrTargetResourceCount] = len(targets)
		var displayNames []string
		for _, tr := range targets {
			t, ok := tr.(map[string]any)
			if !ok {
				continue
			}
			if dn := str(t, "displayName"); dn != "" {
				displayNames = append(displayNames, dn)
			}
		}
		if len(displayNames) > 0 {
			attrs[semconv.AttrTargetDisplayNames] = displayNames
		}
	}

	sev := telemetry.SeverityInfo
	if result == "failure" {
		sev = telemetry.SeverityWarn
	}

	return id, telemetry.Event{
		Name:     eventName,
		Body:     fmt.Sprintf("%s: %s (%s)", category, activityDisplayName, result),
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

// Compile-time checks that the directory-audits collector satisfies every
// interface the composition root type-asserts on.
var (
	_ collector.WindowCollector = (*collectorImpl)(nil)
)
