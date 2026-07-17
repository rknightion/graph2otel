// Package provisioning is the Entra provisioning log source: a single
// WindowCollector over GET /auditLogs/provisioning, emitting one OTLP log
// record per provisioningObjectSummary event through the generic
// logpipeline engine (#13).
//
// Provisioning logs capture SCIM/app-provisioning sync events — a user
// created, updated, or disabled in a target enterprise app. Its one
// structural difference from the other audit streams: the
// provisioningObjectSummary resource's activityDateTime filters with STRICT
// gt/lt (not ge/le) and its $orderby is unreliable, so this collector sets
// logpipeline.FlavorGtLt and OrderByReliable=false — the engine drains the
// full window and sorts client-side by activityDateTime rather than trusting
// server order. Correctness rests on the watermark + id-dedupe, not server
// order.
//
// Cardinality note (INVERTED from the metric collectors): these are LOGS, so
// per-entity detail — the record id, source/target identity ids, the
// provisioning job id — belongs here as structured log attributes. That same
// data must NEVER become a metric label; this package emits no metrics.
//
// See GitHub issue #23.
package provisioning

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
	path = "/auditLogs/provisioning"
	// name is the stable collector key.
	name = "entra.provisioning"
	// eventName is the OTLP LogRecord EventName every provisioning record
	// carries.
	eventName = "entra.provisioning"
)

// Schedule tuning: provisioning volume is proportional to the number of
// provisioning-enabled enterprise apps and their user scope (#23), so a
// longer poll interval than the 5-minute sign-in/audit streams is fine.
const (
	interval        = 15 * time.Minute
	lag             = 15 * time.Minute
	initialLookback = time.Hour
	maxWindow       = 24 * time.Hour
)

// collectorImpl is the provisioning WindowCollector: the generic
// LogCollector plus the permission declaration the composition root's
// preflight check reads. No license gate and not a beta endpoint.
type collectorImpl struct {
	*logpipeline.LogCollector
}

// RequiredPermissions declares the least-privilege Graph application scope.
func (c *collectorImpl) RequiredPermissions() []string { return []string{"AuditLog.Read.All"} }

// newCollector builds the provisioning WindowCollector.
func newCollector(d collectors.WindowDeps) *collectorImpl {
	cfg := logpipeline.EndpointConfig{
		Path:            path,
		TimeField:       "activityDateTime",
		Flavor:          logpipeline.FlavorGtLt, // strict gt/lt: provisioning requires it (#23)
		OrderByReliable: false,                  // $orderby is unreliable on provisioning; sort client-side
		Map:             mapProvisioning,
	}
	lc := logpipeline.NewLogCollector(name, interval, lag, d.TenantID, cfg, d.Fetcher, d.Store)
	return &collectorImpl{LogCollector: lc}
}

// mapProvisioning turns one raw provisioningObjectSummary record into its
// dedupe id (the immutable activity id) and the OTLP log Event. It sets only
// the attributes actually present: a record with no servicePrincipal entry,
// or no errorInformation on a successful event, simply omits those
// attributes rather than emitting them empty.
func mapProvisioning(rec map[string]any) (string, telemetry.Event) {
	id := str(rec, "id")
	action := str(rec, "provisioningAction")

	attrs := telemetry.Attrs{}
	setStr(attrs, "id", id)
	setStr(attrs, "job_id", str(rec, "jobId"))
	setStr(attrs, "cycle_id", str(rec, "cycleId"))
	setStr(attrs, "change_id", str(rec, "changeId"))
	setStr(attrs, "provisioning_action", action)

	status := ""
	sev := telemetry.SeverityInfo
	if statusInfo := nested(rec, "provisioningStatusInfo"); statusInfo != nil {
		status = str(statusInfo, "status")
		setStr(attrs, "status", status)
		if status == "failure" {
			sev = telemetry.SeverityWarn
		}
		if errInfo := nested(statusInfo, "errorInformation"); errInfo != nil {
			setStr(attrs, "status_info", str(errInfo, "reason"))
			setStr(attrs, "status_error_code", str(errInfo, "errorCode"))
		}
	}

	if src := nested(rec, "sourceIdentity"); src != nil {
		setStr(attrs, "source_identity_id", str(src, "id"))
		setStr(attrs, "source_identity_display_name", str(src, "displayName"))
	}
	if tgt := nested(rec, "targetIdentity"); tgt != nil {
		setStr(attrs, "target_identity_id", str(tgt, "id"))
		setStr(attrs, "target_identity_display_name", str(tgt, "displayName"))
	}
	// servicePrincipal is a SINGLE OBJECT on provisioningObjectSummary
	// `[live-measured 2026-07-17, #165, #167]`, not the collection the Graph
	// resource doc describes, and its name field is "displayName", not "name".
	// The old firstNested/"name" reading matched the doc but never the wire,
	// so service_principal_id/service_principal_name were silently dropped
	// from every real record.
	if sp := nested(rec, "servicePrincipal"); sp != nil {
		setStr(attrs, "service_principal_id", str(sp, "id"))
		setStr(attrs, "service_principal_name", str(sp, "displayName"))
	}

	return id, telemetry.Event{
		Name:     eventName,
		Body:     fmt.Sprintf("provisioning %s: %s", action, status),
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

// Compile-time checks that the provisioning collector satisfies every
// interface the composition root type-asserts on.
var (
	_ collector.WindowCollector = (*collectorImpl)(nil)
)
