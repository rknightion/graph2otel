// Package graphactivity is the MicrosoftGraphActivityLogs source: one OTLP log
// record per Microsoft Graph API call made against the tenant, read from Azure
// Storage rather than from Graph (#89).
//
// This is THE signal that justifies the whole blob-ingest path. Graph has no
// endpoint for its own API-call telemetry — none, permanently — so this data
// exists only as Azure Monitor diagnostic-settings output. It is also the bulk
// of the traffic: ~150,000 rows and ~70% of billable volume per 7 days on a
// small tenant, dwarfing every category graph2otel can poll.
//
// What it answers, which nothing else does: which app or user called which Graph
// endpoint, with which permissions, from where, and what came back. That makes
// it the audit trail for token misuse, over-permissioned apps, and
// enumeration-shaped reconnaissance against the directory.
//
// Cardinality (INVERTED from the metric collectors, as for every log source):
// per-entity detail — the caller's app id, service principal, IP, the request
// URI with a UPN embedded in it — belongs here as structured log attributes.
// None of it may ever become a metric label. This package emits no metrics; the
// question of deriving bounded aggregates from these events is #128's, and is
// deliberately not answered here.
package graphactivity

import (
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/rknightion/graph2otel/internal/blobpipeline"
	"github.com/rknightion/graph2otel/internal/collector"
	"github.com/rknightion/graph2otel/internal/collectors"
	"github.com/rknightion/graph2otel/internal/telemetry"
)

const (
	// collectorName is the stable config/self-obs key.
	collectorName = "entra.graph_activity"
	// container is where Azure Monitor writes this category: the fixed
	// "insights-logs-" prefix plus the diagnostic-settings category name,
	// lowercased.
	container = "insights-logs-microsoftgraphactivitylogs"
	// eventName is the OTLP LogRecord EventName every record carries.
	eventName = "entra.graph_activity"
	// interval is how often the container is re-listed. Records land ~4-5
	// minutes behind the event (an Entra-side floor measured live — the
	// destination cannot beat it, #89), so polling faster than this buys
	// nothing but list operations, which are billed at the write rate.
	interval = 5 * time.Minute
)

// blobPrefix returns the listing prefix for a tenant's records.
//
// This is "tenantId=<guid>/" and NOT the documented
// "resourceId=/tenants/<guid>/providers/microsoft.aadiam/..." form — verified
// live 2026-07-16 (#89). Every published Microsoft example is for a
// subscription-scoped resource; a TENANT-level (microsoft.aadiam) diagnostic
// setting uses the tenantId= form instead. Coding to the docs produces a
// collector that lists zero blobs and reports success forever, which is the
// single most likely way this silently breaks.
func blobPrefix(tenantID string) string {
	return "tenantId=" + tenantID + "/"
}

// newCollector builds the MicrosoftGraphActivityLogs blob collector for a tenant.
func newCollector(d collectors.BlobDeps) collector.SnapshotCollector {
	cfg := blobpipeline.ContainerConfig{
		Container: container,
		Prefix:    blobPrefix(d.TenantID),
		Map:       mapActivity,
	}
	return blobpipeline.NewBlobCollector(collectorName, interval, d.TenantID, cfg, d.Source, d.Store, d.Logger)
}

// mapActivity turns one raw MicrosoftGraphActivityLogs record into its OTLP log
// Event. It returns false for a record with no properties object — there is
// nothing useful to say about it, and blobpipeline still consumes the bytes so a
// rejected record never stalls the cursor.
//
// Every field read here was verified against a 335-record live sample
// (2026-07-16); nothing below is inferred from documentation.
func mapActivity(rec map[string]any) (telemetry.Event, bool) {
	props := nested(rec, "properties")
	if props == nil {
		return telemetry.Event{}, false
	}

	attrs := telemetry.Attrs{}
	setStr(attrs, "request_id", str(props, "requestId"))
	setStr(attrs, "operation_id", str(props, "operationId"))
	setStr(attrs, "client_request_id", str(props, "clientRequestId"))
	setStr(attrs, "correlation_id", str(rec, "correlationId"))
	setStr(attrs, "sign_in_activity_id", str(props, "signInActivityId"))

	setStr(attrs, "request_method", str(props, "requestMethod"))
	setStr(attrs, "request_uri", str(props, "requestUri"))
	setStr(attrs, "api_version", str(props, "apiVersion"))
	setStr(attrs, "user_agent", str(props, "userAgent"))

	// Numbers come from properties, never from the top level: the SAME record
	// carries durationMs as a string ("497815") at the top and as an int
	// (497815) here. The top-level resultSignature is likewise a stringified
	// status code.
	status, hasStatus := intOf(props, "responseStatusCode")
	if hasStatus {
		attrs["response_status_code"] = status
	}
	if v, ok := intOf(props, "durationMs"); ok {
		attrs["duration_ms"] = v
	}
	if v, ok := intOf(props, "responseSizeBytes"); ok {
		attrs["response_size_bytes"] = v
	}

	// Caller identity. A call is either app-only (servicePrincipalId) or
	// delegated (userId) — never both — and C_Idtyp says which.
	setStr(attrs, "app_id", str(props, "appId"))
	setStr(attrs, "service_principal_id", str(props, "servicePrincipalId"))
	setStr(attrs, "user_id", str(props, "userId"))
	setStr(attrs, "user_principal_object_id", str(props, "UserPrincipalObjectID"))
	setStr(attrs, "identity_type", str(props, "C_Idtyp"))
	setStr(attrs, "identity_provider", str(props, "identityProvider"))
	setStr(attrs, "token_issued_at", str(props, "tokenIssuedAt"))

	// roles/scopes/wids arrive space-separated in one string. Splitting them
	// makes "which app used which permission" a filter rather than a substring
	// search.
	setList(attrs, "roles", str(props, "roles"))
	setList(attrs, "scopes", str(props, "scopes"))
	setList(attrs, "wids", str(props, "wids"))

	ip := str(props, "ipAddress")
	if ip == "" {
		ip = str(rec, "callerIpAddress")
	}
	setStr(attrs, "caller_ip_address", ip)
	setStr(attrs, "location", str(rec, "location"))
	if v, ok := props["isReplay"].(bool); ok {
		attrs["is_replay"] = v
	}

	return telemetry.Event{
		Name:      eventName,
		Body:      body(props, status),
		Severity:  severity(status),
		Timestamp: eventTime(rec, props),
		Attrs:     attrs,
	}, true
}

// severity maps the HTTP status of the Graph call.
//
// It deliberately ignores the record's own `level` field: that is
// "Informational" on EVERY record, including the 500s (verified across a
// 335-record sample spanning 200/201/204/400/401/403/404/500). Trusting it would
// mark every server error INFO, permanently. This is also why a shared
// severity mapper across blob categories would be wrong — SignInLogs encodes
// level as a numeric string ("4") instead.
func severity(status int) telemetry.Severity {
	switch {
	case status >= 500:
		return telemetry.SeverityError
	case status >= 400:
		return telemetry.SeverityWarn
	default:
		return telemetry.SeverityInfo
	}
}

// eventTime resolves the record's event time, preferring the top-level `time`
// and falling back to properties.timeGenerated, which carries the same instant.
// A zero timestamp would make the emitter stamp the record at ingest time,
// silently misplacing it — and these records are routinely backfilled hours
// late, so that is not a hypothetical.
func eventTime(rec, props map[string]any) time.Time {
	for _, raw := range []string{str(rec, "time"), str(props, "timeGenerated")} {
		if raw == "" {
			continue
		}
		if t, err := time.Parse(time.RFC3339Nano, raw); err == nil {
			return t
		}
	}
	return time.Time{}
}

// body builds a short human-readable summary: the method, the request path
// (without the host or query string, which live in the request_uri attribute),
// the status, and how long it took.
func body(props map[string]any, status int) string {
	method := str(props, "requestMethod")
	if method == "" {
		method = "?"
	}
	path := str(props, "requestUri")
	if u, err := url.Parse(path); err == nil && u.Path != "" {
		path = u.Path
	}
	ms, _ := intOf(props, "durationMs")
	return fmt.Sprintf("%s %s -> %d (%dms)", method, path, status, ms)
}

// --- small defensive accessors for untyped JSON ---

func str(m map[string]any, key string) string {
	s, _ := m[key].(string)
	return s
}

func nested(m map[string]any, key string) map[string]any {
	n, _ := m[key].(map[string]any)
	return n
}

// intOf reads a JSON number (which decodes as float64) as an int.
func intOf(m map[string]any, key string) (int, bool) {
	f, ok := m[key].(float64)
	if !ok {
		return 0, false
	}
	return int(f), true
}

// setStr adds key=val only when val is non-empty, so absent fields don't emit
// empty attributes.
func setStr(attrs telemetry.Attrs, key, val string) {
	if val != "" {
		attrs[key] = val
	}
}

// setList splits a space-separated field into a list attribute, omitting it
// entirely when empty (scopes is empty on every app-only call).
func setList(attrs telemetry.Attrs, key, val string) {
	if parts := strings.Fields(val); len(parts) > 0 {
		attrs[key] = parts
	}
}

func init() {
	collectors.RegisterBlob(newCollector)
}

// Compile-time check that the collector satisfies the interface the scheduler
// type-switches on. Failing this would make it silently never run.
var _ = func() collector.SnapshotCollector {
	return newCollector(collectors.BlobDeps{})
}
