// Package graphnotifications is the GraphNotificationsActivityLogs source: one
// OTLP log record per Microsoft Graph change-notification publish event, read
// from Azure Storage rather than from Graph (#134).
//
// Graph change notifications are the webhook/event-hub delivery mechanism a
// subscription owner registers to be told when a resource changes. This category
// is the delivery telemetry for that mechanism: which app owns the subscription,
// which workload it targets, where the notification was published, and whether
// the publish succeeded. Graph exposes no endpoint for this — it exists only as
// Azure Monitor diagnostic-settings output.
//
// What it answers, which nothing else does: which application is receiving a
// live stream of directory-change notifications, and to where. A change
// notification subscription is a persistence / supply-chain foothold — an
// attacker who registers one gets a durable, low-noise feed of tenant activity —
// so `applicationId` (the subscription owner) is the load-bearing attribute here.
//
// Cardinality (INVERTED from the metric collectors, as for every log source):
// per-entity detail — the owning app id, subscription id, correlation/context
// ids — belongs here as structured log attributes, never as a metric label. This
// package emits no metrics.
package graphnotifications

import (
	"fmt"
	"time"

	"github.com/rknightion/graph2otel/internal/blobpipeline"
	"github.com/rknightion/graph2otel/internal/collector"
	"github.com/rknightion/graph2otel/internal/collectors"
	"github.com/rknightion/graph2otel/internal/semconv"
	"github.com/rknightion/graph2otel/internal/telemetry"
)

const (
	// collectorName is the stable config/self-obs key.
	collectorName = "entra.graph_notifications"
	// container is where Azure Monitor writes this category: the fixed
	// "insights-logs-" prefix plus the diagnostic-settings category name,
	// lowercased.
	container = "insights-logs-graphnotificationsactivitylogs"
	// eventName is the OTLP LogRecord EventName every record carries.
	eventName = "entra.graph_notifications"
	// interval is how often the container is re-listed. Records land minutes
	// behind the event; polling faster buys nothing but list operations.
	interval = 5 * time.Minute
)

// blobPrefix returns the listing prefix for a tenant's records.
//
// This is "tenantId=<guid>/" and NOT the documented resourceId=/tenants/... form
// — verified live across every insights-logs container this project consumes
// (#89 established the pattern; confirmed again for this category 2026-07-17).
// Coding to the docs produces a collector that lists zero blobs and reports
// success forever.
func blobPrefix(tenantID string) string {
	return "tenantId=" + tenantID + "/"
}

// blobCollector wraps the generic BlobCollector so collectordoc recovers THIS
// package by reflection: a bare *blobpipeline.BlobCollector resolves to the
// blobpipeline package that DEFINES the type, not the one whose factory built
// it. Wrapping (as entra/signins and the defender collectors do) is the
// codebase's preferred fix over a directBlobPackages entry.
type blobCollector struct {
	*blobpipeline.BlobCollector
}

// newCollector builds the GraphNotificationsActivityLogs blob collector for a
// tenant. It is NOT experimental — it registers whenever blob ingest is
// configured.
func newCollector(d collectors.BlobDeps) collector.SnapshotCollector {
	cfg := blobpipeline.ContainerConfig{
		Container:     container,
		Prefix:        blobPrefix(d.TenantID),
		Map:           mapRecord,
		CollectorName: collectorName,
	}
	return blobCollector{blobpipeline.NewBlobCollector(collectorName, interval, d.TenantID, cfg, d.Source, d.Store, d.Logger)}
}

// mapRecord turns one raw GraphNotificationsActivityLogs record into its OTLP log
// Event. It returns false for a record with no properties object, and for a
// record whose event time will not parse — a zero timestamp would make the
// emitter stamp the record at ingest time, silently misplacing a backfilled
// event. blobpipeline still consumes the bytes so a rejected record never stalls
// the cursor.
//
// Every field read here was verified against a live sample captured as
// graph2otel-poller (2026-07-17, #134); nothing below is inferred from docs.
func mapRecord(rec map[string]any) (telemetry.Event, bool) {
	props := nested(rec, "properties")
	if props == nil {
		return telemetry.Event{}, false
	}

	ts := eventTime(rec, props)
	if ts.IsZero() {
		return telemetry.Event{}, false
	}

	// resultStatusCode is an int in properties; the record's own `level` field is
	// "Informational" on everything (same trap as MGAL), so severity is derived
	// from the status code, never from level.
	status, _ := intOf(props, "resultStatusCode")

	attrs := telemetry.Attrs{}
	attrs[semconv.AttrResultStatusCode] = status

	// applicationId is the app that OWNS the change-notification subscription —
	// the persistence / supply-chain signal — so it is the load-bearing id here.
	telemetry.SetStr(attrs, semconv.AttrApplicationId, str(props, "applicationId"))
	telemetry.SetStr(attrs, semconv.AttrSubscriptionId, str(props, "subscriptionId"))
	telemetry.SetStr(attrs, semconv.AttrWorkloadNamespace, str(props, "workloadNamespace"))
	telemetry.SetStr(attrs, semconv.AttrOperationType, str(props, "operationType"))
	telemetry.SetStr(attrs, semconv.AttrCorrelationId, str(props, "correlationId"))
	telemetry.SetStr(attrs, semconv.AttrContextId, str(props, "contextId"))
	telemetry.SetStr(attrs, semconv.AttrResultDescription, str(props, "resultDescription"))
	telemetry.SetStr(attrs, semconv.AttrAccountType, str(props, "accountType"))

	location := str(props, "location")
	if location == "" {
		location = str(rec, "location")
	}
	telemetry.SetStr(attrs, semconv.AttrLocation, location)

	if v, ok := intOf(props, "durationMs"); ok {
		attrs[semconv.AttrDurationMs] = v
	}
	if v, ok := props["isReplay"].(bool); ok {
		attrs[semconv.AttrIsReplay] = v
	}

	return telemetry.Event{
		Name:      eventName,
		Body:      body(props),
		Severity:  severity(status),
		Timestamp: ts,
		Attrs:     attrs,
	}, true
}

// severity maps the publish result status.
//
// It deliberately ignores the record's own `level` field, which is
// "Informational" on every record (verified live), including any that carry a
// 4xx/5xx resultStatusCode. Trusting it would mark every failed publish INFO.
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

// eventTime resolves the record's event time, preferring properties.timeGenerated
// (RFC3339Nano) and falling back to the top-level `time`, which carries the same
// instant (byte-identical in the live sample). Returns the zero time when neither
// parses, which mapRecord turns into a drop.
func eventTime(rec, props map[string]any) time.Time {
	for _, raw := range []string{str(props, "timeGenerated"), str(rec, "time")} {
		if raw == "" {
			continue
		}
		if t, err := time.Parse(time.RFC3339Nano, raw); err == nil {
			return t
		}
	}
	return time.Time{}
}

// body builds a short human-readable summary. The verbose free-text `message`
// field lives in neither the body nor an attribute of its own — the operation
// type and the result description together say what happened without the noise.
func body(props map[string]any) string {
	op := str(props, "operationType")
	if op == "" {
		op = "?"
	}
	desc := str(props, "resultDescription")
	return fmt.Sprintf("%s: %s", op, desc)
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

func init() {
	collectors.RegisterBlob(newCollector)
}

// Compile-time check that the collector satisfies the interface the scheduler
// type-switches on. Failing this would make it silently never run.
var _ collector.SnapshotCollector = blobCollector{}
