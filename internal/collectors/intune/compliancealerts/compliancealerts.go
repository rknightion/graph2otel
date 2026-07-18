// Package compliancealerts is the Intune OperationalLogs blob collector
// (#94/#135 group A): one OTLP log record per compliance fired-event, read from
// Azure Storage rather than from Graph.
//
// OperationalLogs is the Azure Monitor diagnostic category Intune writes when a
// managed device changes compliance state — the "Managed Device X is not
// Compliant" alerts an operator actually cares about. Each record names the
// device, its owner, and which compliance rule fired, so it is a device-health
// SIEM signal, not a metric: per-entity detail (device name/host, UPN suffix,
// the failing setting in Description) belongs here as structured log attributes
// and never as a metric label.
//
// Every field mapped below was verified against a live sample captured
// 2026-07-17 as graph2otel-poller — nothing here is inferred from documentation.
package compliancealerts

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
	collectorName = "intune.compliance_alerts"
	// container is where Azure Monitor writes this category: the fixed
	// "insights-logs-" prefix plus the diagnostic-settings category name,
	// lowercased.
	container = "insights-logs-operationallogs"
	// eventName is the OTLP LogRecord EventName every record carries.
	eventName = "intune.compliance_alert"
	// interval is how often the container is re-listed.
	interval = 5 * time.Minute
)

// blobPrefix returns the listing prefix for a tenant's records.
//
// This is "tenantId=<guid>/" — verified live: every insights-logs- container on
// this tenant uses the tenantId= form, NOT the documented
// "resourceId=/tenants/<guid>/providers/..." (subscription-scoped) form, which
// lists zero blobs and reports success forever.
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

// newCollector builds the OperationalLogs (Intune compliance alerts) blob
// collector for a tenant.
func newCollector(d collectors.BlobDeps) collector.SnapshotCollector {
	cfg := blobpipeline.ContainerConfig{
		Container:     container,
		Prefix:        blobPrefix(d.TenantID),
		Map:           mapRecord,
		CollectorName: collectorName,
	}
	return blobCollector{blobpipeline.NewBlobCollector(collectorName, interval, d.TenantID, cfg, d.Source, d.Store, d.Logger)}
}

// mapRecord turns one raw OperationalLogs record into its OTLP log Event. It
// returns false for a record with no properties object, or one whose event time
// cannot be resolved — the emitter would otherwise stamp it at ingest time,
// silently claiming a compliance alert happened now. blobpipeline still consumes
// the bytes, so a rejected record never stalls the cursor.
func mapRecord(rec map[string]any) (telemetry.Event, bool) {
	props := nested(rec, "properties")
	if props == nil {
		return telemetry.Event{}, false
	}
	ts, ok := eventTime(rec, props)
	if !ok {
		return telemetry.Event{}, false
	}

	attrs := telemetry.Attrs{}
	telemetry.SetStr(attrs, semconv.AttrIntuneAccountId, str(props, "IntuneAccountId"))
	telemetry.SetStr(attrs, semconv.AttrAlertDisplayName, str(props, "AlertDisplayName"))
	telemetry.SetStr(attrs, semconv.AttrAlertType, str(props, "AlertType"))
	telemetry.SetStr(attrs, semconv.AttrDescription, str(props, "Description"))
	telemetry.SetStr(attrs, semconv.AttrDeviceDnsDomain, str(props, "DeviceDnsDomain"))
	telemetry.SetStr(attrs, semconv.AttrDeviceHostName, str(props, "DeviceHostName"))
	telemetry.SetStr(attrs, semconv.AttrDeviceId, str(props, "IntuneDeviceId"))
	telemetry.SetStr(attrs, semconv.AttrDeviceName, str(props, "DeviceName"))
	telemetry.SetStr(attrs, semconv.AttrDeviceNetBiosName, str(props, "DeviceNetBiosName"))
	telemetry.SetStr(attrs, semconv.AttrOperatingSystem, str(props, "DeviceOperatingSystem"))
	telemetry.SetStr(attrs, semconv.AttrScaleUnit, str(props, "ScaleUnit"))
	telemetry.SetStr(attrs, semconv.AttrScenarioName, str(props, "ScenarioName"))
	telemetry.SetStr(attrs, semconv.AttrUserName, str(props, "UserName"))
	telemetry.SetStr(attrs, semconv.AttrUpnSuffix, str(props, "UPNSuffix"))
	telemetry.SetStr(attrs, semconv.AttrUserDisplayName, str(props, "UserDisplayName"))
	telemetry.SetStr(attrs, semconv.AttrIntuneUserId, str(props, "IntuneUserId"))
	telemetry.SetStr(attrs, semconv.AttrOperationalLogCategory, str(props, "OperationalLogCategory"))

	return telemetry.Event{
		Name: eventName,
		Body: body(props),
		// A compliance alert means a device fell OUT of compliance: an operator
		// signal, not INFO.
		Severity:  telemetry.SeverityWarn,
		Timestamp: ts,
		Attrs:     attrs,
	}, true
}

// eventTime resolves the record's event time, binding to
// properties.StartTimeUtc and falling back to the top-level `time` (byte-identical
// on the live sample). If NEITHER parses it returns ok=false so the record is
// dropped rather than stamped at ingest time.
func eventTime(rec, props map[string]any) (time.Time, bool) {
	for _, raw := range []string{str(props, "StartTimeUtc"), str(rec, "time")} {
		if raw == "" {
			continue
		}
		if t, err := time.Parse(time.RFC3339Nano, raw); err == nil {
			return t, true
		}
	}
	return time.Time{}, false
}

// body builds a short human-readable summary: the alert type, the device it
// fired on, and the failing-rule Description.
func body(props map[string]any) string {
	return fmt.Sprintf("%s: %s - %s",
		str(props, "AlertType"), str(props, "DeviceName"), str(props, "Description"))
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

func init() {
	collectors.RegisterBlob(newCollector)
}

// Compile-time check that the collector satisfies the interface the scheduler
// type-switches on. Failing this would make it silently never run.
var _ collector.SnapshotCollector = blobCollector{}
