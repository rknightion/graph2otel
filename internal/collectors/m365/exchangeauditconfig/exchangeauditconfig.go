// Package exchangeauditconfig is the Exchange Online admin-audit-log
// configuration collector (#250): whether the tenant's unified audit log is
// ingesting, and the admin-audit-log settings, read over the Exchange Online
// admin API's app-only cmdlet transport (internal/exoclient).
//
// # Why this matters — the #99 correction
//
// #99 recorded that turning on the unified audit log is "outside every API
// surface graph2otel touches". Since #233 that is no longer true for the READ
// half: Get-AdminAuditLogConfig runs on the transport graph2otel now owns, and it
// carries UnifiedAuditLogIngestionEnabled. This is load-bearing: when the unified
// audit log is OFF, m365.activity and m365.unified_audit silently return nothing,
// and that is indistinguishable from a quiet tenant. graph2otel still cannot and
// should not SET it, but it can now report that it is off — which is the whole
// point of this collector, and the Warn condition below.
//
// # Both sides of the cardinality boundary, from one cmdlet
//
// Get-AdminAuditLogConfig returns a single config object. From it:
//
//   - bounded GAUGE m365.exchange.audit_config.enabled{setting} — a 0/1 posture
//     value per audit setting (unified_audit_log_ingestion, admin_audit_log). The
//     series count is fixed at the number of settings, never grows;
//   - one LOG twin m365.exchange_audit_config carrying the full config (log level,
//     age limit, first opt-in date, test-cmdlet logging) the gauge collapses.
//
// A state snapshot, not an event stream: the twin is stamped at poll time.
package exchangeauditconfig

import (
	"context"
	"fmt"
	"time"

	"github.com/rknightion/graph2otel/internal/collector"
	"github.com/rknightion/graph2otel/internal/collectors"
	"github.com/rknightion/graph2otel/internal/semconv"
	"github.com/rknightion/graph2otel/internal/telemetry"
)

const (
	// collectorName is the stable key for config, self-observability and the
	// admin status page.
	collectorName = "m365.exchange_audit_config"
	// eventName is the OTLP LogRecord EventName the config twin carries.
	eventName = "m365.exchange_audit_config"
	// metricEnabled is the 0/1 posture gauge keyed by setting.
	metricEnabled = "m365.exchange.audit_config.enabled"
	// cmdlet is the single Exchange Online cmdlet this collector runs.
	cmdlet = "Get-AdminAuditLogConfig"
	// unitSetting is the annotation unit for a bounded 0/1 posture flag.
	unitSetting = "{setting}"
	// interval: audit configuration changes on the timescale of an admin editing
	// it. Hourly is ample and one cmdlet call is cheap.
	interval = time.Hour
)

// The two posture settings the gauge reports, and their wire fields.
const (
	settingUnifiedAudit = "unified_audit_log_ingestion"
	settingAdminAudit   = "admin_audit_log"
	fieldUnifiedAudit   = "UnifiedAuditLogIngestionEnabled"
	fieldAdminAudit     = "AdminAuditLogEnabled"
)

// Collector reads the Exchange Online admin-audit-log configuration.
type Collector struct {
	c collectors.EXOClient
}

// New builds the audit-config collector.
func New(d collectors.EXODeps) *Collector { return &Collector{c: d.Client} }

// Name implements collector.Collector.
func (c *Collector) Name() string { return collectorName }

// DefaultInterval implements collector.Collector.
func (c *Collector) DefaultInterval() time.Duration { return interval }

// IngestTransport marks every record as coming from the Exchange Online admin
// API rather than Graph (#141) — the same position as defender.quarantine, since
// there is no ingest engine on this path.
func (c *Collector) IngestTransport() telemetry.Transport {
	return telemetry.TransportExchangeOnline
}

// RequiredPermissions is empty: access is the two grants outside the Graph-scope
// vocabulary (Exchange.ManageAsApp + Security Reader), the same as
// defender.quarantine. Get-AdminAuditLogConfig is authorized at Security Reader
// (live-measured 2026-07-23), unlike Get-OrganizationConfig.
func (c *Collector) RequiredPermissions() []string { return nil }

// Collect runs the cmdlet and emits the posture gauge plus the config twin.
func (c *Collector) Collect(ctx context.Context, e telemetry.Emitter) error {
	// Stamp the transport HERE: there is no ingest engine on this path, and the
	// Scheduler baseline is TransportGraph, so without this every record would
	// claim to be a Graph poll. Same fix as defender.quarantine.
	e = telemetry.WithTransport(e, telemetry.TransportExchangeOnline)

	recs, err := c.c.Invoke(ctx, cmdlet, nil)
	if err != nil {
		return fmt.Errorf("%s: %w", cmdlet, err)
	}
	if len(recs) == 0 {
		// No config object returned — nothing to emit rather than a misleading zero.
		return nil
	}
	r := recs[0]

	unifiedOn := boolVal(r, fieldUnifiedAudit)
	adminOn := boolVal(r, fieldAdminAudit)

	e.GaugeSnapshot(metricEnabled, unitSetting,
		"Exchange Online audit posture as a 0/1 flag per setting: unified_audit_log_ingestion (when off, m365.activity and m365.unified_audit silently return nothing) and admin_audit_log.",
		[]telemetry.GaugePoint{
			{Value: b2f(unifiedOn), Attrs: telemetry.Attrs{semconv.AttrSetting: settingUnifiedAudit}},
			{Value: b2f(adminOn), Attrs: telemetry.Attrs{semconv.AttrSetting: settingAdminAudit}},
		})

	e.LogEvent(configTwin(r, unifiedOn, adminOn))
	return nil
}

// configTwin renders the config object as a log record. Warn when unified audit
// log ingestion is OFF — the case that makes the M365 audit collectors silently
// empty; everything else is Info.
func configTwin(r map[string]any, unifiedOn, adminOn bool) telemetry.Event {
	attrs := telemetry.Attrs{}
	telemetry.SetBool(attrs, semconv.AttrUnifiedAuditLogIngestionEnabled, unifiedOn)
	telemetry.SetBool(attrs, semconv.AttrAdminAuditLogEnabled, adminOn)
	telemetry.SetBool(attrs, semconv.AttrTestCmdletLoggingEnabled, boolVal(r, "TestCmdletLoggingEnabled"))
	telemetry.SetStr(attrs, semconv.AttrLogLevel, str(r, "LogLevel"))
	telemetry.SetStr(attrs, semconv.AttrAdminAuditLogAgeLimit, str(r, "AdminAuditLogAgeLimit"))
	telemetry.SetStr(attrs, semconv.AttrUnifiedAuditLogFirstOptInDate, str(r, "UnifiedAuditLogFirstOptInDate"))

	sev := telemetry.SeverityInfo
	if !unifiedOn {
		sev = telemetry.SeverityWarn
	}
	return telemetry.Event{
		Name:     eventName,
		Body:     fmt.Sprintf("exchange audit config: unified_audit_log_ingestion=%t admin_audit_log=%t", unifiedOn, adminOn),
		Severity: sev,
		Attrs:    attrs,
	}
}

// b2f is 1 for true, 0 for false — the 0/1 posture gauge value.
func b2f(b bool) float64 {
	if b {
		return 1
	}
	return 0
}

// boolVal reads a boolean column, false when absent or non-bool.
func boolVal(m map[string]any, key string) bool {
	b, _ := m[key].(bool)
	return b
}

// str reads a string column, "" when absent or non-string. The API decorates
// several columns with "<Name>@data.type" sidecar keys; reading by exact name
// ignores them.
func str(m map[string]any, key string) string {
	s, _ := m[key].(string)
	return s
}

func init() {
	collectors.RegisterEXO(func(d collectors.EXODeps) collector.SnapshotCollector { return New(d) })
}

var _ collector.SnapshotCollector = (*Collector)(nil)
