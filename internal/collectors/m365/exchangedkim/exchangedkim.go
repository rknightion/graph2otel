// Package exchangedkim is the Exchange Online DKIM signing-posture collector
// (#250): for every accepted domain, is outbound DKIM signing turned on and is
// its selector configuration currently valid.
//
// # Why this is not a Graph collector
//
// There is no Graph endpoint for a tenant's DKIM signing configuration. The
// only source is the Exchange Online admin API's app-only PowerShell transport
// (internal/exoclient) — the Get-DkimSigningConfig cmdlet — which is why this
// package rides the EXO registration path (collectors.EXODeps), alongside
// defender.quarantine. Its access is the same two grants that path always
// needs: the Exchange.ManageAsApp app role (authentication) plus an Entra
// directory role, Security Reader being the least-privileged sufficient one
// (authorization). Live-verified 200 as graph2otel-poller under Security Reader,
// 2026-07-23, returning real data for both accepted domains.
//
// # Both sides of the cardinality boundary, from one cmdlet
//
// Per cycle, from a single Get-DkimSigningConfig call:
//
//   - a bounded GAUGE, m365.exchange.dkim.signing, counting accepted domains by
//     the enabled x status tuple. Both dimensions are small Microsoft-controlled
//     enums (a bool, and a Valid/… status), so the series count is fixed by
//     Microsoft's vocabulary and never grows with the number of accepted domains;
//   - one LOG TWIN per domain, m365.exchange_dkim_config, carrying everything the
//     gauge collapses away: the domain name, both selectors' key sizes and CNAME
//     targets, the signing algorithm, the header/body canonicalization, and the
//     rotation/creation/last-checked timestamps.
//
// The twin is not garnish. "Not a metric label" means "log twin", never
// "dropped" (#114): a collector that counts how many domains sign but cannot say
// WHICH domain is broken answers the wrong question. The domain name in
// particular is per-entity data and so is log-only, never a metric label.
//
// # The Warn rule
//
// A twin is emitted at WARN when Enabled==true but Status != "Valid": DKIM
// signing is switched on for the domain yet its selector configuration is not
// valid, so mail is going out unsigned or with a failing selector — the
// actionable case. Everything else is INFO: a domain with signing simply
// disabled is a posture fact, not an alert.
//
// # A STATE feed, not an event stream
//
// Each domain's config is re-emitted every cycle for as long as it stays
// configured, which is what makes "was DKIM valid at 14:00" answerable. Log
// records are therefore stamped at POLL time (Timestamp left zero) rather than
// with any wire timestamp; the wire times (key creation, last checked, rotation)
// are preserved as attributes instead. Same shape as defender.quarantine and
// entra/risk.
//
// # Wire-over-docs
//
// Every field mapped here is present on the verbatim live sample captured from
// m7kni on 2026-07-23 (internal fixture liveRecord). The "<Field>@data.type" /
// "<Field>@odata.type" sidecar keys the adminapi decorates the wire with are
// ignored by reading each field by its exact name (the str/SetNum helpers).
package exchangedkim

import (
	"context"
	"fmt"
	"strconv"
	"time"

	"github.com/rknightion/graph2otel/internal/collector"
	"github.com/rknightion/graph2otel/internal/collectors"
	"github.com/rknightion/graph2otel/internal/semconv"
	"github.com/rknightion/graph2otel/internal/telemetry"
)

const (
	// collectorName is the stable key used for config (enable/interval),
	// self-observability, and the admin status page.
	collectorName = "m365.exchange_dkim"
	// eventName is the OTLP LogRecord EventName every per-domain twin carries.
	eventName = "m365.exchange_dkim_config"
	// metricSigning counts accepted domains by the bounded enabled x status
	// tuple. Named for what it counts: the tenant's outbound DKIM signing posture,
	// one series per (enabled, status) combination.
	metricSigning = "m365.exchange.dkim.signing"
	// unitDomain is the annotation unit for the gauge: it counts accepted domains.
	unitDomain = "{domain}"
	// cmdlet is the Exchange Online cmdlet this collector runs. It takes no
	// parameters and returns one record per accepted domain.
	cmdlet = "Get-DkimSigningConfig"
	// statusValid is the only Status value that means the signing configuration is
	// healthy. Any other value while Enabled is true is the actionable Warn case.
	statusValid = "Valid"
	// interval: a domain's DKIM signing configuration changes on the timescale of
	// admin action and scheduled key rotation, not seconds. Hourly is ample and
	// trivially cheap against the undocumented adminapi throttling ceiling.
	interval = time.Hour
)

// Collector polls Exchange Online for every accepted domain's DKIM signing
// configuration.
type Collector struct {
	c collectors.EXOClient
}

// New builds the DKIM signing-posture collector.
func New(d collectors.EXODeps) *Collector {
	return &Collector{c: d.Client}
}

// Name implements collector.Collector.
func (c *Collector) Name() string { return collectorName }

// DefaultInterval implements collector.Collector.
func (c *Collector) DefaultInterval() time.Duration { return interval }

// IngestTransport marks every record this collector emits as having come from
// the Exchange Online admin API rather than Graph (#141). It is stamped here
// because there is no ingest engine on this path — the same position
// defender.quarantine and mdca.discovery_parse are in.
func (c *Collector) IngestTransport() telemetry.Transport {
	return telemetry.TransportExchangeOnline
}

// RequiredPermissions is empty because this collector needs no GRAPH scope, and
// the declaration surface models Graph scopes. Its access is two grants that
// live outside that vocabulary and cannot be requested by consent alone (see the
// package doc and defender.quarantine): the Exchange.ManageAsApp app role, plus
// an Entra directory role (Security Reader suffices). Both are read-only.
func (c *Collector) RequiredPermissions() []string { return nil }

// gaugeKey is the bounded label tuple the signing gauge is counted by.
type gaugeKey struct {
	enabled string
	status  string
}

// Collect runs the cmdlet once and emits both sides of the cardinality
// boundary: the bounded gauge, and one log twin per accepted domain.
//
// GaugeSnapshot (not Gauge) is used deliberately: it is an observable
// instrument, so an (enabled, status) combination that no longer appears on a
// later tick drops out of the export instead of ghosting forever under Grafana
// Cloud's forced cumulative temporality. An empty result (a tenant with no
// accepted domains) emits NO series at all rather than a zero.
func (c *Collector) Collect(ctx context.Context, e telemetry.Emitter) error {
	// Stamp the transport HERE, not just in IngestTransport(). There is no ingest
	// engine on this path to do it, and the Scheduler's baseline is
	// telemetry.TransportGraph — so without this wrapper every record from the
	// Exchange Online admin API would claim to be a Graph poll. Same position, and
	// the same fix, as defender.quarantine.
	e = telemetry.WithTransport(e, telemetry.TransportExchangeOnline)

	recs, err := c.c.Invoke(ctx, cmdlet, nil)
	if err != nil {
		return fmt.Errorf("%s: %w", cmdlet, err)
	}

	counts := map[gaugeKey]int64{}
	for _, r := range recs {
		counts[gaugeKey{
			enabled: strconv.FormatBool(boolVal(r, "Enabled")),
			status:  str(r, "Status"),
		}]++
		e.LogEvent(logTwin(r))
	}

	points := make([]telemetry.GaugePoint, 0, len(counts))
	for k, v := range counts {
		points = append(points, telemetry.GaugePoint{
			Value: float64(v),
			Attrs: telemetry.Attrs{
				semconv.AttrEnabled: k.enabled,
				semconv.AttrStatus:  k.status,
			},
		})
	}
	e.GaugeSnapshot(metricSigning, unitDomain,
		"Accepted domains counted by outbound DKIM signing enablement and configuration status.",
		points)
	return nil
}

// dkimStrFields maps the row's string columns to their attribute keys. Every one
// is present on the live sample; each is per-domain detail the bounded gauge
// cannot carry.
var dkimStrFields = []struct{ attr, src string }{
	{semconv.AttrDomain, "Domain"},
	{semconv.AttrStatus, "Status"},
	{semconv.AttrAlgorithm, "Algorithm"},
	{semconv.AttrSelector1Cname, "Selector1CNAME"},
	{semconv.AttrSelector2Cname, "Selector2CNAME"},
	{semconv.AttrHeaderCanonicalization, "HeaderCanonicalization"},
	{semconv.AttrBodyCanonicalization, "BodyCanonicalization"},
	{semconv.AttrRotateOnDate, "RotateOnDate"},
	{semconv.AttrKeyCreationTime, "KeyCreationTime"},
	{semconv.AttrLastChecked, "LastChecked"},
}

// dkimNumFields maps the row's numeric columns (selector key sizes arrive as
// JSON numbers, decoded to float64).
var dkimNumFields = []struct{ attr, src string }{
	{semconv.AttrSelector1KeySize, "Selector1KeySize"},
	{semconv.AttrSelector2KeySize, "Selector2KeySize"},
}

// dkimBoolFields maps the row's boolean columns. They are emitted even when
// false: false is an ANSWER here — enabled=false is precisely the posture fact
// an operator filters for, and is_valid=false is the broken case.
var dkimBoolFields = []struct{ attr, src string }{
	{semconv.AttrEnabled, "Enabled"},
	{semconv.AttrIsDefault, "IsDefault"},
	{semconv.AttrIsValid, "IsValid"},
}

// logTwin renders one accepted domain's DKIM configuration as an OTLP log
// record. Timestamp is left zero (poll time) — see the package doc on why a
// state feed must not stamp its source time; the wire times are preserved as
// attributes. Severity is Warn when signing is enabled but the configuration is
// not valid.
func logTwin(r map[string]any) telemetry.Event {
	attrs := telemetry.Attrs{}
	for _, f := range dkimStrFields {
		telemetry.SetStr(attrs, f.attr, str(r, f.src))
	}
	for _, f := range dkimNumFields {
		telemetry.SetNum(attrs, f.attr, r, f.src)
	}
	for _, f := range dkimBoolFields {
		if b, ok := r[f.src].(bool); ok {
			telemetry.SetBool(attrs, f.attr, b)
		}
	}

	enabled := boolVal(r, "Enabled")
	status := str(r, "Status")
	sev := telemetry.SeverityInfo
	if enabled && status != statusValid {
		// Signing is on but the selector configuration is not valid: mail is going
		// out unsigned or with a failing selector. This is the one actionable state.
		sev = telemetry.SeverityWarn
	}

	return telemetry.Event{
		Name:     eventName,
		Body:     body(r, enabled, status),
		Severity: sev,
		Attrs:    attrs,
	}
}

// body builds a short human-readable summary line for one domain's DKIM state.
func body(r map[string]any, enabled bool, status string) string {
	domain := str(r, "Domain")
	if domain == "" {
		domain = "unknown domain"
	}
	if !enabled {
		return fmt.Sprintf("DKIM signing disabled for %s (status %s)", domain, status)
	}
	return fmt.Sprintf("DKIM signing enabled for %s: status %s", domain, status)
}

// boolVal reads a boolean column, false when absent or non-bool.
func boolVal(m map[string]any, key string) bool {
	b, _ := m[key].(bool)
	return b
}

// str reads a string column, "" when absent or non-string. The adminapi
// decorates several columns with sidecar "<Name>@data.type" / "<Name>@odata.type"
// keys; reading by exact name ignores them.
func str(m map[string]any, key string) string {
	s, _ := m[key].(string)
	return s
}

func init() {
	collectors.RegisterEXO(func(d collectors.EXODeps) collector.SnapshotCollector { return New(d) })
}

var _ collector.SnapshotCollector = (*Collector)(nil)
