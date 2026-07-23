// Package mdopolicies is the Microsoft Defender for Office 365 policy-posture
// collector (#250): which anti-spam, anti-malware, anti-phish, Safe Links, Safe
// Attachments, ATP and Teams-protection policies exist, and how each one is
// configured.
//
// # Why this is not a Graph collector
//
// Defender for Office 365 policy configuration has no Graph surface. The only way
// to read a HostedContentFilterPolicy, an AntiPhishPolicy or a SafeLinksPolicy is
// the Exchange Online admin API's app-only PowerShell transport
// (internal/exoclient), which is why this package sits on the EXO registration
// path (collectors.EXODeps) alongside defender.quarantine. Each of the seven
// Get-*Policy cmdlets returns a flat array of policy objects, one Invoke per
// cmdlet.
//
// # Both sides of the cardinality boundary, from seven fetches
//
// Per cycle, one Invoke per cmdlet (all seven live-verified 200 as
// graph2otel-poller under Security Reader, 2026-07-23):
//
//   - bounded GAUGES: a count of policies per policy_type, and a count of
//     policies where a named boolean protection (zap, spam_zap, safe_links_email,
//     ...) is enabled, keyed by policy_type x protection. Both dimensions are a
//     small closed set fixed by Microsoft's policy model, so neither grows with
//     tenant size.
//   - one LOG twin per policy carrying the per-policy verdict/action detail the
//     gauges collapse — the actions, thresholds and toggles an operator reads to
//     decide whether a policy is actually protecting anything.
//
// The twin is not garnish. "Not a metric label" means "log twin", never "dropped"
// (#114): a collector that counts policies but cannot say WHICH one has ZAP off,
// or which one quarantines vs merely junks spam, answers the wrong question. The
// posture booleans are emitted even when false, because zap_enabled=false — ZAP
// switched off on a policy that supports it — is precisely the case to filter for.
//
// # A STATE feed, not an event stream
//
// A policy is re-emitted every cycle for as long as it exists, so log records are
// stamped at POLL time (Timestamp left zero) rather than with a WhenChanged wire
// time, which would pile every repeat onto the policy's last-edit instant. Same
// shape as defender.quarantine and entra/securescore.
//
// # Wire, not docs
//
// Every field mapped here was read off a VERBATIM live capture of the m7kni
// tenant (testdata/*.json, 2026-07-23). Fields Microsoft documents but that were
// not on the wire are deliberately not decoded (#142). Where a policy type omits
// a field (an ATP or Teams policy has no RecommendedPolicyType on the wire), the
// SetStr/SetNum/SetBool helpers omit the attribute rather than emit a blank one,
// so one twin builder serves all seven shapes by attempting every mapped field.
package mdopolicies

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/rknightion/graph2otel/internal/collector"
	"github.com/rknightion/graph2otel/internal/collectors"
	"github.com/rknightion/graph2otel/internal/semconv"
	"github.com/rknightion/graph2otel/internal/telemetry"
)

const (
	// collectorName is the stable key used for config (enable/interval),
	// self-observability, and the admin status page.
	collectorName = "defender.mdo_policies"
	// eventName is the OTLP LogRecord EventName every per-policy twin carries.
	eventName = "defender.mdo_policy"
	// metricPolicies counts policies by policy_type.
	metricPolicies = "defender.mdo.policies"
	// metricProtection counts policies with a named boolean protection enabled,
	// by policy_type and protection.
	metricProtection = "defender.mdo.protection_enabled"
	// unitPolicy is the annotation count unit for both gauges. An annotation unit
	// ({thing}) is a count and needs no internal/semconv/additive.go entry.
	unitPolicy = "{policy}"
	// interval: MDO policy configuration changes on the timescale of admin action,
	// not seconds, and each tick costs seven Exchange Online round trips. Hourly is
	// ample — the same cadence entra.secure_score uses for the same reason.
	interval = time.Hour
)

// protection maps a policy type's boolean toggle to the stable protection name it
// is counted under on metricProtection.
type protection struct {
	name  string // the bounded protection label, e.g. "zap"
	field string // the wire boolean field, e.g. "ZapEnabled"
}

// policyType binds one Get-*Policy cmdlet to its policy_type label and the set of
// protection toggles that exist on that shape. The protection list is closed per
// type, taken from the live wire samples — never from documentation.
type policyType struct {
	name        string
	cmdlet      string
	protections []protection
}

// policyTypes is the full set of MDO policy shapes this collector reads. Order is
// the fetch order; a failure in one is aggregated and does not stop the rest.
var policyTypes = []policyType{
	{
		name:   "hosted_content",
		cmdlet: "Get-HostedContentFilterPolicy",
		protections: []protection{
			{"zap", "ZapEnabled"},
			{"spam_zap", "SpamZapEnabled"},
			{"phish_zap", "PhishZapEnabled"},
		},
	},
	{
		name:   "malware",
		cmdlet: "Get-MalwareFilterPolicy",
		protections: []protection{
			{"file_filter", "EnableFileFilter"},
			{"zap", "ZapEnabled"},
		},
	},
	{
		name:   "anti_phish",
		cmdlet: "Get-AntiPhishPolicy",
		protections: []protection{
			{"spoof_intelligence", "EnableSpoofIntelligence"},
			{"mailbox_intelligence", "EnableMailboxIntelligence"},
		},
	},
	{
		name:   "safe_links",
		cmdlet: "Get-SafeLinksPolicy",
		protections: []protection{
			{"safe_links_email", "EnableSafeLinksForEmail"},
			{"safe_links_teams", "EnableSafeLinksForTeams"},
			{"scan_urls", "ScanUrls"},
		},
	},
	{
		name:   "safe_attachments",
		cmdlet: "Get-SafeAttachmentPolicy",
		protections: []protection{
			{"safe_attachments", "Enable"},
		},
	},
	{
		name:   "atp_o365",
		cmdlet: "Get-AtpPolicyForO365",
		protections: []protection{
			{"safe_docs", "EnableSafeDocs"},
		},
	},
	{
		name:   "teams_protection",
		cmdlet: "Get-TeamsProtectionPolicy",
		protections: []protection{
			{"zap", "ZapEnabled"},
		},
	},
}

// Collector reads Microsoft Defender for Office 365 policy configuration over the
// Exchange Online admin API.
type Collector struct {
	c      collectors.EXOClient
	logger *slog.Logger
}

// New builds the MDO policy collector. A nil logger falls back to slog.Default().
func New(d collectors.EXODeps) *Collector {
	logger := d.Logger
	if logger == nil {
		logger = slog.Default()
	}
	return &Collector{c: d.Client, logger: logger}
}

// Name implements collector.Collector.
func (c *Collector) Name() string { return collectorName }

// DefaultInterval implements collector.Collector.
func (c *Collector) DefaultInterval() time.Duration { return interval }

// IngestTransport marks every record this collector emits as having come from the
// Exchange Online admin API rather than Graph (#141). Stamped here because there
// is no ingest engine on this path — the same position defender.quarantine and
// mdca.discovery_parse are in.
func (c *Collector) IngestTransport() telemetry.Transport {
	return telemetry.TransportExchangeOnline
}

// RequiredPermissions is empty because this collector needs no GRAPH scope, and
// the declaration surface models Graph scopes. Its access is two grants that live
// outside that vocabulary and cannot be requested by consent alone:
//
//   - the app role Exchange.ManageAsApp on the Office 365 Exchange Online service
//     principal — authentication;
//   - an Entra DIRECTORY role, Security Reader being the least-privileged
//     sufficient one — authorization.
//
// Neither alone grants anything (live-measured 2026-07-23: 401 → 403 → 200 as the
// grants are added). Both are read-only. Same requirement as defender.quarantine.
func (c *Collector) RequiredPermissions() []string { return nil }

// protKey is the bounded (policy_type, protection) tuple metricProtection is
// counted by.
type protKey struct {
	policyType string
	protection string
}

// Collect fetches all seven policy shapes and emits both sides of the cardinality
// boundary: the bounded count gauges and one log twin per policy.
//
// Fetches are independent: a failure in one cmdlet is logged and surfaced as a
// non-fatal aggregated error, and the other six still emit — the securescore
// shape, not quarantine's single-cmdlet fail-fast.
//
// GaugeSnapshot (not Gauge) is used deliberately: it is an observable instrument,
// so a (policy_type, protection) combination that no longer appears on a later
// tick drops out of the export instead of ghosting forever under Grafana Cloud's
// forced cumulative temporality. Alert on a series crossing a threshold, never on
// its absence.
func (c *Collector) Collect(ctx context.Context, e telemetry.Emitter) error {
	// Stamp the transport HERE, not just in IngestTransport(). There is no ingest
	// engine on this path, and the Scheduler's baseline is telemetry.TransportGraph
	// — so without this wrapper every record from the Exchange Online admin API
	// would claim to be a Graph poll. The declared value and the stamped value name
	// one constant so the status page cannot disagree with the records.
	e = telemetry.WithTransport(e, telemetry.TransportExchangeOnline)

	policyCounts := map[string]int64{}
	protPresent := map[protKey]bool{}
	protOn := map[protKey]int64{}

	var errs []error
	for _, pt := range policyTypes {
		recs, err := c.c.Invoke(ctx, pt.cmdlet, nil)
		if err != nil {
			c.logger.Warn("mdo policy fetch failed",
				"collector", collectorName, "cmdlet", pt.cmdlet, "error", err)
			errs = append(errs, fmt.Errorf("%s: %w", pt.cmdlet, err))
			continue
		}
		for _, r := range recs {
			policyCounts[pt.name]++
			for _, p := range pt.protections {
				b, ok := r[p.field].(bool)
				if !ok {
					// The toggle is absent on this policy — skip it rather than
					// emitting a zero-valued point for a protection this type does
					// not have.
					continue
				}
				k := protKey{policyType: pt.name, protection: p.name}
				protPresent[k] = true
				if b {
					protOn[k]++
				}
			}
			e.LogEvent(policyTwin(pt.name, r))
		}
	}

	countPoints := make([]telemetry.GaugePoint, 0, len(policyCounts))
	for name, n := range policyCounts {
		countPoints = append(countPoints, telemetry.GaugePoint{
			Value: float64(n),
			Attrs: telemetry.Attrs{semconv.AttrPolicyType: name},
		})
	}
	e.GaugeSnapshot(metricPolicies, unitPolicy,
		"Microsoft Defender for Office 365 policies, by policy type.", countPoints)

	// A protection PRESENT on a type but enabled on no policy still emits a point
	// valued 0: the series is capable-but-off, which is a real, alertable posture
	// state distinct from the protection not existing on that type at all (skipped
	// above). Both dimensions are bounded, so the series count is fixed.
	protPoints := make([]telemetry.GaugePoint, 0, len(protPresent))
	for k := range protPresent {
		protPoints = append(protPoints, telemetry.GaugePoint{
			Value: float64(protOn[k]),
			Attrs: telemetry.Attrs{
				semconv.AttrPolicyType: k.policyType,
				semconv.AttrProtection: k.protection,
			},
		})
	}
	e.GaugeSnapshot(metricProtection, unitPolicy,
		"MDO policies with a named boolean protection enabled, by policy type and protection.", protPoints)

	return errors.Join(errs...)
}

// twinStrFields maps a policy's string action/name columns to their attribute
// keys. Every field is attempted against every shape; SetStr omits the ones a
// given policy type does not carry.
var twinStrFields = []struct{ attr, src string }{
	{semconv.AttrPolicyName, "Name"},
	{semconv.AttrRecommendedPolicyType, "RecommendedPolicyType"},
	{semconv.AttrSpamAction, "SpamAction"},
	{semconv.AttrHighConfidenceSpamAction, "HighConfidenceSpamAction"},
	{semconv.AttrPhishSpamAction, "PhishSpamAction"},
	{semconv.AttrHighConfidencePhishAction, "HighConfidencePhishAction"},
	{semconv.AttrBulkSpamAction, "BulkSpamAction"},
	{semconv.AttrFileTypeAction, "FileTypeAction"},
	{semconv.AttrAuthenticationFailAction, "AuthenticationFailAction"},
	{semconv.AttrDmarcRejectAction, "DmarcRejectAction"},
	{semconv.AttrDmarcQuarantineAction, "DmarcQuarantineAction"},
	{semconv.AttrMailboxIntelligenceProtectionAction, "MailboxIntelligenceProtectionAction"},
	{semconv.AttrTargetedUserProtectionAction, "TargetedUserProtectionAction"},
	{semconv.AttrTargetedDomainProtectionAction, "TargetedDomainProtectionAction"},
	{semconv.AttrSafeAttachmentAction, "Action"},
}

// twinNumFields maps a policy's numeric threshold/retention columns.
var twinNumFields = []struct{ attr, src string }{
	{semconv.AttrBulkThreshold, "BulkThreshold"},
	{semconv.AttrPhishThresholdLevel, "PhishThresholdLevel"},
	{semconv.AttrQuarantineRetentionPeriod, "QuarantineRetentionPeriod"},
}

// twinBoolFields maps a policy's boolean posture toggles. They are emitted even
// when false: false is an ANSWER here (#114), the case an operator filters for.
var twinBoolFields = []struct{ attr, src string }{
	{semconv.AttrZapEnabled, "ZapEnabled"},
	{semconv.AttrSpamZapEnabled, "SpamZapEnabled"},
	{semconv.AttrPhishZapEnabled, "PhishZapEnabled"},
	{semconv.AttrFileFilterEnabled, "EnableFileFilter"},
	{semconv.AttrSpoofIntelligenceEnabled, "EnableSpoofIntelligence"},
	{semconv.AttrMailboxIntelligenceEnabled, "EnableMailboxIntelligence"},
	{semconv.AttrSafeDocsEnabled, "EnableSafeDocs"},
	{semconv.AttrSafeLinksEmailEnabled, "EnableSafeLinksForEmail"},
	{semconv.AttrSafeLinksTeamsEnabled, "EnableSafeLinksForTeams"},
	{semconv.AttrSafeLinksOfficeEnabled, "EnableSafeLinksForOffice"},
	{semconv.AttrSafeAttachmentsEnabled, "Enable"},
	{semconv.AttrScanUrlsEnabled, "ScanUrls"},
	{semconv.AttrAllowClickThrough, "AllowClickThrough"},
	{semconv.AttrDeliverMessageAfterScan, "DeliverMessageAfterScan"},
	{semconv.AttrEnableForInternalSenders, "EnableForInternalSenders"},
	{semconv.AttrEnableTargetedUserProtection, "EnableTargetedUserProtection"},
	{semconv.AttrEnableTargetedDomainsProt, "EnableTargetedDomainsProtection"},
	{semconv.AttrAllowSafeDocsOpen, "AllowSafeDocsOpen"},
	{semconv.AttrEnableAtpForSpoTeamsOdb, "EnableATPForSPOTeamsODB"},
	{semconv.AttrHonorDmarcPolicy, "HonorDmarcPolicy"},
	{semconv.AttrEnabled, "Enabled"},
	{semconv.AttrIsDefault, "IsDefault"},
}

// policyTwin renders one policy as an OTLP log record: the per-policy posture
// detail the count gauges collapse away. Timestamp is left zero (poll time) — see
// the package doc on why a state feed must not stamp its source time.
//
// Severity escalates to Warn when a policy that SUPPORTS ZAP has it switched off
// (ZapEnabled present and false) — a real, wire-visible weakening of posture.
// Everything else is Info. The rule is grounded in a field on the wire rather than
// a docs threshold; on the live m7kni tenant every ZapEnabled is true, so every
// live twin is Info.
func policyTwin(policyType string, r map[string]any) telemetry.Event {
	attrs := telemetry.Attrs{}
	telemetry.SetStr(attrs, semconv.AttrPolicyType, policyType)
	for _, f := range twinStrFields {
		telemetry.SetStr(attrs, f.attr, str(r, f.src))
	}
	for _, f := range twinNumFields {
		telemetry.SetNum(attrs, f.attr, r, f.src)
	}
	for _, f := range twinBoolFields {
		if b, ok := r[f.src].(bool); ok {
			telemetry.SetBool(attrs, f.attr, b)
		}
	}

	sev := telemetry.SeverityInfo
	if zap, ok := r["ZapEnabled"].(bool); ok && !zap {
		sev = telemetry.SeverityWarn
	}

	name := str(r, "Name")
	if name == "" {
		name = "unknown"
	}
	return telemetry.Event{
		Name:     eventName,
		Body:     fmt.Sprintf("mdo %s policy %q (recommended=%s)", policyType, name, str(r, "RecommendedPolicyType")),
		Severity: sev,
		Attrs:    attrs,
	}
}

// str reads a string column, "" when absent or non-string. The API decorates
// several columns with sidecar "<Name>@data.type"/"<Name>@odata.type" keys;
// reading by exact name ignores them.
func str(m map[string]any, key string) string {
	s, _ := m[key].(string)
	return s
}

func init() {
	collectors.RegisterEXO(func(d collectors.EXODeps) collector.SnapshotCollector { return New(d) })
}

var _ collector.SnapshotCollector = (*Collector)(nil)
