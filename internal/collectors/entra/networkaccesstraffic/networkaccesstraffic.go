// Package networkaccesstraffic is the Entra Global Secure Access traffic-log
// source (#338): a single WindowCollector over
// GET /beta/networkAccess/logs/traffic, emitting one OTLP log record per GSA
// connection through the generic logpipeline engine.
//
// It is the per-connection half of Global Secure Access. entra.gsa reports the
// POSTURE — is GSA onboarded, which forwarding profiles exist, which filtering
// policies are configured. This reports what actually happened through them:
// which device reached which host, under whose identity, allowed or blocked by
// which rule. No other signal in this project names a host a managed device
// connected to.
//
// # It ships OFF, and it is HighVolume rather than expensive-Experimental
//
// Measured on m7kni 2026-07-29 as graph2otel-poller: **3,695 records in one
// clock hour** (server-filtered window 18:00-19:00Z, 4 pages, not truncated),
// which is ~88,700/day — from essentially ONE Windows 11 client. The rate
// scales with TRAFFIC, not tenant size, which is precisely the HighVolume
// definition (#254), so it declares collectors.HighVolume and registers only
// when an operator explicitly enables it.
//
// It is ALSO Experimental, and both gates are load-bearing rather than
// belt-and-braces: the endpoint exists only on Graph beta (#183), and beta
// status and firehose volume are different facts an operator needs
// independently. Per #254 the volume figure above is stated in the
// collectordoc annotation as a measured number, because "high volume" with no
// number is nothing anyone can plan capacity against.
//
// # Query surface, all live-measured — including two ceilings
//
//   - $top ceiling is exactly 1000: $top=1001 answers 400 naming the limit.
//   - $filter on createdDateTime works, including a two-sided ge/lt window.
//   - $count=true answers 400 (`Query option 'Count' is not allowed`), so
//     there is no cheap way to size a window before draining it.
//   - the endpoint's DEFAULT order is createdDateTime DESCENDING — newest
//     first. That is the opposite of what every watermark poller wants, and a
//     collector that paged with the default and stopped early would harvest
//     the newest rows while its watermark stayed put.
//
// $orderby=createdDateTime asc is accepted, but this collector deliberately
// does NOT set OrderByReliable. Accepting an $orderby is not evidence that
// page order is stable across a paged, throttled, multi-region firehose, and
// that is a property this project does not assume from a single successful
// request (#142/#165). So the window is drained and sorted CLIENT-SIDE with
// FlavorGtLt, which the engine already supports. The cost is bounded: at the
// measured rate a 5-minute interval drains roughly 300 records per window.
//
// # Log-only, deliberately, with no bounded counter
//
// #239's original sketch proposed a bounded counter
// entra.network_access.transactions{traffic_type, action}. It is not built,
// and that is a decision rather than an omission: the logpipeline engine emits
// logs only, a LogQL `count by (traffic_type, action)` over these records
// answers the identical question at no extra series cost, and every other
// dimension anyone would actually slice by (destination FQDN, user, device,
// policy rule) is unbounded and could never be a label anyway (#112). Adding a
// second emit path to the shared engine to publish two series that LogQL
// already gives free is the wrong trade.
//
// # Two different encodings of "no value" in one record
//
// ~20 fields per row are structurally present and set to the EMPTY STRING
// (sessionId, destinationIp, destinationUrl, policyRuleId on some rows,
// threatType, remoteNetworkId, userId/userPrincipalName on service traffic),
// while httpMethod, responseCode, operationStatus, policyType, isAgentic and
// every nested detail object use JSON null. So a presence check finds a row
// carrying nothing, and every string here goes through telemetry.SetStr while
// every nullable scalar is pointer-modeled.
//
// # What is NOT emitted, and why
//
//   - **Generative AI prompt/content data.** #338's own non-goal. Nothing
//     under the GenAI surface is fetched or mapped here.
//   - **processArgs / processTree.** A command line can carry a credential in
//     an argument, and this project's one content exclusion exists for exactly
//     that shape (#190). Both are empty on all 3,000 observed rows, so there
//     is no live sample to review either — mapping them would be a
//     docs-shaped guess about a field that may contain secrets.
//   - **The agentic-AI block** (agenticSessionId, agentVirtualId, agentTypeId,
//     agentTypeName, mcpPrimitiveName, mcpProtocolVersion, aiAgentDetails,
//     aiAgentDetectionDetails). Null or empty on every observed row. isAgentic
//     itself IS carried because it has observed values; the rest have no
//     mapped shape and this project does not write mappers against unseen data.
//     The unblock is a tenant with agentic traffic actually flowing.
//
// # Wirecheck
//
// Nothing is watched, and that is a recorded decision. wirecheck guards the
// fields whose values key a METRIC LABEL, where an unmapped enum member moves
// series membership and makes the number wrong (#233/#234). This collector
// emits no metrics, so no value it reads can move a series; an unrecognized
// trafficType or action lands verbatim on the record, which is the outcome a
// watchdog would be asking for anyway. Observed value sets are small on this
// tenant (trafficType internet/microsoft365, action allow/block) and a
// watchdog built on them would fire on the first `private` row from Private
// Access — a correct row, which is the failure this project refuses to ship.
package networkaccesstraffic

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
	// path is the Graph BETA path this collector polls. There is no v1.0 form.
	path = "/networkAccess/logs/traffic"
	// betaBaseURL overrides the engine's default v1.0 service root.
	betaBaseURL = "https://graph.microsoft.com/beta"
	// name is the stable collector key.
	name = "entra.network_access_traffic"
	// eventName is the OTLP LogRecord EventName every GSA connection carries.
	eventName = "entra.network_access_traffic"
)

// Schedule tuning. The interval is short because the window has to stay small:
// at the measured ~3,695 records/hour a 5-minute window is ~300 records, well
// inside one 1000-row page, so a poll normally completes in a single request.
//
// initialLookback is deliberately ONE HOUR rather than the day-scale lookback
// a low-volume audit stream can afford: a first run on a busy tenant would
// otherwise drain tens of thousands of records before the first watermark is
// written. maxWindow caps a catch-up after downtime for the same reason.
const (
	interval        = 5 * time.Minute
	lag             = 15 * time.Minute
	initialLookback = time.Hour
	maxWindow       = 6 * time.Hour
)

// collectorImpl is the GSA traffic-log WindowCollector: the generic
// LogCollector plus this collector's own gating and permission declarations.
type collectorImpl struct {
	*logpipeline.LogCollector
}

// RequiredPermissions declares the least-privilege Graph application scope.
// graph2otel-poller already holds it (live-verified 2026-07-23 and again
// 2026-07-29), so this collector needed no new grant. Do NOT widen this to the
// NetworkAccess.ReadWrite.All or Directory.ReadWrite.All variants the
// endpoint's own 403 message also lists — read is sufficient, measured.
func (c *collectorImpl) RequiredPermissions() []string { return []string{"NetworkAccess.Read.All"} }

// Experimental marks the beta dependency: the endpoint exists only under
// /beta/networkAccess, with no v1.0 form (#183).
func (c *collectorImpl) Experimental() bool { return true }

// HighVolume marks the firehose. ~3,695 records/hour from one client,
// live-measured — see the package doc (#254).
func (c *collectorImpl) HighVolume() bool { return true }

// newCollector builds the GSA traffic WindowCollector.
func newCollector(d collectors.WindowDeps) *collectorImpl {
	cfg := logpipeline.EndpointConfig{
		Path:            path,
		BaseURLOverride: betaBaseURL,
		TimeField:       "createdDateTime",
		// Strict bounds plus client-side ordering: the endpoint's default
		// order is DESCENDING and its ordering guarantees under paging are
		// unmeasured, so page order is not trusted. See the package doc.
		Flavor:          logpipeline.FlavorGtLt,
		OrderByReliable: false,
		Map:             mapTrafficRecord,
	}
	lc := logpipeline.NewLogCollector(name, interval, lag, d.TenantID, cfg, d.Fetcher, d.Store)
	return &collectorImpl{LogCollector: lc}
}

// mapTrafficRecord turns one raw GSA traffic row into its dedupe id (the
// immutable transactionId) and the OTLP log Event.
//
// Severity is Warn for a blocked connection and Info otherwise. That is the
// right way round for this signal even though block is the MAJORITY action on
// the live tenant (2,941 of 3,000): a block is the security-relevant event —
// something on a managed device tried to reach a destination policy forbids —
// and severity is what makes it selectable without knowing the attribute
// vocabulary. It is also why the volume gate exists.
func mapTrafficRecord(rec map[string]any) (string, telemetry.Event) {
	id := str(rec, "transactionId")
	action := str(rec, "action")
	trafficType := str(rec, "trafficType")
	fqdn := str(rec, "destinationFQDN")

	attrs := telemetry.Attrs{}
	telemetry.SetStr(attrs, semconv.AttrTransactionId, id)
	telemetry.SetStr(attrs, semconv.AttrConnectionId, str(rec, "connectionId"))
	telemetry.SetStr(attrs, semconv.AttrSessionId, str(rec, "sessionId"))
	telemetry.SetStr(attrs, semconv.AttrTrafficType, trafficType)
	telemetry.SetStr(attrs, semconv.AttrDeviceCategory, str(rec, "deviceCategory"))
	telemetry.SetStr(attrs, semconv.AttrAction, action)

	// Destination. The FQDN is the field an investigation starts from; the IP
	// and URL are populated only when GSA resolved them (3 and 9 of 3,000
	// observed rows respectively).
	telemetry.SetStr(attrs, semconv.AttrDestinationFqdn, fqdn)
	telemetry.SetStr(attrs, semconv.AttrDestinationIpAddress, str(rec, "destinationIp"))
	telemetry.SetStr(attrs, semconv.AttrDestinationUrl, str(rec, "destinationUrl"))
	setInt(attrs, semconv.AttrDestinationPort, num(rec, "destinationPort"))

	// Source and client.
	telemetry.SetStr(attrs, semconv.AttrSourceIp, str(rec, "sourceIp"))
	setInt(attrs, semconv.AttrSourcePort, num(rec, "sourcePort"))
	telemetry.SetStr(attrs, semconv.AttrDeviceId, str(rec, "deviceId"))
	telemetry.SetStr(attrs, semconv.AttrDeviceOperatingSystem, str(rec, "deviceOperatingSystem"))
	telemetry.SetStr(attrs, semconv.AttrDeviceOperatingSystemVersion, str(rec, "deviceOperatingSystemVersion"))
	telemetry.SetStr(attrs, semconv.AttrAgentVersion, str(rec, "agentVersion"))
	telemetry.SetStr(attrs, semconv.AttrInitiatingProcessName, str(rec, "initiatingProcessName"))

	// Identity. Empty on service-originated traffic, which is a real
	// distinction from a user connection and must stay absent rather than
	// become an empty-string principal.
	telemetry.SetStr(attrs, semconv.AttrUserId, str(rec, "userId"))
	telemetry.SetStr(attrs, semconv.AttrUserPrincipalName, str(rec, "userPrincipalName"))

	// Protocol.
	telemetry.SetStr(attrs, semconv.AttrTransportProtocol, str(rec, "transportProtocol"))
	telemetry.SetStr(attrs, semconv.AttrNetworkProtocol, str(rec, "networkProtocol"))
	telemetry.SetStr(attrs, semconv.AttrApplicationProtocol, str(rec, "applicationProtocol"))
	telemetry.SetStr(attrs, semconv.AttrHttpMethod, str(rec, "httpMethod"))
	telemetry.SetStr(attrs, semconv.AttrUserAgent, str(rec, "httpUserAgent"))
	setInt(attrs, semconv.AttrResponseCode, num(rec, "responseCode"))

	// Which policy decided this, on both the filtering and TLS axes.
	telemetry.SetStr(attrs, semconv.AttrPolicyId, str(rec, "policyId"))
	telemetry.SetStr(attrs, semconv.AttrPolicyName, str(rec, "policyName"))
	telemetry.SetStr(attrs, semconv.AttrPolicyRuleId, str(rec, "policyRuleId"))
	telemetry.SetStr(attrs, semconv.AttrPolicyRuleName, str(rec, "policyRuleName"))
	telemetry.SetStr(attrs, semconv.AttrFilteringProfileId, str(rec, "filteringProfileId"))
	telemetry.SetStr(attrs, semconv.AttrFilteringProfileName, str(rec, "filteringProfileName"))

	// Byte counters are emitted unconditionally, including zero: a blocked
	// connection genuinely transferred nothing, and that measured zero is the
	// evidence the block took effect.
	attrs[semconv.AttrSentBytes] = numOrZero(rec, "sentBytes")
	attrs[semconv.AttrReceivedBytes] = numOrZero(rec, "receivedBytes")

	telemetry.SetStr(attrs, semconv.AttrOperationStatus, str(rec, "operationStatus"))
	telemetry.SetStr(attrs, semconv.AttrThreatType, str(rec, "threatType"))
	telemetry.SetStr(attrs, semconv.AttrPopProcessingRegion, str(rec, "popProcessingRegion"))

	// isAgentic is null on microsoft365 rows and false on internet ones —
	// "GSA did not evaluate this" and "GSA decided no" are different facts.
	if v, ok := rec["isAgentic"].(bool); ok {
		attrs[semconv.AttrIsAgentic] = v
	}

	// destinationWebCategory.name arrives comma-joined and is kept verbatim:
	// the wire's own grouping is the datum (#322).
	if cat := nested(rec, "destinationWebCategory"); cat != nil {
		telemetry.SetStr(attrs, semconv.AttrDestinationWebCategory, str(cat, "name"))
	}

	// tlsDetails is present on the large majority of rows here, so its
	// absence — not its presence — is the case worth noticing.
	if tls := nested(rec, "tlsDetails"); tls != nil {
		telemetry.SetStr(attrs, semconv.AttrTlsAction, str(tls, "action"))
		telemetry.SetStr(attrs, semconv.AttrTlsStatus, str(tls, "status"))
		telemetry.SetStr(attrs, semconv.AttrTlsPolicyId, str(tls, "policyId"))
		telemetry.SetStr(attrs, semconv.AttrTlsPolicyName, str(tls, "policyName"))
		telemetry.SetStr(attrs, semconv.AttrTlsRuleId, str(tls, "ruleId"))
		telemetry.SetStr(attrs, semconv.AttrTlsRuleName, str(tls, "ruleName"))
	}

	sev := telemetry.SeverityInfo
	if action == "block" {
		sev = telemetry.SeverityWarn
	}

	dest := fqdn
	if dest == "" {
		dest = str(rec, "destinationIp")
	}
	if dest == "" {
		dest = "unknown destination"
	}
	return id, telemetry.Event{
		Name:     eventName,
		Body:     fmt.Sprintf("GSA %s %s %s", trafficType, actionVerb(action), dest),
		Severity: sev,
		Attrs:    attrs,
	}
}

// actionVerb renders the action for the record body without asserting a
// vocabulary: an action Microsoft adds later reads as `action=<value>` rather
// than being silently folded into allow or block.
func actionVerb(action string) string {
	switch action {
	case "allow":
		return "allowed"
	case "block":
		return "blocked"
	case "":
		return "with no recorded action to"
	default:
		return "action=" + action
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

// num returns the numeric value when the wire carried one, as a pointer, so an
// absent or null field stays distinguishable from a real zero. Every JSON
// number decodes as float64 through the engine's generic map decode.
func num(m map[string]any, key string) *float64 {
	f, ok := m[key].(float64)
	if !ok {
		return nil
	}
	return &f
}

// numOrZero is for the two byte counters, where the wire always sends a number
// and zero is a real measurement.
func numOrZero(m map[string]any, key string) float64 {
	f, _ := m[key].(float64)
	return f
}

// setInt writes a pointer-modeled numeric only when the wire carried it.
func setInt(attrs telemetry.Attrs, key string, v *float64) {
	if v != nil {
		attrs[key] = *v
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

// Compile-time checks that the collector satisfies every interface the
// composition root type-asserts on.
var (
	_ collector.WindowCollector = (*collectorImpl)(nil)
	_ collectors.Experimental   = (*collectorImpl)(nil)
	_ collectors.HighVolume     = (*collectorImpl)(nil)
)
