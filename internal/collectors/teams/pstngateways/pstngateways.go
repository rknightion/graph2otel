// Package pstngateways is the Teams Direct Routing gateway (SBC) configuration
// collector (#722), read from the Teams admin API (internal/teamsadminclient)
// behind Get-CsOnlinePSTNGateway. One twin per gateway per poll plus a bounded
// gauge of gateways by enablement. Wire facts: docs/teams-admin-api.md.
//
// # Wire quirks this mapper keeps
//
//   - The translation-rule list OutbundTeamsNumberTranslationRules is misspelled by
//     Microsoft. It is read under that spelling and exported as
//     pstn_gateway_outbund_teams_number_translation_rules, so the key reads off
//     the wire. The correctly spelt field name is not read.
//   - Null fields (GatewaySiteId, MediaRelayRoutingLocationOverride, ProxySbc,
//     Description) mean "not set" and are omitted, never defaulted. An empty
//     translation-rule list exports key_count=0 and no list, so "emptied" differs
//     from "absent".
//
// # Not exported
//
// Every scalar field of the lab fixture is exported. The Key and ConfigId
// blocks do not occur on this resource. Any field the fixture does not carry is
// not exported until a fixture shows it.
//
// A state snapshot, not an event stream: each twin is stamped at poll time.
package pstngateways

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/rknightion/graph2otel/internal/collector"
	"github.com/rknightion/graph2otel/internal/collectors"
	"github.com/rknightion/graph2otel/internal/recordoutcome"
	"github.com/rknightion/graph2otel/internal/semconv"
	"github.com/rknightion/graph2otel/internal/teams/adminmap"
	"github.com/rknightion/graph2otel/internal/teamsadminclient"
	"github.com/rknightion/graph2otel/internal/telemetry"
	"github.com/rknightion/graph2otel/internal/wirecheck"
)

const (
	collectorName = "teams.pstn_gateways"
	eventName     = "teams.pstn_gateway"
	metricCount   = "teams.pstn_gateway.count"
	unitGateway   = "{gateway}"
	// resource is the /Skype.Policy/configurations/ name Get-CsOnlinePSTNGateway reads.
	resource = "OnlinePSTNGateway"
	interval = time.Hour

	// enabledUnknown labels a gateway whose Enabled is absent or not a boolean,
	// so the gauge total always equals the number of gateways.
	enabledUnknown = "unknown"

	fieldIdentity = "Identity"
	fieldEnabled  = "Enabled"
	fieldMetadata = "ConfigMetadata"
	fieldAuthLeaf = "Authority"
)

type kind int

const (
	kindString kind = iota
	kindBool
	kindInt
	kindList
)

// field maps one wire field to one twin attribute.
type field struct {
	wire string
	key  string
	kind kind
	// counted lists have a companion key + "_count" (adminmap.SetIDs).
}

// gatewayFields is every wire field exported, in no particular order. The
// ConfigMetadata.Authority leaf is handled separately.
var gatewayFields = []field{
	{"Identity", semconv.AttrPstnGatewayIdentity, kindString},
	{"Fqdn", semconv.AttrPstnGatewayFqdn, kindString},
	{"SipSignalingPort", semconv.AttrPstnGatewaySipSignalingPort, kindInt},
	{"FailoverTimeSeconds", semconv.AttrPstnGatewayFailoverTimeSeconds, kindInt},
	{"ForwardCallHistory", semconv.AttrPstnGatewayForwardCallHistory, kindBool},
	{"ForwardPai", semconv.AttrPstnGatewayForwardPai, kindBool},
	{"SendSipOptions", semconv.AttrPstnGatewaySendSipOptions, kindBool},
	{"MaxConcurrentSessions", semconv.AttrPstnGatewayMaxConcurrentSessions, kindInt},
	{"Enabled", semconv.AttrPstnGatewayEnabled, kindBool},
	{"MediaBypass", semconv.AttrPstnGatewayMediaBypass, kindBool},
	{"GatewaySiteId", semconv.AttrPstnGatewayGatewaySiteId, kindString},
	{"GatewaySiteLbrEnabled", semconv.AttrPstnGatewayGatewaySiteLbrEnabled, kindBool},
	{"GatewayLbrEnabledUserOverride", semconv.AttrPstnGatewayGatewayLbrEnabledUserOverride, kindBool},
	{"FailoverResponseCodes", semconv.AttrPstnGatewayFailoverResponseCodes, kindString},
	{"PidfLoSupported", semconv.AttrPstnGatewayPidfLoSupported, kindBool},
	{"MediaRelayRoutingLocationOverride", semconv.AttrPstnGatewayMediaRelayRoutingLocationOverride, kindString},
	{"ProxySbc", semconv.AttrPstnGatewayProxySbc, kindString},
	{"BypassMode", semconv.AttrPstnGatewayBypassMode, kindString},
	{"Description", semconv.AttrPstnGatewayDescription, kindString},
	{"IPAddressVersion", semconv.AttrPstnGatewayIpAddressVersion, kindString},
	{"InviteWithReplaces", semconv.AttrPstnGatewayInviteWithReplaces, kindString},
	{"InboundTeamsNumberTranslationRules", semconv.AttrPstnGatewayInboundTeamsNumberTranslationRules, kindList},
	{"InboundPstnNumberTranslationRules", semconv.AttrPstnGatewayInboundPstnNumberTranslationRules, kindList},
	// Microsoft's spelling, kept on purpose (see the package doc).
	{"OutbundTeamsNumberTranslationRules", semconv.AttrPstnGatewayOutbundTeamsNumberTranslationRules, kindList},
	{"OutboundPstnNumberTranslationRules", semconv.AttrPstnGatewayOutboundPstnNumberTranslationRules, kindList},
}

// Collector reads Direct Routing gateway configuration.
type Collector struct {
	client collectors.TeamsAdminClient
	watch  *wirecheck.Reporter
}

// New builds the collector. A zero Deps (the census) yields a collector whose
// Collect returns an error.
func New(d collectors.Deps) *Collector {
	return &Collector{client: d.TeamsAdmin, watch: wirecheck.New(collectorName, d.Logger)}
}

// Name implements collector.Collector.
func (*Collector) Name() string { return collectorName }

// Profiles declares this collector's profile membership.
func (*Collector) Profiles() collector.ProfileSet { return collector.ProfileTeams }

// DefaultInterval implements collector.Collector: gateway configuration changes
// when an admin edits it.
func (*Collector) DefaultInterval() time.Duration { return interval }

// IngestTransport implements collector.TransportOf: records come from the Teams
// admin API, not Graph.
func (*Collector) IngestTransport() telemetry.Transport { return telemetry.TransportTeamsAdmin }

// RequiredPermissions is nil: access is an Entra directory role on the poller
// (Teams Reader is the least-privileged role measured; Global Reader also works), not a Graph scope.
func (*Collector) RequiredPermissions() []string { return nil }

// Collect emits one twin per gateway and the gateway count gauge.
func (c *Collector) Collect(ctx context.Context, e telemetry.Emitter, outcomes *recordoutcome.Recorder) error {
	if c.client == nil {
		return errors.New("teams admin API client is not configured")
	}
	e = telemetry.WithTransport(e, telemetry.TransportTeamsAdmin)

	recs, err := c.client.Configurations(ctx, resource)
	if err != nil {
		if teamsadminclient.IsPermission(err) {
			outcomes.Cause(recordoutcome.CausePermissionDenied)
		} else {
			outcomes.Cause(recordoutcome.CauseSourceError)
		}
		return fmt.Errorf("teams admin %s: %w", resource, err)
	}
	outcomes.Add(recordoutcome.OutcomeFetched, uint64(len(recs)))

	counts := map[string]int{}
	for _, r := range recs {
		e.LogEvent(c.twin(e, r))
		outcomes.Add(recordoutcome.OutcomeMapped, 1)
		outcomes.Add(recordoutcome.OutcomeEmitted, 1)
		counts[enabledLabel(r)]++
	}

	pts := make([]telemetry.GaugePoint, 0, len(counts))
	for label, n := range counts {
		pts = append(pts, telemetry.GaugePoint{Value: float64(n), Attrs: telemetry.Attrs{semconv.AttrEnabled: label}})
	}
	e.GaugeSnapshot(metricCount, unitGateway,
		"Teams Direct Routing gateways by whether they are enabled (enabled=true or false; unknown when the wire carried no boolean). An empty snapshot means no gateway is configured.",
		pts)
	return nil
}

// enabledLabel is the gauge label for one gateway.
func enabledLabel(r map[string]any) string {
	if b, ok := r[fieldEnabled].(bool); ok {
		if b {
			return "true"
		}
		return "false"
	}
	return enabledUnknown
}

// twin renders one gateway as a log record.
func (c *Collector) twin(e telemetry.Emitter, r map[string]any) telemetry.Event {
	attrs := mapGateway(c.watch, e, r)
	attrs[semconv.AttrConfigHashVersion] = adminmap.HashVersion
	attrs[semconv.AttrConfigSHA256] = adminmap.Hash(attrs)

	body := "PSTN gateway"
	if id, _ := r[fieldIdentity].(string); id != "" {
		body += " " + id
	}
	return telemetry.Event{Name: eventName, Body: body, Severity: telemetry.SeverityInfo, Attrs: attrs}
}

// mapGateway returns the exported attributes of one gateway, without the hash.
func mapGateway(rep *wirecheck.Reporter, e telemetry.Emitter, r map[string]any) telemetry.Attrs {
	attrs := telemetry.Attrs{}
	if id, _ := r[fieldIdentity].(string); id == "" {
		rep.MissingField(e, fieldIdentity)
	}
	for _, f := range gatewayFields {
		v, present := r[f.wire]
		if !present || v == nil {
			continue
		}
		switch f.kind {
		case kindString:
			if s, ok := v.(string); ok {
				telemetry.SetStr(attrs, f.key, s)
				continue
			}
		case kindBool:
			if b, ok := v.(bool); ok {
				telemetry.SetBool(attrs, f.key, b)
				continue
			}
		case kindInt:
			if n, ok := v.(float64); ok && n == float64(int64(n)) {
				attrs[f.key] = int(n)
				continue
			}
		case kindList:
			if ids, allStrings, isList := stringList(v); isList {
				adminmap.SetIDs(attrs, f.key, ids)
				if !allStrings {
					// Exported anyway (JSON-encoded elements): dropping config is worse.
					rep.Invariant(e, collectorName+" list element type: "+f.wire, "non-string element")
				}
				continue
			}
		}
		rep.Invariant(e, collectorName+" field type: "+f.wire, fmt.Sprintf("%T", v))
	}
	if md, ok := r[fieldMetadata].(map[string]any); ok {
		if s, ok := md[fieldAuthLeaf].(string); ok {
			telemetry.SetStr(attrs, semconv.AttrPstnGatewayAuthority, s)
		}
	}
	return attrs
}

// stringList reads a JSON array as strings. An empty array is a non-nil empty
// slice, so SetIDs exports _count=0. A non-string element (a shape the lab
// fixture does not show) is kept as its JSON encoding and allStrings is false.
// isList is false when v is not an array at all.
func stringList(v any) (out []string, allStrings, isList bool) {
	arr, ok := v.([]any)
	if !ok {
		return nil, false, false
	}
	out = make([]string, 0, len(arr))
	allStrings = true
	for _, el := range arr {
		if s, ok := el.(string); ok {
			out = append(out, s)
			continue
		}
		allStrings = false
		enc, err := json.Marshal(el)
		if err != nil {
			enc = []byte(fmt.Sprint(el))
		}
		out = append(out, string(enc))
	}
	return out, allStrings, true
}

func init() {
	collectors.Register(func(d collectors.Deps) collector.SnapshotCollector { return New(d) })
}

var _ collector.SnapshotCollector = (*Collector)(nil)
