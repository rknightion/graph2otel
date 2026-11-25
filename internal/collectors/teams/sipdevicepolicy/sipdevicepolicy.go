// Package sipdevicepolicy is the Teams SIP device and IP phone configuration
// collector (#722), read from the Teams admin API (internal/teamsadminclient)
// behind Get-CsTeamsSipDevicesConfiguration and Get-CsTeamsIPPhonePolicy. It
// emits one teams.sip_devices_configuration twin per tenant setting object and
// one teams.ip_phone_policy twin per policy instance, and no gauge: the objects
// are few and their settings are strings, so counts are left to LogQL. Wire
// facts: docs/teams-admin-api.md.
//
// # Not exported
//
// Both resources carry a Key block (scope class, schema ID, authority and the
// default XML) and a ConfigId that repeat Identity or restate the schema, so
// neither is exported. ConfigMetadata.Authority is exported as
// <prefix>authority. Null fields (IP phone policy Description) are omitted.
//
// One resource failing does not stop the other: the collector emits what it
// fetched and returns the joined errors, so the tick still counts as failed.
//
// A state snapshot, not an event stream: each twin is stamped at poll time.
package sipdevicepolicy

import (
	"context"
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
	collectorName = "teams.sip_device_policy"
	eventSipDev   = "teams.sip_devices_configuration"
	eventIPPhone  = "teams.ip_phone_policy"
	interval      = time.Hour

	// The /Skype.Policy/configurations/ names the two cmdlets read.
	resourceSipDev  = "TeamsSipDevicesConfiguration"
	resourceIPPhone = "TeamsIPPhonePolicy"

	fieldIdentity = "Identity"
	fieldMetadata = "ConfigMetadata"
	fieldAuthLeaf = "Authority"
)

type kind int

const (
	kindString kind = iota
	kindBool
	kindInt
)

// field maps one wire field to one twin attribute.
type field struct {
	wire string
	key  string
	kind kind
}

var sipDevicesFields = []field{
	{"Identity", semconv.AttrSipDevicesIdentity, kindString},
	{"BulkSignIn", semconv.AttrSipDevicesBulkSignIn, kindString},
}

var ipPhoneFields = []field{
	{"Identity", semconv.AttrIpPhonePolicyIdentity, kindString},
	{"Description", semconv.AttrIpPhonePolicyDescription, kindString},
	{"SignInMode", semconv.AttrIpPhonePolicySignInMode, kindString},
	{"SearchOnCommonAreaPhoneMode", semconv.AttrIpPhonePolicySearchOnCommonAreaPhoneMode, kindString},
	{"AllowHomeScreen", semconv.AttrIpPhonePolicyAllowHomeScreen, kindString},
	{"AllowBetterTogether", semconv.AttrIpPhonePolicyAllowBetterTogether, kindString},
	{"AllowHotDesking", semconv.AttrIpPhonePolicyAllowHotDesking, kindBool},
	{"HotDeskingIdleTimeoutInMinutes", semconv.AttrIpPhonePolicyHotDeskingIdleTimeoutInMinutes, kindInt},
}

// resourceSpec is one configuration resource and how its objects become twins.
type resourceSpec struct {
	resource  string
	event     string
	kindWord  string
	fields    []field
	authority string
}

var specs = []resourceSpec{
	{resourceSipDev, eventSipDev, "SIP devices configuration", sipDevicesFields, semconv.AttrSipDevicesAuthority},
	{resourceIPPhone, eventIPPhone, "IP phone policy", ipPhoneFields, semconv.AttrIpPhonePolicyAuthority},
}

// Collector reads SIP device configuration and IP phone policies.
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

// DefaultInterval implements collector.Collector.
func (*Collector) DefaultInterval() time.Duration { return interval }

// IngestTransport implements collector.TransportOf: records come from the Teams
// admin API, not Graph.
func (*Collector) IngestTransport() telemetry.Transport { return telemetry.TransportTeamsAdmin }

// RequiredPermissions is nil: access is an Entra directory role on the poller
// (Global Reader measured sufficient), not a Graph scope.
func (*Collector) RequiredPermissions() []string { return nil }

// Collect emits one twin per fetched object. A failing resource records its
// cause and is joined into the returned error; the other is still emitted.
func (c *Collector) Collect(ctx context.Context, e telemetry.Emitter, outcomes *recordoutcome.Recorder) error {
	if c.client == nil {
		return errors.New("teams admin API client is not configured")
	}
	e = telemetry.WithTransport(e, telemetry.TransportTeamsAdmin)

	var errs []error
	for _, s := range specs {
		recs, err := c.client.Configurations(ctx, s.resource)
		if err != nil {
			if teamsadminclient.IsPermission(err) {
				outcomes.Cause(recordoutcome.CausePermissionDenied)
			} else {
				outcomes.Cause(recordoutcome.CauseSourceError)
			}
			errs = append(errs, fmt.Errorf("teams admin %s: %w", s.resource, err))
			continue
		}
		outcomes.Add(recordoutcome.OutcomeFetched, uint64(len(recs)))
		for _, r := range recs {
			e.LogEvent(c.twin(e, s, r))
			outcomes.Add(recordoutcome.OutcomeMapped, 1)
			outcomes.Add(recordoutcome.OutcomeEmitted, 1)
		}
	}
	return errors.Join(errs...)
}

// twin renders one object as a log record.
func (c *Collector) twin(e telemetry.Emitter, s resourceSpec, r map[string]any) telemetry.Event {
	attrs := mapObject(c.watch, e, s, r)
	attrs[semconv.AttrConfigHashVersion] = adminmap.HashVersion
	attrs[semconv.AttrConfigSHA256] = adminmap.Hash(attrs)

	body := s.kindWord
	if id, _ := r[fieldIdentity].(string); id != "" {
		body += " " + id
	}
	return telemetry.Event{Name: s.event, Body: body, Severity: telemetry.SeverityInfo, Attrs: attrs}
}

// mapObject returns the exported attributes of one object, without the hash.
func mapObject(rep *wirecheck.Reporter, e telemetry.Emitter, s resourceSpec, r map[string]any) telemetry.Attrs {
	attrs := telemetry.Attrs{}
	if id, _ := r[fieldIdentity].(string); id == "" {
		rep.MissingField(e, s.resource+"."+fieldIdentity)
	}
	for _, f := range s.fields {
		v, present := r[f.wire]
		if !present || v == nil {
			continue
		}
		switch f.kind {
		case kindString:
			if str, ok := v.(string); ok {
				telemetry.SetStr(attrs, f.key, str)
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
		}
		rep.Invariant(e, collectorName+" field type: "+s.resource+"."+f.wire, fmt.Sprintf("%T", v))
	}
	if md, ok := r[fieldMetadata].(map[string]any); ok {
		if str, ok := md[fieldAuthLeaf].(string); ok {
			telemetry.SetStr(attrs, s.authority, str)
		}
	}
	return attrs
}

func init() {
	collectors.Register(func(d collectors.Deps) collector.SnapshotCollector { return New(d) })
}

var _ collector.SnapshotCollector = (*Collector)(nil)
