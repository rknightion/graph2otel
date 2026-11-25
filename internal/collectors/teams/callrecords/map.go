package callrecords

import (
	"strings"
	"time"

	"github.com/rknightion/graph2otel/internal/teams/sites"
)

// Field shapes are docs-derived. For the endpoint and media projections see:
// https://learn.microsoft.com/graph/api/resources/communicationsidentityset
// https://learn.microsoft.com/graph/api/resources/callrecords-participantendpoint
// https://learn.microsoft.com/graph/api/resources/callrecords-mediastream
// https://learn.microsoft.com/graph/api/resources/callrecords-deviceinfo
// https://learn.microsoft.com/graph/api/resources/callrecords-networkinfo
func mapCall(d detail, version int64, sessions []hydratedSession, people []participant, table *sites.Table, domains sites.Domains) Call {
	call := Call{
		ID: d.ID, Version: version, Type: d.Type, Modalities: d.Modalities,
		Start: parseTime(d.Start), End: parseTime(d.End), JoinWebURL: d.JoinWebURL,
	}
	seen := make(map[string]struct{}, len(people))
	identityByID := make(map[string]Identity, len(people))
	for _, person := range people {
		identity := person.identity()
		if identity.ID != "" {
			identityByID[identity.ID] = identity
		}
		if person.ID != "" {
			identityByID[person.ID] = identity
			if _, ok := seen[person.ID]; ok {
				continue
			}
			seen[person.ID] = struct{}{}
		}
		call.Counts.add(identity.Kind)
	}
	if d.Organizer != nil {
		call.Organizer = fillIdentity(d.Organizer.identity(), identityByID)
	}
	for _, session := range sessions {
		call.observe(session.Failure, session.Caller.Agent, session.Callee.Agent)
		for _, segment := range session.segments {
			call.observe(segment.Failure, segment.Caller.Agent, segment.Callee.Agent)
			for _, m := range segment.Media {
				caller := mapSide(segment.Caller, session.Caller, m.CallerNetwork, m.CallerDevice, identityByID, table, domains)
				callee := mapSide(segment.Callee, session.Callee, m.CalleeNetwork, m.CalleeDevice, identityByID, table, domains)
				for _, s := range m.Streams {
					call.Streams = append(call.Streams, mapStream(s, m.Label, session.session, segment, caller, callee))
				}
			}
		}
	}
	return call
}

func (c *Call) observe(failure *Failure, agents ...Agent) {
	if failure != nil {
		c.failures = append(c.failures, *failure)
	}
	for _, a := range agents {
		if a.Platform != "" || a.ProductFamily != "" || a.Version != "" {
			c.clients = append(c.clients, a)
		}
	}
}

func (p participant) identity() Identity {
	s := p.Identities
	for _, v := range [...]struct {
		value *Identity
		kind  string
	}{
		{s.Guest, "guest"}, {s.Phone, "pstn"}, {s.Application, "app"},
		{s.ApplicationInstance, "app"}, {s.Device, "device"}, {s.User, "user"},
		{s.OnPremises, "user"}, {s.ACSUser, ""}, {s.Asserted, ""},
	} {
		if v.value != nil {
			id := *v.value
			id.ID = first(id.ID, p.ID)
			id.Kind = first(v.kind, identityKind(id.ODataType))
			return id
		}
	}
	return Identity{ID: p.ID}
}

func identityKind(odataType string) string {
	switch strings.TrimPrefix(odataType, "#microsoft.graph.") {
	case "communicationsUserIdentity", "userIdentity":
		return "user"
	case "communicationsGuestIdentity":
		return "guest"
	case "communicationsPhoneIdentity", "phoneIdentity":
		return "pstn"
	case "communicationsApplicationIdentity", "communicationsApplicationInstanceIdentity", "applicationIdentity":
		return "app"
	case "communicationsDeviceIdentity", "deviceIdentity":
		return "device"
	default:
		return ""
	}
}

func (p *ParticipantCounts) add(kind string) {
	p.Total++
	switch kind {
	case "user":
		p.Users++
	case "guest":
		p.Guests++
	case "pstn":
		p.PSTN++
	case "app":
		p.Apps++
	case "device":
		p.Devices++
	default:
		p.Unknown++
	}
}

func fillIdentity(id Identity, byID map[string]Identity) Identity {
	fallback := byID[id.ID]
	id.DisplayName = first(id.DisplayName, fallback.DisplayName)
	id.UPN = first(id.UPN, fallback.UPN)
	id.Kind = first(id.Kind, identityKind(id.ODataType), fallback.Kind)
	return id
}

func mapSide(ep, parent endpoint, network Network, device Device, byID map[string]Identity, table *sites.Table, domains sites.Domains) Side {
	id := ep.Identity
	if id.ID == "" && id.UPN == "" && id.DisplayName == "" && id.ODataType == "" {
		id = parent.Identity
	} else if id.ID != "" && id.ID == parent.Identity.ID {
		id.UPN = first(id.UPN, parent.Identity.UPN)
		id.DisplayName = first(id.DisplayName, parent.Identity.DisplayName)
	}
	id = fillIdentity(id, byID)
	// Do not attach a user from the session to a different segment endpoint.
	// A session endpoint may be omitted and is also the fallback for feedback.
	same := ep.Identity == (Identity{}) || (id.ID != "" && id.ID == parent.Identity.ID) || (id.UPN != "" && strings.EqualFold(id.UPN, parent.Identity.UPN))
	agent, feedback, name := ep.Agent, ep.Feedback, ep.Name
	if same {
		if agent == (Agent{}) {
			agent = parent.Agent
		}
		if feedback == nil {
			feedback = parent.Feedback
		}
		name = first(name, parent.Name)
	}
	return Side{
		Identity: id, Agent: agent, Feedback: feedback, DeviceName: name,
		Network: network, Device: device, Site: table.Lookup(network.Subnet, network.IP),
		IdentityScope: domains.Classify(id.UPN), IPClass: sites.ClassifyIP(network.IP),
		RelayAddressPresent: sites.RelayUsed(network.RelayIP),
	}
}

func mapStream(s streamWire, label string, session session, segment segment, caller, callee Side) Stream {
	metrics := s.StreamMetrics
	metrics.AverageRTTMs, metrics.MaxRTTMs = millis(s.AverageRTT), millis(s.MaxRTT)
	metrics.AverageJitterMs, metrics.MaxJitterMs = millis(s.AverageJitter), millis(s.MaxJitter)
	metrics.AverageAudioJitterMs, metrics.MaxAudioJitterMs = millis(s.AverageAudioNetworkJitter), millis(s.MaxAudioNetworkJitter)
	// Microsoft documents per-stream times only for SIP; the enclosing
	// segment supplies the event time for other streams. A malformed explicit
	// time is not a missing SIP field and must not be disguised by fallback.
	return Stream{
		SessionID: session.ID, SegmentID: segment.ID, ID: s.ID,
		Media: mediaKind(label), MediaLabel: label, Direction: s.Direction,
		Start: parseTime(first(s.Start, segment.Start)), End: parseTime(first(s.End, segment.End)),
		Metrics: metrics, Caller: caller, Callee: callee,
		SessionFailure: session.Failure, SegmentFailure: segment.Failure,
	}
}

func mediaKind(label string) string { return mediaLabels.project(label) }

var durationUnits = strings.NewReplacer("H", "h", "M", "m", "S", "s")

// Graph's media latency values are ISO 8601 time durations (e.g. PT0.016S).
func millis(raw string) *float64 {
	s, ok := strings.CutPrefix(raw, "PT")
	if !ok || s == "" || strings.Trim(s, "0123456789.HMS") != "" {
		return nil
	}
	d, err := time.ParseDuration(durationUnits.Replace(s))
	if err != nil {
		return nil
	}
	v := float64(d) / float64(time.Millisecond)
	return &v
}

func first(values ...string) string {
	for _, s := range values {
		if s != "" {
			return s
		}
	}
	return ""
}
