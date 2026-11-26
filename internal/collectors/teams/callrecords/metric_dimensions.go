package callrecords

import (
	"strings"

	"github.com/rknightion/graph2otel/internal/checkpoint"
	"github.com/rknightion/graph2otel/internal/semconv"
	"github.com/rknightion/graph2otel/internal/teams/sites"
	"github.com/rknightion/graph2otel/internal/telemetry"
	"github.com/rknightion/graph2otel/internal/wirecheck"
)

const (
	unknown         = "unknown"
	other           = "other"
	siteOverflow    = "overflow"
	metricSiteLimit = 16
)

// The enum inputs come from the v1.0 callRecords schema (also in the pinned
// Graph SDK's models/callrecords); media labels use the existing aliases.
// Unknown input is counted under a fixed value, never passed through. Version,
// failure reason and site are not wire enums and are intentionally unwatched.
type wireDimension struct {
	labels map[string]string
	enum   wirecheck.Enum
}

func dimension(labels map[string]string) wireDimension {
	enum := make(wirecheck.Enum, len(labels))
	for key := range labels {
		enum[key] = struct{}{}
	}
	return wireDimension{labels, enum}
}

func enumDimension(values ...string) wireDimension {
	labels := make(map[string]string, len(values)+1)
	for _, value := range values {
		labels[value] = value
	}
	labels["unknownfuturevalue"] = unknown
	return dimension(labels)
}

func (d wireDimension) project(value string) string {
	return first(d.labels[strings.ToLower(value)], unknown)
}

func (d wireDimension) watch(e telemetry.Emitter, field, value string) string {
	wirecheck.Shared(Name).Value(e, field, strings.ToLower(value), d.enum)
	return d.project(value)
}

var (
	callTypes  = dimension(map[string]string{"peertopeer": "peer_to_peer", "groupcall": "group_call", "unknown": unknown, "unknownfuturevalue": unknown})
	modalities = dimension(map[string]string{
		"audio": "audio", "video": "video", "videobasedscreensharing": "sharing", "screensharing": "sharing",
		"data": "data", "unknownfuturevalue": unknown,
	})
	mediaLabels = dimension(map[string]string{
		"audio": "audio", "main-audio": "audio", "video": "video", "main-video": "video", "screensharing": "sharing",
		"applicationsharing": "sharing", "main-appsharing": "sharing", "main-applicationsharing": "sharing",
		"videobasedscreensharing": "sharing", "vbss": "sharing", "main-vbss": "sharing",
		// live-measured: #708 (Teams observability review) observed media_label=data.
		"data": "data",
	})
	directions    = dimension(map[string]string{"callertocallee": "caller_to_callee", "calleetocaller": "callee_to_caller"})
	transports    = enumDimension(unknown, "tcp", "udp")
	connections   = enumDimension(unknown, "wired", "wifi", "mobile", "tunnel")
	platforms     = enumDimension(unknown, "windows", "macos", "ios", "android", "web", "ipphone", "roomsystem", "surfacehub", "hololens")
	products      = enumDimension(unknown, "teams", "skypeforbusiness", "lync", "azurecommunicationservices")
	ratings       = enumDimension("poor", "good", "bad", "fair", "excellent", "notrated")
	failureStages = enumDimension(unknown, "callsetup", "midcall")
)

func (c Call) callDimensions(e telemetry.Emitter) telemetry.Attrs {
	known := len(c.Modalities) > 0
	var video, sharing bool
	pstn := c.Counts.PSTN > 0
	for _, raw := range c.Modalities {
		switch modalities.watch(e, "modalities", raw) {
		case "video":
			video = true
		case "sharing":
			sharing = true
		case unknown:
			known = false
		}
	}
	for _, s := range c.Streams {
		video = video || s.Media == "video"
		sharing = sharing || s.Media == "sharing"
		pstn = pstn || s.Caller.Identity.Kind == "pstn" || s.Callee.Identity.Kind == "pstn"
	}
	return telemetry.Attrs{
		semconv.AttrType: callTypes.watch(e, "type", c.Type), semconv.AttrCallHealth: string(c.quality.health),
		semconv.AttrTeamsHasVideo: presence(video, known), semconv.AttrTeamsHasSharing: presence(sharing, known),
		semconv.AttrTeamsHasPSTN: presence(pstn, c.Counts.Total > 0 && c.Counts.Unknown == 0),
	}
}

func presence(found, known bool) string {
	if found {
		return "true"
	}
	if known {
		return "false"
	}
	return unknown
}

// Metric sites are operator-defined location names, never Graph-supplied
// addresses. Reserve slots for a checkpoint lifetime, including across CSV
// reloads: changing the file cannot continually create fresh time series.
func metricSite(state *checkpoint.TeamsCallMetrics, name string) string {
	if name == "" || name == sites.Unmapped {
		return sites.Unmapped
	}
	if name == siteOverflow || name == other || !siteLabel(name) {
		return siteOverflow
	}
	if state.Sites[name] {
		return name
	}
	if len(state.Sites) >= metricSiteLimit {
		return siteOverflow
	}
	state.Sites[name] = true
	return name
}

// A site label is a short human location name, not a CIDR, IP, UPN or URL.
func siteLabel(name string) bool {
	if len(name) == 0 || len(name) > 48 {
		return false
	}
	for i, ch := range name {
		if 'A' <= ch && ch <= 'Z' || 'a' <= ch && ch <= 'z' {
			continue
		}
		suffixChar := ch == ' ' || ch == '-' || ch == '_' || '0' <= ch && ch <= '9'
		if i == 0 || !suffixChar {
			return false
		}
	}
	return true
}

// No build, patch or raw version appears in a label. 20xxx through 29xxx
// distinguish five-digit client release trains without assuming date semantics.
func versionBucket(version string) string {
	if version == "" {
		return unknown
	}
	if len(version) > 64 {
		return other
	}
	parts := strings.Split(version, ".")
	for _, part := range parts {
		if part == "" || strings.Trim(part, "0123456789") != "" {
			return other
		}
	}
	major := parts[0]
	if len(major) == 1 {
		return major
	}
	if len(major) == 5 && major[0] == '2' {
		return major[:2] + "xxx"
	}
	return other
}
