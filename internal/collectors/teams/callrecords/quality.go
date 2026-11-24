package callrecords

import (
	"net/netip"
	"strings"

	"github.com/rknightion/graph2otel/internal/semconv"
	"github.com/rknightion/graph2otel/internal/teams/quality"
)

type health string

const (
	good         health = "good"
	poor         health = "poor"
	unclassified health = "unclassified"
)

type qualityCause string

const (
	causeRTT              qualityCause = "rtt"
	causeJitter           qualityCause = "jitter"
	causePacketLoss       qualityCause = "packet_loss"
	causeFrameRate        qualityCause = "frame_rate"
	causeFrameLoss        qualityCause = "frame_loss"
	causePostFECLoss      qualityCause = "post_fec_loss"
	causeLowPackets       qualityCause = "low_packet_utilisation" //nolint:misspell // The quality signal contract uses this spelling.
	causeNoMetrics        qualityCause = "no_metrics"
	causeUnsupportedShare qualityCause = "unsupported_sharing_stats"
	causeUnsupportedMedia qualityCause = "unsupported_media"
)

type qualityEvidence struct {
	metric           string
	value, threshold float64
}

type streamQuality struct {
	health   health
	cause    qualityCause
	evidence *qualityEvidence
}

type callQuality struct {
	health                health
	poorStreams           int
	worstRTT, worstJitter *float64
	worstLoss             *float64
	dominantTransport     string
	sharedReflexiveIP     bool
}

type qualityTest struct {
	cause     qualityCause
	metric    string
	value     *float64
	threshold float64
	minimum   bool
}

func (q qualityTest) result() streamQuality {
	if q.value == nil {
		return streamQuality{health: unclassified, cause: causeNoMetrics}
	}
	if (q.minimum && *q.value < q.threshold) || (!q.minimum && *q.value > q.threshold) {
		return streamQuality{health: poor, cause: q.cause, evidence: &qualityEvidence{q.metric, *q.value, q.threshold}}
	}
	return streamQuality{health: good}
}

func classifyStream(s Stream, q quality.Thresholds) streamQuality {
	m := s.Metrics
	switch s.Media {
	case "sharing":
		// CQD's H264S rule applies in either direction. Graph documents h264s
		// and the matching received-video fps metric, but no CQD endpoint-
		// relative inbound/outbound reference for the other codec rules, and
		// no RDP tile or relative one-way measurements.
		if sharingKind(s.MediaLabel) == vbss && strings.EqualFold(m.VideoCodec, "h264s") {
			return (qualityTest{causeFrameRate, semconv.AttrVideoFrameRate, m.VideoFrameRate, q.VBSSFrameRate, true}).result()
		}
		return streamQuality{health: unclassified, cause: causeUnsupportedShare}
	case "audio", "video":
		if m.PacketUtilization == nil {
			return streamQuality{health: unclassified, cause: causeNoMetrics}
		}
		if *m.PacketUtilization <= q.MinPackets {
			return streamQuality{health: unclassified, cause: causeLowPackets, evidence: &qualityEvidence{
				semconv.AttrPacketUtilization, float64(*m.PacketUtilization), float64(q.MinPackets),
			}}
		}
	default:
		return streamQuality{health: unclassified, cause: causeUnsupportedMedia}
	}

	if s.Media == "video" {
		// A measured zero is available. Only an absent field permits fallback.
		for _, rule := range [...]qualityTest{
			{causeFrameLoss, semconv.AttrVideoFrameLossPercent, m.VideoFrameLossPercent, q.VideoFrameLoss, false},
			{causeFrameRate, semconv.AttrVideoFrameRate, m.VideoFrameRate, q.VideoFrameRate, true},
			{causePostFECLoss, semconv.AttrPostFECPacketLossRate, m.PostFECLoss, q.VideoPostFECLoss, false},
		} {
			if rule.value != nil {
				return rule.result()
			}
		}
		return streamQuality{health: unclassified, cause: causeNoMetrics}
	}

	// Any audio breach makes the stream poor. If several are present, show
	// the first in CQD's table order so the single cause is stable.
	result := streamQuality{health: unclassified, cause: causeNoMetrics}
	for _, rule := range [...]qualityTest{
		{causeRTT, semconv.AttrAverageRTTMs, m.AverageRTTMs, q.AudioRTTMs, false},
		{causePacketLoss, semconv.AttrAveragePacketLossRate, m.AverageLoss, q.AudioPacketLoss, false},
		{causeJitter, semconv.AttrAverageJitterMs, m.AverageJitterMs, q.AudioJitterMs, false},
	} {
		switch verdict := rule.result(); verdict.health {
		case poor:
			return verdict
		case good:
			result = verdict
		}
	}
	return result
}

type shareKind uint8

const (
	ambiguousSharing shareKind = iota
	rdp
	vbss
)

func sharingKind(label string) shareKind {
	switch strings.ToLower(label) {
	case "applicationsharing", "main-appsharing", "main-applicationsharing":
		return rdp
	case "videobasedscreensharing", "vbss", "main-vbss":
		return vbss
	default:
		return ambiguousSharing
	}
}

func assessCall(c *Call, q quality.Thresholds) {
	rollup := callQuality{health: unclassified}
	var tcp, udp int
	reflexive := make(map[netip.Addr]string)
	for i := range c.Streams {
		s := &c.Streams[i]
		s.quality = classifyStream(*s, q)
		switch s.quality.health {
		case good:
			if rollup.health == unclassified {
				rollup.health = good
			}
		case poor:
			rollup.health = poor
			rollup.poorStreams++
		}
		m := s.Metrics
		rollup.worstRTT = largest(rollup.worstRTT, m.MaxRTTMs, m.AverageRTTMs)
		rollup.worstJitter = largest(rollup.worstJitter, m.MaxJitterMs, m.AverageJitterMs, m.MaxAudioJitterMs, m.AverageAudioJitterMs)
		rollup.worstLoss = largest(rollup.worstLoss, m.MaxLoss, m.AverageLoss, m.VideoPacketLoss)
		// Each stream votes at most once per observed protocol. If its two
		// endpoints disagree, both observations count; neither wins a tie.
		if hasTransport(s, "tcp") {
			tcp++
		}
		if hasTransport(s, "udp") {
			udp++
		}
		if !rollup.sharedReflexiveIP {
			rollup.sharedReflexiveIP = noteReflexiveIP(reflexive, s.Caller) || noteReflexiveIP(reflexive, s.Callee)
		}
	}
	switch {
	case tcp > udp:
		rollup.dominantTransport = "tcp"
	case udp > tcp:
		rollup.dominantTransport = "udp"
	case tcp > 0:
		rollup.dominantTransport = "mixed"
	}
	c.quality = rollup
}

func largest(current *float64, values ...*float64) *float64 {
	for _, value := range values {
		if value != nil && (current == nil || *value > *current) {
			current = value
		}
	}
	return current
}

func hasTransport(s *Stream, protocol string) bool {
	return strings.EqualFold(s.Caller.Network.Transport, protocol) || strings.EqualFold(s.Callee.Network.Transport, protocol)
}

func noteReflexiveIP(seen map[netip.Addr]string, side Side) bool {
	id := side.Identity.ID
	ip, err := netip.ParseAddr(side.Network.ReflexiveIP)
	if id == "" || err != nil || !ip.IsGlobalUnicast() || ip.Zone() != "" {
		return false
	}
	ip = ip.Unmap()
	if other, ok := seen[ip]; ok {
		return other != id
	}
	seen[ip] = id
	return false
}

func transportEvidence(s Stream, network Network) string {
	if !strings.EqualFold(network.Transport, "tcp") {
		return ""
	}
	sharing := sharingKind(s.MediaLabel)
	switch {
	case s.Media == "audio", s.Media == "video", s.Media == "sharing" && sharing == vbss:
		return "expected_udp"
	case s.Media == "sharing" && sharing == rdp:
		return "expected_rdp_tcp"
	default:
		return "" // no protocol expectation for an ambiguous media label
	}
}
