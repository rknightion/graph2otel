package callrecords

import (
	"encoding/json"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/rknightion/graph2otel/internal/semconv"
	"github.com/rknightion/graph2otel/internal/teams/sites"
	"github.com/rknightion/graph2otel/internal/telemetry"
)

const (
	callEvent    = "teams.call"
	streamEvent  = "teams.call_stream"
	maxHops      = 32
	maxJSONBytes = 2048
	maxTextBytes = 512
)

// emitCall is the typed delivery seam shared by the poll and direct fetch.
// It runs only after logpipeline accepts the authoritative detail version.
func emitCall(e telemetry.Emitter, c Call) {
	a := telemetry.Attrs{
		semconv.AttrVersion: c.Version, semconv.AttrParticipantCount: c.Counts.Total,
		semconv.AttrParticipantUsers: c.Counts.Users, semconv.AttrParticipantGuests: c.Counts.Guests,
		semconv.AttrParticipantPSTN: c.Counts.PSTN, semconv.AttrParticipantApps: c.Counts.Apps,
		semconv.AttrParticipantDevices: c.Counts.Devices, semconv.AttrParticipantUnknown: c.Counts.Unknown,
	}
	setTexts(a, "", semconv.AttrCallId, c.ID, semconv.AttrCallType, c.Type)
	setText(a, semconv.AttrJoinWebUrl, c.JoinWebURL, 4096)
	if len(c.Modalities) != 0 {
		setJSON(a, semconv.AttrModalities, c.Modalities)
	}
	setIdentity(a, "organizer_", c.Organizer)
	setTimes(a, c.Start, c.End)
	if !c.End.IsZero() && !c.End.Before(c.Start) {
		a[semconv.AttrDurationSeconds] = c.End.Sub(c.Start).Seconds()
	}
	q := c.quality
	a[semconv.AttrCallHealth] = string(q.health)
	a[semconv.AttrPoorStreamCount] = q.poorStreams
	setFloat(a, semconv.AttrWorstRTTMs, q.worstRTT)
	setFloat(a, semconv.AttrWorstJitterMs, q.worstJitter)
	setFloat(a, semconv.AttrWorstPacketLossRate, q.worstLoss)
	setText(a, semconv.AttrDominantTransport, q.dominantTransport, maxTextBytes)
	if q.sharedReflexiveIP {
		a[semconv.AttrSharedReflexiveIP] = true
	}
	e.LogEvent(telemetry.Event{Name: callEvent, Body: "Teams call", Timestamp: c.Start, Attrs: a})
	for _, s := range c.Streams {
		e.LogEvent(streamLog(c, s))
	}
}

func streamLog(c Call, s Stream) telemetry.Event {
	a := telemetry.Attrs{semconv.AttrVersion: c.Version, semconv.AttrMedia: s.Media}
	setTexts(a, "", semconv.AttrCallId, c.ID, semconv.AttrSessionId, s.SessionID, semconv.AttrSegmentId, s.SegmentID,
		semconv.AttrStreamId, s.ID, semconv.AttrMediaLabel, s.MediaLabel, semconv.AttrDirection, s.Direction,
		semconv.AttrAudioCodec, s.Metrics.AudioCodec, semconv.AttrVideoCodec, s.Metrics.VideoCodec)
	setTimes(a, s.Start, s.End)
	m := s.Metrics
	setFloat(a, semconv.AttrAverageRTTMs, m.AverageRTTMs)
	setFloat(a, semconv.AttrMaxRTTMs, m.MaxRTTMs)
	setFloat(a, semconv.AttrAverageJitterMs, m.AverageJitterMs)
	setFloat(a, semconv.AttrMaxJitterMs, m.MaxJitterMs)
	setFloat(a, semconv.AttrAverageAudioNetworkJitterMs, m.AverageAudioJitterMs)
	setFloat(a, semconv.AttrMaxAudioNetworkJitterMs, m.MaxAudioJitterMs)
	setFloat(a, semconv.AttrAveragePacketLossRate, m.AverageLoss)
	setFloat(a, semconv.AttrMaxPacketLossRate, m.MaxLoss)
	setFloat(a, semconv.AttrPostFECPacketLossRate, m.PostFECLoss)
	setFloat(a, semconv.AttrVideoFrameRate, m.VideoFrameRate)
	setFloat(a, semconv.AttrReceivedFrameRate, m.ReceivedFrameRate)
	setFloat(a, semconv.AttrVideoFrameLossPercent, m.VideoFrameLossPercent)
	setFloat(a, semconv.AttrVideoPacketLossRate, m.VideoPacketLoss)
	setFloat(a, semconv.AttrAverageAudioDegradation, m.AverageAudioDegradation)
	setFloat(a, semconv.AttrLowFrameRateRatio, m.LowFrameRateRatio)
	setInt(a, semconv.AttrPacketUtilization, m.PacketUtilization)
	setSide(a, "caller_", s.Caller)
	setSide(a, "callee_", s.Callee)
	setStreamQuality(a, s)
	if f := s.SessionFailure; f != nil {
		setTexts(a, "", semconv.AttrSessionFailureStage, f.Stage, semconv.AttrSessionFailureReason, f.Reason)
	}
	if f := s.SegmentFailure; f != nil {
		setTexts(a, "", semconv.AttrSegmentFailureStage, f.Stage, semconv.AttrSegmentFailureReason, f.Reason)
	}
	return telemetry.Event{Name: streamEvent, Body: "Teams call media stream", Timestamp: s.Start, Attrs: a}
}

func setStreamQuality(a telemetry.Attrs, s Stream) {
	q := s.quality
	a[semconv.AttrStreamHealth] = string(q.health)
	setText(a, semconv.AttrStreamHealthCause, string(q.cause), maxTextBytes)
	if v := q.evidence; v != nil {
		a[semconv.AttrStreamHealthMetric] = v.metric
		a[semconv.AttrStreamHealthValue] = v.value
		a[semconv.AttrStreamHealthThreshold] = v.threshold
	}
	if q.health == poor {
		switch s.Direction {
		case "callerToCallee":
			a["caller_impact"], a["callee_impact"] = "impacting", "impacted"
		case "calleeToCaller":
			a["caller_impact"], a["callee_impact"] = "impacted", "impacting"
		}
	}
	setSideQuality(a, "caller_", s, s.Caller)
	setSideQuality(a, "callee_", s, s.Callee)
}

func setSideQuality(a telemetry.Attrs, p string, s Stream, side Side) {
	transport := transportEvidence(s, side.Network)
	setText(a, p+"transport_evidence", transport, maxTextBytes)
	issue := s.quality.health == poor || transport == "expected_udp"
	for _, flag := range [...]struct {
		key   string
		ratio *float64
	}{
		{"cpu_insufficient", side.Device.CPUInsufficient},
		{"device_glitch", side.Device.Glitch},
		// Graph reports an explicit low-speech detection ratio. Do not turn raw
		// signal strength or RMS into a low-signal verdict using guessed limits.
		{"low_speech_signal", side.Device.LowSpeech},
	} {
		if flag.ratio != nil {
			detected := *flag.ratio > 0
			a[p+flag.key] = detected
			issue = issue || detected
		}
	}
	if issue && strings.EqualFold(side.Network.ConnectionType, "wifi") {
		a[p+"wifi_with_issue"] = true
	}
}

func setSide(a telemetry.Attrs, p string, s Side) {
	setIdentity(a, p, s.Identity)
	app := first(s.Agent.ApplicationID, s.Agent.AzureAppID)
	if app == "" && s.Identity.Kind == "app" {
		app = s.Identity.ID
	}
	setTexts(a, p, semconv.AttrUserAgent, s.Agent.Header, semconv.AttrPlatform, s.Agent.Platform,
		"product_family", s.Agent.ProductFamily, "client_version", s.Agent.Version,
		"bot_role", s.Agent.Role, semconv.AttrAppId, app, semconv.AttrDeviceName, s.DeviceName)
	if f := s.Feedback; f != nil {
		setTexts(a, p, "feedback_rating", f.Rating, "feedback_text", f.Text)
		if len(f.Tokens) != 0 {
			setJSON(a, p+"feedback_tokens", f.Tokens)
		}
	}
	setText(a, p+"site", s.Site.Name, maxTextBytes)
	if s.Site.Name != sites.Unmapped {
		setText(a, p+"site_country", s.Site.Country, maxTextBytes)
		a[p+"site_latitude"] = s.Site.Latitude
		a[p+"site_longitude"] = s.Site.Longitude
	}
	a[p+semconv.AttrIsInternal] = s.Internal
	a[p+"relay_address_present"] = s.RelayAddressPresent
	setText(a, p+"ip_class", string(s.IPClass), maxTextBytes)
	n := s.Network
	setTexts(a, p, semconv.AttrIpAddress, n.IP, "subnet", n.Subnet, "reflexive_ip_address", n.ReflexiveIP,
		"relay_ip_address", n.RelayIP, "connection_type", n.ConnectionType, semconv.AttrTransportProtocol, n.Transport,
		"wifi_band", n.WiFiBand, "wifi_radio_type", n.WiFiRadio, "wifi_bssid", n.WiFiBSSID,
		"wifi_microsoft_driver", n.WiFiMicrosoftDriver, "wifi_microsoft_driver_version", n.WiFiMicrosoftDriverVersion,
		"wifi_vendor_driver", n.WiFiVendorDriver, "wifi_vendor_driver_version", n.WiFiVendorDriverVersion)
	setInt(a, p+"wifi_channel", n.WiFiChannel)
	setInt(a, p+"wifi_signal_strength", n.WiFiSignal)
	setInt(a, p+"wifi_battery_charge", n.WiFiBattery)
	setFloat(a, p+"bandwidth_low_ratio", n.BandwidthLowRatio)
	setFloat(a, p+"delay_event_ratio", n.DelayRatio)
	setFloat(a, p+"sent_quality_event_ratio", n.SentQualityRatio)
	setFloat(a, p+"received_quality_event_ratio", n.ReceivedQualityRatio)
	setTraceRoute(a, p, n.TraceRoute)
	if d := s.Device; d != (Device{}) {
		d.CaptureName, d.CaptureDriver = clipText(a, d.CaptureName, maxTextBytes), clipText(a, d.CaptureDriver, maxTextBytes)
		d.RenderName, d.RenderDriver = clipText(a, d.RenderName, maxTextBytes), clipText(a, d.RenderDriver, maxTextBytes)
		setJSON(a, p+"device", d)
	}
}

func setIdentity(a telemetry.Attrs, p string, id Identity) {
	setTexts(a, p, semconv.AttrId, id.ID, semconv.AttrDisplayName, id.DisplayName,
		semconv.AttrUserPrincipalName, id.UPN, "identity_kind", id.Kind)
}

func setTimes(a telemetry.Attrs, start, end time.Time) {
	if !start.IsZero() {
		a[semconv.AttrStartTime] = start.UTC().Format(time.RFC3339Nano)
	}
	if !end.IsZero() {
		a[semconv.AttrEndTime] = end.UTC().Format(time.RFC3339Nano)
	}
}

func setFloat(a telemetry.Attrs, key string, value *float64) {
	if value != nil {
		a[key] = *value
	}
}

func setInt(a telemetry.Attrs, key string, value *int64) {
	if value != nil {
		a[key] = *value
	}
}

func setTexts(a telemetry.Attrs, prefix string, pairs ...string) {
	for i := 0; i+1 < len(pairs); i += 2 {
		setText(a, prefix+pairs[i], pairs[i+1], maxTextBytes)
	}
}

func setText(a telemetry.Attrs, key, value string, limit int) {
	if value != "" {
		a[key] = clipText(a, value, limit)
	}
}

func clipText(a telemetry.Attrs, value string, limit int) string {
	if len(value) <= limit {
		return value
	}
	const key = semconv.AttrTextFieldsTruncated
	count, _ := a[key].(int)
	a[key] = count + 1
	for !utf8.RuneStart(value[limit]) {
		limit--
	}
	return value[:limit]
}

// Trace and feedback are JSON, not delimiter-separated fields. Bound them
// here so the sink's last-resort byte clipping does not split their syntax.
func setJSON(a telemetry.Attrs, key string, value any) {
	b, err := json.Marshal(value)
	if err == nil && len(b) <= maxJSONBytes {
		a[key] = string(b)
	} else {
		a[key+"_omitted"] = true
	}
}

func setTraceRoute(a telemetry.Attrs, prefix string, hops []Hop) {
	if len(hops) == 0 {
		return
	}
	var b strings.Builder
	b.WriteByte('[')
	kept := 0
	for _, hop := range hops[:min(len(hops), maxHops)] {
		raw, err := json.Marshal(hop)
		if err != nil || b.Len()+len(raw)+2 > maxJSONBytes {
			break
		}
		if kept > 0 {
			b.WriteByte(',')
		}
		b.Write(raw)
		kept++
	}
	b.WriteByte(']')
	a[prefix+"trace_route_hops"] = b.String()
	if kept < len(hops) {
		a[prefix+"trace_route_hops_omitted"] = len(hops) - kept
	}
}
