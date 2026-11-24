package callrecords

import (
	"time"

	"github.com/rknightion/graph2otel/internal/teams/sites"
)

// Call is one hydrated Graph detail version. The collector creates it once on
// the shared ingestion path, before projecting it into logs. Quality and
// metrics should consume this value, not re-read the wire or parse log attrs.
type Call struct {
	ID         string
	Version    int64
	Type       string
	Modalities []string
	Start, End time.Time
	JoinWebURL string
	Organizer  Identity
	Counts     ParticipantCounts
	Streams    []Stream
}

// ParticipantCounts counts distinct participants_v2 entries by their identity
// kind. Unknown includes types without a documented match to the named groups.
type ParticipantCounts struct {
	Total, Users, Guests, PSTN, Apps, Devices, Unknown int
}

// Stream groups media metrics and evidence for a single directional stream.
// Caller and Callee identify the segment sides, not the sender and receiver:
// Direction tells a consumer which side sent this stream.
type Stream struct {
	SessionID, SegmentID, ID       string
	Media, MediaLabel, Direction   string
	Start, End                     time.Time
	Metrics                        StreamMetrics
	Caller, Callee                 Side
	SessionFailure, SegmentFailure *Failure
}

// StreamMetrics preserves missing values as nil. Durations are milliseconds;
// fractions, percentages, frame and packet rates retain Microsoft's units.
type StreamMetrics struct {
	AverageRTTMs, MaxRTTMs                 *float64 `json:"-"`
	AverageJitterMs, MaxJitterMs           *float64 `json:"-"`
	AverageAudioJitterMs, MaxAudioJitterMs *float64 `json:"-"`
	AverageLoss                            *float64 `json:"averagePacketLossRate"`
	MaxLoss                                *float64 `json:"maxPacketLossRate"`
	PostFECLoss                            *float64 `json:"postForwardErrorCorrectionPacketLossRate"`
	VideoFrameRate                         *float64 `json:"averageVideoFrameRate"`
	ReceivedFrameRate                      *float64 `json:"averageReceivedFrameRate"`
	VideoFrameLossPercent                  *float64 `json:"averageVideoFrameLossPercentage"`
	VideoPacketLoss                        *float64 `json:"averageVideoPacketLossRate"`
	AverageAudioDegradation                *float64 `json:"averageAudioDegradation"`
	LowFrameRateRatio                      *float64 `json:"lowFrameRateRatio"`
	PacketUtilization                      *int64   `json:"packetUtilization"`
	AudioCodec                             string   `json:"audioCodec"`
	VideoCodec                             string   `json:"videoCodec"`
}

// Side is one endpoint's identity, device and network evidence. An allocated
// relay address is evidence of allocation, not proof packets crossed it.
type Side struct {
	Identity            Identity
	Agent               Agent
	DeviceName          string
	Feedback            *Feedback
	Network             Network
	Device              Device
	Site                sites.Site
	Internal            bool
	IPClass             sites.IPClass
	RelayAddressPresent bool
}

// Identity is the documented identity projection (not a metric dimension).
type Identity struct {
	ODataType   string `json:"@odata.type"`
	ID          string `json:"id"`
	DisplayName string `json:"displayName"`
	UPN         string `json:"userPrincipalName"`
	Kind        string `json:"-"`
}

// Agent carries the client and service user-agent fields where available.
type Agent struct {
	Header        string `json:"headerValue"`
	Platform      string `json:"platform"`
	ProductFamily string `json:"productFamily"`
	Version       string `json:"applicationVersion"`
	Role          string `json:"role"`
	AzureAppID    string `json:"azureADAppId"`
	ApplicationID string `json:"applicationId"`
}

// Failure is Graph's session or segment failure evidence, without bucketing.
type Failure struct {
	Stage  string `json:"stage"`
	Reason string `json:"reason"`
}

// Feedback comes from the participant endpoint (usually the parent session).
type Feedback struct {
	Rating string          `json:"rating"`
	Tokens map[string]bool `json:"tokens"`
	Text   string          `json:"text"`
}

// Network is the per-side media network observation. Address classes and sites
// are derived from these fields, not from an external geolocation service.
type Network struct {
	IP                         string   `json:"ipAddress"`
	Subnet                     string   `json:"subnet"`
	ReflexiveIP                string   `json:"reflexiveIPAddress"`
	RelayIP                    string   `json:"relayIPAddress"`
	ConnectionType             string   `json:"connectionType"`
	Transport                  string   `json:"networkTransportProtocol"`
	BandwidthLowRatio          *float64 `json:"bandwidthLowEventRatio"`
	DelayRatio                 *float64 `json:"delayEventRatio"`
	SentQualityRatio           *float64 `json:"sentQualityEventRatio"`
	ReceivedQualityRatio       *float64 `json:"receivedQualityEventRatio"`
	WiFiBand                   string   `json:"wifiBand"`
	WiFiRadio                  string   `json:"wifiRadioType"`
	WiFiBSSID                  string   `json:"basicServiceSetIdentifier"`
	WiFiChannel                *int64   `json:"wifiChannel"`
	WiFiSignal                 *int64   `json:"wifiSignalStrength"`
	WiFiBattery                *int64   `json:"wifiBatteryCharge"`
	WiFiMicrosoftDriver        string   `json:"wifiMicrosoftDriver"`
	WiFiMicrosoftDriverVersion string   `json:"wifiMicrosoftDriverVersion"`
	WiFiVendorDriver           string   `json:"wifiVendorDriver"`
	WiFiVendorDriverVersion    string   `json:"wifiVendorDriverVersion"`
	TraceRoute                 []Hop    `json:"traceRouteHops"`
}

// Hop preserves the structured trace route shape with its ISO-8601 duration.
type Hop struct {
	Count *int64 `json:"hopCount,omitempty"`
	IP    string `json:"ipAddress,omitempty"`
	RTT   string `json:"roundTripTime,omitempty"`
}

// Device is Graph's per-side capture, rendering and audio evidence. Optional
// numerics keep a real zero distinct from an absent measurement.
type Device struct {
	CaptureName           string   `json:"captureDeviceName,omitempty"`
	CaptureDriver         string   `json:"captureDeviceDriver,omitempty"`
	RenderName            string   `json:"renderDeviceName,omitempty"`
	RenderDriver          string   `json:"renderDeviceDriver,omitempty"`
	CaptureNotFunctioning *float64 `json:"captureNotFunctioningEventRatio,omitempty"`
	CPUInsufficient       *float64 `json:"cpuInsufficentEventRatio,omitempty"` // Graph spelling
	Clipping              *float64 `json:"deviceClippingEventRatio,omitempty"`
	Glitch                *float64 `json:"deviceGlitchEventRatio,omitempty"`
	Howling               *int64   `json:"howlingEventCount,omitempty"`
	InitialSignalRMS      *float64 `json:"initialSignalLevelRootMeanSquare,omitempty"`
	LowSpeech             *float64 `json:"lowSpeechLevelEventRatio,omitempty"`
	LowSpeechToNoise      *float64 `json:"lowSpeechToNoiseEventRatio,omitempty"`
	MicGlitch             *float64 `json:"micGlitchRate,omitempty"`
	ReceivedNoise         *int64   `json:"receivedNoiseLevel,omitempty"`
	ReceivedSignal        *int64   `json:"receivedSignalLevel,omitempty"`
	RenderMute            *float64 `json:"renderMuteEventRatio,omitempty"`
	RenderNotFunctioning  *float64 `json:"renderNotFunctioningEventRatio,omitempty"`
	RenderZeroVolume      *float64 `json:"renderZeroVolumeEventRatio,omitempty"`
	SentNoise             *int64   `json:"sentNoiseLevel,omitempty"`
	SentSignal            *int64   `json:"sentSignalLevel,omitempty"`
	SpeakerGlitch         *float64 `json:"speakerGlitchRate,omitempty"`
}
