package callrecords

import (
	"reflect"
	"testing"
	"time"

	"github.com/rknightion/graph2otel/internal/checkpoint"
	"github.com/rknightion/graph2otel/internal/collectors"
	"github.com/rknightion/graph2otel/internal/recordoutcome"
	"github.com/rknightion/graph2otel/internal/teams/quality"
	"github.com/rknightion/graph2otel/internal/telemetrytest"
)

func TestClassifyStream(t *testing.T) {
	q := quality.Thresholds{MinPackets: 500, AudioRTTMs: 500, AudioPacketLoss: .1, AudioJitterMs: 30,
		VideoFrameLoss: 50, VideoFrameRate: 7, VideoPostFECLoss: .15, VBSSFrameRate: 1}
	for _, tc := range []struct {
		name, media, label string
		metrics            StreamMetrics
		want               streamQuality
	}{
		{"audio packet absent", "audio", "", StreamMetrics{AverageRTTMs: new(501.0)}, streamQuality{unclassified, causeNoMetrics, nil}},
		{"audio metrics absent", "audio", "", StreamMetrics{PacketUtilization: new(int64(501))}, streamQuality{unclassified, causeNoMetrics, nil}},
		{"audio exactly 500", "audio", "", StreamMetrics{PacketUtilization: new(int64(500)), AverageRTTMs: new(501.0)}, streamQuality{unclassified, causeLowPackets, &qualityEvidence{"packet_utilization", 500, 500}}},
		{"audio zero packets", "audio", "", StreamMetrics{PacketUtilization: new(int64(0))}, streamQuality{unclassified, causeLowPackets, &qualityEvidence{"packet_utilization", 0, 500}}},
		{"audio zero loss is measured", "audio", "", StreamMetrics{PacketUtilization: new(int64(501)), AverageLoss: new(0.0)}, streamQuality{good, "", nil}},
		{"audio exactly at limits", "audio", "", StreamMetrics{PacketUtilization: new(int64(501)), AverageRTTMs: new(500.0), AverageJitterMs: new(30.0), AverageLoss: new(.1)}, streamQuality{good, "", nil}},
		{"audio RTT wins multiple crossings", "audio", "", StreamMetrics{PacketUtilization: new(int64(501)), AverageRTTMs: new(501.0), AverageJitterMs: new(31.0), AverageLoss: new(.11)}, streamQuality{poor, causeRTT, &qualityEvidence{"average_rtt_ms", 501, 500}}},
		{"audio loss", "audio", "", StreamMetrics{PacketUtilization: new(int64(501)), AverageRTTMs: new(500.0), AverageLoss: new(.11)}, streamQuality{poor, causePacketLoss, &qualityEvidence{"average_packet_loss_rate", .11, .1}}},
		{"audio jitter", "audio", "", StreamMetrics{PacketUtilization: new(int64(501)), AverageLoss: new(0.0), AverageJitterMs: new(31.0)}, streamQuality{poor, causeJitter, &qualityEvidence{"average_jitter_ms", 31, 30}}},
		{"video exactly 500", "video", "", StreamMetrics{PacketUtilization: new(int64(500)), VideoFrameRate: new(0.0)}, streamQuality{unclassified, causeLowPackets, &qualityEvidence{"packet_utilization", 500, 500}}},
		{"video unmatched metric is not an alias", "video", "", StreamMetrics{PacketUtilization: new(int64(501)), ReceivedFrameRate: new(0.0), VideoPacketLoss: new(.8)}, streamQuality{unclassified, causeNoMetrics, nil}},
		{"video frame loss crossing", "video", "", StreamMetrics{PacketUtilization: new(int64(501)), VideoFrameLossPercent: new(50.1)}, streamQuality{poor, causeFrameLoss, &qualityEvidence{"video_frame_loss_percent", 50.1, 50}}},
		{"video frame loss at limit wins", "video", "", StreamMetrics{PacketUtilization: new(int64(501)), VideoFrameLossPercent: new(50.0), VideoFrameRate: new(0.0), PostFECLoss: new(.2)}, streamQuality{good, "", nil}},
		{"video zero frame loss wins", "video", "", StreamMetrics{PacketUtilization: new(int64(501)), VideoFrameLossPercent: new(0.0), VideoFrameRate: new(0.0)}, streamQuality{good, "", nil}},
		{"video zero fps wins", "video", "", StreamMetrics{PacketUtilization: new(int64(501)), VideoFrameRate: new(0.0), PostFECLoss: new(0.0)}, streamQuality{poor, causeFrameRate, &qualityEvidence{"video_frame_rate", 0, 7}}},
		{"video fps at limit wins", "video", "", StreamMetrics{PacketUtilization: new(int64(501)), VideoFrameRate: new(7.0), PostFECLoss: new(.2)}, streamQuality{good, "", nil}},
		{"video falls through to post FEC", "video", "", StreamMetrics{PacketUtilization: new(int64(501)), PostFECLoss: new(.16)}, streamQuality{poor, causePostFECLoss, &qualityEvidence{"post_fec_packet_loss_rate", .16, .15}}},
		{"video post FEC at limit", "video", "", StreamMetrics{PacketUtilization: new(int64(501)), PostFECLoss: new(.15)}, streamQuality{good, "", nil}},
		{"VBSS H264S at limit", "sharing", "vbss", StreamMetrics{VideoCodec: "h264s", VideoFrameRate: new(1.0), VideoFrameLossPercent: new(99.0)}, streamQuality{good, "", nil}},
		{"VBSS H264S poor", "sharing", "main-vbss", StreamMetrics{VideoCodec: "h264s", VideoFrameRate: new(.9)}, streamQuality{poor, causeFrameRate, &qualityEvidence{"video_frame_rate", .9, 1}}},
		{"VBSS H264S missing fps", "sharing", "vbss", StreamMetrics{VideoCodec: "h264s", VideoFrameLossPercent: new(99.0)}, streamQuality{unclassified, causeNoMetrics, nil}},
		{"VBSS non-H264S lacks endpoint-relative direction", "sharing", "vbss", StreamMetrics{VideoCodec: "h264", VideoFrameRate: new(0.0), VideoFrameLossPercent: new(99.0)}, streamQuality{unclassified, causeUnsupportedShare, nil}},
		{"sharing with ambiguous label", "sharing", "screensharing", StreamMetrics{VideoCodec: "h264s", VideoFrameRate: new(0.0)}, streamQuality{unclassified, causeUnsupportedShare, nil}},
		{"legacy RDP has no tile metrics", "sharing", "main-appsharing", StreamMetrics{AverageRTTMs: new(999.0)}, streamQuality{unclassified, causeUnsupportedShare, nil}},
		{"new negotiation label", "unknown", "", StreamMetrics{}, streamQuality{unclassified, causeUnsupportedMedia, nil}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			for _, direction := range []string{"callerToCallee", "calleeToCaller"} {
				got := classifyStream(Stream{Media: tc.media, MediaLabel: tc.label, Direction: direction, Metrics: tc.metrics}, q)
				if !reflect.DeepEqual(got, tc.want) {
					t.Errorf("%s: health/cause/evidence = %q/%q/%+v, want %q/%q/%+v", direction, got.health, got.cause, got.evidence, tc.want.health, tc.want.cause, tc.want.evidence)
				}
			}
		})
	}
}

func TestCallQualityRollup(t *testing.T) {
	side := func(id, transport string) Side {
		return Side{Identity: Identity{ID: id}, Network: Network{Transport: transport, ReflexiveIP: "192.0.2.9"}}
	}
	measure := func(jitter float64, caller, callee Side) Stream {
		return Stream{Media: "audio", Caller: caller, Callee: callee,
			Metrics: StreamMetrics{PacketUtilization: new(int64(600)), AverageJitterMs: &jitter}}
	}
	a := side("a", "udp")
	b := side("b", "tcp")
	q := quality.Thresholds{MinPackets: 500, AudioJitterMs: 0} // explicit zero override
	for _, tc := range []struct {
		name      string
		streams   []Stream
		health    health
		poorCount int
		transport string
		sharedIP  bool
	}{
		{"empty", nil, unclassified, 0, "", false},
		{"unclassified", []Stream{{Media: "audio", Caller: a, Callee: a}}, unclassified, 0, "udp", false},
		{"one good and unclassified", []Stream{{Media: "video"}, measure(0, a, Side{})}, good, 0, "udp", false},
		{"poor takes priority, tie is mixed", []Stream{measure(1, a, b), measure(0, Side{}, Side{})}, poor, 1, "mixed", true},
		{"do not count both sides as two streams", []Stream{measure(0, a, a), measure(1, b, Side{}), measure(2, b, Side{})}, poor, 2, "tcp", true},
		{"no attribution without distinct known IDs", []Stream{measure(0, a, side("", "udp")), measure(0, a, a)}, good, 0, "udp", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := Call{Streams: tc.streams}
			assessCall(&c, q)
			g := c.quality
			if g.health != tc.health || g.poorStreams != tc.poorCount || g.dominantTransport != tc.transport || g.sharedReflexiveIP != tc.sharedIP {
				t.Errorf("roll-up = %q/%d/%q/%v, want %q/%d/%q/%v", g.health, g.poorStreams, g.dominantTransport, g.sharedReflexiveIP,
					tc.health, tc.poorCount, tc.transport, tc.sharedIP)
			}
		})
	}
}

func TestQualityEventsThroughPollAndDirect(t *testing.T) {
	// Synthetic, docs-derived Graph v1.0 shape; not a tenant capture.
	start := now.Add(-time.Minute)
	const id = "synthetic-quality"
	g := fakeGraph(func(address, prefer string) ([]byte, error) {
		switch address {
		case absolutePath + "/" + id + "?$expand=sessions($expand=segments)":
			return []byte(`{"id":"` + id + `","version":1,"startDateTime":"` + stamp(start) + `","sessions":[{"id":"session","segments":[{
				"id":"segment","startDateTime":"` + stamp(start) + `",
				"caller":{"associatedIdentity":{"id":"synthetic-caller"}},"callee":{"associatedIdentity":{"id":"synthetic-callee"}},
				"media":[{"label":"main-audio",
					"callerNetwork":{"connectionType":"wifi","networkTransportProtocol":"tcp","reflexiveIPAddress":"2001:db8::1","relayIPAddress":"192.0.2.1"},
					"calleeNetwork":{"connectionType":"wifi","networkTransportProtocol":"tcp","reflexiveIPAddress":"2001:0db8::1"},
					"callerDevice":{"cpuInsufficentEventRatio":0.1,"deviceGlitchEventRatio":0,"lowSpeechLevelEventRatio":0.02},
					"calleeDevice":{"deviceGlitchEventRatio":0.01},
					"streams":[{"streamId":"poor-audio","streamDirection":"calleeToCaller","packetUtilization":501,"averageRoundTripTime":"PT0S","averageJitter":"PT0.031S","maxJitter":"PT0.060S","maxAudioNetworkJitter":"PT0.070S","averagePacketLossRate":0}]
				},{"label":"main-appsharing","callerNetwork":{"connectionType":"wifi","networkTransportProtocol":"tcp"},
					"calleeDevice":{"cpuInsufficentEventRatio":0,"lowSpeechLevelEventRatio":0},
					"streams":[{"streamId":"rdp","streamDirection":"callerToCallee","averageRoundTripTime":"PT0.6S"}]
				}]
			}]}]}`), nil
		case absolutePath + "/" + id + "/participants_v2":
			return collection(t, ""), nil
		default:
			assertList(t, address, prefer)
			return collection(t, "", listEntry(id, 1, start)), nil
		}
	})
	var results [][]telemetrytest.LogRecord
	for _, direct := range []bool{false, true} {
		c := collectorForTest(t, collectors.WindowDeps{Graph: g, Store: checkpoint.NewStore(t.TempDir()), TenantID: "synthetic-tenant"})
		rec, outcomes := telemetrytest.New(), recordoutcome.NewRecorder()
		if direct {
			if err := c.CollectCall(t.Context(), id, rec.Emitter(), outcomes); err != nil {
				t.Fatal(err)
			}
		} else if _, err := c.CollectWindow(t.Context(), now.Add(-time.Hour), now, rec.Emitter(), outcomes); err != nil {
			t.Fatal(err)
		}
		logs := rec.LogRecords()
		if len(logs) != 3 {
			t.Fatalf("got %d records, want one call and two streams", len(logs))
		}
		assertAttrs(t, logs[0], map[string]string{
			"call_health": "poor", "poor_stream_count": "1", "worst_rtt_ms": "600", "worst_jitter_ms": "70",
			"worst_packet_loss_rate": "0", "dominant_transport": "tcp", "shared_reflexive_ip": "true",
		})
		assertAttrs(t, logs[1], map[string]string{
			"stream_health": "poor", "stream_health_cause": "jitter", "stream_health_metric": "average_jitter_ms",
			"stream_health_value": "31", "stream_health_threshold": "30", "caller_impact": "impacted", "callee_impact": "impacting",
			"caller_transport_evidence": "expected_udp", "caller_wifi_with_issue": "true", "caller_cpu_insufficient": "true",
			"caller_device_glitch": "false", "caller_low_speech_signal": "true", "callee_device_glitch": "true", "caller_relay_address_present": "true",
			"callee_wifi_with_issue": "true", "callee_transport_evidence": "expected_udp",
		})
		assertAttrs(t, logs[2], map[string]string{
			"stream_health": "unclassified", "stream_health_cause": "unsupported_sharing_stats", "caller_transport_evidence": "expected_rdp_tcp",
			"callee_cpu_insufficient": "false", "callee_low_speech_signal": "false",
		})
		for _, key := range []string{"callee_cpu_insufficient", "caller_relay_used"} {
			if _, ok := logs[1].Attrs[key]; ok {
				t.Errorf("unmeasured evidence emitted: %s", key)
			}
		}
		for _, key := range []string{"stream_health_value", "stream_health_threshold", "caller_impact", "callee_impact", "callee_transport_evidence", "caller_wifi_with_issue"} {
			if _, ok := logs[2].Attrs[key]; ok {
				t.Errorf("unsupported evidence emitted: %s", key)
			}
		}
		results = append(results, logs)
	}
	if !reflect.DeepEqual(results[0], results[1]) {
		t.Error("poll and direct fetch emitted different call quality records")
	}
}
