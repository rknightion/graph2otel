package callrecords

import (
	"testing"
	"time"

	"github.com/rknightion/graph2otel/internal/checkpoint"
	"github.com/rknightion/graph2otel/internal/collectors"
	"github.com/rknightion/graph2otel/internal/teams/quality"
	"github.com/rknightion/graph2otel/internal/telemetrytest"
)

func TestStreamMediaReplay(t *testing.T) {
	// live-measured, #708 (Teams observability review): 32 stored streams had
	// media_label=data. That attribute is the unchanged Graph media.label.
	// Only the label comes from the review; the enclosing records and all
	// other fields (including the omission of measurements) are synthetic.
	for _, tc := range []struct {
		name, label, media, health, cause string
		hasRTT, unexpected                bool
	}{
		{name: "data", label: "data", media: "data", health: "unclassified", cause: "unsupported_media"},
		{name: "data with reported RTT", label: "data", media: "data", health: "unclassified", cause: "unsupported_media", hasRTT: true},
		{name: "audio control", label: "main-audio", media: "audio", health: "poor", cause: "rtt", hasRTT: true},
		{name: "unknown control", label: "Future-Media", media: "unknown", health: "unclassified", cause: "unsupported_media", hasRTT: true, unexpected: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			const id = "media-replay"
			start := now.Add(-time.Hour)
			d := syntheticDetail(t, id, 1, start)
			d["modalities"] = []string{"audio", "data"} // identical for all stream labels
			segment := d["sessions"].([]any)[0].(map[string]any)["segments"].([]any)[0].(map[string]any)
			stream := map[string]any{"streamId": "replay-stream", "streamDirection": "callerToCallee"}
			if tc.hasRTT {
				stream["averageRoundTripTime"] = "PT0.75S"
				stream["packetUtilization"] = 650
			}
			segment["media"] = []any{map[string]any{
				"label": tc.label, "streams": []any{stream},
				"callerNetwork": map[string]any{"networkTransportProtocol": "tcp"},
			}}
			g := fakeGraph(func(address, _ string) ([]byte, error) {
				switch address {
				case absolutePath + "/" + id + "?$expand=sessions($expand=segments)":
					return encoded(t, d), nil
				case absolutePath + "/" + id + "/participants_v2":
					return collection(t, ""), nil
				default:
					t.Fatalf("unexpected request: %q", address)
					return nil, nil
				}
			})
			limits := quality.Thresholds{MinPackets: 500, AudioRTTMs: 500}
			c := collectorForTest(t, collectors.WindowDeps{Graph: g, Store: checkpoint.NewStore(t.TempDir()), TeamsQualityThresholds: &limits})
			rec := telemetrytest.New()
			if err := c.CollectCall(t.Context(), id, rec.Emitter(), nil); err != nil {
				t.Fatal(err)
			}

			logs := rec.LogRecords()
			if len(logs) != 2 || logs[0].EventName != "teams.call" || logs[1].EventName != "teams.call_stream" || !logs[1].Timestamp.Equal(start.Add(2*time.Second)) {
				t.Fatalf("expected one call and one dated stream: %+v", logs)
			}
			isAudio := tc.media == "audio"
			callAttrs := map[string]string{"call_health": tc.health, "poor_stream_count": "0", "modalities": `["audio","data"]`}
			attrs := map[string]string{"stream_id": "replay-stream", "media_label": tc.label, "media": tc.media, "stream_health": tc.health, "stream_health_cause": tc.cause}
			if isAudio {
				callAttrs["poor_stream_count"] = "1"
				attrs["stream_health_metric"], attrs["stream_health_value"], attrs["stream_health_threshold"] = "average_rtt_ms", "750", "500"
				attrs["caller_transport_evidence"] = "expected_udp"
			} else {
				for _, key := range []string{"stream_health_metric", "stream_health_value", "stream_health_threshold", "caller_transport_evidence", "caller_impact", "callee_impact", "audio_codec", "average_audio_network_jitter_ms", "audio_fec_used"} {
					if value, ok := logs[1].Attrs[key]; ok {
						t.Errorf("non-audio stream emitted %s=%q", key, value)
					}
				}
			}
			if tc.hasRTT {
				attrs["average_rtt_ms"], callAttrs["worst_rtt_ms"] = "750", "750"
			} else {
				if _, ok := logs[1].Attrs["average_rtt_ms"]; ok {
					t.Error("missing RTT was fabricated in the stream log")
				}
				if _, ok := logs[0].Attrs["worst_rtt_ms"]; ok {
					t.Error("missing RTT was fabricated in the call rollup")
				}
			}
			assertAttrs(t, logs[0], callAttrs)
			assertAttrs(t, logs[1], attrs)

			pts := rec.MetricPoints("teams.streams")
			if len(pts) != 1 || pts[0].Value != 1 || pts[0].Attrs["media"] != tc.media || pts[0].Attrs["stream_health"] != tc.health || pts[0].Attrs["stream_health_cause"] != tc.cause {
				t.Errorf("want one %s/%s/%s stream increment, got %+v", tc.media, tc.health, tc.cause, pts)
			}
			pts = rec.MetricPoints("teams.stream.rtt")
			if tc.hasRTT && (len(pts) != 1 || pts[0].Count != 1 || pts[0].Value != 0.75 || pts[0].Attrs["media"] != tc.media) || !tc.hasRTT && len(pts) != 0 {
				t.Errorf("RTT should be carried only if reported and under %q: %+v", tc.media, pts)
			}
			for _, name := range []string{"teams.stream.jitter", "teams.stream.packet_loss"} {
				if pts := rec.MetricPoints(name); len(pts) != 0 {
					t.Errorf("unreported measurement %s: %+v", name, pts)
				}
			}
			pts = rec.MetricPoints("teams.stream.transport")
			if isAudio && (len(pts) != 1 || pts[0].Value != 1 || pts[0].Attrs["transport"] != "tcp") || !isAudio && len(pts) != 0 {
				t.Errorf("only the audio control enters the audio transport metric: %+v", pts)
			}
			var unexpected float64
			for _, p := range rec.MetricPoints("graph2otel.api.unexpected") {
				if p.Attrs["collector"] == "teams.call_records" && p.Attrs["field"] == "media.label" && p.Attrs["kind"] == "unmapped_value" {
					unexpected += p.Value
				}
			}
			wantUnexpected := 0.0
			if tc.unexpected {
				wantUnexpected = 1
			}
			if unexpected != wantUnexpected {
				t.Errorf("unexpected media.label increments = %v, want %v", unexpected, wantUnexpected)
			}
		})
	}
}
