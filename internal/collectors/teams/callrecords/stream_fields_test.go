package callrecords

import (
	"encoding/json"
	"os"
	"testing"
	"time"

	"github.com/rknightion/graph2otel/internal/checkpoint"
	"github.com/rknightion/graph2otel/internal/collectors"
	"github.com/rknightion/graph2otel/internal/telemetrytest"
)

func TestCallStreamMeasuredFields(t *testing.T) {
	// live-measured 2026-11-25, #708 (Teams observability review): the root
	// projected only these four fields from expanded Graph v1.0 streams. The
	// surrounding call and stream identifier in this test are synthetic.
	data, err := os.ReadFile("testdata/measured-media-stream-fields.json")
	if err != nil {
		t.Fatal(err)
	}
	var fragments []map[string]json.RawMessage
	if err := json.Unmarshal(data, &fragments); err != nil {
		t.Fatal(err)
	}
	if len(fragments) != 4 {
		t.Fatalf("expected four live-derived stream fragments, got %d", len(fragments))
	}

	// Derived edges, not extra measurements: omit the optional keys, then
	// mutate the observed integer bandwidth field to a reported zero.
	fragments = append(fragments, nil, map[string]json.RawMessage{"averageBandwidthEstimate": json.RawMessage("0")})
	for i, tc := range []struct {
		name                         string
		bandwidth, average, max, fec string
	}{
		{"null ratios and bandwidth, false FEC", "", "", "", "false"},
		{"zero ratios, null FEC", "", "0", "0", ""},
		{"nonzero ratios", "", "0.0005", "0.002997", "false"},
		{"nonzero bandwidth", "920568", "0", "0", "false"},
		{"omitted keys", "", "", "", ""},
		{"zero bandwidth", "0", "", "", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			const id = "stream-fields"
			d := syntheticDetail(t, id, 1, now.Add(-time.Hour))
			for key, value := range fragments[i] {
				firstAudioStream(d)[key] = value
			}
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
			c := collectorForTest(t, collectors.WindowDeps{Graph: g, Store: checkpoint.NewStore(t.TempDir())})
			rec := telemetrytest.New()
			if err := c.CollectCall(t.Context(), id, rec.Emitter(), nil); err != nil {
				t.Fatal(err)
			}
			for _, log := range rec.LogRecords() {
				if log.EventName != streamEvent || log.Attrs["stream_id"] != "audio-nosip" {
					continue
				}
				for key, want := range map[string]string{
					"average_bandwidth_estimate_bps": tc.bandwidth, "average_ratio_of_concealed_samples": tc.average,
					"max_ratio_of_concealed_samples": tc.max, "audio_fec_used": tc.fec,
				} {
					if got, ok := log.Attrs[key]; ok != (want != "") || got != want {
						t.Errorf("%s = %q (present %t), want %q (present %t)", key, got, ok, want, want != "")
					}
				}
				return
			}
			t.Fatal("missing dated audio stream")
		})
	}
}
