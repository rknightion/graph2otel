package callrecords

import (
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/rknightion/graph2otel/internal/checkpoint"
	"github.com/rknightion/graph2otel/internal/collectors"
	"github.com/rknightion/graph2otel/internal/recordoutcome"
	"github.com/rknightion/graph2otel/internal/teams/geoip"
	"github.com/rknightion/graph2otel/internal/teams/geoiptest"
	"github.com/rknightion/graph2otel/internal/telemetrytest"
)

func TestCallStreamGeoIP(t *testing.T) {
	reader, err := geoip.Open(geoiptest.ASN(t), geoiptest.City(t))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := reader.Close(); err != nil {
			t.Error(err)
		}
	})
	for _, tc := range []struct {
		name string
		poll bool
		db   *geoip.Reader
	}{
		{"poll", true, reader}, {"direct", false, reader}, {"disabled", false, nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			start := now.Add(-time.Hour)
			d := syntheticDetail(t, "geoip", 1, start)
			segment := d["sessions"].([]any)[0].(map[string]any)["segments"].([]any)[0].(map[string]any)
			media := segment["media"].([]any)
			// Public reflexive with a distinct relay, private reflexive, no
			// reflexive (despite other IPs), and reflexive equal to the relay.
			media[0].(map[string]any)["callerNetwork"] = map[string]any{"reflexiveIPAddress": "2fff::661", "relayIPAddress": "2fff::662"}
			private := netip.AddrFrom4([4]byte{10, 8, 7, 6}).String()
			media[0].(map[string]any)["calleeNetwork"] = map[string]any{"reflexiveIPAddress": private, "ipAddress": "2fff::661"}
			media[1].(map[string]any)["callerNetwork"] = map[string]any{"ipAddress": "2fff::661", "relayIPAddress": "2fff::662"}
			media[1].(map[string]any)["calleeNetwork"] = map[string]any{"reflexiveIPAddress": "2fff::662", "relayIPAddress": "2fff:0:0:0:0:0:0:662"}
			if !tc.poll {
				media[1].(map[string]any)["calleeNetwork"] = map[string]any{"reflexiveIPAddress": "2fff::663"}
			}
			g := fakeGraph(func(address, prefer string) ([]byte, error) {
				switch address {
				case absolutePath + "/geoip?$expand=sessions($expand=segments)":
					return encoded(t, d), nil
				case absolutePath + "/geoip/participants_v2":
					return peoplePage(t), nil
				default:
					assertList(t, address, prefer)
					return collection(t, "", listEntry("geoip", 1, start)), nil
				}
			})
			c := collectorForTest(t, collectors.WindowDeps{Graph: g, Store: checkpoint.NewStore(t.TempDir()), TeamsGeoIP: tc.db})
			rec := telemetrytest.New()
			outcomes := recordoutcome.NewRecorder()
			var err error
			if tc.poll {
				_, err = c.CollectWindow(t.Context(), now.Add(-2*time.Hour), now, rec.Emitter(), outcomes)
			} else {
				err = c.CollectCall(t.Context(), "geoip", rec.Emitter(), outcomes)
			}
			if err != nil {
				t.Fatal(err)
			}
			logs := rec.LogRecords()
			if len(logs) != 3 {
				t.Fatalf("want call and two streams, got %d records", len(logs))
			}
			for _, log := range logs {
				prefix := ""
				if tc.db != nil && log.EventName == streamEvent {
					switch log.Attrs["stream_id"] {
					case "audio-nosip":
						prefix = "caller_"
					case "video-sip":
						if !tc.poll {
							prefix = "callee_"
						}
					}
				}
				if prefix != "" {
					assertAttrs(t, log, map[string]string{
						prefix + "asn": "64512", prefix + "asn_organization": "Example Network",
						prefix + "geoip_country_code": "ZZ", prefix + "geoip_city": "Example City",
						prefix + "geoip_latitude": "0", prefix + "geoip_longitude": "12.5",
					})
				}
				for key := range log.Attrs {
					if strings.Contains(key, "trace_route") || (strings.Contains(key, "_geoip_") || strings.Contains(key, "_asn")) &&
						(prefix == "" || !strings.HasPrefix(key, prefix)) {
						t.Errorf("unexpected attribute %s on %s/%s", key, log.EventName, log.Attrs["stream_id"])
					}
				}
			}
		})
	}
}
