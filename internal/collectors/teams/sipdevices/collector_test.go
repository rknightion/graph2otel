package sipdevices

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/rknightion/graph2otel/internal/collectors"
	"github.com/rknightion/graph2otel/internal/recordoutcome"
	"github.com/rknightion/graph2otel/internal/telemetry"
	"github.com/rknightion/graph2otel/internal/telemetrytest"
)

const listPath = "/beta/teamwork/devices"

// The device and health objects are the redacted 2026-11-25 captures. The
// paging envelope, non-SIP control and failed read are synthetic controls.
func TestSIPDevicesFromGraph(t *testing.T) {
	payload, err := os.ReadFile("testdata/teamwork-devices.json")
	if err != nil {
		t.Fatal(err)
	}
	var rows []struct {
		Device json.RawMessage
		Health json.RawMessage
	}
	if err := json.Unmarshal(payload, &rows); err != nil {
		t.Fatal(err)
	}
	const first = "228bd6e5-2f19-4edd-a615-81b17b6e39eb"
	const second = "88080e2b-a309-4c43-82e4-7ff20c9ff14b"
	const next = listPath + "?$skiptoken=example"
	paths := map[string]string{
		listPath:                            fmt.Sprintf(`{"value":[%s,{"deviceType":"teamsPhone","id":"not-sip"}],"@odata.nextLink":"https://graph.microsoft.com%s"}`, rows[0].Device, next),
		next:                                fmt.Sprintf(`{"value":[%s]}`, rows[1].Device),
		listPath + "/" + first + "/health":  string(rows[0].Health),
		listPath + "/" + second + "/health": string(rows[1].Health),
	}
	for _, scenario := range []string{"measured", "health denied"} {
		t.Run(scenario, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				payload, ok := paths[r.URL.RequestURI()]
				if r.Method != http.MethodGet || !ok {
					t.Errorf("unexpected Graph request: %s %s", r.Method, r.URL.RequestURI())
					w.WriteHeader(http.StatusNotFound)
					return
				}
				if scenario == "health denied" && r.URL.Path == listPath+"/"+second+"/health" {
					w.WriteHeader(http.StatusForbidden)
					return
				}
				_, _ = io.WriteString(w, payload)
			}))
			defer server.Close()
			graph := fixtureGraph{server.URL, server.Client()}
			rec := telemetrytest.New()
			outcomes := recordoutcome.NewRecorder()
			for _, factory := range collectors.All() {
				c := factory(collectors.Deps{Graph: graph})
				if c.Name() != "teams.sip_devices" {
					continue
				}
				emitter := telemetry.WithTenant(telemetry.WithTransport(rec.Emitter(), telemetry.TransportGraph), "example-tenant")
				if err := c.Collect(t.Context(), emitter, outcomes); err != nil {
					t.Fatal(err)
				}
				want := recordoutcome.Counts{Fetched: 3, Mapped: 2, Emitted: 2, Filtered: 1}
				wantResult := recordoutcome.ResultSuccess
				if scenario == "health denied" {
					want.Mapped, want.Emitted, want.Errored = 1, 1, 1
					wantResult = recordoutcome.ResultPartial
				}
				snapshot := outcomes.Snapshot()
				if summary := snapshot.Summarize(nil, false); summary.Counts != want || summary.Result != wantResult {
					t.Errorf("summary = %+v, want %s with %+v", summary, wantResult, want)
				}
				logs := rec.LogRecords()
				if len(logs) != int(want.Emitted) {
					t.Fatalf("SIP device logs = %+v, want %d", logs, want.Emitted)
				}
				for i, log := range logs {
					attrs := log.Attrs
					if log.EventName != "m365.teams.sip_device" || attrs["device_id"] != []string{first, second}[i] ||
						attrs["health_status"] != "healthy" || attrs["connection_status"] != "connected" ||
						attrs["software_update_readout"] != "not_reported" || attrs["model"] != "Example" ||
						attrs["last_modified_date_time"] != "2026-01-02T00:00:00Z" ||
						attrs["tenant_id"] != "example-tenant" || attrs["ingest_transport"] != "graph" || !log.Timestamp.IsZero() {
						t.Errorf("unexpected SIP observation: %+v", log)
					}
				}
				if metrics := rec.MetricNames(); len(metrics) != 0 {
					t.Errorf("log-only inventory emitted metrics: %v", metrics)
				}
				return
			}
			t.Fatal("teams.sip_devices is not registered as a snapshot collector")
		})
	}
}

// fixtureGraph sends the raw request selected by the collector to the local
// HTTP fixture. It changes only the origin; the method, path and query survive.
type fixtureGraph struct {
	origin string
	client *http.Client
}

func (g fixtureGraph) RawGet(ctx context.Context, address string) ([]byte, error) {
	return g.RawGetWithHeaders(ctx, address, nil)
}

func (g fixtureGraph) RawGetWithHeaders(ctx context.Context, address string, headers map[string]string) ([]byte, error) {
	path, ok := strings.CutPrefix(address, "https://graph.microsoft.com/")
	if !ok {
		return nil, errors.New("unexpected Graph origin")
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, g.origin+"/"+path, nil)
	if err != nil {
		return nil, err
	}
	for key, value := range headers {
		req.Header.Set(key, value)
	}
	resp, err := g.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("fixture Graph status %d", resp.StatusCode)
	}
	return io.ReadAll(resp.Body)
}
