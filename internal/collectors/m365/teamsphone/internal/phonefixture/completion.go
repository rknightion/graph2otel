package phonefixture

import (
	"encoding/hex"
	"fmt"
	"maps"
	"testing"

	"github.com/rknightion/graph2otel/internal/collectors"
	"github.com/rknightion/graph2otel/internal/recordoutcome"
	"github.com/rknightion/graph2otel/internal/telemetry"
	"github.com/rknightion/graph2otel/internal/telemetrytest"
)

// CompletionCase describes the source and observed values for a collector's poll replay.
type CompletionCase struct {
	Name, URL, Event, State string
	Before, After           string
	OldState, NewState      string
}

// CheckCompletion runs inside each collector's signal gate so its own logs and
// metrics remain the capture authority. It exercises the registered poller.
func CheckCompletion(t *testing.T, tc CompletionCase) {
	t.Helper()
	graph := Graph{}
	var poller func(telemetry.Emitter) error
	for _, build := range collectors.All() {
		c := build(collectors.Deps{Graph: graph})
		if c.Name() == tc.Name {
			poller = func(e telemetry.Emitter) error { return c.Collect(t.Context(), e, recordoutcome.NewRecorder()) }
			break
		}
	}
	if poller == nil {
		t.Fatal("collector not registered")
	}
	next := "https://graph.microsoft.com/v1.0/example-next-page"
	seen := map[string]bool{}
	for _, poll := range []struct {
		name, tenant, page, nextPage string
		want                         map[string]string // source ID to assignment/voice state; nil means failure
	}{
		{"initial", "one", fmt.Sprintf(`{"value":[{"id":"retained",%s}],"@odata.nextLink":%q}`, tc.Before, next),
			fmt.Sprintf(`{"value":[{"id":"removed",%s}]}`, tc.Before), map[string]string{"retained": tc.OldState, "removed": tc.OldState}},
		{"changed", "one", fmt.Sprintf(`{"value":[{"id":"retained",%s}]}`, tc.After), "", map[string]string{"retained": tc.NewState}},
		{"other tenant", "two", fmt.Sprintf(`{"value":[{"id":"retained",%s}]}`, tc.Before), "", map[string]string{"retained": tc.OldState}},
		{"empty", "one", `{"value":[]}`, "", map[string]string{}},
		{"page failure", "one", fmt.Sprintf(`{"value":[{"id":"retained",%s}],"@odata.nextLink":%q}`, tc.After, next), "", nil},
		{"decode failure", "one", `{"value":[{"id":"retained"},{"id":23}]}`, "", nil},
		{"null row", "one", `{"value":[{"id":"retained"},null]}`, "", nil},
	} {
		t.Run(poll.name, func(t *testing.T) {
			graph[tc.URL] = poll.page
			delete(graph, next)
			if poll.nextPage != "" {
				graph[next] = poll.nextPage
			}
			rec := telemetrytest.New()
			err := poller(telemetry.WithTenant(rec.Emitter(), poll.tenant))
			logs := rec.LogRecords()
			if poll.want == nil {
				if err == nil || len(logs) != 0 {
					t.Fatalf("failed poll published inventory: error %v, records %+v", err, logs)
				}
				return
			}
			if err != nil || len(logs) != len(poll.want)+1 {
				t.Fatalf("expected all twins then one completion, error %v, records %+v", err, logs)
			}
			marker := logs[len(logs)-1]
			id := marker.Attrs["snapshot_id"]
			decoded, decodeErr := hex.DecodeString(id)
			if marker.EventName != "m365.teams.phone_inventory_snapshot" || decodeErr != nil || len(decoded) != 16 || seen[id] ||
				marker.Attrs["collector"] != tc.Name || marker.Attrs["tenant_id"] != poll.tenant ||
				marker.Attrs["entity_count"] != fmt.Sprint(len(poll.want)) {
				t.Fatalf("incorrect completion marker: %+v", marker)
			}
			seen[id] = true
			got := map[string]string{}
			for _, row := range logs[:len(logs)-1] {
				if row.EventName != tc.Event || row.Attrs["snapshot_id"] != id || row.Attrs["tenant_id"] != poll.tenant {
					t.Errorf("row in the wrong inventory snapshot: %+v", row)
				}
				got[row.Attrs["id"]] = row.Attrs[tc.State]
			}
			if !maps.Equal(got, poll.want) {
				t.Errorf("snapshot rows = %v, want %v", got, poll.want)
			}
		})
	}
}
