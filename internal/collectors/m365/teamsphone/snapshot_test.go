package teamsphone_test

import (
	"fmt"
	"maps"
	"testing"

	"github.com/rknightion/graph2otel/internal/collectors"
	"github.com/rknightion/graph2otel/internal/collectors/m365/teamsphone/internal/phonefixture"
	_ "github.com/rknightion/graph2otel/internal/collectors/m365/teamsphone/numbers"
	_ "github.com/rknightion/graph2otel/internal/collectors/m365/teamsphone/users"
	"github.com/rknightion/graph2otel/internal/recordoutcome"
	"github.com/rknightion/graph2otel/internal/telemetry"
	"github.com/rknightion/graph2otel/internal/telemetrytest"
)

func TestInventoryCompletionTracksEachFullPoll(t *testing.T) {
	for _, tc := range []struct{ name, url, event, state, before, after string }{
		{"teams.phone_numbers", "https://graph.microsoft.com/v1.0/admin/teams/telephoneNumberManagement/numberAssignments?$top=1000",
			"m365.teams.phone_number", "assignment_status", `"assignmentStatus":"unassigned"`, `"assignmentStatus":"userAssigned"`},
		{"teams.user_configuration", "https://graph.microsoft.com/v1.0/admin/teams/userConfigurations",
			"m365.teams.user_configuration", "enterprise_voice_enabled", `"isEnterpriseVoiceEnabled":false`, `"isEnterpriseVoiceEnabled":true`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			graph := phonefixture.Graph{}
			var poller func(telemetry.Emitter) error
			for _, build := range collectors.All() {
				c := build(collectors.Deps{Graph: graph})
				if c.Name() == tc.name {
					poller = func(e telemetry.Emitter) error { return c.Collect(t.Context(), e, recordoutcome.NewRecorder()) }
					break
				}
			}
			if poller == nil {
				t.Fatal("collector not registered")
			}
			oldState, newState := "unassigned", "userAssigned"
			if tc.state == "enterprise_voice_enabled" {
				oldState, newState = "false", "true"
			}
			next := "https://graph.microsoft.com/v1.0/example-next-page"
			seen := map[string]bool{}
			for _, poll := range []struct {
				name, tenant, page, nextPage string
				want                         map[string]string // source ID to assignment/voice state; nil means failure
			}{
				{"initial", "one", fmt.Sprintf(`{"value":[{"id":"retained",%s}],"@odata.nextLink":%q}`, tc.before, next),
					fmt.Sprintf(`{"value":[{"id":"removed",%s}]}`, tc.before), map[string]string{"retained": oldState, "removed": oldState}},
				{"changed", "one", fmt.Sprintf(`{"value":[{"id":"retained",%s}]}`, tc.after), "", map[string]string{"retained": newState}},
				{"other tenant", "two", fmt.Sprintf(`{"value":[{"id":"retained",%s}]}`, tc.before), "", map[string]string{"retained": oldState}},
				{"empty", "one", `{"value":[]}`, "", map[string]string{}},
				{"page failure", "one", fmt.Sprintf(`{"value":[{"id":"retained",%s}],"@odata.nextLink":%q}`, tc.after, next), "", nil},
				{"decode failure", "one", `{"value":[{"id":"retained"},{"id":23}]}`, "", nil},
				{"null row", "one", `{"value":[{"id":"retained"},null]}`, "", nil},
			} {
				t.Run(poll.name, func(t *testing.T) {
					graph[tc.url] = poll.page
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
					if marker.EventName != "m365.teams.phone_inventory_snapshot" || id == "" || len(id) > 32 || seen[id] ||
						marker.Attrs["collector"] != tc.name || marker.Attrs["tenant_id"] != poll.tenant ||
						marker.Attrs["entity_count"] != fmt.Sprint(len(poll.want)) {
						t.Fatalf("incorrect completion marker: %+v", marker)
					}
					seen[id] = true
					got := map[string]string{}
					for _, row := range logs[:len(logs)-1] {
						if row.EventName != tc.event || row.Attrs["snapshot_id"] != id || row.Attrs["tenant_id"] != poll.tenant {
							t.Errorf("row in the wrong inventory snapshot: %+v", row)
						}
						got[row.Attrs["id"]] = row.Attrs[tc.state]
					}
					if !maps.Equal(got, poll.want) {
						t.Errorf("snapshot rows = %v, want %v", got, poll.want)
					}
				})
			}
		})
	}
}
