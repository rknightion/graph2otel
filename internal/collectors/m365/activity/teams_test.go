package activity

import (
	"encoding/json"
	"fmt"
	"maps"
	"strings"
	"testing"
	"time"

	"github.com/rknightion/graph2otel/internal/o365activityclient"
	"github.com/rknightion/graph2otel/internal/telemetrytest"
)

func TestTeamsAuditEndToEnd(t *testing.T) {
	// live-measured: synthetic values in the shapes of the #665 Management
	// Activity API capture. Distinct identifiers expose accidental substitution.
	const wire = `[
		{"Id":"created","Operation":"TeamCreated","TeamGuid":"team-opaque","TeamName":"Example Team","AADGroupId":"different-group"},
		{"Id":"settings","Operation":"TeamSettingChanged","TeamGuid":"team-opaque","TeamName":"Example Team","ModifiedProperties":[{"Name":"TestSetting","NewValue":"unmapped-field-sentinel"}]},
		{"Id":"channel","Operation":"ChannelAdded","TeamGuid":"team-opaque","TeamName":"Example Team","ChannelGuid":"channel-opaque","ChannelName":"Example Channel"},
		{"Id":"tab","Operation":"TabAdded","TeamGuid":"team-opaque","TeamName":"Example Team","ChannelGuid":"channel-opaque","ChannelName":"Example Channel","AddOnGuid":"tab::example-addon"},
		{"Id":"member","Operation":"MemberAdded","TeamGuid":"team-opaque","TeamName":"Example Team","Members":[
			{"DisplayName":"Example Member","OrganizationId":"example-org","Role":2,"UPN":"one@example.com","Unknown":"unmapped-field-sentinel"},
			{"DisplayName":"Another Member","OrganizationId":"other-org","Role":1,"UPN":"two@example.com"},
			{"UPN":"zero@example.com","Role":0},null,{"UPN":"missing@example.com","Role":1.5}]},
		{"Id":"session","Operation":"TeamsSessionStarted","ObjectId":"opaque-session-object","MeetingId":"unmapped-field-sentinel"}
	]`
	var records []map[string]any
	if err := json.Unmarshal([]byte(wire), &records); err != nil {
		t.Fatal(err)
	}
	for _, r := range records {
		r["CreationTime"] = "2026-01-02T03:04:05"
		r["Workload"] = "MicrosoftTeams"
		r["RecordType"] = 25
	}
	other := maps.Clone(records[4])
	other["Id"], other["Workload"] = "other", "SharePoint"
	admin := maps.Clone(records[4])
	admin["Id"], admin["Operation"], admin["RecordType"] = "admin", "TeamsAdminAction", 57

	large := maps.Clone(records[4])
	large["Id"] = "large"
	members := make([]any, 51)
	for i := range members {
		members[i] = map[string]any{"UPN": fmt.Sprintf("member-%d@example.com", i)}
	}
	large["Members"] = members
	wide := maps.Clone(records[4])
	wide["Id"] = "wide"
	wide["Members"] = []any{members[0], map[string]any{"DisplayName": strings.Repeat("<", 8192)}}
	records = append(records, other, admin, large, wide)

	c := newTestCollector(t, &fakeAPI{records: records}, o365activityclient.ContentGeneral)
	rec := telemetrytest.New()
	from, to := window()
	if _, err := c.CollectWindow(t.Context(), from, to, rec.Emitter(), nil); err != nil {
		t.Fatalf("CollectWindow: %v", err)
	}
	logs := rec.LogRecords()
	if len(logs) != len(records) {
		t.Fatalf("emitted %d logs, want %d", len(logs), len(records))
	}
	for _, log := range logs {
		a := log.Attrs
		id := strings.TrimSuffix(a["id"], "@Audit.General")
		if log.EventName != "m365.audit" || !log.Timestamp.Equal(time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)) {
			t.Errorf("%s: event/time changed: %q %v", id, log.EventName, log.Timestamp)
		}
		want := map[string]string{}
		switch id {
		case "created", "settings", "channel", "tab", "member", "large", "wide":
			want["team_guid"], want["team_name"] = "team-opaque", "Example Team"
		case "session", "admin", "other":
		default:
			t.Fatalf("unexpected record id %q", id)
		}
		if id == "channel" || id == "tab" {
			want["channel_guid"], want["channel_name"] = "channel-opaque", "Example Channel"
		}
		switch id {
		case "member":
			assertTeamsMembers(t, a["teams_members_json"], []map[string]any{
				{"display_name": "Example Member", "organization_id": "example-org", "role": float64(2), "upn": "one@example.com"},
				{"display_name": "Another Member", "organization_id": "other-org", "role": float64(1), "upn": "two@example.com"},
				{"upn": "zero@example.com", "role": float64(0)},
				{"upn": "missing@example.com"},
			})
		case "large":
			wantMembers := make([]map[string]any, 50)
			for i := range wantMembers {
				wantMembers[i] = map[string]any{"upn": fmt.Sprintf("member-%d@example.com", i)}
			}
			assertTeamsMembers(t, a["teams_members_json"], wantMembers)
			want["teams_members_truncated"] = "true"
		case "wide":
			assertTeamsMembers(t, a["teams_members_json"], []map[string]any{{"upn": "member-0@example.com"}})
			want["teams_members_truncated"] = "true"
		default:
			if _, ok := a["teams_members_json"]; ok {
				t.Errorf("%s: unexpected member projection", id)
			}
		}
		for _, key := range []string{"team_guid", "team_name", "channel_guid", "channel_name", "teams_members_truncated"} {
			got, present := a[key]
			value, expected := want[key]
			if got != value || present != expected {
				t.Errorf("%s: %s = %q (present %t), want %q (present %t)", id, key, got, present, value, expected)
			}
		}
		// AddOnGuid is emitted as served since #665; other records carry none.
		if got, want := a["teams_addon_id"], map[string]string{"tab": "tab::example-addon"}[id]; got != want {
			t.Errorf("%s: teams_addon_id = %q, want %q", id, got, want)
		}
		if id == "session" && a["object_id"] != "opaque-session-object" {
			t.Errorf("session object_id = %q, want opaque wire value", a["object_id"])
		}
		for _, forbidden := range []string{"unmapped-field-sentinel"} {
			if strings.Contains(log.Body, forbidden) {
				t.Errorf("%s: body leaked %q", id, forbidden)
			}
			for k, v := range a {
				if strings.Contains(v, forbidden) {
					t.Errorf("%s: attribute %s leaked %q", id, k, forbidden)
				}
			}
		}
	}
}

func assertTeamsMembers(t *testing.T, raw string, want []map[string]any) {
	t.Helper()
	var got []map[string]any
	if err := json.Unmarshal([]byte(raw), &got); err != nil {
		t.Errorf("teams_members_json is not a JSON array: %v", err)
		return
	}
	if len(got) != len(want) {
		t.Errorf("member rows = %d, want %d", len(got), len(want))
		return
	}
	for i := range want {
		if !maps.Equal(got[i], want[i]) {
			t.Errorf("member %d = %v, want %v", i, got[i], want[i])
		}
	}
}
