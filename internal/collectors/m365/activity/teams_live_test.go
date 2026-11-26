package activity

import (
	"encoding/json"
	"maps"
	"os"
	"strings"
	"testing"

	"github.com/rknightion/graph2otel/internal/o365activityclient"
	"github.com/rknightion/graph2otel/internal/telemetrytest"
)

// teamsLiveKeys are the Teams audit attributes added for meeting, call, app and
// join detail (#665). Every one must be present exactly where the test expects
// it and absent everywhere else, so a projection onto the wrong operation fails.
var teamsLiveKeys = []string{
	"teams_meeting_detail_id", "call_id",
	"teams_join_time", "teams_leave_time", "teams_joined_from_lobby",
	"teams_meeting_start_time", "teams_meeting_end_time", "teams_meeting_url",
	"teams_communication_type", "teams_communication_sub_type", "teams_modalities", "teams_provider_types",
	"teams_organizer_object_id", "teams_organizer_organization_id",
	"teams_attendees_count", "teams_attendees_truncated", "teams_members_count",
	"user_agent", "teams_users_invited_during_meeting", "teams_rtmp_in_enabled",
	"teams_device_id", "teams_device_information",
	"teams_addon_id", "teams_addon_type_id", "teams_addon_name", "teams_tab_type",
	"teams_has_foreign_tenant_users", "teams_has_guest_users", "teams_has_other_guest_users",
	"teams_has_unauthenticated_users", "teams_participating_tenant_ids",
}

// TestTeamsAuditLiveShapes drives redacted live Audit.General records through
// the collector. live-measured 2026-11-26 (#665): the fixture is twelve records
// read as the poller from the 2026-11-25 lab window and the meetings and calls
// after it. Identifiers are placeholders; field names, nesting, types and
// non-identifying values are as served, except that the browser version reads
// 127.0.0.0 and the chat thread host ends in .example, so the privacy sweep
// does not take them for an address and a mailbox.
func TestTeamsAuditLiveShapes(t *testing.T) {
	raw, err := os.ReadFile("testdata/teams_audit_live.json")
	if err != nil {
		t.Fatal(err)
	}
	var records []map[string]any
	if err := json.Unmarshal(raw, &records); err != nil {
		t.Fatal(err)
	}

	const (
		tenant      = "00000000-0000-4000-8000-000000000002"
		channelMtg  = "00000000-0000-4000-8000-000000000001"
		pstnMtg     = "00000000-0000-4000-8000-000000000006"
		webAgent    = "SkypeSpaces/1415/26110100716/os=linux; osVer=undefined; deviceType=computer; browser=chrome; browserVer=127.0.0.0/TsCallingVersion=2026.42.01.12/Ovb=611c636ac53930844697ebcd9b226941eab6cbd4"
		signalAgent = "CallSignalingAgent (50/26304.1206.5384.1209/26110100716;release_user/verif_delivery/ahtilego/bp_4828384_r42/20261029t165428z.2026.42.01.12;releases/CL2026.R42)"
	)
	want := map[string]map[string]string{
		// MeetingDetail for a channel meeting.
		channelMtg: {
			"teams_communication_type": "Meeting", "teams_communication_sub_type": "AdHocMeeting, ChannelMeeting",
			"teams_modalities": "Audio", "teams_provider_types": "Teams",
			"teams_meeting_start_time": "2026-11-25T15:14:04Z", "teams_meeting_end_time": "2026-11-25T15:15:22Z",
			"teams_meeting_url":         "teams.microsoft.com/l/meetup-join/19%3a00000000000000000000000000000001%40thread.tacv2/1700000000001?context=%7b%22Tid%22%3a%2200000000-0000-4000-8000-000000000002%22%2c%22Oid%22%3a%2200000000-0000-4000-8000-000000000003%22%7d",
			"teams_organizer_object_id": "00000000-0000-4000-8000-000000000003", "teams_organizer_organization_id": tenant,
			"user_agent": webAgent, "teams_users_invited_during_meeting": "false", "teams_rtmp_in_enabled": "false",
		},
		// MeetingParticipantDetail for that meeting: MeetingDetailId is the
		// MeetingDetail record's Id.
		"00000000-0000-4000-8000-000000000004": {
			"teams_meeting_detail_id": channelMtg,
			"teams_join_time":         "2026-11-25T15:14:04Z", "teams_leave_time": "2026-11-25T15:15:22Z",
			"teams_joined_from_lobby":   "false",
			"teams_organizer_object_id": "00000000-0000-4000-8000-000000000003", "teams_organizer_organization_id": tenant,
			"teams_attendees_count": "1", "user_agent": webAgent,
			"teams_device_id": "00000000-0000-4000-8000-000000000005", "teams_device_information": "PC",
		},
		// MeetingDetail for an escalated PSTN call, with no channel or URL.
		pstnMtg: {
			"teams_communication_type": "Meeting", "teams_communication_sub_type": "AdHocMeeting, Transfer, Escalation",
			"teams_modalities": "Audio", "teams_provider_types": "Teams, PSTN",
			"teams_meeting_start_time": "2026-11-25T11:26:33Z", "teams_meeting_end_time": "2026-11-25T11:27:21Z",
			"teams_organizer_object_id": "00000000-0000-4000-8000-000000000007", "teams_organizer_organization_id": tenant,
			"user_agent": signalAgent, "teams_users_invited_during_meeting": "true", "teams_rtmp_in_enabled": "false",
		},
		// A bot participant invited into that meeting.
		"00000000-0000-4000-8000-000000000008": {
			"teams_meeting_detail_id": pstnMtg,
			"teams_join_time":         "2026-11-25T11:26:46Z", "teams_leave_time": "2026-11-25T11:27:01Z",
			"teams_joined_from_lobby":   "false",
			"teams_organizer_object_id": "00000000-0000-4000-8000-000000000007", "teams_organizer_organization_id": tenant,
			"teams_attendees_count": "1",
			"user_agent":            "appid:00000000-0000-4000-8000-000000000009 Microsoft.Skype.Platform.Echo.Logic/1.11.2358.0",
		},
		// Two sides of one missed PSTN call: join and leave are equal on the wire.
		"00000000-0000-4000-8000-000000000010": {
			"call_id":         "00000000-0000-4000-8000-000000000011",
			"teams_join_time": "2026-11-25T11:04:47Z", "teams_leave_time": "2026-11-25T11:04:47Z",
			"teams_attendees_count": "1", "user_agent": "pstn (Teams/)", "teams_participating_tenant_ids": tenant,
		},
		"00000000-0000-4000-8000-000000000012": {
			"call_id":         "00000000-0000-4000-8000-000000000011",
			"teams_join_time": "2026-11-25T11:04:47Z", "teams_leave_time": "2026-11-25T11:04:47Z",
			"teams_attendees_count": "1", "user_agent": signalAgent, "teams_participating_tenant_ids": tenant,
		},
		// AppDeleted carries a bare GUID; TabAdded prefixes it with "tab::".
		"00000000-0000-4000-8000-000000000014": {
			"teams_addon_id": "00000000-0000-4000-8000-000000000016", "teams_addon_type_id": "4",
		},
		"00000000-0000-4000-8000-000000000017": {
			"teams_addon_id": "tab::00000000-0000-4000-8000-000000000020", "teams_addon_type_id": "3",
			"teams_addon_name": "Notes", "teams_tab_type": "extension", "teams_communication_type": "Channel",
			"teams_has_foreign_tenant_users": "false", "teams_has_guest_users": "false", "teams_has_unauthenticated_users": "false",
		},
		"00000000-0000-4000-8000-000000000022": {"teams_device_id": "00000000-0000-4000-8000-000000000023"},
		"00000000-0000-4000-8000-000000000024": {"teams_device_information": "MacT21"},
		// Chat records carry the fourth external-participation flag.
		"00000000-0000-4000-8000-000000000027": {
			"teams_communication_type": "GroupChat", "teams_participating_tenant_ids": tenant,
			"teams_has_foreign_tenant_users": "false", "teams_has_guest_users": "false",
			"teams_has_other_guest_users": "false", "teams_has_unauthenticated_users": "false",
		},
		// The live missed-call record with 51 copies of its attendee: the list
		// is capped at 50 rows and the wire count is kept.
		"bounds": {
			"call_id":         "00000000-0000-4000-8000-000000000011",
			"teams_join_time": "2026-11-25T11:04:47Z", "teams_leave_time": "2026-11-25T11:04:47Z",
			"teams_attendees_count": "51", "teams_attendees_truncated": "true",
			"user_agent": "pstn (Teams/)", "teams_participating_tenant_ids": tenant,
		},
		"00000000-0000-4000-8000-000000000025": {
			"teams_communication_type": "Team", "teams_members_count": "2",
			"teams_has_foreign_tenant_users": "false", "teams_has_guest_users": "false", "teams_has_unauthenticated_users": "false",
		},
	}
	attendees := map[string][]map[string]any{
		"00000000-0000-4000-8000-000000000004": {{
			"organization_id": tenant, "recipient_type": "InternalFederated",
			"user_object_id": "00000000-0000-4000-8000-000000000003", "display_name": "Example Person 1",
			"role": float64(1), "upn": "person1@example.com",
		}},
		"00000000-0000-4000-8000-000000000008": {{
			"display_name": "00000000-0000-4000-8000-000000000009", "role": float64(1),
			"inviter": map[string]any{
				"invite_time": "2026-11-25T11:26:46", "organization_id": tenant, "user_type": "Teams",
				"display_name": "Example Person 2", "upn": "person2@example.com",
				"user_identifier": "orgid:00000000-0000-4000-8000-000000000007",
			},
		}},
		"00000000-0000-4000-8000-000000000010": {{
			"is_aad_guest": false, "is_organizer": false, "provider_type": "Teams, PSTN",
			"user_id_type": "PstnNumber", "display_name": "+15555550001", "role": float64(1),
		}},
		"00000000-0000-4000-8000-000000000012": {{
			"is_aad_guest": false, "is_organizer": true, "organization_id": tenant, "provider_type": "Teams, PSTN",
			"recipient_type": "InternalFederated", "user_id_type": "ObjectId",
			"user_object_id": "00000000-0000-4000-8000-000000000007", "display_name": "Example Person 2",
			"role": float64(1), "upn": "person2@example.com",
		}},
	}

	bounds := maps.Clone(records[4])
	bounds["Id"] = "bounds"
	many := make([]any, 51)
	for i := range many {
		many[i] = records[4]["Attendees"].([]any)[0]
	}
	bounds["Attendees"] = many
	records = append(records, bounds)
	wantBounds := make([]map[string]any, 50)
	for i := range wantBounds {
		wantBounds[i] = attendees["00000000-0000-4000-8000-000000000010"][0]
	}
	attendees["bounds"] = wantBounds

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
		exp, ok := want[id]
		if !ok {
			t.Fatalf("unexpected record id %q", id)
		}
		for _, key := range teamsLiveKeys {
			got, present := a[key]
			value, expected := exp[key]
			if got != value || present != expected {
				t.Errorf("%s (%s): %s = %q (present %t), want %q (present %t)", id, a["operation"], key, got, present, value, expected)
			}
		}
		if wantAtt, ok := attendees[id]; ok {
			assertJSONRows(t, id, a["teams_attendees_json"], wantAtt)
		} else if _, ok := a["teams_attendees_json"]; ok {
			t.Errorf("%s: unexpected attendee projection", id)
		}
	}
}

func assertJSONRows(t *testing.T, id, raw string, want []map[string]any) {
	t.Helper()
	var got []map[string]any
	if err := json.Unmarshal([]byte(raw), &got); err != nil {
		t.Errorf("%s: attendees are not a JSON array: %v", id, err)
		return
	}
	gotJSON, _ := json.Marshal(got)
	wantJSON, _ := json.Marshal(want)
	if string(gotJSON) != string(wantJSON) {
		t.Errorf("%s: attendees =\n%s\nwant\n%s", id, gotJSON, wantJSON)
	}
}
