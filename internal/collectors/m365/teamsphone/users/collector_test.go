package users

import (
	"encoding/json"
	"maps"
	"os"
	"testing"

	"github.com/rknightion/graph2otel/internal/collectors/m365/teamsphone/internal/inventory"
	"github.com/rknightion/graph2otel/internal/collectors/m365/teamsphone/internal/phonefixture"
	"github.com/rknightion/graph2otel/internal/recordoutcome"
	"github.com/rknightion/graph2otel/internal/telemetrytest"
)

const userURL = "https://graph.microsoft.com/v1.0/admin/teams/userConfigurations"

// The original #663 (Teams Phone inventory) rows had empty arrays.
const voiceUser = `{"id":"example-user-1","userPrincipalName":"voice@example.com","accountType":"user","isEnterpriseVoiceEnabled":true,"createdDateTime":"2026-11-01T11:00:00Z","modifiedDateTime":"2026-11-20T13:05:00.1234567Z","featureTypes":["Teams","CallingPlan"],"effectivePolicyAssignments":[],"telephoneNumbers":[],"tenantId":"example-tenant"}`

func TestUserConfigurationsFromGraph(t *testing.T) {
	next := userURL + "?$skiptoken=example"
	rec := phonefixture.Collect(t, "teams.user_configuration", phonefixture.Graph{
		userURL: `{"value":[` + voiceUser + `],"@odata.nextLink":"` + next + `"}`,
		next: `{"value":[
			{"id":"example-user-2","userPrincipalName":"resource@example.com","accountType":"resourceAccount","isEnterpriseVoiceEnabled":false,"createdDateTime":"2026-11-03T00:00:00Z","modifiedDateTime":"0001-01-01T00:00:00Z","featureTypes":[],"effectivePolicyAssignments":[],"telephoneNumbers":[]},
			{"id":"example-user-3","accountType":"example-new-type"}]}`,
	})
	want := map[[2]string]float64{{"user", "true"}: 1, {"resourceAccount", "false"}: 1, {"unknown", "unknown"}: 1}
	got := map[[2]string]float64{}
	for _, p := range rec.MetricPoints("m365.teams.user_configuration.users") {
		if len(p.Attrs) != 2 {
			t.Errorf("unexpected user label: %+v", p)
		}
		got[[2]string{p.Attrs["account_type"], p.Attrs["enterprise_voice_enabled"]}] = p.Value
	}
	if !maps.Equal(got, want) {
		t.Errorf("user counts = %v, want %v", got, want)
	}
	twins := rec.LogRecords()
	if len(twins) != 4 {
		t.Fatalf("user records = %+v, want three twins and a completion", twins)
	}
	if twins[0].EventName != "m365.teams.user_configuration" || !twins[0].Timestamp.IsZero() || !twins[1].Timestamp.IsZero() || !twins[2].Timestamp.IsZero() ||
		twins[0].Attrs["modified_date_time"] != "2026-11-20T13:05:00.1234567Z" || twins[1].Attrs["created_date_time"] != "2026-11-03T00:00:00Z" ||
		twins[0].Attrs["id"] != "example-user-1" || twins[0].Attrs["user_principal_name"] != "voice@example.com" ||
		twins[0].Attrs["enterprise_voice_enabled"] != "true" || twins[0].Attrs["feature_types"] == "" ||
		twins[1].Attrs["enterprise_voice_enabled"] != "false" || twins[2].Attrs["enterprise_voice_enabled"] != "" ||
		twins[2].Attrs["account_type"] != "example-new-type" {
		t.Errorf("user twins = %+v", twins)
	}
}

func TestSuccessfulEmptyPolicyPollPublishesZeroForEachBoundedBucket(t *testing.T) {
	for _, tc := range []struct {
		name, body string
		twins      int
	}{
		{"no assignments", `{"value":[` + voiceUser + `]}`, 1},
		{"no users", `{"value":[]}`, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := users{inventory.New(phonefixture.Graph{userURL: tc.body}, usersName, usersScope, nil)}
			rec := telemetrytest.New()
			if err := c.Collect(t.Context(), rec.Emitter(), recordoutcome.NewRecorder()); err != nil {
				t.Fatal(err)
			}
			if len(rec.LogRecords()) != tc.twins {
				t.Fatalf("got %d user twins; want %d", len(rec.LogRecords()), tc.twins)
			}
			points := rec.MetricPoints("m365.teams.user_configuration.effective_policy_assignments")
			want := map[string]float64{"TeamsCallingPolicy": 0, "OnlineVoiceRoutingPolicy": 0, "unknown": 0}
			if len(points) != len(want) {
				t.Fatalf("got %d policy points after a complete empty policy poll; want %d explicit zeroes", len(points), len(want))
			}
			got := map[string]float64{}
			for _, point := range points {
				got[point.Attrs["policy_type"]] = point.Value
			}
			if !maps.Equal(got, want) {
				t.Errorf("policy points = %v; want %v", got, want)
			}
		})
	}
}

func TestUserConfigurationsPreserveObservedAssignments(t *testing.T) {
	// Minimal subset of the live-measured 2026-11-25 response for #708
	// (Teams observability review), with synthetic identifiers and one future policy type.
	body, err := os.ReadFile("testdata/populated.json")
	if err != nil {
		t.Fatal(err)
	}
	rec := phonefixture.Collect(t, "teams.user_configuration", phonefixture.Graph{userURL: string(body)})
	twins := rec.LogRecords()
	var policies []struct {
		PolicyType       string
		PolicyAssignment struct{ AssignmentType, DisplayName, PolicyID string }
	}
	if err := json.Unmarshal([]byte(twins[0].Attrs["effective_policy_assignments"]), &policies); err != nil {
		t.Errorf("decode policy list on user twin: %v", err)
	} else if len(policies) != 1 || policies[0].PolicyType != "TeamsCallingPolicy" ||
		policies[0].PolicyAssignment.AssignmentType != "direct" || policies[0].PolicyAssignment.PolicyID != "example-policy-1" ||
		policies[0].PolicyAssignment.DisplayName != "Example policy" {
		t.Errorf("log did not preserve the nested policy assignment: %+v", policies)
	}
	var numbers []struct{ AssignmentCategory, TelephoneNumber string }
	if err := json.Unmarshal([]byte(twins[0].Attrs["telephone_numbers"]), &numbers); err != nil {
		t.Errorf("decode number list on user twin: %v", err)
	} else if len(numbers) != 1 || numbers[0].AssignmentCategory != "primary" || numbers[0].TelephoneNumber != "+12025550100" {
		t.Errorf("log did not preserve the number assignment: %+v", numbers)
	}
	if twins[1].Attrs["effective_policy_assignments"] != "" || twins[1].Attrs["telephone_numbers"] != "" ||
		twins[2].Attrs["telephone_numbers"] != "" {
		t.Errorf("empty arrays produced assignment evidence: %+v", twins[1:3])
	}
	got := map[string]float64{}
	for _, p := range rec.MetricPoints("m365.teams.user_configuration.effective_policy_assignments") {
		if len(p.Attrs) != 1 {
			t.Errorf("unexpected policy metric labels: %+v", p)
		}
		got[p.Attrs["policy_type"]] += p.Value
	}
	if want := (map[string]float64{"TeamsCallingPolicy": 1, "OnlineVoiceRoutingPolicy": 1, "unknown": 1}); !maps.Equal(got, want) {
		t.Errorf("policy counts = %v, want %v", got, want)
	}
}
