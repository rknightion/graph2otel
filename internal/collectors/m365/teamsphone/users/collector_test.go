package users

import (
	"maps"
	"testing"

	"github.com/rknightion/graph2otel/internal/collectors/m365/teamsphone/internal/phonefixture"
)

const userURL = "https://graph.microsoft.com/v1.0/admin/teams/userConfigurations"

// The two nested lists were empty on the wire. These fixtures deliberately
// retain that shape and do not claim coverage for populated policy objects.
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
	if len(twins) != 3 {
		t.Fatalf("user twins = %+v, want three", twins)
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
