package numbers

import (
	"maps"
	"strings"
	"testing"

	"github.com/rknightion/graph2otel/internal/collectors/m365/teamsphone/internal/phonefixture"
	"github.com/rknightion/graph2otel/internal/semconv"
)

const numberURL = "https://graph.microsoft.com/v1.0/admin/teams/telephoneNumberManagement/numberAssignments?$top=1000"

// Field types come from the redacted v1.0 response shape
// (2026-11-24, #663). No values are copied from the tenant. Enum examples
// are from Graph's numberAssignment docs and numbers are reserved examples.
const numberRow = `{"id":"example-line-1","telephoneNumber":"+12025550101","activationState":"activated","assignmentStatus":"unassigned","assignmentCategory":null,"assignmentTargetId":null,"capabilities":["userAssignment","conferenceAssignment"],"city":"Example City","civicAddressId":null,"isoCountryCode":"US","locationId":null,"networkSiteId":null,"numberSource":"online","numberType":"callingPlan","operatorId":"example-operator","portInStatus":null,"reverseNumberLookupOptions":[],"supportedCustomerActions":["locationUpdate"]}`

func TestNumberInventoryCompletionTracksEachFullPoll(t *testing.T) {
	phonefixture.CheckCompletion(t, phonefixture.CompletionCase{
		Name: "teams.phone_numbers", URL: numberURL, Event: "m365.teams.phone_number", State: "assignment_status",
		Before: `"assignmentStatus":"unassigned"`, After: `"assignmentStatus":"userAssigned"`,
		OldState: "unassigned", NewState: "userAssigned",
	})
}

func TestPhoneNumbersFromGraph(t *testing.T) {
	next := numberURL + "&$skiptoken=example"
	rec := phonefixture.Collect(t, "teams.phone_numbers", phonefixture.Graph{
		numberURL: `{"value":[` + numberRow + `],"@odata.nextLink":"` + next + `"}`,
		next:      `{"value":[{"id":"example-line-2","telephoneNumber":"+12025550102","numberType":"example-new-type","assignmentStatus":"unassigned","activationState":"activated","capabilities":[]}]}`,
	})
	points := rec.MetricPoints("m365.teams.phone_numbers.total")
	want := map[string]string{"number_type": "callingPlan", "assignment_status": "unassigned", "activation_state": "activated", "capability": ""}
	seen := map[string]bool{}
	for _, p := range points {
		if semconv.MetricAdditive(p.Unit, p.Kind) {
			t.Errorf("overlapping capabilities must not be added to a synthetic other number count: %+v", p)
		}
		capability := p.Attrs["capability"]
		want["capability"] = capability
		want["number_type"] = "callingPlan"
		if capability == "none" {
			want["number_type"] = "unknown"
		}
		if !maps.Equal(p.Attrs, want) || p.Value != 1 {
			t.Errorf("unexpected phone count: %+v", p)
		}
		seen[capability] = true
	}
	if !maps.Equal(seen, map[string]bool{"userAssignment": true, "conferenceAssignment": true, "none": true}) {
		t.Errorf("capability buckets = %v", seen)
	}
	if got := rec.MetricPoints("m365.teams.phone_numbers.unassigned"); len(got) != 1 || got[0].Value != 2 || len(got[0].Attrs) != 0 {
		t.Errorf("unassigned count (one per number, not per capability) = %+v", got)
	}
	twins := rec.LogRecords()
	if len(twins) != 3 || twins[0].EventName != "m365.teams.phone_number" || !twins[0].Timestamp.IsZero() || !twins[1].Timestamp.IsZero() ||
		twins[0].Attrs["telephone_number"] != "+12025550101" || twins[0].Attrs["id"] != "example-line-1" ||
		twins[0].Attrs["operator_id"] != "example-operator" || twins[0].Attrs["assignment_target_id"] != "" ||
		twins[1].Attrs["number_type"] != "example-new-type" {
		t.Errorf("number twins = %+v", twins)
	}
}

func TestPhoneNumbersContinuesAfterFullOffsetPage(t *testing.T) {
	const row = `{"id":"example-assigned","assignmentStatus":"userAssigned","numberType":"callingPlan","activationState":"activated","capabilities":["userAssignment"]}`
	rec := phonefixture.Collect(t, "teams.phone_numbers", phonefixture.Graph{
		numberURL:                 `{"value":[` + strings.Repeat(row+",", 999) + row + `]}`,
		numberURL + "&$skip=1000": `{"value":[` + numberRow + `]}`,
	})
	if got := rec.MetricPoints("m365.teams.phone_numbers.unassigned"); len(got) != 1 || got[0].Value != 1 {
		t.Errorf("unassigned number from short second page = %+v, want 1", got)
	}
	if twins := rec.LogRecords(); len(twins) != 1002 || twins[1000].Attrs["id"] != "example-line-1" {
		t.Errorf("last number missing after offset page, got %d twins", len(twins))
	}
}
