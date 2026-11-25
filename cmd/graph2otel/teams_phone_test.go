package main

import (
	"slices"
	"testing"

	"github.com/rknightion/graph2otel/internal/preflight"
)

func TestTeamsPhoneProfileAndPreflightDiscovery(t *testing.T) {
	const numberScope = "TeamsTelephoneNumber.Read.All"
	const userScope = "TeamsUserConfiguration.Read.All"
	want := map[string]string{"teams.phone_numbers": numberScope, "teams.user_configuration": userScope}
	for _, profile := range []string{"graph", "teams"} {
		t.Run(profile, func(t *testing.T) {
			cfg := loadProfileTestConfig(t, "profiles: ["+profile+"]\ntenants: [{tenant_id: \""+profileTestTenant+"\"}]\n")
			names := profileTestRegistryNames(setupProfileTestTenant(t, cfg))
			for name := range want {
				if !slices.Contains(names, name) {
					t.Errorf("%s is absent from %s startup", name, profile)
				}
			}
			reqs, err := requiredCollectorPermissions(cfg, profileTestTenant, allAvailabilityTestCapabilities())
			if err != nil {
				t.Fatal(err)
			}
			var phoneReqs []preflight.CollectorReq
			for _, req := range reqs {
				if scope, ok := want[req.Name]; ok {
					if !slices.Equal(req.Permissions, []string{scope}) || len(req.PermissionAlternatives) != 0 {
						t.Errorf("%s requires %v, alternatives %v; want exactly %s", req.Name, req.Permissions, req.PermissionAlternatives, scope)
					}
					phoneReqs = append(phoneReqs, req)
				}
			}
			if len(phoneReqs) != len(want) {
				t.Fatalf("discovered %v; want both Teams Phone requirements", phoneReqs)
			}
			for _, granted := range []string{numberScope, userScope} {
				missing := userScope
				if granted == userScope {
					missing = numberScope
				}
				if got := preflight.Check([]string{granted}, phoneReqs); got.OK || !slices.Equal(got.MissingAggregate, []string{missing}) {
					t.Errorf("with only %s granted, preflight = %+v; want missing %s", granted, got, missing)
				}
			}
			if got := preflight.Check([]string{numberScope, userScope}, phoneReqs); !got.OK {
				t.Errorf("both exact read scopes granted: %+v", got)
			}
		})
	}
}
