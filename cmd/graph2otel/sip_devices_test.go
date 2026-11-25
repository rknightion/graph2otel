package main

import (
	"slices"
	"testing"
)

func TestSIPDeviceOptInAndPreflight(t *testing.T) {
	for _, profile := range []string{"graph", "teams"} {
		for _, override := range []string{"", "true", "false"} {
			t.Run(profile+"/"+override, func(t *testing.T) {
				const name = "teams.sip_devices"
				yaml := "profiles: [" + profile + "]\ntenants:\n  - tenant_id: " + profileTestTenant + "\n"
				if override != "" {
					yaml += "    collectors:\n      " + name + ": {enabled: " + override + "}\n"
				}
				cfg := loadProfileTestConfig(t, yaml)
				want := override == "true"
				source := setupProfileTestTenant(t, cfg)
				if got := slices.Contains(profileTestRegistryNames(source), name); got != want {
					t.Errorf("startup SIP collector active = %t, want %t", got, want)
				}
				reqs, err := requiredCollectorPermissions(cfg, profileTestTenant, allAvailabilityTestCapabilities())
				if err != nil {
					t.Fatal(err)
				}
				found := false
				for _, req := range reqs {
					if req.Name == name {
						found = true
						if !slices.Equal(req.Permissions, []string{"TeamworkDevice.Read.All"}) {
							t.Errorf("SIP device preflight permissions = %v, want only TeamworkDevice.Read.All", req.Permissions)
						}
					}
				}
				if found != want {
					t.Errorf("SIP device listed in preflight = %t, want %t", found, want)
				}
			})
		}
	}
}
