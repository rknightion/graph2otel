package config

import (
	"fmt"

	"github.com/rknightion/graph2otel/internal/profile"
)

// SelectedProfiles resolves the tenant's replacement list, the global list,
// or Graph for an unset configuration.
func (c *Config) SelectedProfiles(tenantID string) profile.Set {
	profiles := c.Profiles
	for _, tenant := range c.Tenants {
		if tenant.TenantID == tenantID && tenant.Profiles != nil {
			profiles = tenant.Profiles
			break
		}
	}
	if profiles == nil {
		return profile.Graph
	}
	var set profile.Set
	for _, name := range profiles {
		set |= profile.Parse(name)
	}
	return set
}

func validateProfiles(profiles []string, path string) error {
	if profiles == nil {
		return nil
	}
	if len(profiles) == 0 {
		return fmt.Errorf("%s: select at least one of graph and teams", path)
	}
	var seen profile.Set
	for _, name := range profiles {
		bit := profile.Parse(name)
		if bit == 0 {
			return fmt.Errorf("%s: unknown profile %q; expected graph or teams", path, name)
		}
		if seen&bit != 0 {
			return fmt.Errorf("%s: duplicate profile %q", path, name)
		}
		seen |= bit
	}
	return nil
}
