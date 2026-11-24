package config

import (
	"fmt"
	"slices"

	"github.com/rknightion/graph2otel/internal/teams/sites"
)

// TeamsConfig holds YAML-only site and internal-domain rules for one tenant.
// Neither setting enables a collector.
type TeamsConfig struct {
	SitesFile       string   `yaml:"sites_file"`
	InternalDomains []string `yaml:"internal_domains"`

	siteFile *sites.File
	domains  sites.Domains
}

// resolveTeamsSites validates and opens each configured file once, during Load,
// before either startup mode constructs credentials or registers collectors.
func (c *Config) resolveTeamsSites() error {
	for i := range c.Tenants {
		t := c.Tenants[i].Teams
		if t == nil {
			continue
		}
		domains, err := sites.NewDomains(t.InternalDomains)
		if err != nil {
			return fmt.Errorf("tenants[%d].%w", i, err)
		}
		t.domains = domains
		if t.SitesFile == "" {
			continue
		}
		file, err := sites.Open(t.SitesFile)
		if err != nil {
			return fmt.Errorf("tenants[%d].teams.sites_file: %w", i, err)
		}
		t.siteFile = file
	}
	return nil
}

// TeamsSiteInputs returns one tenant's loaded site file (nil when disabled)
// and compiled domain rules. The caller reuses this file, rather than opening
// it again.
func (c *Config) TeamsSiteInputs(tenantID string) (*sites.File, sites.Domains) {
	i := slices.IndexFunc(c.Tenants, func(t TenantConfig) bool { return t.TenantID == tenantID })
	if i < 0 || c.Tenants[i].Teams == nil {
		return nil, sites.Domains{}
	}
	t := c.Tenants[i].Teams
	return t.siteFile, t.domains
}
