package config

import (
	"errors"
	"fmt"
	"slices"

	"github.com/rknightion/graph2otel/internal/teams/sites"
	"github.com/rknightion/graph2otel/internal/vaacclient"
)

// TeamsConfig holds tenant-local site rules and the separate VAAC opt-in.
// The site settings do not enable a collector.
type TeamsConfig struct {
	SitesFile       string      `yaml:"sites_file"`
	InternalDomains []string    `yaml:"internal_domains"`
	VAAC            *VAACConfig `yaml:"vaac" json:",omitempty"`

	siteFile *sites.File
	domains  sites.Domains
}

// VAACConfig opts into the unsupported Teams voice analytics user credential
// flow. The paths (and their contents) are absent from JSON config dumps and
// the startup fingerprint. Enabled remains visible.
type VAACConfig struct {
	Enabled      bool   `yaml:"enabled"`
	UsernameFile string `yaml:"username_file" json:"-"`
	PasswordFile string `yaml:"password_file" json:"-"`
}

func (v *VAACConfig) validate() error {
	if v == nil || (!v.Enabled && v.UsernameFile == "" && v.PasswordFile == "") {
		return nil
	}
	if !vaacclient.ValidSecretPath(v.UsernameFile) || !vaacclient.ValidSecretPath(v.PasswordFile) || v.UsernameFile == v.PasswordFile {
		return errors.New("username_file and password_file must be distinct absolute secret file paths")
	}
	return nil
}

// TenantVAAC returns the tenant's opt-in and credential paths without reading them.
func (c *Config) TenantVAAC(tenantID string) VAACConfig {
	for _, tenant := range c.Tenants {
		if tenant.TenantID == tenantID && tenant.Teams != nil && tenant.Teams.VAAC != nil {
			return *tenant.Teams.VAAC
		}
	}
	return VAACConfig{}
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
