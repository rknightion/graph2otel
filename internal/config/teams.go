package config

import (
	"errors"
	"fmt"
	"slices"
	"strings"

	"github.com/rknightion/graph2otel/internal/teams/quality"
	"github.com/rknightion/graph2otel/internal/teams/sites"
	"github.com/rknightion/graph2otel/internal/vaacclient"
)

// TeamsQualityConfig holds the global settings used by all call record collectors.
type TeamsQualityConfig struct {
	QualityThresholds quality.Thresholds `yaml:"quality_thresholds"`
}

// TeamsConfig holds tenant-local enrichment settings and the separate VAAC opt-in.
// The enrichment settings do not enable a collector.
type TeamsConfig struct {
	SitesFile       string           `yaml:"sites_file"`
	InternalDomains []string         `yaml:"internal_domains"`
	VAAC            *VAACConfig      `yaml:"vaac" json:",omitempty"`
	AdminAPI        *AdminAPIConfig  `yaml:"admin_api" json:",omitempty"`
	GeoIP           TeamsGeoIPConfig `yaml:"geoip" json:",omitzero"`

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

// AdminAPIConfig opts into the teams_admin transport (#712): the Teams admin
// REST API behind the MicrosoftTeams PowerShell Get-Cs* cmdlets. It carries no
// credential; access rests on an Entra directory role held by the poller.
type AdminAPIConfig struct {
	Enabled bool `yaml:"enabled"`
}

// TenantTeamsAdminAPI returns the tenant's teams_admin opt-in (false when unset).
func (c *Config) TenantTeamsAdminAPI(tenantID string) AdminAPIConfig {
	for _, tenant := range c.Tenants {
		if tenant.TenantID == tenantID && tenant.Teams != nil && tenant.Teams.AdminAPI != nil {
			return *tenant.Teams.AdminAPI
		}
	}
	return AdminAPIConfig{}
}

// TeamsGeoIPConfig contains optional local MaxMind database paths.
type TeamsGeoIPConfig struct {
	ASNDB  string `yaml:"asn_db"`
	CityDB string `yaml:"city_db"`
}

const tenantTeamsGeoIPEnvPrefix = "tenants.<n>.teams.geoip."

var teamsGeoIPFields = [...]string{"asn_db", "city_db"}

type tenantGeoIPEnvOverride struct {
	index                  int
	field, variable, value string
}

func parseTenantGeoIPEnvName(name string) (tenantGeoIPEnvOverride, bool) {
	parts := strings.Split(name, envNestDelim)
	if len(parts) != 5 || parts[0] != EnvPrefix+"TENANTS" || parts[2] != "TEAMS" || parts[3] != "GEOIP" {
		return tenantGeoIPEnvOverride{}, false
	}
	index, ok := parseTenantEnvIndex(parts[1])
	field := strings.ToLower(parts[4])
	if !ok || parts[4] != strings.ToUpper(field) || !slices.Contains(teamsGeoIPFields[:], field) {
		return tenantGeoIPEnvOverride{}, false
	}
	return tenantGeoIPEnvOverride{index: index, field: field, variable: name}, true
}

func (c *Config) applyTeamsGeoIPEnvironment(overrides []tenantGeoIPEnvOverride) error {
	for _, override := range overrides {
		if override.index >= len(c.Tenants) {
			return fmt.Errorf("%s: tenant index out of range (tenants are configured in YAML)", override.variable)
		}
		tenant := &c.Tenants[override.index]
		if tenant.Teams == nil {
			if override.value == "" {
				continue
			}
			tenant.Teams = &TeamsConfig{}
		}
		switch override.field {
		case "asn_db":
			tenant.Teams.GeoIP.ASNDB = override.value
		case "city_db":
			tenant.Teams.GeoIP.CityDB = override.value
		}
	}
	return nil
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
