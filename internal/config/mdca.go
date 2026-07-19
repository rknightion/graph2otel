package config

import (
	"fmt"
	"net/url"
	"strings"
)

// MDCAConfig points a tenant's Microsoft Defender for Cloud Apps (MDCA)
// Cloud-Discovery collectors at the tenant's legacy portal API (#145).
//
// It is the one graph2otel signal whose auth is NOT the Entra poller: the MDCA
// portal API is authenticated with a static "Authorization: Token <secret>"
// header, not azidentity, so there is no app-registration scope to grant.
//
// # Why token_file and not an env Secret
//
// The token is per-tenant, and this config's tenants are a slice. koanf's env
// provider CANNOT bind a value into a slice element — measured 2026-07-19,
// setting G2O_TENANTS__0__CLIENT_ID did not merely fail, it wiped the whole
// tenants slice (see env.go: this config has no []TenantConfig env binding by
// design). ProfilingPyroscope.BasicAuthPassword can be an env Secret only
// because it is TOP-LEVEL. So the token cannot ride env here.
//
// Instead both fields are NON-secret — a URL and a filesystem path — so they
// live safely in YAML, and the actual token is read from TokenFile at client
// construction (fail-fast if unreadable). That keeps the credential out of YAML
// and out of the environment, and is the standard k8s secret-mount pattern:
// mount the token as a file, point token_file at it.
type MDCAConfig struct {
	// PortalURL is the tenant's MDCA portal endpoint, e.g.
	// "https://<tenant>.<region>.portal.cloudappsecurity.com". Setting it IS the
	// opt-in: empty (the default) registers no MDCA collectors for this tenant,
	// exactly as an unset blob_ingest.account_url registers no blob collectors.
	PortalURL string `yaml:"portal_url"`
	// TokenFile is the path to a file containing the static portal API token.
	// It is a path, never the token itself — the token must never appear in YAML
	// or env. Required when PortalURL is set.
	TokenFile string `yaml:"token_file"`
}

// Configured reports whether this tenant has opted into MDCA collectors. A set
// PortalURL is the whole opt-in.
func (m MDCAConfig) Configured() bool { return strings.TrimSpace(m.PortalURL) != "" }

// validate checks an MDCA block in isolation. An unset block is valid (opt-out);
// a set PortalURL requires a token_file and a URL with a host.
func (m MDCAConfig) validate() error {
	if !m.Configured() {
		// Opt-out. A stray token_file with no portal_url is still a mistake worth
		// catching — it silently does nothing otherwise.
		if strings.TrimSpace(m.TokenFile) != "" {
			return fmt.Errorf("token_file is set but portal_url is empty (MDCA is off unless portal_url is set)")
		}
		return nil
	}
	u, err := url.Parse(m.PortalURL)
	if err != nil || u.Host == "" || u.Scheme == "" {
		return fmt.Errorf("portal_url %q is not a valid absolute URL", m.PortalURL)
	}
	if strings.TrimSpace(m.TokenFile) == "" {
		return fmt.Errorf("token_file is required when portal_url is set")
	}
	return nil
}
