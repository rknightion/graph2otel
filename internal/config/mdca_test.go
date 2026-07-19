package config

import (
	"strings"
	"testing"
)

// baseValidConfig returns the smallest config that passes Validate, so an MDCA
// case can mutate one tenant's mdca block and assert only that.
func baseValidConfig(mdca MDCAConfig) *Config {
	c := Default()
	c.Tenants = []TenantConfig{{TenantID: "t1", MDCA: mdca}}
	return c
}

func TestMDCAConfigValidate(t *testing.T) {
	for _, tc := range []struct {
		name    string
		mdca    MDCAConfig
		wantErr string // substring; "" = must pass
	}{
		{
			name: "unset is opt-out and valid",
			mdca: MDCAConfig{},
		},
		{
			name: "portal_url plus token_file is valid",
			mdca: MDCAConfig{PortalURL: "https://m7knio.eu2.portal.cloudappsecurity.com", TokenFile: "/run/secrets/mdca_token"},
		},
		{
			name:    "portal_url without token_file is an error",
			mdca:    MDCAConfig{PortalURL: "https://m7knio.eu2.portal.cloudappsecurity.com"},
			wantErr: "token_file",
		},
		{
			name:    "token_file without portal_url is an error",
			mdca:    MDCAConfig{TokenFile: "/run/secrets/mdca_token"},
			wantErr: "portal_url",
		},
		{
			name:    "portal_url with no host is an error",
			mdca:    MDCAConfig{PortalURL: "not-a-url", TokenFile: "/run/secrets/mdca_token"},
			wantErr: "portal_url",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := baseValidConfig(tc.mdca).Validate()
			if tc.wantErr == "" {
				if err != nil {
					t.Fatalf("Validate() = %v, want nil", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("Validate() = %v, want error containing %q", err, tc.wantErr)
			}
		})
	}
}

// TestMDCAConfigConfiguredEnablesCollectors pins the opt-in predicate the
// composition root gates on: a portal URL set means MDCA collectors register.
func TestMDCAConfigConfiguredEnablesCollectors(t *testing.T) {
	if (MDCAConfig{}).Configured() {
		t.Error("empty MDCAConfig.Configured() = true, want false (opt-out)")
	}
	if !(MDCAConfig{PortalURL: "https://x.eu2.portal.cloudappsecurity.com", TokenFile: "/t"}).Configured() {
		t.Error("set MDCAConfig.Configured() = false, want true")
	}
}
