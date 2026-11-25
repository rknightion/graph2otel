package config

import (
	"strings"
	"testing"
)

func TestCallNotificationsValidation(t *testing.T) {
	valid := CallNotificationsConfig{
		Enabled: true, Addr: ":8443", PublicURL: "https://receiver.example.invalid/graph/call-records",
		TLSCertFile: "/synthetic/cert.pem", TLSKeyFile: "/synthetic/key.pem",
	}
	for _, tc := range []struct {
		name string
		edit func(*Config)
		want string
	}{
		{"valid", func(*Config) {}, ""},
		{"admin port", func(c *Config) { c.Admin.Enabled = true; c.Admin.Addr = "localhost:8443" }, "different port"},
		{"credentials", func(c *Config) {
			c.CallNotifications.PublicURL = "https://synthetic-inline@example.com/graph/call-records"
		}, "public_url"},
		{"plaintext", func(c *Config) { c.CallNotifications.PublicURL = "http://receiver.example.invalid/graph/call-records" }, "public_url"},
		{"query", func(c *Config) { c.CallNotifications.PublicURL += "?probe=synthetic-inline" }, "public_url"},
		{"key file", func(c *Config) { c.CallNotifications.TLSKeyFile = "synthetic-inline" }, "tls_key_file"},
		{"no tenant opted in", func(c *Config) { c.Tenants[0].CallNotificationClientStateFile = "" }, "client_state_file"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := Default()
			cfg.CallNotifications = valid
			cfg.Tenants = []TenantConfig{{TenantID: "00000000-0000-0000-0000-000000000000", CallNotificationClientStateFile: "/synthetic/client-state"}}
			tc.edit(cfg)
			err := cfg.Validate()
			if tc.want == "" {
				if err != nil {
					t.Fatal(err)
				}
			} else if err == nil || !strings.Contains(err.Error(), tc.want) || strings.Contains(err.Error(), "synthetic-inline") {
				t.Fatalf("want a diagnostic containing %q without the input, got %v", tc.want, err)
			}
		})
	}
}
