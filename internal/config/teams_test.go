package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const adminAPITenantA = "00000000-0000-0000-0000-000000000001"
const adminAPITenantB = "00000000-0000-0000-0000-000000000002"

func loadAdminAPIConfig(t *testing.T, teamsBlock string) (*Config, error) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "config.yaml")
	body := "otlp:\n  protocol: stdout\ntenants:\n  - tenant_id: " + adminAPITenantA + "\n" + teamsBlock +
		"  - tenant_id: " + adminAPITenantB + "\n"
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return Load(path)
}

func TestTenantTeamsAdminAPI(t *testing.T) {
	tests := []struct {
		name  string
		block string
		want  bool
	}{
		{"absent", "", false},
		{"teams without admin_api", "    teams:\n      internal_domains: [example.test]\n", false},
		{"explicit false", "    teams:\n      admin_api:\n        enabled: false\n", false},
		{"enabled", "    teams:\n      admin_api:\n        enabled: true\n", true},
		{"empty mapping", "    teams:\n      admin_api: {}\n", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg, err := loadAdminAPIConfig(t, tt.block)
			if err != nil {
				t.Fatal(err)
			}
			if got := cfg.TenantTeamsAdminAPI(adminAPITenantA).Enabled; got != tt.want {
				t.Errorf("tenant A enabled = %t, want %t", got, tt.want)
			}
			if cfg.TenantTeamsAdminAPI(adminAPITenantB).Enabled {
				t.Error("one tenant's opt-in enabled another tenant")
			}
			if cfg.TenantTeamsAdminAPI("00000000-0000-0000-0000-0000000000ff").Enabled {
				t.Error("an unknown tenant reported enabled")
			}
		})
	}
}

func TestTeamsAdminAPIStrictValidation(t *testing.T) {
	tests := []struct {
		name    string
		block   string
		wantErr string
	}{
		{"unknown key", "    teams:\n      admin_api:\n        enabled: true\n        base_url: https://example.test\n", "unknown key"},
		{"string instead of boolean", "    teams:\n      admin_api:\n        enabled: \"true\"\n", "expected a boolean"},
		{"integer instead of boolean", "    teams:\n      admin_api:\n        enabled: 1\n", "expected a boolean"},
		{"scalar instead of mapping", "    teams:\n      admin_api: true\n", "expected a mapping"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := loadAdminAPIConfig(t, tt.block)
			if err == nil || !strings.Contains(err.Error(), tt.wantErr) || !strings.Contains(err.Error(), "admin_api") {
				t.Fatalf("Load error = %v, want one naming admin_api and %q", err, tt.wantErr)
			}
		})
	}
}
