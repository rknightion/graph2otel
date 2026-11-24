package config_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/rknightion/graph2otel/internal/config"
)

func TestRejectsInvalidProfileConfiguration(t *testing.T) {
	for _, test := range []struct {
		name, yaml, variable, value, want string
	}{
		{name: "unknown", yaml: "profiles: [other]", want: `profiles: unknown profile "other"`},
		{name: "empty global", yaml: "profiles: []", want: "profiles: select at least one"},
		{name: "empty tenant", yaml: "tenants: [{profiles: []}]", want: "tenants[0].profiles: select at least one"},
		{name: "duplicate", yaml: "profiles: [teams, teams]", want: `profiles: duplicate profile "teams"`},
		{name: "string instead of list", yaml: "profiles: teams", want: "profiles: expected a list"},
		{name: "empty environment entry", variable: "G2O_PROFILES", value: "teams,", want: `profiles: unknown profile ""`},
		{name: "index without tenant", variable: "G2O_TENANTS__0__PROFILES", value: "teams", want: "G2O_TENANTS__0__PROFILES: tenant index out of range"},
		{name: "noncanonical index", variable: "G2O_TENANTS__00__PROFILES", value: "teams", want: "unknown configuration environment variable G2O_TENANTS__00__PROFILES"},
	} {
		t.Run(test.name, func(t *testing.T) {
			if test.variable != "" {
				t.Setenv(test.variable, test.value)
			}
			path := filepath.Join(t.TempDir(), "config.yaml")
			if err := os.WriteFile(path, []byte("otlp: {protocol: stdout}\n"+test.yaml+"\n"), 0o600); err != nil {
				t.Fatal(err)
			}
			cfg, err := config.Load(path)
			if err == nil {
				err = cfg.Validate()
			}
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("invalid profiles: got %v, want %q", err, test.want)
			}
		})
	}
}
