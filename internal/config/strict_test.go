package config_test

import (
	"strings"
	"testing"

	"github.com/rknightion/graph2otel/internal/config"
)

func TestLoadRejectsUnknownYAMLKeys(t *testing.T) {
	tests := []struct {
		name     string
		yaml     string
		wantPath string
	}{
		{
			name:     "top level",
			yaml:     "log_leevl: secret-top-level-value\n",
			wantPath: "log_leevl",
		},
		{
			name:     "nested fixed object",
			yaml:     "otlp:\n  protocolx: secret-nested-value\n",
			wantPath: "otlp.protocolx",
		},
		{
			name: "tenant",
			yaml: `tenants:
  - tenant_id: example
    clientd: secret-tenant-value
`,
			wantPath: "tenants[0].clientd",
		},
		{
			name: "tenant nested fixed object",
			yaml: `tenants:
  - tenant_id: example
    blob_ingest:
      account_urll: secret-blob-value
`,
			wantPath: "tenants[0].blob_ingest.account_urll",
		},
		{
			name: "global collector value",
			yaml: `collectors:
  entra.directory_audits:
    sourcex: secret-source-value
`,
			wantPath: `collectors["entra.directory_audits"].sourcex`,
		},
		{
			name: "tenant collector value",
			yaml: `tenants:
  - tenant_id: example
    collectors:
      entra.directory_audits:
        enabeld: secret-enabled-value
`,
			wantPath: `tenants[0].collectors["entra.directory_audits"].enabeld`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := config.Load(writeTemp(t, tt.yaml))
			if err == nil {
				t.Fatalf("Load accepted unknown key %s", tt.wantPath)
			}
			if !strings.Contains(err.Error(), tt.wantPath) {
				t.Errorf("error %q does not contain full path %q", err, tt.wantPath)
			}
			if strings.Contains(err.Error(), "secret-") {
				t.Errorf("error exposed the unknown key's value: %q", err)
			}
		})
	}
}

func TestLoadRejectsUnknownEnvironmentVariables(t *testing.T) {
	tests := []struct {
		name  string
		env   string
		value string
	}{
		{
			name:  "top level",
			env:   "G2O_LOG_LEEVL",
			value: "secret-top-level-value",
		},
		{
			name:  "nested credential typo",
			env:   "G2O_OTLP__GRAFANA_CLOUD__TOKNE",
			value: "secret-credential-value",
		},
		{
			name:  "tenant collection",
			env:   "G2O_TENANTS__0__CLIENT_ID",
			value: "secret-client-value",
		},
		{
			name:  "free form map",
			env:   "G2O_PROFILING__PYROSCOPE__TAGS__REGION",
			value: "secret-tag-value",
		},
		{
			name:  "collector leaf",
			env:   "G2O_COLLECTORS__ENTRA.DIRECTORY_AUDITS__TRANSPORT",
			value: "secret-source-value",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Setenv(tt.env, tt.value)
			_, err := config.Load("")
			if err == nil {
				t.Fatalf("Load accepted unknown environment variable %s", tt.env)
			}
			if !strings.Contains(err.Error(), tt.env) {
				t.Errorf("error %q does not name exact environment variable %q", err, tt.env)
			}
			if strings.Contains(err.Error(), tt.value) {
				t.Errorf("error exposed environment value for %s: %q", tt.env, err)
			}
		})
	}
}

func TestStrictYAMLAcceptsOpenMaps(t *testing.T) {
	const y = `otlp:
  protocol: stdout
profiling:
  pyroscope:
    tags:
      arbitrary_key: arbitrary-value
      another.key: another-value
collectors:
  arbitrary.collector_name:
    enabled: false
    interval: 5m
    source: graph
tenants:
  - tenant_id: example
    collectors:
      another.arbitrary_name:
        enabled: true
`

	cfg, err := config.Load(writeTemp(t, y))
	if err != nil {
		t.Fatalf("Load rejected intentional open maps: %v", err)
	}
	if got := cfg.Profiling.Pyroscope.Tags["another.key"]; got != "another-value" {
		t.Errorf("free-form tag = %q, want another-value", got)
	}
	if _, ok := cfg.Collectors["arbitrary.collector_name"]; !ok {
		t.Fatal("dynamic collector map key was not preserved")
	}
	if _, ok := cfg.Tenants[0].Collectors["another.arbitrary_name"]; !ok {
		t.Fatal("dynamic tenant collector map key was not preserved")
	}
}

func TestStrictEnvironmentAcceptsScalarAndCollectorOverrides(t *testing.T) {
	t.Setenv("G2O_OTLP__ENDPOINT", "https://example.test/otlp")
	t.Setenv("G2O_COLLECTORS__ENTRA.DIRECTORY_AUDITS__SOURCE", "blob")

	cfg, err := config.Load("")
	if err != nil {
		t.Fatalf("Load rejected documented environment variables: %v", err)
	}
	if cfg.OTLP.Endpoint != "https://example.test/otlp" {
		t.Errorf("endpoint = %q, want environment override", cfg.OTLP.Endpoint)
	}
	override, ok := cfg.Collectors["entra.directory_audits"]
	if !ok {
		t.Fatal("collector name containing dots was not preserved as one map key")
	}
	if override.Source != "blob" {
		t.Errorf("collector source = %q, want blob", override.Source)
	}
}
