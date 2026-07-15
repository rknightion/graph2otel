// Package config loads, defaults, and validates the graph2otel configuration
// into typed Go structs.
//
// Configuration is layered, lowest precedence first: built-in defaults
// (Default) -> an optional YAML file -> environment variables. Every field is
// settable via an environment variable named with the G2O_ prefix and "__" as
// the nesting delimiter (single underscores inside a name are preserved):
//
//	G2O_OTLP__ENDPOINT       -> otlp.endpoint
//	G2O_OTLP__GRAFANA_CLOUD__TOKEN -> otlp.grafana_cloud.token
//
// The env layer overrides the file, so secrets live in environment variables
// and never need to appear in the YAML. The file is optional: with no -config
// path the process runs from defaults + environment alone (handy for
// containers).
//
// Tenant auth material (client secrets, certificates) is NEVER read from this
// package's config surface at all: tenants authenticate via
// azidentity.DefaultAzureCredential, which reads its own well-known
// environment variables (AZURE_CLIENT_ID, AZURE_CLIENT_SECRET,
// AZURE_CLIENT_CERTIFICATE_PATH, AZURE_TENANT_ID, or workload/managed
// identity). TenantConfig carries only the non-secret identifiers
// (tenant_id, client_id) needed to select which tenant/credential a
// collector run applies to.
package config

import (
	"fmt"

	"github.com/go-viper/mapstructure/v2"
	"github.com/knadh/koanf/parsers/yaml"
	env "github.com/knadh/koanf/providers/env/v2"
	"github.com/knadh/koanf/providers/file"
	"github.com/knadh/koanf/providers/structs"
	"github.com/knadh/koanf/v2"
)

// EnvPrefix is the prefix for every configuration environment variable.
const EnvPrefix = "G2O_"

// keyDelim is koanf's internal key-path delimiter; envNestDelim is the token
// that separates nesting levels in an environment-variable name (so a single
// underscore within a level, e.g. client_id, is preserved).
const (
	keyDelim     = "."
	envNestDelim = "__"
)

// Config is the root configuration document.
type Config struct {
	LogLevel string         `yaml:"log_level"`
	Tenants  []TenantConfig `yaml:"tenants"`
	OTLP     OTLPConfig     `yaml:"otlp"`
}

// TenantConfig identifies one Entra tenant to poll. It intentionally carries
// no secret material: DefaultAzureCredential resolves the actual credential
// (client secret, certificate, workload identity, ...) from the process
// environment at run time, never from this struct or the YAML file.
type TenantConfig struct {
	// TenantID is the Entra (Azure AD) tenant GUID or verified domain name.
	TenantID string `yaml:"tenant_id"`
	// ClientID is the app registration (application) ID used to authenticate
	// against this tenant. Optional: a single shared app registration across
	// tenants can leave this unset and rely on AZURE_CLIENT_ID.
	ClientID string `yaml:"client_id"`
}

// OTLPConfig configures the OTLP exporter.
type OTLPConfig struct {
	// Protocol selects the OTLP transport: "grpc", "http", or "stdout" (the
	// last emits telemetry to the console instead of exporting, and is the
	// only mode Validate permits to run with zero configured tenants).
	Protocol string `yaml:"protocol"`
	Endpoint string `yaml:"endpoint"`

	GrafanaCloud GrafanaCloudConfig `yaml:"grafana_cloud"`
}

// GrafanaCloudConfig holds Grafana Cloud OTLP credentials.
type GrafanaCloudConfig struct {
	InstanceID string `yaml:"instance_id"`
	Token      Secret `yaml:"token"`
}

// Default returns a Config populated with the documented default values. Load
// starts from Default and unmarshals the user's YAML on top, so any key the
// user omits keeps its default.
func Default() *Config {
	return &Config{
		LogLevel: "info",
		OTLP: OTLPConfig{
			Protocol: "http",
			Endpoint: "https://otlp-gateway-prod-us-central-0.grafana.net/otlp",
		},
	}
}

// Load builds the configuration by layering, lowest precedence first:
// built-in defaults, an optional YAML file at path (skipped when path is
// ""), and G2O_* environment variables. The merged result is NOT validated
// here — call Validate explicitly once the config is fully assembled (e.g.
// after any flag-driven overrides in main). A non-empty path that cannot be
// read is an error; absence of a path is not (defaults + environment are
// sufficient to run).
func Load(path string) (*Config, error) {
	k := koanf.New(keyDelim)

	// 1. Built-in defaults.
	if err := k.Load(structs.Provider(Default(), "yaml"), nil); err != nil {
		return nil, fmt.Errorf("load defaults: %w", err)
	}

	// 2. Optional YAML file (overrides defaults).
	if path != "" {
		if err := k.Load(file.Provider(path), yaml.Parser()); err != nil {
			return nil, fmt.Errorf("read config %s: %w", path, err)
		}
	}

	// 3. Environment overrides (highest precedence).
	if err := k.Load(env.Provider(keyDelim, env.Opt{
		Prefix:        EnvPrefix,
		TransformFunc: envTransform,
	}), nil); err != nil {
		return nil, fmt.Errorf("load environment: %w", err)
	}

	var cfg Config
	if err := k.UnmarshalWithConf("", &cfg, koanf.UnmarshalConf{
		Tag: "yaml",
		DecoderConfig: &mapstructure.DecoderConfig{
			Result:           &cfg,
			WeaklyTypedInput: true, // env values are strings ("true", "10", ...)
		},
	}); err != nil {
		return nil, fmt.Errorf("decode config: %w", err)
	}

	return &cfg, nil
}

// oneOf reports whether v equals one of the allowed values.
func oneOf(v string, allowed ...string) bool {
	for _, a := range allowed {
		if v == a {
			return true
		}
	}
	return false
}

// Validate reports the first configuration error it finds, or nil if the
// Config is valid.
func (c *Config) Validate() error {
	if !oneOf(c.LogLevel, "debug", "info", "warn", "error") {
		return fmt.Errorf("log_level %q invalid: must be one of debug, info, warn, error", c.LogLevel)
	}
	if !oneOf(c.OTLP.Protocol, "grpc", "http", "stdout") {
		return fmt.Errorf("otlp.protocol %q invalid: must be one of grpc, http, stdout", c.OTLP.Protocol)
	}

	// The stdout exporter needs no real backend or credentials, so it is the
	// only mode allowed to run with zero configured tenants (e.g. a quick
	// local smoke test of the scaffold). Every other mode ships telemetry
	// somewhere real and so needs at least one tenant to poll.
	if len(c.Tenants) == 0 && c.OTLP.Protocol != "stdout" {
		return fmt.Errorf("tenants: at least one tenant is required when otlp.protocol is %q "+
			"(only otlp.protocol=stdout may run with no tenants configured)", c.OTLP.Protocol)
	}

	seen := make(map[string]bool, len(c.Tenants))
	for i, t := range c.Tenants {
		if t.TenantID == "" {
			return fmt.Errorf("tenants[%d].tenant_id: required", i)
		}
		if seen[t.TenantID] {
			return fmt.Errorf("tenants[%d].tenant_id %q: duplicate tenant", i, t.TenantID)
		}
		seen[t.TenantID] = true
	}

	return nil
}
