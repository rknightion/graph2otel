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
	"time"

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
	// Collectors holds global per-collector overrides keyed by collector name.
	// A collector absent from this map runs with its built-in defaults
	// (enabled, default interval). Per-tenant overrides on TenantConfig layer
	// on top of these (see CollectorSettings).
	Collectors map[string]CollectorConfig `yaml:"collectors"`
	// Admin configures the operator health/status endpoint (#12).
	Admin AdminConfig `yaml:"admin"`
	// Profiling configures optional Pyroscope continuous profiling (#85).
	Profiling ProfilingConfig `yaml:"profiling"`
	// CheckpointDir is the root directory for the file-based CheckpointStore
	// (#7); each (tenant, endpoint) window poller persists its watermark there.
	CheckpointDir string `yaml:"checkpoint_dir"`
}

// CollectorConfig overrides a single collector's runtime behavior. It is used
// both globally (Config.Collectors) and per-tenant (TenantConfig.Collectors),
// with the tenant layer winning field-by-field over the global one.
type CollectorConfig struct {
	// Enabled toggles the collector. A nil pointer means "unset" — inherit the
	// lower layer, ultimately defaulting to true — which is deliberately
	// distinct from an explicit false (disable).
	Enabled *bool `yaml:"enabled"`
	// Interval overrides the collector's poll cadence. Zero means "unset" —
	// inherit the lower layer, ultimately the collector's DefaultInterval
	// (resolved by the scheduler, not here).
	Interval time.Duration `yaml:"interval"`
}

// AdminConfig configures the admin/health HTTP endpoint (#12).
type AdminConfig struct {
	Enabled bool   `yaml:"enabled"`
	Addr    string `yaml:"addr"`
}

// ProfilingConfig configures optional continuous profiling. Everything here is
// off by default; enabling the Pyroscope push has no effect on the exporter's
// core job and a failure to reach Pyroscope is non-fatal.
type ProfilingConfig struct {
	Pyroscope ProfilingPyroscope `yaml:"pyroscope"`
	// MutexProfileFraction sets runtime.SetMutexProfileFraction (0 = disabled)
	// and BlockProfileRate sets runtime.SetBlockProfileRate (0 = disabled). Both
	// feed the Pyroscope mutex + block profiles; leave 0 unless investigating
	// contention, since sampling them is not free.
	MutexProfileFraction int `yaml:"mutex_profile_fraction"`
	BlockProfileRate     int `yaml:"block_profile_rate"`
}

// ProfilingPyroscope configures the Pyroscope continuous-profiling push. Auth
// material (BasicAuthPassword) is a Secret so it redacts in any config dump;
// supply it via env (G2O_PROFILING__PYROSCOPE__BASIC_AUTH_PASSWORD) like every
// other credential, never in committed YAML.
type ProfilingPyroscope struct {
	Enabled           bool              `yaml:"enabled"`
	ServerAddress     string            `yaml:"server_address"`
	BasicAuthUser     string            `yaml:"basic_auth_user"`
	BasicAuthPassword Secret            `yaml:"basic_auth_password"`
	TenantID          string            `yaml:"tenant_id"`
	UploadRate        time.Duration     `yaml:"upload_rate"`
	Tags              map[string]string `yaml:"tags"`
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
	// Collectors holds per-tenant collector overrides that layer on top of the
	// global Config.Collectors — a tenant may disable a globally-enabled
	// collector or tune its interval. See CollectorSettings.
	Collectors map[string]CollectorConfig `yaml:"collectors"`
}

// CollectorSettings resolves the effective enabled state and interval for a
// collector on a given tenant, applying the precedence:
//
//	per-tenant override > global collectors config > built-in default
//
// A returned interval of 0 means "no override — use the collector's
// DefaultInterval" (the scheduler applies that fallback at registration). The
// returned enabled flag defaults to true when neither layer sets it.
func (c *Config) CollectorSettings(tenantID, collectorName string) (enabled bool, interval time.Duration) {
	enabled = true // default when unset at every layer

	if gc, ok := c.Collectors[collectorName]; ok {
		if gc.Enabled != nil {
			enabled = *gc.Enabled
		}
		if gc.Interval > 0 {
			interval = gc.Interval
		}
	}

	for i := range c.Tenants {
		if c.Tenants[i].TenantID != tenantID {
			continue
		}
		if tc, ok := c.Tenants[i].Collectors[collectorName]; ok {
			if tc.Enabled != nil {
				enabled = *tc.Enabled
			}
			if tc.Interval > 0 {
				interval = tc.Interval
			}
		}
		break
	}
	return enabled, interval
}

// CollectorExplicitlyEnabled reports whether some config layer (global or the
// matching per-tenant override) set enabled=true EXPLICITLY for the collector,
// as distinct from the default-true CollectorSettings returns when nothing is
// set. It exists to gate experimental (beta) collectors, which are opt-in: they
// must never register on the default, only on an explicit opt-in. A per-tenant
// explicit value wins over a global one; an explicit false at either layer
// means "not explicitly enabled".
func (c *Config) CollectorExplicitlyEnabled(tenantID, collectorName string) bool {
	explicit := false
	if gc, ok := c.Collectors[collectorName]; ok && gc.Enabled != nil {
		explicit = *gc.Enabled
	}
	for i := range c.Tenants {
		if c.Tenants[i].TenantID != tenantID {
			continue
		}
		if tc, ok := c.Tenants[i].Collectors[collectorName]; ok && tc.Enabled != nil {
			explicit = *tc.Enabled
		}
		break
	}
	return explicit
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
		Admin: AdminConfig{
			Enabled: false,
			Addr:    ":9090",
		},
		CheckpointDir: "./checkpoints",
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
			// Decode duration strings ("5m", "30s") from the file/env layers
			// into time.Duration fields (collector intervals). Values already
			// typed as time.Duration (the structs defaults layer) pass through.
			DecodeHook: mapstructure.StringToTimeDurationHookFunc(),
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

		for name, cc := range t.Collectors {
			if err := validateInterval(cc.Interval); err != nil {
				return fmt.Errorf("tenants[%d].collectors[%q].interval: %w", i, name, err)
			}
		}
	}

	for name, cc := range c.Collectors {
		if err := validateInterval(cc.Interval); err != nil {
			return fmt.Errorf("collectors[%q].interval: %w", name, err)
		}
	}

	if c.Profiling.Pyroscope.Enabled && c.Profiling.Pyroscope.ServerAddress == "" {
		return fmt.Errorf("profiling.pyroscope.server_address is required when profiling.pyroscope.enabled is true")
	}

	return nil
}

// minInterval is the smallest permitted collector poll interval. A positive
// interval below this is almost certainly a mistake (a unit typo, e.g. "10ms"
// instead of "10m") that would hammer Graph into throttling; reject it. A zero
// interval is allowed — it means "use the collector's built-in default".
const minInterval = time.Second

func validateInterval(d time.Duration) error {
	if d != 0 && d < minInterval {
		return fmt.Errorf("%v is below the %v minimum (0 means use the collector default)", d, minInterval)
	}
	return nil
}
