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
	// Cardinality governs output-side active-series limits (#105).
	Cardinality CardinalityConfig `yaml:"cardinality"`
	// Backfill tunes how much history a cold-started window collector recovers
	// (#118).
	Backfill BackfillConfig `yaml:"backfill"`
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

// CardinalityConfig governs output-side series cardinality (#105). Grafana
// Cloud bills on active series, and a mis-scoped metric label (an entity id
// leaking into a metric dimension) can balloon series unbounded. The limit is a
// hard per-instrument ceiling: distinct attribute sets beyond it collapse into
// the SDK's otel.metric.overflow series (dropped + counted) rather than growing
// the bill, and the graph2otel.series.active/.limit/.overflowing self-obs gauges
// report where each metric sits against it.
type CardinalityConfig struct {
	// MetricLimit is the hard per-instrument cap on distinct active series.
	// 0 (or negative) means unlimited (the OTEL SDK's own default of 2000 still
	// applies as a backstop, but no explicit limit or overflow accounting is
	// enforced by graph2otel). Env: G2O_CARDINALITY__METRIC_LIMIT.
	MetricLimit int `yaml:"metric_limit"`
}

// BackfillConfig tunes the cold-start backfill window shared by every window
// (log) collector (#118).
//
// It applies only to WINDOW collectors, deliberately. A snapshot collector
// re-derives its whole state every tick, so a missed metric tick costs nothing
// and there is no history for it to recover — backfill is meaningless there.
type BackfillConfig struct {
	// InitialLookback overrides how far back a window collector reaches on a COLD
	// START — no checkpoint yet: a new tenant, a wiped volume, a first deploy. It
	// bounds how much history that start recovers, and therefore how long an
	// outage can be before events are lost for good.
	//
	// 0 (the default) means "use each collector's own built-in lookback", which
	// is NOT one value: most streams use 1h, m365.unified_audit 4h,
	// entra.security_incidents 24h — tuned per endpoint's latency and throttling
	// ceiling. A non-zero value here replaces ALL of them, so set it for a
	// deliberate recovery (a long outage, a fresh volume) rather than as a
	// permanent default.
	//
	// It does NOT affect the steady state: once a checkpoint exists, polling
	// resumes from the watermark and the MaxWindow clamp walks a long gap forward
	// in chunks losslessly. This is only the no-checkpoint case.
	//
	// There is a downstream CEILING on what any of this buys — see Warnings and
	// backendAcceptWindow. Env: G2O_BACKFILL__INITIAL_LOOKBACK.
	InitialLookback time.Duration `yaml:"initial_lookback"`
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
	// BlobIngest configures the read-only Azure Storage blob consumer (#89),
	// the one place graph2otel reads from outside Graph. Off unless an account
	// URL is set.
	BlobIngest BlobIngestConfig `yaml:"blob_ingest"`
}

// BlobIngestConfig points a tenant's blob-sourced collectors at the Azure
// Storage account its Entra/Intune diagnostic settings write to (#89).
//
// This exists because a handful of signals have no Graph endpoint at all —
// MicrosoftGraphActivityLogs, MicrosoftServicePrincipalSignInLogs, Intune
// OperationalLogs — and reach us only as Azure Monitor diagnostic-settings
// output landing in blob storage.
//
// It carries no credential: the tenant's existing DefaultAzureCredential is
// reused, and the SDK requests the storage audience itself. The identity needs
// the DATA-plane role Storage Blob Data Reader on this account — read-only, by
// design (graph2otel never deletes; the account's lifecycle rule owns
// retention).
type BlobIngestConfig struct {
	// AccountURL is the blob service endpoint, e.g.
	// "https://myaccount.blob.core.windows.net". Empty (the default) disables
	// blob ingest entirely for this tenant: no blob collectors are registered,
	// so a deployment with no storage account is unaffected.
	AccountURL string `yaml:"account_url"`
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
		Profiling: ProfilingConfig{
			// Contention profiling on by default. It is applied only when the
			// Pyroscope push is enabled (see profiling.Start), so it costs nothing
			// when profiling is off. Fraction 5 samples 1/5 of mutex-contention
			// events; block rate 100µs records blocking events averaging at least
			// that long. Set either to 0 to drop that profile.
			MutexProfileFraction: 5,
			BlockProfileRate:     100_000,
		},
		Cardinality: CardinalityConfig{
			// A generous per-instrument default: graph2otel's metrics are bounded
			// tenant-shaped aggregates (dozens–low-hundreds of series each), so
			// 2000 is a blast-radius guard against a mis-scoped label, not a normal
			// operating constraint. Matches the OTEL SDK's own default so the
			// series.limit gauge is meaningful out of the box. Set 0 for unlimited.
			MetricLimit: 2000,
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

		if err := validateBlobAccountURL(t.BlobIngest.AccountURL); err != nil {
			return fmt.Errorf("tenants[%d].blob_ingest.account_url: %w", i, err)
		}
	}

	for name, cc := range c.Collectors {
		if err := validateInterval(cc.Interval); err != nil {
			return fmt.Errorf("collectors[%q].interval: %w", name, err)
		}
	}

	if c.Cardinality.MetricLimit < 0 {
		return fmt.Errorf("cardinality.metric_limit %d invalid: must be >= 0 (0 = unlimited)", c.Cardinality.MetricLimit)
	}

	if c.Profiling.Pyroscope.Enabled && c.Profiling.Pyroscope.ServerAddress == "" {
		return fmt.Errorf("profiling.pyroscope.server_address is required when profiling.pyroscope.enabled is true")
	}

	if c.Backfill.InitialLookback < 0 {
		return fmt.Errorf("backfill.initial_lookback %v invalid: must be >= 0 (0 means use each collector's built-in lookback)",
			c.Backfill.InitialLookback)
	}

	return nil
}

// backendAcceptWindow is how far back the OTLP backend is ASSUMED to accept log
// samples. Grafana Cloud's Loki rejects samples older than its
// reject_old_samples_max_age, which the maintainer puts at ~13 days (#118, #89 —
// which sets its blob lifecycle to 7 days for the same reason).
//
// It is deliberately a warning threshold and NOT a clamp. graph2otel cannot know
// every backend's retention policy: a self-hosted Loki may be configured wider,
// and a non-Loki OTLP sink has entirely different rules. Clamping would silently
// break a correctly-configured deployment, which is the same class of mistake as
// the failure it guards against. So the value takes effect as written and the
// operator is told what to expect.
const backendAcceptWindow = 13 * 24 * time.Hour

// Warnings returns non-fatal configuration advisories: settings that are valid,
// take effect exactly as written, and are still very likely not what the operator
// meant. It is separate from Validate because none of these should stop the
// process — the caller logs them (see cmd/graph2otel).
func (c *Config) Warnings() []string {
	var out []string

	// A lookback beyond the backend's accept window is NOT a longer recovery — it
	// is a guaranteed silent drop at ingest, and that is worse than a short
	// lookback precisely because it looks like it is working: graph2otel pages
	// Graph for the history, maps it, ships it, reports no error, and Loki drops
	// everything past its window on arrival. The operator sees Graph calls being
	// made, a clean log, and no data in Grafana. This warning is the only thing
	// connecting that symptom to this setting.
	if c.Backfill.InitialLookback > backendAcceptWindow {
		out = append(out, fmt.Sprintf(
			"backfill.initial_lookback is %v, beyond the ~%v that Grafana Cloud's Loki accepts old samples within "+
				"(reject_old_samples_max_age). graph2otel will poll Graph for that history, map it and ship it, and the "+
				"backend will silently REJECT every record older than its accept window — no error here, no data in Grafana. "+
				"This is not clamped, because a self-hosted Loki or a non-Loki OTLP sink may accept more: if yours does, "+
				"ignore this. Otherwise reduce it to %v or less",
			c.Backfill.InitialLookback, backendAcceptWindow, backendAcceptWindow))
	}

	return out
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
