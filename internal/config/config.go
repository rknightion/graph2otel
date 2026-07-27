// Package config loads, defaults, and validates the graph2otel configuration
// into typed Go structs.
//
// Configuration is layered, lowest precedence first: built-in defaults
// (Default) -> an optional YAML file -> environment variables. Every field is
// Scalar fields are settable via an environment variable named with the G2O_
// prefix and "__" as the nesting delimiter (single underscores inside a name
// are preserved):
//
//	G2O_OTLP__ENDPOINT       -> otlp.endpoint
//	G2O_OTLP__GRAFANA_CLOUD__TOKEN -> otlp.grafana_cloud.token
//
// The global collectors map additionally supports
// G2O_COLLECTORS__<NAME>__(ENABLED|INTERVAL|SOURCE). Structured tenants and
// free-form Pyroscope tags remain file-only. The env layer overrides the file,
// so secrets live in environment variables and never need to appear in the
// YAML. The file is optional: with no -config path the process runs from
// defaults + environment alone (handy for containers).
//
// Tenant auth material (client secrets, certificates) is NEVER read from this
// package's config surface at all. TenantID is a hyphenated Entra directory GUID;
// auth sets it on every token request, restricts the credential to that target,
// and verifies the returned token's tid before tenant-labeled collection starts.
// azidentity.DefaultAzureCredential selects one ambient application identity for
// the process from its well-known environment variables (AZURE_CLIENT_ID,
// AZURE_CLIENT_SECRET, AZURE_CLIENT_CERTIFICATE_PATH, or workload/managed
// identity). ClientID is only an optional non-secret assertion about that
// selected identity; it is never passed to the credential chain.
package config

import (
	"fmt"
	"strings"
	"time"

	"github.com/go-viper/mapstructure/v2"
	"github.com/google/uuid"
	"github.com/knadh/koanf/parsers/yaml"
	env "github.com/knadh/koanf/providers/env/v2"
	"github.com/knadh/koanf/providers/file"
	"github.com/knadh/koanf/providers/structs"
	"github.com/knadh/koanf/v2"

	"github.com/rknightion/graph2otel/internal/telemetry"
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
	// Cost configures opt-in, observational cost accounting (#289).
	Cost CostConfig `yaml:"cost"`
	// Backfill tunes how much history a cold-started window collector recovers
	// (#118).
	Backfill BackfillConfig `yaml:"backfill"`
	// GrafanaAnnotations configures the opt-in Grafana annotation writer (#400)
	// — the ONE authorized second egress path (see the package doc on
	// internal/annotations). Off unless url is set.
	GrafanaAnnotations GrafanaAnnotationsConfig `yaml:"grafana_annotations"`
	// CheckpointDir is the root directory for the file-based CheckpointStore
	// (#7); each (tenant, endpoint) window poller persists its watermark there.
	CheckpointDir string `yaml:"checkpoint_dir"`

	// collectorEnvOrigins associates dynamic collector override paths with the
	// exact environment variable that supplied them. It is per-loaded Config
	// so concurrent loads cannot race or misattribute a diagnostic.
	collectorEnvOrigins map[string]string
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
	// Source selects the ingest TRANSPORT for a collector that supports both:
	// "graph" (poll the Graph API — the default) or "blob" (consume the Azure
	// Storage diagnostic-settings container instead). Empty means unset →
	// "graph". Only meaningful for a source-switchable collector — a log-shaped
	// event stream whose blob twin reuses the same mapper and emits the same
	// records (e.g. entra.directory_audits); setting it on a collector with no
	// blob source is invalid. The two transports are mutually exclusive per
	// collector (#131/#144): exactly one is active, so the same event is never
	// ingested twice. Blob scales better on high-volume tenants (Graph's
	// reporting endpoints throttle hard, blob does not), so it is the right
	// choice for a large deployment; graph is the default because a deployment
	// with no blob ingest configured has no blob source to switch to.
	Source string `yaml:"source"`
}

// AdminConfig configures the admin/health HTTP endpoint (#12).
type AdminConfig struct {
	Enabled bool   `yaml:"enabled"`
	Addr    string `yaml:"addr"`
	// RefreshInterval is how often the status page's JS re-polls
	// /api/status.json to patch the live view. Default 5s (fleet standard). The
	// page's 1s freshness ticker is independent of this.
	RefreshInterval time.Duration `yaml:"refresh_interval"`
}

// CardinalityConfig governs output-side series cardinality (#105, #235). Grafana
// Cloud bills on active series, and a mis-scoped metric label (an entity id
// leaking into a metric dimension) can balloon series unbounded.
//
// Both limits are enforced by graph2otel's own limiter (internal/telemetry), not
// by the OTEL SDK's per-instrument cap, which is disabled outright in favor of
// it. The SDK's cap is arrival-ordered: the series that survive are whichever
// showed up first, and the rest collapse into an opaque otel.metric.overflow
// that names nothing. graph2otel's keeps the most SIGNIFICANT series and folds
// the rest into a named `other` bucket, which is strictly better in every case,
// so running both would only reimpose an arbitrary lower ceiling.
type CardinalityConfig struct {
	// PerMetricLimit caps the distinct active series a single metric may emit.
	// Beyond it the top series by value are kept and the tail is folded into an
	// `other` bucket (additive metrics) or dropped and counted (non-additive
	// ones, where a synthetic aggregate would be worse than the loss).
	// 0 means unlimited. Env: G2O_CARDINALITY__PER_METRIC_LIMIT.
	PerMetricLimit int `yaml:"per_metric_limit"`

	// GlobalLimit caps the TOTAL active series across every metric, which a
	// per-metric cap alone cannot do — 200 metrics at 5000 each is a million
	// series. When the total exceeds it, per-metric limits are reduced by max-min
	// fairness: a metric under its fair share of the budget is never shrunk to
	// pay for another metric's overage. 0 means unlimited.
	// Env: G2O_CARDINALITY__GLOBAL_LIMIT.
	GlobalLimit int `yaml:"global_limit"`
}

// CostConfig configures opt-in, observational cost accounting. Pricing is
// supplied by the operator; graph2otel does not embed vendor rates.
type CostConfig struct {
	Enabled          bool            `yaml:"enabled"`
	Currency         string          `yaml:"currency"`
	Version          string          `yaml:"version"`
	Source           string          `yaml:"source"`
	EffectiveAt      string          `yaml:"effective_at"`
	Period           time.Duration   `yaml:"period"`
	Rates            CostRatesConfig `yaml:"rates"`
	BudgetMicrounits int64           `yaml:"budget_microunits"`
}

// CostRatesConfig holds integer microunit rates. Pointers preserve the
// distinction between an omitted rate and an explicitly supplied zero rate.
type CostRatesConfig struct {
	SourceRecord           *int64 `yaml:"source_record_microunits"`
	MetricPoint            *int64 `yaml:"metric_point_microunits"`
	LogRecord              *int64 `yaml:"log_record_microunits"`
	TransmittedPayloadByte *int64 `yaml:"transmitted_payload_byte_microunits"`
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
	Enabled           bool   `yaml:"enabled"`
	ServerAddress     string `yaml:"server_address"`
	BasicAuthUser     string `yaml:"basic_auth_user"`
	BasicAuthPassword Secret `yaml:"basic_auth_password"`
	// BasicAuthPasswordFile is an optional path to a file holding the Pyroscope
	// basic-auth password — the file-based alternative to BasicAuthPassword
	// (and G2O_PROFILING__PYROSCOPE__BASIC_AUTH_PASSWORD), for k8s/Docker secret
	// mounts, mirroring mdca.token_file (#212). value XOR file: set the password
	// OR the _file path, never both. Load reads the file (trimming a trailing
	// newline) into BasicAuthPassword so it still redacts.
	BasicAuthPasswordFile string            `yaml:"basic_auth_password_file"`
	TenantID              string            `yaml:"tenant_id"`
	UploadRate            time.Duration     `yaml:"upload_rate"`
	Tags                  map[string]string `yaml:"tags"`
}

// TenantConfig identifies one Entra tenant to poll. It intentionally carries
// no secret material: TenantID is the hyphenated directory GUID auth binds to
// each token request and verifies against the token's tid, while
// DefaultAzureCredential resolves one application identity for the process
// (client secret, certificate, workload identity, managed identity, ...) from
// the ambient environment at run time, never from this struct or the YAML file.
type TenantConfig struct {
	// TenantID is the hyphenated Entra directory GUID. Verified domains and other
	// names are rejected because their tenant binding cannot be proved locally.
	TenantID string `yaml:"tenant_id"`
	// ClientID optionally asserts the expected app registration (application) ID.
	// It never selects or overrides DefaultAzureCredential. When set, startup
	// warns if it disagrees with the authenticated token's appid; the
	// authenticated value remains authoritative.
	ClientID string `yaml:"client_id"`
	// ExcludeSelf, when true, drops records authored by this tenant's own poller —
	// graph2otel's polling exhaust — across every transport whose records carry an
	// appId that can be matched to the poller. It is a TENANT-level flag (#176)
	// because the same "self" spans transports: it drives both the blob consumer
	// (the ~60% of MicrosoftGraphActivityLogs volume that is the poller's own
	// traffic — #152/#154) and the Graph-polled service-principal sign-in stream
	// (entra.signins.service_principal). Default false.
	//
	// "Self" is proved from the non-empty appid in the Graph access token issued
	// to this tenant-pinned credential. A configured ClientID is never proof and
	// never controls the comparison; a mismatch warns once and the authenticated
	// value wins. If the identity cannot be proved, filtering is disabled for the
	// tenant, every record is retained, and startup emits one bounded warning.
	// Every dropped record increments a loud per-collector self-obs counter
	// (graph2otel.blob.self_excluded / graph2otel.logpipeline.self_excluded), so
	// the reduction is visible and alertable, never silent.
	//
	// Live-measured (2026-07-19, #176): the poller is 59.9% of blob MGAL volume
	// but only ~1.1% of the Graph service-principal sign-in stream and 0% of the
	// m365.activity default subscription — so the blob transport is the material
	// saving; the Graph-stream filter is offered for completeness and stays off by
	// default, and m365.activity carries no self filter at all.
	ExcludeSelf bool `yaml:"exclude_self"`
	// Collectors holds per-tenant collector overrides that layer on top of the
	// global Config.Collectors — a tenant may disable a globally-enabled
	// collector or tune its interval. See CollectorSettings.
	Collectors map[string]CollectorConfig `yaml:"collectors"`
	// BlobIngest configures the read-only Azure Storage blob consumer (#89),
	// the one place graph2otel reads from outside Graph. Off unless an account
	// URL is set.
	BlobIngest BlobIngestConfig `yaml:"blob_ingest"`
	// O365Activity configures the Office 365 Management Activity API collector
	// (#100). Unlike BlobIngest this needs no opt-in to run at all — the
	// collector is default-on — so this block only widens what it subscribes to.
	O365Activity O365ActivityConfig `yaml:"o365_activity"`
	// MDCA configures the Microsoft Defender for Cloud Apps Cloud-Discovery
	// collectors (#145), the one non-Graph, non-poller signal. Off unless
	// mdca.portal_url is set. See MDCAConfig.
	MDCA MDCAConfig `yaml:"mdca"`
	// ExchangeOnline configures the Exchange Online admin API collectors (#233)
	// — quarantine queue depth, which has no Graph endpoint. Off unless
	// exchange_online.enabled is true. See ExchangeOnlineConfig.
	ExchangeOnline ExchangeOnlineConfig `yaml:"exchange_online"`
	// Hunting configures the advanced-hunting collectors (#249) — the DeviceTvm*
	// threat-and-vulnerability-management posture, reached over the Graph
	// runHuntingQuery API. Off unless hunting.enabled is true. See HuntingConfig.
	Hunting HuntingConfig `yaml:"hunting"`
	// PrivilegedGroups configures the allowlisted privileged-group
	// member-count gauge (#337). Off unless privileged_groups.group_ids is
	// non-empty. See PrivilegedGroupsConfig.
	PrivilegedGroups PrivilegedGroupsConfig `yaml:"privileged_groups"`
}

// ExchangeOnlineConfig enables the Exchange Online admin API collectors for a
// tenant (#233) — today, defender.quarantine.
//
// It carries no credential and no URL, unlike MDCAConfig: the tenant's existing
// DefaultAzureCredential is reused and only the audience differs
// (https://outlook.office365.com/.default). So the whole block is one switch.
//
// It is a switch rather than default-on because the transport needs TWO grants
// that a default deployment will not have, and that graph2otel cannot detect in
// advance:
//
//   - the app role Exchange.ManageAsApp on the Office 365 Exchange Online
//     service principal — without it the API answers 401;
//   - an Entra DIRECTORY role on the service principal, Security Reader being
//     the least-privileged sufficient one — without it the API answers 403.
//
// Neither alone grants anything (live-measured 2026-07-23, #233: 401 with
// neither, 403 with the app role only, 200 with both). The second is the
// unusual one — assigning a directory role to a service principal is a
// deliberate act an operator takes in the Entra portal, not something a scope
// consent grants — so defaulting this on would make every unprepared deployment
// log an authorization failure on every tick with no way to act on it.
//
// The 403 is also indistinguishable from a missing-cmdlet 403 and arrives with
// a body that is not JSON (see internal/exoclient), so "it is misconfigured" is
// genuinely hard to tell from "it is broken" — another reason the operator opts
// in explicitly rather than discovering this by reading error logs.
type ExchangeOnlineConfig struct {
	// Enabled turns on the Exchange Online collectors for this tenant. false
	// (the default) registers none of them, exactly as an unset
	// blob_ingest.account_url registers no blob collectors.
	Enabled bool `yaml:"enabled"`
}

// HuntingConfig enables the advanced-hunting collectors for a tenant (#249) —
// the DeviceTvm* threat-and-vulnerability-management posture (device
// vulnerabilities, secure-configuration assessments, software inventory).
//
// Like ExchangeOnlineConfig it carries no credential of its own — the tenant's
// existing DefaultAzureCredential is reused against the Graph audience — so the
// whole block is one switch.
//
// It is opt-in rather than default-on for two reasons graph2otel cannot detect
// in advance:
//
//   - It needs the app role ThreatHunting.Read.All. A token mints fine without
//     it and the failure surfaces only when a query runs (403).
//   - Every advanced-hunting query draws on a per-tenant CPU budget SHARED with
//     humans running queries in the Defender portal (#106). The collectors poll
//     on a deliberately long interval to stay light on it, but an operator
//     should still consciously turn them on rather than have every deployment
//     start spending that shared budget by default.
//
// A tenant with no Defender-onboarded devices sees empty results, not an error,
// so enabling it there is harmless — but pointless, which is the third reason it
// is off by default.
type HuntingConfig struct {
	// Enabled turns on the advanced-hunting collectors for this tenant. false
	// (the default) registers none of them.
	Enabled bool `yaml:"enabled"`
}

// O365ActivityConfig selects which Management Activity API content types the
// m365.activity collector subscribes to for a tenant (#100).
//
// This is config rather than a constant because the API has NO server-side
// filtering, so a content type is all-or-nothing: subscribing means fetching
// every record it carries, and there is no request that says "Teams only".
//
// The numbers that shape the default, measured on m7kni over 23h: Audit.General
// carries 4,035 records, of which 3,865 are Endpoint DLP file activity, 165 are
// SecurityComplianceCenter and 3 are Teams. So a tenant that wants Teams admin
// activity fetches the entire catch-all to get it, and that ratio scales with
// fleet size while the Teams benefit does not.
type O365ActivityConfig struct {
	// ContentTypes overrides which content types this tenant subscribes to.
	// Empty (the default) uses the collector's built-in set: Audit.Exchange +
	// Audit.SharePoint. Valid members are Audit.AzureActiveDirectory,
	// Audit.Exchange, Audit.SharePoint, Audit.General and DLP.All.
	//
	// The two deliberate omissions from the default, both for reasons that are
	// not "volume costs money":
	//
	//   - Audit.General is opt-in because graph2otel is deployed by operators
	//     who pay per GB downstream, and defaulting them into a workload they
	//     never asked for is the wrong way round. It is a genuine feature for a
	//     SIEM — Endpoint DLP carries per-file hashes, device and user, which is
	//     exfiltration and ransomware signal, not noise — so when it IS set,
	//     every record ships. There is no record-type include-list: fetching
	//     per-entity rows and discarding them is the bug #112 calls out by name.
	//
	//   - Audit.AzureActiveDirectory is omitted because entra.signins.interactive
	//     and entra.directory_audits already emit those records, both are
	//     logs-only collectors, and both are default-on — so subscribing here
	//     duplicates them into the same pipeline.
	ContentTypes []string `yaml:"content_types"`
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
	// MetricRecencyWindow gates blob-derived metrics (#128): a record whose event
	// time is older than this takes the log path only, never a counter, so a
	// backfilled event can never be credited to "now" (OTEL counters are stamped
	// at export time under cumulative temporality). Default 20m — steady-state
	// blob latency is ~5m and the tick is 5m, so ~15m is the floor; 20m gives
	// margin. Validated (0, 1h]: a larger window would re-admit backfill, the
	// exact bug the gate exists to prevent.
	MetricRecencyWindow time.Duration `yaml:"metric_recency_window"`
}

// DefaultMetricRecencyWindow is the blob-derived-metrics gate window when a
// tenant leaves metric_recency_window unset (#128).
const DefaultMetricRecencyWindow = 20 * time.Minute

// MaxMetricRecencyWindow is the hard ceiling on the gate window: a larger value
// would re-admit backfilled events into cumulative counters (#128).
const MaxMetricRecencyWindow = time.Hour

// BlobMetricRecencyWindow returns the effective blob-derived-metrics recency
// window for a tenant. blob_ingest is a per-tenant, file-only key — there is no
// top-level Config.BlobIngest — so this iterates tenants and falls back to
// DefaultMetricRecencyWindow, never to a global block.
func (c *Config) BlobMetricRecencyWindow(tenantID string) time.Duration {
	for i := range c.Tenants {
		if c.Tenants[i].TenantID == tenantID && c.Tenants[i].BlobIngest.MetricRecencyWindow > 0 {
			return c.Tenants[i].BlobIngest.MetricRecencyWindow
		}
	}
	return DefaultMetricRecencyWindow
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

// CollectorSource resolves the ingest transport for a collector, applying the
// same precedence as CollectorSettings (per-tenant override > global collectors
// config > built-in default). Returns "graph" (the default) or "blob".
// ValidateCollectorOverrides rejects an unrecognized or inapplicable source
// before runtime construction; the graph fallback here is defensive for direct
// callers that construct Config values without running startup validation.
func (c *Config) CollectorSource(tenantID, collectorName string) string {
	src := ""
	if gc, ok := c.Collectors[collectorName]; ok && gc.Source != "" {
		src = gc.Source
	}
	for i := range c.Tenants {
		if c.Tenants[i].TenantID != tenantID {
			continue
		}
		if tc, ok := c.Tenants[i].Collectors[collectorName]; ok && tc.Source != "" {
			src = tc.Source
		}
		break
	}
	if src == "blob" {
		return "blob"
	}
	return "graph"
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
	// TokenFile is an optional path to a file holding the OTLP push token — the
	// file-based alternative to Token (and G2O_OTLP__GRAFANA_CLOUD__TOKEN),
	// intended for Kubernetes/Docker secret mounts, and mirroring
	// mdca.token_file (#145/#212). value XOR file: set token OR token_file,
	// never both. Load reads the file (trimming a trailing newline) into Token,
	// so the resolved credential still redacts in every config dump.
	TokenFile string `yaml:"token_file"`
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
			Enabled:         false,
			Addr:            ":9090",
			RefreshInterval: 5 * time.Second,
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
			// Generous defaults: graph2otel's metrics are bounded tenant-shaped
			// aggregates, and the largest on a live tenant measures 175 series
			// (`live-measured 2026-07-23, #235`). These are blast-radius guards
			// against a mis-scoped label, not normal operating constraints — and
			// unlike the SDK cap they replace, exceeding one degrades gracefully
			// into a named `other` bucket rather than dropping series at random,
			// which is what makes a higher default the safer one. 0 = unlimited.
			PerMetricLimit: 5000,
			GlobalLimit:    100_000,
		},
		Cost: CostConfig{
			Period: 30 * 24 * time.Hour,
		},
		GrafanaAnnotations: defaultGrafanaAnnotations(),
		CheckpointDir:      "./checkpoints",
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

	collectorEnv, err := strictEnvironment()
	if err != nil {
		return nil, err
	}

	// 1. Built-in defaults.
	if err := k.Load(structs.Provider(Default(), "yaml"), nil); err != nil {
		return nil, fmt.Errorf("load defaults: %w", err)
	}

	// 2. Optional YAML file (overrides defaults).
	if path != "" {
		if err := validateYAMLFile(path); err != nil {
			return nil, err
		}
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

	// #235 removed cardinality.metric_limit. koanf silently ignores a key with no
	// matching struct field, so an operator who had tuned it would lose the
	// setting without a word — and it is not a pure rename: the old key drove the
	// OTEL SDK's ARRIVAL-ordered per-instrument cap, which is now disabled
	// entirely in favor of a significance-ranked limiter. Somebody who set it to
	// 50000 to neuter the old behavior would silently inherit the new one at its
	// default. Refusing to start is the loud option.
	if k.Exists("cardinality" + keyDelim + "metric_limit") {
		return nil, fmt.Errorf("cardinality.metric_limit was removed in #235: it set the OTEL " +
			"SDK's arrival-ordered per-instrument cap, which graph2otel now disables in favor " +
			"of its own significance-ranked limiter. Use cardinality.per_metric_limit " +
			"(G2O_CARDINALITY__PER_METRIC_LIMIT, default 5000, 0 = unlimited) and " +
			"cardinality.global_limit (default 100000)")
	}

	var cfg Config
	if err := k.UnmarshalWithConf("", &cfg, koanf.UnmarshalConf{
		Tag: "yaml",
		DecoderConfig: &mapstructure.DecoderConfig{
			Result:           &cfg,
			WeaklyTypedInput: true, // env values are strings ("true", "10", ...)
			ErrorUnused:      true,
			// Decode duration strings ("5m", "30s") from the file/env layers
			// into time.Duration fields (collector intervals). Values already
			// typed as time.Duration (the structs defaults layer) pass through.
			DecodeHook: mapstructure.StringToTimeDurationHookFunc(),
		},
	}); err != nil {
		return nil, fmt.Errorf("decode config: %w", err)
	}

	if err := applyCollectorEnvironment(&cfg, collectorEnv); err != nil {
		return nil, err
	}

	// Resolve the *_file secret siblings once all layers are merged, so an
	// inline value from any layer (YAML or the G2O_* environment) participates
	// in the value-XOR-file check.
	if err := cfg.resolveSecretFiles(); err != nil {
		return nil, err
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
		tenantUUID, err := uuid.Parse(t.TenantID)
		if err != nil || tenantUUID.String() != strings.ToLower(t.TenantID) {
			return fmt.Errorf(
				"tenants[%d].tenant_id %q: must be a hyphenated Entra directory GUID",
				i,
				t.TenantID,
			)
		}
		tenantKey := tenantUUID.String()
		if seen[tenantKey] {
			return fmt.Errorf("tenants[%d].tenant_id %q: duplicate tenant", i, t.TenantID)
		}
		seen[tenantKey] = true

		for name, cc := range t.Collectors {
			if err := validateInterval(cc.Interval); err != nil {
				return fmt.Errorf("tenants[%d].collectors[%q].interval: %w", i, name, err)
			}
		}

		if err := validateBlobAccountURL(t.BlobIngest.AccountURL); err != nil {
			return fmt.Errorf("tenants[%d].blob_ingest.account_url: %w", i, err)
		}

		if w := t.BlobIngest.MetricRecencyWindow; w < 0 || w > MaxMetricRecencyWindow {
			return fmt.Errorf("tenants[%d].blob_ingest.metric_recency_window: %v out of range (0, %v]", i, w, MaxMetricRecencyWindow)
		}

		if err := t.MDCA.validate(); err != nil {
			return fmt.Errorf("tenants[%d].mdca.%w", i, err)
		}

		if err := t.PrivilegedGroups.validate(); err != nil {
			return fmt.Errorf("tenants[%d].privileged_groups.%w", i, err)
		}
	}

	for name, cc := range c.Collectors {
		if err := validateInterval(cc.Interval); err != nil {
			return fmt.Errorf("collectors[%q].interval: %w", name, err)
		}
	}

	if c.Cardinality.PerMetricLimit < 0 {
		return fmt.Errorf("cardinality.per_metric_limit %d invalid: must be >= 0 (0 = unlimited)",
			c.Cardinality.PerMetricLimit)
	}
	if c.Cardinality.GlobalLimit < 0 {
		return fmt.Errorf("cardinality.global_limit %d invalid: must be >= 0 (0 = unlimited)",
			c.Cardinality.GlobalLimit)
	}

	if c.Cost.Enabled {
		if !isUpperCurrencyCode(c.Cost.Currency) {
			return fmt.Errorf(
				"cost.currency %q invalid: must be an uppercase 3-letter currency code",
				c.Cost.Currency,
			)
		}
		if strings.TrimSpace(c.Cost.Version) == "" {
			return fmt.Errorf("cost.version: required when cost.enabled is true")
		}
		if strings.TrimSpace(c.Cost.Source) == "" {
			return fmt.Errorf("cost.source: required when cost.enabled is true")
		}
		if _, err := time.Parse(time.RFC3339, c.Cost.EffectiveAt); err != nil {
			return fmt.Errorf("cost.effective_at %q invalid: must be RFC3339", c.Cost.EffectiveAt)
		}
		if c.Cost.Period <= 0 {
			return fmt.Errorf("cost.period %v invalid: must be > 0", c.Cost.Period)
		}
		for _, rate := range []struct {
			name  string
			value *int64
		}{
			{"source_record_microunits", c.Cost.Rates.SourceRecord},
			{"metric_point_microunits", c.Cost.Rates.MetricPoint},
			{"log_record_microunits", c.Cost.Rates.LogRecord},
			{"transmitted_payload_byte_microunits", c.Cost.Rates.TransmittedPayloadByte},
		} {
			if rate.value == nil {
				return fmt.Errorf(
					"cost.rates.%s: required when cost.enabled is true",
					rate.name,
				)
			}
			if *rate.value < 0 {
				return fmt.Errorf(
					"cost.rates.%s %d invalid: must be >= 0",
					rate.name,
					*rate.value,
				)
			}
		}
		if c.Cost.BudgetMicrounits < 0 {
			return fmt.Errorf(
				"cost.budget_microunits %d invalid: must be >= 0 (0 = no comparison)",
				c.Cost.BudgetMicrounits,
			)
		}
	}

	if c.Profiling.Pyroscope.Enabled && c.Profiling.Pyroscope.ServerAddress == "" {
		return fmt.Errorf("profiling.pyroscope.server_address is required when profiling.pyroscope.enabled is true")
	}

	if c.Backfill.InitialLookback < 0 {
		return fmt.Errorf("backfill.initial_lookback %v invalid: must be >= 0 (0 means use each collector's built-in lookback)",
			c.Backfill.InitialLookback)
	}

	if err := c.GrafanaAnnotations.validate(); err != nil {
		return fmt.Errorf("grafana_annotations.%w", err)
	}

	return nil
}

func isUpperCurrencyCode(value string) bool {
	if len(value) != 3 {
		return false
	}
	for i := range value {
		if value[i] < 'A' || value[i] > 'Z' {
			return false
		}
	}
	return true
}

// backendAcceptWindow is how far back the OTLP backend accepts log samples.
//
// MEASURED, not assumed (#226, live against the Grafana Cloud OTLP gateway
// 2026-07-22). The gateway states the limit itself, in the rejection body:
//
//	400 Bad Request: entry for stream '{service_name="…"}' has timestamp too
//	old: 2026-07-08T13:05:10Z, oldest acceptable timestamp is: 2026-07-15T13:05:10Z
//
// which is exactly now-168h. Records at 12h, 1d, 2d and 3d all landed; 7d and
// 14d were rejected. Rejection is per-ENTRY, not per-batch — the same push had
// its in-window records accepted while the two out-of-window ones were refused —
// so one over-old record cannot poison a batch of good ones.
//
// It is a warning threshold rather than a hard cap for a reason that still
// holds: graph2otel cannot know every backend's retention policy. A self-hosted
// Loki may be configured wider and a non-Loki OTLP sink has entirely different
// rules, so refusing to start on a value the operator's own backend accepts would
// be the same class of mistake as the failure it guards against.
//
// What CHANGED (2026-07-27, #401): the value is now clamped at
// telemetry.EventHorizon for the actual poll, while the configured value is still
// reported. Reaching further back than the backend accepts is not a longer
// recovery, it is a slower one that ends in per-entry rejections — so the clamp
// removes wasted work rather than capability. An operator whose sink accepts more
// raises the horizon explicitly; see EffectiveInitialLookback.
const backendAcceptWindow = 7 * 24 * time.Hour

// Warnings returns non-fatal configuration advisories: settings that are valid,
// take effect exactly as written, and are still very likely not what the operator
// meant. It is separate from Validate because none of these should stop the
// process — the caller logs them (see cmd/graph2otel).
func (c *Config) Warnings() []string {
	var out []string

	// A lookback beyond Grafana Cloud's measured accept window is NOT a longer
	// recovery: the gateway explicitly rejects each over-age entry. Keep the
	// accepted-but-late indexing path separate — an in-window backdated record may
	// take minutes to become queryable even though the gateway accepted it.
	// ONE warning, not two. Before #401 this advised that the value was NOT
	// clamped; it now is, so keeping the old text alongside the new would leave two
	// live statements that contradict each other — worse than either being absent,
	// because a reader has to guess which one is true.
	if c.Backfill.InitialLookback > telemetry.EventHorizon {
		out = append(out, fmt.Sprintf(
			"backfill.initial_lookback is %v and is CLAMPED to %v for the actual poll (#401). "+
				"Grafana Cloud's Loki accepts log samples for 7 days (%v, live-measured 2026-07-22, "+
				"#226). Its rejection is explicit and per-entry: the gateway returns HTTP 400 through "+
				"the OTel error handler for each over-age entry while accepting in-window entries in "+
				"the same batch, so reaching further back is not a longer recovery — it is the same "+
				"recovery plus rejected requests. The clamp keeps a %v margin because a rejection "+
				"observed in production on 2026-07-27 was only about an hour past the limit. A "+
				"self-hosted Loki or non-Loki OTLP sink may accept more; raise the emit horizon "+
				"deliberately if yours does. Accepted in-window backdated records can still be indexed "+
				"later, so an immediately empty query is not evidence of rejection.",
			c.Backfill.InitialLookback, telemetry.EventHorizon, backendAcceptWindow,
			backendAcceptWindow-telemetry.EventHorizon))
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
