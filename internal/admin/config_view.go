package admin

import (
	"sort"

	"github.com/rknightion/graph2otel/internal/config"
)

// ConfigView is the effective, NON-secret configuration rendered on the Config
// tab and served at /api/config.json (#211). It is assembled entirely from the
// injected *config.Config — a passive in-memory read, never a live tenant call.
//
// Every credential is surfaced PRESENCE-ONLY: this struct stores a bool
// (…Set) for each config.Secret, never the value, so neither the HTML page nor
// the JSON encoding can leak a token. The presence bit is derived via
// Secret.Reveal at build time and the revealed string is discarded immediately;
// no config.Secret ever reaches this view (see configView).
type ConfigView struct {
	LogLevel        string                `json:"log_level"`
	CheckpointDir   string                `json:"checkpoint_dir"`
	RefreshInterval string                `json:"refresh_interval,omitempty"`
	TenantCount     int                   `json:"tenant_count"`
	OTLP            ConfigOTLPView        `json:"otlp"`
	Profiling       ConfigProfilingView   `json:"profiling"`
	Cardinality     ConfigCardinalityView `json:"cardinality"`
	// BackfillInitialLookback is the cold-start backfill override, empty ("") when
	// unset (each collector uses its own built-in lookback).
	BackfillInitialLookback string `json:"backfill_initial_lookback,omitempty"`
	// Collectors are the GLOBAL per-collector overrides (Config.Collectors),
	// sorted by name for deterministic output.
	Collectors []ConfigCollectorView `json:"collectors,omitempty"`
	// Tenants is the per-tenant non-secret view (identifiers + collector overrides).
	Tenants []ConfigTenantView `json:"tenants,omitempty"`
}

// ConfigOTLPView is the OTLP exporter config; GrafanaToken is presence-only.
type ConfigOTLPView struct {
	Protocol          string `json:"protocol"`
	Endpoint          string `json:"endpoint"`
	GrafanaInstanceID string `json:"grafana_instance_id,omitempty"`
	GrafanaTokenSet   bool   `json:"grafana_token_set"`
}

// ConfigProfilingView is the profiling config; the Pyroscope basic-auth
// password is presence-only.
type ConfigProfilingView struct {
	PyroscopeEnabled              bool   `json:"pyroscope_enabled"`
	PyroscopeServerAddress        string `json:"pyroscope_server_address,omitempty"`
	PyroscopeBasicAuthUser        string `json:"pyroscope_basic_auth_user,omitempty"`
	PyroscopeBasicAuthPasswordSet bool   `json:"pyroscope_basic_auth_password_set"`
	MutexProfileFraction          int    `json:"mutex_profile_fraction"`
	BlockProfileRate              int    `json:"block_profile_rate"`
}

// ConfigCardinalityView carries the configured per-instrument series limit.
type ConfigCardinalityView struct {
	MetricLimit int `json:"metric_limit"`
}

// ConfigTenantView is one tenant's non-secret configuration. TenantConfig
// carries no credential material at all (auth is resolved out of band via
// DefaultAzureCredential), so every field here is safe to render.
type ConfigTenantView struct {
	TenantID    string `json:"tenant_id"`
	ClientID    string `json:"client_id,omitempty"`
	ExcludeSelf bool   `json:"exclude_self,omitempty"`
	// BlobIngest is true when this tenant has a blob storage account configured.
	BlobIngest bool `json:"blob_ingest,omitempty"`
	// Overrides are this tenant's per-collector overrides, sorted by name.
	Overrides []ConfigCollectorView `json:"collector_overrides,omitempty"`
}

// ConfigCollectorView is one collector override entry (global or per-tenant).
// Enabled is a *bool so an unset override (inherit) is distinct from an explicit
// false; Interval/Source are empty when unset.
type ConfigCollectorView struct {
	Name     string `json:"name"`
	Enabled  *bool  `json:"enabled,omitempty"`
	Interval string `json:"interval,omitempty"`
	Source   string `json:"source,omitempty"`
}

// EnabledLabel renders the tri-state Enabled pointer for the HTML page.
func (c ConfigCollectorView) EnabledLabel() string {
	switch {
	case c.Enabled == nil:
		return "—"
	case *c.Enabled:
		return "enabled"
	default:
		return "disabled"
	}
}

// configView assembles the non-secret configuration snapshot from s.cfg. A nil
// cfg (e.g. not wired) yields a zero view rather than a panic. It makes no live
// call — it reads only the injected config struct.
func (s *Server) configView() ConfigView {
	if s.cfg == nil {
		return ConfigView{}
	}
	c := s.cfg
	v := ConfigView{
		LogLevel:      c.LogLevel,
		CheckpointDir: c.CheckpointDir,
		TenantCount:   len(c.Tenants),
		OTLP: ConfigOTLPView{
			Protocol:          c.OTLP.Protocol,
			Endpoint:          c.OTLP.Endpoint,
			GrafanaInstanceID: c.OTLP.GrafanaCloud.InstanceID,
			// Presence-only: Reveal is called solely to test for emptiness; the
			// revealed value is never stored or emitted.
			GrafanaTokenSet: c.OTLP.GrafanaCloud.Token.Reveal() != "",
		},
		Profiling: ConfigProfilingView{
			PyroscopeEnabled:              c.Profiling.Pyroscope.Enabled,
			PyroscopeServerAddress:        c.Profiling.Pyroscope.ServerAddress,
			PyroscopeBasicAuthUser:        c.Profiling.Pyroscope.BasicAuthUser,
			PyroscopeBasicAuthPasswordSet: c.Profiling.Pyroscope.BasicAuthPassword.Reveal() != "",
			MutexProfileFraction:          c.Profiling.MutexProfileFraction,
			BlockProfileRate:              c.Profiling.BlockProfileRate,
		},
		Cardinality: ConfigCardinalityView{MetricLimit: c.Cardinality.MetricLimit},
		Collectors:  collectorOverrides(c.Collectors),
	}
	if c.Admin.RefreshInterval > 0 {
		v.RefreshInterval = c.Admin.RefreshInterval.String()
	}
	if c.Backfill.InitialLookback > 0 {
		v.BackfillInitialLookback = c.Backfill.InitialLookback.String()
	}
	for i := range c.Tenants {
		t := c.Tenants[i]
		v.Tenants = append(v.Tenants, ConfigTenantView{
			TenantID:    t.TenantID,
			ClientID:    t.ClientID,
			ExcludeSelf: t.ExcludeSelf,
			BlobIngest:  t.BlobIngest.AccountURL != "",
			Overrides:   collectorOverrides(t.Collectors),
		})
	}
	return v
}

// collectorOverrides flattens a collector-override map into a name-sorted slice
// for deterministic rendering. Returns nil for an empty map.
func collectorOverrides(m map[string]config.CollectorConfig) []ConfigCollectorView {
	if len(m) == 0 {
		return nil
	}
	names := make([]string, 0, len(m))
	for n := range m {
		names = append(names, n)
	}
	sort.Strings(names)
	out := make([]ConfigCollectorView, 0, len(names))
	for _, n := range names {
		cc := m[n]
		cv := ConfigCollectorView{Name: n, Enabled: cc.Enabled, Source: cc.Source}
		if cc.Interval > 0 {
			cv.Interval = cc.Interval.String()
		}
		out = append(out, cv)
	}
	return out
}
