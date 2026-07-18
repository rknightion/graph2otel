// Package sharepointsettings polls the tenant's SharePoint/OneDrive sharing
// posture (#127): GET /admin/sharepoint/settings, one tenant-config object,
// emitted as bounded security-posture gauges plus a log twin carrying the full
// configuration — including the external-sharing domain allow/block lists,
// which are unbounded and so must live as log attributes, never metric labels
// (#112).
//
// Every field mapped below was verified against a live sample captured
// 2026-07-18 as graph2otel-poller (needs SharePointTenantSettings.Read.All,
// granted that day) — nothing here is inferred from documentation.
package sharepointsettings

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"time"

	"github.com/rknightion/graph2otel/internal/collector"
	"github.com/rknightion/graph2otel/internal/collectors"
	"github.com/rknightion/graph2otel/internal/semconv"
	"github.com/rknightion/graph2otel/internal/telemetry"
)

const (
	// collectorName is the stable config/self-obs key.
	collectorName = "m365.sharepoint_settings"
	// eventName is the OTLP LogRecord EventName the posture twin carries.
	eventName      = "m365.sharepoint_settings"
	defaultBaseURL = "https://graph.microsoft.com/v1.0"

	metricSharing                 = "m365.sharepoint.sharing"
	metricLegacyAuth              = "m365.sharepoint.legacy_auth_enabled"
	metricExternalResharing       = "m365.sharepoint.external_resharing_enabled"
	metricUnmanagedSyncRestricted = "m365.sharepoint.unmanaged_sync_restricted"
	metricIdleSignout             = "m365.sharepoint.idle_session_signout_enabled"
	metricAllowedDomains          = "m365.sharepoint.sharing_allowed_domains"
	metricBlockedDomains          = "m365.sharepoint.sharing_blocked_domains"
	metricPersonalStorageMB       = "m365.sharepoint.personal_site_storage_limit_mb"
	metricSiteStorageMB           = "m365.sharepoint.site_storage_limit_mb"
	metricRetentionDays           = "m365.sharepoint.deleted_user_retention_days"
)

// settings is the subset of /admin/sharepoint/settings this collector reads.
type settings struct {
	SharingCapability                     string   `json:"sharingCapability"`
	SharingDomainRestrictionMode          string   `json:"sharingDomainRestrictionMode"`
	SharingAllowedDomainList              []string `json:"sharingAllowedDomainList"`
	SharingBlockedDomainList              []string `json:"sharingBlockedDomainList"`
	IsLegacyAuthProtocolsEnabled          bool     `json:"isLegacyAuthProtocolsEnabled"`
	IsResharingByExternalUsersEnabled     bool     `json:"isResharingByExternalUsersEnabled"`
	IsUnmanagedSyncAppForTenantRestricted bool     `json:"isUnmanagedSyncAppForTenantRestricted"`
	PersonalSiteStorageLimitMB            float64  `json:"personalSiteDefaultStorageLimitInMB"`
	SiteStorageLimitMB                    float64  `json:"siteCreationDefaultStorageLimitInMB"`
	DeletedUserRetentionDays              float64  `json:"deletedUserPersonalSiteRetentionPeriodInDays"`
	IdleSessionSignOut                    struct {
		IsEnabled bool `json:"isEnabled"`
	} `json:"idleSessionSignOut"`
}

// Collector polls GET /admin/sharepoint/settings.
type Collector struct {
	g       collectors.GraphClient
	baseURL string
	logger  *slog.Logger
}

// New builds the SharePoint settings collector. A nil logger falls back to the
// slog default.
func New(g collectors.GraphClient, logger *slog.Logger) *Collector {
	if logger == nil {
		logger = slog.Default()
	}
	return &Collector{g: g, baseURL: defaultBaseURL, logger: logger}
}

// Name implements collector.Collector.
func (c *Collector) Name() string { return collectorName }

// DefaultInterval implements collector.Collector. Tenant sharing/security config
// is admin-authored and drifts slowly; hourly is ample.
func (c *Collector) DefaultInterval() time.Duration { return time.Hour }

// RequiredPermissions declares the least-privilege Graph application scope.
func (c *Collector) RequiredPermissions() []string {
	return []string{"SharePointTenantSettings.Read.All"}
}

func boolToFloat(b bool) float64 {
	if b {
		return 1
	}
	return 0
}

func orUnknown(s string) string {
	if s == "" {
		return "unknown"
	}
	return s
}

// Collect fetches the single settings object and emits the bounded posture
// gauges plus the full-config log twin. /admin/sharepoint/settings is a single
// resource (not a collection), so it is read with RawGet directly.
func (c *Collector) Collect(ctx context.Context, e telemetry.Emitter) error {
	raw, err := c.g.RawGet(ctx, c.baseURL+"/admin/sharepoint/settings")
	if err != nil {
		return fmt.Errorf("sharepointsettings: fetch settings: %w", err)
	}
	var s settings
	if err := json.Unmarshal(raw, &s); err != nil {
		return fmt.Errorf("sharepointsettings: decode settings: %w", err)
	}

	// Bounded security-posture gauges. sharingCapability + the domain-restriction
	// mode are a small closed enum set, so they ride a constant-1 info gauge as
	// attributes; the rest are 0/1 or numeric limits.
	e.Gauge(metricSharing, semconv.UnitDimensionless,
		"Constant 1 carrying the tenant's external-sharing posture as bounded attributes.",
		1, telemetry.Attrs{
			semconv.AttrSharingCapability:            orUnknown(s.SharingCapability),
			semconv.AttrSharingDomainRestrictionMode: orUnknown(s.SharingDomainRestrictionMode),
		})
	e.Gauge(metricLegacyAuth, semconv.UnitDimensionless,
		"1 if legacy authentication protocols are enabled tenant-wide (a security risk), else 0.",
		boolToFloat(s.IsLegacyAuthProtocolsEnabled), nil)
	e.Gauge(metricExternalResharing, semconv.UnitDimensionless,
		"1 if external users may re-share content that was shared with them, else 0.",
		boolToFloat(s.IsResharingByExternalUsersEnabled), nil)
	e.Gauge(metricUnmanagedSyncRestricted, semconv.UnitDimensionless,
		"1 if the OneDrive sync app is restricted to managed/domain-joined devices, else 0.",
		boolToFloat(s.IsUnmanagedSyncAppForTenantRestricted), nil)
	e.Gauge(metricIdleSignout, semconv.UnitDimensionless,
		"1 if idle-session sign-out is enabled for SharePoint/OneDrive, else 0.",
		boolToFloat(s.IdleSessionSignOut.IsEnabled), nil)
	e.Gauge(metricAllowedDomains, "{domain}",
		"Count of domains on the external-sharing allow list.",
		float64(len(s.SharingAllowedDomainList)), nil)
	e.Gauge(metricBlockedDomains, "{domain}",
		"Count of domains on the external-sharing block list.",
		float64(len(s.SharingBlockedDomainList)), nil)
	e.Gauge(metricPersonalStorageMB, "MB",
		"Default per-user OneDrive storage limit, in MB.", s.PersonalSiteStorageLimitMB, nil)
	e.Gauge(metricSiteStorageMB, "MB",
		"Default per-site SharePoint storage limit, in MB.", s.SiteStorageLimitMB, nil)
	e.Gauge(metricRetentionDays, "d",
		"Retention period for a deleted user's personal site, in days.", s.DeletedUserRetentionDays, nil)

	// Log twin: the full posture, including the domain allow/block lists — those
	// are unbounded and so must never become metric labels (#112).
	attrs := telemetry.Attrs{}
	telemetry.SetStr(attrs, semconv.AttrSharingCapability, s.SharingCapability)
	telemetry.SetStr(attrs, semconv.AttrSharingDomainRestrictionMode, s.SharingDomainRestrictionMode)
	telemetry.SetStrs(attrs, semconv.AttrSharingAllowedDomains, s.SharingAllowedDomainList)
	telemetry.SetStrs(attrs, semconv.AttrSharingBlockedDomains, s.SharingBlockedDomainList)
	telemetry.SetBool(attrs, semconv.AttrLegacyAuthEnabled, s.IsLegacyAuthProtocolsEnabled)
	telemetry.SetBool(attrs, semconv.AttrExternalResharingEnabled, s.IsResharingByExternalUsersEnabled)
	telemetry.SetBool(attrs, semconv.AttrUnmanagedSyncRestricted, s.IsUnmanagedSyncAppForTenantRestricted)
	telemetry.SetBool(attrs, semconv.AttrIdleSessionSignoutEnabled, s.IdleSessionSignOut.IsEnabled)

	// Legacy auth on is the one posture that is a standing risk worth surfacing
	// above INFO on the log twin itself.
	sev := telemetry.SeverityInfo
	if s.IsLegacyAuthProtocolsEnabled {
		sev = telemetry.SeverityWarn
	}
	e.LogEvent(telemetry.Event{
		Name: eventName,
		Body: fmt.Sprintf("SharePoint sharing: %s (domain restriction: %s)",
			orUnknown(s.SharingCapability), orUnknown(s.SharingDomainRestrictionMode)),
		Severity: sev,
		Attrs:    attrs,
	})
	return nil
}

func init() {
	collectors.Register(func(d collectors.Deps) collector.SnapshotCollector {
		return New(d.Graph, d.Logger)
	})
}

// Compile-time check that the collector satisfies the interface the scheduler
// type-switches on.
var _ collector.SnapshotCollector = (*Collector)(nil)
