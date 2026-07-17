// Package organization is the Entra organization/tenant-posture collector:
// GET /organization (a single-element collection — there is exactly one
// organization object per tenant) emitted as directory-sync freshness plus a
// handful of bounded tenant-posture gauges.
//
// Deviation from the tracking issue: the current Microsoft Graph v1.0
// organization resource has NO onPremisesLastPasswordSyncDateTime property
// (verified against learn.microsoft.com/graph/api/resources/organization on
// 2026-07-15) — that field exists only on the user resource. Only
// onPremisesLastSyncDateTime is read here.
package organization

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

// collectorName is the stable key used for config (enable/interval),
// self-observability, and the admin status page.
const collectorName = "entra.organization"

// Metric names this collector emits.
const (
	// syncAgeMetricName is the operationally useful signal: how stale the
	// on-premises directory (AD Connect / Cloud Sync) is. Only emitted when
	// hybrid sync is enabled AND Graph reports a last-sync timestamp, so a
	// cloud-only tenant never gets a misleading "0/huge" value.
	syncAgeMetricName = "entra.directory.sync.last_sync_age_seconds"
	// syncEnabledMetricName mirrors onPremisesSyncEnabled as 0/1. Graph's
	// null (never synced from on-premises AD, the cloud-only default) and
	// false (previously synced, no longer) both collapse to 0 — only true
	// means "currently hybrid-synced".
	syncEnabledMetricName = "entra.organization.on_premises_sync_enabled"
	// ageDaysMetricName is the tenant's age from createdDateTime, in days.
	ageDaysMetricName = "entra.organization.age_days"
	// verifiedDomainsMetricName is the total count of verified domains on the
	// tenant — a single aggregate, not a per-domain series, so cardinality
	// never grows with tenant size.
	verifiedDomainsMetricName = "entra.organization.verified_domains.total"
	// infoMetricName is a build_info-style constant-1 gauge carrying bounded
	// tenant posture (tenantType has exactly three possible values: AAD,
	// AAD B2C, CIAM) as an attribute. Never the tenant id or displayName —
	// those are resource-attribute concerns (composition root/#8), not
	// metric label values.
	infoMetricName = "entra.organization.info"
)

// defaultBaseURL is the Graph v1.0 root.
const defaultBaseURL = "https://graph.microsoft.com/v1.0"

// graphOrganization mirrors the subset of the Graph organization resource
// this collector reads. Pointer fields distinguish "absent/null" (Graph's
// documented default for a cloud-only tenant) from a real zero value.
type graphOrganization struct {
	TenantType                 string            `json:"tenantType"`
	CreatedDateTime            *time.Time        `json:"createdDateTime"`
	OnPremisesSyncEnabled      *bool             `json:"onPremisesSyncEnabled"`
	OnPremisesLastSyncDateTime *time.Time        `json:"onPremisesLastSyncDateTime"`
	VerifiedDomains            []json.RawMessage `json:"verifiedDomains"`
}

// Collector polls GET /organization.
type Collector struct {
	g       collectors.GraphClient
	baseURL string
	logger  *slog.Logger
	// now is the clock used for age computations; overridden in tests for a
	// deterministic result, defaults to time.Now.
	now func() time.Time
}

// New builds the organization collector. A nil logger falls back to the slog
// default.
func New(g collectors.GraphClient, logger *slog.Logger) *Collector {
	if logger == nil {
		logger = slog.Default()
	}
	return &Collector{g: g, baseURL: defaultBaseURL, logger: logger, now: time.Now}
}

// Name implements collector.Collector.
func (c *Collector) Name() string { return collectorName }

// DefaultInterval implements collector.Collector. Tenant posture and
// directory-sync freshness both drift slowly; fifteen minutes is ample and
// cheap on the directory-objects throttle bucket.
func (c *Collector) DefaultInterval() time.Duration { return 15 * time.Minute }

// RequiredPermissions declares the least-privilege Graph application scope.
// Per current Microsoft Graph docs (learn.microsoft.com/graph/api/organization-get),
// Organization.Read.All is the least-privileged application permission that
// reads every property this collector needs (Directory.Read.All also works,
// per the issue, but is the broader blanket scope).
func (c *Collector) RequiredPermissions() []string { return []string{"Organization.Read.All"} }

// Collect fetches the tenant's single organization object and emits
// directory-sync freshness plus bounded tenant-posture gauges. GET
// /organization returns a collection with exactly one element (verified
// against current Graph docs), so GetAllValues — meant for small, bounded
// collections — is the right helper; element [0] is the tenant.
func (c *Collector) Collect(ctx context.Context, e telemetry.Emitter) error {
	raw, err := collectors.GetAllValues(ctx, c.g, c.baseURL+"/organization", nil)
	if err != nil {
		return fmt.Errorf("organization: fetch organization: %w", err)
	}
	if len(raw) == 0 {
		c.logger.Warn("organization: /organization returned an empty collection; skipping this cycle", "collector", collectorName)
		return nil
	}

	var org graphOrganization
	if err := json.Unmarshal(raw[0], &org); err != nil {
		return fmt.Errorf("organization: decode organization: %w", err)
	}

	syncEnabled := org.OnPremisesSyncEnabled != nil && *org.OnPremisesSyncEnabled
	e.Gauge(syncEnabledMetricName, semconv.UnitDimensionless,
		"1 if the tenant is currently synced from an on-premises directory (hybrid AD Connect/Cloud Sync), else 0.",
		boolToFloat(syncEnabled), nil)

	if syncEnabled && org.OnPremisesLastSyncDateTime != nil {
		age := c.now().Sub(*org.OnPremisesLastSyncDateTime).Seconds()
		if age < 0 {
			age = 0
		}
		e.Gauge(syncAgeMetricName, semconv.UnitSeconds,
			"Seconds since the on-premises directory last synced to this tenant. Only emitted when on-premises sync is enabled and a last-sync timestamp is available.",
			age, nil)
	}

	if org.CreatedDateTime != nil {
		ageDays := c.now().Sub(*org.CreatedDateTime).Hours() / 24
		if ageDays < 0 {
			ageDays = 0
		}
		e.Gauge(ageDaysMetricName, "d", "Age of the Entra tenant in days, from its createdDateTime.", ageDays, nil)
	}

	e.Gauge(verifiedDomainsMetricName, "{domain}",
		"Total verified domains associated with the tenant.",
		float64(len(org.VerifiedDomains)), nil)

	tenantType := org.TenantType
	if tenantType == "" {
		tenantType = "unknown"
	}
	e.Gauge(infoMetricName, semconv.UnitDimensionless,
		"Constant 1 gauge carrying bounded tenant posture (tenant type) as an attribute.",
		1, telemetry.Attrs{semconv.AttrTenantType: tenantType})

	return nil
}

func boolToFloat(b bool) float64 {
	if b {
		return 1
	}
	return 0
}

func init() {
	collectors.Register(func(d collectors.Deps) collector.SnapshotCollector {
		return New(d.Graph, d.Logger)
	})
}
