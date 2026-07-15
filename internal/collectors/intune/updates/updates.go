// Package updates is the Intune Windows Update management collector: Windows
// Update rings (a `deviceConfigurations` subtype) plus the beta feature/
// quality/driver update profile families.
//
// This collector owns EXACTLY the `windowsUpdateForBusinessConfiguration`
// slice of the heterogeneous `/deviceManagement/deviceConfigurations`
// collection (the frozen Group B partition, tracker #79 / issue #59) - every
// other `@odata.type` in that collection belongs to #53's config-profiles
// collector, so the ring list is always filtered client-side before any
// metric is derived from it.
//
// The ring metrics (pause/rollback/status) come from v1.0 endpoints and are
// always on. The feature/quality/driver update profile families exist only
// on /beta (v1.0 404s) and are where most of this collector's value lives, so
// the WHOLE collector implements collectors.Experimental (opt-in, off by
// default) rather than splitting into a v1.0-default + beta-opt-in pair -
// see the entra/recommendations precedent for the same call.
//
// Per-device rollout status (FeatureUpdateDeviceState,
// QualityUpdateDeviceStatusByPolicy, DriverUpdatePolicyStatusSummary, ...) is
// deliberately out of scope: those are export-job-only reports, deferred to
// the M5 export-job subsystem.
package updates

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/rknightion/graph2otel/internal/collector"
	"github.com/rknightion/graph2otel/internal/collectors"
	"github.com/rknightion/graph2otel/internal/telemetry"
)

// collectorName is the stable key used for config (enable/interval),
// self-observability, and the admin status page.
const collectorName = "intune.updates"

// Metric names this collector emits. Each is its own metric name so that
// summing a single metric always yields the true count/value for that
// breakdown - mixing independent dimensions under one metric name would mean
// a naive `sum()` over it silently multi-counts.
const (
	pauseStateMetric      = "intune.update_ring.pause_state"
	pauseExpiryMetric     = "intune.update_ring.pause_expiry_seconds"
	rollbackActiveMetric  = "intune.update_ring.rollback_active"
	ringStatusMetric      = "intune.update_ring.status"
	featureEOLMetric      = "intune.feature_update_profile.eol_target"
	driverPendingMetric   = "intune.driver_update.pending_approval"
	driverStalenessMetric = "intune.driver_update.sync_staleness_seconds"
	// qualityConfigCountMetric is not named in the tracking issue's telemetry
	// model (which only lists ring + feature-profile + driver-profile
	// metrics); windowsQualityUpdateProfiles/windowsQualityUpdatePolicies are
	// still an explicit scope item ("config drift"), so this collector polls
	// both and emits a bounded per-resource-type count as the cheapest
	// drift-visible signal (a count change = a profile/policy was added or
	// removed) rather than skipping the fetch entirely. Flagged for the
	// integrator to confirm/rename.
	qualityConfigCountMetric = "intune.quality_update_config.count"
)

// defaultBaseURL is the Graph v1.0 root - deviceConfigurations and its
// deviceStatusOverview child are v1.0.
const defaultBaseURL = "https://graph.microsoft.com/v1.0"

// betaBaseURL is the Graph beta root - windowsFeatureUpdateProfiles,
// windowsQualityUpdateProfiles, windowsQualityUpdatePolicies, and
// windowsDriverUpdateProfiles all 404 on v1.0 (verified per the tracking
// issue's API surface table).
const betaBaseURL = "https://graph.microsoft.com/beta"

// windowsUpdateForBusinessODataType is the one deviceConfigurations subtype
// this collector owns (the frozen Group B partition). Every other
// @odata.type value in that collection is #53's and must never be emitted
// from here.
const windowsUpdateForBusinessODataType = "#microsoft.graph.windowsUpdateForBusinessConfiguration"

// odataTyped is decoded first from every deviceConfigurations element to
// branch on @odata.type before committing to the full updateRingConfig
// unmarshal - the collection is heterogeneous and other subtypes don't share
// this schema.
type odataTyped struct {
	ODataType string `json:"@odata.type"`
	ID        string `json:"id"`
}

// updateRingConfig is the subset of the windowsUpdateForBusinessConfiguration
// resource this collector reads
// (https://learn.microsoft.com/en-us/graph/api/resources/intune-deviceconfig-windowsupdateforbusinessconfiguration).
// Ring-specific properties reject server-side $filter ("Query parameters not
// supported" per the tracking issue), so the full object is fetched and
// filtered/read client-side.
type updateRingConfig struct {
	ID                                string     `json:"id"`
	DisplayName                       string     `json:"displayName"`
	QualityUpdatesPaused              bool       `json:"qualityUpdatesPaused"`
	FeatureUpdatesPaused              bool       `json:"featureUpdatesPaused"`
	QualityUpdatesPauseExpiryDateTime *time.Time `json:"qualityUpdatesPauseExpiryDateTime"`
	FeatureUpdatesPauseExpiryDateTime *time.Time `json:"featureUpdatesPauseExpiryDateTime"`
	QualityUpdatesWillBeRolledBack    bool       `json:"qualityUpdatesWillBeRolledBack"`
	FeatureUpdatesWillBeRolledBack    bool       `json:"featureUpdatesWillBeRolledBack"`
}

// deviceStatusOverview is the deviceConfigurationDeviceOverview singleton
// returned by a deviceConfiguration's /deviceStatusOverview child - a
// Microsoft-maintained rollup of per-device rollout state, never the
// per-device deviceStatuses collection itself.
type deviceStatusOverview struct {
	PendingCount       int64 `json:"pendingCount"`
	NotApplicableCount int64 `json:"notApplicableCount"`
	SuccessCount       int64 `json:"successCount"`
	ErrorCount         int64 `json:"errorCount"`
	FailedCount        int64 `json:"failedCount"`
}

// points returns the fixed 5-state rollup as bounded gauge points, ring_name
// already applied by the caller.
func (o deviceStatusOverview) points(ringName string) []telemetry.GaugePoint {
	return []telemetry.GaugePoint{
		{Value: float64(o.PendingCount), Attrs: telemetry.Attrs{"ring_name": ringName, "state": "pending"}},
		{Value: float64(o.NotApplicableCount), Attrs: telemetry.Attrs{"ring_name": ringName, "state": "not_applicable"}},
		{Value: float64(o.SuccessCount), Attrs: telemetry.Attrs{"ring_name": ringName, "state": "success"}},
		{Value: float64(o.ErrorCount), Attrs: telemetry.Attrs{"ring_name": ringName, "state": "error"}},
		{Value: float64(o.FailedCount), Attrs: telemetry.Attrs{"ring_name": ringName, "state": "failed"}},
	}
}

// graphDate unmarshals a Microsoft Graph Edm.Date scalar ("YYYY-MM-DD", no
// time component) - windowsFeatureUpdateProfile.endOfSupportDate uses this
// type rather than a full dateTimeOffset, so time.Time's own RFC3339
// unmarshaling can't be used directly.
type graphDate struct {
	time.Time
}

func (d *graphDate) UnmarshalJSON(b []byte) error {
	s := strings.Trim(string(b), `"`)
	if s == "" || s == "null" {
		return nil
	}
	t, err := time.Parse("2006-01-02", s)
	if err != nil {
		return fmt.Errorf("updates: parse graph date %q: %w", s, err)
	}
	d.Time = t
	return nil
}

// featureUpdateProfile is the subset of the windowsFeatureUpdateProfile
// (beta) resource this collector reads.
type featureUpdateProfile struct {
	DisplayName          string    `json:"displayName"`
	FeatureUpdateVersion string    `json:"featureUpdateVersion"`
	EndOfSupportDate     graphDate `json:"endOfSupportDate"`
}

// driverUpdateProfile is the subset of the windowsDriverUpdateProfile (beta)
// resource this collector reads. newUpdates/deviceReporting are embedded
// scalar fields on the profile itself - no driverInventories walk needed for
// the headline metrics, and syncInventory/executeAction are deliberately
// never called (they trigger backend work rather than just reading state).
type driverUpdateProfile struct {
	DisplayName     string `json:"displayName"`
	NewUpdates      int64  `json:"newUpdates"`
	DeviceReporting int64  `json:"deviceReporting"`
	InventorySync   struct {
		LastSuccessfulSyncDateTime *time.Time `json:"lastSuccessfulSyncDateTime"`
	} `json:"inventorySyncStatus"`
}

// namedResource is the minimal shape read from windowsQualityUpdateProfiles
// and windowsQualityUpdatePolicies - both are counted only (config-drift
// visibility), never per-entity, so nothing beyond a successful decode is
// needed.
type namedResource struct {
	DisplayName string `json:"displayName"`
}

// Collector polls the Windows Update ring subset of deviceConfigurations
// (v1.0) and the feature/quality/driver update profile families (beta).
type Collector struct {
	g       collectors.GraphClient
	baseURL string
	betaURL string
	logger  *slog.Logger
	// now returns the current time; overridable in tests so pause-expiry and
	// staleness countdowns are deterministic and assertable.
	now func() time.Time
}

// New builds the updates collector. A nil logger falls back to the slog
// default.
func New(g collectors.GraphClient, logger *slog.Logger) *Collector {
	if logger == nil {
		logger = slog.Default()
	}
	return &Collector{g: g, baseURL: defaultBaseURL, betaURL: betaBaseURL, logger: logger, now: time.Now}
}

// Name implements collector.Collector.
func (c *Collector) Name() string { return collectorName }

// DefaultInterval implements collector.Collector. Update ring/profile
// configuration is admin-authored and drifts slowly.
func (c *Collector) DefaultInterval() time.Duration { return 30 * time.Minute }

// Experimental marks this as a beta, opt-in collector: the feature/quality/
// driver profile families (the bulk of its value) exist only on /beta.
func (c *Collector) Experimental() bool { return true }

// RequiredPermissions declares the least-privilege Graph application scope
// every endpoint this collector polls documents.
func (c *Collector) RequiredPermissions() []string {
	return []string{"DeviceManagementConfiguration.Read.All"}
}

// Collect fetches update rings and the beta profile families. Each section
// is independently resilient: a failure in one is logged and joined into the
// returned error, but every other section's metrics still emit.
func (c *Collector) Collect(ctx context.Context, e telemetry.Emitter) error {
	var errs []error

	if err := c.collectRings(ctx, e); err != nil {
		c.logger.Warn("updates: update ring collection failed", "collector", collectorName, "error", err)
		errs = append(errs, fmt.Errorf("update rings: %w", err))
	}

	if err := c.collectFeatureProfiles(ctx, e); err != nil {
		c.logger.Warn("updates: feature update profile collection failed", "collector", collectorName, "error", err)
		errs = append(errs, fmt.Errorf("feature update profiles: %w", err))
	}

	if err := c.collectQualityConfigs(ctx, e); err != nil {
		c.logger.Warn("updates: quality update config collection failed", "collector", collectorName, "error", err)
		errs = append(errs, fmt.Errorf("quality update configs: %w", err))
	}

	if err := c.collectDriverProfiles(ctx, e); err != nil {
		c.logger.Warn("updates: driver update profile collection failed", "collector", collectorName, "error", err)
		errs = append(errs, fmt.Errorf("driver update profiles: %w", err))
	}

	return errors.Join(errs...)
}

// collectRings pages the heterogeneous deviceConfigurations collection,
// keeps only the windowsUpdateForBusinessConfiguration elements (the Group B
// partition this collector owns), fetches each kept ring's
// deviceStatusOverview, and emits the pause/expiry/rollback/status gauges.
func (c *Collector) collectRings(ctx context.Context, e telemetry.Emitter) error {
	raw, err := collectors.GetAllValues(ctx, c.g, c.baseURL+"/deviceManagement/deviceConfigurations", nil)
	if err != nil {
		return err
	}

	now := c.now()
	var pauseState, pauseExpiry, rollback, status []telemetry.GaugePoint

	for _, r := range raw {
		var typed odataTyped
		if err := json.Unmarshal(r, &typed); err != nil {
			c.logger.Warn("updates: skipping unparseable deviceConfigurations element", "collector", collectorName, "error", err)
			continue
		}
		if typed.ODataType != windowsUpdateForBusinessODataType {
			continue // owned by #53's config-profiles collector, not this one
		}

		var ring updateRingConfig
		if err := json.Unmarshal(r, &ring); err != nil {
			c.logger.Warn("updates: skipping unparseable update ring element", "collector", collectorName, "error", err)
			continue
		}
		name := ring.DisplayName

		pauseState = append(pauseState,
			telemetry.GaugePoint{Value: bool2float(ring.QualityUpdatesPaused), Attrs: telemetry.Attrs{"ring_name": name, "update_type": "quality"}},
			telemetry.GaugePoint{Value: bool2float(ring.FeatureUpdatesPaused), Attrs: telemetry.Attrs{"ring_name": name, "update_type": "feature"}},
		)
		rollback = append(rollback,
			telemetry.GaugePoint{Value: bool2float(ring.QualityUpdatesWillBeRolledBack), Attrs: telemetry.Attrs{"ring_name": name, "update_type": "quality"}},
			telemetry.GaugePoint{Value: bool2float(ring.FeatureUpdatesWillBeRolledBack), Attrs: telemetry.Attrs{"ring_name": name, "update_type": "feature"}},
		)
		if ring.QualityUpdatesPauseExpiryDateTime != nil {
			pauseExpiry = append(pauseExpiry, telemetry.GaugePoint{
				Value: ring.QualityUpdatesPauseExpiryDateTime.Sub(now).Seconds(),
				Attrs: telemetry.Attrs{"ring_name": name, "update_type": "quality"},
			})
		}
		if ring.FeatureUpdatesPauseExpiryDateTime != nil {
			pauseExpiry = append(pauseExpiry, telemetry.GaugePoint{
				Value: ring.FeatureUpdatesPauseExpiryDateTime.Sub(now).Seconds(),
				Attrs: telemetry.Attrs{"ring_name": name, "update_type": "feature"},
			})
		}

		body, err := c.g.RawGet(ctx, c.baseURL+"/deviceManagement/deviceConfigurations/"+typed.ID+"/deviceStatusOverview")
		if err != nil {
			c.logger.Warn("updates: deviceStatusOverview fetch failed, skipping ring status", "collector", collectorName, "ring", name, "error", err)
			continue
		}
		var overview deviceStatusOverview
		if err := json.Unmarshal(body, &overview); err != nil {
			c.logger.Warn("updates: skipping unparseable deviceStatusOverview", "collector", collectorName, "ring", name, "error", err)
			continue
		}
		status = append(status, overview.points(name)...)
	}

	e.GaugeSnapshot(pauseStateMetric, "1", "Windows Update ring pause state (1=paused, 0=not paused), by ring and update type.", pauseState)
	e.GaugeSnapshot(pauseExpiryMetric, "s", "Seconds until a paused Windows Update ring's pause expires, by ring and update type.", pauseExpiry)
	e.GaugeSnapshot(rollbackActiveMetric, "1", "Windows Update ring rollback-active state (1=active, 0=inactive), by ring and update type.", rollback)
	e.GaugeSnapshot(ringStatusMetric, "{device}", "Windows Update ring device rollout status rollup, by ring and state.", status)
	return nil
}

// collectFeatureProfiles polls the beta windowsFeatureUpdateProfiles family
// and emits the end-of-support countdown gauge. Unavailable on this tenant
// (403/404) is skipped-and-logged, not an error.
func (c *Collector) collectFeatureProfiles(ctx context.Context, e telemetry.Emitter) error {
	raw, err := collectors.GetAllValues(ctx, c.g, c.betaURL+"/deviceManagement/windowsFeatureUpdateProfiles", nil)
	if err != nil {
		if isUnavailable(err) {
			c.logger.Info("updates: windowsFeatureUpdateProfiles unavailable on this tenant; skipping", "collector", collectorName, "error", err)
			e.GaugeSnapshot(featureEOLMetric, "s", "Seconds until a Windows feature update profile's target version reaches end of support.", nil)
			return nil
		}
		return err
	}

	now := c.now()
	var points []telemetry.GaugePoint
	for _, r := range raw {
		var p featureUpdateProfile
		if err := json.Unmarshal(r, &p); err != nil {
			c.logger.Warn("updates: skipping unparseable feature update profile", "collector", collectorName, "error", err)
			continue
		}
		if p.EndOfSupportDate.IsZero() {
			continue
		}
		points = append(points, telemetry.GaugePoint{
			Value: p.EndOfSupportDate.Sub(now).Seconds(),
			Attrs: telemetry.Attrs{"profile_name": p.DisplayName, "feature_update_version": p.FeatureUpdateVersion},
		})
	}
	e.GaugeSnapshot(featureEOLMetric, "s", "Seconds until a Windows feature update profile's target version reaches end of support.", points)
	return nil
}

// collectQualityConfigs polls both beta windowsQualityUpdateProfiles and
// windowsQualityUpdatePolicies (two parallel resources for the same
// tenant-config job - a tenant may use either or both) and emits a per-
// resource-type count as a config-drift signal. Unavailable (403/404) is
// skipped-and-logged, not an error.
func (c *Collector) collectQualityConfigs(ctx context.Context, e telemetry.Emitter) error {
	var errs []error
	var points []telemetry.GaugePoint

	if n, err := c.countNamedResources(ctx, c.betaURL+"/deviceManagement/windowsQualityUpdateProfiles"); err != nil {
		errs = append(errs, fmt.Errorf("quality update profiles: %w", err))
	} else if n >= 0 {
		points = append(points, telemetry.GaugePoint{Value: float64(n), Attrs: telemetry.Attrs{"resource_type": "profile"}})
	}

	if n, err := c.countNamedResources(ctx, c.betaURL+"/deviceManagement/windowsQualityUpdatePolicies"); err != nil {
		errs = append(errs, fmt.Errorf("quality update policies: %w", err))
	} else if n >= 0 {
		points = append(points, telemetry.GaugePoint{Value: float64(n), Attrs: telemetry.Attrs{"resource_type": "policy"}})
	}

	e.GaugeSnapshot(qualityConfigCountMetric, "{resource}", "Count of Windows quality update config resources, by resource type (profile vs policy).", points)
	return errors.Join(errs...)
}

// countNamedResources pages url and returns the element count. A -1 count
// with a nil error signals the endpoint is unavailable on this tenant
// (403/404) and was skipped-and-logged.
func (c *Collector) countNamedResources(ctx context.Context, url string) (int, error) {
	raw, err := collectors.GetAllValues(ctx, c.g, url, nil)
	if err != nil {
		if isUnavailable(err) {
			c.logger.Info("updates: quality update resource unavailable on this tenant; skipping", "collector", collectorName, "url", url, "error", err)
			return -1, nil
		}
		return -1, err
	}
	n := 0
	for _, r := range raw {
		var res namedResource
		if err := json.Unmarshal(r, &res); err != nil {
			c.logger.Warn("updates: skipping unparseable quality update resource", "collector", collectorName, "error", err)
			continue
		}
		n++
	}
	return n, nil
}

// collectDriverProfiles polls the beta windowsDriverUpdateProfiles family
// and emits the pending-approval and sync-staleness gauges from each
// profile's embedded fields - no driverInventories walk, no
// syncInventory/executeAction calls. Unavailable (403/404) is
// skipped-and-logged, not an error.
func (c *Collector) collectDriverProfiles(ctx context.Context, e telemetry.Emitter) error {
	raw, err := collectors.GetAllValues(ctx, c.g, c.betaURL+"/deviceManagement/windowsDriverUpdateProfiles", nil)
	if err != nil {
		if isUnavailable(err) {
			c.logger.Info("updates: windowsDriverUpdateProfiles unavailable on this tenant; skipping", "collector", collectorName, "error", err)
			e.GaugeSnapshot(driverPendingMetric, "{update}", "Pending-approval driver updates awaiting admin action, by driver update profile.", nil)
			e.GaugeSnapshot(driverStalenessMetric, "s", "Seconds since a driver update profile's last successful inventory sync.", nil)
			return nil
		}
		return err
	}

	now := c.now()
	var pending, staleness []telemetry.GaugePoint
	for _, r := range raw {
		var p driverUpdateProfile
		if err := json.Unmarshal(r, &p); err != nil {
			c.logger.Warn("updates: skipping unparseable driver update profile", "collector", collectorName, "error", err)
			continue
		}
		pending = append(pending, telemetry.GaugePoint{
			Value: float64(p.NewUpdates),
			Attrs: telemetry.Attrs{"profile_name": p.DisplayName},
		})
		if sync := p.InventorySync.LastSuccessfulSyncDateTime; sync != nil {
			staleness = append(staleness, telemetry.GaugePoint{
				Value: now.Sub(*sync).Seconds(),
				Attrs: telemetry.Attrs{"profile_name": p.DisplayName},
			})
		}
	}
	e.GaugeSnapshot(driverPendingMetric, "{update}", "Pending-approval driver updates awaiting admin action, by driver update profile.", pending)
	e.GaugeSnapshot(driverStalenessMetric, "s", "Seconds since a driver update profile's last successful inventory sync.", staleness)
	return nil
}

// bool2float converts a boolean state gauge value to its OTEL 1/0 form.
func bool2float(b bool) float64 {
	if b {
		return 1
	}
	return 0
}

// isUnavailable reports whether err is a 4xx from a beta endpoint being
// unavailable/unlicensed on the tenant (403 forbidden, 404 not found) - an
// expected "no data here" condition, not a failure, mirroring the
// entra/recommendations precedent.
func isUnavailable(err error) bool {
	s := err.Error()
	return strings.Contains(s, "status 403") || strings.Contains(s, "status 404")
}

var (
	_ collector.SnapshotCollector = (*Collector)(nil)
	_ collectors.Experimental     = (*Collector)(nil)
)

func init() {
	collectors.Register(func(d collectors.Deps) collector.SnapshotCollector {
		return New(d.Graph, d.Logger)
	})
}
