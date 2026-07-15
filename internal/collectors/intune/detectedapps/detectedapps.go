// Package detectedapps is the Intune software-inventory collector: bounded
// device-count gauges over the tenant-wide `/deviceManagement/detectedApps`
// catalog.
//
// The catalog itself is NOT bounded - Intune records one entry per distinct
// (app, version, platform) tuple ever observed across every enrolled device,
// which can run to tens of thousands of rows in a large tenant, and the
// endpoint accepts no server-side `$filter`. Turning that into per-entity
// metric labels would be a straight cardinality bomb (CLAUDE.md's central
// M4 rule), so this collector paginates the catalog client-side but only
// promotes device counts for a small, package-level ALLOW-LIST of common
// apps (defaultAllowedApps below) into the device_count series, matched by
// case-insensitive displayName. Every other catalog row is counted toward
// catalog_size (a single unlabeled scalar) and otherwise dropped. The
// allow-list is the cardinality boundary: it is fixed and small by design,
// not tenant- or config-driven in v1, so the device_count series can never
// grow with the size of the catalog or the tenant.
//
// Deliberately deferred: detectedApps/{id}/managedDevices (confirming which
// specific devices run a given detected app) is an N+1-per-app call chain
// with low aggregate value over the deviceCount scalar already on the
// catalog object, so v1 omits it. Revisit only if a concrete use case needs
// per-device app presence, and land it in the logs pipeline (M5), not here.
package detectedapps

import (
	"context"
	"encoding/json"
	"log/slog"
	"strings"
	"time"

	"github.com/rknightion/graph2otel/internal/collector"
	"github.com/rknightion/graph2otel/internal/collectors"
	"github.com/rknightion/graph2otel/internal/telemetry"
)

// collectorName is the stable key used for config (enable/interval),
// self-observability, and the admin status page.
const collectorName = "intune.detected_apps"

// Metric names this collector emits.
const (
	deviceCountMetric = "intune.detected_apps.device_count"
	catalogSizeMetric = "intune.detected_apps.catalog_size"
)

// defaultBaseURL is the Graph v1.0 root; detectedApps is a stable v1.0
// endpoint, not beta.
const defaultBaseURL = "https://graph.microsoft.com/v1.0"

// defaultAllowedApps is the fixed, package-level cardinality boundary: only
// detectedApp rows whose displayName case-insensitively matches one of these
// are promoted to the device_count series. A handful of common,
// security/inventory-relevant cross-platform apps, chosen so the series stays
// small and bounded regardless of tenant size or catalog growth. Vendors
// occasionally version-suffix a displayName (e.g. "1Password 8" vs
// "1Password 7"); an exact-match miss here simply means that variant is
// counted in catalog_size but not broken out by name - a known v1 limitation,
// not silently wrong data.
var defaultAllowedApps = []string{
	"Google Chrome",
	"Microsoft Edge",
	"Mozilla Firefox",
	"Microsoft Teams",
	"Zoom",
	"Slack",
	"1Password",
	"Adobe Acrobat Reader DC",
}

// detectedApp is the subset of the Graph detectedApp resource this collector
// reads. deviceCount is already a scalar on the object (Microsoft aggregates
// it per catalog row), so no per-device N+1 traversal is needed to populate
// it.
type detectedApp struct {
	DisplayName string `json:"displayName"`
	Platform    string `json:"platform"`
	DeviceCount int64  `json:"deviceCount"`
}

// Collector polls the Intune detectedApps catalog.
type Collector struct {
	g       collectors.GraphClient
	baseURL string
	logger  *slog.Logger
	// allowed maps a lowercased displayName to its canonical (as configured)
	// label value, so the emitted app_name attribute always reads in the
	// allow-list's own casing regardless of how the tenant's catalog spelled
	// it.
	allowed map[string]string
}

// New builds the detected-apps collector. A nil logger falls back to the
// slog default.
func New(g collectors.GraphClient, logger *slog.Logger) *Collector {
	if logger == nil {
		logger = slog.Default()
	}
	allowed := make(map[string]string, len(defaultAllowedApps))
	for _, name := range defaultAllowedApps {
		allowed[strings.ToLower(name)] = name
	}
	return &Collector{g: g, baseURL: defaultBaseURL, logger: logger, allowed: allowed}
}

// Name implements collector.Collector.
func (c *Collector) Name() string { return collectorName }

// DefaultInterval implements collector.Collector. The detectedApps catalog is
// a full, unfiltered tenant-wide page walk that can run to tens of thousands
// of rows, so it gets a longer cadence than a $count-based snapshot.
func (c *Collector) DefaultInterval() time.Duration { return time.Hour }

// RequiredPermissions declares the least-privilege Graph application scope.
// Per https://learn.microsoft.com/en-us/graph/api/intune-devices-detectedapp-list,
// DeviceManagementManagedDevices.Read.All is the least-privileged permission
// (delegated or application) for listing detectedApps.
func (c *Collector) RequiredPermissions() []string {
	return []string{"DeviceManagementManagedDevices.Read.All"}
}

// Collect pages the full detectedApps catalog once, emitting a bounded
// device_count gauge (allow-listed app names only, grouped by platform) and
// an unlabeled catalog_size scalar covering every row. A 403 (Intune
// unlicensed/unavailable on the tenant) is skipped-and-logged rather than
// treated as a failure; any other error is surfaced.
func (c *Collector) Collect(ctx context.Context, e telemetry.Emitter) error {
	raw, err := collectors.GetAllValues(ctx, c.g, c.baseURL+"/deviceManagement/detectedApps", nil)
	if err != nil {
		if isForbidden(err) {
			c.logger.Info("detectedApps endpoint unavailable on this tenant; skipping",
				"collector", collectorName, "error", err)
			return nil
		}
		return err
	}

	type bucketKey struct{ appName, platform string }
	buckets := map[bucketKey]int64{}

	for _, r := range raw {
		var app detectedApp
		if err := json.Unmarshal(r, &app); err != nil {
			c.logger.Warn("detected_apps: skipping unparseable catalog entry", "collector", collectorName, "error", err)
			continue
		}
		canonical, ok := c.allowed[strings.ToLower(strings.TrimSpace(app.DisplayName))]
		if !ok {
			continue
		}
		key := bucketKey{appName: canonical, platform: orUnknown(app.Platform)}
		buckets[key] += app.DeviceCount
	}

	points := make([]telemetry.GaugePoint, 0, len(buckets))
	for key, count := range buckets {
		points = append(points, telemetry.GaugePoint{
			Value: float64(count),
			Attrs: telemetry.Attrs{"app_name": key.appName, "platform": key.platform},
		})
	}
	e.GaugeSnapshot(deviceCountMetric, "{device}",
		"Devices reporting an allow-listed detected app installed, by app name and platform.", points)

	e.Gauge(catalogSizeMetric, "{app}",
		"Total distinct app/version/platform rows in the Intune detectedApps catalog.",
		float64(len(raw)), telemetry.Attrs{})

	return nil
}

// orUnknown substitutes "unknown" for an empty platform value so the
// device_count attribute is never blank.
func orUnknown(s string) string {
	if s == "" {
		return "unknown"
	}
	return s
}

// isForbidden reports whether err is a 403 from the endpoint being
// unlicensed/unavailable on the tenant - an expected "no data here"
// condition, not a failure.
func isForbidden(err error) bool {
	return strings.Contains(err.Error(), "status 403")
}

var (
	_ collector.SnapshotCollector = (*Collector)(nil)
)

func init() {
	collectors.Register(func(d collectors.Deps) collector.SnapshotCollector {
		return New(d.Graph, d.Logger)
	})
}
