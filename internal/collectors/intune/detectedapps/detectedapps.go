// Package detectedapps is the Intune software-inventory collector: bounded
// device-count gauges over the tenant-wide `/deviceManagement/detectedApps`
// catalog.
//
// The catalog itself is NOT bounded - Intune records one entry per distinct
// (app, version, platform) tuple ever observed across every enrolled device,
// which can run to tens of thousands of rows in a large tenant, and the
// endpoint accepts no server-side `$filter`. So device_count genuinely needs a
// ceiling, and it gets the CENTRAL one (#235): telemetry's limiter keeps the top
// N apps BY DEVICE COUNT and folds the rest into app_name="other", preserving
// the bounded platform breakdown.
//
// It used to get a package-level ALLOW-LIST of eight common applications
// instead, with every other row counted toward catalog_size and otherwise
// discarded. That bounded the series correctly and answered the wrong question:
// the list was a standing guess about what mattered, and on a real tenant the
// answer was "none of it" — this package's live capture promoted ZERO series,
// because nobody's catalog leads with Chrome and Slack. The collector could
// report how many applications existed and never which ones. Ranking by device
// count keeps whatever the tenant actually runs, without anyone having to
// predict it.
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
	"github.com/rknightion/graph2otel/internal/semconv"
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
}

// New builds the detected-apps collector. A nil logger falls back to the
// slog default.
func New(g collectors.GraphClient, logger *slog.Logger) *Collector {
	if logger == nil {
		logger = slog.Default()
	}
	return &Collector{g: g, baseURL: defaultBaseURL, logger: logger}
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

// Collect pages the full detectedApps catalog once, emitting a device_count
// gauge per app name and platform plus an unlabeled catalog_size scalar. Rows
// are summed across VERSIONS — the catalog carries one entry per
// (app, version, platform), and a version dimension would multiply the series
// count by a number that grows with patch cadence rather than with anything
// anyone queries. A 403 (Intune unlicensed/unavailable on the tenant) is
// skipped-and-logged rather than treated as a failure; any other error is
// surfaced.
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

	// Keyed on the LOWERCASED name: Intune's catalog carries casing variants of
	// one application ("Google Chrome" and "google chrome" are both real rows), so
	// case-sensitive keys would double the series for no information. The retired
	// allow-list folded case as a side effect of canonicalizing to its own
	// spelling; doing it explicitly keeps that behavior without the list.
	//
	// The emitted label is the FIRST spelling seen in catalog order, which is
	// deterministic because the catalog is walked as a slice — picking from a map
	// would make the label depend on Go's map iteration order and flip between
	// runs, creating and retiring series for nothing.
	type bucketKey struct{ appNameLower, platform string }
	type bucket struct {
		display string
		count   int64
	}
	buckets := map[bucketKey]*bucket{}
	var order []bucketKey

	for _, r := range raw {
		var app detectedApp
		if err := json.Unmarshal(r, &app); err != nil {
			c.logger.Warn("detected_apps: skipping unparseable catalog entry", "collector", collectorName, "error", err)
			continue
		}
		name := strings.TrimSpace(app.DisplayName)
		if name == "" {
			// An unnamed catalog row cannot be attributed to anything; it still
			// counts toward catalog_size.
			continue
		}
		key := bucketKey{appNameLower: strings.ToLower(name), platform: orUnknown(app.Platform)}
		b, ok := buckets[key]
		if !ok {
			b = &bucket{display: name}
			buckets[key] = b
			order = append(order, key)
		}
		b.count += app.DeviceCount
	}

	points := make([]telemetry.GaugePoint, 0, len(buckets))
	for _, key := range order {
		b := buckets[key]
		points = append(points, telemetry.GaugePoint{
			Value: float64(b.count),
			Attrs: telemetry.Attrs{semconv.AttrAppName: b.display, semconv.AttrPlatform: key.platform},
		})
	}
	e.GaugeSnapshot(deviceCountMetric, "{device}",
		"Devices reporting a detected app installed, by app name and platform, summed across versions. "+
			"Bounded by the central cardinality limiter: past cardinality.per_metric_limit the top apps "+
			"by device count are kept and the tail folds into app_name=\"other\".", points)

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
