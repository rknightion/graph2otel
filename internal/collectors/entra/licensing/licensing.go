// Package licensing is the Entra licensing collector: tenant-wide
// subscribedSku inventory emitted as two correctly-bounded per-SKU gauges,
// entra.license.consumed and entra.license.enabled.
//
// Assignment-error detection is deliberately NOT implemented. The traditional
// (non-preview) license model exposes assignment failures only as a per-user
// property (`licenseAssignmentStates` on the user resource, state == "Error"),
// which has no v1.0 tenant-level aggregate — detecting it would mean paging
// every user in the tenant just to produce one counter, which is exactly the
// per-entity-scan-for-an-aggregate anti-pattern this collector framework
// exists to avoid. Microsoft Graph beta does have a newer `assignmentError`
// entity (see the beta-only "cloud licensing" / allotments API), but that API
// models an entirely different, opt-in licensing paradigm (allotments, not
// classic direct/group-based subscribedSkus licensing) and is beta-only, so
// it isn't a safe v1.0 substitute. See issue #45 and this collector's final
// implementation brief for the full reasoning; revisit if Microsoft ships a
// v1.0, tenant-level assignment-error aggregate for classic licensing.
package licensing

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
const collectorName = "entra.licensing"

// Metric names this collector emits. Both are per-SKU (bounded, tenant-shaped:
// cardinality grows with the number of purchased SKUs, tens at most, never
// with tenant size).
const (
	consumedMetricName = "entra.license.consumed"
	enabledMetricName  = "entra.license.enabled"
)

// defaultBaseURL is the Graph v1.0 root.
const defaultBaseURL = "https://graph.microsoft.com/v1.0"

// prepaidUnits mirrors the Graph licenseUnitsDetail complex type; only the
// enabled count is needed here.
type prepaidUnits struct {
	Enabled int64 `json:"enabled"`
}

// subscribedSku mirrors the fields of the Graph subscribedSku resource this
// collector reads. skuPartNumber is the bounded, tenant-shaped label value
// ("sku") — never skuId (an opaque GUID, less operator-readable) and never
// any per-assignment/per-user field.
type subscribedSku struct {
	SkuPartNumber string       `json:"skuPartNumber"`
	ConsumedUnits int64        `json:"consumedUnits"`
	PrepaidUnits  prepaidUnits `json:"prepaidUnits"`
}

// Collector polls /subscribedSkus.
type Collector struct {
	g       collectors.GraphClient
	baseURL string
	logger  *slog.Logger
}

// New builds the licensing collector. A nil logger falls back to the slog
// default.
func New(g collectors.GraphClient, logger *slog.Logger) *Collector {
	if logger == nil {
		logger = slog.Default()
	}
	return &Collector{g: g, baseURL: defaultBaseURL, logger: logger}
}

// Name implements collector.Collector.
func (c *Collector) Name() string { return collectorName }

// DefaultInterval implements collector.Collector. License consumption drifts
// slowly and subscribedSkus has no delta/filter support (a full read every
// cycle), so a longer interval than the directory counts is appropriate.
func (c *Collector) DefaultInterval() time.Duration { return 15 * time.Minute }

// RequiredPermissions declares the least-privilege Graph application scope.
// Per current Microsoft Graph docs (learn.microsoft.com/graph/api/subscribedsku-list),
// LicenseAssignment.Read.All is now the least-privileged permission for
// GET /subscribedSkus — Directory.Read.All/Organization.Read.All (named in
// issue #45) are listed there as higher-privileged alternatives, so this
// deliberately deviates from the issue text toward the narrower scope per the
// authoring guide's "prefer the specific scope" rule.
func (c *Collector) RequiredPermissions() []string { return []string{"LicenseAssignment.Read.All"} }

// Collect fetches the full subscribedSkus collection and emits two atomic
// gauge snapshots (consumed units and enabled/prepaid units), one point per
// SKU. subscribedSkus is a small, tenant-wide collection with no $filter or
// delta support, so GetAllValues (not Count) is the right helper here.
func (c *Collector) Collect(ctx context.Context, e telemetry.Emitter) error {
	raw, err := collectors.GetAllValues(ctx, c.g, c.baseURL+"/subscribedSkus", nil)
	if err != nil {
		return fmt.Errorf("licensing: fetch subscribedSkus: %w", err)
	}

	consumed := make([]telemetry.GaugePoint, 0, len(raw))
	enabled := make([]telemetry.GaugePoint, 0, len(raw))
	for _, r := range raw {
		var sku subscribedSku
		if err := json.Unmarshal(r, &sku); err != nil {
			c.logger.Warn("licensing: skipping unparseable subscribedSku", "collector", collectorName, "error", err)
			continue
		}
		if sku.SkuPartNumber == "" {
			c.logger.Warn("licensing: skipping subscribedSku with empty skuPartNumber", "collector", collectorName)
			continue
		}
		attrs := telemetry.Attrs{semconv.AttrSku: sku.SkuPartNumber}
		consumed = append(consumed, telemetry.GaugePoint{Value: float64(sku.ConsumedUnits), Attrs: attrs})
		enabled = append(enabled, telemetry.GaugePoint{Value: float64(sku.PrepaidUnits.Enabled), Attrs: attrs})
	}

	e.GaugeSnapshot(consumedMetricName, "{unit}", "Consumed license units per Entra subscribed SKU.", consumed)
	e.GaugeSnapshot(enabledMetricName, "{unit}", "Enabled (prepaid) license units per Entra subscribed SKU.", enabled)
	return nil
}

func init() {
	collectors.Register(func(d collectors.Deps) collector.SnapshotCollector {
		return New(d.Graph, d.Logger)
	})
}
