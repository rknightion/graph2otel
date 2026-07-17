// Package recommendations is the Entra recommendations collector (BETA):
// Microsoft's own tenant-posture scoreboard from /beta/directory/recommendations,
// emitted as bounded counts by status/priority and by recommendation type.
//
// Beta-only: the endpoint lives on /beta and its schema is unstable, so this
// collector implements collectors.Experimental (opt-in, off by default) and
// degrades cleanly — a 403/404 (endpoint unavailable or unlicensed on the
// tenant) is skipped-and-logged rather than treated as a failure.
package recommendations

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/rknightion/graph2otel/internal/collector"
	"github.com/rknightion/graph2otel/internal/collectors"
	"github.com/rknightion/graph2otel/internal/semconv"
	"github.com/rknightion/graph2otel/internal/telemetry"
)

const (
	collectorName  = "entra.recommendations"
	totalMetric    = "entra.recommendations.total"
	impactedMetric = "entra.recommendations.impacted_resources.total"
	betaBaseURL    = "https://graph.microsoft.com/beta"
)

// recommendation is the subset of the beta recommendation resource this
// collector reads. impactedResources is read inline (avoiding an N+1 call to
// the per-recommendation impactedResources endpoint); a beta schema that omits
// it simply yields a zero impacted count.
type recommendation struct {
	RecommendationType string            `json:"recommendationType"`
	Status             string            `json:"status"`
	Priority           string            `json:"priority"`
	ImpactedResources  []json.RawMessage `json:"impactedResources"`
}

// Collector polls /beta/directory/recommendations.
type Collector struct {
	g       collectors.GraphClient
	baseURL string
	logger  *slog.Logger
}

// New builds the recommendations collector. A nil logger falls back to the
// slog default.
func New(g collectors.GraphClient, logger *slog.Logger) *Collector {
	if logger == nil {
		logger = slog.Default()
	}
	return &Collector{g: g, baseURL: betaBaseURL, logger: logger}
}

// Name implements collector.Collector.
func (c *Collector) Name() string { return collectorName }

// DefaultInterval implements collector.Collector. The recommendation catalog
// drifts slowly; a longer cadence is fine.
func (c *Collector) DefaultInterval() time.Duration { return 30 * time.Minute }

// Experimental marks this as a beta, opt-in collector.
func (c *Collector) Experimental() bool { return true }

// RequiredPermissions declares the least-privilege Graph scope.
func (c *Collector) RequiredPermissions() []string {
	return []string{"DirectoryRecommendations.Read.All"}
}

// Collect fetches the recommendation list and emits status/priority counts plus
// per-type impacted-resource counts. Because coverage is license-dependent and
// the endpoint is beta, a 4xx (unavailable/unlicensed) is skipped-and-logged,
// not surfaced as an error.
func (c *Collector) Collect(ctx context.Context, e telemetry.Emitter) error {
	raw, err := collectors.GetAllValues(ctx, c.g, c.baseURL+"/directory/recommendations", nil)
	if err != nil {
		if isUnavailable(err) {
			c.logger.Info("recommendations endpoint unavailable on this tenant; skipping",
				"collector", collectorName, "error", err)
			return nil
		}
		return fmt.Errorf("recommendations: list: %w", err)
	}

	byStatusPriority := map[[2]string]int{}
	impactedByType := map[string]int{}
	for _, r := range raw {
		var rec recommendation
		if err := json.Unmarshal(r, &rec); err != nil {
			c.logger.Warn("recommendations: skipping unparseable entry", "collector", collectorName, "error", err)
			continue
		}
		status := orUnknown(rec.Status)
		priority := orUnknown(rec.Priority)
		byStatusPriority[[2]string{status, priority}]++
		if rec.RecommendationType != "" {
			impactedByType[rec.RecommendationType] += len(rec.ImpactedResources)
		}
	}

	total := make([]telemetry.GaugePoint, 0, len(byStatusPriority))
	for k, v := range byStatusPriority {
		total = append(total, telemetry.GaugePoint{
			Value: float64(v),
			Attrs: telemetry.Attrs{semconv.AttrStatus: k[0], semconv.AttrPriority: k[1]},
		})
	}
	e.GaugeSnapshot(totalMetric, "{recommendation}", "Entra recommendations by status and priority.", total)

	impacted := make([]telemetry.GaugePoint, 0, len(impactedByType))
	for typ, n := range impactedByType {
		impacted = append(impacted, telemetry.GaugePoint{
			Value: float64(n),
			Attrs: telemetry.Attrs{semconv.AttrRecommendation: typ},
		})
	}
	e.GaugeSnapshot(impactedMetric, "{resource}", "Impacted resources per Entra recommendation type.", impacted)
	return nil
}

// isUnavailable reports whether err is a 4xx from the beta endpoint being
// unavailable/unlicensed on the tenant (403 forbidden, 404 not found) — an
// expected "no data here" condition, not a failure.
func isUnavailable(err error) bool {
	s := err.Error()
	return strings.Contains(s, "status 403") || strings.Contains(s, "status 404")
}

func orUnknown(s string) string {
	if s == "" {
		return "unknown"
	}
	return s
}

func init() {
	collectors.Register(func(d collectors.Deps) collector.SnapshotCollector {
		return New(d.Graph, d.Logger)
	})
}
