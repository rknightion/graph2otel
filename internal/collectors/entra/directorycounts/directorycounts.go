// Package directorycounts is the Entra directory-summary collector: one
// tenant-wide `$count` per directory object type, emitted as the
// correctly-bounded aggregate gauge entra.directory.objects.total{type=...}.
// It is the reference SnapshotCollector — the cheapest, highest-value signal
// and the pattern every other Entra metrics collector follows.
package directorycounts

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/rknightion/graph2otel/internal/collector"
	"github.com/rknightion/graph2otel/internal/collectors"
	"github.com/rknightion/graph2otel/internal/telemetry"
)

// collectorName is the stable key used for config (enable/interval),
// self-observability, and the admin status page.
const collectorName = "entra.directory_counts"

// metricName is the single gauge this collector emits.
const metricName = "entra.directory.objects.total"

// defaultBaseURL is the Graph v1.0 root; overridable in tests is unnecessary
// because the fake GraphClient just ignores the host, but keeping it a field
// keeps the URLs readable.
const defaultBaseURL = "https://graph.microsoft.com/v1.0"

// objectType pairs a bounded `type` attribute value with its $count segment.
type objectType struct {
	attr string
	path string
}

// objectTypes is the fixed, bounded set of directory object types counted.
// Cardinality of the emitted metric is exactly len(objectTypes).
var objectTypes = []objectType{
	{"user", "/users/$count"},
	{"group", "/groups/$count"},
	{"device", "/devices/$count"},
	{"service_principal", "/servicePrincipals/$count"},
	{"application", "/applications/$count"},
}

// Collector polls the directory object $count segments.
type Collector struct {
	g       collectors.GraphClient
	baseURL string
	logger  *slog.Logger
}

// New builds the directory-counts collector. A nil logger falls back to the
// slog default.
func New(g collectors.GraphClient, logger *slog.Logger) *Collector {
	if logger == nil {
		logger = slog.Default()
	}
	return &Collector{g: g, baseURL: defaultBaseURL, logger: logger}
}

// Name implements collector.Collector.
func (c *Collector) Name() string { return collectorName }

// DefaultInterval implements collector.Collector. Directory sizes drift slowly;
// five minutes is ample and trivially cheap on the RU budget.
func (c *Collector) DefaultInterval() time.Duration { return 5 * time.Minute }

// RequiredPermissions declares the least-privilege Graph scope. Directory.Read.All
// blanket-covers every object type's $count.
func (c *Collector) RequiredPermissions() []string { return []string{"Directory.Read.All"} }

// Collect fetches each object type's count and emits them as one atomic gauge
// snapshot. A failure on one type is logged and that type is dropped from the
// snapshot, but the others still emit; the aggregated error is returned so the
// partial failure is visible in scrape self-obs without hiding the data.
func (c *Collector) Collect(ctx context.Context, e telemetry.Emitter) error {
	points := make([]telemetry.GaugePoint, 0, len(objectTypes))
	var errs []error
	for _, ot := range objectTypes {
		n, err := collectors.Count(ctx, c.g, c.baseURL+ot.path)
		if err != nil {
			c.logger.Warn("directory count failed", "collector", collectorName, "type", ot.attr, "error", err)
			errs = append(errs, fmt.Errorf("%s: %w", ot.attr, err))
			continue
		}
		points = append(points, telemetry.GaugePoint{
			Value: float64(n),
			Attrs: telemetry.Attrs{"type": ot.attr},
		})
	}
	e.GaugeSnapshot(metricName, "{object}", "Total Entra directory objects, by object type.", points)
	return errors.Join(errs...)
}

func init() {
	collectors.Register(func(d collectors.Deps) collector.SnapshotCollector {
		return New(d.Graph, d.Logger)
	})
}
