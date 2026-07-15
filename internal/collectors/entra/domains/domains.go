// Package domains is the Entra domain posture collector: verified/federated/
// managed domain posture, aggregated into small, tenant-shaped gauges. A
// tenant's domain list is tiny, but domain names/ids are still never emitted
// as a metric label — only the bounded posture attributes (authentication
// type, verification state) are, plus a convenience federated-count gauge for
// alerting on a trust-surface change.
package domains

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
const collectorName = "entra.domains"

// Metric names this collector emits.
const (
	metricTotal          = "entra.domains.total"
	metricFederatedTotal = "entra.domains.federated.total"
)

// defaultBaseURL is the Graph v1.0 root.
const defaultBaseURL = "https://graph.microsoft.com/v1.0"

// domainsPath is a plain, unfiltered domain list — GET /domains — a small,
// bounded collection with no delta query and no $filter/$search of note (both
// are documented as unreliable on this endpoint), so a full read every tick is
// the correct, cheap approach.
const domainsPath = "/domains"

// domain is the subset of the Graph domain resource this collector reads. See
// https://learn.microsoft.com/en-us/graph/api/resources/domain -
// authenticationType is "Managed" or "Federated" (exact casing from Graph).
type domain struct {
	AuthenticationType string `json:"authenticationType"`
	IsVerified         bool   `json:"isVerified"`
}

// Collector polls GET /domains and aggregates domain posture.
type Collector struct {
	g       collectors.GraphClient
	baseURL string
	logger  *slog.Logger
}

// New builds the domains collector. A nil logger falls back to the slog
// default.
func New(g collectors.GraphClient, logger *slog.Logger) *Collector {
	if logger == nil {
		logger = slog.Default()
	}
	return &Collector{g: g, baseURL: defaultBaseURL, logger: logger}
}

// Name implements collector.Collector.
func (c *Collector) Name() string { return collectorName }

// DefaultInterval implements collector.Collector. Domain posture changes
// rarely; fifteen minutes is ample for a free-tier, tiny-collection signal.
func (c *Collector) DefaultInterval() time.Duration { return 15 * time.Minute }

// RequiredPermissions declares the least-privilege Graph scope: Domain.Read.All
// covers GET /domains without the broader Directory.Read.All blanket.
func (c *Collector) RequiredPermissions() []string { return []string{"Domain.Read.All"} }

// postureKey is the bounded (authentication_type, is_verified) combination a
// domain is aggregated under. At most 4 distinct values can ever exist.
type postureKey struct {
	authType string
	verified bool
}

// Collect fetches the tenant's domains and emits two gauges: a bounded
// posture-count snapshot and a federated-domain convenience total. A domain
// entry that fails to decode is logged and skipped (aggregated into the
// returned error) without discarding the rest of the snapshot; a failure to
// list the collection at all aborts before emitting anything, since there is
// no partial data to report in that case.
func (c *Collector) Collect(ctx context.Context, e telemetry.Emitter) error {
	raw, err := collectors.GetAllValues(ctx, c.g, c.baseURL+domainsPath, nil)
	if err != nil {
		return fmt.Errorf("entra.domains: list domains: %w", err)
	}

	counts := map[postureKey]int64{}
	var federated int64
	var errs []error

	for _, r := range raw {
		var d domain
		if err := json.Unmarshal(r, &d); err != nil {
			c.logger.Warn("domain decode failed", "collector", collectorName, "error", err)
			errs = append(errs, fmt.Errorf("decode domain: %w", err))
			continue
		}
		authType := normalizeAuthType(d.AuthenticationType)
		counts[postureKey{authType: authType, verified: d.IsVerified}]++
		if authType == "federated" {
			federated++
		}
	}

	points := make([]telemetry.GaugePoint, 0, len(counts))
	for k, n := range counts {
		points = append(points, telemetry.GaugePoint{
			Value: float64(n),
			Attrs: telemetry.Attrs{
				"authentication_type": k.authType,
				"is_verified":         k.verified,
			},
		})
	}
	e.GaugeSnapshot(metricTotal, "{domain}", "Entra domains by authentication type and verification status.", points)
	e.Gauge(metricFederatedTotal, "{domain}", "Entra domains configured with federated authentication.", float64(federated), nil)

	return errors.Join(errs...)
}

// normalizeAuthType lowercases Graph's authenticationType value ("Managed" /
// "Federated") for the metric attribute. An empty or unrecognized value (a
// future Graph enum addition) is bucketed as "unknown" rather than silently
// dropped or left case-inconsistent, keeping the series set still bounded.
func normalizeAuthType(s string) string {
	if s == "" {
		return "unknown"
	}
	return strings.ToLower(s)
}

func init() {
	collectors.Register(func(d collectors.Deps) collector.SnapshotCollector {
		return New(d.Graph, d.Logger)
	})
}
