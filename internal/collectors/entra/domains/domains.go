// Package domains is the Entra domain posture collector: verified/federated/
// managed domain posture, aggregated into small, tenant-shaped gauges, PLUS a
// log twin of the same fetch — one OTEL log record per domain carrying the
// identity/posture detail the gauges never carry (the domain name itself,
// isDefault/isInitial/isRoot/isAdminManaged, supportedServices).
//
// A tenant's domain list is tiny (dozens at most, see domainsPath), so this
// was never a cardinality problem — domain names/ids are still never emitted
// as a metric LABEL (a per-domain series buys nothing over the bounded
// posture breakdown below), but "not a metric label" means "log twin", not
// "dropped". "Which domain is unverified or federated" is a genuine
// trust-surface question this collector previously couldn't answer (#114).
//
// The two bounded gauges — entra.domains.total (authentication_type x
// is_verified) and the federated-count convenience gauge — are unchanged.
package domains

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"strconv"
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

// eventDomain is the log-twin EventName: one record per domain per cycle,
// carrying the identity/posture detail the gauges above cannot. See the
// package doc.
const eventDomain = "entra.domain"

// defaultBaseURL is the Graph v1.0 root.
const defaultBaseURL = "https://graph.microsoft.com/v1.0"

// domainsPath is a plain, unfiltered domain list — GET /domains — a small,
// bounded collection with no delta query and no $filter/$search of note (both
// are documented as unreliable on this endpoint), so a full read every tick is
// the correct, cheap approach.
const domainsPath = "/domains"

// domain is the subset of the Graph domain resource this collector reads. See
// https://learn.microsoft.com/en-us/graph/api/resources/domain (verified
// live against the v1.0 docs, 2026-07-16) - authenticationType is "Managed"
// or "Federated" (exact casing from Graph). ID is the domain's fully
// qualified name (Graph's own key field for this resource - there is no
// separate GUID id and no separate "name" property). IsAdminManaged,
// IsDefault, IsInitial, IsRoot, and SupportedServices bucket ONLY into the
// log twin, never a metric label - see the package doc.
type domain struct {
	ID                 string   `json:"id"`
	AuthenticationType string   `json:"authenticationType"`
	IsVerified         bool     `json:"isVerified"`
	IsDefault          bool     `json:"isDefault"`
	IsInitial          bool     `json:"isInitial"`
	IsRoot             bool     `json:"isRoot"`
	IsAdminManaged     bool     `json:"isAdminManaged"`
	SupportedServices  []string `json:"supportedServices"`
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
		e.LogEvent(domainLogTwin(d, authType))
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

// domainLogTwin renders one domain as an OTLP log record carrying the
// identity/posture detail entra.domains.total cannot (see the package doc).
// authType is the already-normalized authentication type so the twin and the
// gauge never disagree on bucketing.
//
// Severity escalates to Warn for an unverified or federated domain: those are
// the concrete trust-surface questions an operator asks of a domain list
// ("which domain isn't ours yet" / "which domain hands authentication to a
// third party"). A routine managed, verified domain stays Info.
func domainLogTwin(d domain, authType string) telemetry.Event {
	attrs := telemetry.Attrs{}
	setStr(attrs, "id", d.ID)
	setStr(attrs, "authentication_type", authType)
	// Booleans have no "absent" state (false is meaningful data, not a missing
	// field, unlike an empty string) - see the frozen seam in #114 - so these
	// are always set, never gated by setStr.
	attrs["is_verified"] = strconv.FormatBool(d.IsVerified)
	attrs["is_default"] = strconv.FormatBool(d.IsDefault)
	attrs["is_initial"] = strconv.FormatBool(d.IsInitial)
	attrs["is_root"] = strconv.FormatBool(d.IsRoot)
	attrs["is_admin_managed"] = strconv.FormatBool(d.IsAdminManaged)
	setStr(attrs, "supported_services", strings.Join(d.SupportedServices, ","))

	sev := telemetry.SeverityInfo
	if !d.IsVerified || authType == "federated" {
		sev = telemetry.SeverityWarn
	}

	return telemetry.Event{
		Name:     eventDomain,
		Body:     fmt.Sprintf("domain %s: authentication_type=%s is_verified=%t", d.ID, authType, d.IsVerified),
		Severity: sev,
		Attrs:    attrs,
	}
}

// setStr adds key=val to attrs only when val is non-empty, so an absent
// string field emits no attribute rather than an empty one - matches the
// entra/risk and purview/labels reference collectors.
func setStr(attrs telemetry.Attrs, key, val string) {
	if val != "" {
		attrs[key] = val
	}
}

func init() {
	collectors.Register(func(d collectors.Deps) collector.SnapshotCollector {
		return New(d.Graph, d.Logger)
	})
}
