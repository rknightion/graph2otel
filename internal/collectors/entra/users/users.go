// Package users is the Entra user-population collector: cheap, sliced
// `$count` aggregates (account_enabled, user_type, on_premises_sync_enabled)
// emitted on every license tier, plus an optional stale-account gauge that
// partially degrades — the signInActivity property (and therefore the
// stale-accounts signal) is licensed under Microsoft Entra ID P1 or P2 and
// requires AuditLog.Read.All on top of User.Read.All, so it is emitted only
// when the tenant holds one of those capabilities. Population counts always
// emit regardless of license tier. See GitHub issue #39.
package users

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/url"
	"time"

	"github.com/rknightion/graph2otel/internal/collector"
	"github.com/rknightion/graph2otel/internal/collectors"
	"github.com/rknightion/graph2otel/internal/license"
	"github.com/rknightion/graph2otel/internal/telemetry"
)

// collectorName is the stable key used for config (enable/interval),
// self-observability, and the admin status page.
const collectorName = "entra.users"

// Metric names this collector emits.
const (
	metricPopulation = "entra.users.total"
	metricStale      = "entra.users.stale.total"
)

// defaultBaseURL is the Graph v1.0 root.
const defaultBaseURL = "https://graph.microsoft.com/v1.0"

// staleThresholdsDays is the fixed, bounded set of "no sign-in for at least N
// days" cutoffs the stale gauge reports. Cardinality of entra.users.stale.total
// is exactly len(staleThresholdsDays).
var staleThresholdsDays = []int{30, 90}

// sliceValue pairs one bounded attribute value with the $filter expression
// that selects the users matching it.
type sliceValue struct {
	value  string
	filter string
}

// axis is one independent population dimension: a metric attribute key plus
// its fixed, bounded set of values. entra.users.total emits one point per
// value PER AXIS, not a cross-product across axes — so total cardinality is
// the SUM of each axis's value count (6, here), not the product (8).
type axis struct {
	attr   string
	values []sliceValue
}

// populationAxes is the fixed set of population slices backing
// entra.users.total. Each axis is counted independently via its own
// sliced $count call, per the issue's "cheap $count calls, don't page the
// full collection" requirement.
var populationAxes = []axis{
	{
		attr: "account_enabled",
		values: []sliceValue{
			{"true", "accountEnabled eq true"},
			{"false", "accountEnabled eq false"},
		},
	},
	{
		attr: "user_type",
		values: []sliceValue{
			{"member", "userType eq 'Member'"},
			{"guest", "userType eq 'Guest'"},
		},
	},
	{
		attr: "on_premises_sync_enabled",
		values: []sliceValue{
			{"true", "onPremisesSyncEnabled eq true"},
			// onPremisesSyncEnabled is a nullable Boolean: false means "no
			// longer synced from on-prem", null means "never synced". Both
			// fold into the bounded "false" bucket so the two buckets
			// exhaustively partition the tenant's users.
			{"false", "onPremisesSyncEnabled eq false or onPremisesSyncEnabled eq null"},
		},
	},
}

// Collector polls Entra user population counts and, when licensed, the
// stale-accounts gauge.
type Collector struct {
	g       collectors.GraphClient
	caps    license.Capabilities
	baseURL string
	logger  *slog.Logger
	now     func() time.Time
}

// New builds the users collector. A nil logger falls back to the slog
// default. caps is the tenant's detected license capability set
// (internal/license) — the stale-accounts gauge is emitted only when caps
// grants CapEntraP1 or CapEntraP2 (Microsoft licenses the signInActivity
// property under either tier; see the user-list docs' Example 11 note).
// Population gauges always emit regardless of caps: this collector
// deliberately does NOT implement license.CapabilityRequirer, since it must
// keep running on every tier to emit the base population signal.
func New(g collectors.GraphClient, caps license.Capabilities, logger *slog.Logger) *Collector {
	if logger == nil {
		logger = slog.Default()
	}
	return &Collector{g: g, caps: caps, baseURL: defaultBaseURL, logger: logger, now: time.Now}
}

// Name implements collector.Collector.
func (c *Collector) Name() string { return collectorName }

// DefaultInterval implements collector.Collector. User population and
// sign-in staleness drift slowly; 15 minutes keeps both the directory-object
// $count budget and the licensed signInActivity queries cheap.
func (c *Collector) DefaultInterval() time.Duration { return 15 * time.Minute }

// RequiredPermissions declares the least-privilege Graph application scopes:
// User.Read.All for the population counts, plus AuditLog.Read.All, which
// Microsoft requires (on top of User.Read.All) to read the signInActivity
// property backing the stale-accounts gauge.
func (c *Collector) RequiredPermissions() []string {
	return []string{"User.Read.All", "AuditLog.Read.All"}
}

// Collect emits the population gauges on every tier, then the stale-accounts
// gauge only when the tenant holds Entra ID P1 or P2. A per-bucket count
// failure is logged and that bucket is dropped from its snapshot, but the
// others still emit; the aggregated error is returned so the partial failure
// is visible in scrape self-observability without hiding the data.
func (c *Collector) Collect(ctx context.Context, e telemetry.Emitter) error {
	var errs []error

	points := make([]telemetry.GaugePoint, 0, 6)
	for _, ax := range populationAxes {
		for _, v := range ax.values {
			n, err := c.count(ctx, v.filter)
			if err != nil {
				c.logger.Warn("user population count failed",
					"collector", collectorName, "attr", ax.attr, "value", v.value, "error", err)
				errs = append(errs, fmt.Errorf("%s=%s: %w", ax.attr, v.value, err))
				continue
			}
			points = append(points, telemetry.GaugePoint{
				Value: float64(n),
				Attrs: telemetry.Attrs{ax.attr: v.value},
			})
		}
	}
	e.GaugeSnapshot(metricPopulation, "{user}",
		"Total Entra users, independently sliced by account_enabled, user_type, and on_premises_sync_enabled.",
		points)

	if !c.caps.Has(license.CapEntraP1) && !c.caps.Has(license.CapEntraP2) {
		c.logger.Info("skipping entra.users.stale.total: tenant lacks entra_p1/entra_p2 (signInActivity is licensed)",
			"collector", collectorName)
		return errors.Join(errs...)
	}

	stalePoints := make([]telemetry.GaugePoint, 0, len(staleThresholdsDays))
	for _, days := range staleThresholdsDays {
		cutoff := c.now().UTC().AddDate(0, 0, -days).Truncate(time.Second).Format("2006-01-02T15:04:05Z")
		filter := fmt.Sprintf("signInActivity/lastSignInDateTime le %s", cutoff)
		n, err := c.countStale(ctx, filter)
		if err != nil {
			c.logger.Warn("stale user count failed",
				"collector", collectorName, "threshold_days", days, "error", err)
			errs = append(errs, fmt.Errorf("stale threshold_days=%d: %w", days, err))
			continue
		}
		stalePoints = append(stalePoints, telemetry.GaugePoint{
			Value: float64(n),
			Attrs: telemetry.Attrs{"threshold_days": days},
		})
	}
	e.GaugeSnapshot(metricStale, "{user}",
		"Count of Entra users whose last sign-in is older than threshold_days. Requires Entra ID P1 or P2 (signInActivity).",
		stalePoints)

	return errors.Join(errs...)
}

// count issues a sliced $count request for the given (unescaped) $filter
// expression against the /users/$count segment. Correct for simple-property
// filters (accountEnabled, userType, onPremisesSyncEnabled).
func (c *Collector) count(ctx context.Context, filter string) (int64, error) {
	u := c.baseURL + "/users/$count?$filter=" + url.QueryEscape(filter)
	return collectors.Count(ctx, c.g, u)
}

// countStale counts users matching a signInActivity filter. The /users/$count
// segment returns HTTP 502 for a signInActivity filter (verified live against
// Graph), so this uses the $count=true collection form reading @odata.count —
// the documented way to count by signInActivity. $top=1&$select=id keeps the
// response body tiny (we only read the count, not the page).
func (c *Collector) countStale(ctx context.Context, filter string) (int64, error) {
	u := c.baseURL + "/users?$filter=" + url.QueryEscape(filter) + "&$count=true&$top=1&$select=id"
	return collectors.CountViaCollection(ctx, c.g, u)
}

func init() {
	collectors.Register(func(d collectors.Deps) collector.SnapshotCollector {
		return New(d.Graph, d.Caps, d.Logger)
	})
}
