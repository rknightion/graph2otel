// Package groups is the Entra groups collector: bounded population aggregates
// (by group type, membership model, security-enabled, mail-enabled) plus a
// dedicated role-assignable-group count, all via cheap $count slices. It
// never enumerates individual groups or group membership — see the
// per-group member-count deviation note in this package's design brief.
package groups

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/url"
	"time"

	"github.com/rknightion/graph2otel/internal/collector"
	"github.com/rknightion/graph2otel/internal/collectors"
	"github.com/rknightion/graph2otel/internal/semconv"
	"github.com/rknightion/graph2otel/internal/telemetry"
)

// collectorName is the stable key used for config (enable/interval),
// self-observability, and the admin status page.
const collectorName = "entra.groups"

// totalMetricName is the bounded population-slice gauge.
const totalMetricName = "entra.groups.total"

// roleAssignableMetricName is the dedicated, dimensionless privileged-group
// count — a direct compliance signal, so it gets its own series rather than
// being folded into totalMetricName as another group_type value.
const roleAssignableMetricName = "entra.groups.role_assignable.total"

// defaultBaseURL is the Graph v1.0 root.
const defaultBaseURL = "https://graph.microsoft.com/v1.0"

// roleAssignableFilter selects groups that can be granted a directory role.
// isAssignableToRole supports both default and advanced query per the Graph
// "Advanced query capabilities on directory objects" reference (verified
// 2026-07-15).
const roleAssignableFilter = "isAssignableToRole eq true"

// groupSlice pairs a bounded, single-key attribute with the $filter that
// selects it. Every filter here was verified live against the Graph v1.0
// "List groups" reference (learn.microsoft.com/en-us/graph/api/group-list),
// which documents this exact four-way group_type classification (Microsoft
// 365 / security / mail-enabled security / distribution) and the
// groupTypes/any(...) DynamicMembership filter for membership_type.
type groupSlice struct {
	label  string // for logs/errors, e.g. "group_type=m365"
	attrs  telemetry.Attrs
	filter string
}

// groupSlices is the fixed, bounded set of population slices counted every
// tick. Cardinality of totalMetricName is exactly len(groupSlices), regardless
// of tenant size.
var groupSlices = []groupSlice{
	// group_type: mutually exclusive, exhaustive 4-way split straight from the
	// Graph docs' own "Filter by group types" table.
	{"group_type=m365", telemetry.Attrs{semconv.AttrGroupType: "m365"}, "groupTypes/any(c:c eq 'Unified')"},
	{"group_type=security", telemetry.Attrs{semconv.AttrGroupType: "security"}, "mailEnabled eq false and securityEnabled eq true"},
	{"group_type=mail_enabled_security", telemetry.Attrs{semconv.AttrGroupType: "mail_enabled_security"}, "NOT groupTypes/any(c:c eq 'Unified') and mailEnabled eq true and securityEnabled eq true"},
	{"group_type=distribution", telemetry.Attrs{semconv.AttrGroupType: "distribution"}, "NOT groupTypes/any(c:c eq 'Unified') and mailEnabled eq true and securityEnabled eq false"},

	// membership_type: dynamic membership rule vs statically assigned.
	{"membership_type=dynamic", telemetry.Attrs{semconv.AttrMembershipType: "dynamic"}, "groupTypes/any(c:c eq 'DynamicMembership')"},
	{"membership_type=assigned", telemetry.Attrs{semconv.AttrMembershipType: "assigned"}, "NOT groupTypes/any(c:c eq 'DynamicMembership')"},

	// security_enabled / mail_enabled: the two raw booleans the issue asks for
	// as their own slices, independent of the group_type classification above.
	{"security_enabled=true", telemetry.Attrs{semconv.AttrSecurityEnabled: true}, "securityEnabled eq true"},
	{"security_enabled=false", telemetry.Attrs{semconv.AttrSecurityEnabled: false}, "securityEnabled eq false"},
	{"mail_enabled=true", telemetry.Attrs{semconv.AttrMailEnabled: true}, "mailEnabled eq true"},
	{"mail_enabled=false", telemetry.Attrs{semconv.AttrMailEnabled: false}, "mailEnabled eq false"},
}

// filterCountURL builds a /groups/$count URL with the given $filter, letting
// net/url handle escaping consistently.
func filterCountURL(baseURL, filter string) string {
	return baseURL + "/groups/$count?" + url.Values{"$filter": {filter}}.Encode()
}

// Collector polls bounded Entra group population slices.
type Collector struct {
	g       collectors.GraphClient
	baseURL string
	logger  *slog.Logger
}

// New builds the groups collector. A nil logger falls back to the slog
// default.
func New(g collectors.GraphClient, logger *slog.Logger) *Collector {
	if logger == nil {
		logger = slog.Default()
	}
	return &Collector{g: g, baseURL: defaultBaseURL, logger: logger}
}

// Name implements collector.Collector.
func (c *Collector) Name() string { return collectorName }

// DefaultInterval implements collector.Collector. Group population drifts
// slowly; five minutes matches the directory-counts collector's cadence and
// is trivially cheap on the directory-objects RU budget (11 $count calls/tick).
func (c *Collector) DefaultInterval() time.Duration { return 5 * time.Minute }

// RequiredPermissions declares the least-privilege Graph application scope.
// Group.Read.All covers every $count slice this collector issues; the
// broader Directory.Read.All also works per the issue but isn't the minimum.
func (c *Collector) RequiredPermissions() []string { return []string{"Group.Read.All"} }

// Collect fetches every bounded population slice plus the role-assignable
// count and emits them. A failure on one slice (or on the role-assignable
// count) is logged and that series is dropped from its snapshot, but every
// other series still emits; the aggregated error is returned so partial
// failure is visible in scrape self-obs without hiding the data that did
// succeed.
func (c *Collector) Collect(ctx context.Context, e telemetry.Emitter) error {
	points := make([]telemetry.GaugePoint, 0, len(groupSlices))
	var errs []error

	for _, s := range groupSlices {
		n, err := collectors.Count(ctx, c.g, filterCountURL(c.baseURL, s.filter))
		if err != nil {
			c.logger.Warn("group count failed", "collector", collectorName, "slice", s.label, "error", err)
			errs = append(errs, fmt.Errorf("%s: %w", s.label, err))
			continue
		}
		points = append(points, telemetry.GaugePoint{Value: float64(n), Attrs: s.attrs})
	}
	e.GaugeSnapshot(totalMetricName, "{group}", "Total Entra groups, sliced by bounded population dimensions (group_type, membership_type, security_enabled, mail_enabled).", points)

	if n, err := collectors.Count(ctx, c.g, filterCountURL(c.baseURL, roleAssignableFilter)); err != nil {
		c.logger.Warn("role-assignable group count failed", "collector", collectorName, "error", err)
		errs = append(errs, fmt.Errorf("role_assignable: %w", err))
	} else {
		e.Gauge(roleAssignableMetricName, "{group}", "Total Entra groups assignable to a directory role.", float64(n), nil)
	}

	return errors.Join(errs...)
}

func init() {
	collectors.Register(func(d collectors.Deps) collector.SnapshotCollector {
		return New(d.Graph, d.Logger)
	})
}
