// Package serviceactivity is the Entra Service Activity collector (#368): the
// beta M365 monitoring `serviceActivity` surface, which reports MEASURED
// tenant sign-in and Global Secure Access experience rather than what
// Microsoft has DECLARED. m365.service_health already answers "does Microsoft
// say there is an incident"; this answers "did our tenant's MFA success rate
// fall off a cliff" — a fact Microsoft's own advisories cannot see, because
// nothing is wrong on their side.
//
// # Scope correction against the issue's premise — read this before adding a metric
//
// #368 was filed expecting Teams, Exchange, M365 Apps, MFA and GSA metrics.
// The beta EDM declares metric functions for exactly two things: tenant
// sign-in health (MFA, SAML, Conditional Access) and Global Secure Access.
// There is no Teams, Exchange or M365 Apps function anywhere on this surface
// (verified against the beta $metadata and all nineteen live 200s, 2026-07-28).
// That is why this lives under entra/ rather than under the m365/ package the
// issue's area label implies — it is not an oversight, it is what exists.
//
// # Nineteen independent functions, one non-fatal aggregate
//
// Every function is `getMetricsFor<X>` under
// /beta/reports/serviceActivity/, taking a bound
// (inclusiveIntervalStartDateTime, exclusiveIntervalEndDateTime,
// aggregationIntervalInMinutes) interval and returning a bare
// Collection(serviceActivityValueMetric) — {intervalStartDateTime, value}
// buckets, nothing else. aggregationIntervalInMinutes accepts ONLY 5, 10, 15
// or 30 (live-measured: 60 returns 400 "aggregationIntervalInMinutes not
// valid. Allowed values are 5, 10, 15, 30."); this collector always requests
// 30. Each function degrades independently: Collect issues all nineteen GETs,
// logs and folds a failure into a non-fatal errors.Join, and every other
// function still emits.
//
// # Four metrics, not one, and why
//
// Signins, network-access apps, network-access users and network-access
// branches are four separate metrics because their unit differs — sign-ins,
// apps, users and branches are not summable, so one metric with a mixed unit
// would make a `sum by` meaningless. Which of the nineteen functions a point
// came from is the bounded `activity` dimension (semconv.AttrActivity), whose
// values are graph2otel's own snake_case rendering of the function name — a
// code-supplied closed set, not a Graph-supplied one, so nothing here is
// declared to internal/wirecheck (see the functions table below, the single
// source of truth for the function -> metric -> activity mapping).
//
// # A measured zero is not an empty response, and both are not an error
//
// 18 of the 19 functions are a MEASURED ZERO on m7kni (live-measured
// 2026-07-28): no MFA-method sign-ins recorded, no GSA deployed. A bucket
// whose value is literally 0 IS a measurement and is emitted; the collector
// must never conflate that with "no data" the way an empty `value` array or a
// failed request are gaps. Both of the latter contribute NOTHING — no point —
// because a fabricated zero would misreport "unavailable" as "measured empty",
// exactly the distinction this collector's data exists to preserve (#240).
//
// # The window: publish the latest COMPLETE bucket, never a partial one
//
// The end of the request window is truncated DOWN to a 30-minute boundary so
// every bucket the API can return is complete, then the collector publishes
// the value of the LATEST such bucket — not the sum, not an average. Sampling
// a partial trailing bucket would report a half-counted interval that reads,
// on a graph, exactly like a real drop: the one failure mode this collector
// exists to catch. The request window itself is [end-2h, end) so a short or
// late-arriving response still yields at least one complete bucket. "Now" is
// taken from an injectable clock (Collector.now, default time.Now) rather than
// a literal — an absolute date baked into a time-compared path turns a build
// red on a calendar date instead of on a code change, which has happened on
// this repo before.
//
// # No log twin, and that is not an omission
//
// Every function returns a bare {intervalStartDateTime, value} pair with NO
// entity dimension at all — nothing per-user, per-app or per-branch is ever
// fetched, so #114's "not a metric label means log twin, never dropped" has
// nothing to preserve here. This is the one collector shape in this tree where
// a gauge is the complete signal, by construction, not by choice.
//
// # No interval_start attribute — raised, decided, and corrected upstream
//
// An earlier draft of this collector carried the bucket's own start time as a
// gauge-point attribute, reasoning that a metric was the only place left for
// it once "no log twin" was established. That was flagged rather than shipped
// silently, and the flag was right: attrs_entra_serviceactivity.go's
// correction block records why it is gone. A new bucket start every 30
// minutes mints a new series every 30 minutes, forever, each receiving
// exactly one sample — the same shape #112 forbids for a correlation ID,
// reached from a different direction. internal/signalcapture's per-entity
// check is an exact-match keyword list and does not name "interval_start", so
// signalgate_test.go passed over it mechanically; that pass was never
// evidence the attribute was safe.
//
// What is lost, honestly: the gauge publishes the latest COMPLETE bucket, so
// its value describes a window ending at most one aggregation interval (30
// minutes) ago, not the instant it was scraped. A reader who needs the exact
// window has no attribute to read it from — Prometheus's own sample
// timestamp is the closest available proxy, and it is a lag bound, not the
// bucket's real start.
//
// TestEmittedAttributeKeysAreExactly in serviceactivity_test.go is the guard
// against this coming back: it allow-lists the exact attribute-key set per
// metric rather than trusting a shared denylist to catch a name it was never
// told about.
package serviceactivity

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/rknightion/graph2otel/internal/collector"
	"github.com/rknightion/graph2otel/internal/collectors"
	entraoutcome "github.com/rknightion/graph2otel/internal/outcomehelper"
	"github.com/rknightion/graph2otel/internal/recordoutcome"
	"github.com/rknightion/graph2otel/internal/semconv"
	"github.com/rknightion/graph2otel/internal/telemetry"
)

// collectorName is the stable key used for config (enable/interval),
// self-observability, and the admin status page.
const collectorName = "entra.service_activity"

// betaBaseURL is the Graph beta service root — the serviceActivity metric
// functions have no v1.0 form.
const betaBaseURL = "https://graph.microsoft.com/beta"

// aggregationIntervalMinutes is the ONLY value this collector ever requests.
// Live-measured 2026-07-28: the API accepts exactly 5, 10, 15 or 30; 60
// returns a 400 naming that allowed set.
const aggregationIntervalMinutes = 30

// windowLookback is how far back the request window reaches. It is wider than
// one bucket so a short or late-arriving response still yields at least one
// complete, publishable bucket.
const windowLookback = 2 * time.Hour

// isoLayout formats a window bound as UNQUOTED ISO-8601
// (2026-07-27T12:00:00Z) — live-measured 2026-07-28: the function-call
// arguments take bare timestamps, not quoted strings, unlike some other bound
// Graph functions.
const isoLayout = "2006-01-02T15:04:05Z"

// Metric names emitted by this collector. Four rather than one: signins,
// network-access apps, users and branches are not summable together, so one
// metric with a mixed unit would make a `sum by` meaningless.
const (
	metricSignins  = "entra.service_activity.signins"
	metricNAApps   = "entra.service_activity.network_access_apps"
	metricNAUsers  = "entra.service_activity.network_access_users"
	metricNABranch = "entra.service_activity.network_access_branches"
)

// metricOrder fixes the GaugeSnapshot emission order (map iteration in Go is
// randomized, and a stable order keeps test output and docs generation
// deterministic).
var metricOrder = []string{metricSignins, metricNAApps, metricNAUsers, metricNABranch}

// metricMeta carries the unit and operator-facing description for each of the
// four metrics.
var metricMeta = map[string]struct{ unit, desc string }{
	metricSignins: {
		"{signin}",
		"Count of tenant sign-ins in the latest complete 30-minute bucket, by activity (MFA success/failure, SAML, Conditional Access outcome). Beta M365 monitoring serviceActivity surface (#368) — measured sign-in experience, distinct from m365.service_health's declared incidents. See the package doc.",
	},
	metricNAApps: {
		"{app}",
		"Count of Global Secure Access app-policy evaluations in the latest complete 30-minute bucket, by activity (internet/private app policy, allowed/blocked).",
	},
	metricNAUsers: {
		"{user}",
		"Count of Global Secure Access user-policy evaluations in the latest complete 30-minute bucket, by activity (internet/private app policy, allowed/blocked).",
	},
	metricNABranch: {
		"{branch}",
		"Count of Global Secure Access remote-network branches in the latest complete 30-minute bucket, by connectivity activity (alive, BGP/tunnel connected or disconnected).",
	},
}

// metricFunc is one of the nineteen serviceActivity metric functions: its
// Graph function name, the metric it feeds, and the activity label value it
// carries. This table is the single source of truth for the function -> metric
// -> activity mapping; nothing else restates it.
type metricFunc struct {
	fn       string
	metric   string
	activity string
}

// functions is every metric function this collector polls, grouped as the
// issue describes them. graph2otel's own snake_case rendering of each Graph
// function name is the activity label value — a code-supplied closed set, so
// none of it is declared to internal/wirecheck.
var functions = []metricFunc{
	// signins (6)
	{"getMetricsForMfaSignInSuccess", metricSignins, "mfa_signin_success"},
	{"getMetricsForMfaSignInFailure", metricSignins, "mfa_signin_failure"},
	{"getMetricsForSamlSignInSuccess", metricSignins, "saml_signin_success"},
	{"getMetricsForConditionalAccessBlockedSignIn", metricSignins, "ca_blocked_signin"},
	{"getMetricsForConditionalAccessCompliantDevicesSignInSuccess", metricSignins, "ca_compliant_devices_signin_success"},
	{"getMetricsForConditionalAccessManagedDevicesSignInSuccess", metricSignins, "ca_managed_devices_signin_success"},

	// network_access_apps (4)
	{"getMetricsForNetworkAccessInternetAppPolicyAllowedApps", metricNAApps, "internet_app_policy_allowed_apps"},
	{"getMetricsForNetworkAccessInternetAppPolicyBlockedApps", metricNAApps, "internet_app_policy_blocked_apps"},
	{"getMetricsForNetworkAccessPrivateAppsAllowedByConnector", metricNAApps, "private_apps_allowed_by_connector"},
	{"getMetricsForNetworkAccessPrivateAppsBlockedByConnector", metricNAApps, "private_apps_blocked_by_connector"},

	// network_access_users (4)
	{"getMetricsForNetworkAccessInternetAppPolicyAllowedUsers", metricNAUsers, "internet_app_policy_allowed_users"},
	{"getMetricsForNetworkAccessInternetAppPolicyBlockedUsers", metricNAUsers, "internet_app_policy_blocked_users"},
	{"getMetricsForNetworkAccessPrivateAppUsersAllowedByConnector", metricNAUsers, "private_app_users_allowed_by_connector"},
	{"getMetricsForNetworkAccessPrivateAppUsersBlockedByConnector", metricNAUsers, "private_app_users_blocked_by_connector"},

	// network_access_branches (5)
	{"getMetricsForNetworkAccessRemoteNetworkBranchesAlive", metricNABranch, "remote_network_branches_alive"},
	{"getMetricsForNetworkAccessRemoteNetworkBranchesBGPConnected", metricNABranch, "remote_network_branches_bgp_connected"},
	{"getMetricsForNetworkAccessRemoteNetworkBranchesBGPDisconnected", metricNABranch, "remote_network_branches_bgp_disconnected"},
	{"getMetricsForNetworkAccessRemoteNetworkBranchesTunnelConnected", metricNABranch, "remote_network_branches_tunnel_connected"},
	{"getMetricsForNetworkAccessRemoteNetworkBranchesTunnelDisconnected", metricNABranch, "remote_network_branches_tunnel_disconnected"},
}

// serviceActivityValue is one bucket of a serviceActivity metric-function
// response. Value is a pointer so a bucket that omits it (never observed live,
// but the shape is not guaranteed) is distinguishable from a measured zero.
type serviceActivityValue struct {
	IntervalStartDateTime string   `json:"intervalStartDateTime"`
	Value                 *float64 `json:"value"`
}

// serviceActivityResponse is the bare Collection(serviceActivityValueMetric)
// every function returns.
type serviceActivityResponse struct {
	Value []serviceActivityValue `json:"value"`
}

// Collector polls the Entra Service Activity beta metrics surface.
type Collector struct {
	g       collectors.GraphClient
	baseURL string
	logger  *slog.Logger
	// now is the injectable clock; nil means time.Now. Tests pin it so the
	// window-truncation boundary is deterministic rather than a function of
	// when the test happens to run.
	now func() time.Time
}

// New builds the collector. A nil logger falls back to slog.Default().
func New(g collectors.GraphClient, logger *slog.Logger) *Collector {
	if logger == nil {
		logger = slog.Default()
	}
	return &Collector{g: g, baseURL: betaBaseURL, logger: logger, now: time.Now}
}

// Name implements collector.Collector.
func (c *Collector) Name() string { return collectorName }

// DefaultInterval implements collector.Collector.
func (c *Collector) DefaultInterval() time.Duration { return 30 * time.Minute }

// Experimental marks this collector beta/opt-in: every serviceActivity
// function it reads exists only on the Graph beta endpoint, with no v1.0
// fallback (#183).
func (c *Collector) Experimental() bool { return true }

// RequiredPermissions declares the scope this collector reads with.
// Reports.Read.All is already held for the sibling m365 usage-report
// collectors and covers this /reports/serviceActivity surface too — all
// nineteen live 200s (2026-07-28) were obtained with no new grant, so this is
// stated honestly as a REUSE, not invented for this collector.
func (c *Collector) RequiredPermissions() []string { return []string{"Reports.Read.All"} }

// clock returns the collector's clock, defaulting to time.Now when unset.
func (c *Collector) clock() time.Time {
	if c.now != nil {
		return c.now()
	}
	return time.Now()
}

// Collect issues the nineteen independent fetches, one per metric function.
// Each is guarded on its own: a failure is logged and folded into a non-fatal
// aggregated error, and never prevents the others from emitting.
func (c *Collector) Collect(ctx context.Context, e telemetry.Emitter, outcomes *recordoutcome.Recorder) error {
	end := c.clock().UTC().Truncate(30 * time.Minute)
	start := end.Add(-windowLookback)
	startStr := start.Format(isoLayout)
	endStr := end.Format(isoLayout)

	groups := make(map[string][]telemetry.GaugePoint, len(metricOrder))
	var errs []error

	for _, mf := range functions {
		url := buildURL(c.baseURL, mf.fn, startStr, endStr)
		body, err := c.g.RawGet(ctx, url)
		if err != nil {
			c.logger.Warn("service activity fetch failed", "collector", collectorName, "function", mf.fn, "error", err)
			errs = append(errs, fmt.Errorf("%s: %w", mf.fn, err))
			entraoutcome.SourceError(outcomes)
			continue
		}

		var resp serviceActivityResponse
		if err := json.Unmarshal(body, &resp); err != nil {
			errs = append(errs, fmt.Errorf("%s: decode: %w", mf.fn, err))
			entraoutcome.Errored(outcomes, 1, recordoutcome.CauseDecodeError)
			continue
		}

		point := latestCompleteBucket(resp.Value, mf.activity)
		if point == nil {
			// An empty `value` array, or a response with no bucket carrying a
			// value, is a GAP — not a measured zero and not an error. Nothing
			// is emitted for this function this cycle.
			entraoutcome.Filtered(outcomes, 1)
			continue
		}
		groups[mf.metric] = append(groups[mf.metric], *point)
		entraoutcome.Emitted(outcomes, 1)
	}

	for _, name := range metricOrder {
		meta := metricMeta[name]
		e.GaugeSnapshot(name, meta.unit, meta.desc, groups[name])
	}

	return errors.Join(errs...)
}

// buildURL constructs the bound-function URL for one metric function. Times
// are unquoted ISO-8601 (live-measured 2026-07-28), and
// aggregationIntervalInMinutes is always 30.
func buildURL(baseURL, fn, startStr, endStr string) string {
	return fmt.Sprintf("%s/reports/serviceActivity/%s(inclusiveIntervalStartDateTime=%s,exclusiveIntervalEndDateTime=%s,aggregationIntervalInMinutes=%d)",
		baseURL, fn, startStr, endStr, aggregationIntervalMinutes)
}

// latestCompleteBucket returns the gauge point for the LATEST bucket carrying
// a value, or nil when no bucket does (an empty response, or one whose
// buckets all omit "value" — both gaps, never a fabricated zero). Every
// bucket the request window can return is already complete (the window end is
// truncated to a 30-minute boundary before the request is made), so "latest"
// here means "latest of what was returned", not a completeness filter.
func latestCompleteBucket(vals []serviceActivityValue, activity string) *telemetry.GaugePoint {
	var best *serviceActivityValue
	var bestTime time.Time
	for i := range vals {
		v := &vals[i]
		if v.Value == nil {
			continue
		}
		t, err := time.Parse(time.RFC3339, v.IntervalStartDateTime)
		if err != nil {
			continue
		}
		if best == nil || t.After(bestTime) {
			best = v
			bestTime = t
		}
	}
	if best == nil {
		return nil
	}
	return &telemetry.GaugePoint{
		Value: *best.Value,
		Attrs: telemetry.Attrs{
			semconv.AttrActivity:                   activity,
			semconv.AttrAggregationIntervalMinutes: int64(aggregationIntervalMinutes),
		},
	}
}

func init() {
	collectors.Register(func(d collectors.Deps) collector.SnapshotCollector {
		return New(d.Graph, d.Logger)
	})
}

// Compile-time checks that the collector satisfies every interface the
// composition root type-asserts on.
var (
	_ collector.SnapshotCollector = (*Collector)(nil)
	_ collectors.Experimental     = (*Collector)(nil)
)
