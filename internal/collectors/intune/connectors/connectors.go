// Package connectors is the Intune connector-health collector: connection
// state and heartbeat/sync staleness for the three connector types Intune
// exposes for hybrid integrations — the Exchange Connector (on-premises/
// hosted Exchange ActiveSync conditional access), the Mobile Threat Defense
// (MTD) partner connector, and the Network Device Enrollment Service (NDES)
// certificate connector.
//
// Exchange and MTD are v1.0 endpoints; NDES has no v1.0 mirror
// (deviceManagement/ndesConnectors is beta-only), so this collector is NOT
// collectors.Experimental overall — the default-on Exchange/MTD coverage must
// not depend on a beta surface — but it polls NDES best-effort against
// /beta with fully isolated error handling: an NDES/beta failure drops only
// the NDES points from a cycle's snapshots and never fails the Exchange/MTD
// metrics (M4 seam decision, issue #51 / tracker #79 comment). The sibling
// certificates collector (#63) intentionally excludes ndesConnectors and any
// NDES metric — this collector owns all NDES connector-health data.
package connectors

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
const collectorName = "intune.connectors"

// Metric names this collector emits. state and heartbeat_age are shared
// across all three connector types (sliced by the bounded connector_type
// attribute) so a query can compare them directly; mtd_platform is its own
// metric because its dimensions (platform, enabled) don't apply to the other
// two connector types.
const (
	stateMetric        = "intune.connector.state"
	heartbeatAgeMetric = "intune.connector.heartbeat_age_seconds"
	mtdPlatformMetric  = "intune.connector.mtd_platform.total"
)

// connector_type attribute values. Bounded: exactly these three, regardless
// of tenant size (a tenant can configure multiple instances of a given
// connector type, e.g. several Exchange connectors, but the type enum itself
// never grows).
const (
	connectorTypeExchange = "exchange"
	connectorTypeMTD      = "mtd"
	connectorTypeNDES     = "ndes"
)

// defaultBaseURL is the Graph v1.0 root, used for the Exchange and MTD
// connector endpoints. betaBaseURL is used only for the NDES connector
// endpoint, which has no v1.0 mirror.
const (
	defaultBaseURL = "https://graph.microsoft.com/v1.0"
	betaBaseURL    = "https://graph.microsoft.com/beta"
)

// mtdPlatforms is the fixed, ordered set of platforms the MTD connector
// resource exposes an *Enabled field for. Fixed order keeps emitted point
// order deterministic, which is convenient for tests; it has no effect on
// correctness (GaugeSnapshot replaces the whole named series set regardless
// of point order).
var mtdPlatforms = []string{"android", "ios", "windows"}

// exchangeConnector is the subset of the v1.0 deviceManagementExchangeConnector
// resource this collector reads. status is a
// deviceManagementExchangeConnectorStatus enum: none, connectionPending,
// connected, disconnected, unknownFutureValue.
type exchangeConnector struct {
	Status           string    `json:"status"`
	LastSyncDateTime time.Time `json:"lastSyncDateTime"`
}

// mtdConnector is the subset of the v1.0 mobileThreatDefenseConnector
// resource this collector reads. partnerState is a
// mobileThreatPartnerTenantState enum: unavailable, available, enabled,
// unresponsive, notSetUp, error, unknownFutureValue — "unresponsive" is a
// compliance-impacting state, not just a health blip: it means Intune has
// stopped trusting the MTD partner's device risk signal for compliance
// evaluation, so devices depending on that signal can silently fall out of
// compliance until the partner is responsive again. That value flows through
// this collector's state gauge like every other enum value (bounded, no
// special-casing needed to make it visible - a dashboard/alert slices on
// state=="unresponsive" directly).
type mtdConnector struct {
	PartnerState          string    `json:"partnerState"`
	LastHeartbeatDateTime time.Time `json:"lastHeartbeatDateTime"`
	AndroidEnabled        bool      `json:"androidEnabled"`
	IosEnabled            bool      `json:"iosEnabled"`
	WindowsEnabled        bool      `json:"windowsEnabled"`
}

// ndesConnector is the subset of the beta ndesConnector resource this
// collector reads. state is an ndesConnectorState enum: none, active,
// inactive.
type ndesConnector struct {
	State                  string    `json:"state"`
	LastConnectionDateTime time.Time `json:"lastConnectionDateTime"`
}

// Collector polls the Exchange, MTD, and (beta) NDES connector endpoints.
type Collector struct {
	g       collectors.GraphClient
	baseURL string
	betaURL string
	logger  *slog.Logger
	// now returns the current time; overridable in tests so heartbeat-age
	// values are deterministic and assertable.
	now func() time.Time
}

// New builds the connectors collector. A nil logger falls back to the slog
// default.
func New(g collectors.GraphClient, logger *slog.Logger) *Collector {
	if logger == nil {
		logger = slog.Default()
	}
	return &Collector{g: g, baseURL: defaultBaseURL, betaURL: betaBaseURL, logger: logger, now: time.Now}
}

// Name implements collector.Collector.
func (c *Collector) Name() string { return collectorName }

// DefaultInterval implements collector.Collector. Connector configuration and
// health drift slowly and each poll is three tiny list requests, so a
// moderate cadence (matching entra.devices) is fine.
func (c *Collector) DefaultInterval() time.Duration { return 15 * time.Minute }

// RequiredPermissions declares the least-privilege Graph application scope.
// DeviceManagementServiceConfig.Read.All covers all three connector list
// endpoints (Exchange, MTD, and beta NDES).
func (c *Collector) RequiredPermissions() []string {
	return []string{"DeviceManagementServiceConfig.Read.All"}
}

// Collect fetches the three connector lists and emits the state and
// heartbeat-age gauges (plus the optional MTD per-platform gauge). Exchange,
// MTD, and NDES are each collected independently: a failure in one is logged
// and joined into the returned error, but never prevents the other two from
// emitting. All three get the same graceful-skip treatment for
// isUnavailable errors (403/404/501): a tenant that simply hasn't configured
// a given connector type (verified live — a missing Exchange connector
// returns 501 NotSupported, not an empty list) yields no points for that
// type and no entry in the returned error, rather than "collector failed" on
// every scrape. Only a genuine error (5xx other than 501, auth failure, bad
// JSON at the transport level, ...) is logged at WARN and joined into the
// returned error.
func (c *Collector) Collect(ctx context.Context, e telemetry.Emitter) error {
	var errs []error
	var statePoints []telemetry.GaugePoint
	var heartbeatPoints []telemetry.GaugePoint
	var mtdPlatformPoints []telemetry.GaugePoint

	now := c.now()

	exPoints, exAge, err := c.exchangeSnapshot(ctx, now)
	if err != nil {
		if isUnavailable(err) {
			c.logger.Info("connectors: exchange connectors endpoint unavailable on this tenant; skipping exchange metrics",
				"collector", collectorName, "error", err)
		} else {
			c.logger.Warn("connectors: exchange connectors list failed", "collector", collectorName, "error", err)
			errs = append(errs, fmt.Errorf("exchange connectors: %w", err))
		}
	} else {
		statePoints = append(statePoints, exPoints...)
		if exAge != nil {
			heartbeatPoints = append(heartbeatPoints, *exAge)
		}
	}

	mtdPoints, mtdAge, platformPoints, err := c.mtdSnapshot(ctx, now)
	if err != nil {
		if isUnavailable(err) {
			c.logger.Info("connectors: mobile threat defense connectors endpoint unavailable on this tenant; skipping mtd metrics",
				"collector", collectorName, "error", err)
		} else {
			c.logger.Warn("connectors: mobile threat defense connectors list failed", "collector", collectorName, "error", err)
			errs = append(errs, fmt.Errorf("mtd connectors: %w", err))
		}
	} else {
		statePoints = append(statePoints, mtdPoints...)
		if mtdAge != nil {
			heartbeatPoints = append(heartbeatPoints, *mtdAge)
		}
		mtdPlatformPoints = append(mtdPlatformPoints, platformPoints...)
	}

	ndesPoints, ndesAge, err := c.ndesSnapshot(ctx, now)
	if err != nil {
		if isUnavailable(err) {
			c.logger.Info("connectors: ndes connectors endpoint unavailable on this tenant; skipping NDES metrics",
				"collector", collectorName, "error", err)
		} else {
			c.logger.Warn("connectors: ndes connectors list failed (isolated beta endpoint; exchange/mtd metrics unaffected)",
				"collector", collectorName, "error", err)
			errs = append(errs, fmt.Errorf("ndes connectors (beta, isolated): %w", err))
		}
	} else {
		statePoints = append(statePoints, ndesPoints...)
		if ndesAge != nil {
			heartbeatPoints = append(heartbeatPoints, *ndesAge)
		}
	}

	e.GaugeSnapshot(stateMetric, "{connector}", "Intune connector instances by connector type and state.", statePoints)
	e.GaugeSnapshot(heartbeatAgeMetric, "s",
		"Age of the most recent heartbeat/sync across each Intune connector type's instances, in seconds (the most stale instance, not an average).",
		heartbeatPoints)
	if len(mtdPlatformPoints) > 0 {
		e.GaugeSnapshot(mtdPlatformMetric, "{connector}", "Mobile Threat Defense connector instances by platform and enabled state.", mtdPlatformPoints)
	}

	return errors.Join(errs...)
}

// exchangeSnapshot lists the Exchange connectors and returns the state-count
// points plus the heartbeat-age point (nil if no instance has a non-zero
// lastSyncDateTime).
func (c *Collector) exchangeSnapshot(ctx context.Context, now time.Time) ([]telemetry.GaugePoint, *telemetry.GaugePoint, error) {
	raw, err := collectors.GetAllValues(ctx, c.g, c.baseURL+"/deviceManagement/exchangeConnectors", nil)
	if err != nil {
		return nil, nil, err
	}

	byState := map[string]int{}
	var maxAge float64
	haveAge := false
	for _, r := range raw {
		var conn exchangeConnector
		if err := json.Unmarshal(r, &conn); err != nil {
			c.logger.Warn("connectors: skipping unparseable exchange connector", "collector", collectorName, "error", err)
			continue
		}
		byState[orUnknown(conn.Status)]++
		if !conn.LastSyncDateTime.IsZero() {
			if age := now.Sub(conn.LastSyncDateTime).Seconds(); !haveAge || age > maxAge {
				maxAge, haveAge = age, true
			}
		}
	}

	points := make([]telemetry.GaugePoint, 0, len(byState))
	for state, n := range byState {
		points = append(points, telemetry.GaugePoint{
			Value: float64(n),
			Attrs: telemetry.Attrs{"connector_type": connectorTypeExchange, "state": state},
		})
	}
	return points, agePointOrNil(connectorTypeExchange, maxAge, haveAge), nil
}

// mtdSnapshot lists the Mobile Threat Defense connectors and returns the
// state-count points, the heartbeat-age point, and the per-platform
// enabled/disabled counts. The platform points are only meaningful (and only
// returned) when at least one MTD connector instance exists; a tenant with no
// MTD partner configured gets no mtd_platform series at all rather than a
// spurious all-zero one.
func (c *Collector) mtdSnapshot(ctx context.Context, now time.Time) ([]telemetry.GaugePoint, *telemetry.GaugePoint, []telemetry.GaugePoint, error) {
	raw, err := collectors.GetAllValues(ctx, c.g, c.baseURL+"/deviceManagement/mobileThreatDefenseConnectors", nil)
	if err != nil {
		return nil, nil, nil, err
	}

	byState := map[string]int{}
	enabledCount := map[string]int{}
	disabledCount := map[string]int{}
	var maxAge float64
	haveAge := false
	instances := 0
	for _, r := range raw {
		var conn mtdConnector
		if err := json.Unmarshal(r, &conn); err != nil {
			c.logger.Warn("connectors: skipping unparseable mtd connector", "collector", collectorName, "error", err)
			continue
		}
		instances++
		byState[orUnknown(conn.PartnerState)]++
		if !conn.LastHeartbeatDateTime.IsZero() {
			if age := now.Sub(conn.LastHeartbeatDateTime).Seconds(); !haveAge || age > maxAge {
				maxAge, haveAge = age, true
			}
		}
		bumpPlatform(enabledCount, disabledCount, "android", conn.AndroidEnabled)
		bumpPlatform(enabledCount, disabledCount, "ios", conn.IosEnabled)
		bumpPlatform(enabledCount, disabledCount, "windows", conn.WindowsEnabled)
	}

	points := make([]telemetry.GaugePoint, 0, len(byState))
	for state, n := range byState {
		points = append(points, telemetry.GaugePoint{
			Value: float64(n),
			Attrs: telemetry.Attrs{"connector_type": connectorTypeMTD, "state": state},
		})
	}

	var platformPoints []telemetry.GaugePoint
	if instances > 0 {
		platformPoints = make([]telemetry.GaugePoint, 0, 2*len(mtdPlatforms))
		for _, platform := range mtdPlatforms {
			platformPoints = append(platformPoints,
				telemetry.GaugePoint{Value: float64(enabledCount[platform]), Attrs: telemetry.Attrs{"platform": platform, "enabled": true}},
				telemetry.GaugePoint{Value: float64(disabledCount[platform]), Attrs: telemetry.Attrs{"platform": platform, "enabled": false}},
			)
		}
	}

	return points, agePointOrNil(connectorTypeMTD, maxAge, haveAge), platformPoints, nil
}

// ndesSnapshot lists the beta NDES connectors and returns the state-count
// points plus the heartbeat-age point. Errors are returned as-is (including
// 403/404) for Collect to classify; this function has no opinion on whether a
// given error is "unavailable" vs. real.
func (c *Collector) ndesSnapshot(ctx context.Context, now time.Time) ([]telemetry.GaugePoint, *telemetry.GaugePoint, error) {
	raw, err := collectors.GetAllValues(ctx, c.g, c.betaURL+"/deviceManagement/ndesConnectors", nil)
	if err != nil {
		return nil, nil, err
	}

	byState := map[string]int{}
	var maxAge float64
	haveAge := false
	for _, r := range raw {
		var conn ndesConnector
		if err := json.Unmarshal(r, &conn); err != nil {
			c.logger.Warn("connectors: skipping unparseable ndes connector", "collector", collectorName, "error", err)
			continue
		}
		byState[orUnknown(conn.State)]++
		if !conn.LastConnectionDateTime.IsZero() {
			if age := now.Sub(conn.LastConnectionDateTime).Seconds(); !haveAge || age > maxAge {
				maxAge, haveAge = age, true
			}
		}
	}

	points := make([]telemetry.GaugePoint, 0, len(byState))
	for state, n := range byState {
		points = append(points, telemetry.GaugePoint{
			Value: float64(n),
			Attrs: telemetry.Attrs{"connector_type": connectorTypeNDES, "state": state},
		})
	}
	return points, agePointOrNil(connectorTypeNDES, maxAge, haveAge), nil
}

// bumpPlatform increments the enabled or disabled counter for platform
// depending on on.
func bumpPlatform(enabled, disabled map[string]int, platform string, on bool) {
	if on {
		enabled[platform]++
	} else {
		disabled[platform]++
	}
}

// agePointOrNil builds the heartbeat-age gauge point for a connector type, or
// nil if no instance yielded a usable age (no instances, or every instance
// had a zero-value timestamp).
func agePointOrNil(connectorType string, age float64, have bool) *telemetry.GaugePoint {
	if !have {
		return nil
	}
	return &telemetry.GaugePoint{Value: age, Attrs: telemetry.Attrs{"connector_type": connectorType}}
}

// isUnavailable reports whether err reflects the connector type simply not
// being provisioned/licensed on this tenant, rather than a real failure: 403
// (forbidden/unlicensed), 404 (not found), or 501 (NotSupported — verified
// live: GET /deviceManagement/exchangeConnectors returns 501 on a tenant with
// no Exchange connector configured, not an empty list). Applied to all three
// connector fetches so a tenant simply missing a connector type degrades to
// "no points for that type" instead of "collector failed" on every scrape.
// Mirrors entra/recommendations' isUnavailable, the precedent for a beta
// collector degrading cleanly.
func isUnavailable(err error) bool {
	s := err.Error()
	return strings.Contains(s, "status 403") || strings.Contains(s, "status 404") || strings.Contains(s, "status 501")
}

// orUnknown maps an empty enum string to "unknown" so a missing/nullable
// state field still yields a bounded, present bucket rather than a silently
// dropped connector instance.
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

// Compile-time interface assertions.
var _ collector.SnapshotCollector = (*Collector)(nil)
