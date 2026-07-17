// Package securescore is the Entra Microsoft Secure Score collector: the
// tenant's latest daily posture score (current/max/percentage) plus the
// bounded control-profile catalog counted by control category and by the
// tenant's stated implementation status for each control. It never emits a
// per-control gauge — the control catalog is a few dozen entries today but is
// not a Microsoft-documented bounded contract, so this collector aggregates
// it into the genuinely bounded dimensions (category, status) instead of
// risking an unbounded per-control-name series set.
package securescore

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
	"github.com/rknightion/graph2otel/internal/semconv"
	"github.com/rknightion/graph2otel/internal/telemetry"
)

// collectorName is the stable key used for config (enable/interval),
// self-observability, and the admin status page.
const collectorName = "entra.secure_score"

// Metric names emitted by this collector.
const (
	metricCurrent    = "entra.secure_score.current"
	metricMax        = "entra.secure_score.max"
	metricPercentage = "entra.secure_score.percentage"
	metricByCategory = "entra.secure_score.control_profiles.by_category"
	metricByStatus   = "entra.secure_score.control_profiles.by_status"
)

// defaultBaseURL is the Graph v1.0 root.
const defaultBaseURL = "https://graph.microsoft.com/v1.0"

// Collector polls the latest Microsoft Secure Score and the control-profile
// catalog.
type Collector struct {
	g       collectors.GraphClient
	baseURL string
	logger  *slog.Logger
}

// New builds the secure-score collector. A nil logger falls back to the slog
// default.
func New(g collectors.GraphClient, logger *slog.Logger) *Collector {
	if logger == nil {
		logger = slog.Default()
	}
	return &Collector{g: g, baseURL: defaultBaseURL, logger: logger}
}

// Name implements collector.Collector.
func (c *Collector) Name() string { return collectorName }

// DefaultInterval implements collector.Collector. Microsoft publishes at most
// one new secure score per day and the control-profile catalog barely
// changes; an hourly poll is ample and trivially cheap on the security
// workload's throttle budget.
func (c *Collector) DefaultInterval() time.Duration { return time.Hour }

// RequiredPermissions declares the least-privilege Graph scope both endpoints
// share.
func (c *Collector) RequiredPermissions() []string { return []string{"SecurityEvents.Read.All"} }

// Collect fetches the latest secure score and the control-profile catalog
// independently: a failure in one is logged and surfaced as a non-fatal
// aggregated error, but does not prevent the other from emitting.
func (c *Collector) Collect(ctx context.Context, e telemetry.Emitter) error {
	var errs []error

	if err := c.collectScore(ctx, e); err != nil {
		c.logger.Warn("secure score fetch failed", "collector", collectorName, "error", err)
		errs = append(errs, fmt.Errorf("secure score: %w", err))
	}

	if err := c.collectControlProfiles(ctx, e); err != nil {
		c.logger.Warn("secure score control profiles fetch failed", "collector", collectorName, "error", err)
		errs = append(errs, fmt.Errorf("control profiles: %w", err))
	}

	return errors.Join(errs...)
}

// secureScoresResponse is the minimal shape of a GET /security/secureScores
// response this collector needs.
type secureScoresResponse struct {
	Value []secureScore `json:"value"`
}

type secureScore struct {
	CurrentScore float64 `json:"currentScore"`
	MaxScore     float64 `json:"maxScore"`
}

// collectScore fetches the single latest daily secure score ($top=1 asks
// Graph for exactly that) and emits current/max/percentage gauges. It
// deliberately reads only value[0] even if the response somehow carries more
// than one entry, so a full retained series is never mistaken for "latest".
func (c *Collector) collectScore(ctx context.Context, e telemetry.Emitter) error {
	body, err := c.g.RawGet(ctx, c.baseURL+"/security/secureScores?$top=1")
	if err != nil {
		return err
	}
	var resp secureScoresResponse
	if err := json.Unmarshal(body, &resp); err != nil {
		return fmt.Errorf("decode secureScores response: %w", err)
	}
	if len(resp.Value) == 0 {
		// No score has been published for this tenant yet; nothing to emit.
		return nil
	}
	latest := resp.Value[0]

	e.Gauge(metricCurrent, "{score}", "Latest Microsoft Secure Score for the tenant.", latest.CurrentScore, nil)
	e.Gauge(metricMax, "{score}", "Maximum attainable Microsoft Secure Score for the tenant.", latest.MaxScore, nil)
	if latest.MaxScore > 0 {
		pct := latest.CurrentScore / latest.MaxScore * 100
		e.Gauge(metricPercentage, "%", "Latest Secure Score expressed as a percentage of the maximum attainable score.", pct, nil)
	}
	return nil
}

// controlProfile is the subset of secureScoreControlProfile fields this
// collector aggregates.
type controlProfile struct {
	ControlCategory     string               `json:"controlCategory"`
	ControlStateUpdates []controlStateUpdate `json:"controlStateUpdates"`
}

type controlStateUpdate struct {
	State           string    `json:"state"`
	UpdatedDateTime time.Time `json:"updatedDateTime"`
}

// collectControlProfiles fetches the full control-profile catalog (a small,
// bounded collection — GetAllValues is safe here) and emits two GaugeSnapshot
// series sets: counts by control category and counts by the tenant's stated
// implementation status for each control. It never emits a per-control gauge.
func (c *Collector) collectControlProfiles(ctx context.Context, e telemetry.Emitter) error {
	raws, err := collectors.GetAllValues(ctx, c.g, c.baseURL+"/security/secureScoreControlProfiles", nil)
	if err != nil {
		return err
	}

	byCategory := map[string]int64{}
	byStatus := map[string]int64{}
	for _, raw := range raws {
		var p controlProfile
		if err := json.Unmarshal(raw, &p); err != nil {
			return fmt.Errorf("decode secureScoreControlProfile: %w", err)
		}
		byCategory[normalizeCategory(p.ControlCategory)]++
		byStatus[normalizeStatus(latestState(p.ControlStateUpdates))]++
	}

	catPoints := make([]telemetry.GaugePoint, 0, len(byCategory))
	for cat, n := range byCategory {
		catPoints = append(catPoints, telemetry.GaugePoint{
			Value: float64(n),
			Attrs: telemetry.Attrs{semconv.AttrCategory: cat},
		})
	}
	e.GaugeSnapshot(metricByCategory, "{control}", "Secure Score control profiles, by control category.", catPoints)

	statusPoints := make([]telemetry.GaugePoint, 0, len(byStatus))
	for st, n := range byStatus {
		statusPoints = append(statusPoints, telemetry.GaugePoint{
			Value: float64(n),
			Attrs: telemetry.Attrs{semconv.AttrStatus: st},
		})
	}
	e.GaugeSnapshot(metricByStatus, "{control}", "Secure Score control profiles, by tenant implementation status.", statusPoints)

	return nil
}

// latestState returns the most recently updated state in a control's history,
// or "" (which normalizeStatus maps to "default") when the tenant has never
// updated the control's state.
func latestState(updates []controlStateUpdate) string {
	if len(updates) == 0 {
		return ""
	}
	latest := updates[0]
	for _, u := range updates[1:] {
		if u.UpdatedDateTime.After(latest.UpdatedDateTime) {
			latest = u
		}
	}
	return latest.State
}

// normalizeCategory maps a controlCategory value to graph2otel's bounded
// category set (Identity, Data, Device, Apps, Infrastructure per Microsoft's
// docs). Any value outside that documented set — a future Microsoft addition,
// or bad data — collapses into "unknown" rather than becoming a fresh,
// unbounded label.
func normalizeCategory(raw string) string {
	switch strings.ToLower(raw) {
	case "identity":
		return "identity"
	case "data":
		return "data"
	case "device":
		return "device"
	case "apps":
		return "apps"
	case "infrastructure":
		return "infrastructure"
	default:
		return "unknown"
	}
}

// normalizeStatus maps a control's latest controlStateUpdates.state to
// graph2otel's bounded status set (Default, Ignored, ThirdParty, Reviewed per
// Microsoft's docs). Any value outside that documented set collapses into
// "unknown" rather than becoming a fresh, unbounded label.
func normalizeStatus(raw string) string {
	switch strings.ToLower(raw) {
	case "", "default":
		return "default"
	case "ignored":
		return "ignored"
	case "thirdparty":
		return "third_party"
	case "reviewed":
		return "reviewed"
	default:
		return "unknown"
	}
}

func init() {
	collectors.Register(func(d collectors.Deps) collector.SnapshotCollector {
		return New(d.Graph, d.Logger)
	})
}
