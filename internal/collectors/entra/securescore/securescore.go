// Package securescore is the Entra Microsoft Secure Score collector: the
// tenant's latest daily posture score (current/max/percentage), the per-control
// state and peer benchmarks the latest score carries, and the control-profile
// catalog.
//
// # Both sides of the cardinality boundary (#243, #114)
//
// The latest secureScore already carries a controlScores array (234 entries
// live) and averageComparativeScores; the control-profile catalog carries a
// per-control maximum. All of it was fetched every cycle and decoded by nothing
// — the collector could answer "what is my score" but never "which control is
// failing and what do I do about it". It now emits, from those same two fetches:
//
//   - bounded GAUGES: score summed by control category, the per-category maximum
//     from the catalog, and peer average by comparison basis — plus the original
//     profile counts by category and by implementation status;
//   - LOG TWINS: one entra.secure_score_control per control (its current state,
//     Warn below 100%) and one entra.secure_score_control_profile per catalog
//     entry (the worklist metadata — actionUrl, tier, threats).
//
// It still never emits a per-control-NAME metric label: per-control identity is
// log-only, because a series per control grows with the catalog and bills as
// active series. "Not a metric label" means "log twin", not "dropped" (#114).
//
// The two endpoints stay independent: a failure fetching one is surfaced as a
// non-fatal aggregated error and does not prevent the other from emitting, so
// the twins are deliberately NOT joined across endpoints.
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
	"github.com/rknightion/graph2otel/internal/wirecheck"
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

	// #243: the latest score already carries per-control state (controlScores)
	// and peer benchmarks (averageComparativeScores), and the profile catalog
	// carries a per-category maximum — all of it fetched every cycle and
	// previously discarded. These aggregate the newly-decoded data into bounded
	// dimensions (control category, comparison basis), never per control.
	metricScoreByCategory    = "entra.secure_score.by_category"
	metricMaxScoreByCategory = "entra.secure_score.max_by_category"
	metricPeerAverage        = "entra.secure_score.peer_average"
)

// The two log twins carrying the per-control detail the bounded gauges cannot
// (#243, #114). One record per control per cycle; volume is bounded by
// Microsoft's control catalog (~234 today), not tenant size.
const (
	eventControl        = "entra.secure_score_control"
	eventControlProfile = "entra.secure_score_control_profile"
)

// defaultBaseURL is the Graph v1.0 root.
const defaultBaseURL = "https://graph.microsoft.com/v1.0"

// Collector polls the latest Microsoft Secure Score and the control-profile
// catalog.
type Collector struct {
	g       collectors.GraphClient
	baseURL string
	logger  *slog.Logger
	watch   *wirecheck.Reporter
}

// The wire assumptions this collector watches at runtime (#233/#234).
//
// Both fields are METRIC LABELS and both normalizers below collapse an
// unrecognized member into "unknown" — a bucket nobody inspects. A category
// Microsoft adds moves the by-category score AND the maximum-attainable score
// it is compared against; a state Microsoft adds moves the by-status control
// count. Neither is visible without this.
//
// Each Enum is the set its normalizer NAMES: a value this collector explicitly
// handles is one it was built against, which is what makes the watchdog fire on
// a hole in the mapping rather than on correct data (the m365.message_trace
// precedent). Members are the LOWERCASED forms the switches match on, and the
// reported value is lowercased to match — the raw casing is not what the
// mapping keys on ("Identity" and "identity" are the same control category).
var (
	knownCategories = wirecheck.NewEnum("identity", "data", "device", "apps", "infrastructure")
	knownStates     = wirecheck.NewEnum("default", "ignored", "thirdparty", "reviewed")
)

// New builds the secure-score collector. A nil logger falls back to the slog
// default.
func New(g collectors.GraphClient, logger *slog.Logger) *Collector {
	if logger == nil {
		logger = slog.Default()
	}
	return &Collector{g: g, baseURL: defaultBaseURL, logger: logger, watch: wirecheck.New(collectorName, logger)}
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
	// ControlScores is the tenant's current per-control assessment (#243): 234
	// entries live, previously decoded by nothing. Aggregated into the bounded
	// by-category gauge and emitted per control as the eventControl twin.
	ControlScores []controlScore `json:"controlScores"`
	// AverageComparativeScores are Microsoft's peer benchmarks by basis
	// (AllTenants / seat band / industry) — the "how do we compare" number
	// (#243).
	AverageComparativeScores []comparativeScore `json:"averageComparativeScores"`
}

// controlScore is one entry of secureScore.controlScores: the tenant's current
// state for a single control. ScoreInPercentage is a POINTER so an absent field
// is distinguishable from a genuine 0% — only a present value below 100 escalates
// the twin to Warn; a control that simply omits the field stays Info (the
// risk.IsProcessing pattern). Count/Total arrive as strings on the wire.
type controlScore struct {
	ControlCategory      string   `json:"controlCategory"`
	ControlName          string   `json:"controlName"`
	Score                float64  `json:"score"`
	ScoreInPercentage    *float64 `json:"scoreInPercentage"`
	ImplementationStatus string   `json:"implementationStatus"`
	Count                string   `json:"count"`
	Total                string   `json:"total"`
	LastSynced           string   `json:"lastSynced"`
}

// comparativeScore is one entry of secureScore.averageComparativeScores: a peer
// benchmark for one basis. Basis is a small Microsoft-controlled enum
// (AllTenants, TotalSeats, IndustryTypes, …), so it is a safe bounded gauge
// label; #235's limiter backstops any future addition.
type comparativeScore struct {
	Basis        string  `json:"basis"`
	AverageScore float64 `json:"averageScore"`
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

	c.emitControlScores(e, latest.ControlScores)
	c.emitPeerAverages(e, latest.AverageComparativeScores)
	return nil
}

// emitControlScores emits BOTH sides of the cardinality boundary from the latest
// score's controlScores: the bounded per-category gauge (scores summed by
// control category), and one eventControl log twin per control carrying the
// per-control detail the gauge cannot (#243, #114). A control below 100%
// escalates its twin to Warn.
func (c *Collector) emitControlScores(e telemetry.Emitter, scores []controlScore) {
	byCategory := map[string]float64{}
	for _, cs := range scores {
		c.watch.Value(e, semconv.AttrCategory, strings.ToLower(cs.ControlCategory), knownCategories)
		byCategory[normalizeCategory(cs.ControlCategory)] += cs.Score
		e.LogEvent(controlTwin(cs))
	}
	if len(byCategory) == 0 {
		return
	}
	points := make([]telemetry.GaugePoint, 0, len(byCategory))
	for cat, sum := range byCategory {
		points = append(points, telemetry.GaugePoint{
			Value: sum,
			Attrs: telemetry.Attrs{semconv.AttrCategory: cat},
		})
	}
	e.GaugeSnapshot(metricScoreByCategory, "{score}", "Current Secure Score achieved, summed by control category.", points)
}

// controlTwin renders one controlScore as a log record. Per-control identity
// (control_name, implementation_status) is log-only — never a metric label. The
// timestamp is left zero (poll time): this is a state feed re-emitted every
// cycle, so stamping it with lastSynced would collapse repeats onto one instant.
func controlTwin(cs controlScore) telemetry.Event {
	attrs := telemetry.Attrs{}
	telemetry.SetStr(attrs, semconv.AttrControlName, cs.ControlName)
	telemetry.SetStr(attrs, semconv.AttrCategory, normalizeCategory(cs.ControlCategory))
	attrs[semconv.AttrScore] = cs.Score
	telemetry.SetStr(attrs, semconv.AttrImplementationStatus, cs.ImplementationStatus)
	telemetry.SetStr(attrs, semconv.AttrControlCount, cs.Count)
	telemetry.SetStr(attrs, semconv.AttrControlTotal, cs.Total)
	telemetry.SetStr(attrs, semconv.AttrLastSynced, cs.LastSynced)

	// scoreInPercentage present <100 is the actionable signal; absent (nil) is not
	// asserted either way — the twin stays Info and omits the attribute.
	sev := telemetry.SeverityInfo
	if cs.ScoreInPercentage != nil {
		attrs[semconv.AttrScoreInPercentage] = *cs.ScoreInPercentage
		if *cs.ScoreInPercentage < 100 {
			sev = telemetry.SeverityWarn
		}
	}

	name := cs.ControlName
	if name == "" {
		name = "unknown"
	}
	return telemetry.Event{
		Name:     eventControl,
		Body:     fmt.Sprintf("secure score control %s: category=%s score=%g", name, normalizeCategory(cs.ControlCategory), cs.Score),
		Severity: sev,
		Attrs:    attrs,
	}
}

// emitPeerAverages emits the peer-benchmark gauge from averageComparativeScores:
// averageScore keyed by basis. Basis is a bounded Microsoft enum (see
// comparativeScore).
func (c *Collector) emitPeerAverages(e telemetry.Emitter, cmps []comparativeScore) {
	points := make([]telemetry.GaugePoint, 0, len(cmps))
	for _, cmp := range cmps {
		if cmp.Basis == "" {
			continue
		}
		points = append(points, telemetry.GaugePoint{
			Value: cmp.AverageScore,
			Attrs: telemetry.Attrs{semconv.AttrScoreComparisonBasis: cmp.Basis},
		})
	}
	if len(points) == 0 {
		return
	}
	e.GaugeSnapshot(metricPeerAverage, "{score}", "Peer average Secure Score, by comparison basis.", points)
}

// controlProfile is the subset of secureScoreControlProfile fields this
// collector aggregates and twins. The catalog is bounded (a few hundred
// entries), so the per-profile eventControlProfile twin is safe (#243) — it
// carries the worklist metadata (actionUrl, tier, threats) the two count gauges
// collapse away.
type controlProfile struct {
	ID                  string               `json:"id"`
	ControlCategory     string               `json:"controlCategory"`
	ControlStateUpdates []controlStateUpdate `json:"controlStateUpdates"`
	MaxScore            float64              `json:"maxScore"`
	Tier                string               `json:"tier"`
	Rank                int                  `json:"rank"`
	Threats             []string             `json:"threats"`
	Service             string               `json:"service"`
	ActionType          string               `json:"actionType"`
	ActionURL           string               `json:"actionUrl"`
	Deprecated          bool                 `json:"deprecated"`
	ImplementationCost  string               `json:"implementationCost"`
	UserImpact          string               `json:"userImpact"`
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
	maxByCategory := map[string]float64{}
	for _, raw := range raws {
		var p controlProfile
		if err := json.Unmarshal(raw, &p); err != nil {
			return fmt.Errorf("decode secureScoreControlProfile: %w", err)
		}
		state := latestState(p.ControlStateUpdates)
		c.watch.Value(e, semconv.AttrCategory, strings.ToLower(p.ControlCategory), knownCategories)
		c.watch.Value(e, semconv.AttrStatus, strings.ToLower(state), knownStates)

		cat := normalizeCategory(p.ControlCategory)
		byCategory[cat]++
		byStatus[normalizeStatus(state)]++
		maxByCategory[cat] += p.MaxScore
		e.LogEvent(profileTwin(p))
	}

	catPoints := make([]telemetry.GaugePoint, 0, len(byCategory))
	for cat, n := range byCategory {
		catPoints = append(catPoints, telemetry.GaugePoint{
			Value: float64(n),
			Attrs: telemetry.Attrs{semconv.AttrCategory: cat},
		})
	}
	e.GaugeSnapshot(metricByCategory, "{control}", "Secure Score control profiles, by control category.", catPoints)

	maxPoints := make([]telemetry.GaugePoint, 0, len(maxByCategory))
	for cat, sum := range maxByCategory {
		maxPoints = append(maxPoints, telemetry.GaugePoint{
			Value: sum,
			Attrs: telemetry.Attrs{semconv.AttrCategory: cat},
		})
	}
	e.GaugeSnapshot(metricMaxScoreByCategory, "{score}", "Maximum attainable Secure Score, summed by control category.", maxPoints)

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

// profileTwin renders one secureScoreControlProfile as a log record: the
// bounded catalog metadata the two count gauges discard. Emitted at Info —
// deprecation is informational, not an alert. Category is normalized to match
// the gauge; the other fields carry the raw catalog values (tier, service,
// actionUrl) an operator reads as a remediation worklist.
func profileTwin(p controlProfile) telemetry.Event {
	attrs := telemetry.Attrs{}
	telemetry.SetStr(attrs, semconv.AttrId, p.ID)
	telemetry.SetStr(attrs, semconv.AttrCategory, normalizeCategory(p.ControlCategory))
	attrs[semconv.AttrMaxScore] = p.MaxScore
	attrs[semconv.AttrRank] = p.Rank
	telemetry.SetStr(attrs, semconv.AttrTier, p.Tier)
	telemetry.SetStrs(attrs, semconv.AttrThreats, p.Threats)
	telemetry.SetStr(attrs, semconv.AttrService, p.Service)
	telemetry.SetStr(attrs, semconv.AttrActionType, p.ActionType)
	telemetry.SetStr(attrs, semconv.AttrActionUrl, p.ActionURL)
	telemetry.SetBool(attrs, semconv.AttrDeprecated, p.Deprecated)
	telemetry.SetStr(attrs, semconv.AttrImplementationCost, p.ImplementationCost)
	telemetry.SetStr(attrs, semconv.AttrUserImpact, p.UserImpact)

	id := p.ID
	if id == "" {
		id = "unknown"
	}
	return telemetry.Event{
		Name:     eventControlProfile,
		Body:     fmt.Sprintf("secure score control profile %s: category=%s max_score=%g", id, normalizeCategory(p.ControlCategory), p.MaxScore),
		Severity: telemetry.SeverityInfo,
		Attrs:    attrs,
	}
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
