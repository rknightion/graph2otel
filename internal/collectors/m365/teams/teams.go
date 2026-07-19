// Package teams is the Microsoft Teams inventory collector (#121): a governance
// view over Teams, whose headline signals are OWNERLESS teams (zero owners = an
// unmanageable orphan holding files) and GUEST exposure (external guests = a
// data-egress surface). graph2otel's audit collectors see Teams activity;
// nothing saw the inventory until this.
//
// # Two-call shape, and the four-field trap
//
// GET /teams lists teams but populates ONLY id, displayName, description and
// visibility — summary and isArchived come back null on the list regardless of
// $select (a documented Graph limitation, live-verified 2026-07-19). So the
// membership counts and archived state need a per-team GET
// /teams/{id}?$select=summary,isArchived. That fan-out is one request per team,
// paced through the directory rate-limiter bucket (see graphclient workload
// classification) and kept cheap by a long default interval — Teams inventory
// is not a sub-hour signal.
//
// # Cardinality (CLAUDE.md): metrics carry aggregates, logs carry entities
//
// The metrics are bounded, tenant-shaped counts: teams by visibility, the
// ownerless and with-guests totals, and membership by role. A team id or name
// NEVER becomes a metric label. The per-team detail — id, name, the three
// counts — is the m365.team LOG twin, one per team, so "which teams are
// ownerless" is a free LogQL query over data already shipped (#112/#114).
//
// # Archived teams
//
// An archived team is the desired end-state of a wound-down team, not an orphan,
// so it is EXCLUDED from the ownerless count — but it still gets a log twin
// carrying is_archived=true, so it is never silently dropped.
package teams

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"strconv"
	"time"

	"strings"

	"github.com/rknightion/graph2otel/internal/collector"
	"github.com/rknightion/graph2otel/internal/collectors"
	"github.com/rknightion/graph2otel/internal/semconv"
	"github.com/rknightion/graph2otel/internal/telemetry"
)

const (
	// collectorName is the stable collector key / config key.
	collectorName = "m365.teams"
	// eventName is the per-team log twin's OTLP LogRecord EventName.
	eventName = "m365.team"
	// defaultBaseURL is the Graph v1.0 root.
	defaultBaseURL = "https://graph.microsoft.com/v1.0"
	// teamsListPath lists teams. Only id/displayName/description/visibility are
	// populated on the list (summary/isArchived are null — see the package doc),
	// so the $select is those four and the rest come from the per-team call.
	teamsListPath = "/teams?$select=id,displayName,description,visibility"
	// defaultInterval is long by design: Teams inventory is a slow-moving
	// governance signal, and a long interval is also how this collector stays
	// "opt-in-ish" — it bounds the per-team fan-out cost without a default-off
	// mechanism (Experimental is reserved for Graph beta surfaces, #183; /teams
	// is v1.0 stable).
	defaultInterval = 1 * time.Hour

	metricTotal      = "m365.teams.total"
	metricOwnerless  = "m365.teams.ownerless.total"
	metricWithGuests = "m365.teams.with_guests.total"
	metricMembership = "m365.teams.membership.total"
)

// knownVisibilities is the closed set emitted as an explicit grid every cycle
// (0 when empty) so an alert baseline is stable rather than a series that blinks
// in and out. hiddenMembership is a real Teams visibility value.
var knownVisibilities = []string{"public", "private", "hiddenMembership"}

// membershipRoles is the closed grid for the membership-by-role metric.
var membershipRoles = []string{"owner", "member", "guest"}

// Collector is the Teams inventory SnapshotCollector.
type Collector struct {
	g       collectors.GraphClient
	baseURL string
	logger  *slog.Logger
}

// New builds the Teams collector. A nil logger falls back to slog.Default().
func New(g collectors.GraphClient, logger *slog.Logger) *Collector {
	if logger == nil {
		logger = slog.Default()
	}
	return &Collector{g: g, baseURL: defaultBaseURL, logger: logger}
}

// Name implements collector.Collector.
func (c *Collector) Name() string { return collectorName }

// DefaultInterval implements collector.Collector.
func (c *Collector) DefaultInterval() time.Duration { return defaultInterval }

// RequiredPermissions declares the least-privilege application scopes.
//
// Team.ReadBasic.All backs GET /teams (the list); TeamSettings.Read.All backs
// GET /teams/{id}?$select=summary. The narrower documented least-privilege for
// the summary — TeamSettings.Read.Group — is RESOURCE-SPECIFIC CONSENT (granted
// per team via a Teams app manifest), which cannot serve a tenant-wide poller,
// so TeamSettings.Read.All is the workable app-only scope. See docs/permissions.md.
func (c *Collector) RequiredPermissions() []string {
	return []string{"Team.ReadBasic.All", "TeamSettings.Read.All"}
}

// team is the list-response shape (the four fields /teams actually populates).
type team struct {
	ID          string `json:"id"`
	DisplayName string `json:"displayName"`
	Description string `json:"description"`
	Visibility  string `json:"visibility"`
}

// teamDetail is the per-team response: summary counts + archived state.
type teamDetail struct {
	IsArchived bool `json:"isArchived"`
	Summary    struct {
		OwnersCount  int64 `json:"ownersCount"`
		MembersCount int64 `json:"membersCount"`
		GuestsCount  int64 `json:"guestsCount"`
	} `json:"summary"`
}

// Collect lists every team, fetches each team's summary, buckets the bounded
// gauges, and emits one log twin per team.
//
// A 403 on the list is treated as "scopes not granted": the collector logs and
// no-ops rather than erroring the whole scrape, exactly as entra/risk degrades
// when a capability is absent. That is the graceful path for a tenant that
// enabled the collector before granting Team.ReadBasic.All.
func (c *Collector) Collect(ctx context.Context, e telemetry.Emitter) error {
	raws, err := collectors.GetAllValues(ctx, c.g, c.baseURL+teamsListPath, nil)
	if err != nil {
		if isForbidden(err) {
			c.logger.Info("skipping teams inventory: Team.ReadBasic.All not granted", "collector", collectorName)
			return nil
		}
		return fmt.Errorf("teams: list: %w", err)
	}

	// Aggregates (bounded), seeded to the full grid so every bucket reports each
	// cycle.
	byVisibility := map[string]int64{}
	for _, v := range knownVisibilities {
		byVisibility[v] = 0
	}
	membership := map[string]int64{}
	for _, r := range membershipRoles {
		membership[r] = 0
	}
	var ownerless, withGuests int64

	for _, raw := range raws {
		var t team
		if err := json.Unmarshal(raw, &t); err != nil || t.ID == "" {
			continue
		}
		det, err := c.fetchDetail(ctx, t.ID)
		if err != nil {
			// One team's detail failing must not sink the whole inventory; log and
			// skip it (it is absent from the aggregates this cycle, which the
			// GaugeSnapshot semantics make self-healing next cycle).
			c.logger.Warn("teams: summary fetch failed", "collector", collectorName, "team", t.ID, "error", err)
			continue
		}

		// Visibility bucket (normalize an unexpected value into the grid rather
		// than minting a new label).
		if _, known := byVisibility[t.Visibility]; known {
			byVisibility[t.Visibility]++
		} else {
			byVisibility[t.Visibility] = byVisibility[t.Visibility] + 1
		}

		membership["owner"] += det.Summary.OwnersCount
		membership["member"] += det.Summary.MembersCount
		membership["guest"] += det.Summary.GuestsCount
		if det.Summary.GuestsCount > 0 {
			withGuests++
		}
		// Ownerless: zero owners AND not archived (an archived team is a desired
		// end-state, not an orphan).
		if det.Summary.OwnersCount == 0 && !det.IsArchived {
			ownerless++
		}

		e.LogEvent(logTwin(t, det))
	}

	emitVisibilityGauge(e, byVisibility)
	emitMembershipGauge(e, membership)
	e.Gauge(metricOwnerless, semconv.UnitDimensionless,
		"Teams with zero owners (excluding archived) — unmanageable orphans.", float64(ownerless), nil)
	e.Gauge(metricWithGuests, semconv.UnitDimensionless,
		"Teams with at least one external guest — a data-egress exposure surface.", float64(withGuests), nil)
	return nil
}

// fetchDetail gets one team's summary + archived state (the fields /teams omits).
func (c *Collector) fetchDetail(ctx context.Context, id string) (teamDetail, error) {
	url := c.baseURL + "/teams/" + id + "?$select=isArchived,summary"
	body, err := c.g.RawGet(ctx, url)
	if err != nil {
		return teamDetail{}, err //nolint:wrapcheck // the graphclient error is already specific
	}
	var det teamDetail
	if err := json.Unmarshal(body, &det); err != nil {
		return teamDetail{}, fmt.Errorf("decode team %s detail: %w", id, err)
	}
	return det, nil
}

// emitVisibilityGauge snapshots teams-by-visibility as an observable gauge (the
// bucket set is bounded and stable, but GaugeSnapshot keeps it consistent with
// the rest of the repo's per-attribute gauges and avoids a ghost if a visibility
// value ever disappears).
func emitVisibilityGauge(e telemetry.Emitter, byVisibility map[string]int64) {
	points := make([]telemetry.GaugePoint, 0, len(byVisibility))
	for v, n := range byVisibility {
		points = append(points, telemetry.GaugePoint{
			Value: float64(n),
			Attrs: telemetry.Attrs{semconv.AttrVisibility: v},
		})
	}
	e.GaugeSnapshot(metricTotal, semconv.UnitDimensionless,
		"Total Teams by visibility.", points)
}

// emitMembershipGauge snapshots tenant-wide membership counts by role.
func emitMembershipGauge(e telemetry.Emitter, membership map[string]int64) {
	points := make([]telemetry.GaugePoint, 0, len(membership))
	for role, n := range membership {
		points = append(points, telemetry.GaugePoint{
			Value: float64(n),
			Attrs: telemetry.Attrs{semconv.AttrRole: role},
		})
	}
	e.GaugeSnapshot(metricMembership, semconv.UnitDimensionless,
		"Tenant-wide Teams membership count by role.", points)
}

// logTwin renders one team as its per-entity log event. An ownerless team is
// Warn severity — the actionable signal — and every count is a string attribute
// (Loki structured metadata is string-valued; telemetrytest cannot render an
// int64 attr, so a numeric attr would read empty in a recorder assertion).
func logTwin(t team, det teamDetail) telemetry.Event {
	attrs := telemetry.Attrs{}
	telemetry.SetStr(attrs, semconv.AttrId, t.ID)
	telemetry.SetStr(attrs, semconv.AttrDisplayName, t.DisplayName)
	telemetry.SetStr(attrs, semconv.AttrDescription, t.Description)
	telemetry.SetStr(attrs, semconv.AttrVisibility, t.Visibility)
	attrs[semconv.AttrOwnersCount] = strconv.FormatInt(det.Summary.OwnersCount, 10)
	attrs[semconv.AttrMembersCount] = strconv.FormatInt(det.Summary.MembersCount, 10)
	attrs[semconv.AttrGuestsCount] = strconv.FormatInt(det.Summary.GuestsCount, 10)
	attrs[semconv.AttrIsArchived] = det.IsArchived

	sev := telemetry.SeverityInfo
	body := fmt.Sprintf("team %s: owners=%d members=%d guests=%d visibility=%s",
		t.DisplayName, det.Summary.OwnersCount, det.Summary.MembersCount, det.Summary.GuestsCount, t.Visibility)
	if det.Summary.OwnersCount == 0 && !det.IsArchived {
		sev = telemetry.SeverityWarn
		body = "OWNERLESS " + body
	}
	return telemetry.Event{Name: eventName, Body: body, Severity: sev, Attrs: attrs}
}

// isForbidden reports whether err is a Graph 403. The graphclient error carries
// the status in its message ("… status 403: …"), so this string-matches it, the
// same way entra/recommendations detects an unlicensed/unavailable endpoint.
func isForbidden(err error) bool {
	return err != nil && strings.Contains(err.Error(), "status 403")
}

func init() {
	collectors.Register(func(d collectors.Deps) collector.SnapshotCollector {
		return New(d.Graph, d.Logger)
	})
}

// Compile-time checks.
var (
	_ collector.SnapshotCollector = (*Collector)(nil)
	_ interface {
		RequiredPermissions() []string
	} = (*Collector)(nil)
)
