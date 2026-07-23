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
//
// # Installed apps + channel census (#247)
//
// Two further signals ride the SAME per-team fan-out (no extra full sweep): for
// each team we also GET /beta/teams/{id}/installedApps?$expand=teamsApp and
// GET /beta/teams/{id}/channels. That takes the per-cycle cost from 1 GET/team
// (the summary) to 3 GETs/team, so a tenant of N teams costs 1 (list) + 3·N
// requests per cycle (was 1 + N). Both are paced through the same directory
// rate-limiter bucket, which is why the interval stays long.
//
//   - installedApps surfaces two blind spots: SIDELOADED apps
//     (distributionMethod=sideloaded, an app installed outside the tenant
//     catalog/store) and RSC — grantedResourceSpecificApplicationPermissions,
//     resource-specific consent granted PER TEAM (e.g. ChannelMessage.Read.Group).
//     RSC is invisible to entra.consent, which only sees tenant-wide app-role
//     consent — this is the whole point of the signal. The endpoint REJECTS the
//     $top query option ("Query option 'Top' is not allowed"), so it is paged by
//     the @odata.nextLink walk (GetAllValues), never $top (live-verified against
//     m7kni, 2026-07-23).
//   - channels is the per-team channel census: membershipType
//     (standard/private/shared) and archived state, plus per-channel detail
//     (email, files-folder URL) on the log twin.
//
// Beta, but NOT Experimental. installedApps' RSC field
// (grantedResourceSpecificApplicationPermissions) is beta-only, so both calls
// use the /beta base URL. The collector is deliberately NOT marked Experimental
// (that would hide the valuable v1.0 team inventory behind the beta opt-in, #183)
// — it issues beta GETs for these two sub-resources only. The beta surface still
// needs registering in spec/graph-beta-surface.json (the wiring pass owns that).
// channels' fields all exist in v1.0 too and could be moved there to shrink the
// beta footprint; it uses beta here only because the single live sample captured
// was beta (wire-over-docs).
//
// # What is unvalidated (n=1 on m7kni, 2026-07-23)
//
// The live samples this mapper was written against are thin: all 63 installed
// apps on the one probed team were distributionMethod=store with ZERO RSC grants,
// and the team had ONE channel, membershipType=standard. So the sideloaded and
// RSC-grant SHAPES are mapped from the fields but their DISTRIBUTION is
// unobservable here, and the private/shared channel membership types were never
// seen on the wire. The element type of grantedResourceSpecificApplication
// Permissions is decoded as []string (the documented shape) but is unvalidated —
// every observed array was empty. These are docs-only / n=1, not live-measured.
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
	// eventNameApp is the per-(team,installed-app) log twin EventName (#247).
	eventNameApp = "m365.teams_app"
	// eventNameChannel is the per-channel log twin EventName (#247).
	eventNameChannel = "m365.team_channel"
	// defaultBaseURL is the Graph v1.0 root.
	defaultBaseURL = "https://graph.microsoft.com/v1.0"
	// betaBaseURL is the Graph beta root, used ONLY for the installedApps + channels
	// sub-resource GETs (#247) — the RSC field is beta-only. The collector stays
	// non-Experimental; see the package doc.
	betaBaseURL = "https://graph.microsoft.com/beta"
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
	// metricInstalledApps counts installed apps by distribution_method ×
	// has_rsc_permissions (both closed sets — bounded). (#247)
	metricInstalledApps = "m365.teams.installed_apps.total"
	// metricChannels counts channels by membership_type × is_archived (both
	// closed sets — bounded). (#247)
	metricChannels = "m365.teams.channels.total"
)

// knownVisibilities is the closed set emitted as an explicit grid every cycle
// (0 when empty) so an alert baseline is stable rather than a series that blinks
// in and out. hiddenMembership is a real Teams visibility value.
var knownVisibilities = []string{"public", "private", "hiddenMembership"}

// membershipRoles is the closed grid for the membership-by-role metric.
var membershipRoles = []string{"owner", "member", "guest"}

// distributionMethods is the closed distributionMethod enum, seeded as an
// explicit grid so every bucket reports each cycle for a stable alert baseline.
var distributionMethods = []string{"store", "organization", "sideloaded"}

// rscStates is the closed has_rsc_permissions grid (a bool rendered as a string).
var rscStates = []string{"false", "true"}

// membershipTypes is the closed channel membershipType enum.
var membershipTypes = []string{"standard", "private", "shared"}

// archivedStates is the closed is_archived grid (a bool rendered as a string).
var archivedStates = []string{"false", "true"}

// Collector is the Teams inventory SnapshotCollector.
type Collector struct {
	g       collectors.GraphClient
	baseURL string
	betaURL string
	logger  *slog.Logger
}

// New builds the Teams collector. A nil logger falls back to slog.Default().
func New(g collectors.GraphClient, logger *slog.Logger) *Collector {
	if logger == nil {
		logger = slog.Default()
	}
	return &Collector{g: g, baseURL: defaultBaseURL, betaURL: betaBaseURL, logger: logger}
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
// so TeamSettings.Read.All is the workable app-only scope.
//
// TeamsAppInstallation.Read.All backs GET /teams/{id}/installedApps and
// Channel.ReadBasic.All backs GET /teams/{id}/channels (#247). Both are the
// documented app-only least-privilege scopes (docs-only — not yet live-verified
// against m7kni). A team-scoped GET that 403s because these are ungranted is
// skipped for the cycle, not fatal. See docs/permissions.md.
func (c *Collector) RequiredPermissions() []string {
	return []string{
		"Team.ReadBasic.All",
		"TeamSettings.Read.All",
		"TeamsAppInstallation.Read.All",
		"Channel.ReadBasic.All",
	}
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

// installedApp is one entry of GET /beta/teams/{id}/installedApps?$expand=teamsApp
// (#247). grantedResourceSpecificApplicationPermissions is decoded as []string —
// the documented RSC-grant value shape (e.g. ChannelMessage.Read.Group); every
// live sample was empty, so the element type is docs-only/unvalidated.
type installedApp struct {
	GrantedRSC []string `json:"grantedResourceSpecificApplicationPermissions"`
	ScopeInfo  struct {
		Scope string `json:"scope"`
	} `json:"scopeInfo"`
	TeamsApp struct {
		ID                 string `json:"id"`
		ExternalID         string `json:"externalId"`
		DisplayName        string `json:"displayName"`
		DistributionMethod string `json:"distributionMethod"`
	} `json:"teamsApp"`
}

// channel is one entry of GET /beta/teams/{id}/channels (#247). Every decoded
// field is present on the live m7kni sample (2026-07-23).
type channel struct {
	ID                string `json:"id"`
	DisplayName       string `json:"displayName"`
	Email             string `json:"email"`
	FilesFolderWebURL string `json:"filesFolderWebUrl"`
	MembershipType    string `json:"membershipType"`
	IsArchived        bool   `json:"isArchived"`
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

	// #247 grids, seeded to the full cross-product so every bucket reports each
	// cycle. appsForbidden / channelsForbidden latch on the first 403 so an
	// ungranted scope neither spams a log per team nor emits a misleading
	// all-zero grid (a skipped gauge != an observed zero).
	appsGrid := map[appKey]int64{}
	for _, dm := range distributionMethods {
		for _, rsc := range rscStates {
			appsGrid[appKey{dm, rsc}] = 0
		}
	}
	channelsGrid := map[chanKey]int64{}
	for _, mt := range membershipTypes {
		for _, arch := range archivedStates {
			channelsGrid[chanKey{mt, arch}] = 0
		}
	}
	var appsForbidden, channelsForbidden bool

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

		// #247: installed apps + channels ride this same per-team fan-out.
		c.collectInstalledApps(ctx, e, t, appsGrid, &appsForbidden)
		c.collectChannels(ctx, e, t, channelsGrid, &channelsForbidden)
	}

	emitVisibilityGauge(e, byVisibility)
	emitMembershipGauge(e, membership)
	e.Gauge(metricOwnerless, semconv.UnitDimensionless,
		"Teams with zero owners (excluding archived) — unmanageable orphans.", float64(ownerless), nil)
	e.Gauge(metricWithGuests, semconv.UnitDimensionless,
		"Teams with at least one external guest — a data-egress exposure surface.", float64(withGuests), nil)
	// Skip a gauge whose scope was never granted — a seeded all-zero grid would
	// falsely read as "no apps / no channels" rather than "not measured".
	if !appsForbidden {
		emitInstalledAppsGauge(e, appsGrid)
	}
	if !channelsForbidden {
		emitChannelsGauge(e, channelsGrid)
	}
	return nil
}

// appKey / chanKey are the bounded composite grid keys for the #247 metrics.
type appKey struct{ distribution, hasRSC string }
type chanKey struct{ membership, archived string }

// collectInstalledApps fetches one team's installed apps (beta, $expand=teamsApp),
// buckets each into the bounded grid, and emits one m365.teams_app twin per app.
// A 403 latches appsForbidden so the rest of the cycle skips the call; any other
// error skips this team's apps only.
func (c *Collector) collectInstalledApps(ctx context.Context, e telemetry.Emitter, t team, grid map[appKey]int64, forbidden *bool) {
	if *forbidden {
		return
	}
	// installedApps REJECTS $top — page via the nextLink walk, never $top.
	url := c.betaURL + "/teams/" + t.ID + "/installedApps?$expand=teamsApp"
	raws, err := collectors.GetAllValues(ctx, c.g, url, nil)
	if err != nil {
		if isForbidden(err) {
			*forbidden = true
			c.logger.Info("skipping installed-apps: TeamsAppInstallation.Read.All not granted", "collector", collectorName)
			return
		}
		c.logger.Warn("teams: installedApps fetch failed", "collector", collectorName, "team", t.ID, "error", err)
		return
	}
	for _, raw := range raws {
		var a installedApp
		if err := json.Unmarshal(raw, &a); err != nil {
			continue
		}
		hasRSC := len(a.GrantedRSC) > 0
		grid[appKey{a.TeamsApp.DistributionMethod, strconv.FormatBool(hasRSC)}]++
		e.LogEvent(appTwin(t, a, hasRSC))
	}
}

// collectChannels fetches one team's channels (beta), buckets each into the
// bounded grid, and emits one m365.team_channel twin per channel. Same 403
// latching / per-team skip discipline as collectInstalledApps.
func (c *Collector) collectChannels(ctx context.Context, e telemetry.Emitter, t team, grid map[chanKey]int64, forbidden *bool) {
	if *forbidden {
		return
	}
	url := c.betaURL + "/teams/" + t.ID + "/channels"
	raws, err := collectors.GetAllValues(ctx, c.g, url, nil)
	if err != nil {
		if isForbidden(err) {
			*forbidden = true
			c.logger.Info("skipping channels: Channel.ReadBasic.All not granted", "collector", collectorName)
			return
		}
		c.logger.Warn("teams: channels fetch failed", "collector", collectorName, "team", t.ID, "error", err)
		return
	}
	for _, raw := range raws {
		var ch channel
		if err := json.Unmarshal(raw, &ch); err != nil || ch.ID == "" {
			continue
		}
		grid[chanKey{ch.MembershipType, strconv.FormatBool(ch.IsArchived)}]++
		e.LogEvent(channelTwin(t, ch))
	}
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

// emitInstalledAppsGauge snapshots installed-app counts by distribution_method ×
// has_rsc_permissions — both closed, bounded sets (#247).
func emitInstalledAppsGauge(e telemetry.Emitter, grid map[appKey]int64) {
	points := make([]telemetry.GaugePoint, 0, len(grid))
	for k, n := range grid {
		points = append(points, telemetry.GaugePoint{
			Value: float64(n),
			Attrs: telemetry.Attrs{
				semconv.AttrDistributionMethod: k.distribution,
				semconv.AttrHasRscPermissions:  k.hasRSC,
			},
		})
	}
	e.GaugeSnapshot(metricInstalledApps, semconv.UnitDimensionless,
		"Teams installed apps by distribution method and whether they hold RSC grants.", points)
}

// emitChannelsGauge snapshots channel counts by membership_type × is_archived —
// both closed, bounded sets (#247).
func emitChannelsGauge(e telemetry.Emitter, grid map[chanKey]int64) {
	points := make([]telemetry.GaugePoint, 0, len(grid))
	for k, n := range grid {
		points = append(points, telemetry.GaugePoint{
			Value: float64(n),
			Attrs: telemetry.Attrs{
				semconv.AttrMembershipType: k.membership,
				semconv.AttrIsArchived:     k.archived,
			},
		})
	}
	e.GaugeSnapshot(metricChannels, semconv.UnitDimensionless,
		"Teams channels by membership type and archived state.", points)
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

// appTwin renders one installed app as its per-entity log event (#247). The RSC
// grant list and the app/team identity are per-entity → log twin only. Warn is
// the actionable signal: a SIDELOADED app (installed outside the tenant
// catalog/store) OR any non-empty RSC grant (a per-team consent entra.consent
// cannot see).
func appTwin(t team, a installedApp, hasRSC bool) telemetry.Event {
	attrs := telemetry.Attrs{}
	telemetry.SetStr(attrs, semconv.AttrTeamId, t.ID)
	telemetry.SetStr(attrs, semconv.AttrTeamDisplayName, t.DisplayName)
	telemetry.SetStr(attrs, semconv.AttrAppId, a.TeamsApp.ID)
	telemetry.SetStr(attrs, semconv.AttrExternalId, a.TeamsApp.ExternalID)
	telemetry.SetStr(attrs, semconv.AttrAppDisplayName, a.TeamsApp.DisplayName)
	telemetry.SetStr(attrs, semconv.AttrDistributionMethod, a.TeamsApp.DistributionMethod)
	telemetry.SetStr(attrs, semconv.AttrScope, a.ScopeInfo.Scope)
	telemetry.SetBool(attrs, semconv.AttrHasRscPermissions, hasRSC)
	telemetry.SetStrs(attrs, semconv.AttrRscPermissions, a.GrantedRSC)

	sev := telemetry.SeverityInfo
	body := fmt.Sprintf("app %s in team %s: distribution=%s rsc=%v",
		a.TeamsApp.DisplayName, t.DisplayName, a.TeamsApp.DistributionMethod, a.GrantedRSC)
	if a.TeamsApp.DistributionMethod == "sideloaded" || hasRSC {
		sev = telemetry.SeverityWarn
		body = "REVIEW " + body
	}
	return telemetry.Event{Name: eventNameApp, Body: body, Severity: sev, Attrs: attrs}
}

// channelTwin renders one channel as its per-entity log event (#247). email and
// filesFolderWebUrl are per-entity → log twin only, never a metric label.
func channelTwin(t team, ch channel) telemetry.Event {
	attrs := telemetry.Attrs{}
	telemetry.SetStr(attrs, semconv.AttrTeamId, t.ID)
	telemetry.SetStr(attrs, semconv.AttrTeamDisplayName, t.DisplayName)
	telemetry.SetStr(attrs, semconv.AttrId, ch.ID)
	telemetry.SetStr(attrs, semconv.AttrDisplayName, ch.DisplayName)
	telemetry.SetStr(attrs, semconv.AttrMembershipType, ch.MembershipType)
	telemetry.SetStr(attrs, semconv.AttrEmailAddress, ch.Email)
	telemetry.SetStr(attrs, semconv.AttrFilesFolderWebUrl, ch.FilesFolderWebURL)
	telemetry.SetBool(attrs, semconv.AttrIsArchived, ch.IsArchived)

	body := fmt.Sprintf("channel %s in team %s: membership=%s archived=%v",
		ch.DisplayName, t.DisplayName, ch.MembershipType, ch.IsArchived)
	return telemetry.Event{Name: eventNameChannel, Body: body, Severity: telemetry.SeverityInfo, Attrs: attrs}
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
