// Package collaborationactivity reports daily per-workload collaboration
// posture and adoption from Graph usage reports (#362): is anyone actually
// using Teams/SharePoint/OneDrive, and who has gone quiet. Where the existing
// audit feeds (m365.activity, unifiedaudit, ...) give EVENTS, this collector
// gives daily per-user SUMMARIES — the getTeamsUserActivityUserDetail,
// getSharePointActivityUserDetail and getOneDriveActivityUserDetail usage
// reports, each returning one row per licensed user for the trailing 7-day
// window (period='D7').
//
// It shares the M365 usage-reporting transport internal/collectors/m365/
// storage and internal/collectors/m365/mailboxusage already hardened: RawGet
// follows the report's 302 redirect to a CSV, reachable app-only under the
// already-held Reports.Read.All. There is no genuinely shared CSV-parsing
// package to import — storage.go and mailboxusage.go each own a copy of
// parseCSV (see that comment in mailboxusage.go) — so this package follows the
// same one-file-one-owner precedent and owns its own copy too. Both existing
// copies already strip a leading UTF-8 BOM before parsing headers; this
// package's parseCSV does the same, because the live captures (2026-07-28,
// m7kni, #362) begin with one (`\xEF\xBB\xBF`) that would otherwise corrupt
// the first header cell ("Report Refresh Date" becomes a BOM-prefixed
// variant of it) and silently break every row["Report Refresh Date"] lookup.
//
// Three reports are fetched independently and DEGRADE independently — a
// SharePoint fetch failure must not lose Teams or OneDrive, mirroring
// storage.go's per-report best-effort handling. Only ALL THREE reports
// failing is a collector failure (the #240 "100% success on zero data" trap);
// a single report failing is non-fatal, and a report that succeeds with zero
// rows (a legitimately empty tenant/window) is a success, not a failure.
//
// Cardinality (#112): per-user identity (User Principal Name, and Teams' User
// Id) rides the log twin (m365.collaboration_activity_user) only, never a
// metric label. Metrics carry bounded aggregates:
//   - m365.collaboration_activity.users{workload, activity_state} — a user
//     count per (workload, derived state) bucket; cardinality is exactly 9
//     (3 workloads x 3 states) when all three reports succeed, fewer when one
//     degrades. activity_state is derived HERE (active/inactive/never_active
//     from Last Activity Date vs. the report's own refresh date and period),
//     never restated from a Graph-supplied enum, so there is nothing for
//     internal/wirecheck to watch (see below).
//   - m365.collaboration_activity.actions{workload, action} — the SUM across
//     users of each workload's fixed action-count columns. The action set is
//     bounded by this package's own column list, not by user count: teams =
//     team_chat_messages/private_chat_messages/calls/meetings_organized/
//     meetings_attended; sharepoint = files_viewed_or_edited/files_synced/
//     files_shared_internally/files_shared_externally/pages_visited; onedrive
//     = the same four SharePoint file actions (OneDrive's report has no page
//     views).
//   - m365.collaboration_activity.users.deleted{workload} — count of rows
//     with Is Deleted = true, per workload.
//   - m365.collaboration_activity.shared_externally{workload} — the summed
//     Shared Externally File Count as its OWN series (not folded into the
//     actions gauge), because external sharing is the alertable signal an
//     operator wants without a `sum by` over every action. Teams' report has
//     no external-sharing column, so Teams never contributes a point here.
//
// Not Experimental (#183): these are GA v1.0 usage-report endpoints, not a
// beta Graph surface. Not HighVolume (#254): row count is one per licensed
// user, which scales with TENANT SIZE, not traffic — the opposite of what
// HighVolume means.
//
// internal/wirecheck: this collector declares NOTHING. Every metric label
// value (workload, activity_state, action) is derived by the collector itself
// from its own fixed column/workload list, never restated from a
// Graph-supplied value set — there is no enum here for Microsoft to extend out
// from under a mapping. internal/collectors/m365/storage and mailboxusage
// establish the same "declare nothing" precedent for the same reason.
//
// Report concealment (Reports.DisplayConcealedNames): NOT observed live on
// this tenant as of 2026-07-28 — every captured row carried a real UPN. The
// mapper is written defensively to survive it anyway: User Principal Name is
// never validated as an email shape and is never used to decide whether to
// emit a row, so a tenant with concealed names (an opaque-but-stable string in
// that column) still gets a twin and still counts toward every aggregate.
// Unblock: someone enables displayConcealedNames on a reachable tenant so the
// behavior can be measured directly, per this repo's wire-over-docs rule.
//
// Assigned Products ships VERBATIM as one string, never split. The live
// value contains an inner " + " as part of a single license SKU name
// ("ENTERPRISE MOBILITY + SECURITY E5"), so a naive split on "+" produces
// fragments that are not products — publishing "ENTERPRISE MOBILITY " next to
// "SECURITY E5" as if they were two licenses would be a fabricated catalog,
// worse than an unparsed string.
//
// Non-goal: this collector reports the daily AGGREGATE a usage report gives
// it. It never infers an individual file-open or chat-message EVENT from
// those aggregate counts — that would be synthesizing data the report does
// not carry.
package collaborationactivity

import (
	"bytes"
	"context"
	"encoding/csv"
	"errors"
	"fmt"
	"log/slog"
	"strconv"
	"strings"
	"time"

	"github.com/rknightion/graph2otel/internal/collector"
	"github.com/rknightion/graph2otel/internal/collectors"
	"github.com/rknightion/graph2otel/internal/recordoutcome"
	"github.com/rknightion/graph2otel/internal/semconv"
	"github.com/rknightion/graph2otel/internal/telemetry"
)

const (
	collectorName  = "m365.collaboration_activity"
	eventName      = "m365.collaboration_activity_user"
	defaultBaseURL = "https://graph.microsoft.com/v1.0"

	metricUsers            = "m365.collaboration_activity.users"
	metricActions          = "m365.collaboration_activity.actions"
	metricDeleted          = "m365.collaboration_activity.users.deleted"
	metricSharedExternally = "m365.collaboration_activity.shared_externally"

	workloadTeams      = "teams"
	workloadSharePoint = "sharepoint"
	workloadOneDrive   = "onedrive"

	// Derived activity-state vocabulary (#112: this is OUR bucketing, not a
	// Graph-supplied enum, so it is not a internal/wirecheck candidate).
	stateActive      = "active"
	stateInactive    = "inactive"
	stateNeverActive = "never_active"

	// defaultReportPeriodDays backstops a missing/unparseable Report Period
	// cell. Every report requested here is period='D7', so 7 is the value the
	// column itself always carries; this only guards against a malformed cell,
	// never overrides a real one.
	defaultReportPeriodDays = 7
)

// actionColumn binds one usage-report CSV column to the bounded metric-label
// value it sums into (action) and the twin attribute it also rides on
// unaggregated (attr).
type actionColumn struct {
	column string
	action string
	attr   string
}

// teamsActions is the fixed, bounded action set for the Teams report. Meeting
// Count (the combined organized+attended column) is deliberately NOT included
// here — Meetings Organized/Attended already cover that ground without a
// third, overlapping series.
var teamsActions = []actionColumn{
	{"Team Chat Message Count", "team_chat_messages", semconv.AttrTeamChatMessageCount},
	{"Private Chat Message Count", "private_chat_messages", semconv.AttrPrivateChatMessageCount},
	{"Call Count", "calls", semconv.AttrCallCount},
	{"Meetings Organized Count", "meetings_organized", semconv.AttrMeetingsOrganizedCount},
	{"Meetings Attended Count", "meetings_attended", semconv.AttrMeetingsAttendedCount},
}

// spActions is the fixed, bounded action set for the SharePoint report.
var spActions = []actionColumn{
	{"Viewed Or Edited File Count", "files_viewed_or_edited", semconv.AttrFilesViewedOrEditedCount},
	{"Synced File Count", "files_synced", semconv.AttrFilesSyncedCount},
	{"Shared Internally File Count", "files_shared_internally", semconv.AttrFilesSharedInternallyCount},
	{"Shared Externally File Count", "files_shared_externally", semconv.AttrFilesSharedExternallyCount},
	{"Visited Page Count", "pages_visited", semconv.AttrPagesVisitedCount},
}

// odActions is spActions minus Visited Page Count — OneDrive's report has no
// page-view column (live-measured 2026-07-28, #362).
var odActions = spActions[:4]

// sharedExternallyColumn is the CSV column both SharePoint and OneDrive carry;
// Teams has no external-sharing concept in this report.
const sharedExternallyColumn = "Shared Externally File Count"

// report identifies one usage-report OData function and how to map its rows.
type report struct {
	fn                    string
	workload              string
	actions               []actionColumn
	hasUserID             bool
	externalSharingColumn string // "" when the report carries no such column
}

var (
	teamsReport = report{
		fn:        "getTeamsUserActivityUserDetail(period='D7')",
		workload:  workloadTeams,
		actions:   teamsActions,
		hasUserID: true,
	}
	spReport = report{
		fn:                    "getSharePointActivityUserDetail(period='D7')",
		workload:              workloadSharePoint,
		actions:               spActions,
		externalSharingColumn: sharedExternallyColumn,
	}
	odReport = report{
		fn:                    "getOneDriveActivityUserDetail(period='D7')",
		workload:              workloadOneDrive,
		actions:               odActions,
		externalSharingColumn: sharedExternallyColumn,
	}
)

// reportCount is the number of usage reports Collect fetches; all of them
// failing is the #240-shaped total-failure condition storage.go established.
const reportCount = 3

var errReportDecode = errors.New("decode usage report")

// Collector polls the M365 collaboration-activity usage reports.
type Collector struct {
	g       collectors.GraphClient
	baseURL string
	logger  *slog.Logger
}

// New builds the collaboration-activity collector. A nil logger falls back to
// the slog default.
func New(g collectors.GraphClient, logger *slog.Logger) *Collector {
	if logger == nil {
		logger = slog.Default()
	}
	return &Collector{g: g, baseURL: defaultBaseURL, logger: logger}
}

// Name implements collector.Collector.
func (c *Collector) Name() string { return collectorName }

// DefaultInterval implements collector.Collector. The usage reports refresh at
// most daily (the live Report Refresh Date trails today by ~2 days), so a 6h
// poll is ample and keeps staleness bounded — matches storage.go/
// mailboxusage.go's interval for the same report family.
func (c *Collector) DefaultInterval() time.Duration { return 6 * time.Hour }

// RequiredPermissions declares the least-privilege Graph application scope.
// Reports.Read.All is already held for the other usage-report collectors and
// covers all three reports here; no write scope is needed.
func (c *Collector) RequiredPermissions() []string {
	return []string{"Reports.Read.All"}
}

// reportResult pairs a fetched report with its rows (nil when it failed).
type reportResult struct {
	rep  report
	rows []map[string]string
	err  error
}

// Collect fetches the three usage reports and emits bounded aggregates + one
// per-user log twin per row. Each report is independent and best-effort: only
// ALL THREE failing is a collector failure (#240-shaped).
func (c *Collector) Collect(ctx context.Context, e telemetry.Emitter, outcomes *recordoutcome.Recorder) error {
	results := []reportResult{
		{rep: teamsReport},
		{rep: spReport},
		{rep: odReport},
	}
	for i := range results {
		results[i].rows, results[i].err = c.fetch(ctx, results[i].rep)
	}

	var fetchErrs []error
	for _, r := range results {
		if r.err == nil {
			continue
		}
		fetchErrs = append(fetchErrs, fmt.Errorf("%s: %w", r.rep.fn, r.err))
		if errors.Is(r.err, errReportDecode) {
			outcomes.Cause(recordoutcome.CauseDecodeError)
		} else {
			outcomes.Cause(recordoutcome.CauseSourceError)
		}
	}

	var userPoints, actionPoints, deletedPoints, sharedPoints []telemetry.GaugePoint
	for _, r := range results {
		if r.err != nil {
			// A failed report contributes NOTHING to any grid — emitting
			// explicit zeros here would be the #240 fabrication this repo
			// forbids: "unavailable" and "measured zero" are different facts.
			continue
		}
		n := uint64(len(r.rows))
		outcomes.Add(recordoutcome.OutcomeFetched, n)
		outcomes.Add(recordoutcome.OutcomeMapped, n)
		outcomes.Add(recordoutcome.OutcomeEmitted, n)

		agg := c.processReport(e, r.rep, r.rows)

		for _, st := range []string{stateActive, stateInactive, stateNeverActive} {
			userPoints = append(userPoints, telemetry.GaugePoint{
				Value: agg.stateCounts[st],
				Attrs: telemetry.Attrs{semconv.AttrWorkload: r.rep.workload, semconv.AttrActivityState: st},
			})
		}
		for _, ac := range r.rep.actions {
			actionPoints = append(actionPoints, telemetry.GaugePoint{
				Value: agg.actionSums[ac.action],
				Attrs: telemetry.Attrs{semconv.AttrWorkload: r.rep.workload, semconv.AttrAction: ac.action},
			})
		}
		deletedPoints = append(deletedPoints, telemetry.GaugePoint{
			Value: agg.deletedCount,
			Attrs: telemetry.Attrs{semconv.AttrWorkload: r.rep.workload},
		})
		if r.rep.externalSharingColumn != "" {
			sharedPoints = append(sharedPoints, telemetry.GaugePoint{
				Value: agg.sharedExternally,
				Attrs: telemetry.Attrs{semconv.AttrWorkload: r.rep.workload},
			})
		}
	}

	if len(userPoints) > 0 {
		e.GaugeSnapshot(metricUsers, "{user}",
			"Count of licensed users per (workload, derived activity_state) bucket: active (activity within the report window), inactive (activity outside it), never_active (no Last Activity Date on record).",
			userPoints)
	}
	if len(actionPoints) > 0 {
		e.GaugeSnapshot(metricActions, "{action}",
			"Sum, across all users, of each workload's collaboration action counts for the report period.",
			actionPoints)
	}
	if len(deletedPoints) > 0 {
		e.GaugeSnapshot(metricDeleted, "{user}",
			"Count of users marked deleted in the workload's usage report.",
			deletedPoints)
	}
	if len(sharedPoints) > 0 {
		e.GaugeSnapshot(metricSharedExternally, "{file}",
			"Sum, across all users, of files shared externally — the alertable external-sharing signal, as its own series so it needs no aggregation over the actions gauge.",
			sharedPoints)
	}

	// #240-shaped: every report failing is a fabricated "nobody is using
	// anything" grid unless surfaced explicitly as a collector failure. A
	// partial failure (1 or 2 of 3) stays best-effort/non-fatal.
	if len(fetchErrs) == reportCount {
		return fmt.Errorf("m365.collaboration_activity: all usage reports failed: %w", errors.Join(fetchErrs...))
	}
	return nil
}

// reportAggregate accumulates one report's per-user rows into the bounded
// values Collect turns into gauge points.
type reportAggregate struct {
	stateCounts      map[string]float64
	actionSums       map[string]float64
	deletedCount     float64
	sharedExternally float64
}

// processReport emits one log twin per row and accumulates the bounded
// aggregates for rep's workload. It is the per-report half of Collect, split
// out so each report's zero-filled bucket set is seeded independently of
// whether any rows exist.
func (c *Collector) processReport(e telemetry.Emitter, rep report, rows []map[string]string) reportAggregate {
	agg := reportAggregate{
		stateCounts: map[string]float64{stateActive: 0, stateInactive: 0, stateNeverActive: 0},
		actionSums:  map[string]float64{},
	}
	for _, ac := range rep.actions {
		agg.actionSums[ac.action] = 0
	}

	for _, row := range rows {
		state := activityState(row["Last Activity Date"], row["Report Refresh Date"], row["Report Period"])
		agg.stateCounts[state]++

		for _, ac := range rep.actions {
			agg.actionSums[ac.action] += parseOptionalNum(row[ac.column]).orZero()
		}
		if strings.EqualFold(row["Is Deleted"], "true") {
			agg.deletedCount++
		}
		if rep.externalSharingColumn != "" {
			agg.sharedExternally += parseOptionalNum(row[rep.externalSharingColumn]).orZero()
		}

		c.emitTwin(e, rep, row)
	}
	return agg
}

// activityState derives the bounded active/inactive/never_active bucket from
// a row's Last Activity Date, the report's own Report Refresh Date, and its
// Report Period (in days). An empty Last Activity Date means the user has
// never been active — that is an absence of fact, never coerced to a zero/
// epoch date. Unparseable dates fall back to inactive rather than fabricating
// "active": asserting recent activity from data that could not be read would
// be a false-healthy signal, exactly the class of bug #240 exists to prevent.
func activityState(lastActivityDate, reportRefreshDate, reportPeriod string) string {
	if lastActivityDate == "" {
		return stateNeverActive
	}
	last, errLast := time.Parse("2006-01-02", lastActivityDate)
	refresh, errRefresh := time.Parse("2006-01-02", reportRefreshDate)
	if errLast != nil || errRefresh != nil {
		return stateInactive
	}

	period := defaultReportPeriodDays
	if p, err := strconv.Atoi(strings.TrimSpace(reportPeriod)); err == nil && p > 0 {
		period = p
	}

	diffDays := refresh.Sub(last).Hours() / 24
	if diffDays < 0 {
		diffDays = 0
	}
	if diffDays <= float64(period) {
		return stateActive
	}
	return stateInactive
}

// emitTwin emits one m365.collaboration_activity_user log for a detail row.
// User Principal Name is passed through verbatim and is NEVER validated as an
// email shape — under report concealment it is a stable-but-opaque token, and
// this mapper must not drop or reshape it (see package doc).
func (c *Collector) emitTwin(e telemetry.Emitter, rep report, row map[string]string) {
	attrs := telemetry.Attrs{semconv.AttrWorkload: rep.workload}
	telemetry.SetStr(attrs, semconv.AttrUserPrincipalName, row["User Principal Name"])
	if rep.hasUserID {
		telemetry.SetStr(attrs, semconv.AttrUserId, row["User Id"])
	}
	telemetry.SetStr(attrs, semconv.AttrReportRefreshDate, row["Report Refresh Date"])
	telemetry.SetStr(attrs, semconv.AttrReportPeriod, row["Report Period"])
	// An empty Last Activity Date is omitted (SetStr no-ops on ""), never
	// stamped as an epoch or empty-string value — absence is the fact.
	telemetry.SetStr(attrs, semconv.AttrLastActivityDate, row["Last Activity Date"])
	telemetry.SetBool(attrs, semconv.AttrIsDeleted, strings.EqualFold(row["Is Deleted"], "true"))
	telemetry.SetStr(attrs, semconv.AttrDeletedDate, row["Deleted Date"])
	// Verbatim, never split — see package doc's Assigned Products note.
	telemetry.SetStr(attrs, semconv.AttrAssignedProducts, row["Assigned Products"])

	for _, ac := range rep.actions {
		if n, ok := parseOptionalNum(row[ac.column]).get(); ok {
			attrs[ac.attr] = n
		}
	}
	if rep.externalSharingColumn != "" {
		if n, ok := parseOptionalNum(row[rep.externalSharingColumn]).get(); ok {
			attrs[semconv.AttrFilesSharedExternallyCount] = n
		}
	}

	e.LogEvent(telemetry.Event{
		Name:     eventName,
		Body:     fmt.Sprintf("%s collaboration activity: %s", rep.workload, row["User Principal Name"]),
		Severity: telemetry.SeverityInfo,
		Attrs:    attrs,
	})
}

// fetch GETs a report (RawGet follows the 302 to the CSV) and parses it.
// Copied-pattern from internal/collectors/m365/storage's fetch (unexported
// there; not edited per this package's one-file-one-owner rule) — behavior is
// intentionally identical.
func (c *Collector) fetch(ctx context.Context, r report) ([]map[string]string, error) {
	raw, err := c.g.RawGet(ctx, c.baseURL+"/reports/"+r.fn)
	if err != nil {
		c.logger.Warn("m365.collaboration_activity: report unavailable, skipping",
			"collector", collectorName, "report", r.fn, "error", err)
		return nil, err
	}
	rows, err := parseCSV(raw)
	if err != nil {
		c.logger.Warn("m365.collaboration_activity: report parse failed, skipping",
			"collector", collectorName, "report", r.fn, "error", err)
		return nil, fmt.Errorf("%w: %w", errReportDecode, err)
	}
	return rows, nil
}

// parseCSV parses a usage-report CSV into header-keyed rows. It strips a
// leading UTF-8 BOM (which would corrupt the first header) and runs the reader
// with LazyQuotes + a variable field count. Copied from
// internal/collectors/m365/storage's parseCSV (unexported there; not edited
// per this package's one-file-one-owner rule) — behavior is intentionally
// identical.
func parseCSV(data []byte) ([]map[string]string, error) {
	data = bytes.TrimPrefix(data, []byte{0xEF, 0xBB, 0xBF})
	if len(bytes.TrimSpace(data)) == 0 {
		return nil, nil
	}
	rd := csv.NewReader(bytes.NewReader(data))
	rd.LazyQuotes = true
	rd.FieldsPerRecord = -1
	records, err := rd.ReadAll()
	if err != nil {
		return nil, fmt.Errorf("parse csv: %w", err)
	}
	if len(records) < 1 {
		return nil, nil
	}
	header := records[0]
	rows := make([]map[string]string, 0, len(records)-1)
	for _, rec := range records[1:] {
		row := make(map[string]string, len(header))
		for i, h := range header {
			if i < len(rec) {
				row[h] = rec[i]
			}
		}
		rows = append(rows, row)
	}
	return rows, nil
}

// optionalNum is the result of parsing a possibly-blank numeric CSV cell. A
// blank cell (or one that fails to parse) is NOT a zero: ok is false and the
// caller must omit the attribute rather than fabricate a value. Copied from
// internal/collectors/m365/mailboxusage's optionalNum (unexported there; not
// edited per this package's one-file-one-owner rule).
type optionalNum struct {
	v  float64
	ok bool
}

func (n optionalNum) get() (float64, bool) { return n.v, n.ok }

// orZero collapses to 0 for callers that intentionally want a zero-filled
// aggregate (the bounded action-sum gauge) rather than an omitted attribute.
func (n optionalNum) orZero() float64 {
	if !n.ok {
		return 0
	}
	return n.v
}

// parseOptionalNum parses s as a float64. A blank string is never coerced to
// 0 — ok is false, distinct from a genuine 0 value on the wire.
func parseOptionalNum(s string) optionalNum {
	s = strings.TrimSpace(s)
	if s == "" {
		return optionalNum{}
	}
	f, err := strconv.ParseFloat(s, 64)
	if err != nil {
		return optionalNum{}
	}
	return optionalNum{v: f, ok: true}
}

func init() {
	collectors.Register(func(d collectors.Deps) collector.SnapshotCollector {
		return New(d.Graph, d.Logger)
	})
}

var _ collector.SnapshotCollector = (*Collector)(nil)
