package teamsusage

import (
	"strconv"
	"strings"
	"time"

	"github.com/rknightion/graph2otel/internal/recordoutcome"
	"github.com/rknightion/graph2otel/internal/semconv"
	"github.com/rknightion/graph2otel/internal/telemetry"
)

// The labels key on fixed CSV headers, not a wire enum. Windows Phone is
// outside the platform mix requested for this signal.
var platforms = []column{
	{"Used Web", "web"},
	{"Used Windows", "windows"},
	{"Used Mac", "mac"},
	{"Used iOS", "ios"},
	{"Used Android Phone", "android"},
	{"Used Linux", "linux"},
	{"Used  Chrome OS", "chrome_os"}, // Graph sends two spaces after Used.
}

var teamCounts = []column{
	{"Active Users", semconv.AttrActiveUsersCount},
	{"Active Channels", semconv.AttrActiveChannelsCount},
	{"Channel Messages", semconv.AttrChannelMessagesCount},
	{"Reactions", semconv.AttrReactionsCount},
	{"Meetings Organized", semconv.AttrMeetingsOrganizedCount},
	{"Post Messages", semconv.AttrPostMessagesCount},
	{"Reply Messages", semconv.AttrReplyMessagesCount},
	{"Urgent Messages", semconv.AttrUrgentMessagesCount},
	{"Mentions", semconv.AttrMentionsCount},
	{"Guests", semconv.AttrGuestsCount},
	{"Active Shared Channels", semconv.AttrActiveSharedChannelsCount},
	{"Active External Users", semconv.AttrActiveExternalUsersCount},
}

// UserCounts counts users who performed each activity, not the number of
// actions. Groups overlap and the wire supplies no distinct-user total.
var activities = []column{
	{"Team Chat Messages", "team_chat_messages"},
	{"Private Chat Messages", "private_chat_messages"},
	{"Calls", "calls"},
	{"Meetings", "meetings"},
	{"Other Actions", "other_actions"},
}

func emitPlatforms(e telemetry.Emitter, o *recordoutcome.Recorder, t table) {
	points := make([]telemetry.GaugePoint, 0, len(platforms))
	for _, platform := range platforms {
		users, known := 0, true
		for _, row := range t.rows {
			switch strings.ToLower(strings.TrimSpace(t.cell(row, platform.header))) {
			case "yes":
				users++
			case "no":
			default:
				known = false
			}
			if !known {
				break
			}
		}
		if !known {
			// An unknown flag would make the tenant count a lower bound.
			o.Cause(recordoutcome.CauseMappingError)
			continue
		}
		points = append(points, telemetry.GaugePoint{Value: float64(users), Attrs: telemetry.Attrs{semconv.AttrPlatform: platform.key}})
	}
	e.GaugeSnapshot(metricPlatform, unitUserCohort, platformDesc, points)
	if len(points) == 0 {
		o.Add(recordoutcome.OutcomeErrored, uint64(len(t.rows)))
	} else {
		emitted(o, uint64(len(t.rows)))
	}
}

func emitTeams(e telemetry.Emitter, o *recordoutcome.Recorder, t table, concealed *bool) {
	for _, row := range t.rows {
		refresh := t.cell(row, "Report Refresh Date")
		date, err := time.Parse(time.DateOnly, refresh)
		if err != nil {
			o.Add(recordoutcome.OutcomeDropped, 1)
			o.Cause(recordoutcome.CauseMissingEventTime)
			continue
		}
		attrs := telemetry.Attrs{semconv.AttrReportRefreshDate: refresh}
		// Match the `id` attribute on the m365.team inventory twin. Empty or
		// concealed IDs are not replaced with an inferred join key.
		telemetry.SetStr(attrs, semconv.AttrId, t.cell(row, "Team Id"))
		telemetry.SetStr(attrs, semconv.AttrDisplayName, t.cell(row, "Team Name"))
		telemetry.SetStr(attrs, semconv.AttrTeamType, t.cell(row, "Team Type"))
		telemetry.SetStr(attrs, semconv.AttrLastActivityDate, t.cell(row, "Last Activity Date"))
		telemetry.SetStr(attrs, semconv.AttrReportPeriod, t.cell(row, "Report Period"))
		if v, err := strconv.ParseBool(t.cell(row, "Is Deleted")); err == nil {
			attrs[semconv.AttrIsDeleted] = v
		}
		if concealed != nil {
			attrs[semconv.AttrNamesConcealed] = *concealed
		}
		for _, count := range teamCounts {
			if v, ok := parseCount(t.cell(row, count.header)); ok {
				attrs[count.key] = v
			}
		}
		e.LogEvent(telemetry.Event{Name: eventTeamActivity, Body: "Teams activity summary", Timestamp: date, Attrs: attrs})
		emitted(o, 1)
	}
}

func emitActivity(e telemetry.Emitter, o *recordoutcome.Recorder, t table) {
	const reportDays = 30
	dates := make([]time.Time, len(t.rows))
	var latest time.Time
	for i, row := range t.rows {
		date, err := time.Parse(time.DateOnly, t.cell(row, "Report Date"))
		if err == nil {
			dates[i] = date
			if date.After(latest) {
				latest = date
			}
		}
	}
	var seen [reportDays]bool
	points := make([]telemetry.GaugePoint, 0, reportDays*len(activities))
	for i, row := range t.rows {
		if dates[i].IsZero() {
			o.Add(recordoutcome.OutcomeDropped, 1)
			o.Cause(recordoutcome.CauseMappingError)
			continue
		}
		age := int(latest.Sub(dates[i]).Hours() / 24)
		if age < 0 || age >= reportDays || seen[age] {
			o.Add(recordoutcome.OutcomeFiltered, 1)
			continue
		}
		before := len(points)
		for _, activity := range activities {
			if count, ok := parseCount(t.cell(row, activity.header)); ok {
				points = append(points, telemetry.GaugePoint{Value: float64(count), Attrs: telemetry.Attrs{
					semconv.AttrActivity: activity.key, semconv.AttrDaysAgo: age,
				}})
			}
		}
		if len(points) == before {
			o.Add(recordoutcome.OutcomeErrored, 1)
			o.Cause(recordoutcome.CauseMappingError)
		} else {
			seen[age] = true
			emitted(o, 1)
		}
	}
	e.GaugeSnapshot(metricActivity, unitUserCohort, activityDesc, points)
}

func parseCount(cell string) (int64, bool) {
	v, err := strconv.ParseInt(strings.TrimSpace(cell), 10, 64)
	return v, err == nil && v >= 0
}

func emitted(o *recordoutcome.Recorder, n uint64) {
	o.Add(recordoutcome.OutcomeMapped, n)
	o.Add(recordoutcome.OutcomeEmitted, n)
}
