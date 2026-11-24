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
// part of the source row but outside the gauge's established platform mix.
var platforms = []struct{ header, label, attr string }{
	{"Used Web", "web", semconv.AttrUsedWeb},
	{"Used Windows", "windows", semconv.AttrUsedWindows},
	{"Used Mac", "mac", semconv.AttrUsedMac},
	{"Used iOS", "ios", semconv.AttrUsedIOS},
	{"Used Android Phone", "android", semconv.AttrUsedAndroidPhone},
	{"Used Linux", "linux", semconv.AttrUsedLinux},
	{"Used  Chrome OS", "chrome_os", semconv.AttrUsedChromeOS}, // Graph sends two spaces after Used.
	{"Used Windows Phone", "", semconv.AttrUsedWindowsPhone},
}

func requiredPlatformHeaders() []string {
	var headers []string
	for _, platform := range platforms {
		if platform.label != "" {
			headers = append(headers, platform.header)
		}
	}
	return headers
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

func emitDeviceUsage(e telemetry.Emitter, o *recordoutcome.Recorder, t table) {
	hasGauges := emitPlatformGauges(e, o, t)
	for _, row := range t.rows {
		refresh := t.cell(row, "Report Refresh Date")
		date, err := time.Parse(time.DateOnly, refresh)
		if err != nil || date.IsZero() {
			o.Cause(recordoutcome.CauseMissingEventTime)
			if hasGauges {
				// This row still contributes to every complete platform count.
				emitted(o, 1)
			} else {
				o.Add(recordoutcome.OutcomeDropped, 1)
			}
			continue
		}
		attrs := telemetry.Attrs{semconv.AttrReportRefreshDate: refresh}
		// Preserve the report's identifiers as supplied, even when concealed.
		telemetry.SetStr(attrs, semconv.AttrUserId, t.cell(row, "User Id"))
		telemetry.SetStr(attrs, semconv.AttrUserPrincipalName, t.cell(row, "User Principal Name"))
		telemetry.SetStr(attrs, semconv.AttrLastActivityDate, t.cell(row, "Last Activity Date"))
		telemetry.SetStr(attrs, semconv.AttrDeletedDate, t.cell(row, "Deleted Date"))
		telemetry.SetStr(attrs, semconv.AttrReportPeriod, t.cell(row, "Report Period"))
		if v, err := strconv.ParseBool(t.cell(row, "Is Deleted")); err == nil {
			attrs[semconv.AttrIsDeleted] = v
		}
		if v, ok := parseYesNo(t.cell(row, "Is Licensed")); ok {
			attrs[semconv.AttrIsLicensed] = v
		}
		for _, platform := range platforms {
			if v, ok := parseYesNo(t.cell(row, platform.header)); ok {
				attrs[platform.attr] = v
			}
		}
		e.LogEvent(telemetry.Event{Name: eventDeviceUsage, Body: "Teams device usage summary", Timestamp: date, Attrs: attrs})
		emitted(o, 1)
	}
}

func emitPlatformGauges(e telemetry.Emitter, o *recordoutcome.Recorder, t table) bool {
	points := make([]telemetry.GaugePoint, 0, len(platforms))
	for _, platform := range platforms {
		if platform.label == "" {
			continue
		}
		users, known := 0, true
		for _, row := range t.rows {
			used, ok := parseYesNo(t.cell(row, platform.header))
			if !ok {
				known = false
				break
			}
			if used {
				users++
			}
		}
		if !known {
			// An unknown flag would make the tenant count a lower bound.
			o.Cause(recordoutcome.CauseMappingError)
			continue
		}
		points = append(points, telemetry.GaugePoint{Value: float64(users), Attrs: telemetry.Attrs{semconv.AttrPlatform: platform.label}})
	}
	e.GaugeSnapshot(metricPlatform, unitUserCohort, platformDesc, points)
	return len(points) > 0
}

func parseYesNo(cell string) (value, known bool) {
	switch strings.ToLower(strings.TrimSpace(cell)) {
	case "yes":
		return true, true
	case "no":
		return false, true
	default:
		return false, false
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
