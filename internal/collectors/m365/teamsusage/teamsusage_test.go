package teamsusage

import (
	"context"
	"errors"
	"maps"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/rknightion/graph2otel/internal/collector"
	"github.com/rknightion/graph2otel/internal/recordoutcome"
	"github.com/rknightion/graph2otel/internal/telemetry"
	"github.com/rknightion/graph2otel/internal/telemetrytest"
)

const (
	devicesPath = "/v1.0/reports/getTeamsDeviceUsageUserDetail(period='D7')"
	teamsPath   = "/v1.0/reports/getTeamsTeamActivityDetail(period='D7')"
	trendPath   = "/v1.0/reports/getTeamsUserActivityUserCounts(period='D30')"
	settingPath = "/v1.0/admin/reportSettings"

	devicesCSV = "\ufeffReport Refresh Date,User Id,User Principal Name,Last Activity Date,Is Deleted,Deleted Date,Used Web,Used Windows Phone,Used iOS,Used Mac,Used Android Phone,Used Windows,Used  Chrome OS,Used Linux,Is Licensed,Report Period\n" +
		"2026-11-23,192.0.2.1,one@example.com,2026-11-21,false,,Yes,Yes,No,No,No,Yes,Yes,No,Yes,7\n" +
		"2026-11-23,192.0.2.2,two@example.com,2026-11-21,false,,No,No,Yes,No,Yes,Yes,No,Yes,Yes,7\n"
	teamsCSV = "Report Refresh Date,Team Id,Team Name,Last Activity Date,Team Type,Is Deleted,Report Period,Active Users,Active Channels,Channel Messages,Reactions,Meetings Organized,Post Messages,Reply Messages,Urgent Messages,Mentions,Guests,Active Shared Channels,Active External Users\n" +
		"2026-11-23,192.0.2.11,\"Example, Team\",2026-11-21,Private,False,7,12,2,22,6,3,4,5,1,9,2,0,0\n" +
		"2026-11-23,192.0.2.12,Second Example,,Public,True,7,0,,0,,bad,,,,,0,,\n" +
		"invalid,192.0.2.13,Invalid date,,Public,False,7,0,,0,,,,,,,0,,\n"
	trendCSV = "Report Refresh Date,Report Date,Team Chat Messages,Private Chat Messages,Calls,Meetings,Other Actions,Report Period\n" +
		"2026-11-23,2026-11-19,2,5,0,,4,30\n" +
		"2026-11-23,2026-11-21,9,11,3,4,8,30\n" +
		"2026-11-23,2026-10-22,42,42,42,42,42,30\n"
)

type graphStub struct {
	bodies map[string]string
	paths  []string
}

func (g *graphStub) RawGet(_ context.Context, rawURL string) ([]byte, error) {
	path := strings.TrimPrefix(rawURL, "https://graph.microsoft.com")
	g.paths = append(g.paths, path)
	body, ok := g.bodies[path]
	if !ok {
		return nil, errors.New("fixture: no response")
	}
	return []byte(body), nil
}

func (g *graphStub) RawGetWithHeaders(ctx context.Context, url string, _ map[string]string) ([]byte, error) {
	return g.RawGet(ctx, url)
}

func TestCollectTeamsReports(t *testing.T) {
	g := &graphStub{bodies: map[string]string{
		devicesPath: devicesCSV, teamsPath: teamsCSV, trendPath: trendCSV, settingPath: `{"displayConcealedNames":true}`,
	}}
	c := New(g)
	if got := c.Profiles(); got != collector.ProfileTeams {
		t.Errorf("profile = %v, want Teams only", got)
	}
	rec := telemetrytest.New()
	if err := c.Collect(t.Context(), rec.Emitter(), recordoutcome.NewRecorder()); err != nil {
		t.Fatal(err)
	}
	wantPaths := []string{devicesPath, teamsPath, trendPath, settingPath}
	slices.Sort(wantPaths)
	slices.Sort(g.paths)
	if !slices.Equal(g.paths, wantPaths) {
		t.Errorf("requested %v, want only %v", g.paths, wantPaths)
	}

	platforms := map[string]float64{}
	for _, pt := range rec.MetricPoints("teams.device_usage.users") {
		if len(pt.Attrs) != 1 || pt.Kind != "gauge" {
			t.Errorf("invalid platform point: %+v", pt)
		}
		platforms[pt.Attrs["platform"]] = pt.Value
	}
	wantPlatforms := map[string]float64{"web": 1, "ios": 1, "mac": 0, "android": 1, "windows": 2, "chrome_os": 1, "linux": 1}
	if !maps.Equal(platforms, wantPlatforms) {
		t.Errorf("platforms = %v, want %v", platforms, wantPlatforms)
	}

	trend := map[string]float64{}
	for _, pt := range rec.MetricPoints("m365.teams_usage.activity.users") {
		if len(pt.Attrs) != 2 || pt.Kind != "gauge" {
			t.Errorf("invalid trend point: %+v", pt)
		}
		trend[pt.Attrs["days_ago"]+"/"+pt.Attrs["activity"]] = pt.Value
	}
	wantTrend := map[string]float64{
		"0/team_chat_messages": 9, "0/private_chat_messages": 11, "0/calls": 3, "0/meetings": 4, "0/other_actions": 8,
		"2/team_chat_messages": 2, "2/private_chat_messages": 5, "2/calls": 0, "2/other_actions": 4,
	}
	if !maps.Equal(trend, wantTrend) {
		t.Errorf("trend = %v, want %v", trend, wantTrend)
	}
	setting := rec.MetricPoints("m365.teams_usage.names_concealed")
	if len(setting) != 1 || setting[0].Value != 1 || len(setting[0].Attrs) != 0 {
		t.Errorf("concealment = %+v, want one unlabelled point with value 1", setting)
	}

	logs := rec.LogRecords()
	logs = slices.DeleteFunc(logs, func(log telemetrytest.LogRecord) bool { return log.EventName != "m365.team_activity" })
	if len(logs) != 2 {
		t.Fatalf("logs = %+v, want two dated team twins", logs)
	}
	if first := logs[0]; first.EventName != "m365.team_activity" ||
		!first.Timestamp.Equal(time.Date(2026, 11, 23, 0, 0, 0, 0, time.UTC)) ||
		first.Attrs["id"] != "192.0.2.11" || first.Attrs["display_name"] != "Example, Team" ||
		first.Attrs["active_users_count"] != "12" || first.Attrs["post_messages_count"] != "4" ||
		first.Attrs["meetings_organized_count"] != "3" || first.Attrs["names_concealed"] != "true" {
		t.Errorf("first twin = %+v", first)
	}
	if second := logs[1]; second.Attrs["id"] != "192.0.2.12" || second.Attrs["active_users_count"] != "0" ||
		second.Attrs["is_deleted"] != "true" || second.Attrs["meetings_organized_count"] != "" || second.Attrs["active_channels_count"] != "" {
		t.Errorf("second twin = %+v; want blank and invalid optional counts omitted", second)
	}
}

func TestUsageReportRefreshDates(t *testing.T) {
	g := &graphStub{bodies: map[string]string{
		devicesPath: devicesCSV, teamsPath: teamsCSV,
		trendPath: strings.ReplaceAll(trendCSV, "2026-11-23,", "2026-11-24,"),
	}}
	c, rec := New(g), telemetrytest.New()
	check := func(want map[string]float64) {
		t.Helper()
		if err := c.Collect(t.Context(), rec.Emitter(), recordoutcome.NewRecorder()); err != nil {
			t.Fatal(err)
		}
		got := map[string]float64{}
		for _, pt := range rec.MetricPoints("m365.teams_usage.report_refresh_timestamp") {
			if len(pt.Attrs) != 1 || pt.Kind != "gauge" {
				t.Errorf("invalid freshness point: %+v", pt)
			}
			got[pt.Attrs["report_period"]] = pt.Value
		}
		if !maps.Equal(got, want) {
			t.Errorf("report refresh timestamps = %v, want %v", got, want)
		}
	}
	d7 := float64(time.Date(2026, 11, 23, 0, 0, 0, 0, time.UTC).Unix())
	d30 := float64(time.Date(2026, 11, 24, 0, 0, 0, 0, time.UTC).Unix())
	check(map[string]float64{"7": d7, "30": d30})

	// A mixed refresh date must not label the complete platform aggregate.
	g.bodies[devicesPath] = strings.Replace(devicesCSV, "2026-11-23,", "2026-11-24,", 1)
	check(map[string]float64{"30": d30})
	if got := rec.MetricPoints("teams.device_usage.users"); len(got) != 7 {
		t.Errorf("mixed refresh dates must not erase platform counts: %+v", got)
	}

	// Unavailable D30 refresh data must not leave yesterday's date behind.
	g.bodies[devicesPath] = devicesCSV
	delete(g.bodies, trendPath)
	check(map[string]float64{"7": d7})

	// A header-only CSV supplies no date. A mismatched period is not D30.
	g.bodies[devicesPath], _, _ = strings.Cut(devicesCSV, "\n")
	g.bodies[trendPath] = strings.ReplaceAll(trendCSV, ",30\n", ",7\n")
	check(nil)
}

func TestCollectDeviceUsageTwins(t *testing.T) {
	header, _, _ := strings.Cut(devicesCSV, "\n")
	g := &graphStub{bodies: map[string]string{
		devicesPath: header + ",Additional Column\n" +
			"2026-11-23,concealed-id,concealed-upn,2026-11-18,true,2026-11-19,Yes,No,No,,No,Yes,Yes,No,Yes,7,not-for-export\n" +
			"2026-11-23,,,2026-11-21,false,,No,Yes,,No,Yes,No,No,Yes,No,7,not-for-export\n" +
			",undated-id,,2026-11-21,false,,Yes,No,No,Yes,No,Yes,No,No,,7,not-for-export\n",
		teamsPath:   strings.SplitN(teamsCSV, "\n", 2)[0] + "\n",
		trendPath:   strings.SplitN(trendCSV, "\n", 2)[0] + "\n",
		settingPath: `{"displayConcealedNames":true}`,
	}}
	rec, outcomes := telemetrytest.New(), recordoutcome.NewRecorder()
	if err := New(g).Collect(t.Context(), rec.Emitter(), outcomes); err != nil {
		t.Fatal(err)
	}
	logs := rec.LogRecords()
	if len(logs) != 2 {
		t.Fatalf("got %d logs, want two dated device usage twins", len(logs))
	}
	for i, want := range []map[string]string{
		{
			"user_id": "concealed-id", "user_principal_name": "concealed-upn", "last_activity_date": "2026-11-18",
			"report_refresh_date": "2026-11-23", "report_period": "7", "is_deleted": "true", "deleted_date": "2026-11-19",
			"used_web": "true", "used_windows_phone": "false", "used_ios": "false", "used_android_phone": "false",
			"used_windows": "true", "used_chrome_os": "true", "used_linux": "false", "is_licensed": "true",
		},
		{
			"last_activity_date": "2026-11-21", "report_refresh_date": "2026-11-23", "report_period": "7", "is_deleted": "false",
			"used_web": "false", "used_windows_phone": "true", "used_mac": "false", "used_android_phone": "true",
			"used_windows": "false", "used_chrome_os": "false", "used_linux": "true", "is_licensed": "false",
		},
	} {
		got := logs[i]
		if got.EventName != "m365.teams_device_usage" || !got.Timestamp.Equal(time.Date(2026, 11, 23, 0, 0, 0, 0, time.UTC)) {
			t.Errorf("log %d: event = %q, timestamp = %v; want device usage at report refresh", i, got.EventName, got.Timestamp)
		}
		if !maps.Equal(got.Attrs, want) {
			t.Errorf("log %d attrs = %v, want %v", i, got.Attrs, want)
		}
	}
	gauges := map[string]float64{}
	for _, pt := range rec.MetricPoints("teams.device_usage.users") {
		gauges[pt.Attrs["platform"]] = pt.Value
	}
	wantGauges := map[string]float64{"web": 2, "android": 1, "windows": 2, "chrome_os": 1, "linux": 1}
	if !maps.Equal(gauges, wantGauges) {
		t.Errorf("platforms = %v, want %v (including the undated row, but excluding unknown counts)", gauges, wantGauges)
	}
	snap := outcomes.Snapshot()
	wantCounts := recordoutcome.Counts{Fetched: 3, Mapped: 3, Emitted: 3}
	if got := snap.Summarize(nil, false); got.Result != recordoutcome.ResultPartial || got.Counts != wantCounts ||
		!slices.Contains(snap.Causes, recordoutcome.CauseMissingEventTime) {
		t.Errorf("outcomes = %+v, causes = %v; want partial with all rows used and missing log date reported", got, snap.Causes)
	}
}

func TestDeviceUsageWithoutRefreshColumnKeepsGauges(t *testing.T) {
	devices := strings.ReplaceAll(devicesCSV, "2026-11-23,", "")
	devices = strings.Replace(devices, "Report Refresh Date,", "", 1)
	g := &graphStub{bodies: map[string]string{
		devicesPath: devices,
		teamsPath:   strings.SplitN(teamsCSV, "\n", 2)[0] + "\n",
		trendPath:   strings.SplitN(trendCSV, "\n", 2)[0] + "\n",
	}}
	rec, outcomes := telemetrytest.New(), recordoutcome.NewRecorder()
	if err := New(g).Collect(t.Context(), rec.Emitter(), outcomes); err != nil {
		t.Fatal(err)
	}
	if got := rec.LogRecords(); len(got) != 0 {
		t.Errorf("got %d logs without a report refresh date, want none", len(got))
	}
	if got := rec.MetricPoints("teams.device_usage.users"); len(got) != 7 {
		t.Errorf("got %d complete platform gauges, want seven", len(got))
	}
	want := recordoutcome.Summary{
		Result: recordoutcome.ResultPartial,
		Cause:  recordoutcome.CauseMissingEventTime,
		Counts: recordoutcome.Counts{Fetched: 2, Mapped: 2, Emitted: 2},
	}
	if got := outcomes.Snapshot().Summarize(nil, false); got != want {
		t.Errorf("summary = %+v, want %+v", got, want)
	}
}

func TestUsageLimitsNeverFoldOverlappingUserCounts(t *testing.T) {
	g := &graphStub{bodies: map[string]string{devicesPath: devicesCSV, trendPath: trendCSV}}
	rec := telemetrytest.New()
	emitter := telemetry.WithCardinalityLimits(rec.Emitter(), telemetry.Limits{PerMetric: 1})
	if err := New(g).Collect(t.Context(), emitter, recordoutcome.NewRecorder()); err != nil {
		t.Fatal(err)
	}
	for _, want := range []struct {
		metric string
		value  float64
		attrs  map[string]string
	}{
		{"teams.device_usage.users", 2, map[string]string{"platform": "windows"}},
		{"m365.teams_usage.activity.users", 11, map[string]string{"days_ago": "0", "activity": "private_chat_messages"}},
	} {
		pts := rec.MetricPoints(want.metric)
		if len(pts) != 1 || pts[0].Value != want.value || !maps.Equal(pts[0].Attrs, want.attrs) {
			t.Errorf("%s clipped to %+v; want only the top measured point and no fabricated other group", want.metric, pts)
		}
	}
}

func TestUnavailableReportsClearTheirOwnGauges(t *testing.T) {
	g := &graphStub{bodies: map[string]string{
		devicesPath: devicesCSV, trendPath: trendCSV, settingPath: `{"displayConcealedNames":false}`,
	}}
	c := New(g)
	rec := telemetrytest.New()
	run := func() error { return c.Collect(t.Context(), rec.Emitter(), recordoutcome.NewRecorder()) }
	if err := run(); err != nil {
		t.Fatalf("partial report failure: %v", err)
	}
	setting := rec.MetricPoints("m365.teams_usage.names_concealed")
	if len(setting) != 1 || setting[0].Value != 0 {
		t.Fatalf("concealment = %+v, want known off", setting)
	}

	// A schema mismatch is not zero usage. The independent trend remains.
	g.bodies[devicesPath] = strings.Replace(devicesCSV, "Used  Chrome OS", "Unexpected column", 1)
	g.bodies[settingPath] = `{"@odata.context":"https://example.com"}`
	if err := run(); err != nil {
		t.Fatalf("partial report failure: %v", err)
	}
	for _, metric := range []string{"teams.device_usage.users", "m365.teams_usage.names_concealed"} {
		if got := rec.MetricPoints(metric); len(got) != 0 {
			t.Errorf("unavailable %s emitted stale points: %+v", metric, got)
		}
	}
	if got := rec.MetricPoints("m365.teams_usage.activity.users"); len(got) != 9 {
		t.Errorf("healthy independent trend: got %d points, want 9", len(got))
	}
	delete(g.bodies, trendPath)
	if err := run(); err == nil {
		t.Fatal("all three usage reports failed but Collect returned success")
	}
	if got := rec.MetricPoints("m365.teams_usage.activity.users"); len(got) != 0 {
		t.Errorf("unavailable trend emitted stale points: %+v", got)
	}
}
