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
