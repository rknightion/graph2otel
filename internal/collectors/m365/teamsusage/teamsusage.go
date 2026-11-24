// Package teamsusage collects Teams client and team activity usage reports.
package teamsusage

import (
	"bytes"
	"context"
	"encoding/csv"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/rknightion/graph2otel/internal/collector"
	"github.com/rknightion/graph2otel/internal/collectors"
	"github.com/rknightion/graph2otel/internal/graphclient"
	"github.com/rknightion/graph2otel/internal/recordoutcome"
	"github.com/rknightion/graph2otel/internal/telemetry"
)

const (
	name              = "m365.teams_usage"
	baseURL           = "https://graph.microsoft.com/v1.0"
	metricPlatform    = "teams.device_usage.users"
	metricActivity    = "m365.teams_usage.activity.users"
	metricConcealment = "m365.teams_usage.names_concealed"
	eventTeamActivity = "m365.team_activity"
	unitUserCohort    = "{overlapping_user_count}"

	platformDesc  = "Users who used each Teams client platform in the D7 report. A user can use more than one platform."
	activityDesc  = "Daily Teams users per activity in the D30 report, by days before its latest Report Date. Activity groups overlap."
	concealedDesc = "Whether Microsoft Graph usage reports conceal names (1: on, 0: off, absent: unknown)."
)

// Collector polls the Teams usage reports without fetching other workloads.
type Collector struct {
	graph collectors.GraphClient
}

// New builds a Teams usage collector on the tenant's shared Graph client.
func New(graph collectors.GraphClient) *Collector { return &Collector{graph: graph} }

// Name implements collector.SnapshotCollector.
func (*Collector) Name() string { return name }

// Profiles selects Teams explicitly without expanding the legacy Graph roster.
func (*Collector) Profiles() collector.ProfileSet { return collector.ProfileTeams }

// DefaultInterval implements collector.SnapshotCollector.
func (*Collector) DefaultInterval() time.Duration { return 6 * time.Hour }

// RequiredPermissions declares the scopes for the reports and concealment setting.
func (*Collector) RequiredPermissions() []string {
	return []string{"Reports.Read.All", "ReportSettings.Read.All"}
}

// Collect processes the reports independently. If none can be read, return an
// error even if the setting was readable.
func (c *Collector) Collect(ctx context.Context, e telemetry.Emitter, o *recordoutcome.Recorder) error {
	concealed := c.readConcealment(ctx)
	var setting []telemetry.GaugePoint
	if concealed != nil {
		var value float64
		if *concealed {
			value = 1
		}
		setting = []telemetry.GaugePoint{{Value: value}}
	}
	e.GaugeSnapshot(metricConcealment, "1", concealedDesc, setting)

	reports := []struct {
		function string
		columns  []column
		require  []string
		mapRows  func(table)
		clear    func()
	}{
		{"getTeamsDeviceUsageUserDetail(period='D7')", platforms, nil,
			func(t table) { emitPlatforms(e, o, t) }, func() { e.GaugeSnapshot(metricPlatform, unitUserCohort, platformDesc, nil) }},
		{"getTeamsTeamActivityDetail(period='D7')", teamCounts, []string{"Team Id", "Report Refresh Date"},
			func(t table) { emitTeams(e, o, t, concealed) }, nil},
		{"getTeamsUserActivityUserCounts(period='D30')", activities, []string{"Report Date"},
			func(t table) { emitActivity(e, o, t) }, func() { e.GaugeSnapshot(metricActivity, unitUserCohort, activityDesc, nil) }},
	}
	var errs []error
	for _, report := range reports {
		t, err := c.readReport(ctx, o, report.function, report.columns, report.require)
		if err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", report.function, err))
			if report.clear != nil {
				report.clear()
			}
			continue
		}
		o.Add(recordoutcome.OutcomeFetched, uint64(len(t.rows)))
		report.mapRows(t)
	}
	if len(errs) == len(reports) {
		return fmt.Errorf("%s: all Teams usage reports failed: %w", name, errors.Join(errs...))
	}
	return nil
}

func (c *Collector) readConcealment(ctx context.Context) *bool {
	raw, err := c.graph.RawGet(ctx, baseURL+"/admin/reportSettings")
	if err != nil {
		return nil
	}
	var settings struct {
		Concealed *bool `json:"displayConcealedNames"`
	}
	if err := json.Unmarshal(raw, &settings); err != nil {
		return nil
	}
	return settings.Concealed
}

type column struct{ header, key string }

type table struct {
	cols map[string]int
	rows [][]string
}

func (t table) cell(row []string, header string) string {
	if i, ok := t.cols[header]; ok {
		return row[i]
	}
	return ""
}

func (c *Collector) readReport(ctx context.Context, o *recordoutcome.Recorder, function string, columns []column, require []string) (table, error) {
	raw, err := c.graph.RawGet(graphclient.ReportDownloadContext(ctx), baseURL+"/reports/"+function)
	if err != nil {
		o.Cause(recordoutcome.CauseForError(err))
		// A download error may include its ticket-bearing URL or response body.
		var status *graphclient.HTTPStatusError
		if errors.As(err, &status) {
			return table{}, fmt.Errorf("fetch report: HTTP %d", status.StatusCode)
		}
		if ctx.Err() != nil {
			return table{}, ctx.Err()
		}
		return table{}, errors.New("fetch report failed")
	}
	parsed, err := parseReport(raw, columns, require)
	if err != nil {
		o.Cause(recordoutcome.CauseDecodeError)
	}
	return parsed, err
}

func parseReport(raw []byte, columns []column, require []string) (table, error) {
	r := csv.NewReader(bytes.NewReader(bytes.TrimPrefix(raw, []byte("\xef\xbb\xbf"))))
	r.LazyQuotes = true
	header, err := r.Read()
	if err != nil {
		return table{}, errors.New("read CSV header")
	}
	cols := make(map[string]int, len(header))
	for i, field := range header {
		if _, exists := cols[field]; exists {
			return table{}, errors.New("duplicate CSV header")
		}
		cols[field] = i
	}
	for _, col := range columns {
		if _, ok := cols[col.header]; !ok {
			return table{}, fmt.Errorf("missing CSV header %q", col.header)
		}
	}
	for _, field := range require {
		if _, ok := cols[field]; !ok {
			return table{}, fmt.Errorf("missing CSV header %q", field)
		}
	}
	rows, err := r.ReadAll()
	if err != nil {
		return table{}, errors.New("read CSV rows")
	}
	return table{cols: cols, rows: rows}, nil
}

func init() {
	collectors.Register(func(d collectors.Deps) collector.SnapshotCollector { return New(d.Graph) })
}
