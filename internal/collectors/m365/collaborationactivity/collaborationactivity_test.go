package collaborationactivity

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/rknightion/graph2otel/internal/collectors"
	"github.com/rknightion/graph2otel/internal/recordoutcome"
	"github.com/rknightion/graph2otel/internal/semconv"
	"github.com/rknightion/graph2otel/internal/telemetrytest"
)

// fakeGraph routes each report URL to a canned CSV body, matched on the report
// function name — mirrors internal/collectors/m365/storage's fakeGraph.
type fakeGraph struct {
	teams, sharepoint, onedrive          string
	teamsErr, sharepointErr, onedriveErr error
}

func (f *fakeGraph) RawGet(_ context.Context, url string) ([]byte, error) {
	switch {
	case strings.Contains(url, "getTeamsUserActivityUserDetail"):
		if f.teamsErr != nil {
			return nil, f.teamsErr
		}
		return []byte(f.teams), nil
	case strings.Contains(url, "getSharePointActivityUserDetail"):
		if f.sharepointErr != nil {
			return nil, f.sharepointErr
		}
		return []byte(f.sharepoint), nil
	case strings.Contains(url, "getOneDriveActivityUserDetail"):
		if f.onedriveErr != nil {
			return nil, f.onedriveErr
		}
		return []byte(f.onedrive), nil
	}
	return nil, nil
}

func (f *fakeGraph) RawGetWithHeaders(ctx context.Context, url string, _ map[string]string) ([]byte, error) {
	return f.RawGet(ctx, url)
}

var _ collectors.GraphClient = (*fakeGraph)(nil)

func readTestdata(t *testing.T, name string) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("testdata", name))
	if err != nil {
		t.Fatalf("read testdata/%s: %v", name, err)
	}
	return string(b)
}

func liveFake(t *testing.T) *fakeGraph {
	t.Helper()
	return &fakeGraph{
		teams:      readTestdata(t, "teams_activity.csv"),
		sharepoint: readTestdata(t, "sharepoint_activity.csv"),
		onedrive:   readTestdata(t, "onedrive_activity.csv"),
	}
}

// TestCollectEmitsSixTwinsFromLiveReports drives all three live-captured CSVs
// (2026-07-28, m7kni, #362) end-to-end and asserts a twin per user per
// workload plus the exact action sums the fixtures carry.
func TestCollectEmitsSixTwinsFromLiveReports(t *testing.T) {
	rec := telemetrytest.New()
	c := New(liveFake(t), nil)
	if err := c.Collect(context.Background(), rec.Emitter(), nil); err != nil {
		t.Fatalf("Collect: %v", err)
	}

	logs := rec.LogRecords()
	var twins int
	byWorkloadUser := map[[2]string]bool{}
	for _, l := range logs {
		if l.EventName != eventName {
			continue
		}
		twins++
		byWorkloadUser[[2]string{l.Attrs[semconv.AttrWorkload], l.Attrs[semconv.AttrUserPrincipalName]}] = true
	}
	if twins != 6 {
		t.Fatalf("emitted %d %s twins, want 6 (2 users x 3 workloads)", twins, eventName)
	}
	for _, wl := range []string{workloadTeams, workloadSharePoint, workloadOneDrive} {
		for _, upn := range []string{"rob@m7kni.io", "vmuser@m7kni.io"} {
			if !byWorkloadUser[[2]string{wl, upn}] {
				t.Errorf("missing twin for workload=%s user=%s", wl, upn)
			}
		}
	}

	// Exact action sums from the live fixtures: rob's row carries all the
	// counted actions at 0 except Is Licensed/Has Other Action (not counted
	// actions), and both live rows are 0 across every counted column except
	// SharePoint/OneDrive file counts.
	sums := map[[2]string]float64{}
	for _, p := range rec.MetricPoints(metricActions) {
		sums[[2]string{p.Attrs[semconv.AttrWorkload], p.Attrs[semconv.AttrAction]}] = p.Value
	}
	want := map[[2]string]float64{
		{workloadTeams, "team_chat_messages"}:           0,
		{workloadTeams, "private_chat_messages"}:        0,
		{workloadTeams, "calls"}:                        0,
		{workloadTeams, "meetings_organized"}:           0,
		{workloadTeams, "meetings_attended"}:            0,
		{workloadSharePoint, "files_viewed_or_edited"}:  1,
		{workloadSharePoint, "files_synced"}:            0,
		{workloadSharePoint, "files_shared_internally"}: 0,
		{workloadSharePoint, "files_shared_externally"}: 0,
		{workloadSharePoint, "pages_visited"}:           0,
		{workloadOneDrive, "files_viewed_or_edited"}:    16, // 14 + 2
		{workloadOneDrive, "files_synced"}:              63, // 62 + 1
		{workloadOneDrive, "files_shared_internally"}:   2,  // 1 + 1
		{workloadOneDrive, "files_shared_externally"}:   0,
	}
	for k, v := range want {
		if got := sums[k]; got != v {
			t.Errorf("action sum %v = %v, want %v", k, got, v)
		}
	}
}

// TestParsesReportWithBOM pins that a BOM-prefixed CSV still resolves "Report
// Refresh Date" — a corrupted header lookup would silently return "".
func TestParsesReportWithBOM(t *testing.T) {
	rec := telemetrytest.New()
	c := New(liveFake(t), nil) // fixtures are BOM-prefixed as captured live
	if err := c.Collect(context.Background(), rec.Emitter(), nil); err != nil {
		t.Fatalf("Collect: %v", err)
	}
	found := false
	for _, l := range rec.LogRecords() {
		if l.EventName != eventName {
			continue
		}
		found = true
		if l.Attrs[semconv.AttrReportRefreshDate] == "" {
			t.Errorf("report_refresh_date empty on twin %+v — BOM likely corrupted the header lookup", l.Attrs)
		}
	}
	if !found {
		t.Fatal("no twins emitted")
	}
}

// TestAssignedProductsSurvivesVerbatim pins that the raw Assigned Products
// string ships unsplit, INCLUDING its inner " + " — splitting on "+" would
// fragment "ENTERPRISE MOBILITY + SECURITY E5" into non-product garbage.
func TestAssignedProductsSurvivesVerbatim(t *testing.T) {
	const want = "MICROSOFT INTUNE SUITE+ENTERPRISE MOBILITY + SECURITY E5+MICROSOFT DEFENDER FOR ENDPOINT P2+WINDOWS 10/11 ENTERPRISE E3+MICROSOFT POWER AUTOMATE FREE+MICROSOFT 365 E5+POWER BI PRO+POWER BI PREMIUM PER USER+MICROSOFT FABRIC (FREE)+AGENT 365+MICROSOFT COPILOT STUDIO USER LICENSE"

	rec := telemetrytest.New()
	c := New(liveFake(t), nil)
	if err := c.Collect(context.Background(), rec.Emitter(), nil); err != nil {
		t.Fatalf("Collect: %v", err)
	}
	sawExact := false
	for _, l := range rec.LogRecords() {
		if l.EventName != eventName {
			continue
		}
		v := l.Attrs[semconv.AttrAssignedProducts]
		if v == "" {
			continue
		}
		if strings.Contains(v, "ENTERPRISE MOBILITY ") && v != want {
			t.Errorf("assigned_products fragment leaked: %q", v)
		}
		if v == want {
			sawExact = true
		}
		// No attribute anywhere may equal a bare fragment of the split.
		if v == "ENTERPRISE MOBILITY " {
			t.Errorf("assigned_products was split — found bare fragment %q", v)
		}
	}
	if !sawExact {
		t.Error("no twin carried the exact live assigned_products string")
	}
}

// TestEmptyLastActivityDateOmitsAttrAndBucketsNeverActive covers the vmuser row
// (Teams/SharePoint have it blank): the twin must OMIT last_activity_date
// rather than emit "", and the user metric must bucket it never_active.
func TestEmptyLastActivityDateOmitsAttrAndBucketsNeverActive(t *testing.T) {
	rec := telemetrytest.New()
	c := New(liveFake(t), nil)
	if err := c.Collect(context.Background(), rec.Emitter(), nil); err != nil {
		t.Fatalf("Collect: %v", err)
	}
	for _, l := range rec.LogRecords() {
		if l.EventName != eventName {
			continue
		}
		if l.Attrs[semconv.AttrUserPrincipalName] != "vmuser@m7kni.io" || l.Attrs[semconv.AttrWorkload] != workloadTeams {
			continue
		}
		if _, ok := l.Attrs[semconv.AttrLastActivityDate]; ok {
			t.Errorf("last_activity_date should be omitted for a never-active user, got %v", l.Attrs[semconv.AttrLastActivityDate])
		}
	}

	counts := map[[2]string]float64{}
	for _, p := range rec.MetricPoints(metricUsers) {
		counts[[2]string{p.Attrs[semconv.AttrWorkload], p.Attrs[semconv.AttrActivityState]}] = p.Value
	}
	if counts[[2]string{workloadTeams, stateNeverActive}] != 1 {
		t.Errorf("teams never_active = %v, want 1 (vmuser)", counts[[2]string{workloadTeams, stateNeverActive}])
	}
	if counts[[2]string{workloadTeams, stateActive}] != 1 {
		t.Errorf("teams active = %v, want 1 (rob)", counts[[2]string{workloadTeams, stateActive}])
	}
}

// TestNoUPNOrUserIDOnAnyMetric enforces #112 explicitly (belt-and-braces on
// top of signalgate_test.go's package-wide gate): no metric point may carry a
// UPN or user id.
func TestNoUPNOrUserIDOnAnyMetric(t *testing.T) {
	rec := telemetrytest.New()
	c := New(liveFake(t), nil)
	if err := c.Collect(context.Background(), rec.Emitter(), nil); err != nil {
		t.Fatalf("Collect: %v", err)
	}
	for _, name := range []string{metricUsers, metricActions, metricDeleted, metricSharedExternally} {
		for _, p := range rec.MetricPoints(name) {
			for k := range p.Attrs {
				if k == semconv.AttrUserPrincipalName || k == semconv.AttrUserId {
					t.Errorf("metric %s carries per-entity label %q", name, k)
				}
			}
		}
	}
}

// TestSharePointFailureDoesNotLoseTeamsOrOneDrive pins independent
// degradation: SharePoint fetch failing must not suppress Teams/OneDrive
// metrics or twins.
func TestSharePointFailureDoesNotLoseTeamsOrOneDrive(t *testing.T) {
	f := liveFake(t)
	f.sharepointErr = errors.New("429 ServiceThrottleThresholdExceeded")
	rec := telemetrytest.New()
	if err := New(f, nil).Collect(context.Background(), rec.Emitter(), nil); err != nil {
		t.Fatalf("Collect must stay non-fatal on a single report failure: %v", err)
	}

	sawTeams, sawOneDrive, sawSharePoint := false, false, false
	for _, l := range rec.LogRecords() {
		if l.EventName != eventName {
			continue
		}
		switch l.Attrs[semconv.AttrWorkload] {
		case workloadTeams:
			sawTeams = true
		case workloadOneDrive:
			sawOneDrive = true
		case workloadSharePoint:
			sawSharePoint = true
		}
	}
	if !sawTeams {
		t.Error("Teams twins missing when only SharePoint failed")
	}
	if !sawOneDrive {
		t.Error("OneDrive twins missing when only SharePoint failed")
	}
	if sawSharePoint {
		t.Error("SharePoint twins present despite its report failing")
	}

	sawSPMetric := false
	for _, p := range rec.MetricPoints(metricUsers) {
		if p.Attrs[semconv.AttrWorkload] == workloadSharePoint {
			sawSPMetric = true
		}
	}
	if sawSPMetric {
		t.Error("SharePoint metric points present despite its report failing")
	}
}

// TestAllReportsFailingIsAnError mirrors storage.go's #240 handling: every
// report failing must not report success over an empty/fabricated grid.
func TestAllReportsFailingIsAnError(t *testing.T) {
	f := &fakeGraph{
		teamsErr:      errors.New("429"),
		sharepointErr: errors.New("429"),
		onedriveErr:   errors.New("429"),
	}
	rec := telemetrytest.New()
	outcomes := recordoutcome.NewRecorder()
	err := New(f, nil).Collect(context.Background(), rec.Emitter(), outcomes)
	if err == nil {
		t.Fatal("Collect returned nil despite all three reports failing")
	}
	got := outcomes.Snapshot().Summarize(err, false)
	if got.Result != recordoutcome.ResultFailure || got.Cause != recordoutcome.CauseSourceError {
		t.Errorf("outcome = %#v, want failure/source_error", got)
	}
}

// TestConcealedNameRowIsMappedNotDropped covers report concealment: a row
// whose "User Principal Name" is an opaque non-email token (Microsoft's
// displayConcealedNames behavior, not observed live but must be survived) is
// still mapped and counted, never silently dropped.
func TestConcealedNameRowIsMappedNotDropped(t *testing.T) {
	const concealedTeams = "Report Refresh Date,User Id,User Principal Name,Last Activity Date,Is Deleted,Deleted Date,Assigned Products,Team Chat Message Count,Private Chat Message Count,Call Count,Meeting Count,Meetings Organized Count,Meetings Attended Count,Report Period\n" +
		"2026-07-26,,3f2504e0-4f89-11d3-9a0c-0305e82c3301,2026-07-23,False,,MICROSOFT 365 E5,3,1,0,0,0,0,7\n"
	f := &fakeGraph{teams: concealedTeams, sharepoint: "", onedrive: ""}
	rec := telemetrytest.New()
	if err := New(f, nil).Collect(context.Background(), rec.Emitter(), nil); err != nil {
		t.Fatalf("Collect: %v", err)
	}
	found := false
	for _, l := range rec.LogRecords() {
		if l.EventName != eventName {
			continue
		}
		found = true
		if l.Attrs[semconv.AttrUserPrincipalName] != "3f2504e0-4f89-11d3-9a0c-0305e82c3301" {
			t.Errorf("concealed UPN not passed through verbatim: %v", l.Attrs[semconv.AttrUserPrincipalName])
		}
	}
	if !found {
		t.Fatal("concealed-name row was dropped instead of mapped")
	}
	sum := 0.0
	for _, p := range rec.MetricPoints(metricActions) {
		if p.Attrs[semconv.AttrWorkload] == workloadTeams && p.Attrs[semconv.AttrAction] == "team_chat_messages" {
			sum = p.Value
		}
	}
	if sum != 3 {
		t.Errorf("concealed row's action count not aggregated: got %v, want 3", sum)
	}
}

// TestEmptyReportEmitsNoTwinsAndIsNotAnError pins that a header-only CSV (a
// legitimately empty tenant/report) is a success with zero twins, not a
// failure — the same distinction storage.go's #240 draws for the other report
// family.
func TestEmptyReportEmitsNoTwinsAndIsNotAnError(t *testing.T) {
	header := "Report Refresh Date,User Id,User Principal Name,Last Activity Date,Is Deleted,Deleted Date,Assigned Products,Team Chat Message Count,Private Chat Message Count,Call Count,Meeting Count,Meetings Organized Count,Meetings Attended Count,Report Period\n"
	f := &fakeGraph{teams: header, sharepoint: header, onedrive: header}
	rec := telemetrytest.New()
	outcomes := recordoutcome.NewRecorder()
	if err := New(f, nil).Collect(context.Background(), rec.Emitter(), outcomes); err != nil {
		t.Fatalf("Collect errored on legitimately-empty reports: %v", err)
	}
	for _, l := range rec.LogRecords() {
		if l.EventName == eventName {
			t.Errorf("unexpected twin emitted from an empty report: %+v", l.Attrs)
		}
	}
	got := outcomes.Snapshot().Summarize(nil, false)
	if got.Result != recordoutcome.ResultEmpty || got.Cause != recordoutcome.CauseNone {
		t.Errorf("outcome = %#v, want empty/none", got)
	}
	// The bounded grids still report explicit zeros for a report that
	// succeeded empty (distinct from a report that failed to fetch at all).
	for _, name := range []string{metricUsers, metricActions} {
		if len(rec.MetricPoints(name)) == 0 {
			t.Errorf("metric %s has no baseline points for a legitimately-empty (but successful) report", name)
		}
	}
}
