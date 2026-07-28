package mailboxusage

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/rknightion/graph2otel/internal/collectors"
	"github.com/rknightion/graph2otel/internal/recordoutcome"
	"github.com/rknightion/graph2otel/internal/semconv"
	"github.com/rknightion/graph2otel/internal/telemetrytest"
)

// fakeGraph routes each report URL to a canned CSV body, matched on the
// report function name — same shape as storage's fakeGraph.
type fakeGraph struct {
	detail, storage, quota string
	reportSettings         string
	reportSettingsErr      error
	// reportsErr, when set, is returned for ALL THREE usage-report URLs.
	reportsErr error
}

func (f *fakeGraph) RawGet(_ context.Context, url string) ([]byte, error) {
	switch {
	case strings.Contains(url, "getMailboxUsageDetail"):
		if f.reportsErr != nil {
			return nil, f.reportsErr
		}
		return []byte(f.detail), nil
	case strings.Contains(url, "getMailboxUsageStorage"):
		if f.reportsErr != nil {
			return nil, f.reportsErr
		}
		return []byte(f.storage), nil
	case strings.Contains(url, "getMailboxUsageQuotaStatusMailboxCounts"):
		if f.reportsErr != nil {
			return nil, f.reportsErr
		}
		return []byte(f.quota), nil
	case strings.HasSuffix(url, "/admin/reportSettings"):
		if f.reportSettingsErr != nil {
			return nil, f.reportSettingsErr
		}
		return []byte(f.reportSettings), nil
	}
	return nil, nil
}

func (f *fakeGraph) RawGetWithHeaders(ctx context.Context, url string, _ map[string]string) ([]byte, error) {
	return f.RawGet(ctx, url)
}

var _ collectors.GraphClient = (*fakeGraph)(nil)

// Verbatim captures off m7kni as graph2otel-poller (2026-07-28, #359), all
// HTTP 200. Real UPNs replaced with the actual live values on purpose — this
// tenant is not concealed, so the raw values are what the wire sends.
const (
	liveDetail = "Report Refresh Date,User Principal Name,Display Name,Is Deleted,Deleted Date,Created Date,Last Activity Date,Item Count,Storage Used (Byte),Issue Warning Quota (Byte),Prohibit Send Quota (Byte),Prohibit Send/Receive Quota (Byte),Deleted Item Count,Deleted Item Size (Byte),Deleted Item Quota (Byte),Has Archive,Report Period\n" +
		"2026-07-25,rob@m7kni.io,Rob Knight,False,,2025-08-08,2026-07-25,4096,23293152,105226698752,106300440576,107374182400,0,0,107374182400,False,7\n" +
		"2026-07-25,vmuser@m7kni.io,vmuser,False,,2026-07-21,2026-07-21,3071,662091,105226698752,106300440576,107374182400,0,0,107374182400,False,7\n"

	liveQuotaCounts = "Report Refresh Date,Under Limit,Warning Issued,Send Prohibited,Send/Receive Prohibited,Indeterminate,Report Date,Report Period\n" +
		"2026-07-25,2,0,0,0,0,2026-07-25,7\n"

	liveStorage = "Report Refresh Date,Storage Used (Byte),Report Date,Report Period\n" +
		"2026-07-25,23955243,2026-07-25,7\n"

	concealedSettings   = `{"displayConcealedNames": true}`
	unconcealedSettings = `{"displayConcealedNames": false}`
)

func liveFake() *fakeGraph {
	return &fakeGraph{
		detail: liveDetail, storage: liveStorage, quota: liveQuotaCounts,
		reportSettings: unconcealedSettings,
	}
}

func TestCollectEmitsTenantStorageUsed(t *testing.T) {
	rec := telemetrytest.New()
	c := New(liveFake(), nil)
	if err := c.Collect(context.Background(), rec.Emitter(), nil); err != nil {
		t.Fatalf("Collect: %v", err)
	}
	pts := rec.MetricPoints(metricStorageUsed)
	if len(pts) != 1 {
		t.Fatalf("got %d %s points, want 1", len(pts), metricStorageUsed)
	}
	if pts[0].Value != 23955243 {
		t.Errorf("storage used = %v, want 23955243", pts[0].Value)
	}
	if len(pts[0].Attrs) != 0 {
		t.Errorf("storage used carries attrs %v, want none (tenant-wide scalar)", pts[0].Attrs)
	}
}

func TestCollectEmitsQuotaStatusZeroFilled(t *testing.T) {
	rec := telemetrytest.New()
	c := New(liveFake(), nil)
	if err := c.Collect(context.Background(), rec.Emitter(), nil); err != nil {
		t.Fatalf("Collect: %v", err)
	}
	got := map[string]float64{}
	for _, p := range rec.MetricPoints(metricQuotaStatus) {
		got[p.Attrs[semconv.AttrQuotaState]] = p.Value
	}
	want := map[string]float64{
		quotaStateUnderLimit:            2,
		quotaStateWarningIssued:         0,
		quotaStateSendProhibited:        0,
		quotaStateSendReceiveProhibited: 0,
		quotaStateIndeterminate:         0,
	}
	for state, wantVal := range want {
		if got[state] != wantVal {
			t.Errorf("quota state %s = %v, want %v", state, got[state], wantVal)
		}
	}
	if len(got) != 5 {
		t.Errorf("got %d quota-state series, want all 5 zero-filled: %v", len(got), got)
	}
}

// TestPicksLatestStorageRowRegardlessOfOrder pins the ordering assumption: the
// row with the largest Report Date wins even when it is NOT first in the CSV.
func TestPicksLatestStorageRowRegardlessOfOrder(t *testing.T) {
	f := liveFake()
	f.storage = "Report Refresh Date,Storage Used (Byte),Report Date,Report Period\n" +
		"2026-07-23,11111111,2026-07-23,7\n" +
		"2026-07-25,33333333,2026-07-25,7\n" + // newest, middle row
		"2026-07-24,22222222,2026-07-24,7\n"
	rec := telemetrytest.New()
	c := New(f, nil)
	if err := c.Collect(context.Background(), rec.Emitter(), nil); err != nil {
		t.Fatalf("Collect: %v", err)
	}
	pts := rec.MetricPoints(metricStorageUsed)
	if len(pts) != 1 || pts[0].Value != 33333333 {
		t.Fatalf("storage used = %v, want [33333333] (the 2026-07-25 row, despite not being first)", pts)
	}
}

// TestPicksLatestQuotaRowRegardlessOfOrder is the same ordering pin for the
// quota-status-counts report.
func TestPicksLatestQuotaRowRegardlessOfOrder(t *testing.T) {
	f := liveFake()
	f.quota = "Report Refresh Date,Under Limit,Warning Issued,Send Prohibited,Send/Receive Prohibited,Indeterminate,Report Date,Report Period\n" +
		"2026-07-24,5,1,0,0,0,2026-07-24,7\n" +
		"2026-07-23,9,9,9,9,9,2026-07-23,7\n" +
		"2026-07-25,7,2,1,0,0,2026-07-25,7\n" // newest, last row
	rec := telemetrytest.New()
	c := New(f, nil)
	if err := c.Collect(context.Background(), rec.Emitter(), nil); err != nil {
		t.Fatalf("Collect: %v", err)
	}
	got := map[string]float64{}
	for _, p := range rec.MetricPoints(metricQuotaStatus) {
		got[p.Attrs[semconv.AttrQuotaState]] = p.Value
	}
	if got[quotaStateUnderLimit] != 7 || got[quotaStateWarningIssued] != 2 || got[quotaStateSendProhibited] != 1 {
		t.Errorf("quota counts = %v, want the 2026-07-25 row (7,2,1,0,0)", got)
	}
}

func TestCollectEmitsOneTwinPerMailbox(t *testing.T) {
	rec := telemetrytest.New()
	c := New(liveFake(), nil)
	if err := c.Collect(context.Background(), rec.Emitter(), nil); err != nil {
		t.Fatalf("Collect: %v", err)
	}
	var twins []telemetrytest.LogRecord
	for _, l := range rec.LogRecords() {
		if l.EventName == eventName {
			twins = append(twins, l)
		}
	}
	if len(twins) != 2 {
		t.Fatalf("emitted %d %s twins, want 2", len(twins), eventName)
	}

	var rob *telemetrytest.LogRecord
	for i := range twins {
		if twins[i].Attrs[semconv.AttrUserPrincipalName] == "rob@m7kni.io" {
			rob = &twins[i]
		}
	}
	if rob == nil {
		t.Fatal("no twin for rob@m7kni.io")
	}
	if rob.Attrs[semconv.AttrDisplayName] != "Rob Knight" {
		t.Errorf("display_name = %q, want Rob Knight", rob.Attrs[semconv.AttrDisplayName])
	}
	if rob.Attrs[semconv.AttrItemCount] != "4096" {
		t.Errorf("item_count = %q, want 4096", rob.Attrs[semconv.AttrItemCount])
	}
	if rob.Attrs[semconv.AttrStorageUsedBytes] != "2.3293152e+07" && rob.Attrs[semconv.AttrStorageUsedBytes] != "23293152" {
		t.Errorf("storage_used_bytes = %q, want 23293152", rob.Attrs[semconv.AttrStorageUsedBytes])
	}
	if rob.Attrs[semconv.AttrIssueWarningQuota] == "" {
		t.Error("issue_warning_quota missing")
	}
	if rob.Attrs[semconv.AttrProhibitSendQuota] == "" {
		t.Error("prohibit_send_quota missing")
	}
	if rob.Attrs[semconv.AttrProhibitSendReceiveQuota] == "" {
		t.Error("prohibit_send_receive_quota missing")
	}
	if rob.Attrs[semconv.AttrDeletedItemCount] != "0" {
		t.Errorf("deleted_item_count = %q, want 0", rob.Attrs[semconv.AttrDeletedItemCount])
	}
	if rob.Attrs[semconv.AttrHasArchive] != "false" {
		t.Errorf("has_archive = %q, want false", rob.Attrs[semconv.AttrHasArchive])
	}
	if rob.Attrs[semconv.AttrIsDeleted] != "false" {
		t.Errorf("is_deleted = %q, want false", rob.Attrs[semconv.AttrIsDeleted])
	}
}

// TestDeletedDateOmittedWhenBlank pins the absent-field rule: the live capture's
// Deleted Date column is empty on a non-deleted mailbox, and that must not
// become a fabricated zero/epoch value — the attribute must be absent.
func TestDeletedDateOmittedWhenBlank(t *testing.T) {
	rec := telemetrytest.New()
	c := New(liveFake(), nil)
	if err := c.Collect(context.Background(), rec.Emitter(), nil); err != nil {
		t.Fatalf("Collect: %v", err)
	}
	for _, l := range rec.LogRecords() {
		if l.EventName != eventName {
			continue
		}
		if _, present := l.Attrs[semconv.AttrDeletedDate]; present {
			t.Errorf("twin for %q carries deleted_date=%q despite a blank CSV cell",
				l.Attrs[semconv.AttrUserPrincipalName], l.Attrs[semconv.AttrDeletedDate])
		}
	}
}

// TestBlankNumericCellOmittedNotFabricated is a synthetic guard: a blank
// numeric cell (no live sample observed one, but the CSV format permits it)
// must not become a fabricated 0.
func TestBlankNumericCellOmittedNotFabricated(t *testing.T) {
	f := liveFake()
	f.detail = "Report Refresh Date,User Principal Name,Display Name,Is Deleted,Deleted Date,Created Date,Last Activity Date,Item Count,Storage Used (Byte),Issue Warning Quota (Byte),Prohibit Send Quota (Byte),Prohibit Send/Receive Quota (Byte),Deleted Item Count,Deleted Item Size (Byte),Deleted Item Quota (Byte),Has Archive,Report Period\n" +
		"2026-07-25,blank@m7kni.io,Blank User,False,,2025-08-08,,,23293152,105226698752,106300440576,107374182400,0,0,107374182400,False,7\n"
	rec := telemetrytest.New()
	c := New(f, nil)
	if err := c.Collect(context.Background(), rec.Emitter(), nil); err != nil {
		t.Fatalf("Collect: %v", err)
	}
	var twin *telemetrytest.LogRecord
	for i := range rec.LogRecords() {
		if rec.LogRecords()[i].EventName == eventName {
			twin = &rec.LogRecords()[i]
		}
	}
	if twin == nil {
		t.Fatal("no twin emitted")
	}
	if _, present := twin.Attrs[semconv.AttrItemCount]; present {
		t.Errorf("item_count present (%q) for a blank CSV cell, want omitted", twin.Attrs[semconv.AttrItemCount])
	}
	if _, present := twin.Attrs[semconv.AttrLastActivityDate]; present {
		t.Errorf("last_activity_date present for a blank CSV cell, want omitted")
	}
	if _, present := twin.Attrs[semconv.AttrDaysInactive]; present {
		t.Errorf("days_inactive present (%q) despite blank Last Activity Date — must never mean 'inactive forever'",
			twin.Attrs[semconv.AttrDaysInactive])
	}
}

func TestDaysInactiveDerivedFromInjectedClock(t *testing.T) {
	rec := telemetrytest.New()
	c := New(liveFake(), nil)
	c.now = func() time.Time { return time.Date(2026, 7, 28, 0, 0, 0, 0, time.UTC) }
	if err := c.Collect(context.Background(), rec.Emitter(), nil); err != nil {
		t.Fatalf("Collect: %v", err)
	}
	for _, l := range rec.LogRecords() {
		if l.EventName != eventName {
			continue
		}
		switch l.Attrs[semconv.AttrUserPrincipalName] {
		case "rob@m7kni.io": // Last Activity Date 2026-07-25 -> 3 days before injected now
			if l.Attrs[semconv.AttrDaysInactive] != "3" {
				t.Errorf("rob days_inactive = %q, want 3", l.Attrs[semconv.AttrDaysInactive])
			}
		case "vmuser@m7kni.io": // Last Activity Date 2026-07-21 -> 7 days before injected now
			if l.Attrs[semconv.AttrDaysInactive] != "7" {
				t.Errorf("vmuser days_inactive = %q, want 7", l.Attrs[semconv.AttrDaysInactive])
			}
		}
	}
}

func TestConcealmentSurfacedOnTwin(t *testing.T) {
	f := liveFake()
	f.reportSettings = concealedSettings
	rec := telemetrytest.New()
	c := New(f, nil)
	if err := c.Collect(context.Background(), rec.Emitter(), nil); err != nil {
		t.Fatalf("Collect: %v", err)
	}
	saw := false
	for _, l := range rec.LogRecords() {
		if l.EventName != eventName {
			continue
		}
		saw = true
		if l.Attrs[semconv.AttrNamesConcealed] != "true" {
			t.Errorf("names_concealed = %q, want true", l.Attrs[semconv.AttrNamesConcealed])
		}
	}
	if !saw {
		t.Fatal("no twins emitted")
	}
}

// TestConcealmentOmittedWhenSettingUnreadable pins that, unlike storage.go,
// this package has no evidenced heuristic fallback: names_concealed must be
// ABSENT (not defaulted false) when /admin/reportSettings cannot be read.
func TestConcealmentOmittedWhenSettingUnreadable(t *testing.T) {
	f := liveFake()
	f.reportSettingsErr = context.DeadlineExceeded
	rec := telemetrytest.New()
	c := New(f, nil)
	if err := c.Collect(context.Background(), rec.Emitter(), nil); err != nil {
		t.Fatalf("Collect: %v", err)
	}
	saw := false
	for _, l := range rec.LogRecords() {
		if l.EventName != eventName {
			continue
		}
		saw = true
		if _, present := l.Attrs[semconv.AttrNamesConcealed]; present {
			t.Errorf("names_concealed = %q present despite unreadable setting and no evidenced heuristic",
				l.Attrs[semconv.AttrNamesConcealed])
		}
	}
	if !saw {
		t.Fatal("no twins emitted")
	}
}

// TestCollectErrorsWhenAllReportsFail mirrors storage.go's #240 pin: when
// every usage report fails to fetch, Collect must surface an error rather than
// reporting success with nothing emitted.
func TestCollectErrorsWhenAllReportsFail(t *testing.T) {
	g := &fakeGraph{reportsErr: errors.New("429 ServiceThrottleThresholdExceeded")}
	rec := telemetrytest.New()
	outcomes := recordoutcome.NewRecorder()
	err := New(g, nil).Collect(context.Background(), rec.Emitter(), outcomes)
	if err == nil {
		t.Fatal("Collect returned nil despite all three reports failing")
	}
	if !strings.Contains(err.Error(), "all mailbox usage reports failed") {
		t.Errorf("error = %q, want it to name the all-reports-failed condition", err.Error())
	}
	got := outcomes.Snapshot().Summarize(err, false)
	if got.Result != recordoutcome.ResultFailure || got.Cause != recordoutcome.CauseSourceError {
		t.Errorf("outcome = %#v, want failure/source_error", got)
	}
}

// TestCollectSucceedsWhenReportsEmpty pins the other side: reports that succeed
// but return no rows are a legitimate empty tenant, not a failure.
func TestCollectSucceedsWhenReportsEmpty(t *testing.T) {
	g := &fakeGraph{} // all report bodies empty, no error
	rec := telemetrytest.New()
	outcomes := recordoutcome.NewRecorder()
	if err := New(g, nil).Collect(context.Background(), rec.Emitter(), outcomes); err != nil {
		t.Fatalf("Collect errored on legitimately-empty reports, want nil: %v", err)
	}
	got := outcomes.Snapshot().Summarize(nil, false)
	if got.Result != recordoutcome.ResultEmpty || got.Cause != recordoutcome.CauseNone {
		t.Errorf("outcome = %#v, want empty/none", got)
	}
}

// TestCollectSurvivesPartialReportFailure pins that a SINGLE report failing
// stays best-effort/non-fatal.
func TestCollectSurvivesPartialReportFailure(t *testing.T) {
	f := liveFake()
	f.storage = ""
	rec := telemetrytest.New()
	c := New(f, nil)
	if err := c.Collect(context.Background(), rec.Emitter(), nil); err != nil {
		t.Fatalf("Collect errored on a single-report failure, want non-fatal: %v", err)
	}
	// Detail twins still emitted.
	twins := 0
	for _, l := range rec.LogRecords() {
		if l.EventName == eventName {
			twins++
		}
	}
	if twins != 2 {
		t.Errorf("emitted %d twins with storage report empty, want 2 (detail unaffected)", twins)
	}
}

// TestParsesReportWithBOM pins that a BOM-prefixed report body does not
// corrupt the first header (mirrors storage.go's identical concern, reusing
// storage's already-proven parseCSV behavior copied into this package).
func TestParsesReportWithBOM(t *testing.T) {
	f := liveFake()
	f.detail = "\ufeff" + liveDetail
	rec := telemetrytest.New()
	c := New(f, nil)
	if err := c.Collect(context.Background(), rec.Emitter(), nil); err != nil {
		t.Fatalf("Collect: %v", err)
	}
	twins := 0
	for _, l := range rec.LogRecords() {
		if l.EventName == eventName {
			twins++
		}
	}
	if twins != 2 {
		t.Errorf("BOM-prefixed detail report emitted %d twins, want 2", twins)
	}
}

// TestMetricsCarryNoPerEntityIdentity pins #112: neither metric may carry a
// UPN or display-name label.
func TestMetricsCarryNoPerEntityIdentity(t *testing.T) {
	rec := telemetrytest.New()
	c := New(liveFake(), nil)
	if err := c.Collect(context.Background(), rec.Emitter(), nil); err != nil {
		t.Fatalf("Collect: %v", err)
	}
	for _, name := range []string{metricStorageUsed, metricQuotaStatus} {
		for _, p := range rec.MetricPoints(name) {
			for k := range p.Attrs {
				if k == semconv.AttrUserPrincipalName || k == semconv.AttrDisplayName {
					t.Errorf("metric %s carries per-entity label %q", name, k)
				}
			}
		}
	}
}
