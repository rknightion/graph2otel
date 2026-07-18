package storage

import (
	"context"
	"strings"
	"testing"

	"github.com/rknightion/graph2otel/internal/collectors"
	"github.com/rknightion/graph2otel/internal/semconv"
	"github.com/rknightion/graph2otel/internal/telemetrytest"
)

// fakeGraph routes each report URL to a canned CSV body, matched on the report
// function name. reportSettings returns the concealment setting as JSON.
type fakeGraph struct {
	spStorage, odStorage, spDetail, odDetail string
	reportSettings                           string
	reportSettingsErr                        error
}

func (f *fakeGraph) RawGet(_ context.Context, url string) ([]byte, error) {
	switch {
	case strings.Contains(url, "getSharePointSiteUsageStorage"):
		return []byte(f.spStorage), nil
	case strings.Contains(url, "getOneDriveUsageStorage"):
		return []byte(f.odStorage), nil
	case strings.Contains(url, "getSharePointSiteUsageDetail"):
		return []byte(f.spDetail), nil
	case strings.Contains(url, "getOneDriveUsageAccountDetail"):
		return []byte(f.odDetail), nil
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

// Real column shapes captured off m7kni as graph2otel-poller (2026-07-18, #120),
// with concealment ON (Site Id zeroed, Site URL blank, owner names hashed) —
// storage bytes are real. The synthetic near-quota OneDrive rows exercise the
// derived quota_state buckets deterministically.
const (
	// Tenant SP storage timeseries: latest Report Date (2026-07-16) is the total.
	liveSPStorage = "Report Refresh Date,Site Type,Storage Used (Byte),Report Date,Report Period\n" +
		"2026-07-16,All,17402422,2026-07-16,7\n" +
		"2026-07-16,All,17384400,2026-07-15,7\n"

	// Tenant OneDrive storage timeseries: both "OneDrive" and "All" Site Type rows;
	// "All" is the tenant total.
	liveODStorage = "Report Refresh Date,Site Type,Storage Used (Byte),Report Date,Report Period\n" +
		"2026-07-16,OneDrive,530866,2026-07-16,7\n" +
		"2026-07-16,All,530866,2026-07-16,7\n" +
		"2026-07-16,OneDrive,530265,2026-07-15,7\n"

	// Two SP sites, pooled model: Storage Allocated is the uniform tenant ceiling
	// (~25 TiB) repeated, so tenant SP total = that ceiling, NOT the sum.
	liveSPDetail = "Report Refresh Date,Site Id,Site URL,Owner Display Name,Is Deleted,Last Activity Date,File Count,Active File Count,Page View Count,Visited Page Count,Storage Used (Byte),Storage Allocated (Byte),Root Web Template,Owner Principal Name,Report Period\n" +
		"2026-07-16,00000000-0000-0000-0000-000000000000,,D86B84272437349ED168F20E2582FBE5,False,,0,0,0,0,1414951,27487790694400,Group,89D12351D71C5B7F17BF2A13C9EB250A,7\n" +
		"2026-07-16,00000000-0000-0000-0000-000000000000,,C15E1AEB922AF1CAB16233DA7F5A4B2F,False,,0,0,0,0,1468006,27487790694400,Group,234B61CDA5A91E499BDDE1C42B1CDA46,7\n"

	// OneDrive accounts: one healthy (203 KB / 1 TiB), one near quota (95% of
	// 10 GiB -> critical), one over quota (exceeded). Per-user allocated is
	// additive: 1099511627776 + 10737418240 + 10737418240.
	liveODDetail = "Report Refresh Date,Site Id,Site URL,Owner Display Name,Is Deleted,Last Activity Date,File Count,Active File Count,Storage Used (Byte),Storage Allocated (Byte),Owner Principal Name,Report Period\n" +
		"2026-07-16,00000000-0000-0000-0000-000000000000,,B64192E6A94FED76C267ADC6276168DC,False,2026-07-15,2,1,203051,1099511627776,9B8EEF2AF0E01A5DD926319F6F043B56,7\n" +
		"2026-07-16,00000000-0000-0000-0000-000000000000,,2A2B92F92ADA11852D702B4F19C2B95B,False,,20,0,10200000000,10737418240,26AF2339011374325CF6A310EEB7C424,7\n" +
		"2026-07-16,00000000-0000-0000-0000-000000000000,,3B3C92F92ADA11852D702B4F19C2B95C,False,,20,0,11000000000,10737418240,36BF2339011374325CF6A310EEB7C425,7\n"

	concealedSettings   = `{"displayConcealedNames": true}`
	unconcealedSettings = `{"displayConcealedNames": false}`
)

func liveFake() *fakeGraph {
	return &fakeGraph{
		spStorage: liveSPStorage, odStorage: liveODStorage,
		spDetail: liveSPDetail, odDetail: liveODDetail,
		reportSettings: concealedSettings,
	}
}

func TestCollectEmitsTenantTotalsByDriveType(t *testing.T) {
	rec := telemetrytest.New()
	c := New(liveFake(), nil)
	if err := c.Collect(context.Background(), rec.Emitter()); err != nil {
		t.Fatalf("Collect: %v", err)
	}

	used := map[string]float64{}
	for _, p := range rec.MetricPoints(metricUsed) {
		used[p.Attrs[semconv.AttrDriveType]] = p.Value
	}
	if used[driveTypeSharePoint] != 17402422 {
		t.Errorf("SP used = %v, want 17402422", used[driveTypeSharePoint])
	}
	if used[driveTypeOneDrive] != 530866 {
		t.Errorf("OneDrive used = %v, want 530866", used[driveTypeOneDrive])
	}

	total := map[string]float64{}
	for _, p := range rec.MetricPoints(metricTotal) {
		total[p.Attrs[semconv.AttrDriveType]] = p.Value
	}
	// SP pooled ceiling (max, not sum).
	if total[driveTypeSharePoint] != 27487790694400 {
		t.Errorf("SP total = %v, want 27487790694400 (pooled ceiling)", total[driveTypeSharePoint])
	}
	// OneDrive per-user quotas summed.
	if want := 1099511627776.0 + 10737418240 + 10737418240; total[driveTypeOneDrive] != want {
		t.Errorf("OneDrive total = %v, want %v (sum of per-user)", total[driveTypeOneDrive], want)
	}
}

func TestCollectBucketsDrivesByDerivedQuotaState(t *testing.T) {
	rec := telemetrytest.New()
	c := New(liveFake(), nil)
	if err := c.Collect(context.Background(), rec.Emitter()); err != nil {
		t.Fatalf("Collect: %v", err)
	}

	// (drive_type, quota_state) -> count. The full grid is always emitted, so
	// healthy states report explicit zeros for stable alert baselines.
	got := map[[2]string]float64{}
	for _, p := range rec.MetricPoints(metricDrives) {
		got[[2]string{p.Attrs[semconv.AttrDriveType], p.Attrs[semconv.AttrQuotaState]}] = p.Value
	}
	// Two SP sites, both tiny vs the 25 TiB ceiling -> normal.
	if got[[2]string{driveTypeSharePoint, stateNormal}] != 2 {
		t.Errorf("SP normal = %v, want 2", got[[2]string{driveTypeSharePoint, stateNormal}])
	}
	// OneDrive: one normal, one critical (95%), one exceeded (>100%).
	if got[[2]string{driveTypeOneDrive, stateNormal}] != 1 {
		t.Errorf("OneDrive normal = %v, want 1", got[[2]string{driveTypeOneDrive, stateNormal}])
	}
	if got[[2]string{driveTypeOneDrive, stateCritical}] != 1 {
		t.Errorf("OneDrive critical = %v, want 1", got[[2]string{driveTypeOneDrive, stateCritical}])
	}
	if got[[2]string{driveTypeOneDrive, stateExceeded}] != 1 {
		t.Errorf("OneDrive exceeded = %v, want 1", got[[2]string{driveTypeOneDrive, stateExceeded}])
	}
	// Baseline zero is present for an unpopulated state.
	if _, ok := got[[2]string{driveTypeOneDrive, stateNearing}]; !ok {
		t.Errorf("OneDrive nearing baseline series missing; want an explicit 0")
	}
}

func TestCollectEmitsOneLogTwinPerDrive(t *testing.T) {
	rec := telemetrytest.New()
	c := New(liveFake(), nil)
	if err := c.Collect(context.Background(), rec.Emitter()); err != nil {
		t.Fatalf("Collect: %v", err)
	}

	logs := rec.LogRecords()
	twins := 0
	var oneOverQuota *telemetrytest.LogRecord
	for i := range logs {
		if logs[i].EventName != eventName {
			continue
		}
		twins++
		if logs[i].Attrs[semconv.AttrQuotaState] == stateExceeded {
			oneOverQuota = &logs[i]
		}
	}
	// 2 SP sites + 3 OneDrive accounts = 5 twins.
	if twins != 5 {
		t.Fatalf("emitted %d %s twins, want 5", twins, eventName)
	}
	if oneOverQuota == nil {
		t.Fatalf("no exceeded-quota twin emitted")
	}
	if oneOverQuota.Attrs[semconv.AttrDriveType] != driveTypeOneDrive {
		t.Errorf("exceeded twin drive_type = %q, want onedrive", oneOverQuota.Attrs[semconv.AttrDriveType])
	}
	if oneOverQuota.SeverityText == "" || oneOverQuota.SeverityNumber == 0 {
		t.Errorf("exceeded twin should carry an elevated severity, got %q", oneOverQuota.SeverityText)
	}
}

// Per #112, per-entity identity must never ride a metric label: no owner UPN,
// site URL, or hashed owner id may appear on any storage metric.
func TestMetricsCarryNoPerEntityIdentity(t *testing.T) {
	rec := telemetrytest.New()
	c := New(liveFake(), nil)
	if err := c.Collect(context.Background(), rec.Emitter()); err != nil {
		t.Fatalf("Collect: %v", err)
	}
	for _, name := range []string{metricUsed, metricTotal, metricDrives} {
		for _, p := range rec.MetricPoints(name) {
			for k := range p.Attrs {
				switch k {
				case semconv.AttrOwnerPrincipalName, semconv.AttrOwnerDisplayName,
					semconv.AttrSiteUrl, semconv.AttrSiteId, semconv.AttrUserPrincipalName:
					t.Errorf("metric %s carries per-entity label %q", name, k)
				}
			}
		}
	}
}

func TestConcealmentReflectedOnTwin(t *testing.T) {
	rec := telemetrytest.New()
	c := New(liveFake(), nil) // reportSettings says concealed
	if err := c.Collect(context.Background(), rec.Emitter()); err != nil {
		t.Fatalf("Collect: %v", err)
	}
	for _, l := range rec.LogRecords() {
		if l.EventName != eventName {
			continue
		}
		if l.Attrs[semconv.AttrNamesConcealed] != "true" {
			t.Errorf("twin names_concealed = %q, want true", l.Attrs[semconv.AttrNamesConcealed])
		}
	}
}

func TestConcealmentDetectedHeuristicallyWhenSettingUnreadable(t *testing.T) {
	f := liveFake()
	f.reportSettingsErr = context.DeadlineExceeded // e.g. 403 without ReportSettings.Read.All
	rec := telemetrytest.New()
	c := New(f, nil)
	if err := c.Collect(context.Background(), rec.Emitter()); err != nil {
		t.Fatalf("Collect: %v", err)
	}
	// Setting unreadable, but every Site Id is zeroed -> heuristic concludes concealed.
	saw := false
	for _, l := range rec.LogRecords() {
		if l.EventName != eventName {
			continue
		}
		saw = true
		if l.Attrs[semconv.AttrNamesConcealed] != "true" {
			t.Errorf("twin names_concealed = %q, want true (heuristic)", l.Attrs[semconv.AttrNamesConcealed])
		}
	}
	if !saw {
		t.Fatal("no twins emitted")
	}
}

func TestUnconcealedPassesRealIdentityThrough(t *testing.T) {
	f := &fakeGraph{
		spStorage: liveSPStorage, odStorage: liveODStorage,
		spDetail: "Report Refresh Date,Site Id,Site URL,Owner Display Name,Is Deleted,Last Activity Date,File Count,Active File Count,Page View Count,Visited Page Count,Storage Used (Byte),Storage Allocated (Byte),Root Web Template,Owner Principal Name,Report Period\n" +
			"2026-07-16,contoso.sharepoint.com|abc,https://contoso.sharepoint.com/sites/eng,Eng Team,False,2026-07-15,42,7,10,5,5000000000,27487790694400,Group,eng@contoso.com,7\n",
		odDetail:       "Report Refresh Date,Site Id,Site URL,Owner Display Name,Is Deleted,Last Activity Date,File Count,Active File Count,Storage Used (Byte),Storage Allocated (Byte),Owner Principal Name,Report Period\n",
		reportSettings: unconcealedSettings,
	}
	rec := telemetrytest.New()
	c := New(f, nil)
	if err := c.Collect(context.Background(), rec.Emitter()); err != nil {
		t.Fatalf("Collect: %v", err)
	}
	var twin *telemetrytest.LogRecord
	for i := range rec.LogRecords() {
		if rec.LogRecords()[i].EventName == eventName {
			twin = &rec.LogRecords()[i]
			break
		}
	}
	if twin == nil {
		t.Fatal("no twin")
	}
	if got := twin.Attrs[semconv.AttrOwnerPrincipalName]; got != "eng@contoso.com" {
		t.Errorf("owner UPN = %q, want eng@contoso.com (must ship per #112)", got)
	}
	if got := twin.Attrs[semconv.AttrSiteUrl]; got != "https://contoso.sharepoint.com/sites/eng" {
		t.Errorf("site URL = %q, want the real URL", got)
	}
	if twin.Attrs[semconv.AttrNamesConcealed] == "true" {
		t.Errorf("names_concealed should be false/absent for an unconcealed tenant")
	}
}

// A BOM-prefixed report body must not corrupt the first header.
func TestParsesReportWithBOM(t *testing.T) {
	f := liveFake()
	f.spStorage = "\ufeff" + liveSPStorage
	rec := telemetrytest.New()
	c := New(f, nil)
	if err := c.Collect(context.Background(), rec.Emitter()); err != nil {
		t.Fatalf("Collect: %v", err)
	}
	for _, p := range rec.MetricPoints(metricUsed) {
		if p.Attrs[semconv.AttrDriveType] == driveTypeSharePoint && p.Value != 17402422 {
			t.Errorf("BOM-prefixed SP used = %v, want 17402422", p.Value)
		}
	}
}

// A report that errors (e.g. unavailable in a sovereign cloud) is skipped, not
// fatal: the collector still emits from the reports that succeeded.
func TestSkipsUnavailableReportWithoutFailing(t *testing.T) {
	f := liveFake()
	f.odStorage = "" // getOneDriveUsageStorage returns empty/unavailable
	f.odDetail = ""  // and its detail too
	rec := telemetrytest.New()
	c := New(f, nil)
	if err := c.Collect(context.Background(), rec.Emitter()); err != nil {
		t.Fatalf("Collect must not fail when one report is unavailable: %v", err)
	}
	// SP still emitted.
	sp := false
	for _, p := range rec.MetricPoints(metricUsed) {
		if p.Attrs[semconv.AttrDriveType] == driveTypeSharePoint {
			sp = true
		}
	}
	if !sp {
		t.Error("SP used should still be emitted when OneDrive reports are unavailable")
	}
}
