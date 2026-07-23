// Package storage reports SharePoint + OneDrive storage utilization (#120):
// tenant-level capacity totals plus per-drive quota state, so a tenant nearing
// its storage ceiling trends on a dashboard weeks before uploads and sync start
// failing.
//
// It is built on the M365 usage-reporting API (getSharePointSiteUsageStorage,
// getOneDriveUsageStorage, and the two *Detail functions), reachable app-only
// under the already-held Reports.Read.All. The live per-drive `quota` facet
// (/sites/{id}/drive) — which carries Microsoft's authoritative quota `state`
// and a `deleted` byte count — was probed and needs Sites.Read.All +
// Files.Read.All (read-everything-in-SharePoint), a disproportionate grant for a
// capacity signal, so this collector derives quota_state from used/allocated
// instead and does not emit a deleted-bytes series. [live-measured 2026-07-18, #120]
//
// Cardinality (#112): per-drive identity — owner UPN, site URL, drive id — rides
// the log twin only, never a metric label. Metrics carry bounded tenant-shaped
// aggregates and a per-(drive_type,quota_state) drive count.
package storage

import (
	"bytes"
	"context"
	"encoding/csv"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"strconv"
	"strings"
	"time"

	"github.com/rknightion/graph2otel/internal/collector"
	"github.com/rknightion/graph2otel/internal/collectors"
	"github.com/rknightion/graph2otel/internal/semconv"
	"github.com/rknightion/graph2otel/internal/telemetry"
)

const (
	collectorName  = "m365.storage"
	eventName      = "m365.drive_storage"
	defaultBaseURL = "https://graph.microsoft.com/v1.0"

	metricUsed   = "m365.storage.used_bytes"
	metricTotal  = "m365.storage.total_bytes"
	metricDrives = "m365.storage.drives.total"

	driveTypeSharePoint = "sharepoint"
	driveTypeOneDrive   = "onedrive"

	// Derived quota states (used/allocated), mirroring Microsoft's own facet
	// vocabulary but computed here — the live `state` verdict needs broad scopes
	// (see the package doc). Thresholds are documented on the metric.
	stateNormal   = "normal"
	stateNearing  = "nearing"
	stateCritical = "critical"
	stateExceeded = "exceeded"
	stateUnknown  = "unknown"

	nearingRatio  = 0.75
	criticalRatio = 0.90

	// The all-zeros GUID Microsoft substitutes for Site Id when report
	// concealment (displayConcealedNames) is on — the heuristic fallback when
	// /admin/reportSettings is unreadable.
	concealedSiteID = "00000000-0000-0000-0000-000000000000"
)

// report identifies one usage-report function and the drive_type its rows map to.
type report struct {
	fn        string // OData function, e.g. getSharePointSiteUsageStorage
	driveType string
}

var (
	spStorageReport = report{"getSharePointSiteUsageStorage(period='D7')", driveTypeSharePoint}
	odStorageReport = report{"getOneDriveUsageStorage(period='D7')", driveTypeOneDrive}
	spDetailReport  = report{"getSharePointSiteUsageDetail(period='D7')", driveTypeSharePoint}
	odDetailReport  = report{"getOneDriveUsageAccountDetail(period='D7')", driveTypeOneDrive}
)

// reportCount is the number of usage reports Collect fetches; all of them
// failing is the #240 total-failure condition.
const reportCount = 4

var (

	// The full (drive_type, quota_state) grid, so every bucket reports an explicit
	// count each cycle — healthy states report 0 for stable alert baselines.
	driveTypes  = []string{driveTypeSharePoint, driveTypeOneDrive}
	quotaStates = []string{stateNormal, stateNearing, stateCritical, stateExceeded, stateUnknown}
)

// Collector polls the M365 storage usage reports.
type Collector struct {
	g       collectors.GraphClient
	baseURL string
	logger  *slog.Logger
}

// New builds the storage collector. A nil logger falls back to the slog default.
func New(g collectors.GraphClient, logger *slog.Logger) *Collector {
	if logger == nil {
		logger = slog.Default()
	}
	return &Collector{g: g, baseURL: defaultBaseURL, logger: logger}
}

// Name implements collector.Collector.
func (c *Collector) Name() string { return collectorName }

// DefaultInterval implements collector.Collector. The usage reports refresh at
// most daily, so a 6h poll is ample and keeps staleness bounded.
func (c *Collector) DefaultInterval() time.Duration { return 6 * time.Hour }

// RequiredPermissions declares the least-privilege Graph application scope. The
// concealment check (/admin/reportSettings) optionally uses ReportSettings.Read.All;
// without it the collector falls back to a heuristic, so it is not required here.
func (c *Collector) RequiredPermissions() []string {
	return []string{"Reports.Read.All"}
}

// Collect fetches the usage reports and emits tenant aggregates + per-drive twins.
// Each report is best-effort: a report that is unavailable (e.g. usage reports do
// not exist in sovereign clouds) is skipped with a warning, not fatal.
func (c *Collector) Collect(ctx context.Context, e telemetry.Emitter) error {
	concealed, settingKnown := c.readConcealment(ctx)

	// Fetch all four reports, tracking which FAILED (as opposed to being
	// legitimately empty). #240: when every report fails, the collector must NOT
	// report success with an all-zero drive grid — that is the "100% success on
	// zero data" lie. A failure of SOME reports stays best-effort/non-fatal (a
	// sovereign cloud legitimately lacks some usage reports — see fetch).
	spStorageRows, spStorageErr := c.fetch(ctx, spStorageReport)
	odStorageRows, odStorageErr := c.fetch(ctx, odStorageReport)
	spRows, spDetailErr := c.fetch(ctx, spDetailReport)
	odRows, odDetailErr := c.fetch(ctx, odDetailReport)

	var fetchErrs []error
	for _, fe := range []struct {
		fn  string
		err error
	}{
		{spStorageReport.fn, spStorageErr},
		{odStorageReport.fn, odStorageErr},
		{spDetailReport.fn, spDetailErr},
		{odDetailReport.fn, odDetailErr},
	} {
		if fe.err != nil {
			fetchErrs = append(fetchErrs, fmt.Errorf("%s: %w", fe.fn, fe.err))
		}
	}

	spUsed, spUsedOK := latestTenantUsed(spStorageRows)
	odUsed, odUsedOK := latestTenantUsed(odStorageRows)

	// Heuristic concealment detection when the setting itself is unreadable: if
	// every detail row has the zeroed Site Id, names are concealed.
	if !settingKnown {
		concealed = allConcealed(spRows) && allConcealed(odRows) && (len(spRows)+len(odRows) > 0)
	}
	if concealed {
		c.logger.Warn("m365.storage: report name concealment is ON — owner/site columns are hashed; storage bytes are unaffected",
			"collector", collectorName)
	}

	// Tenant used, by drive type.
	if spUsedOK {
		e.Gauge(metricUsed, "By", "Tenant SharePoint storage used, in bytes.", spUsed,
			telemetry.Attrs{semconv.AttrDriveType: driveTypeSharePoint})
	}
	if odUsedOK {
		e.Gauge(metricUsed, "By", "Tenant OneDrive storage used, in bytes.", odUsed,
			telemetry.Attrs{semconv.AttrDriveType: driveTypeOneDrive})
	}

	// Tenant total (allocated). SharePoint is a pooled model — every site's
	// Storage Allocated is the same tenant ceiling, so take the max (not the sum).
	// OneDrive quotas are per-user, so they sum.
	if spTotal, ok := maxAllocated(spRows); ok {
		e.Gauge(metricTotal, "By", "Tenant SharePoint storage quota (pooled ceiling), in bytes.", spTotal,
			telemetry.Attrs{semconv.AttrDriveType: driveTypeSharePoint})
	}
	if odTotal, ok := sumAllocated(odRows); ok {
		e.Gauge(metricTotal, "By", "Total provisioned OneDrive quota (sum of per-user), in bytes.", odTotal,
			telemetry.Attrs{semconv.AttrDriveType: driveTypeOneDrive})
	}

	// Per-drive twins + quota-state bucket counts.
	counts := map[string]map[string]float64{}
	for _, dt := range driveTypes {
		counts[dt] = map[string]float64{}
		for _, st := range quotaStates {
			counts[dt][st] = 0
		}
	}
	for _, r := range spRows {
		st := c.emitTwin(e, driveTypeSharePoint, r, concealed, true)
		counts[driveTypeSharePoint][st]++
	}
	for _, r := range odRows {
		st := c.emitTwin(e, driveTypeOneDrive, r, concealed, false)
		counts[driveTypeOneDrive][st]++
	}

	points := make([]telemetry.GaugePoint, 0, len(driveTypes)*len(quotaStates))
	for _, dt := range driveTypes {
		for _, st := range quotaStates {
			points = append(points, telemetry.GaugePoint{
				Value: counts[dt][st],
				Attrs: telemetry.Attrs{semconv.AttrDriveType: dt, semconv.AttrQuotaState: st},
			})
		}
	}
	e.GaugeSnapshot(metricDrives, "{drive}",
		"Count of drives per derived quota state (normal <75% used, nearing >=75%, critical >=90%, exceeded >=100%).",
		points)

	// #240: every report failed — the drive grid above is an all-zero fabrication,
	// not a healthy tenant. Surface it as a collector failure instead of silently
	// reporting success. A partial failure is intentionally non-fatal.
	if len(fetchErrs) == reportCount {
		return fmt.Errorf("m365.storage: all storage reports failed: %w", errors.Join(fetchErrs...))
	}
	return nil
}

// emitTwin emits one m365.drive_storage log for a detail row and returns the
// derived quota state (so the caller can bucket it). isSP toggles the
// SharePoint-only Root Web Template attribute.
func (c *Collector) emitTwin(e telemetry.Emitter, driveType string, row map[string]string, concealed, isSP bool) string {
	used := parseNum(row["Storage Used (Byte)"])
	allocated := parseNum(row["Storage Allocated (Byte)"])
	state := quotaState(used, allocated)

	attrs := telemetry.Attrs{semconv.AttrDriveType: driveType, semconv.AttrQuotaState: state}
	telemetry.SetStr(attrs, semconv.AttrSiteId, row["Site Id"])
	telemetry.SetStr(attrs, semconv.AttrSiteUrl, row["Site URL"])
	telemetry.SetStr(attrs, semconv.AttrOwnerDisplayName, row["Owner Display Name"])
	telemetry.SetStr(attrs, semconv.AttrOwnerPrincipalName, row["Owner Principal Name"])
	telemetry.SetStr(attrs, semconv.AttrLastActivityDate, row["Last Activity Date"])
	telemetry.SetBool(attrs, semconv.AttrIsDeleted, strings.EqualFold(row["Is Deleted"], "true"))
	telemetry.SetBool(attrs, semconv.AttrNamesConcealed, concealed)
	if isSP {
		telemetry.SetStr(attrs, semconv.AttrRootWebTemplate, row["Root Web Template"])
	}
	attrs[semconv.AttrStorageUsedBytes] = used
	attrs[semconv.AttrStorageAllocatedBytes] = allocated
	if allocated > 0 {
		remaining := allocated - used
		if remaining < 0 {
			remaining = 0
		}
		attrs[semconv.AttrStorageRemainingBytes] = remaining
	}
	attrs[semconv.AttrFileCount] = parseNum(row["File Count"])
	if v, ok := row["Active File Count"]; ok {
		attrs[semconv.AttrActiveFileCount] = parseNum(v)
	}

	sev := telemetry.SeverityInfo
	switch state {
	case stateExceeded:
		sev = telemetry.SeverityError
	case stateCritical:
		sev = telemetry.SeverityWarn
	}
	e.LogEvent(telemetry.Event{
		Name:     eventName,
		Body:     fmt.Sprintf("%s drive storage: %s (%s used of %s)", driveType, state, humanBytes(used), humanBytes(allocated)),
		Severity: sev,
		Attrs:    attrs,
	})
	return state
}

// readConcealment reads the tenant report-concealment setting. Returns
// (concealed, known); known is false when the setting could not be read (e.g. no
// ReportSettings.Read.All), so the caller falls back to a data heuristic.
func (c *Collector) readConcealment(ctx context.Context) (bool, bool) {
	raw, err := c.g.RawGet(ctx, c.baseURL+"/admin/reportSettings")
	if err != nil || len(raw) == 0 {
		return false, false
	}
	var s struct {
		DisplayConcealedNames bool `json:"displayConcealedNames"`
	}
	if err := json.Unmarshal(raw, &s); err != nil {
		return false, false
	}
	return s.DisplayConcealedNames, true
}

// latestTenantUsed reads a storage timeseries report's rows and returns the
// latest tenant total (Site Type "All", max Report Date). ok is false when the
// rows are empty. It is a pure function over already-fetched rows so Collect can
// track the fetch error separately (#240).
func latestTenantUsed(rows []map[string]string) (float64, bool) {
	if len(rows) == 0 {
		return 0, false
	}
	var latestDate string
	var latestUsed float64
	found := false
	for _, row := range rows {
		if !strings.EqualFold(row["Site Type"], "All") {
			continue
		}
		if d := row["Report Date"]; d >= latestDate {
			latestDate = d
			latestUsed = parseNum(row["Storage Used (Byte)"])
			found = true
		}
	}
	return latestUsed, found
}

// fetch GETs a report (RawGet follows the 302 to the CSV) and parses it. It
// returns the parsed rows and any fetch/parse error. A failure is logged and
// returned: Collect keeps a SINGLE report's failure best-effort (non-fatal), but
// treats ALL reports failing as a collector failure rather than false success
// (#240). An empty-but-successful report returns (nil, nil) — that is legitimate
// steady state on a small tenant, distinct from a failure.
func (c *Collector) fetch(ctx context.Context, r report) ([]map[string]string, error) {
	raw, err := c.g.RawGet(ctx, c.baseURL+"/reports/"+r.fn)
	if err != nil {
		c.logger.Warn("m365.storage: report unavailable, skipping",
			"collector", collectorName, "report", r.fn, "error", err)
		return nil, err
	}
	rows, err := parseCSV(raw)
	if err != nil {
		c.logger.Warn("m365.storage: report parse failed, skipping",
			"collector", collectorName, "report", r.fn, "error", err)
		return nil, err
	}
	return rows, nil
}

// parseCSV parses a usage-report CSV into header-keyed rows. It strips a leading
// UTF-8 BOM (which would corrupt the first header) and runs the reader with
// LazyQuotes + a variable field count, mirroring the export-job CSV handling.
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

// quotaState derives a bounded quota state from used/allocated bytes.
func quotaState(used, allocated float64) string {
	if allocated <= 0 {
		return stateUnknown
	}
	switch ratio := used / allocated; {
	case ratio >= 1.0:
		return stateExceeded
	case ratio >= criticalRatio:
		return stateCritical
	case ratio >= nearingRatio:
		return stateNearing
	default:
		return stateNormal
	}
}

// maxAllocated returns the largest Storage Allocated across rows (the pooled
// SharePoint ceiling). ok is false when no row carries a positive allocation.
func maxAllocated(rows []map[string]string) (float64, bool) {
	var max float64
	found := false
	for _, r := range rows {
		if a := parseNum(r["Storage Allocated (Byte)"]); a > max {
			max = a
			found = true
		}
	}
	return max, found
}

// sumAllocated returns the sum of Storage Allocated across rows (additive
// per-user OneDrive quotas). ok is false when no row carries an allocation.
func sumAllocated(rows []map[string]string) (float64, bool) {
	var sum float64
	found := false
	for _, r := range rows {
		if a := parseNum(r["Storage Allocated (Byte)"]); a > 0 {
			sum += a
			found = true
		}
	}
	return sum, found
}

// allConcealed reports whether every row has the zeroed Site Id Microsoft
// substitutes under report concealment. False for an empty set.
func allConcealed(rows []map[string]string) bool {
	if len(rows) == 0 {
		return false
	}
	for _, r := range rows {
		if r["Site Id"] != concealedSiteID {
			return false
		}
	}
	return true
}

func parseNum(s string) float64 {
	f, _ := strconv.ParseFloat(strings.TrimSpace(s), 64)
	return f
}

// humanBytes renders a byte count for the log body (not for metrics).
func humanBytes(b float64) string {
	const unit = 1024
	if b < unit {
		return fmt.Sprintf("%.0f B", b)
	}
	div, exp := float64(unit), 0
	for n := b / unit; n >= unit && exp < 4; n /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %ciB", b/div, "KMGTP"[exp])
}

func init() {
	collectors.Register(func(d collectors.Deps) collector.SnapshotCollector {
		return New(d.Graph, d.Logger)
	})
}

var _ collector.SnapshotCollector = (*Collector)(nil)
