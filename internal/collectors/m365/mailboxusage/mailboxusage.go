// Package mailboxusage reports Exchange mailbox storage, quota status, and
// inactivity (#359): tenant-level mailbox storage used, a bounded count of
// mailboxes per Microsoft quota-status bucket, and one usage twin per mailbox
// (item count, storage used, the three quota thresholds, deleted-item
// counters, last-activity date, and archive presence) — so a mailbox nearing
// its send/receive quota, or one that has gone dark, surfaces before it starts
// bouncing mail.
//
// It is built on the same M365 usage-reporting transport
// internal/collectors/m365/storage already hardened: RawGet follows the
// report's 302 redirect to a CSV, reachable app-only under the already-held
// Reports.Read.All. Report concealment (/admin/reportSettings) is read the
// same way storage reads it. Unlike storage, this package does NOT fall back
// to a data heuristic when the setting is unreadable: storage's heuristic is
// backed by an observed sentinel (Microsoft zeroes Site Id under
// concealment), and no analogous sentinel has been observed on
// getMailboxUsageDetail's User Principal Name / Display Name columns. Per
// this repo's wirecheck philosophy, a heuristic with no evidence behind it is
// worse than none, so when /admin/reportSettings is unreadable the twin
// simply omits names_concealed rather than asserting a value nobody has
// measured.
//
// Three reports are fetched:
//   - getMailboxUsageDetail: one row per mailbox, no Report Date column — the
//     detail feeding the per-mailbox log twin.
//   - getMailboxUsageStorage: one row PER DAY of the period, tenant-wide
//     storage used. Only the row with the most recent Report Date is
//     emitted — the earlier days are history the wire happens to repeat on
//     every poll, and re-emitting them would restate the same days forever.
//     Report Date sorts lexically ("2026-07-25" >= "2026-07-24"), the same
//     trick storage's latestTenantUsed uses, but rows are NOT assumed to
//     arrive in date order — see mailboxusage_test.go's
//     TestPicksLatestStorageRowRegardlessOfOrder.
//   - getMailboxUsageQuotaStatusMailboxCounts: also one row per day, same
//     latest-Report-Date selection, five fixed count columns (Under Limit /
//     Warning Issued / Send Prohibited / Send/Receive Prohibited /
//     Indeterminate) that become the bounded quota-status gauge.
//
// Cardinality (#112): mailbox identity (UPN, display name) rides the log twin
// only, never a metric label. The quota-status gauge is bounded by
// construction — Microsoft's fixed five-bucket vocabulary, independent of
// tenant size.
//
// Absent-field handling: an empty CSV cell (e.g. Deleted Date on a
// non-deleted mailbox, or Last Activity Date on a mailbox that has never been
// used) is OMITTED from the twin, never coerced to a zero, false, or epoch
// value — see mailboxusage_test.go's TestBlankCellsAreOmittedNotFabricated.
// days_inactive is derived from Last Activity Date and an injectable clock
// (Collector.now); it is omitted entirely when Last Activity Date is blank or
// unparseable, never treated as "inactive forever".
package mailboxusage

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
	"github.com/rknightion/graph2otel/internal/recordoutcome"
	"github.com/rknightion/graph2otel/internal/semconv"
	"github.com/rknightion/graph2otel/internal/telemetry"
)

const (
	collectorName  = "m365.mailbox_usage"
	eventName      = "m365.mailbox_usage"
	defaultBaseURL = "https://graph.microsoft.com/v1.0"

	// metricStorageUsed is the tenant-wide mailbox storage used, in bytes. One
	// series, no per-entity label.
	metricStorageUsed = "m365.mailbox_usage.storage_used_bytes"
	// metricQuotaStatus is the bounded count of mailboxes per Microsoft
	// quota-status bucket (semconv.AttrQuotaState).
	metricQuotaStatus = "m365.mailbox_usage.quota_status.mailboxes"

	// Microsoft's own mailbox quota-status vocabulary (from
	// getMailboxUsageQuotaStatusMailboxCounts's column headers), distinct from
	// the derived normal/nearing/critical/exceeded states
	// internal/collectors/m365/storage computes for drives.
	quotaStateUnderLimit            = "under_limit"
	quotaStateWarningIssued         = "warning_issued"
	quotaStateSendProhibited        = "send_prohibited"
	quotaStateSendReceiveProhibited = "send_receive_prohibited"
	quotaStateIndeterminate         = "indeterminate"
)

// report identifies one usage-report OData function.
type report struct {
	fn string
}

var (
	detailReport      = report{"getMailboxUsageDetail(period='D7')"}
	storageReport     = report{"getMailboxUsageStorage(period='D7')"}
	quotaCountsReport = report{"getMailboxUsageQuotaStatusMailboxCounts(period='D7')"}
)

// reportCount is the number of usage reports Collect fetches; all of them
// failing is the #240-shaped total-failure condition storage.go established.
const reportCount = 3

// quotaColumns maps each getMailboxUsageQuotaStatusMailboxCounts CSV column to
// its bounded quota-status attribute value, and doubles as the zero-fill set:
// every state below is always emitted, so a bucket dropping to zero mailboxes
// is visible as an explicit 0 rather than a vanished series.
var quotaColumns = []struct {
	column string
	state  string
}{
	{"Under Limit", quotaStateUnderLimit},
	{"Warning Issued", quotaStateWarningIssued},
	{"Send Prohibited", quotaStateSendProhibited},
	{"Send/Receive Prohibited", quotaStateSendReceiveProhibited},
	{"Indeterminate", quotaStateIndeterminate},
}

var errReportDecode = errors.New("decode usage report")

// Collector polls the Exchange mailbox usage reports.
type Collector struct {
	g       collectors.GraphClient
	baseURL string
	logger  *slog.Logger
	// now is the clock, injectable for tests (days_inactive is now-relative).
	now func() time.Time
}

// New builds the mailbox-usage collector. A nil logger falls back to the slog
// default.
func New(g collectors.GraphClient, logger *slog.Logger) *Collector {
	if logger == nil {
		logger = slog.Default()
	}
	return &Collector{g: g, baseURL: defaultBaseURL, logger: logger, now: time.Now}
}

// Name implements collector.Collector.
func (c *Collector) Name() string { return collectorName }

// DefaultInterval implements collector.Collector. The usage reports refresh at
// most daily, so a 6h poll is ample and keeps staleness bounded.
func (c *Collector) DefaultInterval() time.Duration { return 6 * time.Hour }

// RequiredPermissions declares the Graph application scopes this collector
// reads with. Reports.Read.All covers the three usage reports.
//
// ReportSettings.Read.All is listed too, even though the collector degrades
// gracefully without it. It is genuinely used — /admin/reportSettings is a
// separate resource with its own scope, live-verified 2026-07-28 returning
// `displayConcealedNames: false` as graph2otel-poller — and this list is what
// the generated scope documentation is built from, so a scope the code calls
// but the list omits sends an operator to grant an incomplete set and then
// wonder why one attribute never appears. Declaring it is not the same as
// requiring it: the package doc states the degraded behavior, and Collect
// treats a failure here as unknown-concealment rather than as an error.
func (c *Collector) RequiredPermissions() []string {
	return []string{"Reports.Read.All", "ReportSettings.Read.All"}
}

// Collect fetches the usage reports and emits tenant aggregates + per-mailbox
// twins. Each report is best-effort: a single report failing (e.g.
// unavailable in a sovereign cloud) is skipped with a warning, not fatal —
// only ALL reports failing is a collector failure (mirrors storage.go's #240
// handling).
func (c *Collector) Collect(ctx context.Context, e telemetry.Emitter, outcomes *recordoutcome.Recorder) error {
	concealed, settingKnown := c.readConcealment(ctx)

	detailRows, detailErr := c.fetch(ctx, detailReport)
	storageRows, storageErr := c.fetch(ctx, storageReport)
	quotaRows, quotaErr := c.fetch(ctx, quotaCountsReport)

	var fetchErrs []error
	for _, fe := range []struct {
		fn  string
		err error
	}{
		{detailReport.fn, detailErr},
		{storageReport.fn, storageErr},
		{quotaCountsReport.fn, quotaErr},
	} {
		if fe.err != nil {
			fetchErrs = append(fetchErrs, fmt.Errorf("%s: %w", fe.fn, fe.err))
			if errors.Is(fe.err, errReportDecode) {
				outcomes.Cause(recordoutcome.CauseDecodeError)
			} else {
				outcomes.Cause(recordoutcome.CauseSourceError)
			}
		}
	}

	used, usedOK := latestByReportDate(storageRows, "Storage Used (Byte)")
	recordLatestRowOutcomes(storageRows, usedOK, outcomes)

	latestQuota, latestQuotaOK := latestQuotaRow(quotaRows)
	recordLatestRowOutcomes(quotaRows, latestQuotaOK, outcomes)

	recordDetailOutcomes(detailRows, outcomes)

	if usedOK {
		e.Gauge(metricStorageUsed, "By", "Tenant-wide Exchange mailbox storage used, in bytes.", used, nil)
	}

	if latestQuotaOK {
		points := make([]telemetry.GaugePoint, 0, len(quotaColumns))
		for _, qc := range quotaColumns {
			points = append(points, telemetry.GaugePoint{
				Value: parseOptionalNum(latestQuota[qc.column]).orZero(),
				Attrs: telemetry.Attrs{semconv.AttrQuotaState: qc.state},
			})
		}
		e.GaugeSnapshot(metricQuotaStatus, "{mailbox}",
			"Count of mailboxes per Exchange quota-status bucket (Microsoft's own under_limit/warning_issued/send_prohibited/send_receive_prohibited/indeterminate vocabulary).",
			points)
	}

	for _, row := range detailRows {
		c.emitTwin(e, row, concealed, settingKnown)
	}

	// Mirrors storage.go's #240 handling: every report failing is a fabricated
	// "healthy tenant" (nothing emitted, no error) unless surfaced explicitly.
	if len(fetchErrs) == reportCount {
		return fmt.Errorf("m365.mailbox_usage: all mailbox usage reports failed: %w", errors.Join(fetchErrs...))
	}
	return nil
}

// emitTwin emits one m365.mailbox_usage log for a detail row.
func (c *Collector) emitTwin(e telemetry.Emitter, row map[string]string, concealed, settingKnown bool) {
	attrs := telemetry.Attrs{}
	telemetry.SetStr(attrs, semconv.AttrUserPrincipalName, row["User Principal Name"])
	telemetry.SetStr(attrs, semconv.AttrDisplayName, row["Display Name"])
	telemetry.SetBool(attrs, semconv.AttrIsDeleted, strings.EqualFold(row["Is Deleted"], "true"))
	telemetry.SetStr(attrs, semconv.AttrDeletedDate, row["Deleted Date"])
	telemetry.SetStr(attrs, semconv.AttrCreatedDate, row["Created Date"])
	telemetry.SetStr(attrs, semconv.AttrLastActivityDate, row["Last Activity Date"])
	telemetry.SetBool(attrs, semconv.AttrHasArchive, strings.EqualFold(row["Has Archive"], "true"))
	// settingKnown is false only when /admin/reportSettings itself could not be
	// read; there is no evidenced fallback heuristic for this report family (see
	// package doc), so names_concealed is omitted rather than guessed.
	if settingKnown {
		telemetry.SetBool(attrs, semconv.AttrNamesConcealed, concealed)
	}

	if n, ok := parseOptionalNum(row["Item Count"]).get(); ok {
		attrs[semconv.AttrItemCount] = n
	}
	if n, ok := parseOptionalNum(row["Storage Used (Byte)"]).get(); ok {
		attrs[semconv.AttrStorageUsedBytes] = n
	}
	if n, ok := parseOptionalNum(row["Issue Warning Quota (Byte)"]).get(); ok {
		attrs[semconv.AttrIssueWarningQuota] = n
	}
	if n, ok := parseOptionalNum(row["Prohibit Send Quota (Byte)"]).get(); ok {
		attrs[semconv.AttrProhibitSendQuota] = n
	}
	if n, ok := parseOptionalNum(row["Prohibit Send/Receive Quota (Byte)"]).get(); ok {
		attrs[semconv.AttrProhibitSendReceiveQuota] = n
	}
	if n, ok := parseOptionalNum(row["Deleted Item Count"]).get(); ok {
		attrs[semconv.AttrDeletedItemCount] = n
	}
	if n, ok := parseOptionalNum(row["Deleted Item Size (Byte)"]).get(); ok {
		attrs[semconv.AttrDeletedItemSize] = n
	}
	if n, ok := parseOptionalNum(row["Deleted Item Quota (Byte)"]).get(); ok {
		attrs[semconv.AttrDeletedItemQuota] = n
	}

	if days, ok := c.daysInactive(row["Last Activity Date"]); ok {
		attrs[semconv.AttrDaysInactive] = days
	}

	e.LogEvent(telemetry.Event{
		Name:     eventName,
		Body:     fmt.Sprintf("mailbox usage: %s", row["User Principal Name"]),
		Severity: telemetry.SeverityInfo,
		Attrs:    attrs,
	})
}

// daysInactive derives whole days since Last Activity Date using c.now(). ok
// is false when the date is blank or unparseable — a mailbox with no
// observable last-activity date must never be reported as "inactive forever".
func (c *Collector) daysInactive(lastActivityDate string) (float64, bool) {
	if lastActivityDate == "" {
		return 0, false
	}
	t, err := time.Parse("2006-01-02", lastActivityDate)
	if err != nil {
		return 0, false
	}
	days := c.now().Sub(t).Hours() / 24
	if days < 0 {
		days = 0
	}
	return days, true
}

// readConcealment reads the tenant report-concealment setting. Returns
// (concealed, known); known is false when the setting could not be read (e.g.
// no ReportSettings.Read.All).
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

// fetch GETs a report (RawGet follows the 302 to the CSV) and parses it.
func (c *Collector) fetch(ctx context.Context, r report) ([]map[string]string, error) {
	raw, err := c.g.RawGet(ctx, c.baseURL+"/reports/"+r.fn)
	if err != nil {
		c.logger.Warn("m365.mailbox_usage: report unavailable, skipping",
			"collector", collectorName, "report", r.fn, "error", err)
		return nil, err
	}
	rows, err := parseCSV(raw)
	if err != nil {
		c.logger.Warn("m365.mailbox_usage: report parse failed, skipping",
			"collector", collectorName, "report", r.fn, "error", err)
		return nil, fmt.Errorf("%w: %w", errReportDecode, err)
	}
	return rows, nil
}

// latestByReportDate reads a daily timeseries report's rows and returns the
// numeric value in column from the row with the most recent Report Date. ok is
// false when rows is empty. Report Date is a plain YYYY-MM-DD string, so
// lexical comparison is chronological comparison — same trick as storage.go's
// latestTenantUsed. Rows are NOT assumed to arrive newest-first.
func latestByReportDate(rows []map[string]string, column string) (float64, bool) {
	row, ok := latestReportDateRow(rows)
	if !ok {
		return 0, false
	}
	return parseOptionalNum(row[column]).orZero(), true
}

// latestQuotaRow returns the getMailboxUsageQuotaStatusMailboxCounts row with
// the most recent Report Date. ok is false when rows is empty.
func latestQuotaRow(rows []map[string]string) (map[string]string, bool) {
	return latestReportDateRow(rows)
}

// latestReportDateRow returns the row with the largest Report Date, without
// assuming input order.
func latestReportDateRow(rows []map[string]string) (map[string]string, bool) {
	if len(rows) == 0 {
		return nil, false
	}
	var latestDate string
	var latestRow map[string]string
	found := false
	for _, row := range rows {
		if d := row["Report Date"]; d >= latestDate {
			latestDate = d
			latestRow = row
			found = true
		}
	}
	return latestRow, found
}

// recordLatestRowOutcomes accounts for a daily timeseries report: exactly one
// latest row contributes the aggregate; every other fetched row is
// intentionally filtered.
func recordLatestRowOutcomes(rows []map[string]string, used bool, outcomes *recordoutcome.Recorder) {
	outcomes.Add(recordoutcome.OutcomeFetched, uint64(len(rows)))
	if !used {
		outcomes.Add(recordoutcome.OutcomeFiltered, uint64(len(rows)))
		return
	}
	outcomes.Add(recordoutcome.OutcomeMapped, 1)
	outcomes.Add(recordoutcome.OutcomeEmitted, 1)
	outcomes.Add(recordoutcome.OutcomeFiltered, uint64(len(rows))-1)
}

// recordDetailOutcomes accounts for mailbox-detail rows. Every parsed row
// emits one mailbox usage log twin.
func recordDetailOutcomes(rows []map[string]string, outcomes *recordoutcome.Recorder) {
	n := uint64(len(rows))
	outcomes.Add(recordoutcome.OutcomeFetched, n)
	outcomes.Add(recordoutcome.OutcomeMapped, n)
	outcomes.Add(recordoutcome.OutcomeEmitted, n)
}

// parseCSV parses a usage-report CSV into header-keyed rows. It strips a
// leading UTF-8 BOM (which would corrupt the first header) and runs the
// reader with LazyQuotes + a variable field count. Copied from
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
// caller must omit the attribute rather than fabricate a value.
type optionalNum struct {
	v  float64
	ok bool
}

func (n optionalNum) get() (float64, bool) { return n.v, n.ok }

// orZero collapses to 0 for callers that intentionally want a zero-filled
// aggregate (the bounded quota-status grid) rather than an omitted attribute.
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
