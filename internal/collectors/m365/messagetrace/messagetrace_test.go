package messagetrace

import (
	"context"
	"encoding/json"
	"errors"
	"sort"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/rknightion/graph2otel/internal/checkpoint"
	"github.com/rknightion/graph2otel/internal/collectors"
	"github.com/rknightion/graph2otel/internal/exoclient"
	"github.com/rknightion/graph2otel/internal/semconv"
	"github.com/rknightion/graph2otel/internal/telemetry"
	"github.com/rknightion/graph2otel/internal/telemetrytest"
	"github.com/rknightion/graph2otel/internal/wirecheck"
)

// liveRecord is a VERBATIM Get-MessageTraceV2 record captured from the m7kni
// tenant as graph2otel-poller (live-measured 2026-07-23), all twelve keys
// including the "@data.type" sidecars. Every mapping assertion in this file is
// made against this shape rather than a hand-simplified one: a mapper written
// against an invented fixture passes its tests and drops real fields (#142).
const liveRecord = `{
  "MessageTraceId": "a4acd0a2-1b62-4d07-db4f-08dee905ee9b",
  "MessageId": "<Y5PE3KV1VTU4.KRUFCAI594KF@bl6pepf00031abc>",
  "Received@data.type": "System.DateTime",
  "Received": "2026-07-23T22:01:22.0480000Z",
  "SenderAddress": "MSSecurity-noreply@microsoft.com",
  "RecipientAddress": "rob@m7kni.io",
  "FromIP": "2a01:111:f403:c112::5",
  "ToIP": "",
  "Subject": "EXTERNAL: PIM: graph2otel-poller has the Global Reader role",
  "Status": "Delivered",
  "Size@data.type": "System.Int32",
  "Size": 176814
}`

// windowFrom/windowTo bound every test window. They straddle the live record's
// Received so the record is inside the queried range.
var (
	windowFrom = time.Date(2026, 7, 23, 21, 0, 0, 0, time.UTC)
	windowTo   = time.Date(2026, 7, 23, 23, 0, 0, 0, time.UTC)
)

// --- the fake Exchange Online client -----------------------------------------

// fakeEXO serves a fixed record set through the REAL keyset semantics measured
// on the wire (live-measured 2026-07-23): records come back ordered by Received
// DESCENDING, tie-broken by RecipientAddress, the continuation is
// (EndDate, StartingRecipientAddress) taken from the LAST record of the page,
// and the boundary record is returned AGAIN on the next page.
//
// Modeling the server this way rather than scripting canned pages is the whole
// point: a collector that derives the cursor wrongly then loops or skips against
// this fake exactly as it would against Exchange Online.
type fakeEXO struct {
	rows     []map[string]any
	pageSize int
	// calls records the params of every InvokeFull, in order.
	calls []map[string]any
	// err, when set, is returned by every call.
	err error
	// alwaysMore makes the fake pathological: it returns one row and a
	// truncation warning forever, whatever cursor it is given.
	alwaysMore bool
}

func (f *fakeEXO) InvokeFull(_ context.Context, cmdlet string, params map[string]any) (exoclient.InvokeResult, error) {
	f.calls = append(f.calls, params)
	if f.err != nil {
		return exoclient.InvokeResult{}, f.err
	}
	if cmdlet != cmdletMessageTrace {
		return exoclient.InvokeResult{}, errors.New("unexpected cmdlet " + cmdlet)
	}
	if f.alwaysMore {
		return exoclient.InvokeResult{
			Records:  []map[string]any{f.rows[0]},
			Warnings: []string{"There are more results, use the following command to get more."},
		}, nil
	}

	start := mustParseParamTime(params[paramStartDate])
	end := mustParseParamTime(params[paramEndDate])
	startRecipient, keyed := params[paramStartingRecipient].(string)

	var kept []map[string]any
	for _, r := range f.rows {
		rt, err := time.Parse(time.RFC3339, str(r, fieldReceived))
		if err != nil {
			// A row with an unparseable Received is served regardless; the
			// collector decides what to do with it.
			kept = append(kept, r)
			continue
		}
		if rt.Before(start) {
			continue
		}
		if keyed {
			if rt.After(end) {
				continue
			}
			if rt.Equal(end) && str(r, fieldRecipientAddress) < startRecipient {
				continue
			}
		} else if rt.After(end) {
			continue
		}
		kept = append(kept, r)
	}
	sort.SliceStable(kept, func(i, j int) bool {
		ri, rj := str(kept[i], fieldReceived), str(kept[j], fieldReceived)
		if ri != rj {
			return ri > rj // Received descending
		}
		return str(kept[i], fieldRecipientAddress) < str(kept[j], fieldRecipientAddress)
	})

	res := exoclient.InvokeResult{Warnings: []string{}}
	if f.pageSize > 0 && len(kept) > f.pageSize {
		res.Records = kept[:f.pageSize]
		res.Warnings = []string{"There are more results, use the following command to get more."}
	} else {
		res.Records = kept
	}
	if res.Records == nil {
		res.Records = []map[string]any{}
	}
	return res, nil
}

// Invoke exists so the fake satisfies collectors.EXOClient and can be placed in
// WindowDeps.EXO, exactly as *exoclient.Client is. It delegates like the real
// client does — the collector never calls it.
func (f *fakeEXO) Invoke(ctx context.Context, cmdlet string, params map[string]any) ([]map[string]any, error) {
	res, err := f.InvokeFull(ctx, cmdlet, params)
	return res.Records, err
}

// invokeOnlyEXO satisfies collectors.EXOClient and NOTHING more. On this cmdlet
// the envelope is the only truncation signal, so a client that cannot supply it
// must not be handed a collector that would silently report one page.
type invokeOnlyEXO struct{}

func (invokeOnlyEXO) Invoke(context.Context, string, map[string]any) ([]map[string]any, error) {
	return nil, nil
}

func mustParseParamTime(v any) time.Time {
	s, _ := v.(string)
	t, err := time.Parse(time.RFC3339, s)
	if err != nil {
		return time.Time{}
	}
	return t
}

// --- fixtures ------------------------------------------------------------------

func liveRow(t *testing.T) map[string]any {
	t.Helper()
	var r map[string]any
	if err := json.Unmarshal([]byte(liveRecord), &r); err != nil {
		t.Fatalf("unmarshal live record: %v", err)
	}
	return r
}

// row builds a synthetic record in the live wire shape. Only the fields the
// keyset walk and the dedupe turn on vary.
func row(id, received, recipient, status string) map[string]any {
	return map[string]any{
		"MessageTraceId":     id,
		"MessageId":          "<" + id + "@m7kni.io>",
		"Received@data.type": "System.DateTime",
		"Received":           received,
		"SenderAddress":      "sender@example.net",
		"RecipientAddress":   recipient,
		"FromIP":             "203.0.113.7",
		"ToIP":               "",
		"Subject":            "subject " + id,
		"Status":             status,
		"Size@data.type":     "System.Int32",
		"Size":               float64(1024),
	}
}

func at(min int) string {
	return time.Date(2026, 7, 23, 22, min, 0, 0, time.UTC).Format(wireTimeLayout)
}

// atSec spaces records one second apart, for the page-cap fixture where more
// distinct Received values are needed than the window has minutes.
func atSec(sec int) string {
	return windowTo.Add(-time.Duration(sec) * time.Second).Format(wireTimeLayout)
}

// newCollector wires a Collector to a fake client and a real temp-dir
// checkpoint store.
func newCollector(t *testing.T, f *fakeEXO) *Collector {
	t.Helper()
	return New(f, collectors.WindowDeps{TenantID: "tenant-1", Store: checkpoint.NewStore(t.TempDir())})
}

// collect runs one window and returns the recorder and the emitted logs.
func collect(t *testing.T, c *Collector) (*telemetrytest.Recorder, []telemetrytest.LogRecord) {
	t.Helper()
	rec := telemetrytest.New()
	if _, err := c.CollectWindow(context.Background(), windowFrom, windowTo, rec.Emitter()); err != nil {
		t.Fatalf("CollectWindow: %v", err)
	}
	return rec, rec.LogRecords()
}

func traceIDs(logs []telemetrytest.LogRecord) []string {
	out := make([]string, 0, len(logs))
	for _, l := range logs {
		out = append(out, l.Attrs[semconv.AttrMessageTraceId])
	}
	sort.Strings(out)
	return out
}

// --- mapping -------------------------------------------------------------------

// TestMapsLiveRecordVerbatim pins every field of the captured wire record onto
// the log twin, with the formatted strings passed through untouched (#142).
func TestMapsLiveRecordVerbatim(t *testing.T) {
	f := &fakeEXO{rows: []map[string]any{liveRow(t)}}
	_, logs := collect(t, newCollector(t, f))

	if len(logs) != 1 {
		t.Fatalf("got %d log records, want 1", len(logs))
	}
	got := logs[0]
	if got.EventName != eventName {
		t.Errorf("event name = %q, want %q", got.EventName, eventName)
	}
	want := map[string]string{
		semconv.AttrMessageTraceId:    "a4acd0a2-1b62-4d07-db4f-08dee905ee9b",
		semconv.AttrInternetMessageId: "<Y5PE3KV1VTU4.KRUFCAI594KF@bl6pepf00031abc>",
		semconv.AttrReceivedTime:      "2026-07-23T22:01:22.0480000Z",
		semconv.AttrSenderAddress:     "MSSecurity-noreply@microsoft.com",
		semconv.AttrRecipientAddress:  "rob@m7kni.io",
		semconv.AttrFromIp:            "2a01:111:f403:c112::5",
		semconv.AttrSubject:           "EXTERNAL: PIM: graph2otel-poller has the Global Reader role",
		semconv.AttrStatus:            "Delivered",
		semconv.AttrIngestTransport:   string(telemetry.TransportExchangeOnline),
	}
	for k, v := range want {
		if got.Attrs[k] != v {
			t.Errorf("attr %s = %q, want %q", k, got.Attrs[k], v)
		}
	}
	// ToIP is "" on inbound mail — an empty value is omitted, never stamped as
	// an empty attribute.
	if v, ok := got.Attrs[semconv.AttrToIp]; ok {
		t.Errorf("attr %s = %q, want it omitted when the wire value is empty", semconv.AttrToIp, v)
	}
	if got.Attrs[semconv.AttrSize] != "176814" {
		t.Errorf("attr %s = %q, want 176814", semconv.AttrSize, got.Attrs[semconv.AttrSize])
	}
	wantTime := time.Date(2026, 7, 23, 22, 1, 22, 48000000, time.UTC)
	if !got.Timestamp.Equal(wantTime) {
		t.Errorf("timestamp = %s, want %s (Received, not arrival)", got.Timestamp, wantTime)
	}
	if got.SeverityText != "INFO" {
		t.Errorf("severity = %s, want INFO for a Delivered message", got.SeverityText)
	}
}

// TestOutboundMessageCarriesToIp is the other half of the ToIP assertion above,
// and it exists so the attribute reaches the golden at all: every inbound
// fixture leaves ToIP empty, so without an outbound record the drift gate could
// never see to_ip change (#164's thin-golden failure mode).
func TestOutboundMessageCarriesToIp(t *testing.T) {
	r := row("out1", at(3), "someone@example.net", "Delivered")
	r[fieldToIP] = "104.47.14.108"
	f := &fakeEXO{rows: []map[string]any{r}}
	_, logs := collect(t, newCollector(t, f))

	if len(logs) != 1 {
		t.Fatalf("got %d log records, want 1", len(logs))
	}
	if logs[0].Attrs[semconv.AttrToIp] != "104.47.14.108" {
		t.Errorf("attr %s = %q, want the wire value", semconv.AttrToIp, logs[0].Attrs[semconv.AttrToIp])
	}
}

// TestFirstQueryHonorsTheWindowWithOverlap pins the request the collector makes:
// the scheduler's window, extended backwards by the overlap so a record that
// landed in the trace after the watermark passed its Received is re-read (and
// then deduped).
func TestFirstQueryHonorsTheWindowWithOverlap(t *testing.T) {
	f := &fakeEXO{rows: []map[string]any{liveRow(t)}}
	collect(t, newCollector(t, f))

	if len(f.calls) != 1 {
		t.Fatalf("got %d calls, want 1", len(f.calls))
	}
	wantStart := windowFrom.Add(-overlapWindow).Format(wireTimeLayout)
	if f.calls[0][paramStartDate] != wantStart {
		t.Errorf("StartDate = %v, want %q", f.calls[0][paramStartDate], wantStart)
	}
	if f.calls[0][paramEndDate] != windowTo.Format(wireTimeLayout) {
		t.Errorf("EndDate = %v, want %q", f.calls[0][paramEndDate], windowTo.Format(wireTimeLayout))
	}
	if _, keyed := f.calls[0][paramStartingRecipient]; keyed {
		t.Errorf("first page must not carry %s: there is no cursor yet", paramStartingRecipient)
	}
}

// --- the keyset walk -----------------------------------------------------------

// TestKeysetWalkIsLossless is the control experiment in miniature. The live
// experiment (2026-07-23) proved an unpaged read of one window and a derived
// keyset walk at ResultSize 5 return the SAME 37 distinct MessageTraceIds — no
// skip, no extra. This asserts the same property against a fake serving the
// measured semantics, with a page boundary that lands exactly on two records
// sharing a Received and differing only by recipient.
func TestKeysetWalkIsLossless(t *testing.T) {
	rows := []map[string]any{
		row("m5", at(5), "rob@m7kni.io", "Delivered"),
		row("m4", at(4), "rob@m7kni.io", "Delivered"),
		row("m3a", at(3), "alice@m7kni.io", "Delivered"),
		row("m3b", at(3), "bob@m7kni.io", "FilteredAsSpam"),
		row("m2", at(2), "rob@m7kni.io", "Delivered"),
		row("m1", at(1), "rob@m7kni.io", "Resolved"),
	}
	f := &fakeEXO{rows: rows, pageSize: 3}
	_, logs := collect(t, newCollector(t, f))

	want := []string{"m1", "m2", "m3a", "m3b", "m4", "m5"}
	if got := traceIDs(logs); strings.Join(got, ",") != strings.Join(want, ",") {
		t.Errorf("emitted trace ids = %v, want each exactly once %v", got, want)
	}
	if len(f.calls) < 2 {
		t.Fatalf("got %d calls, want a multi-page walk", len(f.calls))
	}
	// The continuation must be derived from the LAST record of the page, never
	// parsed out of the warning prose.
	if f.calls[1][paramEndDate] != at(3) {
		t.Errorf("page 2 EndDate = %v, want %q (last record's Received)", f.calls[1][paramEndDate], at(3))
	}
	if f.calls[1][paramStartingRecipient] != "alice@m7kni.io" {
		t.Errorf("page 2 %s = %v, want alice@m7kni.io (last record's RecipientAddress)",
			paramStartingRecipient, f.calls[1][paramStartingRecipient])
	}
}

// TestKeysetTieBreakDoesNotLoop is the no-loop half of the same property, and it
// is the case a Received-only cursor cannot survive: three records share one
// Received and the page holds two, so a cursor that omits the recipient half
// re-requests the identical page forever.
func TestKeysetTieBreakDoesNotLoop(t *testing.T) {
	rows := []map[string]any{
		row("k5", at(5), "rob@m7kni.io", "Delivered"),
		row("k3a", at(3), "alice@m7kni.io", "Delivered"),
		row("k3b", at(3), "bob@m7kni.io", "Delivered"),
		row("k3c", at(3), "carol@m7kni.io", "Delivered"),
		row("k1", at(1), "rob@m7kni.io", "Delivered"),
	}
	f := &fakeEXO{rows: rows, pageSize: 2}
	rec, logs := collect(t, newCollector(t, f))

	want := []string{"k1", "k3a", "k3b", "k3c", "k5"}
	if got := traceIDs(logs); strings.Join(got, ",") != strings.Join(want, ",") {
		t.Errorf("emitted trace ids = %v, want each exactly once %v", got, want)
	}
	if len(f.calls) >= maxPages {
		t.Errorf("walk took %d calls (cap %d) — the recipient tie-break is not advancing the cursor",
			len(f.calls), maxPages)
	}
	if pts := rec.MetricPoints(wirecheck.MetricUnexpected); len(pts) != 0 {
		t.Errorf("a clean tie-broken walk reported %d wire findings, want none: %+v", len(pts), pts)
	}
}

// TestCursorStallStops guards the one shape the tie-break cannot fix: a server
// that reports "more results" while handing back a page whose last record
// reproduces the cursor it was given. The next request would be byte-identical,
// so the only outcomes are stop or spin — it stops, and says so.
func TestCursorStallStops(t *testing.T) {
	f := &fakeEXO{rows: []map[string]any{row("s1", at(3), "rob@m7kni.io", "Delivered")}, alwaysMore: true}
	rec, logs := collect(t, newCollector(t, f))

	if len(logs) != 1 {
		t.Fatalf("got %d log records, want 1", len(logs))
	}
	if len(f.calls) != 2 {
		t.Errorf("got %d calls, want 2 (the stall is detected on the second)", len(f.calls))
	}
	assertFinding(t, rec, ruleCursorStall)
}

// TestMaxPagesCapReportsWhatItDropped: the cap exists so a pathological window
// cannot spin forever, but stopping early means the OLDEST part of the window is
// never read, and the window advances past it regardless. That is a hole in the
// data, so it is reported as a broken invariant rather than left to a log line
// nobody reads.
func TestMaxPagesCapReportsWhatItDropped(t *testing.T) {
	// One second apart so every page advances the cursor and only the cap can
	// stop the walk. A page of 2 with an inclusive boundary nets one new record
	// per page, so more than maxPages rows are needed to reach it.
	rows := make([]map[string]any, 0, maxPages+10)
	for i := range maxPages + 10 {
		rows = append(rows, row("p"+strconv.Itoa(i), atSec(i), "rob@m7kni.io", "Delivered"))
	}
	f := &fakeEXO{rows: rows, pageSize: 2}
	rec, logs := collect(t, newCollector(t, f))

	if len(f.calls) != maxPages {
		t.Errorf("got %d calls, want the cap %d", len(f.calls), maxPages)
	}
	if len(logs) >= len(rows) {
		t.Errorf("got %d log records of %d rows — the cap did not stop the walk", len(logs), len(rows))
	}
	assertFinding(t, rec, rulePageCap)
}

// --- dedupe --------------------------------------------------------------------

// TestDedupesRepeatedMessageTraceIdWithinOnePage pins the duplicate shape that
// has nothing to do with paging: a single unpaged read returned 44 rows for 37
// distinct MessageTraceIds (live-measured 2026-07-23), so dedupe is mandatory
// even when the walk is one page long.
func TestDedupesRepeatedMessageTraceIdWithinOnePage(t *testing.T) {
	dup := row("d1", at(3), "rob@m7kni.io", "Delivered")
	f := &fakeEXO{rows: []map[string]any{dup, row("d2", at(2), "rob@m7kni.io", "Delivered"), dup}}
	_, logs := collect(t, newCollector(t, f))

	want := []string{"d1", "d2"}
	if got := traceIDs(logs); strings.Join(got, ",") != strings.Join(want, ",") {
		t.Errorf("emitted trace ids = %v, want %v", got, want)
	}
}

// TestDedupesAcrossTicks: each tick re-reads overlapWindow behind its own start,
// so a record near the previous window's end is fetched a second time. The
// persisted SeenIDs set is what stops it leaving the process twice. The record
// is placed INSIDE the overlap on purpose — outside it the second tick would
// never fetch it at all and the test would pass for the wrong reason.
func TestDedupesAcrossTicks(t *testing.T) {
	f := &fakeEXO{rows: []map[string]any{row("t1", at(50), "rob@m7kni.io", "Delivered")}}
	c := newCollector(t, f)
	rec := telemetrytest.New()

	if _, err := c.CollectWindow(context.Background(), windowFrom, windowTo, rec.Emitter()); err != nil {
		t.Fatalf("first tick: %v", err)
	}
	if got := len(rec.LogRecords()); got != 1 {
		t.Fatalf("first tick emitted %d records, want 1", got)
	}

	// The scheduler's next window starts where this one ended.
	next := telemetrytest.New()
	if _, err := c.CollectWindow(context.Background(), windowTo, windowTo.Add(10*time.Minute), next.Emitter()); err != nil {
		t.Fatalf("second tick: %v", err)
	}
	if len(f.calls) < 2 {
		t.Fatalf("second tick made no call")
	}
	floor := f.calls[1][paramStartDate].(string)
	if floor >= at(50) {
		t.Fatalf("second tick's StartDate %s is past the record at %s — it never re-read it, "+
			"so this test proves nothing about dedupe", floor, at(50))
	}
	if got := len(next.LogRecords()); got != 0 {
		t.Errorf("second tick re-emitted %d records, want 0", got)
	}
}

// TestUndedupeableRecordIsStillEmitted encodes the emitter's rule: undedupeable
// is degraded, misdated is wrong, and only wrong justifies a drop. A record with
// no MessageTraceId cannot be deduped and may repeat, but dropping it would lose
// a message that really happened.
func TestUndedupeableRecordIsStillEmitted(t *testing.T) {
	r := row("", at(3), "rob@m7kni.io", "Delivered")
	delete(r, fieldMessageTraceId)
	f := &fakeEXO{rows: []map[string]any{r}}
	rec, logs := collect(t, newCollector(t, f))

	if len(logs) != 1 {
		t.Fatalf("got %d log records, want the record emitted despite being undedupeable", len(logs))
	}
	assertFinding(t, rec, fieldMessageTraceId)
}

// TestUndateableRecordIsDropped is the other half: telemetry only sets non-zero
// timestamps, so a record whose Received does not parse would be stamped with
// the arrival clock and silently claim to have happened now. That is wrong
// rather than degraded, so it is dropped and reported.
func TestUndateableRecordIsDropped(t *testing.T) {
	r := row("bad", "not-a-timestamp", "rob@m7kni.io", "Delivered")
	f := &fakeEXO{rows: []map[string]any{r, row("good", at(3), "rob@m7kni.io", "Delivered")}}
	rec, logs := collect(t, newCollector(t, f))

	if got := traceIDs(logs); strings.Join(got, ",") != "good" {
		t.Errorf("emitted trace ids = %v, want only [good]", got)
	}
	assertFinding(t, rec, fieldReceived)
}

// --- statuses ------------------------------------------------------------------

// TestUnknownStatusIsReportedNotHidden: Status is a metric label, so a value
// Microsoft adds later silently moves the numbers. It is emitted verbatim (never
// bucketed into a fallback that hides it) AND reported through wirecheck.
func TestUnknownStatusIsReportedNotHidden(t *testing.T) {
	f := &fakeEXO{rows: []map[string]any{row("u1", at(3), "rob@m7kni.io", "TimeTravelled")}}
	rec, logs := collect(t, newCollector(t, f))

	if len(logs) != 1 {
		t.Fatalf("got %d log records, want 1", len(logs))
	}
	if logs[0].Attrs[semconv.AttrStatus] != "TimeTravelled" {
		t.Errorf("status = %q, want the wire value verbatim", logs[0].Attrs[semconv.AttrStatus])
	}
	if logs[0].SeverityText != "INFO" {
		t.Errorf("severity = %s, want INFO — an unmapped status is a schema surprise, not a mail failure",
			logs[0].SeverityText)
	}
	assertFinding(t, rec, fieldStatus)

	var found bool
	for _, p := range rec.MetricPoints(metricMessages) {
		if p.Attrs[semconv.AttrStatus] == "TimeTravelled" {
			found = true
		}
	}
	if !found {
		t.Errorf("the unmapped status is missing from %s — bucketing it away is what hides it", metricMessages)
	}
}

// TestSeverityMapping pins the one judgement in the mapper. Only Failed means
// mail did not get where it was sent; filtering and quarantine are the security
// stack working as designed, at firehose volume, so rating them WARN would make
// WARN the dominant severity of the whole stream and destroy its signal.
func TestSeverityMapping(t *testing.T) {
	for _, tc := range []struct{ status, want string }{
		{"Delivered", "INFO"},
		{"FilteredAsSpam", "INFO"},
		{"Resolved", "INFO"},
		{"Quarantined", "INFO"},
		{"Expanded", "INFO"},
		{"Pending", "INFO"},
		{"GettingStatus", "INFO"},
		{"Failed", "WARN"},
	} {
		t.Run(tc.status, func(t *testing.T) {
			f := &fakeEXO{rows: []map[string]any{row("s-"+tc.status, at(3), "rob@m7kni.io", tc.status)}}
			_, logs := collect(t, newCollector(t, f))
			if len(logs) != 1 {
				t.Fatalf("got %d log records, want 1", len(logs))
			}
			if logs[0].SeverityText != tc.want {
				t.Errorf("severity for %s = %s, want %s", tc.status, logs[0].SeverityText, tc.want)
			}
		})
	}
}

// --- metrics -------------------------------------------------------------------

// TestMetricsAreBoundedByStatusOnly is the #112 gate for this collector, stated
// as a property rather than as a golden: a metric keyed by recipient is one
// series per mailbox per status, which grows with the tenant and answers nothing
// the log twin does not answer better.
func TestMetricsAreBoundedByStatusOnly(t *testing.T) {
	rows := []map[string]any{
		row("b1", at(5), "alice@m7kni.io", "Delivered"),
		row("b2", at(4), "bob@m7kni.io", "Delivered"),
		row("b3", at(3), "carol@m7kni.io", "FilteredAsSpam"),
	}
	f := &fakeEXO{rows: rows}
	rec, _ := collect(t, newCollector(t, f))

	perMessage := []string{
		semconv.AttrRecipientAddress, semconv.AttrSenderAddress, semconv.AttrSubject,
		semconv.AttrMessageTraceId, semconv.AttrInternetMessageId, semconv.AttrFromIp,
		semconv.AttrToIp, semconv.AttrSize, semconv.AttrReceivedTime,
	}
	for _, name := range []string{metricMessages, metricBytes} {
		pts := rec.MetricPoints(name)
		if len(pts) == 0 {
			t.Fatalf("%s emitted no points", name)
		}
		for _, p := range pts {
			for _, k := range perMessage {
				if _, bad := p.Attrs[k]; bad {
					t.Errorf("%s carries per-message label %q — one series per message (#112)", name, k)
				}
			}
			if _, ok := p.Attrs[semconv.AttrStatus]; !ok {
				t.Errorf("%s point %+v has no status label", name, p.Attrs)
			}
		}
	}

	// Three messages, two Delivered and one FilteredAsSpam.
	if got := metricValue(rec, metricMessages, "Delivered"); got != 2 {
		t.Errorf("%s{Delivered} = %v, want 2", metricMessages, got)
	}
	if got := metricValue(rec, metricMessages, "FilteredAsSpam"); got != 1 {
		t.Errorf("%s{FilteredAsSpam} = %v, want 1", metricMessages, got)
	}
	if got := metricValue(rec, metricBytes, "Delivered"); got != 2048 {
		t.Errorf("%s{Delivered} = %v, want 2048", metricBytes, got)
	}
}

// TestVolumeMetricsAreCounters: the poll window varies (a catch-up tick after an
// outage is up to maxWindow long), so a gauge of "messages in this window" spikes
// by the window ratio and is indistinguishable from a real mail surge. A
// monotonic counter has no such artifact and is what increase() needs.
func TestVolumeMetricsAreCounters(t *testing.T) {
	f := &fakeEXO{rows: []map[string]any{row("c1", at(3), "rob@m7kni.io", "Delivered")}}
	rec, _ := collect(t, newCollector(t, f))

	for _, name := range []string{metricMessages, metricBytes} {
		pts := rec.MetricPoints(name)
		if len(pts) == 0 {
			t.Fatalf("%s emitted no points", name)
		}
		if pts[0].Kind != "sum" || !pts[0].Monotonic {
			t.Errorf("%s kind=%s monotonic=%t, want a monotonic sum", name, pts[0].Kind, pts[0].Monotonic)
		}
	}
}

// --- registration --------------------------------------------------------------

// TestFactoryDeclinesWithoutAnExchangeClient: WindowDeps.EXO is nil for a tenant
// with no exchange_online block, and a collector constructed anyway would fail
// every cycle forever.
func TestFactoryDeclinesWithoutAnExchangeClient(t *testing.T) {
	got := factory(collectors.WindowDeps{TenantID: "tenant-1", Store: checkpoint.NewStore(t.TempDir())})
	if got.Collector != nil {
		t.Errorf("factory returned a collector with a nil EXO client: %+v", got)
	}
}

// TestFactoryDeclinesWithoutACheckpointStore: the dedupe set is what stops the
// overlap re-shipping every record every tick, so with nowhere to persist it the
// honest answer is not to register.
func TestFactoryDeclinesWithoutACheckpointStore(t *testing.T) {
	got := factory(collectors.WindowDeps{TenantID: "tenant-1", EXO: &fakeEXO{}})
	if got.Collector != nil {
		t.Errorf("factory returned a collector with a nil checkpoint store: %+v", got)
	}
}

// TestFactoryDeclinesWithoutInvokeFull: collectors.EXOClient declares only
// Invoke, which discards the envelope — and the envelope is the ONLY truncation
// signal Get-MessageTraceV2 sends. A collector built on such a client would ship
// page one of a firehose and look healthy.
func TestFactoryDeclinesWithoutInvokeFull(t *testing.T) {
	got := factory(collectors.WindowDeps{
		TenantID: "tenant-1",
		EXO:      invokeOnlyEXO{},
		Store:    checkpoint.NewStore(t.TempDir()),
	})
	if got.Collector != nil {
		t.Errorf("factory returned a collector over an Invoke-only client: %+v", got)
	}
}

// TestFactoryRegistersWithBothSeams is the positive control for the two above.
func TestFactoryRegistersWithBothSeams(t *testing.T) {
	got := factory(collectors.WindowDeps{
		TenantID: "tenant-1",
		EXO:      &fakeEXO{},
		Store:    checkpoint.NewStore(t.TempDir()),
	})
	if got.Collector == nil {
		t.Fatal("factory declined despite both seams being present")
	}
	if got.InitialLookback != initialLookback || got.MaxWindow != maxWindow {
		t.Errorf("schedule bounds = %v/%v, want %v/%v",
			got.InitialLookback, got.MaxWindow, initialLookback, maxWindow)
	}
}

// TestHighVolumeShipsItOff is the acceptance criterion from #254: one record per
// message per recipient is a firehose, so enabling graph2otel must never switch
// it on by accident.
func TestHighVolumeShipsItOff(t *testing.T) {
	c := newCollector(t, &fakeEXO{})
	if !c.HighVolume() {
		t.Error("HighVolume() = false, want true — this collector must be opt-in")
	}
	if _, isExperimental := any(c).(collectors.Experimental); isExperimental {
		t.Error("collector declares Experimental: #183 reserves that for genuine Graph BETA surfaces, " +
			"and Get-MessageTraceV2 is neither beta nor Graph")
	}
}

// TestCollectorIdentity pins the names an operator configures and queries by.
func TestCollectorIdentity(t *testing.T) {
	c := newCollector(t, &fakeEXO{})
	if c.Name() != "m365.message_trace" {
		t.Errorf("Name() = %q, want m365.message_trace", c.Name())
	}
	if c.IngestTransport() != telemetry.TransportExchangeOnline {
		t.Errorf("IngestTransport() = %q, want exchange_online", c.IngestTransport())
	}
	if got := c.RequiredPermissions(); got != nil {
		t.Errorf("RequiredPermissions() = %v, want nil — this transport is not Graph-scope gated", got)
	}
	if c.DefaultInterval() <= 0 || c.Lag() <= 0 {
		t.Errorf("interval/lag = %v/%v, want both positive", c.DefaultInterval(), c.Lag())
	}
}

// TestCheckpointStateReportsProgress covers the admin status page seam: this
// collector owns its checkpoint directly, so it reports it itself.
func TestCheckpointStateReportsProgress(t *testing.T) {
	// Inside the overlap, so the id is still held rather than already evicted.
	f := &fakeEXO{rows: []map[string]any{row("cs1", at(50), "rob@m7kni.io", "Delivered")}}
	c := newCollector(t, f)
	collect(t, c)

	st := c.CheckpointState()
	if st == nil {
		t.Fatal("CheckpointState() = nil after a successful window")
	}
	if !st.Watermark.Equal(windowTo) {
		t.Errorf("watermark = %s, want the drained window end %s", st.Watermark, windowTo)
	}
	if st.SeenIDs != 1 {
		t.Errorf("seen ids = %d, want 1", st.SeenIDs)
	}
}

// TestCollectErrorDoesNotAdvance: an error must surface so the scheduler retries
// the same window rather than skipping it.
func TestCollectErrorDoesNotAdvance(t *testing.T) {
	f := &fakeEXO{err: errors.New("boom")}
	rec := telemetrytest.New()
	if _, err := newCollector(t, f).CollectWindow(context.Background(), windowFrom, windowTo, rec.Emitter()); err == nil {
		t.Fatal("CollectWindow returned nil error on a failing cmdlet")
	}
}

// --- helpers -------------------------------------------------------------------

func metricValue(rec *telemetrytest.Recorder, name, status string) float64 {
	var sum float64
	for _, p := range rec.MetricPoints(name) {
		if p.Attrs[semconv.AttrStatus] == status {
			sum += p.Value
		}
	}
	return sum
}

// assertFinding checks that wirecheck reported something about `field`.
func assertFinding(t *testing.T, rec *telemetrytest.Recorder, field string) {
	t.Helper()
	for _, p := range rec.MetricPoints(wirecheck.MetricUnexpected) {
		if p.Attrs[semconv.AttrField] == field {
			return
		}
	}
	t.Errorf("no %s finding for field %q — the surprise was swallowed", wirecheck.MetricUnexpected, field)
}
