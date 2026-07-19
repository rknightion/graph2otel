package discoveryparse

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/rknightion/graph2otel/internal/checkpoint"
	"github.com/rknightion/graph2otel/internal/collector"
	"github.com/rknightion/graph2otel/internal/collectors"
	"github.com/rknightion/graph2otel/internal/mdcaclient"
	"github.com/rknightion/graph2otel/internal/semconv"
	"github.com/rknightion/graph2otel/internal/telemetry"
	"github.com/rknightion/graph2otel/internal/telemetrytest"
)

// fixedNow is a stable clock for age-gauge assertions.
var fixedNow = time.Date(2026, 7, 19, 12, 0, 0, 0, time.UTC)

// govServer serves a scripted sequence of governance responses, one per POST.
// The last scripted response repeats for any further requests.
type govServer struct {
	responses []string
	i         int
}

func (g *govServer) handler(w http.ResponseWriter, r *http.Request) {
	body := g.responses[g.i]
	if g.i < len(g.responses)-1 {
		g.i++
	}
	_, _ = w.Write([]byte(body))
}

// newTestCollector wires a Collector to an httptest server + a real temp-dir
// checkpoint store + a fixed clock.
func newTestCollector(t *testing.T, gs *govServer) (*Collector, *httptest.Server) {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(gs.handler))
	t.Cleanup(srv.Close)
	client, err := mdcaclient.NewClient("tenant-1", mdcaclient.Options{BaseURL: srv.URL, Token: "tok"})
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	c := New(collectors.MDCADeps{Client: client, TenantID: "tenant-1", Store: checkpoint.NewStore(t.TempDir())})
	c.now = func() time.Time { return fixedNow }
	return c, srv
}

// record builds one governance record JSON object.
func record(id string, tsMillis, updMillis int64, status map[string]any) map[string]any {
	r := map[string]any{
		"_id":             id,
		"taskName":        "DiscoveryParseLogTask",
		"inputStreamId":   "stream-1",
		"timestamp":       tsMillis,
		"updateTimestamp": updMillis,
	}
	if status != nil {
		r["status"] = status
	}
	return r
}

func govBody(t *testing.T, recs ...map[string]any) string {
	t.Helper()
	b, err := json.Marshal(map[string]any{"total": len(recs), "data": recs})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	return string(b)
}

func successStatus(tx, cs int) map[string]any {
	return map[string]any{
		"isSuccess": true,
		"templateMessage": map[string]any{
			"template":   successTemplate,
			"parameters": map[string]any{"transactionsCount": tx, "cloudServicesCount": cs},
		},
	}
}

func failureStatus() map[string]any {
	return map[string]any{
		"isSuccess": false,
		"templateMessage": map[string]any{
			"template":   "REPOOPER_COMPLETION_STATUS_BASELOGPARSER_UNEXPECTED_FORMAT",
			"parameters": map[string]any{"dataSource": "GENERIC_CEF"},
		},
	}
}

func newRec() *telemetrytest.Recorder { return telemetrytest.New() }

// runCollect runs one CollectWindow with a fresh recorder over a wide window and
// returns the emitted log records.
func runCollect(t *testing.T, c *Collector) []telemetrytest.LogRecord {
	t.Helper()
	rec := newRec()
	if _, err := c.CollectWindow(context.Background(), fixedNow.Add(-4*time.Hour), fixedNow, rec.Emitter()); err != nil {
		t.Fatalf("CollectWindow: %v", err)
	}
	return rec.LogRecords()
}

// gaugeValue returns the value of a GaugeSnapshot series for one input stream.
func gaugeValue(t *testing.T, rec *telemetrytest.Recorder, name, streamID string) float64 {
	t.Helper()
	for _, p := range rec.MetricPoints(name) {
		if p.Attrs[semconv.AttrInputStreamId] == streamID {
			return p.Value
		}
	}
	return -1
}

// --- mapper unit tests (drive logTwin directly: telemetrytest cannot render a
// bool attr, so is_success VALUE is asserted on the telemetry.Event) ---

func TestLogTwinPendingIsNotAFailure(t *testing.T) {
	m, ok := parseTask(record("a", fixedNow.UnixMilli(), fixedNow.UnixMilli(), nil))
	if !ok {
		t.Fatal("parseTask dropped a pending record")
	}
	ev := logTwin(m)
	if ev.Severity != telemetry.SeverityInfo {
		t.Errorf("pending severity = %v, want Info", ev.Severity)
	}
	if ev.Attrs[semconv.AttrState] != "pending" {
		t.Errorf("pending state = %v, want pending", ev.Attrs[semconv.AttrState])
	}
	if _, present := ev.Attrs[semconv.AttrIsSuccess]; present {
		t.Error("pending record set is_success — a queued task is NOT a failure and must not carry a verdict")
	}
}

func TestLogTwinTerminalSuccess(t *testing.T) {
	m, ok := parseTask(record("a", fixedNow.UnixMilli(), fixedNow.UnixMilli(), successStatus(21559, 70)))
	if !ok {
		t.Fatal("parseTask dropped a success record")
	}
	ev := logTwin(m)
	if ev.Severity != telemetry.SeverityInfo {
		t.Errorf("success severity = %v, want Info", ev.Severity)
	}
	if v, _ := ev.Attrs[semconv.AttrIsSuccess].(bool); !v {
		t.Errorf("success is_success = %v, want true", ev.Attrs[semconv.AttrIsSuccess])
	}
	if ev.Attrs[semconv.AttrTransactionsCount] != "21559" || ev.Attrs[semconv.AttrCloudServicesCount] != "70" {
		t.Errorf("counts = %v/%v, want 21559/70", ev.Attrs[semconv.AttrTransactionsCount], ev.Attrs[semconv.AttrCloudServicesCount])
	}
}

func TestLogTwinTerminalFailureIsError(t *testing.T) {
	m, ok := parseTask(record("a", fixedNow.UnixMilli(), fixedNow.UnixMilli(), failureStatus()))
	if !ok {
		t.Fatal("parseTask dropped a failure record")
	}
	ev := logTwin(m)
	if ev.Severity != telemetry.SeverityError {
		t.Errorf("failure severity = %v, want Error", ev.Severity)
	}
	if v, _ := ev.Attrs[semconv.AttrIsSuccess].(bool); v {
		t.Errorf("failure is_success = %v, want false", ev.Attrs[semconv.AttrIsSuccess])
	}
	if ev.Attrs[semconv.AttrTemplate] != "REPOOPER_COMPLETION_STATUS_BASELOGPARSER_UNEXPECTED_FORMAT" {
		t.Errorf("failure template = %v", ev.Attrs[semconv.AttrTemplate])
	}
}

func TestParseTaskDropsRecordWithNoTimestamp(t *testing.T) {
	if _, ok := parseTask(map[string]any{"_id": "x", "taskName": "DiscoveryParseLogTask"}); ok {
		t.Error("parseTask kept a record with no timestamp — it would be misdated to now (#135)")
	}
}

// --- CollectWindow behavior tests (through the client + store + recorder) ---

func TestFiltersTaskNameClientSide(t *testing.T) {
	// A non-DiscoveryParseLogTask record in the SAME response must be ignored —
	// proving taskName is filtered client-side, since the server-side filter is a
	// silent-empty trap (#145).
	other := map[string]any{"_id": "o", "taskName": "SomethingElse", "timestamp": fixedNow.UnixMilli(), "updateTimestamp": fixedNow.UnixMilli(), "status": successStatus(1, 1)}
	gs := &govServer{responses: []string{govBody(t, record("a", fixedNow.UnixMilli(), fixedNow.UnixMilli(), successStatus(5, 2)), other)}}
	c, _ := newTestCollector(t, gs)

	logs := runCollect(t, c)
	if len(logs) != 1 {
		t.Fatalf("emitted %d log records, want 1 (the other taskName must be filtered client-side)", len(logs))
	}
	if logs[0].Attrs[semconv.AttrId] != "a" {
		t.Errorf("kept record id = %v, want a", logs[0].Attrs[semconv.AttrId])
	}
}

func TestPendingThenTerminalBothEmitted(t *testing.T) {
	// First tick: task is queued (updateTimestamp == timestamp, no status).
	// Second tick: SAME _id, status settled (updateTimestamp advanced). The
	// verdict must NOT be dropped as a duplicate — dedupe is _id+updateTimestamp.
	ts := fixedNow.Add(-20 * time.Minute).UnixMilli()
	upd1 := ts
	upd2 := fixedNow.Add(-19 * time.Minute).UnixMilli()
	gs := &govServer{responses: []string{
		govBody(t, record("a", ts, upd1, nil)),             // pending
		govBody(t, record("a", ts, upd2, failureStatus())), // settled -> failure
	}}
	c, _ := newTestCollector(t, gs)

	first := runCollect(t, c)
	if len(first) != 1 || first[0].Attrs[semconv.AttrState] != "pending" {
		t.Fatalf("first tick = %+v, want one pending record", first)
	}
	second := runCollect(t, c)
	if len(second) != 1 || second[0].Attrs[semconv.AttrState] != "completed" {
		t.Fatalf("second tick = %+v, want one completed (verdict) record — a naive _id dedupe would hide it", second)
	}
	if second[0].SeverityText != "ERROR" {
		t.Errorf("settled failure severity = %q, want ERROR", second[0].SeverityText)
	}
}

func TestDuplicateSameStateDeduped(t *testing.T) {
	// The SAME record (same _id + updateTimestamp) served twice across ticks must
	// be emitted once — overlap re-reads must not double-ship a settled task.
	ts := fixedNow.Add(-10 * time.Minute).UnixMilli()
	upd := fixedNow.Add(-9 * time.Minute).UnixMilli()
	body := govBody(t, record("a", ts, upd, successStatus(3, 1)))
	gs := &govServer{responses: []string{body, body}}
	c, _ := newTestCollector(t, gs)

	if got := len(runCollect(t, c)); got != 1 {
		t.Fatalf("first tick emitted %d, want 1", got)
	}
	if got := len(runCollect(t, c)); got != 0 {
		t.Fatalf("second tick re-read the same settled record and emitted %d, want 0 (dedupe)", got)
	}
}

func TestLastSuccessAgeGaugeClimbsWhenSilent(t *testing.T) {
	// Tick 1: a success at T-30m records last_success. Tick 2: an EMPTY window
	// (uploads stopped) must STILL emit the age gauge, climbing — the alert-on-
	// silence signal a failure counter cannot produce.
	successTs := fixedNow.Add(-30 * time.Minute)
	gs := &govServer{responses: []string{
		govBody(t, record("a", successTs.UnixMilli(), successTs.UnixMilli(), successStatus(100, 5))),
		govBody(t), // empty window
	}}
	c, srv := newTestCollector(t, gs)
	_ = srv

	rec := newRec()
	if _, err := c.CollectWindow(context.Background(), fixedNow.Add(-4*time.Hour), fixedNow, rec.Emitter()); err != nil {
		t.Fatalf("tick1: %v", err)
	}
	age1 := gaugeValue(t, rec, metricLastSuccessAge, "stream-1")
	if age1 <= 0 {
		t.Fatalf("tick1 age = %v, want > 0", age1)
	}

	rec2 := newRec()
	if _, err := c.CollectWindow(context.Background(), fixedNow.Add(-1*time.Hour), fixedNow, rec2.Emitter()); err != nil {
		t.Fatalf("tick2: %v", err)
	}
	age2 := gaugeValue(t, rec2, metricLastSuccessAge, "stream-1")
	if age2 <= 0 {
		t.Fatal("tick2 (empty window) did not emit the age gauge — alert-on-silence is broken")
	}
	// transactions gauge persists across the quiet tick.
	if tx := gaugeValue(t, rec2, metricTransactions, "stream-1"); tx != 100 {
		t.Errorf("tick2 transactions gauge = %v, want 100 (persisted, not flapped to 0)", tx)
	}
}

func TestCheckpointStateReportsWatermark(t *testing.T) {
	// After a tick advances the watermark, CheckpointState surfaces it read-only
	// for the admin status page (#178 Part B).
	ts := fixedNow.Add(-15 * time.Minute)
	gs := &govServer{responses: []string{govBody(t, record("a", ts.UnixMilli(), ts.UnixMilli(), successStatus(1, 1)))}}
	c, _ := newTestCollector(t, gs)
	runCollect(t, c)

	st := c.CheckpointState()
	if st == nil {
		t.Fatal("CheckpointState = nil after a tick, want the persisted watermark")
	}
	if st.Kind != collector.CheckpointKindWindow {
		t.Errorf("Kind = %q, want window", st.Kind)
	}
	if !st.Watermark.Equal(ts) {
		t.Errorf("Watermark = %v, want %v (the max record timestamp seen)", st.Watermark, ts)
	}
}

func TestBasicMetadataAttrs(t *testing.T) {
	gs := &govServer{responses: []string{govBody(t, record("a", fixedNow.UnixMilli(), fixedNow.UnixMilli(), successStatus(9, 4)))}}
	c, _ := newTestCollector(t, gs)
	logs := runCollect(t, c)
	if len(logs) != 1 {
		t.Fatalf("emitted %d, want 1", len(logs))
	}
	if logs[0].EventName != eventName {
		t.Errorf("event name = %q, want %q", logs[0].EventName, eventName)
	}
	if logs[0].Attrs[semconv.AttrInputStreamId] != "stream-1" {
		t.Errorf("input_stream_id = %q", logs[0].Attrs[semconv.AttrInputStreamId])
	}
	if logs[0].Attrs[semconv.AttrIngestTransport] != string(telemetry.TransportMDCA) {
		t.Errorf("ingest_transport = %q, want %q (stamped inline, no engine)", logs[0].Attrs[semconv.AttrIngestTransport], telemetry.TransportMDCA)
	}
}
