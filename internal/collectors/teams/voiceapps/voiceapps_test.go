package voiceapps

import (
	"bytes"
	"compress/gzip"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"maps"
	"net/http"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/rknightion/graph2otel/internal/checkpoint"
	"github.com/rknightion/graph2otel/internal/collectors"
	"github.com/rknightion/graph2otel/internal/recordoutcome"
	"github.com/rknightion/graph2otel/internal/telemetrytest"
	"github.com/rknightion/graph2otel/internal/vaacclient"
)

const fixtureTenant = "00000000-0000-0000-0000-000000000001"
const fixtureAA = "00000000-0000-0000-0000-000000000002"
const fixtureCQ = "00000000-0000-0000-0000-000000000003"
const fixtureUsername = "synthetic-user@example.com"
const fixturePassword = "synthetic-fixture-secret"
const fixtureToken = "synthetic.access.token"

type fakeWire func(*http.Request) (*http.Response, error)

func (f fakeWire) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

// Synthetic and docs-derived: wire columns and response envelope come from
// Collector 2.12.1 and Microsoft's 3.3.2 template; values are invented.
func fixtureRows(end string) (aa, cq []map[string]any) {
	common := map[string]any{"ConferenceId": "synthetic-conference", "EndTime": end, "Duration": 39,
		"FirstIsCaller": true, "FirstUPN": "synthetic-first@example.com", "PSTNCallType": "synthetic-pstn",
		"PSTNConnectivityType": "synthetic-connectivity", "PSTNCallDuration": 38,
		"Timestamp": end, "UserStartTimeUTC": "2000-01-01T09:56:00Z", "TotalCallCount": 1}
	a := map[string]any{"AutoAttendantId": fixtureAA, "AutoAttendantIdentity": "synthetic-aa@example.com",
		"AutoAttendantCallFlow": "announcement>automatic_menu", "AutoAttendantCallResult": "transferred_to_cq",
		"AutoAttendantCallerActionCounts": 2, "AutoAttendantChainDurationInSecs": 5, "AutoAttendantChainIndex": 1,
		"AutoAttendantChainStartTime": end, "AutoAttendantCount": 1, "AutoAttendantDirectorySearchMethod": "abs_search_dtmf",
		"AutoAttendantTransferAction": "user", "AvgAutoAttendantChainDurationSeconds": 5, "AvgCallDuration": 39, "TotalAudioStreamDuration": 39}
	b := map[string]any{"CallQueueId": fixtureCQ, "CallQueueIdentity": "synthetic-cq@example.com", "DialogId": "synthetic-dialog",
		"SecondUPN": "synthetic-second@example.com", "CallQueueDurationSeconds": 14,
		"CallQueueCallResult": "agent_joined_conference", "CallQueueAgentCount": 4, "CallQueueAgentOptInCount": 2,
		"CallQueueFinalStateAction": "synthetic-final-action", "CallQueueTargetType": "User"}
	for k, v := range common {
		a[k], b[k] = v, v
	}
	c, d, undated := map[string]any{}, map[string]any{}, map[string]any{}
	for k, v := range b {
		c[k], undated[k] = v, v
	}
	for k, v := range a {
		d[k] = v
	}
	c["DialogId"], c["CallQueueCallResult"], c["CallQueueTargetType"], c["CallQueueDurationSeconds"] = "synthetic-abandoned", "disconnected", "Disconnect", nil
	d["AutoAttendantChainIndex"] = 2
	undated["EndTime"] = "not-an-event-time"
	return []map[string]any{a, d, a}, []map[string]any{b, c, undated}
}

func TestVoiceAppsHTTPCheckpointAndTelemetry(t *testing.T) {
	to := time.Date(2000, 1, 1, 10, 0, 0, 0, time.UTC)
	from, eventTime := to.Add(-time.Hour), to.Add(-3*time.Minute)
	aa, cq := fixtureRows(eventTime.Format(time.RFC3339))
	var tokenRequests int
	var filters [][]filterFixture
	failCQ := false
	rt := fakeWire(func(r *http.Request) (*http.Response, error) {
		if r.URL.Host == "login.microsoftonline.com" {
			tokenRequests++
			if r.URL.Scheme != "https" || r.Method != http.MethodPost || r.URL.Path != "/"+fixtureTenant+"/oauth2/token" || r.Header.Get("Authorization") != "" || r.Header.Get("Content-Type") != "application/x-www-form-urlencoded" {
				t.Fatal("unexpected VAAC token endpoint, method or headers")
			}
			if err := r.ParseForm(); err != nil || len(r.Form) != 6 || r.Form.Get("client_id") != "a672d62c-fc7b-4e81-a576-e60dc46e951d" || r.Form.Get("scope") != "user_impersonation" || r.Form.Get("grant_type") != "password" || r.Form.Get("resource") != "https://api.interfaces.records.teams.microsoft.com" || r.Form.Get("username") != fixtureUsername || r.Form.Get("password") != fixturePassword {
				t.Fatal("token form did not match VAAC contract and synthetic file contents")
			}
			return reply(http.StatusOK, `{"access_token":"`+fixtureToken+`","expires_in":"3600"}`), nil
		}
		if r.URL.Scheme != "https" || r.URL.Host != "api.interfaces.records.teams.microsoft.com" || r.URL.Path != "/Teams.VoiceAnalytics/getanalytics" || r.Method != http.MethodGet || r.Body != nil || r.Header.Get("Authorization") != "Bearer "+fixtureToken || r.Header.Get("Accept-Encoding") != "identity" {
			t.Fatal("unexpected VAAC analytics endpoint, body, method or headers")
		}
		q := decodeFixtureQuery(t, r)
		filters = append(filters, q.Filters)
		rows := aa
		switch q.Filters[2] {
		case filterFixture{"HasAA", "True", 0}:
		case filterFixture{"HasCQ", "True", 0}:
			if failCQ {
				return reply(http.StatusForbidden, fixtureUsername+fixturePassword+fixtureToken), nil
			}
			rows = cq
		default:
			t.Fatal("missing stream discriminator")
		}
		return fixtureReply(t, q, rows), nil
	})
	username, password := writeFixtureFiles(t)
	store := checkpoint.NewStore(t.TempDir())
	client, err := vaacclient.New(fixtureTenant, username, password, rt)
	if err != nil {
		t.Fatal(err)
	}
	newCollector := func() *voiceApps {
		return factory(collectors.WindowDeps{VAAC: client, Store: store, TenantID: fixtureTenant}).Collector.(*voiceApps)
	}
	c := newCollector()
	out := telemetrytest.New()
	counts := recordoutcome.NewRecorder()
	failCQ = true
	if hwm, err := c.CollectWindow(t.Context(), from, to, out.Emitter(), counts); err == nil || !hwm.IsZero() || len(out.LogRecords()) != 0 || strings.Contains(err.Error(), fixturePassword) {
		t.Fatal("a failed CQ read must not expose its response, emit the partial AA result or advance the watermark")
	}
	if s := c.CheckpointState(); s == nil || !s.Watermark.IsZero() {
		t.Fatal("partial read persisted a checkpoint")
	}
	failCQ = false
	hwm, err := c.CollectWindow(t.Context(), from, to, out.Emitter(), recordoutcome.NewRecorder())
	if err != nil || !hwm.Equal(to) {
		t.Fatalf("poll = %v, %v; want drained boundary %v", hwm, err, to)
	}
	if len(filters) != 4 || !reflect.DeepEqual(filters[0][:2], []filterFixture{{"EndTime", from.Format(time.RFC3339), 5}, {"EndTime", to.Format(time.RFC3339), 7}}) {
		t.Fatal("initial read did not use the sourced EndTime filters")
	}
	logs := out.LogRecords()
	if len(logs) != 5 {
		t.Fatalf("emitted %d logs; want two AA chain legs, two CQ legs and one saved-batch summary", len(logs))
	}
	for _, rec := range logs[:4] {
		if rec.Timestamp != eventTime || rec.Attrs["ingest_transport"] != "vaac" {
			t.Fatal("incorrect event time or transport")
		}
	}
	if logs[0].EventName != aaEvent || logs[0].Attrs["auto_attendant_call_flow"] != "announcement>automatic_menu" || logs[1].Attrs["auto_attendant_chain_index"] != "2" || logs[2].EventName != cqEvent || logs[2].Attrs["agent_name"] != "synthetic-first@example.com" || logs[3].Attrs["dialog_id"] != "synthetic-abandoned" {
		t.Fatal("voice analytics log twins lost call or leg detail")
	}
	for _, metric := range []string{abandonRate, answerRate, waitTime, aaOutcome} {
		points := out.MetricPoints(metric)
		if len(points) != 1 {
			t.Fatalf("%s metric points = %d, want 1", metric, len(points))
		}
		wantValue, wantAttrs := 0.5, map[string]string{"queue": fixtureCQ}
		if metric == waitTime {
			wantValue = 14
			if points[0].Count != 1 {
				t.Fatal("missing queue wait became zero")
			}
		}
		if metric == aaOutcome {
			wantValue, wantAttrs = 2, map[string]string{"auto_attendant": fixtureAA, "voice_outcome": "transferred"}
		}
		if points[0].Value != wantValue || !reflect.DeepEqual(points[0].Attrs, wantAttrs) {
			t.Fatalf("%s did not emit the expected bounded aggregate: %+v", metric, points[0])
		}
	}
	// A freshly constructed collector reads the same durable SeenIDs. The
	// response still includes old rows, as it would for the overlap window.
	restarted := telemetrytest.New()
	if _, err := newCollector().CollectWindow(t.Context(), to, to.Add(15*time.Minute), restarted.Emitter(), recordoutcome.NewRecorder()); err != nil {
		t.Fatal(err)
	}
	if len(restarted.LogRecords()) != 0 || tokenRequests != 1 || len(filters) != 6 || filters[4][0].Value != to.Add(-6*time.Hour).Format(time.RFC3339) {
		t.Fatal("overlap re-emitted a known leg, skipped the overlap or requested a fresh token")
	}
}

func TestVoiceAppsQueueAdmissionAcrossOverlap(t *testing.T) {
	const queueB = "00000000-0000-0000-0000-000000000004"
	const otherTenant = "00000000-0000-0000-0000-000000000005"
	to := time.Date(2000, 1, 1, 10, 0, 0, 0, time.UTC)
	at := to.Add(-time.Minute)
	_, cq := fixtureRows(at.Format(time.RFC3339))
	answeredA, abandonedA := cq[0], cq[1]
	unknownA := maps.Clone(abandonedA)
	unknownA["DialogId"], unknownA["CallQueueCallResult"] = "synthetic-missing-result", nil
	unknownB := maps.Clone(answeredA) // same dialog ID, different queue
	unknownB["CallQueueId"], unknownB["CallQueueCallResult"], unknownB["CallQueueDurationSeconds"] = queueB, "synthetic-unrecognized", 0
	otherA := maps.Clone(abandonedA)
	otherA["DialogId"], otherA["CallQueueCallResult"] = "synthetic-other", "overflown"
	unkeyedA := maps.Clone(answeredA) // known result and wait, but an invalid dialog type
	unkeyedA["DialogId"] = 42
	unkeyed := maps.Clone(abandonedA) // dialog, but no queue or result
	unkeyed["CallQueueId"], unkeyed["CallQueueCallResult"], unkeyed["CallQueueDurationSeconds"] = nil, nil, 0
	rows := []map[string]any{answeredA, abandonedA, otherA, unknownA, unknownB, unkeyedA, unkeyed}
	nextB := maps.Clone(answeredA)
	nextB["DialogId"], nextB["CallQueueId"], nextB["EndTime"] = "synthetic-next-dialog", queueB, to.Add(time.Minute).Format(time.RFC3339)
	nextA := maps.Clone(unknownA)
	nextA["DialogId"], nextA["EndTime"] = "synthetic-next-unknown", nextB["EndTime"]
	rt := fakeWire(func(r *http.Request) (*http.Response, error) {
		if r.Method == http.MethodPost {
			return reply(http.StatusOK, `{"access_token":"`+fixtureToken+`","expires_in":3600}`), nil
		}
		q := decodeFixtureQuery(t, r)
		if q.Filters[2].DataModelName == "HasAA" {
			return reply(http.StatusOK, `{"dataResult":[]}`), nil
		}
		return fixtureReply(t, q, rows), nil
	})
	username, password := writeFixtureFiles(t)
	client, err := vaacclient.New(fixtureTenant, username, password, rt)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	poll := func(tenant string, from, to time.Time) *telemetrytest.Recorder {
		t.Helper()
		c := factory(collectors.WindowDeps{VAAC: client, Store: checkpoint.NewStore(dir), TenantID: tenant}).Collector.(*voiceApps)
		out := telemetrytest.New()
		hwm, err := c.CollectWindow(t.Context(), from, to, out.Emitter(), recordoutcome.NewRecorder())
		if err != nil || !hwm.Equal(to) {
			t.Fatalf("poll = %v, %v; want %v", hwm, err, to)
		}
		return out
	}
	checkMetric := func(out *telemetrytest.Recorder, name string, want map[string]float64) {
		t.Helper()
		got := make(map[string]float64)
		for _, point := range out.MetricPoints(name) {
			queue := point.Attrs["queue"]
			if !maps.Equal(point.Attrs, map[string]string{"queue": queue}) {
				t.Fatalf("%s has unexpected dimensions: %v", name, point.Attrs)
			}
			if name == waitTime && point.Count != 1 {
				t.Fatalf("queue %s wait samples = %d; want 1", queue, point.Count)
			}
			got[queue] = point.Value
		}
		if !maps.Equal(got, want) {
			t.Errorf("%s = %v; want %v", name, got, want)
		}
	}
	processingStart := time.Now()
	first := poll(fixtureTenant, to.Add(-time.Hour), to)
	parallelTenant := poll(otherTenant, to.Add(-time.Hour), to)
	rows = append(rows, nextA, nextB) // old keyed and unkeyed observations replay on a fresh collector
	second := poll(fixtureTenant, to, to.Add(5*time.Minute))
	checkMetric(first, answerRate, map[string]float64{fixtureCQ: 1.0 / 3})
	checkMetric(first, abandonRate, map[string]float64{fixtureCQ: 1.0 / 3})
	checkMetric(first, waitTime, map[string]float64{fixtureCQ: 14, queueB: 0})
	checkMetric(second, answerRate, map[string]float64{queueB: 1})
	checkMetric(second, abandonRate, map[string]float64{queueB: 0})
	checkMetric(second, waitTime, map[string]float64{queueB: 14})

	savedBatches := func(out *telemetrytest.Recorder) map[string][5]string {
		t.Helper()
		got := map[string][5]string{}
		for _, rec := range out.LogRecords() {
			if rec.EventName != "teams.call_queue_batch" {
				continue
			}
			if rec.Timestamp.Before(processingStart) || rec.Attrs["ingest_transport"] != "vaac" {
				t.Fatalf("queue batch must have a processing timestamp and VAAC transport")
			}
			queue := rec.Attrs["queue"]
			if _, exists := got[queue]; exists {
				t.Fatalf("queue %s has several batch observations", queue)
			}
			got[queue] = [5]string{rec.Attrs["known_result_legs"], rec.Attrs["answered_legs"], rec.Attrs["abandoned_legs"],
				rec.Attrs["answer_share"], rec.Attrs["abandon_share"]}
		}
		return got
	}
	third := strconv.FormatFloat(1.0/3, 'g', -1, 64)
	if got := savedBatches(first); !maps.Equal(got, map[string][5]string{fixtureCQ: {"3", "1", "1", third, third}, queueB: {"0", "0", "0", "", ""}}) {
		t.Errorf("first saved-batch observations = %v", got)
	}
	if got := savedBatches(second); !maps.Equal(got, map[string][5]string{fixtureCQ: {"0", "0", "0", "", ""}, queueB: {"1", "1", "0", "1", "0"}}) {
		t.Errorf("second saved-batch observations = %v", got)
	}

	type key struct{ queue, dialog string }
	observations := map[key]int{}
	bodies := map[string]key{}
	for _, rec := range append(first.LogRecords(), second.LogRecords()...) {
		if rec.EventName == "teams.call_queue_batch" {
			continue
		}
		if rec.EventName != cqEvent || rec.Attrs["ingest_transport"] != "vaac" {
			t.Fatalf("unexpected queue observation: %+v", rec)
		}
		k := key{rec.Attrs["queue"], rec.Attrs["dialog_id"]}
		wantAt := at
		if k.dialog == "synthetic-next-dialog" || k.dialog == "synthetic-next-unknown" {
			wantAt = to.Add(time.Minute)
		}
		if !rec.Timestamp.Equal(wantAt) {
			t.Errorf("queue observation %v time = %v; want event time %v", k, rec.Timestamp, wantAt)
		}
		observations[k]++
		if previous, ok := bodies[rec.Body]; ok && previous != k {
			t.Fatalf("distinct queue observations at the same event time share one Loki body: %v and %v", previous, k)
		}
		bodies[rec.Body] = k
	}
	for _, rec := range parallelTenant.LogRecords() {
		if _, exists := bodies[rec.Body]; exists {
			t.Errorf("two tenants observing the same source row emitted the same body")
		}
	}
	// Eleven observations are not eleven legs: seven have a complete key.
	// The two unkeyed observations remain evidence on both reads.
	want := map[key]int{
		{fixtureCQ, "synthetic-dialog"}: 1, {fixtureCQ, "synthetic-abandoned"}: 1, {fixtureCQ, "synthetic-other"}: 1,
		{fixtureCQ, "synthetic-missing-result"}: 1, {fixtureCQ, "synthetic-next-unknown"}: 1,
		{queueB, "synthetic-dialog"}: 1, {queueB, "synthetic-next-dialog"}: 1,
		{fixtureCQ, ""}: 2, {"", "synthetic-abandoned"}: 2,
	}
	if !maps.Equal(observations, want) {
		t.Errorf("queue observations = %v; want %v", observations, want)
	}
}

type filterFixture struct {
	DataModelName, Value string
	Operand              int
}
type queryFixture struct {
	Filters                  []filterFixture
	Dimensions, Measurements []struct{ DataModelName string }
	Parameters               map[string]string
	LimitResultRowsCount     int
}

func decodeFixtureQuery(t *testing.T, r *http.Request) queryFixture {
	t.Helper()
	params := r.URL.Query()
	data, err := base64.StdEncoding.DecodeString(params.Get("query"))
	if err != nil || len(params) != 1 {
		t.Fatal("analytics query is not the expected base64 parameter")
	}
	z, err := gzip.NewReader(bytes.NewReader(data))
	if err != nil {
		t.Fatal("analytics query is not gzip")
	}
	defer z.Close()
	var q queryFixture
	if err := json.NewDecoder(z).Decode(&q); err != nil || len(q.Filters) != 3 || q.Parameters["UserAgent"] != "Power BI Desktop" || q.LimitResultRowsCount <= 0 || q.LimitResultRowsCount > 4900 {
		t.Fatal("analytics query does not match the bounded Power BI request shape")
	}
	return q
}
func fixtureReply(t *testing.T, q queryFixture, rows []map[string]any) *http.Response {
	t.Helper()
	var result [][]any
	for _, row := range rows {
		values := make([]any, 0, len(q.Dimensions)+len(q.Measurements))
		seen := map[string]bool{}
		for _, columns := range [][]struct{ DataModelName string }{q.Dimensions, q.Measurements} {
			for _, c := range columns {
				v, ok := row[c.DataModelName]
				if !ok || seen[c.DataModelName] {
					t.Fatalf("unexpected or duplicate column %q", c.DataModelName)
				}
				seen[c.DataModelName] = true
				values = append(values, v)
			}
		}
		if len(seen) != len(row) {
			t.Fatal("VAAC query omitted a sourced fixture column")
		}
		result = append(result, values)
	}
	body, err := json.Marshal(map[string]any{"dataResult": result})
	if err != nil {
		t.Fatal(err)
	}
	return reply(http.StatusOK, string(body))
}
func reply(code int, body string) *http.Response {
	return &http.Response{StatusCode: code, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(body))}
}
func writeFixtureFiles(t *testing.T) (string, string) {
	t.Helper()
	dir := t.TempDir()
	u, p := filepath.Join(dir, "username"), filepath.Join(dir, "password")
	for file, value := range map[string]string{u: fixtureUsername, p: fixturePassword} {
		if err := os.WriteFile(file, fmt.Appendf(nil, "%s\n", value), 0600); err != nil {
			t.Fatal(err)
		}
	}
	return u, p
}
