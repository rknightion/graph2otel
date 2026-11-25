package directroutingcalls

import (
	"encoding/json"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/rknightion/graph2otel/internal/checkpoint"
	"github.com/rknightion/graph2otel/internal/collectors"
	"github.com/rknightion/graph2otel/internal/recordoutcome"
	"github.com/rknightion/graph2otel/internal/telemetrytest"
)

// Graph returns startDateTime null on every failed Direct Routing attempt
// (live-measured). Those rows must keep the attempt's invite time, or its
// failure time when that is all there is, instead of being dropped as undated.
func TestDirectRoutingKeepsFailedAttemptsWithoutStartTime(t *testing.T) {
	to := time.Now().UTC().Truncate(time.Second)
	from := to.Add(-3 * time.Hour)
	invite := to.Add(-time.Hour).Add(414 * time.Millisecond)
	failure := invite.Add(1659 * time.Millisecond)
	start := invite.Add(3575 * time.Millisecond)
	body, err := os.ReadFile("testdata/failed_live.json")
	if err != nil {
		t.Fatal(err)
	}
	const wire = "2006-01-02T15:04:05.000Z"
	var rows map[string]json.RawMessage
	r := strings.NewReplacer("{{invite}}", invite.Format(wire), "{{failure}}", failure.Format(wire),
		"{{start}}", start.Format(wire), "{{end}}", start.Add(63*time.Second).Format(wire))
	if err := json.Unmarshal([]byte(r.Replace(string(body))), &rows); err != nil {
		t.Fatal(err)
	}
	var batch []map[string]any
	for _, k := range []string{"failedOutbound", "failedInbound", "answeredOutbound", "failureOnly", "undated"} {
		var row map[string]any
		if err := json.Unmarshal(rows[k], &row); err != nil {
			t.Fatal(err)
		}
		batch = append(batch, row)
	}
	fetch := &replay{t: t, pages: []page{{url: initialURL(from, to), rows: batch}}}
	c := newPoller(collectors.WindowDeps{TenantID: "fixture-tenant", Store: checkpoint.NewStore(t.TempDir()), Fetcher: fetch})
	rec := telemetrytest.New()
	outcomes := recordoutcome.NewRecorder()
	if _, err := c.CollectWindow(t.Context(), from, to, rec.Emitter(), outcomes); err != nil {
		t.Fatal(err)
	}

	want := map[string]time.Time{
		"fixture-failed-out": invite, "fixture-failed-in": invite,
		"fixture-answered-out": start, "fixture-failure-only": failure,
	}
	for _, log := range rec.LogRecords() {
		id := log.Attrs["id"]
		ts, ok := want[id]
		if !ok {
			t.Fatalf("unexpected log %q: %+v", id, log)
		}
		if !log.Timestamp.Equal(ts) {
			t.Fatalf("%s timestamp %s, want %s", id, log.Timestamp, ts)
		}
		delete(want, id)
		switch id {
		case "fixture-failed-out":
			if log.Attrs["start_time"] != "" || log.Attrs["end_time"] != "" || log.Attrs["successful_call"] != "false" ||
				log.Attrs["call_end_sub_reason"] != "560487" || log.Attrs["media_path_location"] != "EUWE" {
				t.Fatalf("failed outbound lost detail or invented a time: %+v", log)
			}
		case "fixture-failed-in":
			if _, present := log.Attrs["media_path_location"]; present {
				t.Fatalf("empty mediaPathLocation must be absent, got %q", log.Attrs["media_path_location"])
			}
		}
	}
	if len(want) != 0 {
		t.Fatalf("dropped rows: %v", want)
	}
	counts := make(map[string]float64)
	for _, p := range rec.MetricPoints(countMetric) {
		counts[p.Attrs["outcome"]+"/"+p.Attrs["sip_class"]] += p.Value
	}
	if counts["failed/4xx"] != 2 || counts["answered/2xx"] != 1 || counts["failed/5xx"] != 1 || len(counts) != 3 {
		t.Fatalf("attempt counts %v, want 2 failed/4xx, 1 failed/5xx and 1 answered/2xx", counts)
	}
	assertRatio(t, rec, 1.0/4)
	// Only the row with no parseable time of any kind is dropped, never stamped.
	if s := outcomes.Snapshot(); s.Counts.Dropped != 1 || s.Counts.Emitted != 4 {
		t.Fatalf("outcomes %+v, want 4 emitted and only the undated row dropped", s.Counts)
	}
}
