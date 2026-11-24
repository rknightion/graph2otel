package pstncalls

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/rknightion/graph2otel/internal/checkpoint"
	"github.com/rknightion/graph2otel/internal/collectors"
	"github.com/rknightion/graph2otel/internal/telemetry"
	"github.com/rknightion/graph2otel/internal/telemetrytest"
)

func TestPSTNFixtureReplay(t *testing.T) {
	to := time.Now().UTC().Truncate(time.Second)
	from := to.Add(-3 * time.Hour)
	first := to.Add(-time.Hour)
	late := to.Add(-2 * time.Hour)
	body, err := os.ReadFile("testdata/pstn.json")
	if err != nil {
		t.Fatal(err)
	}
	var rows struct{ First, Second, Late, Outside []map[string]any }
	replace := strings.NewReplacer("{{first}}", first.Format(time.RFC3339), "{{end}}", first.Add(90*time.Second).Format(time.RFC3339),
		"{{late}}", late.Format(time.RFC3339), "{{old}}", to.Add(-48*time.Hour).Format(time.RFC3339))
	if err := json.Unmarshal([]byte(replace.Replace(string(body))), &rows); err != nil {
		t.Fatal(err)
	}
	next := "https://graph.microsoft.com/v1.0/communications/callRecords/getPstnCalls(from=opaque,to=opaque)?%24skip=1000"
	secondTo := to.Add(time.Minute)
	steps := []page{
		{url: initialURL(from, to), next: next, rows: rows.First},
		{url: next, rows: rows.Second},
		{url: initialURL(to.Add(-24*time.Hour), secondTo), rows: join(rows.First, rows.Second, rows.Late, rows.Outside)},
		{url: initialURL(secondTo.Add(-24*time.Hour), secondTo.Add(time.Minute)), rows: join(rows.First, rows.Second, rows.Late)},
	}
	fetch := &replay{t: t, pages: steps}
	store := t.TempDir()
	deps := collectors.WindowDeps{TenantID: "fixture-tenant", Store: checkpoint.NewStore(store), Fetcher: fetch}
	rec := telemetrytest.New()
	c := newPoller(deps)
	if _, err := c.CollectWindow(t.Context(), from, to, rec.Emitter(), nil); err != nil {
		t.Fatal(err)
	}
	if got := rec.LogRecords(); len(got) != 2 {
		t.Fatalf("first poll emitted %d logs, want two calls sharing a row ID", len(got))
	}
	// Recreate the collector and store before overlap replay.
	deps.Store = checkpoint.NewStore(store)
	c = newPoller(deps)
	if _, err := c.CollectWindow(t.Context(), to, secondTo, rec.Emitter(), nil); err != nil {
		t.Fatal(err)
	}
	if _, err := c.CollectWindow(t.Context(), secondTo, secondTo.Add(time.Minute), rec.Emitter(), nil); err != nil {
		t.Fatal(err)
	}
	logs := rec.LogRecords()
	if len(logs) != 3 || len(fetch.pages) != 0 {
		t.Fatalf("got %d logs and %d unused responses, want 3 logs and 0 responses", len(logs), len(fetch.pages))
	}
	byID := make(map[string]telemetrytest.LogRecord)
	for _, log := range logs {
		if log.EventName != "teams.pstn_call" || log.Attrs["ingest_transport"] != "graph" {
			t.Fatalf("incorrect event routing: %v", log)
		}
		byID[log.Attrs["call_id"]] = log
	}
	if a := byID["fixture-call-a"]; !a.Timestamp.Equal(first) || a.Attrs["caller_number"] != "+000***" ||
		a.Attrs["callee_number"] != "+001***" || a.Attrs["charge"] != "0" || a.Attrs["connectivity_type"] != "calling_plan" {
		t.Fatalf("PSTN log lost detail: %+v", a)
	}
	if b := byID["fixture-call-b"]; !b.Timestamp.Equal(first) || b.Attrs["id"] != "fixture-shared-id" ||
		b.Attrs["connectivity_type"] != "OperatorConnect" || b.Attrs["charge"] != "" {
		t.Fatalf("second PSTN call lost detail: %+v", b)
	}
	if row := byID["fixture-call-c"]; !row.Timestamp.Equal(late) {
		t.Fatalf("late call was lost or misdated: %+v", row)
	}
	calls := rec.MetricPoints("teams.pstn.calls")
	if len(calls) != 2 {
		t.Fatalf("wrong PSTN counts: %+v", calls)
	}
	for _, p := range calls {
		if len(p.Attrs) != 2 || !(p.Attrs["call_type"] == "user_in" && p.Attrs["connectivity_type"] == "calling_plan" && p.Value == 2 ||
			p.Attrs["call_type"] == "user_out" && p.Attrs["connectivity_type"] == "operator_connect" && p.Value == 1) {
			t.Fatalf("wrong PSTN count: %+v", p)
		}
	}
	minutes := rec.MetricPoints("teams.pstn.minutes")
	if len(minutes) != 1 || minutes[0].Value != 3 || len(minutes[0].Attrs) != 0 {
		t.Fatalf("wrong PSTN minutes: %+v", minutes)
	}
}

func TestPSTNSkipsExpiredCatchup(t *testing.T) {
	before := time.Now()
	from := before.Add(-160 * 24 * time.Hour)
	to := from.Add(time.Hour)
	store := checkpoint.NewStore(t.TempDir())
	cp, err := store.Load("fixture-tenant", name)
	if err != nil {
		t.Fatal(err)
	}
	cp.Watermark = from
	cp.SeenIDs.Add("fixture-expired-id", from)
	if err := store.Save(cp); err != nil {
		t.Fatal(err)
	}
	// An expired pending slice must not reach the fetcher at all.
	fetch := &replay{t: t}
	c := newPoller(collectors.WindowDeps{TenantID: "fixture-tenant", Store: store, Fetcher: fetch})
	hw, err := c.CollectWindow(t.Context(), from, to, telemetrytest.New().Emitter(), nil)
	if err != nil || hw.Before(before.Add(-telemetry.EventHorizon)) || hw.After(time.Now().Add(-telemetry.EventHorizon)) {
		t.Fatalf("expired catch-up returned %v, %v; want cursor at event horizon", hw, err)
	}
	if state := c.CheckpointState(); !state.Watermark.Equal(hw) || state.SeenIDs != 0 {
		t.Fatalf("expired cursor was not durably pruned: %+v", state)
	}
}

func initialURL(from, to time.Time) string {
	return fmt.Sprintf("https://graph.microsoft.com/v1.0/communications/callRecords/getPstnCalls(fromDateTime=%s,toDateTime=%s)", from.Format(time.RFC3339), to.Format(time.RFC3339))
}

type page struct {
	url, next string
	rows      []map[string]any
}

type replay struct {
	t     *testing.T
	pages []page
}

func (r *replay) FetchPage(_ context.Context, url string) ([]map[string]any, string, error) {
	r.t.Helper()
	if len(r.pages) == 0 || url != r.pages[0].url {
		r.t.Fatalf("unexpected PSTN request %s, remaining replay: %+v", url, r.pages)
	}
	p := r.pages[0]
	r.pages = r.pages[1:]
	return p.rows, p.next, nil
}

func join(groups ...[]map[string]any) []map[string]any {
	var rows []map[string]any
	for _, group := range groups {
		rows = append(rows, group...)
	}
	return rows
}
