package directroutingcalls

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/rknightion/graph2otel/internal/checkpoint"
	"github.com/rknightion/graph2otel/internal/collectors"
	"github.com/rknightion/graph2otel/internal/telemetry"
	"github.com/rknightion/graph2otel/internal/telemetrytest"
)

const (
	functionURL = "https://graph.microsoft.com/v1.0/communications/callRecords/getDirectRoutingCalls"
	countMetric = "teams.direct_routing.calls"
	ratioMetric = "teams.direct_routing.network_effectiveness_ratio"
)

func TestDirectRoutingFixtureReplay(t *testing.T) {
	to := time.Now().UTC().Truncate(time.Second)
	from := to.Add(-3 * time.Hour)
	start, late := to.Add(-time.Hour), to.Add(-2*time.Hour)
	rows := loadRows(t, start, late)
	next := functionURL + "(from=opaque,to=opaque)?%24skip=1000"
	secondTo := to.Add(time.Minute)
	cutover := to.Add(-24 * time.Hour)
	fetch := &replay{t: t, pages: []page{
		{url: initialURL(from, to), next: next, rows: []map[string]any{rows.Answered}},
		{url: next, err: errors.New("fixture page unavailable")},
		{url: initialURL(from, to), next: next, rows: []map[string]any{rows.Answered}},
		{url: next, rows: []map[string]any{rows.Busy, rows.Failed}},
		{url: initialURL(cutover, secondTo), rows: []map[string]any{rows.Failed, rows.Late, rows.Answered, rows.Busy}},
		{url: initialURL(secondTo.Add(-24*time.Hour), secondTo.Add(time.Minute)), rows: []map[string]any{rows.Late}},
	}}
	deps := collectors.WindowDeps{TenantID: "fixture-tenant", Store: checkpoint.NewStore(t.TempDir()), Fetcher: fetch}
	c := newPoller(deps)
	rec := telemetrytest.New()
	if _, err := c.CollectWindow(t.Context(), from, to, rec.Emitter(), nil); err == nil {
		t.Fatal("page failure did not fail the poll")
	}
	if len(rec.LogRecords()) != 0 || len(rec.MetricPoints(countMetric)) != 0 || len(rec.MetricPoints(ratioMetric)) != 0 {
		t.Fatal("page failure published a partial window")
	}
	if _, err := c.CollectWindow(t.Context(), from, to, rec.Emitter(), nil); err != nil {
		t.Fatal(err)
	}
	assertRatio(t, rec, 2.0/3)
	if _, err := c.CollectWindow(t.Context(), to, secondTo, rec.Emitter(), nil); err != nil {
		t.Fatal(err)
	}
	assertRatio(t, rec, 0)
	if _, err := c.CollectWindow(t.Context(), secondTo, secondTo.Add(time.Minute), rec.Emitter(), nil); err != nil {
		t.Fatal(err)
	}
	if p := rec.MetricPoints(ratioMetric); len(p) != 0 {
		t.Fatalf("poll without new attempts must not emit a ratio: %+v", p)
	}
	logs := slices.DeleteFunc(rec.LogRecords(), func(log telemetrytest.LogRecord) bool {
		return log.EventName != "teams.direct_routing_call"
	})
	if len(logs) != 4 || len(fetch.pages) != 0 {
		t.Fatalf("got %d logs and %d unused replay pages; want 4 logs and 0 pages", len(logs), len(fetch.pages))
	}
	for _, log := range logs {
		if log.EventName != "teams.direct_routing_call" || log.Attrs["ingest_transport"] != "graph" {
			t.Fatalf("incorrect event routing: %+v", log)
		}
		switch log.Attrs["id"] {
		case "fixture-answered":
			if !log.Timestamp.Equal(start) || log.Attrs["trunk_fqdn"] != "SBC.EXAMPLE.INVALID." ||
				log.Attrs["media_bypass_enabled"] != "false" || log.Attrs["failure_time"] != "" {
				t.Fatalf("answered row lost detail or emitted the date sentinel: %+v", log)
			}
		case "fixture-failed":
			if log.Attrs["successful_call"] != "false" || log.Attrs["final_sip_code"] != "503" ||
				log.Attrs["call_end_sub_reason"] != "503001" || log.Attrs["end_time"] != "" || log.Attrs["failure_time"] == "" {
				t.Fatalf("failed row lost detail: %+v", log)
			}
		case "fixture-late":
			if !log.Timestamp.Equal(late) {
				t.Fatalf("late row timestamp: %+v", log)
			}
		}
	}
	want := map[string]float64{"answered/2xx": 1, "busy/4xx": 1, "failed/5xx": 2}
	for _, p := range rec.MetricPoints(countMetric) {
		key := p.Attrs["outcome"] + "/" + p.Attrs["sip_class"]
		if p.Value != want[key] || p.Attrs["trunk_fqdn"] != "sbc.example.invalid" || len(p.Attrs) != 3 {
			t.Fatalf("unexpected attempt count: %+v", p)
		}
		delete(want, key)
	}
	if len(want) != 0 {
		t.Fatalf("missing attempt counts: %v", want)
	}
}

func TestDirectRoutingKeepsSourceSuccessAndSIPConflict(t *testing.T) {
	to := time.Now().UTC().Truncate(time.Second)
	from := to.Add(-3 * time.Hour)
	start := to.Add(-time.Hour).Format(time.RFC3339)
	const trunk = "sbc.example.invalid"
	rows := []map[string]any{
		{"id": "fixture-success-403", "startDateTime": start, "trunkFullyQualifiedDomainName": trunk,
			"successfulCall": true, "finalSipCode": float64(403)},
		{"id": "fixture-busy", "startDateTime": start, "trunkFullyQualifiedDomainName": trunk,
			"successfulCall": false, "finalSipCode": float64(486)},
		{"id": "fixture-unknown", "startDateTime": start, "trunkFullyQualifiedDomainName": trunk},
	}
	fetch := &replay{t: t, pages: []page{{url: initialURL(from, to), rows: rows}}}
	c := newPoller(collectors.WindowDeps{TenantID: "fixture-tenant", Store: checkpoint.NewStore(t.TempDir()), Fetcher: fetch})
	rec := telemetrytest.New()
	if _, err := c.CollectWindow(t.Context(), from, to, rec.Emitter(), nil); err != nil {
		t.Fatal(err)
	}
	found := false
	for _, log := range rec.LogRecords() {
		if log.Attrs["id"] == "fixture-success-403" {
			found = true
			if log.Attrs["successful_call"] != "true" || log.Attrs["final_sip_code"] != "403" {
				t.Fatalf("attempt must preserve both source success and SIP 403: %+v", log.Attrs)
			}
		}
	}
	if !found {
		t.Fatal("missing attempt with source success and SIP 403")
	}
	want := map[string]float64{"answered/4xx": 1, "busy/4xx": 1, "unknown/unknown": 1}
	for _, p := range rec.MetricPoints(countMetric) {
		key := p.Attrs["outcome"] + "/" + p.Attrs["sip_class"]
		if p.Value != want[key] || p.Attrs["trunk_fqdn"] != trunk {
			t.Fatalf("unexpected attempt count: %+v", p)
		}
		delete(want, key)
	}
	if len(want) != 0 {
		t.Fatalf("missing attempt counts: %v", want)
	}
	// Source success and busy are effective. The unclassified attempt is
	// still in the denominator; a 4xx is not necessarily an ineffective call.
	assertRatio(t, rec, 2.0/3)
	polls := slices.DeleteFunc(rec.LogRecords(), func(log telemetrytest.LogRecord) bool {
		return log.EventName != "teams.direct_routing_poll"
	})
	if len(polls) != 1 || polls[0].Attrs["trunk_fqdn"] != trunk || polls[0].Attrs["poll_attempts"] != "3" ||
		polls[0].Attrs["effective_attempts"] != "2" || polls[0].Attrs["source_success_sip_4xx"] != "1" ||
		!polls[0].Timestamp.After(to.Add(-time.Second)) {
		t.Fatalf("missing joint counts at poll time: %+v", polls)
	}
}

func TestDirectRoutingUsesCentralTrunkBudget(t *testing.T) {
	to := time.Now().UTC().Truncate(time.Second)
	from := to.Add(-3 * time.Hour)
	var rows []map[string]any
	for i := range 40 {
		rows = append(rows, map[string]any{
			"id": fmt.Sprintf("fixture-id-%d", i), "startDateTime": from.Add(time.Duration(i) * time.Second).Format(time.RFC3339),
			"trunkFullyQualifiedDomainName": fmt.Sprintf("trunk-%d.example.invalid", i), "finalSipCode": float64(600),
		})
	}
	fetch := &replay{t: t, pages: []page{{url: initialURL(from, to), rows: rows}}}
	c := newPoller(collectors.WindowDeps{TenantID: "fixture-tenant", Store: checkpoint.NewStore(t.TempDir()), Fetcher: fetch})
	rec := telemetrytest.New()
	const budget = 36
	limited := telemetry.WithCardinalityLimits(rec.Emitter(), telemetry.Limits{PerMetric: budget})
	if _, err := c.CollectWindow(t.Context(), from, to, limited, nil); err != nil {
		t.Fatal(err)
	}
	counts := make(map[string]float64)
	for _, p := range rec.MetricPoints(countMetric) {
		counts[p.Attrs["trunk_fqdn"]] += p.Value
		if p.Attrs["outcome"] != "busy" || p.Attrs["sip_class"] != "6xx" {
			t.Fatalf("SIP 600 did not retain its outcome and class: %+v", p)
		}
	}
	if len(counts) != budget+1 || counts["other"] != 4 {
		t.Fatalf("central budget: %d count series with %v attempts in other, want %d plus 4 attempts in other", len(counts), counts["other"], budget+1)
	}
	ratios := rec.MetricPoints(ratioMetric)
	if len(ratios) != budget {
		t.Fatalf("got %d effectiveness ratios, want exactly the central budget %d", len(ratios), budget)
	}
	for _, p := range ratios {
		if p.Attrs["trunk_fqdn"] == "other" || p.Value != 1 {
			t.Fatalf("non-additive ratio must not be folded: %+v", p)
		}
	}
	var logs int
	polls := make(map[string]struct{})
	bodies := make(map[string]struct{})
	for _, event := range rec.LogRecords() {
		switch event.EventName {
		case "teams.direct_routing_call":
			logs++
			if logs == 40 && event.Attrs["trunk_fqdn"] != "trunk-39.example.invalid" {
				t.Fatalf("raw trunk was folded: %+v", event)
			}
		case "teams.direct_routing_poll":
			name := event.Attrs["trunk_fqdn"]
			if !strings.HasPrefix(name, "trunk-") || event.Attrs["poll_attempts"] != "1" ||
				event.Attrs["effective_attempts"] != "1" || event.Attrs["source_success_sip_4xx"] != "0" {
				t.Fatalf("poll counts split by the metric budget: %+v", event)
			}
			polls[name] = struct{}{}
			bodies[event.Body] = struct{}{}
		}
	}
	if logs != 40 || len(polls) != 40 || len(bodies) != 40 {
		t.Fatalf("got %d source rows and %d poll summaries with %d distinct bodies; want 40 of each", logs, len(polls), len(bodies))
	}
}

func assertRatio(t *testing.T, rec *telemetrytest.Recorder, want float64) {
	t.Helper()
	p := rec.MetricPoints(ratioMetric)
	if len(p) != 1 || p[0].Value != want || p[0].Attrs["trunk_fqdn"] != "sbc.example.invalid" || len(p[0].Attrs) != 1 {
		t.Fatalf("network effectiveness: %+v, want %g for sbc.example.invalid", p, want)
	}
}

type fixture struct{ Answered, Busy, Failed, Late map[string]any }

func loadRows(t *testing.T, start, late time.Time) fixture {
	t.Helper()
	body, err := os.ReadFile("testdata/routes.json")
	if err != nil {
		t.Fatal(err)
	}
	var rows fixture
	r := strings.NewReplacer("{{start}}", start.Format(time.RFC3339), "{{end}}", start.Add(30*time.Second).Format(time.RFC3339), "{{late}}", late.Format(time.RFC3339))
	if err := json.Unmarshal([]byte(r.Replace(string(body))), &rows); err != nil {
		t.Fatal(err)
	}
	return rows
}

func initialURL(from, to time.Time) string {
	return fmt.Sprintf("%s(fromDateTime=%s,toDateTime=%s)", functionURL, from.Format(time.RFC3339), to.Format(time.RFC3339))
}

type page struct {
	url, next string
	rows      []map[string]any
	err       error
}

type replay struct {
	t     *testing.T
	pages []page
}

func (r *replay) FetchPage(_ context.Context, url string) ([]map[string]any, string, error) {
	r.t.Helper()
	if len(r.pages) == 0 || url != r.pages[0].url {
		r.t.Fatalf("unexpected Direct Routing request %s, remaining replay: %+v", url, r.pages)
	}
	p := r.pages[0]
	r.pages = r.pages[1:]
	return p.rows, p.next, p.err
}
