package callrecords

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/rknightion/graph2otel/internal/checkpoint"
	"github.com/rknightion/graph2otel/internal/collectors"
	"github.com/rknightion/graph2otel/internal/teams/sites"
	"github.com/rknightion/graph2otel/internal/telemetry"
	"github.com/rknightion/graph2otel/internal/telemetrytest"
)

// Synthetic and docs-derived. The owner waiver for #659 permits fixtures,
// not claims about production Graph response coverage.
func TestQualityMetricsAcrossIngressAndRestart(t *testing.T) {
	start := now.Add(-10 * time.Minute)
	version, rtt := 2, "PT0.075S"
	g := fakeGraph(func(address, prefer string) ([]byte, error) {
		switch address {
		case absolutePath + "/quality?$expand=sessions($expand=segments)":
			d := syntheticDetail(t, "quality", version, start)
			firstAudioStream(d)["averageRoundTripTime"] = rtt
			return encoded(t, d), nil
		case absolutePath + "/quality/participants_v2":
			return peoplePage(t), nil
		default:
			assertList(t, address, prefer)
			return collection(t, "", listEntry("quality", version, start)), nil
		}
	})
	dir := t.TempDir()
	restart := func() *Collector {
		return collectorForTest(t, collectors.WindowDeps{Graph: g, Store: checkpoint.NewStore(dir), TenantID: "synthetic-tenant"})
	}
	c := restart()
	rec := telemetrytest.New()
	e := telemetry.WithTenant(rec.Emitter(), "synthetic-tenant")
	if _, err := c.CollectWindow(t.Context(), start.Add(-time.Minute), now, e, nil); err != nil {
		t.Fatal(err)
	}
	points := rec.MetricPoints("teams.calls")
	if len(points) != 1 || points[0].Value != 1 || !points[0].Monotonic || points[0].Attrs["call_health"] != "good" || points[0].Attrs["tenant_id"] != "synthetic-tenant" {
		t.Fatalf("want one initial good call: %+v", points)
	}
	points = rec.MetricPoints("teams.stream.rtt")
	if len(points) != 1 || points[0].Value != 0.075 || points[0].Count != 1 || points[0].Unit != "s" || points[0].Attrs["direction"] != "caller_to_callee" {
		t.Fatalf("want one observed RTT in seconds: %+v", points)
	}
	points = rec.MetricPoints(metricLoss)
	lossByMedia := make(map[string]telemetrytest.MetricPoint)
	for _, point := range points {
		lossByMedia[point.Attrs["media"]] = point
	}
	if len(points) != 2 || lossByMedia["audio"].Value != 0 || lossByMedia["audio"].Count != 1 || lossByMedia["video"].Value != 0.01 || lossByMedia["audio"].Unit != "1" {
		t.Fatalf("packet-loss histogram lost a real zero or fabricated a measurement: %+v", points)
	}
	points = rec.MetricPoints(metricTransport)
	if len(points) != 1 || points[0].Attrs["transport"] != "tcp" || points[0].Value != 1 {
		t.Fatalf("transport must only use dated audio and the observed sender protocol: %+v", points)
	}
	points = rec.MetricPoints(metricVersions)
	if len(points) != 1 || points[0].Value != 1 || points[0].Kind != "gauge" || points[0].Attrs["version_bucket"] != "0" {
		t.Fatalf("want one recent call with a client in the zero-major bucket: %+v", points)
	}
	points = rec.MetricPoints(metricFeedback)
	if len(points) != 2 || points[0].Value != 1 || points[1].Value != 1 || points[0].Attrs["rating"] != "poor" || points[1].Attrs["rating"] != "poor" {
		t.Fatalf("want the real endpoint rating once for each dated media: %+v", points)
	}
	points = rec.MetricPoints(metricFailures)
	if len(points) != 1 || points[0].Value != 1 || points[0].Attrs["failure_stage"] != "midcall" || points[0].Attrs["reason_bucket"] != "other" {
		t.Fatalf("session and child failures must not count twice: %+v", points)
	}
	for _, step := range []struct {
		version int
		rtt     string
		changes float64
	}{{2, "PT0.075S", 0}, {1, "PT0.8S", 0}, {4, "PT0.8S", 1}, {3, "PT0.075S", 0}, {5, "PT0.9S", 0}, {4, "PT0.8S", 0}} {
		version, rtt = step.version, step.rtt
		c = restart()
		rec = telemetrytest.New()
		if err := c.CollectCall(t.Context(), "quality", telemetry.WithTenant(rec.Emitter(), "synthetic-tenant"), nil); err != nil {
			t.Fatal(err)
		}
		if len(rec.MetricPoints("teams.calls")) != 0 || len(rec.MetricPoints("teams.stream.rtt")) != 0 {
			t.Fatalf("v%d replayed first-version metrics", version)
		}
		points := rec.MetricPoints("teams.call.health_transitions")
		if step.changes == 0 && len(points) != 0 || step.changes == 1 && (len(points) != 1 || points[0].Value != 1 || !points[0].Monotonic || points[0].Attrs["from_health"] != "good" || points[0].Attrs["to_health"] != "poor") {
			t.Fatalf("v%d emitted wrong transition: %+v", version, points)
		}
	}
	version, start = 6, start.Add(-time.Minute)
	if err := c.CollectCall(t.Context(), "quality", telemetry.WithTenant(rec.Emitter(), "synthetic-tenant"), nil); err != nil {
		t.Fatal(err)
	}
	points = rec.MetricPoints(metricSkipped)
	if len(points) != 1 || points[0].Value != 1 || points[0].Attrs["reason_bucket"] != "source_time_changed" || len(rec.LogRecords()) != 3 {
		t.Fatalf("metric admission must refuse a moved start without dropping logs: %+v", points)
	}
}

func TestQualityMetricsCheckpointFailureAndExpiry(t *testing.T) {
	clock := now
	start := now.Add(-retention + time.Minute)
	version := 1
	withEnd := false
	g := fakeGraph(func(address, _ string) ([]byte, error) {
		if strings.Contains(address, "participants_v2") {
			return peoplePage(t), nil
		}
		d := syntheticDetail(t, "replay", version, start)
		if !withEnd {
			delete(d, "endDateTime")
		}
		return encoded(t, d), nil
	})
	dir := t.TempDir()
	restart := func() *Collector {
		c := collectorForTest(t, collectors.WindowDeps{Graph: g, Store: checkpoint.NewStore(dir), TenantID: "synthetic-tenant"})
		c.now = func() time.Time { return clock }
		return c
	}
	c := restart()
	rec := telemetrytest.New()
	collect := func() error { return c.CollectCall(t.Context(), "replay", rec.Emitter(), nil) }
	if err := collect(); err != nil || len(rec.LogRecords()) != 3 || len(rec.MetricPoints(metricCalls)) != 0 {
		t.Fatalf("incomplete call must keep raw logs but not count: %v", err)
	}
	withEnd, version = true, 3
	files, err := os.ReadDir(dir)
	if err != nil || len(files) != 1 {
		t.Fatalf("expected one shared checkpoint, got %v, %v", files, err)
	}
	blocked := filepath.Join(dir, files[0].Name()+".tmp")
	if err := os.Mkdir(blocked, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := collect(); err == nil || len(rec.MetricPoints(metricCalls)) != 0 || len(rec.MetricPoints(metricJitter)) != 0 {
		t.Fatalf("metrics escaped the failed checkpoint save: %v, %v", err, rec.MetricNames())
	}
	if err := os.Remove(blocked); err != nil {
		t.Fatal(err)
	}
	c = restart()
	if err := collect(); err != nil || len(rec.MetricPoints(metricCalls)) != 1 || rec.MetricPoints(metricCalls)[0].Value != 1 {
		t.Fatalf("save recovery did not count once: %v, %+v", err, rec.MetricPoints(metricCalls))
	}
	clock, version = clock.Add(2*time.Minute), 4
	if err := collect(); err != nil {
		t.Fatal(err)
	}
	cp, err := c.Store.Load(c.TenantID, Name)
	if err != nil || cp.TeamsCallMetrics == nil || len(cp.TeamsCallMetrics.Calls) != 0 {
		t.Fatalf("retention did not evict call metric version state: %+v (%v)", cp, err)
	}
	clock = now // an NTP step back cannot make the expired call eligible again
	c = restart()
	if err := collect(); err != nil || rec.MetricPoints(metricCalls)[0].Value != 1 {
		t.Fatalf("clock rollback admitted expired call: %v, %+v", err, rec.MetricPoints(metricCalls))
	}
}

func TestQualityMetricsLabelBudgetAndWirecheck(t *testing.T) {
	const opaque = "not-a-graph-enum"
	start := now.Add(-10 * time.Minute)
	csv := filepath.Join(t.TempDir(), "sites.csv")
	writeSites := func(extra bool) {
		var body strings.Builder
		body.WriteString("subnet,location,country,latitude,longitude\n")
		for i := 0; i <= metricSiteLimit; i++ {
			name := fmt.Sprintf("Synthetic Site %d", i)
			if extra {
				name = "Replacement " + name
			}
			fmt.Fprintf(&body, "192.0.2.%d/32,%s,GB,0,0\n", i, name)
		}
		if err := os.WriteFile(csv, []byte(body.String()), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	writeSites(false)
	file, err := sites.Open(csv)
	if err != nil {
		t.Fatal(err)
	}
	rec, capped := telemetrytest.New(), telemetrytest.New()
	limited := telemetry.WithTenant(telemetry.WithCardinalityLimits(capped.Emitter(), telemetry.Limits{PerMetric: 1}), "synthetic-tenant")
	var g fakeGraph
	dir := t.TempDir()
	for i := 0; i <= metricSiteLimit+2; i++ {
		id := fmt.Sprintf("synthetic-call-%d", i)
		d := syntheticDetail(t, id, 1, start)
		session := d["sessions"].([]any)[0].(map[string]any)
		media := session["segments"].([]any)[0].(map[string]any)["media"].([]any)[0].(map[string]any)
		media["callerNetwork"].(map[string]any)["subnet"] = fmt.Sprintf("192.0.2.%d", i%(metricSiteLimit+1))
		if i == metricSiteLimit+1 {
			writeSites(true) // none of these replacements can take a fresh slot
		}
		if i == metricSiteLimit+2 {
			d["type"], d["modalities"] = opaque, []string{opaque}
			firstAudioStream(d)["streamDirection"] = opaque
			session["caller"].(map[string]any)["userAgent"].(map[string]any)["applicationVersion"] = opaque
		}
		g = func(address, _ string) ([]byte, error) {
			if strings.Contains(address, "participants_v2") {
				return collection(t, ""), nil
			}
			return encoded(t, d), nil
		}
		// Recreate the collector to exercise persisted site admission.
		c := collectorForTest(t, collectors.WindowDeps{Graph: g, Store: checkpoint.NewStore(dir), TenantID: "synthetic-tenant", TeamsSites: file})
		if err := c.CollectCall(t.Context(), id, rec.Emitter(), nil); err != nil {
			t.Fatal(err)
		}
		if i < 4 { // different connections plus sites must share one terminal overflow series
			c = collectorForTest(t, collectors.WindowDeps{Graph: g, Store: checkpoint.NewStore(t.TempDir()), TenantID: "synthetic-tenant", TeamsSites: file})
			if err := c.CollectCall(t.Context(), id, limited, nil); err != nil {
				t.Fatal(err)
			}
		}
	}
	for _, name := range rec.MetricNames() {
		for _, point := range rec.MetricPoints(name) {
			for key, value := range point.Attrs {
				if strings.Contains(value, opaque) || strings.Contains(value, "192.0.2.") || strings.Contains(value, "Replacement") {
					t.Errorf("unbounded %s/%s=%q", name, key, value)
				}
			}
		}
	}
	counts := map[string]uint64{}
	for _, point := range rec.MetricPoints(metricRTT) {
		counts[point.Attrs["site"]] += point.Count
		if point.Attrs["direction"] == unknown && (point.Attrs["site"] != "unmapped" || point.Attrs["connection_type"] != unknown) {
			t.Fatalf("guessed the sender from an unknown direction: %+v", point)
		}
	}
	if len(counts) != metricSiteLimit+2 || counts[siteOverflow] != 2 || counts["Synthetic Site 0"] != 1 || counts["unmapped"] != 1 {
		t.Fatalf("wrong site budget or missing RTT: %v", counts)
	}
	points := capped.MetricPoints(metricStreams)
	if len(points) != 2 {
		t.Fatalf("want one admitted stream series and one terminal overflow series, got %+v", points)
	}
	for _, point := range points {
		if point.Attrs["site"] == other && (point.Value != 7 || point.Attrs["tenant_id"] != "synthetic-tenant" || point.Attrs["transport"] != other) {
			t.Fatalf("overflow did not remove attribution: %+v", point)
		}
	}
	findings := map[string]float64{}
	for _, point := range rec.MetricPoints("graph2otel.api.unexpected") {
		if point.Attrs["kind"] == "unmapped_value" {
			findings[point.Attrs["field"]] += point.Value
		}
	}
	for _, field := range []string{"type", "modalities", "streamDirection"} {
		if findings[field] != 1 {
			t.Fatalf("unmapped %s did not reach watchdog exactly once: %v", field, findings)
		}
	}
}

func firstAudioStream(d map[string]any) map[string]any {
	return d["sessions"].([]any)[0].(map[string]any)["segments"].([]any)[0].(map[string]any)["media"].([]any)[0].(map[string]any)["streams"].([]any)[0].(map[string]any)
}
