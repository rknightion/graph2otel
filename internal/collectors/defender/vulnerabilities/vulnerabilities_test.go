package vulnerabilities

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/rknightion/graph2otel/internal/collectors"
	"github.com/rknightion/graph2otel/internal/semconv"
	"github.com/rknightion/graph2otel/internal/telemetry"
	"github.com/rknightion/graph2otel/internal/telemetrytest"
)

// liveSummary is a verbatim runHuntingQuery result for the summarize query,
// captured from the m7kni tenant as graph2otel-poller on 2026-07-23. Note the
// @odata.type sidecar keys and the SByte-encoded IsExploitAvailable (0/1 as a
// number, not a JSON bool) — both are on the wire exactly as kept here, and only
// six of the eight severity x exploit combinations are present (Critical/exploit
// and Low/exploit have no rows), so the mapper must not assume a full grid.
const liveSummary = `[
  {"VulnerabilitySeverityLevel":"Medium","IsExploitAvailable@odata.type":"#SByte","IsExploitAvailable":0,"instances":6308,"devices":49,"cves":1005,"max_cvss":6.9,"max_epss":0.93305},
  {"VulnerabilitySeverityLevel":"High","IsExploitAvailable@odata.type":"#SByte","IsExploitAvailable":0,"instances":16999,"devices":55,"cves":1564,"max_cvss":8.8,"max_epss":0.797},
  {"VulnerabilitySeverityLevel":"Critical","IsExploitAvailable@odata.type":"#SByte","IsExploitAvailable":0,"instances":772,"devices":44,"cves":147,"max_cvss":10.0,"max_epss":0.5585},
  {"VulnerabilitySeverityLevel":"Low","IsExploitAvailable@odata.type":"#SByte","IsExploitAvailable":0,"instances":563,"devices":49,"cves":78,"max_cvss":3.9,"max_epss":0.10738},
  {"VulnerabilitySeverityLevel":"Medium","IsExploitAvailable@odata.type":"#SByte","IsExploitAvailable":1,"instances":125,"devices":36,"cves":10,"max_cvss":6.2,"max_epss":0.98631},
  {"VulnerabilitySeverityLevel":"High","IsExploitAvailable@odata.type":"#SByte","IsExploitAvailable":1,"instances":145,"devices":33,"cves":19,"max_cvss":8.8,"max_epss":0.99506}
]`

// liveTwinExploit is a verbatim per-entity row from the KB-joined twin query: an
// exploit-available Medium vulnerability. IsExploitAvailable is SByte 1,
// CveMitigationStatus is the empty string (not null), and CveTags is a real
// empty array — the exact shapes the mapper must handle.
const liveTwinExploit = `{
  "DeviceId":"8cfd8e5cd33bfad1aba06d7bc6a1b70d3e9cd468","DeviceName":"desktop-mhtmhh4",
  "OSPlatform":"Windows11","OSVersion":"10.0.26200.6584","OSArchitecture":"x64",
  "SoftwareVendor":"microsoft","SoftwareName":"windows_11","SoftwareVersion":"10.0.26200.6584",
  "CveId":"CVE-2026-33829","VulnerabilitySeverityLevel":"Medium",
  "RecommendedSecurityUpdate":"April 2026 Security Updates","RecommendedSecurityUpdateId":"5083769",
  "CveTags@odata.type":"#Collection(String)","CveTags":[],"CveMitigationStatus":"",
  "AadDeviceId":"06b257c7-b87d-47ef-8336-26d630c35ded","CveId1":"CVE-2026-33829",
  "CvssScore":4.3,"EpssScore":0.03447,"IsExploitAvailable@odata.type":"#SByte","IsExploitAvailable":1,
  "CvssVector":"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:N/A:N/E:U/RL:O/RC:C","PublishedDate":"2026-04-14T07:00:00Z"
}`

// liveTwinCritical is a fabricated-from-shape Critical row (no exploit) to drive
// the "Error on Critical" branch; every column is one the live schema carries.
const liveTwinCritical = `{
  "DeviceId":"aaa","DeviceName":"dc01","OSPlatform":"WindowsServer2022","OSVersion":"10.0.20348",
  "SoftwareVendor":"microsoft","SoftwareName":"windows_server_2022","SoftwareVersion":"10.0.20348",
  "CveId":"CVE-2026-11111","VulnerabilitySeverityLevel":"Critical",
  "RecommendedSecurityUpdate":"April 2026 Security Updates","CveMitigationStatus":"",
  "CvssScore":9.8,"EpssScore":0.5,"IsExploitAvailable@odata.type":"#SByte","IsExploitAvailable":0,
  "CvssVector":"CVSS:3.1/AV:N","PublishedDate":"2026-04-14T07:00:00Z"
}`

// fakeHunt routes queries to canned results. summarize queries get the summary;
// everything else is a twin partition — filtered by severity so per-severity
// fetches return the right rows, and the recorded queries are kept for assertions.
type fakeHunt struct {
	summary []map[string]any
	twins   map[string][]map[string]any // by severity substring
	queries []string
	err     error
	twinErr error
}

func (f *fakeHunt) Query(_ context.Context, _ string, kql string) ([]map[string]any, error) {
	f.queries = append(f.queries, kql)
	if f.err != nil {
		return nil, f.err
	}
	if strings.Contains(kql, "summarize") {
		return f.summary, nil
	}
	if f.twinErr != nil {
		return nil, f.twinErr
	}
	for sev, rows := range f.twins {
		if strings.Contains(kql, `== "`+sev+`"`) {
			return rows, nil
		}
	}
	return nil, nil
}

func rows(t *testing.T, docs ...string) []map[string]any {
	t.Helper()
	out := make([]map[string]any, 0, len(docs))
	for _, d := range docs {
		var m map[string]any
		if err := json.Unmarshal([]byte(d), &m); err != nil {
			t.Fatalf("unmarshal fixture: %v", err)
		}
		out = append(out, m)
	}
	return out
}

func rowsFromArray(t *testing.T, doc string) []map[string]any {
	t.Helper()
	var out []map[string]any
	if err := json.Unmarshal([]byte(doc), &out); err != nil {
		t.Fatalf("unmarshal array fixture: %v", err)
	}
	return out
}

func TestCollect_Gauges(t *testing.T) {
	f := &fakeHunt{summary: rowsFromArray(t, liveSummary), twins: map[string][]map[string]any{}}
	rec := telemetrytest.New()
	c := New(collectors.HuntDeps{Client: f})
	if err := c.Collect(context.Background(), rec.Emitter()); err != nil {
		t.Fatalf("Collect: %v", err)
	}

	// instances: 6 series (only 6 of 8 severity x exploit combos are on the wire).
	inst := rec.MetricPoints(metricInstances)
	if len(inst) != 6 {
		t.Fatalf("instances: got %d series, want 6", len(inst))
	}
	// Spot-check the High/exploit-available instance count and its labels.
	var found bool
	for _, p := range inst {
		if p.Attrs[semconv.AttrSeverity] == "High" && p.Attrs[semconv.AttrExploitAvailable] == "true" {
			found = true
			if p.Value != 145 {
				t.Errorf("High/exploit instances = %v, want 145", p.Value)
			}
		}
	}
	if !found {
		t.Error("no High/exploit-available instances series")
	}

	// max_epss carries the highest probability for High/exploit — 0.99506.
	for _, p := range rec.MetricPoints(metricMaxEPSS) {
		if p.Attrs[semconv.AttrSeverity] == "High" && p.Attrs[semconv.AttrExploitAvailable] == "true" && p.Value != 0.99506 {
			t.Errorf("High/exploit max_epss = %v, want 0.99506", p.Value)
		}
	}

	// All five gauges emit, none keyed by a per-entity attribute.
	for _, m := range []string{metricInstances, metricDevices, metricCVEs, metricMaxCVSS, metricMaxEPSS} {
		pts := rec.MetricPoints(m)
		if len(pts) == 0 {
			t.Errorf("%s emitted no points", m)
		}
		for _, p := range pts {
			for k := range p.Attrs {
				if k != semconv.AttrSeverity && k != semconv.AttrExploitAvailable {
					t.Errorf("%s has unexpected (possibly per-entity) label %q", m, k)
				}
			}
		}
	}
}

func TestCollect_Twins(t *testing.T) {
	f := &fakeHunt{
		summary: rowsFromArray(t, liveSummary),
		twins: map[string][]map[string]any{
			"Medium":   rows(t, liveTwinExploit),
			"Critical": rows(t, liveTwinCritical),
		},
	}
	rec := telemetrytest.New()
	c := New(collectors.HuntDeps{Client: f})
	if err := c.Collect(context.Background(), rec.Emitter()); err != nil {
		t.Fatalf("Collect: %v", err)
	}

	logs := rec.LogRecords()
	if len(logs) != 2 {
		t.Fatalf("got %d twins, want 2", len(logs))
	}
	byCve := map[string]map[string]string{}
	for _, l := range logs {
		if l.EventName != eventName {
			t.Errorf("event name = %q, want %q", l.EventName, eventName)
		}
		byCve[l.Attrs[semconv.AttrCveId]] = l.Attrs
	}

	m := byCve["CVE-2026-33829"]
	if m == nil {
		t.Fatal("missing the Medium/exploit twin")
	}
	if m[semconv.AttrExploitAvailable] != "true" {
		t.Errorf("exploit_available = %q, want true (SByte 1 -> true)", m[semconv.AttrExploitAvailable])
	}
	if m[semconv.AttrCvssScore] != "4.3" {
		t.Errorf("cvss_score = %q, want 4.3", m[semconv.AttrCvssScore])
	}
	if m[semconv.AttrDeviceName] != "desktop-mhtmhh4" {
		t.Errorf("device_name = %q", m[semconv.AttrDeviceName])
	}
	if m[semconv.AttrSoftwareName] != "windows_11" {
		t.Errorf("software_name = %q", m[semconv.AttrSoftwareName])
	}
	// CveMitigationStatus is "" on the wire; an empty value must be omitted, not
	// emitted as a blank attribute.
	if _, present := m[semconv.AttrCveMitigationStatus]; present {
		t.Error("cve_mitigation_status should be omitted when empty on the wire")
	}
}

// TestSeverity drives vulnTwin directly (the telemetry.Severity scale, not the
// recorded log-severity scale — see telemetrytest.LogRecord.SeverityNumber).
func TestSeverity(t *testing.T) {
	exploit := vulnTwin(rows(t, liveTwinExploit)[0]) // Medium but exploit-available
	if exploit.Severity != telemetry.SeverityError {
		t.Errorf("exploit-available severity = %v, want Error", exploit.Severity)
	}
	critical := vulnTwin(rows(t, liveTwinCritical)[0]) // Critical, no exploit
	if critical.Severity != telemetry.SeverityError {
		t.Errorf("Critical severity = %v, want Error", critical.Severity)
	}

	// A Medium row with no exploit is Info.
	benign := rows(t, liveTwinExploit)[0]
	benign["IsExploitAvailable"] = float64(0)
	if got := vulnTwin(benign).Severity; got != telemetry.SeverityInfo {
		t.Errorf("Medium/no-exploit severity = %v, want Info", got)
	}
}

func TestCollect_SummaryFailureIsFatal(t *testing.T) {
	f := &fakeHunt{err: errors.New("403")}
	rec := telemetrytest.New()
	c := New(collectors.HuntDeps{Client: f})
	if err := c.Collect(context.Background(), rec.Emitter()); err == nil {
		t.Fatal("summary failure should be fatal to the tick")
	}
}

func TestCollect_TwinFailureIsNonFatal(t *testing.T) {
	f := &fakeHunt{summary: rowsFromArray(t, liveSummary), twinErr: errors.New("throttled")}
	rec := telemetrytest.New()
	c := New(collectors.HuntDeps{Client: f})
	err := c.Collect(context.Background(), rec.Emitter())
	if err == nil {
		t.Fatal("a twin partition failure should surface an aggregated error")
	}
	// ...but the gauges still emitted.
	if len(rec.MetricPoints(metricInstances)) == 0 {
		t.Error("gauges should emit even when twin partitions fail")
	}
}

// TestPartitioning_NoTruncation forces a tiny row cap so a single severity shards
// into multiple hash partitions, and proves every partition's rows are emitted —
// the collector must not drop a shard.
func TestPartitioning_NoTruncation(t *testing.T) {
	// One severity, 5 instances, cap 2 -> ceil(5/2) = 3 partitions.
	summary := rows(t, `{"VulnerabilitySeverityLevel":"High","IsExploitAvailable":0,"instances":5,"devices":1,"cves":5,"max_cvss":8.8,"max_epss":0.5}`)

	// A fake that returns a distinct row per partition, keyed by the hash predicate.
	perPartition := map[string]string{
		"hash(DeviceId, 3) == 0": `{"CveId":"CVE-A","DeviceName":"d0","VulnerabilitySeverityLevel":"High","IsExploitAvailable":0}`,
		"hash(DeviceId, 3) == 1": `{"CveId":"CVE-B","DeviceName":"d1","VulnerabilitySeverityLevel":"High","IsExploitAvailable":0}`,
		"hash(DeviceId, 3) == 2": `{"CveId":"CVE-C","DeviceName":"d2","VulnerabilitySeverityLevel":"High","IsExploitAvailable":0}`,
	}
	f := &shardFake{summary: summary, perPartition: perPartition, t: t}
	rec := telemetrytest.New()
	c := New(collectors.HuntDeps{Client: f})
	c.rowCap = 2 // force sharding

	if err := c.Collect(context.Background(), rec.Emitter()); err != nil {
		t.Fatalf("Collect: %v", err)
	}
	logs := rec.LogRecords()
	if len(logs) != 3 {
		t.Fatalf("got %d twins, want 3 (one per shard, none dropped)", len(logs))
	}
	got := map[string]bool{}
	for _, l := range logs {
		got[l.Attrs[semconv.AttrCveId]] = true
	}
	for _, cve := range []string{"CVE-A", "CVE-B", "CVE-C"} {
		if !got[cve] {
			t.Errorf("shard row %s was not emitted — a partition was dropped", cve)
		}
	}
}

type shardFake struct {
	summary      []map[string]any
	perPartition map[string]string
	t            *testing.T
}

func (f *shardFake) Query(_ context.Context, _ string, kql string) ([]map[string]any, error) {
	if strings.Contains(kql, "summarize") {
		return f.summary, nil
	}
	for pred, doc := range f.perPartition {
		if strings.Contains(kql, pred) {
			return rows(f.t, doc), nil
		}
	}
	return nil, nil
}
