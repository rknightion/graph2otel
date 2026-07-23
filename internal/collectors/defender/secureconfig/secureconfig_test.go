package secureconfig

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

// liveAssessments is a verbatim summarize result (count by category, compliant)
// captured from m7kni as graph2otel-poller on 2026-07-23: 5 categories, both
// compliance states, IsCompliant SByte-encoded (0/1 as a number).
const liveAssessments = `[
  {"ConfigurationCategory":"Network","IsCompliant":1,"assessments":550},
  {"ConfigurationCategory":"Network","IsCompliant":0,"assessments":468},
  {"ConfigurationCategory":"Security controls","IsCompliant":0,"assessments":953},
  {"ConfigurationCategory":"OS","IsCompliant":1,"assessments":961},
  {"ConfigurationCategory":"OS","IsCompliant":0,"assessments":316},
  {"ConfigurationCategory":"Security controls","IsCompliant":1,"assessments":1085},
  {"ConfigurationCategory":"Accounts","IsCompliant":0,"assessments":135},
  {"ConfigurationCategory":"Application","IsCompliant":0,"assessments":144},
  {"ConfigurationCategory":"Accounts","IsCompliant":1,"assessments":187},
  {"ConfigurationCategory":"Application","IsCompliant":1,"assessments":47}
]`

// liveRisk is the verbatim noncompliant-devices + summed-impact result by category.
const liveRisk = `[
  {"ConfigurationCategory":"Network","noncompliant_devices":52,"impact_at_risk":2675.0},
  {"ConfigurationCategory":"Security controls","noncompliant_devices":46,"impact_at_risk":7348.0},
  {"ConfigurationCategory":"OS","noncompliant_devices":48,"impact_at_risk":2150.0},
  {"ConfigurationCategory":"Accounts","noncompliant_devices":44,"impact_at_risk":727.0},
  {"ConfigurationCategory":"Application","noncompliant_devices":37,"impact_at_risk":675.0}
]`

// liveTwinNoncompliant is a verbatim failing-assessment row: IsCompliant SByte 0,
// IsApplicable SByte 1, an empty subcategory, and the {} null the wire uses for
// IsExpectedUserImpact — none of which the mapper reads, but all present.
const liveTwinNoncompliant = `{
  "DeviceId":"c2487b0c4d46d8274e9f3ad6feaaacc9767f1f99","DeviceName":"U7-Office",
  "OSPlatform":"Linux","Timestamp":"2026-07-19T21:46:29Z","ConfigurationId":"scid-10002",
  "ConfigurationCategory":"Network","ConfigurationSubcategory":"","ConfigurationImpact":5.0,
  "IsCompliant@odata.type":"#SByte","IsCompliant":0,"IsApplicable@odata.type":"#SByte","IsApplicable":1,
  "Context@odata.type":"#Collection(String)","Context":[],"IsExpectedUserImpact":{}
}`

type fakeHunt struct {
	assessments []map[string]any
	risk        []map[string]any
	twins       map[string][]map[string]any
	err         error
	twinErr     error
}

func (f *fakeHunt) Query(_ context.Context, _ string, kql string) ([]map[string]any, error) {
	if f.err != nil {
		return nil, f.err
	}
	switch {
	case strings.Contains(kql, "noncompliant_devices"):
		return f.risk, nil
	case strings.Contains(kql, "summarize assessments"):
		return f.assessments, nil
	}
	if f.twinErr != nil {
		return nil, f.twinErr
	}
	for cat, rows := range f.twins {
		if strings.Contains(kql, `== "`+cat+`"`) {
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
	f := &fakeHunt{
		assessments: rowsFromArray(t, liveAssessments),
		risk:        rowsFromArray(t, liveRisk),
		twins:       map[string][]map[string]any{},
	}
	rec := telemetrytest.New()
	if err := New(collectors.HuntDeps{Client: f}).Collect(context.Background(), rec.Emitter()); err != nil {
		t.Fatalf("Collect: %v", err)
	}

	// 10 assessment series (5 categories x compliant/noncompliant).
	assess := rec.MetricPoints(metricAssessments)
	if len(assess) != 10 {
		t.Fatalf("assessments: got %d series, want 10", len(assess))
	}
	for _, p := range assess {
		if p.Attrs[semconv.AttrConfigurationCategory] == "Security controls" && p.Attrs[semconv.AttrIsCompliant] == "false" && p.Value != 953 {
			t.Errorf("Security controls noncompliant = %v, want 953", p.Value)
		}
	}
	// impact_at_risk carries the summed impact per category — Security controls 7348.
	for _, p := range rec.MetricPoints(metricImpactAtRisk) {
		if p.Attrs[semconv.AttrConfigurationCategory] == "Security controls" && p.Value != 7348 {
			t.Errorf("Security controls impact = %v, want 7348", p.Value)
		}
	}
	// noncompliant_devices is keyed by category only (not compliance).
	for _, p := range rec.MetricPoints(metricNoncompliantDevices) {
		for k := range p.Attrs {
			if k != semconv.AttrConfigurationCategory {
				t.Errorf("noncompliant_devices has unexpected label %q", k)
			}
		}
	}
}

func TestCollect_Twin(t *testing.T) {
	f := &fakeHunt{
		assessments: rowsFromArray(t, liveAssessments),
		risk:        rowsFromArray(t, liveRisk),
		twins:       map[string][]map[string]any{"Network": rows(t, liveTwinNoncompliant)},
	}
	rec := telemetrytest.New()
	if err := New(collectors.HuntDeps{Client: f}).Collect(context.Background(), rec.Emitter()); err != nil {
		t.Fatalf("Collect: %v", err)
	}
	var twin *telemetrytest.LogRecord
	for i, l := range rec.LogRecords() {
		if l.EventName == eventName {
			twin = &rec.LogRecords()[i]
			break
		}
	}
	if twin == nil {
		t.Fatal("no secure_config twin emitted")
	}
	if twin.Attrs[semconv.AttrIsCompliant] != "false" {
		t.Errorf("is_compliant = %q, want false (SByte 0 -> false)", twin.Attrs[semconv.AttrIsCompliant])
	}
	if twin.Attrs[semconv.AttrConfigurationId] != "scid-10002" {
		t.Errorf("configuration_id = %q", twin.Attrs[semconv.AttrConfigurationId])
	}
	if twin.Attrs[semconv.AttrConfigurationImpact] != "5" {
		t.Errorf("configuration_impact = %q, want 5", twin.Attrs[semconv.AttrConfigurationImpact])
	}
	// Empty subcategory omitted.
	if _, present := twin.Attrs[semconv.AttrConfigurationSubcategory]; present {
		t.Error("empty configuration_subcategory should be omitted")
	}
}

func TestConfigTwin_Severity(t *testing.T) {
	noncompliant := configTwin(rows(t, liveTwinNoncompliant)[0])
	if noncompliant.Severity != telemetry.SeverityWarn {
		t.Errorf("noncompliant severity = %v, want Warn", noncompliant.Severity)
	}
	compliant := rows(t, liveTwinNoncompliant)[0]
	compliant["IsCompliant"] = float64(1)
	if got := configTwin(compliant).Severity; got != telemetry.SeverityInfo {
		t.Errorf("compliant severity = %v, want Info", got)
	}
}

func TestCollect_SummaryFailureIsFatal(t *testing.T) {
	f := &fakeHunt{err: errors.New("403")}
	if err := New(collectors.HuntDeps{Client: f}).Collect(context.Background(), telemetrytest.New().Emitter()); err == nil {
		t.Fatal("summary failure should be fatal")
	}
}
