package softwareinventory

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

// liveSummary is a verbatim summarize result captured from m7kni as
// graph2otel-poller on 2026-07-23. The empty EndOfSupportStatus is a REAL bucket
// (supported software, 1,499 installs), not missing data.
const liveSummary = `[
  {"EndOfSupportStatus":"","installs":1499,"eos_devices":74,"products":281},
  {"EndOfSupportStatus":"EOS Software","installs":5,"eos_devices":4,"products":2},
  {"EndOfSupportStatus":"EOS Version","installs":18,"eos_devices":11,"products":3},
  {"EndOfSupportStatus":"Upcoming EOS Version","installs":20,"eos_devices":11,"products":1}
]`

// liveTwinEOS is a verbatim end-of-life install row: EndOfSupportStatus set and
// EndOfSupportDate the {} the wire uses for a null datetime.
const liveTwinEOS = `{
  "DeviceId":"dc18b236b00245ab05a1052e23573e9a8bd8e6f2","DeviceName":"MacBook-Pro",
  "OSPlatform":"macOS","OSVersion":"26.5.2.0","OSArchitecture":"x64",
  "SoftwareVendor":"apple","SoftwareName":"quicktime_for_mac","SoftwareVersion":"10.5.0.0",
  "EndOfSupportStatus":"EOS Software","ProductCodeCpe":"apple:quicktime_for_mac:10.5.0.0",
  "EndOfSupportDate":{}
}`

// liveTwinSupported is a supported install (empty status) — emitted as a twin
// too, per #114.
const liveTwinSupported = `{
  "DeviceId":"aaa","DeviceName":"desktop-1","OSPlatform":"Windows11","OSVersion":"10.0.26200",
  "SoftwareVendor":"google","SoftwareName":"chrome","SoftwareVersion":"140.0.0.0",
  "EndOfSupportStatus":"","ProductCodeCpe":"google:chrome:140.0.0.0","EndOfSupportDate":{}
}`

type fakeHunt struct {
	summary []map[string]any
	twins   map[string][]map[string]any // by EndOfSupportStatus
	err     error
	twinErr error
}

func (f *fakeHunt) Query(_ context.Context, _ string, kql string) ([]map[string]any, error) {
	if f.err != nil {
		return nil, f.err
	}
	if strings.Contains(kql, "summarize") {
		return f.summary, nil
	}
	if f.twinErr != nil {
		return nil, f.twinErr
	}
	for status, rows := range f.twins {
		if strings.Contains(kql, `== "`+status+`"`) {
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
	if err := New(collectors.HuntDeps{Client: f}).Collect(context.Background(), rec.Emitter()); err != nil {
		t.Fatalf("Collect: %v", err)
	}

	// 4 install series, including the empty-status (supported) bucket.
	installs := rec.MetricPoints(metricInstalls)
	if len(installs) != 4 {
		t.Fatalf("installs: got %d series, want 4", len(installs))
	}
	var supported, eos bool
	for _, p := range installs {
		switch p.Attrs[semconv.AttrEndOfSupportStatus] {
		case "":
			supported = true
			if p.Value != 1499 {
				t.Errorf("supported installs = %v, want 1499", p.Value)
			}
		case "EOS Software":
			eos = true
			if p.Value != 5 {
				t.Errorf("EOS Software installs = %v, want 5", p.Value)
			}
		}
	}
	if !supported {
		t.Error("the empty-status (supported) bucket must be emitted, not skipped")
	}
	if !eos {
		t.Error("missing EOS Software series")
	}
	// installs is keyed only by end_of_support_status.
	for _, p := range installs {
		for k := range p.Attrs {
			if k != semconv.AttrEndOfSupportStatus {
				t.Errorf("installs has unexpected (possibly per-entity) label %q", k)
			}
		}
	}
}

func TestCollect_TwinAndSeverity(t *testing.T) {
	f := &fakeHunt{
		summary: rowsFromArray(t, liveSummary),
		twins: map[string][]map[string]any{
			"EOS Software": rows(t, liveTwinEOS),
			"":             rows(t, liveTwinSupported),
		},
	}
	rec := telemetrytest.New()
	if err := New(collectors.HuntDeps{Client: f}).Collect(context.Background(), rec.Emitter()); err != nil {
		t.Fatalf("Collect: %v", err)
	}
	logs := rec.LogRecords()
	if len(logs) != 2 {
		t.Fatalf("got %d twins, want 2 (EOS + supported)", len(logs))
	}
	byName := map[string]map[string]string{}
	for _, l := range logs {
		byName[l.Attrs[semconv.AttrSoftwareName]] = l.Attrs
	}
	eos := byName["quicktime_for_mac"]
	if eos == nil {
		t.Fatal("missing the EOS twin")
	}
	if eos[semconv.AttrEndOfSupportStatus] != "EOS Software" {
		t.Errorf("end_of_support_status = %q", eos[semconv.AttrEndOfSupportStatus])
	}
	if eos[semconv.AttrProductCodeCpe] != "apple:quicktime_for_mac:10.5.0.0" {
		t.Errorf("product_code_cpe = %q", eos[semconv.AttrProductCodeCpe])
	}
	// EndOfSupportDate is {} on the wire -> omitted.
	if _, present := eos[semconv.AttrEndOfSupportDate]; present {
		t.Error("null ({}) end_of_support_date should be omitted")
	}
}

func TestSoftwareTwin_Severity(t *testing.T) {
	eos := softwareTwin(rows(t, liveTwinEOS)[0])
	if eos.Severity != telemetry.SeverityWarn {
		t.Errorf("EOS severity = %v, want Warn", eos.Severity)
	}
	supported := softwareTwin(rows(t, liveTwinSupported)[0])
	if supported.Severity != telemetry.SeverityInfo {
		t.Errorf("supported severity = %v, want Info", supported.Severity)
	}
}

func TestCollect_SummaryFailureIsFatal(t *testing.T) {
	f := &fakeHunt{err: errors.New("403")}
	if err := New(collectors.HuntDeps{Client: f}).Collect(context.Background(), telemetrytest.New().Emitter()); err == nil {
		t.Fatal("summary failure should be fatal")
	}
}
