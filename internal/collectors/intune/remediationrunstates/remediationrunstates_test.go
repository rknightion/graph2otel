package remediationrunstates

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/rknightion/graph2otel/internal/collectors"
	"github.com/rknightion/graph2otel/internal/semconv"
	"github.com/rknightion/graph2otel/internal/telemetrytest"
)

// fakeGraph maps request URLs to canned page bodies (or errors), satisfying
// collectors.GraphClient so Collector runs through collectors.GetAllValues with
// no live Graph call.
type fakeGraph struct {
	bodies map[string]string
	errs   map[string]error
}

func (f *fakeGraph) RawGet(ctx context.Context, url string) ([]byte, error) {
	return f.RawGetWithHeaders(ctx, url, nil)
}

func (f *fakeGraph) RawGetWithHeaders(_ context.Context, url string, _ map[string]string) ([]byte, error) {
	if err, ok := f.errs[url]; ok {
		return nil, err
	}
	body, ok := f.bodies[url]
	if !ok {
		return nil, fmt.Errorf("fakeGraph: no body for %q", url)
	}
	return []byte(body), nil
}

var _ collectors.GraphClient = (*fakeGraph)(nil)

const base = defaultBaseURL

func listURL() string { return base + listPath }
func runURL(id string) string {
	return base + fmt.Sprintf(runStatesTmpl, id)
}

// Two remediations, one failing detection and one passing, VERBATIM-shaped from
// m7kni run states (probed as graph2otel-poller 2026-07-20): device LAPHAM fails
// "Pending Reboot Age" with the real detection message, and passes "Low Disk".
const (
	remPendingReboot = "3fff8e1f-05fb-416c-b628-655bec769596"
	remLowDisk       = "bc7b82cf-65b5-4813-941c-98c3b44a43b4"
)

func liveGraph() *fakeGraph {
	return &fakeGraph{bodies: map[string]string{
		listURL(): `{"value":[
			{"id":"` + remPendingReboot + `","displayName":"Health: Pending Reboot Age (Win)","publisher":"rob"},
			{"id":"` + remLowDisk + `","displayName":"Health: Low Disk Space (Win)","publisher":"rob"}
		]}`,
		runURL(remPendingReboot): `{"value":[
			{"id":"` + remPendingReboot + `:d5900d67-e50c-44ef-9d5c-6a2f891099c6",
			 "detectionState":"fail","remediationState":"skipped",
			 "preRemediationDetectionScriptOutput":"PENDING (PendingFileRename): unrebooted 3.9d (>= 3d)",
			 "preRemediationDetectionScriptError":"","remediationScriptError":"",
			 "lastStateUpdateDateTime":"2026-07-17T18:50:20Z","lastSyncDateTime":"2026-07-14T06:32:17Z",
			 "managedDevice":{"deviceName":"LAPHAM","operatingSystem":"Windows","osVersion":"10.0.26120.3281","managedDeviceOwnerType":"company"}}
		]}`,
		runURL(remLowDisk): `{"value":[
			{"id":"` + remLowDisk + `:d5900d67-e50c-44ef-9d5c-6a2f891099c6",
			 "detectionState":"success","remediationState":"skipped",
			 "preRemediationDetectionScriptOutput":"OK: C: 90.3% free (860.6 GB)",
			 "lastStateUpdateDateTime":"2026-07-17T18:50:20Z","lastSyncDateTime":"2026-07-14T06:32:17Z",
			 "managedDevice":{"deviceName":"LAPHAM","operatingSystem":"Windows","osVersion":"10.0.26120.3281","managedDeviceOwnerType":"company"}}
		]}`,
	}}
}

func TestCollectEmitsBoundedGaugeAndTwinPerRunState(t *testing.T) {
	c := New(liveGraph(), nil)
	rec := telemetrytest.New()
	if err := c.Collect(context.Background(), rec.Emitter()); err != nil {
		t.Fatalf("Collect: %v", err)
	}

	// Gauge: 2 series, keyed only by the bounded (remediation_name, detection_state,
	// remediation_state) triple, each value 1 (one device per remediation).
	points := rec.MetricPoints(metricName)
	if len(points) != 2 {
		t.Fatalf("got %d gauge series, want 2: %+v", len(points), points)
	}
	for _, p := range points {
		if p.Kind != "gauge" {
			t.Errorf("metric kind = %q, want gauge", p.Kind)
		}
		if p.Value != 1 {
			t.Errorf("series %+v value = %v, want 1", p.Attrs, p.Value)
		}
		for k := range p.Attrs {
			if k != semconv.AttrRemediationName && k != semconv.AttrDetectionState && k != semconv.AttrRemediationState {
				t.Errorf("gauge carries unbounded attribute %q; per-device detail belongs on the %s twin (#112)", k, eventName)
			}
		}
	}

	// Twin: one per (remediation, device) = 2, the failing one WARN with the
	// detection message + device_id split from the composite id.
	logs := rec.LogRecords()
	if len(logs) != 2 {
		t.Fatalf("got %d twins, want 2", len(logs))
	}
	var fail telemetrytest.LogRecord
	for _, l := range logs {
		if l.EventName != eventName {
			t.Errorf("EventName = %q", l.EventName)
		}
		if !l.Timestamp.IsZero() {
			t.Errorf("twin timestamp = %v, want zero (state snapshot)", l.Timestamp)
		}
		if l.Attrs[semconv.AttrDetectionState] == "fail" {
			fail = l
		}
	}
	if fail.SeverityText != "WARN" {
		t.Fatalf("failing detection severity = %q, want WARN", fail.SeverityText)
	}
	if fail.Attrs[semconv.AttrRemediationName] != "Health: Pending Reboot Age (Win)" ||
		fail.Attrs[semconv.AttrDeviceName] != "LAPHAM" ||
		fail.Attrs[semconv.AttrDeviceId] != "d5900d67-e50c-44ef-9d5c-6a2f891099c6" ||
		fail.Attrs[semconv.AttrDetectionOutput] != "PENDING (PendingFileRename): unrebooted 3.9d (>= 3d)" ||
		fail.Attrs[semconv.AttrOs] != "Windows" ||
		fail.Attrs[semconv.AttrLastStateUpdate] != "2026-07-17T18:50:20Z" {
		t.Errorf("failing twin attrs = %+v", fail.Attrs)
	}
	// Empty script-error fields must be omitted, never emitted as "".
	if _, ok := fail.Attrs[semconv.AttrDetectionScriptError]; ok {
		t.Errorf("detection_script_error present for an empty value")
	}
}

func TestSuccessfulDetectionIsInfo(t *testing.T) {
	c := New(liveGraph(), nil)
	rec := telemetrytest.New()
	if err := c.Collect(context.Background(), rec.Emitter()); err != nil {
		t.Fatalf("Collect: %v", err)
	}
	for _, l := range rec.LogRecords() {
		if l.Attrs[semconv.AttrDetectionState] == "success" && l.SeverityText != "INFO" {
			t.Errorf("passing detection severity = %q, want INFO", l.SeverityText)
		}
	}
}

func TestScriptErrorEscalatesToWarn(t *testing.T) {
	g := &fakeGraph{bodies: map[string]string{
		listURL(): `{"value":[{"id":"r1","displayName":"R1","publisher":"rob"}]}`,
		runURL("r1"): `{"value":[
			{"id":"r1:dev1","detectionState":"unknown","remediationState":"scriptError",
			 "remediationScriptError":"exit code 1: access denied",
			 "managedDevice":{"deviceName":"dev1"}}
		]}`,
	}}
	c := New(g, nil)
	rec := telemetrytest.New()
	if err := c.Collect(context.Background(), rec.Emitter()); err != nil {
		t.Fatalf("Collect: %v", err)
	}
	logs := rec.LogRecords()
	if len(logs) != 1 || logs[0].SeverityText != "WARN" {
		t.Fatalf("script error should WARN; got %+v", logs)
	}
	if logs[0].Attrs[semconv.AttrRemediationScriptError] != "exit code 1: access denied" {
		t.Errorf("remediation_script_error = %q", logs[0].Attrs[semconv.AttrRemediationScriptError])
	}
}

// One remediation's run-state fetch failing must not drop the others.
func TestPerRemediationFetchErrorSkipsOnlyThatOne(t *testing.T) {
	g := liveGraph()
	g.errs = map[string]error{runURL(remPendingReboot): errors.New("boom")}
	c := New(g, nil)
	rec := telemetrytest.New()
	if err := c.Collect(context.Background(), rec.Emitter()); err != nil {
		t.Fatalf("Collect returned error, want nil: %v", err)
	}
	if n := len(rec.LogRecords()); n != 1 {
		t.Fatalf("got %d twins, want 1 (only the healthy remediation survived)", n)
	}
}

func TestListForbiddenSkipsGracefully(t *testing.T) {
	g := &fakeGraph{errs: map[string]error{listURL(): errors.New("graphclient: GET ...: status 403: forbidden")}}
	c := New(g, nil)
	rec := telemetrytest.New()
	if err := c.Collect(context.Background(), rec.Emitter()); err != nil {
		t.Fatalf("403 should be a graceful skip, got: %v", err)
	}
	if len(rec.MetricPoints(metricName)) != 0 || len(rec.LogRecords()) != 0 {
		t.Error("expected no emissions on 403")
	}
}

func TestListErrorIsSurfaced(t *testing.T) {
	g := &fakeGraph{errs: map[string]error{listURL(): errors.New("boom")}}
	c := New(g, nil)
	rec := telemetrytest.New()
	if err := c.Collect(context.Background(), rec.Emitter()); err == nil {
		t.Error("a non-403 list error must be surfaced")
	}
}

func TestEmptyTenantEmitsEmptyGauge(t *testing.T) {
	g := &fakeGraph{bodies: map[string]string{listURL(): `{"value":[]}`}}
	c := New(g, nil)
	rec := telemetrytest.New()
	if err := c.Collect(context.Background(), rec.Emitter()); err != nil {
		t.Fatalf("Collect: %v", err)
	}
	if len(rec.LogRecords()) != 0 {
		t.Error("no remediations => no twins")
	}
}

func TestCollectorContract(t *testing.T) {
	c := New(nil, nil)
	if !c.Experimental() {
		t.Error("Experimental() = false, want true")
	}
	perms := c.RequiredPermissions()
	if len(perms) != 2 || perms[0] != "DeviceManagementConfiguration.Read.All" || perms[1] != "DeviceManagementManagedDevices.Read.All" {
		t.Errorf("RequiredPermissions = %v", perms)
	}
	if c.Name() != collectorName {
		t.Errorf("Name() = %q", c.Name())
	}
	if c.DefaultInterval() != time.Hour {
		t.Errorf("DefaultInterval = %v, want 1h", c.DefaultInterval())
	}
}
