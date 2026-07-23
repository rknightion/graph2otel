package exchangeauditconfig

import (
	"context"
	"encoding/json"
	"errors"
	"testing"

	"github.com/rknightion/graph2otel/internal/collectors"
	"github.com/rknightion/graph2otel/internal/semconv"
	"github.com/rknightion/graph2otel/internal/telemetry"
	"github.com/rknightion/graph2otel/internal/telemetrytest"
)

// liveRecord is a real Get-AdminAuditLogConfig record captured from the m7kni
// tenant as graph2otel-poller on 2026-07-23 over the Exchange Online admin API.
// The "<Name>@data.type" sidecar keys are on the wire verbatim and kept so the
// mapper proves it ignores them by exact-name reads.
const liveRecord = `{
  "AdminAuditLogEnabled": true,
  "LogLevel": "None",
  "TestCmdletLoggingEnabled": false,
  "AdminAuditLogAgeLimit": "90.00:00:00",
  "LoadBalancerCount@data.type": "System.Int32",
  "LoadBalancerCount": 3,
  "UnifiedAuditLogIngestionEnabled": true,
  "UnifiedAuditLogFirstOptInDate@data.type": "System.DateTime",
  "UnifiedAuditLogFirstOptInDate": "2025-11-13T22:13:46.2485587Z",
  "Name": "Admin Audit Log Settings",
  "Identity": "Admin Audit Log Settings"
}`

// fakeEXO returns canned records for one cmdlet.
type fakeEXO struct {
	recs []map[string]any
	err  error
}

func (f *fakeEXO) Invoke(_ context.Context, _ string, _ map[string]any) ([]map[string]any, error) {
	if f.err != nil {
		return nil, f.err
	}
	return f.recs, nil
}

func recordsFrom(t *testing.T, docs ...string) []map[string]any {
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

func collect(t *testing.T, exo *fakeEXO) *telemetrytest.Recorder {
	t.Helper()
	rec := telemetrytest.New()
	c := New(collectors.EXODeps{Client: exo})
	if err := c.Collect(context.Background(), rec.Emitter()); err != nil {
		t.Fatalf("Collect: %v", err)
	}
	return rec
}

func TestCollect_PostureGauge(t *testing.T) {
	rec := collect(t, &fakeEXO{recs: recordsFrom(t, liveRecord)})

	got := map[string]float64{}
	for _, p := range rec.MetricPoints(metricEnabled) {
		got[p.Attrs[semconv.AttrSetting]] = p.Value
	}
	if got[settingUnifiedAudit] != 1 {
		t.Errorf("unified_audit_log_ingestion = %v, want 1", got[settingUnifiedAudit])
	}
	if got[settingAdminAudit] != 1 {
		t.Errorf("admin_audit_log = %v, want 1", got[settingAdminAudit])
	}
	if len(got) != 2 {
		t.Errorf("want exactly 2 posture series, got %d", len(got))
	}
}

func TestCollect_TwinAttributesInfoWhenHealthy(t *testing.T) {
	rec := collect(t, &fakeEXO{recs: recordsFrom(t, liveRecord)})
	logs := rec.LogRecords()
	if len(logs) != 1 || logs[0].EventName != eventName {
		t.Fatalf("want 1 %s twin, got %v", eventName, logs)
	}
	a := logs[0].Attrs
	if a[semconv.AttrUnifiedAuditLogIngestionEnabled] != "true" {
		t.Errorf("unified enabled attr = %q", a[semconv.AttrUnifiedAuditLogIngestionEnabled])
	}
	if a[semconv.AttrLogLevel] != "None" {
		t.Errorf("log_level = %q", a[semconv.AttrLogLevel])
	}
	if a[semconv.AttrAdminAuditLogAgeLimit] != "90.00:00:00" {
		t.Errorf("age_limit = %q", a[semconv.AttrAdminAuditLogAgeLimit])
	}
	if a[semconv.AttrUnifiedAuditLogFirstOptInDate] == "" {
		t.Error("first_opt_in_date should be present")
	}
}

// TestConfigTwin_WarnWhenUnifiedOff drives the mapper directly: when the unified
// audit log is off, the M365 audit collectors go silently empty, so the twin
// escalates to Warn. Compared as this project's telemetry.Severity to avoid the
// log-severity scale trap.
func TestConfigTwin_WarnWhenUnifiedOff(t *testing.T) {
	off := map[string]any{"UnifiedAuditLogIngestionEnabled": false, "AdminAuditLogEnabled": true}
	if s := configTwin(off, false, true).Severity; s != telemetry.SeverityWarn {
		t.Errorf("unified off severity = %v, want Warn", s)
	}
	on := map[string]any{"UnifiedAuditLogIngestionEnabled": true, "AdminAuditLogEnabled": true}
	if s := configTwin(on, true, true).Severity; s != telemetry.SeverityInfo {
		t.Errorf("unified on severity = %v, want Info", s)
	}
}

func TestCollect_EmptyResult_NoEmit(t *testing.T) {
	rec := collect(t, &fakeEXO{recs: nil})
	if pts := rec.MetricPoints(metricEnabled); len(pts) != 0 {
		t.Errorf("empty result should emit nothing, got %d points", len(pts))
	}
	if logs := rec.LogRecords(); len(logs) != 0 {
		t.Errorf("empty result should emit no twin, got %d", len(logs))
	}
}

func TestCollect_ErrorPropagates(t *testing.T) {
	rec := telemetrytest.New()
	c := New(collectors.EXODeps{Client: &fakeEXO{err: errors.New("403")}})
	if err := c.Collect(context.Background(), rec.Emitter()); err == nil {
		t.Fatal("want error when cmdlet fails")
	}
}
