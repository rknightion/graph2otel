package riskdetections

import (
	"context"
	"testing"
	"time"

	"github.com/rknightion/graph2otel/internal/checkpoint"
	"github.com/rknightion/graph2otel/internal/collectors"
	"github.com/rknightion/graph2otel/internal/graphclient"
	"github.com/rknightion/graph2otel/internal/license"
	"github.com/rknightion/graph2otel/internal/logpipeline"
	"github.com/rknightion/graph2otel/internal/telemetry"
	"github.com/rknightion/graph2otel/internal/telemetrytest"
)

// recordingFetcher is a logpipeline.PageFetcher that returns a fixed set of
// records once and records every requested page URL.
type recordingFetcher struct {
	records  []map[string]any
	seenURLs []string
}

func (f *recordingFetcher) FetchPage(_ context.Context, pageURL string) ([]map[string]any, string, error) {
	f.seenURLs = append(f.seenURLs, pageURL)
	return f.records, "", nil
}

func TestMapRiskDetection(t *testing.T) {
	rec := map[string]any{
		"id":                  "rd-1",
		"riskEventType":       "anonymizedIPAddress",
		"riskType":            "anonymizedIPAddress",
		"riskLevel":           "medium",
		"riskState":           "atRisk",
		"riskDetail":          "none",
		"detectionTimingType": "realtime",
		"source":              "IdentityProtection",
		"ipAddress":           "203.0.113.9",
		"userPrincipalName":   "alice@contoso.com",
		"userId":              "user-guid",
		"correlationId":       "corr-1",
		"requestId":           "req-1",
		"activity":            "signin",
		"detectedDateTime":    "2026-07-01T10:00:00Z",
		"location": map[string]any{
			"city":            "London",
			"countryOrRegion": "GB",
		},
	}

	id, ev := mapRiskDetection(rec)
	if id != "rd-1" {
		t.Fatalf("dedupe id = %q, want rd-1", id)
	}
	if ev.Name != eventName {
		t.Fatalf("event name = %q, want %q", ev.Name, eventName)
	}
	if ev.Severity != telemetry.SeverityWarn {
		t.Errorf("medium risk severity = %v, want Warn", ev.Severity)
	}

	wantAttrs := map[string]any{
		"id":                         "rd-1",
		"risk_event_type":            "anonymizedIPAddress",
		"risk_type":                  "anonymizedIPAddress",
		"risk_level":                 "medium",
		"risk_state":                 "atRisk",
		"risk_detail":                "none",
		"detection_timing_type":      "realtime",
		"source":                     "IdentityProtection",
		"ip_address":                 "203.0.113.9",
		"user_principal_name":        "alice@contoso.com",
		"user_id":                    "user-guid",
		"correlation_id":             "corr-1",
		"request_id":                 "req-1",
		"activity":                   "signin",
		"location_city":              "London",
		"location_country_or_region": "GB",
	}
	for k, want := range wantAttrs {
		if got := ev.Attrs[k]; got != want {
			t.Errorf("attr %q = %v, want %v", k, got, want)
		}
	}
}

func TestMapRiskDetectionSeverityByRiskLevel(t *testing.T) {
	cases := []struct {
		riskLevel string
		want      telemetry.Severity
	}{
		{"high", telemetry.SeverityError},
		{"medium", telemetry.SeverityWarn},
		{"low", telemetry.SeverityInfo},
		{"hidden", telemetry.SeverityInfo},
		{"", telemetry.SeverityInfo},
	}
	for _, tc := range cases {
		rec := map[string]any{"id": "x", "riskLevel": tc.riskLevel}
		_, ev := mapRiskDetection(rec)
		if ev.Severity != tc.want {
			t.Errorf("riskLevel=%q severity = %v, want %v", tc.riskLevel, ev.Severity, tc.want)
		}
	}
}

func TestMapRiskDetectionOmitsAbsentOptionalFields(t *testing.T) {
	rec := map[string]any{
		"id":        "rd-2",
		"riskLevel": "low",
	}
	_, ev := mapRiskDetection(rec)
	for _, k := range []string{"request_id", "activity", "location_city", "location_country_or_region", "ip_address", "correlation_id"} {
		if _, present := ev.Attrs[k]; present {
			t.Errorf("attr %q must be omitted when absent from the record, attrs=%v", k, ev.Attrs)
		}
	}
}

func TestRequiredCapabilityIsEntraP2(t *testing.T) {
	d := collectors.WindowDeps{
		TenantID: "t1",
		Fetcher:  &recordingFetcher{},
		Store:    checkpoint.NewStore(t.TempDir()),
	}
	c := newCollector(d)
	if got := c.RequiredCapability(); got != license.CapEntraP2 {
		t.Errorf("RequiredCapability = %q, want %q", got, license.CapEntraP2)
	}
}

func TestRequiredPermissions(t *testing.T) {
	d := collectors.WindowDeps{
		TenantID: "t1",
		Fetcher:  &recordingFetcher{},
		Store:    checkpoint.NewStore(t.TempDir()),
	}
	c := newCollector(d)
	perms := c.RequiredPermissions()
	if len(perms) != 1 || perms[0] != "IdentityRiskEvent.Read.All" {
		t.Errorf("RequiredPermissions = %v, want [IdentityRiskEvent.Read.All]", perms)
	}
}

// TestClassifyWorkloadRoutesThroughIPC documents (and guards against
// regression of) the load-bearing fact this collector's schedule tuning
// depends on: the transport classifies this endpoint's path onto the
// Identity Protection workload, not the reporting bucket, so it is
// serialized through the shared 1-req/s-per-tenant IPC limiter alongside
// risky users/SPs and Conditional Access.
func TestClassifyWorkloadRoutesThroughIPC(t *testing.T) {
	if got := graphclient.ClassifyWorkload(riskDetectionsPath); got != graphclient.WorkloadIPC {
		t.Errorf("ClassifyWorkload(%q) = %q, want %q", riskDetectionsPath, got, graphclient.WorkloadIPC)
	}
}

func TestCollectorDrainsEmitsAndPersistsWatermark(t *testing.T) {
	dir := t.TempDir()
	from := time.Date(2026, 7, 1, 9, 0, 0, 0, time.UTC)
	newest := "2026-07-01T09:45:00Z"

	f := &recordingFetcher{records: []map[string]any{
		{"id": "rd-a", "detectedDateTime": "2026-07-01T09:10:00Z", "riskLevel": "low", "userPrincipalName": "a@x.com"},
		{"id": "rd-b", "detectedDateTime": newest, "riskLevel": "high", "userPrincipalName": "b@x.com"},
	}}
	store := checkpoint.NewStore(dir)
	rec := telemetrytest.New()
	c := newCollector(collectors.WindowDeps{TenantID: "t1", Fetcher: f, Store: store})

	if _, err := c.CollectWindow(context.Background(), from, from.Add(time.Hour), rec.Emitter()); err != nil {
		t.Fatalf("CollectWindow: %v", err)
	}
	if got := len(rec.LogRecords()); got != 2 {
		t.Fatalf("emitted %d records, want 2", got)
	}

	cp, err := store.Load("t1", riskDetectionsPath)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cp.Watermark.IsZero() {
		t.Fatal("watermark was not persisted")
	}
	wantHW := time.Date(2026, 7, 1, 9, 45, 0, 0, time.UTC).Add(-logpipeline.DefaultSafetyLag)
	if !cp.Watermark.Equal(wantHW) {
		t.Errorf("watermark = %v, want newest(%s) - safetyLag(%v) = %v", cp.Watermark, newest, logpipeline.DefaultSafetyLag, wantHW)
	}
}
