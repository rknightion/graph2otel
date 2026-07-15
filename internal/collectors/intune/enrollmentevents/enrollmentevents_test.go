package enrollmentevents

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/rknightion/graph2otel/internal/checkpoint"
	"github.com/rknightion/graph2otel/internal/collectors"
	"github.com/rknightion/graph2otel/internal/license"
	"github.com/rknightion/graph2otel/internal/logpipeline"
	"github.com/rknightion/graph2otel/internal/telemetry"
	"github.com/rknightion/graph2otel/internal/telemetrytest"
)

// recordingFetcher is a logpipeline.PageFetcher that returns a fixed set of
// records once and records every requested page URL, so a test can both
// drain records and assert the exact first-page URL the collector built.
type recordingFetcher struct {
	records  []map[string]any
	seenURLs []string
}

func (f *recordingFetcher) FetchPage(_ context.Context, pageURL string) ([]map[string]any, string, error) {
	f.seenURLs = append(f.seenURLs, pageURL)
	return f.records, "", nil
}

func TestMapEnrollmentEvent(t *testing.T) {
	rec := map[string]any{
		"id":              "evt-1",
		"deviceId":        "device-guid",
		"userId":          "user-guid",
		"correlationId":   "corr-1",
		"enrollmentType":  "windowsAzureADJoin",
		"failureCategory": "authentication",
		"failureReason":   "Invalid credentials",
		"operatingSystem": "Windows",
		"osVersion":       "10.0.19045",
		"eventDateTime":   "2026-07-01T10:00:00Z",
	}

	id, ev := mapEnrollmentEvent(rec)
	if id != "evt-1" {
		t.Fatalf("dedupe id = %q, want evt-1", id)
	}
	if ev.Name != eventName {
		t.Fatalf("event name = %q, want %q", ev.Name, eventName)
	}
	if ev.Severity != telemetry.SeverityWarn {
		t.Errorf("severity = %v, want Warn (every record is a failure)", ev.Severity)
	}

	wantAttrs := map[string]any{
		"failure_category": "authentication",
		"enrollment_type":  "windowsAzureADJoin",
		"operating_system": "Windows",
		"os_version":       "10.0.19045",
		"failure_reason":   "Invalid credentials",
		"device_id":        "device-guid",
		"user_id":          "user-guid",
		"correlation_id":   "corr-1",
	}
	for k, want := range wantAttrs {
		if got := ev.Attrs[k]; got != want {
			t.Errorf("attr %q = %v, want %v", k, got, want)
		}
	}
}

func TestMapEnrollmentEventOmitsAbsentOptionalFields(t *testing.T) {
	rec := map[string]any{
		"id":              "evt-2",
		"failureCategory": "userAbandonment",
	}
	_, ev := mapEnrollmentEvent(rec)
	for _, k := range []string{"os_version", "device_id", "user_id", "correlation_id", "failure_reason", "enrollment_type", "operating_system"} {
		if _, present := ev.Attrs[k]; present {
			t.Errorf("attr %q must be omitted when absent from the record, attrs=%v", k, ev.Attrs)
		}
	}
}

func TestRequiredCapabilityIsIntune(t *testing.T) {
	d := collectors.WindowDeps{
		TenantID: "t1",
		Fetcher:  &recordingFetcher{},
		Store:    checkpoint.NewStore(t.TempDir()),
	}
	c := newCollector(d)
	if got := c.RequiredCapability(); got != license.CapIntune {
		t.Errorf("RequiredCapability = %q, want %q", got, license.CapIntune)
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
	if len(perms) != 1 || perms[0] != "DeviceManagementManagedDevices.Read.All" {
		t.Errorf("RequiredPermissions = %v, want [DeviceManagementManagedDevices.Read.All]", perms)
	}
}

// TestNoServerFilterOmitsFilterQueryParam guards the endpoint-specific
// constraint the issue calls out: troubleshootingEvents does not support a
// server-side $filter on eventDateTime, so the first-page URL must carry no
// $filter at all — the engine drains the whole collection and bounds the
// window client-side.
func TestNoServerFilterOmitsFilterQueryParam(t *testing.T) {
	f := &recordingFetcher{records: []map[string]any{{"id": "a", "eventDateTime": "2026-07-01T10:00:00Z"}}}
	c := newCollector(collectors.WindowDeps{TenantID: "t1", Fetcher: f, Store: checkpoint.NewStore(t.TempDir())})
	from := time.Date(2026, 7, 1, 9, 0, 0, 0, time.UTC)
	if _, err := c.CollectWindow(context.Background(), from, from.Add(time.Hour), telemetrytest.New().Emitter()); err != nil {
		t.Fatalf("CollectWindow: %v", err)
	}
	if len(f.seenURLs) == 0 {
		t.Fatal("no page fetched")
	}
	if strings.Contains(f.seenURLs[0], "%24filter") || strings.Contains(f.seenURLs[0], "$filter") {
		t.Errorf("first-page URL = %q, want no $filter (NoServerFilter)", f.seenURLs[0])
	}
}

func TestCollectorDrainsFiltersClientSideAndPersistsWatermark(t *testing.T) {
	dir := t.TempDir()
	from := time.Date(2026, 7, 1, 9, 0, 0, 0, time.UTC)
	to := from.Add(time.Hour)
	newest := "2026-07-01T09:45:00Z"

	f := &recordingFetcher{records: []map[string]any{
		{"id": "evt-before", "eventDateTime": "2026-07-01T08:00:00Z", "failureCategory": "authentication"}, // outside [from,to]
		{"id": "evt-a", "eventDateTime": "2026-07-01T09:10:00Z", "failureCategory": "authorization"},
		{"id": "evt-b", "eventDateTime": newest, "failureCategory": "accountValidation"},
		{"id": "evt-after", "eventDateTime": "2026-07-01T11:00:00Z", "failureCategory": "authentication"}, // outside [from,to]
	}}
	store := checkpoint.NewStore(dir)
	rec := telemetrytest.New()
	c := newCollector(collectors.WindowDeps{TenantID: "t1", Fetcher: f, Store: store})

	if _, err := c.CollectWindow(context.Background(), from, to, rec.Emitter()); err != nil {
		t.Fatalf("CollectWindow: %v", err)
	}
	if got := len(rec.LogRecords()); got != 2 {
		t.Fatalf("emitted %d records, want 2 (client-side window filtering)", got)
	}

	cp, err := store.Load("t1", path)
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
