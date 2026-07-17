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

// fullEnrollmentEvent is this package's richest fixture: the one record that
// carries every field mapEnrollmentEvent reads. It is shared by the mapper test
// and by TestCollectorEmitsFullRecordEndToEnd so the two can never drift into
// describing different records, mirroring how entra/riskdetections shares one
// record between its mapper tests and its end-to-end test.
//
// It is SYNTHETIC, and that gap is worth stating rather than implying: unlike
// entra/riskdetections' liveRiskDetection, this tree pins no verbatim GET
// /deviceManagement/troubleshootingEvents response, so no field NAME here is
// evidence of wire shape — they are docs-level claims (see #164, and CLAUDE.md
// on "platform": "windows", #142). Nothing was invented or enriched for the
// golden's benefit; this is the record the mapper test already used.
//
// What the end-to-end test proves regardless of provenance: whatever
// mapEnrollmentEvent sets survives the engine to the emitter — which is what
// makes testdata/signals.json honest, since the golden records attribute KEYS
// ONLY (internal/signalcapture) and a key set does not depend on whether the
// values a fixture carries are real.
//
// Returns a fresh map so the engine can never mutate a shared literal.
func fullEnrollmentEvent() map[string]any {
	return map[string]any{
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
}

func TestMapEnrollmentEvent(t *testing.T) {
	rec := fullEnrollmentEvent()

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

// TestCollectorEmitsFullRecordEndToEnd drives this package's richest record
// through the real engine into an emitter, rather than calling
// mapEnrollmentEvent directly like the tests above.
//
// It proves every attribute mapEnrollmentEvent sets survives the whole path,
// and it is what makes testdata/signals.json honest: the signal gate goldens
// the union of what a package's tests EMIT, so with only the minimal synthetic
// records of the watermark test reaching the emitter, the golden recorded a
// 2-attribute surface (failure_category, ingest_transport) for a collector that
// really ships 9 — understating the exact thing the golden exists to make
// reviewable (#164).
func TestCollectorEmitsFullRecordEndToEnd(t *testing.T) {
	f := &recordingFetcher{records: []map[string]any{fullEnrollmentEvent()}}
	rec := telemetrytest.New()
	c := newCollector(collectors.WindowDeps{TenantID: "t1", Fetcher: f, Store: checkpoint.NewStore(t.TempDir())})

	// The record's eventDateTime (10:00) must fall inside [from, to]: this
	// endpoint is NoServerFilter, so the engine bounds the window client-side.
	from := time.Date(2026, 7, 1, 9, 0, 0, 0, time.UTC)
	if _, err := c.CollectWindow(context.Background(), from, from.Add(2*time.Hour), rec.Emitter()); err != nil {
		t.Fatalf("CollectWindow: %v", err)
	}

	logs := rec.LogRecords()
	if len(logs) != 1 {
		t.Fatalf("emitted %d records, want 1", len(logs))
	}
	got := logs[0]
	if got.EventName != eventName {
		t.Errorf("event name = %q, want %q", got.EventName, eventName)
	}

	// Checked at the emitter rather than the mapper.
	wantAttrs := map[string]string{
		"failure_category": "authentication",
		"enrollment_type":  "windowsAzureADJoin",
		"operating_system": "Windows",
		"os_version":       "10.0.19045",
		"failure_reason":   "Invalid credentials",
		"device_id":        "device-guid",
		"user_id":          "user-guid",
		"correlation_id":   "corr-1",
		// The transport stamp the engine applies at the emitter boundary (#141).
		"ingest_transport": "graph",
	}
	for k, want := range wantAttrs {
		if v := got.Attrs[k]; v != want {
			t.Errorf("emitted attr %q = %q, want %q", k, v, want)
		}
	}

	// The record's own id is the dedupe key but is NOT emitted as an attribute
	// — unlike every sibling window collector (intune/autopilotevents,
	// intune/auditevents, entra/riskdetections all emit "id"). Pinned as
	// observed behavior, not endorsed: see #164 for the report.
	if _, present := got.Attrs["id"]; present {
		t.Errorf("id is unexpectedly emitted now, attrs=%v — update this test and #164", got.Attrs)
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
