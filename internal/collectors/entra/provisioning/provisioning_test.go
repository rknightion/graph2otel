package provisioning

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/rknightion/graph2otel/internal/checkpoint"
	"github.com/rknightion/graph2otel/internal/collectors"
	"github.com/rknightion/graph2otel/internal/telemetry"
	"github.com/rknightion/graph2otel/internal/telemetrytest"
)

// recordingFetcher is a logpipeline.PageFetcher that returns a fixed set of
// records once and records every requested page URL, so a test can both drain
// records and assert the exact first-page URL the collector built.
type recordingFetcher struct {
	records  []map[string]any
	seenURLs []string
}

func (f *recordingFetcher) FetchPage(_ context.Context, pageURL string) ([]map[string]any, string, error) {
	f.seenURLs = append(f.seenURLs, pageURL)
	return f.records, "", nil
}

func depsWith(t *testing.T, f *recordingFetcher) collectors.WindowDeps {
	t.Helper()
	return collectors.WindowDeps{
		TenantID: "t1",
		Fetcher:  f,
		Store:    checkpoint.NewStore(t.TempDir()),
	}
}

func TestMapProvisioningSuccess(t *testing.T) {
	rec := map[string]any{
		"id":                 "prov-1",
		"activityDateTime":   "2026-07-01T10:00:00Z",
		"jobId":              "job-1",
		"cycleId":            "cycle-1",
		"changeId":           "change-1",
		"provisioningAction": "create",
		"provisioningStatusInfo": map[string]any{
			"status": "success",
		},
		"sourceIdentity": map[string]any{
			"id":          "src-guid",
			"displayName": "Alice Source",
		},
		"targetIdentity": map[string]any{
			"id":          "tgt-guid",
			"displayName": "Alice Target",
		},
		"servicePrincipal": []any{
			map[string]any{"id": "sp-guid", "name": "ServiceNow"},
		},
	}

	id, ev := mapProvisioning(rec)
	if id != "prov-1" {
		t.Fatalf("dedupe id = %q, want prov-1", id)
	}
	if ev.Name != eventName {
		t.Fatalf("event name = %q, want %q", ev.Name, eventName)
	}
	if ev.Severity != telemetry.SeverityInfo {
		t.Errorf("successful provisioning severity = %v, want Info", ev.Severity)
	}
	wantBody := "provisioning create: success"
	if ev.Body != wantBody {
		t.Errorf("body = %q, want %q", ev.Body, wantBody)
	}

	wantAttrs := map[string]any{
		"id":                           "prov-1",
		"job_id":                       "job-1",
		"cycle_id":                     "cycle-1",
		"change_id":                    "change-1",
		"provisioning_action":          "create",
		"status":                       "success",
		"source_identity_id":           "src-guid",
		"source_identity_display_name": "Alice Source",
		"target_identity_id":           "tgt-guid",
		"target_identity_display_name": "Alice Target",
		"service_principal_id":         "sp-guid",
		"service_principal_name":       "ServiceNow",
	}
	for k, want := range wantAttrs {
		if got := ev.Attrs[k]; got != want {
			t.Errorf("attr %q = %v, want %v", k, got, want)
		}
	}
	if _, present := ev.Attrs["status_info"]; present {
		t.Errorf("successful event with no errorInformation must not carry status_info, attrs=%v", ev.Attrs)
	}
	if _, present := ev.Attrs["status_error_code"]; present {
		t.Errorf("successful event with no errorInformation must not carry status_error_code, attrs=%v", ev.Attrs)
	}
}

func TestMapProvisioningFailureIsWarn(t *testing.T) {
	rec := map[string]any{
		"id":                 "prov-2",
		"activityDateTime":   "2026-07-01T11:00:00Z",
		"provisioningAction": "update",
		"provisioningStatusInfo": map[string]any{
			"status": "failure",
			"errorInformation": map[string]any{
				"errorCode": "MissingRequiredAttribute",
				"reason":    "The target attribute is required but empty",
			},
		},
	}

	_, ev := mapProvisioning(rec)
	if ev.Severity != telemetry.SeverityWarn {
		t.Errorf("failed provisioning severity = %v, want Warn", ev.Severity)
	}
	if ev.Attrs["status"] != "failure" {
		t.Errorf("status = %v, want failure", ev.Attrs["status"])
	}
	if ev.Attrs["status_info"] != "The target attribute is required but empty" {
		t.Errorf("status_info = %v, want the error reason", ev.Attrs["status_info"])
	}
	if ev.Attrs["status_error_code"] != "MissingRequiredAttribute" {
		t.Errorf("status_error_code = %v, want MissingRequiredAttribute", ev.Attrs["status_error_code"])
	}
	wantBody := "provisioning update: failure"
	if ev.Body != wantBody {
		t.Errorf("body = %q, want %q", ev.Body, wantBody)
	}
}

// A record with no servicePrincipal, sourceIdentity, or targetIdentity (all
// optional per the provisioningObjectSummary resource doc) must omit those
// attributes entirely rather than emitting them empty/zero.
func TestMapProvisioningOmitsAbsentNestedFields(t *testing.T) {
	rec := map[string]any{
		"id":                 "prov-3",
		"activityDateTime":   "2026-07-01T12:00:00Z",
		"provisioningAction": "disable",
	}
	_, ev := mapProvisioning(rec)
	for _, k := range []string{
		"source_identity_id", "source_identity_display_name",
		"target_identity_id", "target_identity_display_name",
		"service_principal_id", "service_principal_name",
		"status", "status_info", "status_error_code",
		"job_id", "cycle_id", "change_id",
	} {
		if _, present := ev.Attrs[k]; present {
			t.Errorf("attr %q must be omitted when the source field is absent, attrs=%v", k, ev.Attrs)
		}
	}
}

func TestNotExperimentalNoLicenseGate(t *testing.T) {
	f := &recordingFetcher{records: []map[string]any{{"id": "a", "activityDateTime": "2026-07-01T10:00:00Z"}}}
	c := newCollector(depsWith(t, f))

	if _, ok := any(c).(collectors.Experimental); ok {
		t.Error("provisioning collector must not implement Experimental (v1.0, not beta)")
	}
	perms := c.RequiredPermissions()
	if len(perms) != 1 || perms[0] != "AuditLog.Read.All" {
		t.Errorf("RequiredPermissions = %v, want [AuditLog.Read.All]", perms)
	}
}

// #23 acceptance: the emitted $filter must use strict gt/lt, never the
// inclusive ge/le the other audit streams use, because provisioning's
// $orderby is unreliable and boundary events are caught by the overlap
// window + id-dedupe instead.
func TestFirstPageURLUsesStrictGtLt(t *testing.T) {
	f := &recordingFetcher{records: []map[string]any{{"id": "a", "activityDateTime": "2026-07-01T10:00:00Z"}}}
	c := newCollector(depsWith(t, f))

	from := time.Date(2026, 7, 1, 9, 0, 0, 0, time.UTC)
	if _, err := c.CollectWindow(context.Background(), from, from.Add(time.Hour), telemetrytest.New().Emitter()); err != nil {
		t.Fatalf("CollectWindow: %v", err)
	}
	if len(f.seenURLs) == 0 {
		t.Fatal("no page fetched")
	}
	u := f.seenURLs[0]
	if !strings.HasPrefix(u, "https://graph.microsoft.com/v1.0/auditLogs/provisioning?") {
		t.Errorf("first-page URL = %q, want the v1.0 provisioning endpoint", u)
	}
	if !strings.Contains(u, "activityDateTime+gt+") {
		t.Errorf("first-page URL = %q, want a strict activityDateTime gt bound", u)
	}
	if !strings.Contains(u, "activityDateTime+lt+") {
		t.Errorf("first-page URL = %q, want a strict activityDateTime lt bound", u)
	}
	if strings.Contains(u, "activityDateTime+ge+") || strings.Contains(u, "activityDateTime+le+") {
		t.Errorf("first-page URL = %q, must not use the inclusive ge/le operators", u)
	}
	if strings.Contains(u, "%24orderby") {
		t.Errorf("first-page URL = %q, must not carry $orderby ($orderby is unreliable on provisioning)", u)
	}
}

func TestCollectorDrainsEmitsAndPersistsWatermark(t *testing.T) {
	dir := t.TempDir()
	from := time.Date(2026, 7, 1, 9, 0, 0, 0, time.UTC)
	newest := "2026-07-01T09:45:00Z"

	f := &recordingFetcher{records: []map[string]any{
		{"id": "a", "activityDateTime": "2026-07-01T09:10:00Z", "provisioningAction": "create"},
		{"id": "b", "activityDateTime": newest, "provisioningAction": "update"},
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

	cp, err := store.Load("t1", path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cp.Watermark.IsZero() {
		t.Fatal("watermark was not persisted")
	}
	wantHW := time.Date(2026, 7, 1, 9, 45, 0, 0, time.UTC).Add(-logpipelineDefaultSafetyLag)
	if !cp.Watermark.Equal(wantHW) {
		t.Errorf("watermark = %v, want newest(%s) - safetyLag = %v", cp.Watermark, newest, wantHW)
	}
}

// The engine must sort the drained window client-side by activityDateTime
// before computing the new high-water mark, since $orderby is unreliable on
// provisioning: even when the server returns records out of time order, the
// persisted watermark must reflect the true newest event time.
func TestCollectorSortsClientSideOnUnreliableOrder(t *testing.T) {
	dir := t.TempDir()
	from := time.Date(2026, 7, 1, 9, 0, 0, 0, time.UTC)
	newest := "2026-07-01T09:45:00Z"

	// Server returns the newer record FIRST, violating $orderby asc.
	f := &recordingFetcher{records: []map[string]any{
		{"id": "b", "activityDateTime": newest, "provisioningAction": "update"},
		{"id": "a", "activityDateTime": "2026-07-01T09:10:00Z", "provisioningAction": "create"},
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

	cp, err := store.Load("t1", path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	wantHW := time.Date(2026, 7, 1, 9, 45, 0, 0, time.UTC).Add(-logpipelineDefaultSafetyLag)
	if !cp.Watermark.Equal(wantHW) {
		t.Errorf("watermark = %v, want newest(%s) - safetyLag = %v (client-side sort must find the true newest record)", cp.Watermark, newest, wantHW)
	}
}

// logpipelineDefaultSafetyLag mirrors logpipeline.DefaultSafetyLag (15m), the
// margin the engine trails the watermark by when EndpointConfig.SafetyLag is
// left at its default.
const logpipelineDefaultSafetyLag = 15 * time.Minute
