package blobcategories

import (
	"context"
	"errors"
	"testing"

	"github.com/rknightion/graph2otel/internal/recordoutcome"
	"github.com/rknightion/graph2otel/internal/semconv"
	"github.com/rknightion/graph2otel/internal/telemetry"
	"github.com/rknightion/graph2otel/internal/telemetrytest"
)

// fakeARM returns canned bytes (or an error) for RawGet, recording the URL.
type fakeARM struct {
	body []byte
	err  error
	url  string
}

func (f *fakeARM) RawGet(_ context.Context, url string) ([]byte, error) {
	f.url = url
	if f.err != nil {
		return nil, f.err
	}
	return f.body, nil
}

// sample is a trimmed but structurally faithful aadiam diagnosticSettings
// response: two settings, only the first sinks to a storage account. It exercises
// every census state plus the "second setting has no storage sink, so its enables
// do not count" rule (AuditLogs is disabled in the storage setting but enabled in
// the Log-Analytics-only setting — it must stay classified from the storage one).
const sample = `{
  "value": [
    {
      "name": "graph2otel",
      "properties": {
        "storageAccountId": "/subscriptions/x/providers/Microsoft.Storage/storageAccounts/acct",
        "logs": [
          {"category": "MicrosoftGraphActivityLogs", "enabled": true},
          {"category": "SignInLogs", "enabled": true},
          {"category": "AuditLogs", "enabled": false},
          {"category": "ADFSSignInLogs", "enabled": false}
        ]
      }
    },
    {
      "name": "to-log-analytics",
      "properties": {
        "storageAccountId": "",
        "workspaceId": "/subscriptions/x/.../workspace",
        "logs": [
          {"category": "AuditLogs", "enabled": true}
        ]
      }
    }
  ]
}`

func collectSample(t *testing.T, containers []string) (*telemetrytest.Recorder, recordoutcome.Snapshot) {
	t.Helper()
	rec := telemetrytest.New()
	outcomes := recordoutcome.NewRecorder()
	c := New(&fakeARM{body: []byte(sample)}, containers, nil)
	emitter := telemetry.WithTenant(
		telemetry.WithTransport(rec.Emitter(), telemetry.TransportGraph),
		"tenant-a",
	)
	if err := c.Collect(context.Background(), emitter, outcomes); err != nil {
		t.Fatalf("Collect: %v", err)
	}
	return rec, outcomes.Snapshot()
}

func TestCollect_ClassifiesEveryState(t *testing.T) {
	// insights-logs-microsoftgraphactivitylogs is read (consumed).
	// insights-logs-auditlogs is read but the category is disabled in the storage
	// setting (mapped_but_disabled), and its enable in the LA-only setting must be
	// ignored. SignInLogs is enabled with no reader (enabled_unread). ADFS is
	// disabled with no reader (disabled).
	containers := []string{
		"insights-logs-microsoftgraphactivitylogs",
		"insights-logs-auditlogs",
		"insights-logs-advancedhunting-deviceinfo", // a defender container, matches no aadiam category
	}
	rec, outcomes := collectSample(t, containers)
	wantOutcomes := recordoutcome.Counts{Fetched: 5, Mapped: 4, Emitted: 4, Filtered: 1}
	if outcomes.Counts != wantOutcomes {
		t.Fatalf("record outcomes = %+v, want %+v", outcomes.Counts, wantOutcomes)
	}
	if err := outcomes.Validate(); err != nil {
		t.Fatalf("record outcomes do not reconcile: %v", err)
	}

	want := map[string]float64{
		stateConsumed:          1, // MicrosoftGraphActivityLogs
		stateEnabledUnread:     1, // SignInLogs
		stateMappedButDisabled: 1, // AuditLogs (disabled in storage setting, has a reader)
		stateDisabled:          1, // ADFSSignInLogs
	}
	got := map[string]float64{}
	for _, p := range rec.MetricPoints(metricCategories) {
		if got := p.Attrs[semconv.AttrTenantID]; got != "tenant-a" {
			t.Errorf("tenant_id = %q, want tenant-a from the emitter boundary", got)
		}
		got[p.Attrs[semconv.AttrState]] = p.Value
	}
	if len(got) != len(want) {
		t.Fatalf("gauge states = %v, want %v", got, want)
	}
	for st, n := range want {
		if got[st] != n {
			t.Errorf("state %q count = %v, want %v", st, got[st], n)
		}
	}
}

func TestCollect_TwinAttributes(t *testing.T) {
	containers := []string{"insights-logs-microsoftgraphactivitylogs", "insights-logs-auditlogs"}
	rec, _ := collectSample(t, containers)

	byCategory := map[string]telemetrytest.LogRecord{}
	for _, l := range rec.LogRecords() {
		if l.EventName == eventCategory {
			byCategory[l.Attrs[semconv.AttrDiagnosticCategory]] = l
		}
	}
	if len(byCategory) != 4 {
		t.Fatalf("want 4 category twins, got %d", len(byCategory))
	}
	for category, record := range byCategory {
		if got := record.Attrs[semconv.AttrTenantID]; got != "tenant-a" {
			t.Errorf("%s tenant_id = %q, want tenant-a", category, got)
		}
		if got := record.Attrs[semconv.AttrIngestTransport]; got != string(telemetry.TransportGraph) {
			t.Errorf("%s ingest_transport = %q, want graph", category, got)
		}
	}
	// The container attribute is the derived insights-logs-<lowercase> name.
	if c := byCategory["SignInLogs"].Attrs[semconv.AttrContainer]; c != "insights-logs-signinlogs" {
		t.Errorf("SignInLogs container = %q", c)
	}
	// State rides the twin too.
	if s := byCategory["SignInLogs"].Attrs[semconv.AttrState]; s != stateEnabledUnread {
		t.Errorf("SignInLogs state = %q", s)
	}
	if s := byCategory["AuditLogs"].Attrs[semconv.AttrState]; s != stateMappedButDisabled {
		t.Errorf("AuditLogs state = %q", s)
	}
}

// TestCategoryTwin_Severity drives the mapper directly and compares this
// project's telemetry.Severity enum — the telemetrytest doc warns that the
// captured SeverityNumber is a DIFFERENT scale (log.Severity), so asserting
// severity end-to-end is a known trap.
func TestCategoryTwin_Severity(t *testing.T) {
	cases := []struct {
		state string
		want  telemetry.Severity
	}{
		{stateConsumed, telemetry.SeverityInfo},
		{stateDisabled, telemetry.SeverityInfo},
		{stateEnabledUnread, telemetry.SeverityWarn},
		{stateMappedButDisabled, telemetry.SeverityError},
	}
	for _, tc := range cases {
		got := categoryTwin("Cat", "insights-logs-cat", tc.state, true, true).Severity
		if got != tc.want {
			t.Errorf("state %q severity = %v, want %v", tc.state, got, tc.want)
		}
	}
}

func TestCollect_NilARMFailsInsteadOfReportingHealthyNoOp(t *testing.T) {
	outcomes := recordoutcome.NewRecorder()
	c := New(nil, []string{"insights-logs-signinlogs"}, nil)
	err := c.Collect(context.Background(), telemetrytest.New().Emitter(), outcomes)
	if err == nil {
		t.Fatal("Collect() error = nil, want missing ARM dependency to fail loudly")
	}
	if got := outcomes.Snapshot().Summarize(err, false).Cause; got != recordoutcome.CauseSourceError {
		t.Fatalf("outcome cause = %q, want source_error", got)
	}
}

func TestCollect_NoStorageSink_NoOp(t *testing.T) {
	body := `{"value":[{"name":"la","properties":{"storageAccountId":"","logs":[{"category":"SignInLogs","enabled":true}]}}]}`
	rec := telemetrytest.New()
	c := New(&fakeARM{body: []byte(body)}, []string{"insights-logs-signinlogs"}, nil)
	outcomes := recordoutcome.NewRecorder()
	if err := c.Collect(context.Background(), rec.Emitter(), outcomes); err != nil {
		t.Fatalf("Collect: %v", err)
	}
	want := recordoutcome.Counts{Fetched: 1, Filtered: 1}
	if got := outcomes.Snapshot().Counts; got != want {
		t.Fatalf("record outcomes = %+v, want %+v", got, want)
	}
	if pts := rec.MetricPoints(metricCategories); len(pts) != 0 {
		t.Errorf("no storage-sinking setting should emit nothing, got %d points", len(pts))
	}
}

func TestCollect_ARMError_Propagates(t *testing.T) {
	rec := telemetrytest.New()
	c := New(&fakeARM{err: errors.New("403 AuthorizationFailed")}, nil, nil)
	outcomes := recordoutcome.NewRecorder()
	if err := c.Collect(context.Background(), rec.Emitter(), outcomes); err == nil {
		t.Fatal("want error when ARM read fails")
	}
	if got := outcomes.Snapshot().Summarize(errors.New("fetch failed"), false); got.Cause != recordoutcome.CauseSourceError {
		t.Fatalf("outcome cause = %q, want source_error", got.Cause)
	}
}

func TestCollect_MalformedPayloadRecordsDecodeFailureWithoutInventingRows(t *testing.T) {
	outcomes := recordoutcome.NewRecorder()
	err := New(&fakeARM{body: []byte(`{"value":`)}, nil, nil).
		Collect(context.Background(), telemetrytest.New().Emitter(), outcomes)
	if err == nil {
		t.Fatal("want malformed payload error")
	}
	got := outcomes.Snapshot()
	if got.Counts != (recordoutcome.Counts{}) {
		t.Fatalf("record outcomes = %+v, want zero before rows can be decoded", got.Counts)
	}
	if summary := got.Summarize(err, false); summary.Cause != recordoutcome.CauseDecodeError {
		t.Fatalf("outcome cause = %q, want decode_error", summary.Cause)
	}
}
